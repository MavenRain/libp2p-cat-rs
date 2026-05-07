//! [`RendezvousNode`]: a [`Host`] that auto-answers inbound
//! rendezvous RPC frames and exposes synchronous client methods.
//!
//! - [`RendezvousNode::observe_self`] (pass 5): ask a remote
//!   rendezvous what address it sees this node coming from.
//! - [`RendezvousNode::punch_via`] (pass 6): ask a remote
//!   rendezvous to relay a punch request to a target peer.
//!
//! Every node plays both client and server roles symmetrically, the
//! way [`KademliaNode`](libp2p_cat_kad::KademliaNode) plays both
//! PING roles.
//!
//! # Mux composability (pass 8)
//!
//! [`RendezvousNode::split`] and [`RendezvousNode::join`] expose the
//! "joined" / "decomposed" views of the node so a multi-protocol mux
//! can hold the underlying [`Host`] alongside other protocols' state
//! and reconstitute a transient `RendezvousNode` for each inbound
//! plaintext.  Rendezvous owns no protocol state beyond the [`Host`],
//! so the second component of [`RendezvousNode::split`]'s tuple is
//! `()`; the same shape applies to the stateful protocols.
//!
//! [`RendezvousNode::process_plaintext`] performs the protocol-level
//! reaction to a single freshly-decrypted plaintext datagram, with
//! no socket-level dispatch.  Standalone deployments go through
//! [`RendezvousNode::recv_one`], which reads one datagram from the
//! socket, surfaces handshake-shaped events directly, and routes
//! [`HostEvent::DatagramDelivered`] through `process_plaintext`.

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_types::{Error, PeerId, UdpAddr};

use crate::codec::{Frame, decode, encode};
use crate::event::RendezvousEvent;

/// A [`Host`] augmented with rendezvous RPC handling.
#[must_use]
pub struct RendezvousNode {
    host: Host,
}

impl RendezvousNode {
    /// Build a node from a [`Host`].
    pub fn new(host: Host) -> Self {
        Self { host }
    }

    /// Decompose this node into its underlying [`Host`] and protocol
    /// state.  Rendezvous owns no extra state, so the second tuple
    /// component is `()`.
    ///
    /// Used by the multi-protocol mux to share a single [`Host`]
    /// across protocols: the mux holds the [`Host`] alongside other
    /// protocols' state and reconstitutes a transient
    /// [`RendezvousNode`] via [`Self::join`] for each rendezvous-
    /// kinded inbound plaintext.
    pub fn split(self) -> (Host, ()) {
        let Self { host } = self;
        (host, ())
    }

    /// Inverse of [`Self::split`]: build a node from a [`Host`] and
    /// protocol state.
    pub fn join(host: Host, _state: ()) -> Self {
        Self { host }
    }

    /// Local libp2p-compatible [`PeerId`].
    pub fn peer_id(&self) -> &PeerId {
        self.host.peer_id()
    }

    /// Borrow the underlying [`Host`].
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Local UDP address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot report the local
    /// address.
    pub fn local_addr(&self) -> Result<UdpAddr, Error> {
        self.host.local_addr()
    }

    /// Initiate a Noise XX handshake with the peer at `addr`; mirrors
    /// [`Host::dial`].
    ///
    /// # Errors
    ///
    /// Same set as [`Host::dial`].
    #[must_use]
    pub fn dial(self, addr: UdpAddr, ephemeral_seed: [u8; 32]) -> Io<Error, Self> {
        let Self { host } = self;
        host.dial(addr, ephemeral_seed)
            .map(move |host| Self { host })
    }

    /// Send `plaintext` to an established peer.  Mirrors
    /// [`Host::send`].
    ///
    /// # Errors
    ///
    /// Same set as [`Host::send`].
    #[must_use]
    pub fn send(self, addr: UdpAddr, plaintext: Vec<u8>) -> Io<Error, Self> {
        let Self { host } = self;
        host.send(addr, plaintext).map(move |host| Self { host })
    }

    /// Send an `OBSERVE_REQ` to `server_addr` and drain `recv_one`
    /// until the matching `OBSERVE_RESP` arrives, returning the
    /// observed address.
    ///
    /// `seed_factory` is called once per [`Self::recv_one`] step
    /// inside the drain loop; only the seed for an unrelated fresh
    /// peer's `msg1` is actually used, but a fresh value should be
    /// supplied for each call regardless.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `server_addr` is not yet
    ///   established (callers must `dial` first and complete the
    ///   handshake).
    /// - Underlying socket / Noise errors propagate transparently.
    /// - [`Error::PubsubProtocol`] if the rendezvous server returns
    ///   a malformed reply or an unexpected event type.
    #[must_use]
    pub fn observe_self<F>(
        self,
        server_addr: UdpAddr,
        seed_factory: F,
    ) -> Io<Error, (Self, UdpAddr)>
    where
        F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
    {
        send_observe_req(self, server_addr)
            .flat_map(move |node| drain_for_observe_response(node, server_addr, seed_factory))
    }

    /// Send a `PUNCH_REQ` to `server_addr` asking it to forward a
    /// punch request to `target_addr`.  Fire-and-forget: the server
    /// will (if it has a session with `target_addr`) send a
    /// `PUNCH_FORWARD` to the target, which then auto-fires a bare
    /// punch datagram at us.  The caller's next [`Self::recv_one`]
    /// will surface the resulting [`RendezvousEvent::Rejected`]
    /// event when the punch lands.
    ///
    /// On loopback this verifies the wire protocol; in real
    /// deployment behind NATs the act of being punched (and our
    /// subsequent dial of `target_addr`) is what threads the
    /// connection through both NATs' mappings.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `server_addr` is not yet
    ///   established.
    /// - Underlying socket / Noise errors propagate transparently.
    #[must_use]
    pub fn punch_via(self, server_addr: UdpAddr, target_addr: UdpAddr) -> Io<Error, Self> {
        let frame = Frame::PunchReq {
            target: target_addr,
        };
        let Self { host } = self;
        Io::suspend(move || encode(&frame))
            .flat_map(move |bytes| host.send(server_addr, bytes).map(move |host| Self { host }))
    }

    /// TURN-style relay: ask `server_addr` (a relay) to forward
    /// `payload` to `target_addr`.  The server forwards if it has
    /// an established session with `target_addr`; otherwise it
    /// replies with `RELAY_FAIL`, which the caller's next
    /// [`Self::recv_one`] surfaces as
    /// [`RendezvousEvent::RelayFailed`].
    ///
    /// The server sees `payload` in plaintext.  End-to-end privacy
    /// requires the two endpoints to layer a separate Noise
    /// handshake over the relay.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `server_addr` is not yet
    ///   established.
    /// - Underlying socket / Noise errors propagate transparently.
    #[must_use]
    pub fn relay_via(
        self,
        server_addr: UdpAddr,
        target_addr: UdpAddr,
        payload: Vec<u8>,
    ) -> Io<Error, Self> {
        let frame = Frame::RelayDataReq {
            target: target_addr,
            payload,
        };
        let Self { host } = self;
        Io::suspend(move || encode(&frame))
            .flat_map(move |bytes| host.send(server_addr, bytes).map(move |host| Self { host }))
    }

    /// Receive one event.  Inbound `OBSERVE_REQ`s are auto-answered,
    /// inbound `PUNCH_REQ`s are auto-forwarded (when the target is
    /// established), and inbound `PUNCH_FORWARD`s auto-fire a bare
    /// punch datagram at the original initiator, all *before* the
    /// corresponding "received" variant is emitted.
    ///
    /// Internally factored as `host.recv_one` (which surfaces
    /// handshake-shaped events directly) followed by
    /// [`Self::process_plaintext`] on the
    /// [`HostEvent::DatagramDelivered`] arm; the multi-protocol mux
    /// reuses the latter directly.
    ///
    /// # Errors
    ///
    /// Underlying socket failures propagate as `Err`; per-peer issues
    /// surface as [`RendezvousEvent::Rejected`].
    #[must_use]
    pub fn recv_one(self, ephemeral_seed: [u8; 32]) -> Io<Error, (Self, RendezvousEvent)> {
        let Self { host } = self;
        host.recv_one(ephemeral_seed)
            .flat_map(move |(host, host_event)| handle_host_event(host, host_event))
    }

    /// React to a single freshly-decrypted plaintext datagram from
    /// `addr`.  Performs only protocol-level work: decoding the
    /// rendezvous frame, auto-replying `OBSERVE_REQ` / forwarding
    /// `PUNCH_REQ` / firing a punch on `PUNCH_FORWARD`, and
    /// surfacing the corresponding [`RendezvousEvent`].  Socket-
    /// level dispatch (handshake progress, decrypt failure, etc.)
    /// happens in [`Self::recv_one`] before this method is called,
    /// so callers wiring this up directly (e.g. the multi-protocol
    /// mux after peeling its kind byte) do not need to handle those
    /// events here.
    ///
    /// `plaintext` is the decoded inner Noise plaintext; the
    /// standalone [`Self::recv_one`] passes it straight through, the
    /// mux passes its sub-slice after peeling its 1-byte kind tag.
    ///
    /// Standalone callers should use this method.  Multi-protocol
    /// mux callers whose envelope prepends a kind byte to every
    /// outbound plaintext should use
    /// [`Self::process_plaintext_with_wrap`] to share their kind-
    /// byte prefix logic with the auto-reply / auto-forward paths
    /// inside this method.
    ///
    /// # Errors
    ///
    /// Underlying socket failures from auto-replies / auto-forwards
    /// propagate as `Err`; malformed frames surface as
    /// [`RendezvousEvent::Rejected`].
    #[must_use]
    pub fn process_plaintext(
        self,
        addr: UdpAddr,
        plaintext: &[u8],
    ) -> Io<Error, (Self, RendezvousEvent)> {
        self.process_plaintext_with_wrap(addr, plaintext, identity_wrap)
    }

    /// Variant of [`Self::process_plaintext`] that applies `wrap` to
    /// the encoded auto-reply / auto-forward frame bytes before
    /// handing them to [`Host::send`].  The standalone
    /// `process_plaintext` calls this with an identity wrap; the
    /// multi-protocol mux calls it with a wrap that prepends its
    /// outer `KIND_RENDEZVOUS` envelope byte, so the mux does not
    /// need to re-implement the rendezvous dispatch.
    ///
    /// `wrap` is `FnOnce` because at most one Noise-wrapped send
    /// fires per call.  The bare-datagram punch fired on
    /// `PUNCH_FORWARD` goes through [`Host::send_raw`] (no Noise,
    /// no kind byte) and bypasses the wrap entirely.
    ///
    /// # Errors
    ///
    /// Same set as [`Self::process_plaintext`].
    #[must_use]
    pub fn process_plaintext_with_wrap<W>(
        self,
        addr: UdpAddr,
        plaintext: &[u8],
        wrap: W,
    ) -> Io<Error, (Self, RendezvousEvent)>
    where
        W: FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static,
    {
        let Self { host } = self;
        handle_datagram(host, addr, plaintext, wrap)
    }
}

/// Identity wrap used by the standalone path: send the rendezvous
/// frame bytes as-is.
fn identity_wrap(bytes: Vec<u8>) -> Vec<u8> {
    bytes
}

fn send_observe_req(node: RendezvousNode, server_addr: UdpAddr) -> Io<Error, RendezvousNode> {
    let RendezvousNode { host } = node;
    Io::suspend(move || encode(&Frame::ObserveReq)).flat_map(move |bytes| {
        host.send(server_addr, bytes)
            .map(move |host| RendezvousNode { host })
    })
}

fn drain_for_observe_response<F>(
    node: RendezvousNode,
    server_addr: UdpAddr,
    seed_factory: F,
) -> Io<Error, (RendezvousNode, UdpAddr)>
where
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    let seed = seed_factory();
    let factory_for_recurse = seed_factory;
    node.recv_one(seed).flat_map(move |(node, ev)| match ev {
        RendezvousEvent::ObserveResponseReceived { from, observed } if from == server_addr => {
            Io::pure((node, observed))
        }
        RendezvousEvent::HandshakeProgress { .. }
        | RendezvousEvent::HandshakeComplete { .. }
        | RendezvousEvent::ObserveRequestReceived { .. }
        | RendezvousEvent::ObserveResponseReceived { .. }
        | RendezvousEvent::PunchRequestReceived { .. }
        | RendezvousEvent::PunchForwardReceived { .. }
        | RendezvousEvent::RelayForwarded { .. }
        | RendezvousEvent::RelayReceived { .. }
        | RendezvousEvent::RelayFailed { .. }
        | RendezvousEvent::Rejected { .. } => {
            drain_for_observe_response(node, server_addr, factory_for_recurse)
        }
    })
}

fn handle_host_event(host: Host, event: HostEvent) -> Io<Error, (RendezvousNode, RendezvousEvent)> {
    match event {
        HostEvent::HandshakeProgress { addr } => Io::pure((
            RendezvousNode { host },
            RendezvousEvent::HandshakeProgress { addr },
        )),
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
            remote_peer_id,
        } => Io::pure((
            RendezvousNode { host },
            RendezvousEvent::HandshakeComplete {
                addr,
                remote_static,
                remote_peer_id,
            },
        )),
        HostEvent::Rejected { addr, reason } => Io::pure((
            RendezvousNode { host },
            RendezvousEvent::Rejected { addr, reason },
        )),
        HostEvent::DatagramDelivered { addr, plaintext } => {
            RendezvousNode { host }.process_plaintext(addr, &plaintext)
        }
    }
}

fn handle_datagram<W>(
    host: Host,
    addr: UdpAddr,
    plaintext: &[u8],
    wrap: W,
) -> Io<Error, (RendezvousNode, RendezvousEvent)>
where
    W: FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static,
{
    match decode(plaintext) {
        Err(
            e @ (Error::Io(_)
            | Error::InvalidProtocolId { .. }
            | Error::InvalidPeerId { .. }
            | Error::DatagramTooLarge { .. }
            | Error::NoiseDecrypt
            | Error::NoiseProtocol { .. }
            | Error::NoiseReplay { .. }
            | Error::RlncLayer { .. }
            | Error::PubsubProtocol { .. }
            | Error::HostState { .. }
            | Error::IdentityVerify { .. }),
        ) => {
            let _ = wrap;
            Io::pure((
                RendezvousNode { host },
                RendezvousEvent::Rejected {
                    addr,
                    reason: format!("rendezvous decode failed: {e}"),
                },
            ))
        }
        Ok(Frame::ObserveReq) => auto_reply_observe(host, addr, wrap),
        Ok(Frame::ObserveResp { observed }) => {
            let _ = wrap;
            Io::pure((
                RendezvousNode { host },
                RendezvousEvent::ObserveResponseReceived {
                    from: addr,
                    observed,
                },
            ))
        }
        Ok(Frame::PunchReq { target }) => auto_forward_punch(host, addr, target, wrap),
        Ok(Frame::PunchForward { initiator }) => {
            let _ = wrap;
            auto_send_punch(host, addr, initiator)
        }
        Ok(Frame::RelayDataReq { target, payload }) => {
            auto_forward_relay(host, addr, target, payload, wrap)
        }
        Ok(Frame::RelayDataDeliver {
            originator,
            payload,
        }) => {
            let _ = wrap;
            Io::pure((
                RendezvousNode { host },
                RendezvousEvent::RelayReceived {
                    from: addr,
                    originator,
                    payload,
                },
            ))
        }
        Ok(Frame::RelayFail { peer, reason }) => {
            let _ = wrap;
            Io::pure((
                RendezvousNode { host },
                RendezvousEvent::RelayFailed {
                    from: addr,
                    peer,
                    reason,
                },
            ))
        }
    }
}

fn auto_reply_observe<W>(
    host: Host,
    addr: UdpAddr,
    wrap: W,
) -> Io<Error, (RendezvousNode, RendezvousEvent)>
where
    W: FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static,
{
    let frame = Frame::ObserveResp { observed: addr };
    Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
        host.send(addr, wrap(bytes)).map(move |host| {
            (
                RendezvousNode { host },
                RendezvousEvent::ObserveRequestReceived { from: addr },
            )
        })
    })
}

/// Server-side: relay an inbound `PUNCH_REQ` to `target` if we
/// have an established session with it.  Surfaces a
/// [`RendezvousEvent::PunchRequestReceived`] either way.
fn auto_forward_punch<W>(
    host: Host,
    from: UdpAddr,
    target: UdpAddr,
    wrap: W,
) -> Io<Error, (RendezvousNode, RendezvousEvent)>
where
    W: FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static,
{
    if host.is_established(target) {
        let frame = Frame::PunchForward { initiator: from };
        Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
            host.send(target, wrap(bytes)).map(move |host| {
                (
                    RendezvousNode { host },
                    RendezvousEvent::PunchRequestReceived {
                        from,
                        target,
                        forwarded: true,
                    },
                )
            })
        })
    } else {
        let _ = wrap;
        Io::pure((
            RendezvousNode { host },
            RendezvousEvent::PunchRequestReceived {
                from,
                target,
                forwarded: false,
            },
        ))
    }
}

/// Client-side: fire a 1-byte bare UDP datagram at `initiator`
/// using [`Host::send_raw`].  The deliberately undersized payload
/// ensures the receiver's `try_responder_msg1` rejects it without
/// starting a half-handshake; the only side-effect we want is the
/// NAT mapping our outbound packet creates.
fn auto_send_punch(
    host: Host,
    from: UdpAddr,
    initiator: UdpAddr,
) -> Io<Error, (RendezvousNode, RendezvousEvent)> {
    host.send_raw(initiator, vec![PUNCH_BYTE]).map(move |host| {
        (
            RendezvousNode { host },
            RendezvousEvent::PunchForwardReceived { from, initiator },
        )
    })
}

/// Server-side: forward a `RELAY_DATA_REQ` payload from `from` to
/// `target` if we have an established session with `target`,
/// otherwise reply to the requester with `RELAY_FAIL`.  Either way,
/// surface a [`RendezvousEvent::RelayForwarded`] with the
/// `forwarded` flag set accordingly.
fn auto_forward_relay<W>(
    host: Host,
    from: UdpAddr,
    target: UdpAddr,
    payload: Vec<u8>,
    wrap: W,
) -> Io<Error, (RendezvousNode, RendezvousEvent)>
where
    W: FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static,
{
    let payload_len = payload.len();
    if host.is_established(target) {
        let frame = Frame::RelayDataDeliver {
            originator: from,
            payload,
        };
        Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
            host.send(target, wrap(bytes)).map(move |host| {
                (
                    RendezvousNode { host },
                    RendezvousEvent::RelayForwarded {
                        from,
                        target,
                        forwarded: true,
                        payload_len,
                    },
                )
            })
        })
    } else {
        let frame = Frame::RelayFail {
            peer: target,
            reason: format!("relay: no established session with {target}"),
        };
        Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
            host.send(from, wrap(bytes)).map(move |host| {
                (
                    RendezvousNode { host },
                    RendezvousEvent::RelayForwarded {
                        from,
                        target,
                        forwarded: false,
                        payload_len,
                    },
                )
            })
        })
    }
}

/// The bare byte we send as a punch.  Any single byte works; we use
/// `0x00` as a stable marker.  Receivers see this as a malformed
/// datagram (length 1, not [`MESSAGE_1_LEN`]) and surface
/// [`HostEvent::Rejected`].
///
/// [`MESSAGE_1_LEN`]: libp2p_cat_noise::MESSAGE_1_LEN
/// [`HostEvent::Rejected`]: libp2p_cat_host::HostEvent::Rejected
const PUNCH_BYTE: u8 = 0x00;
