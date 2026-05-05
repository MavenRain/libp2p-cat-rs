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

    /// Receive one event.  Inbound `OBSERVE_REQ`s are auto-answered,
    /// inbound `PUNCH_REQ`s are auto-forwarded (when the target is
    /// established), and inbound `PUNCH_FORWARD`s auto-fire a bare
    /// punch datagram at the original initiator, all *before* the
    /// corresponding "received" variant is emitted.
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
        HostEvent::DatagramDelivered { addr, plaintext } => handle_datagram(host, addr, &plaintext),
    }
}

fn handle_datagram(
    host: Host,
    addr: UdpAddr,
    plaintext: &[u8],
) -> Io<Error, (RendezvousNode, RendezvousEvent)> {
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
        ) => Io::pure((
            RendezvousNode { host },
            RendezvousEvent::Rejected {
                addr,
                reason: format!("rendezvous decode failed: {e}"),
            },
        )),
        Ok(Frame::ObserveReq) => auto_reply_observe(host, addr),
        Ok(Frame::ObserveResp { observed }) => Io::pure((
            RendezvousNode { host },
            RendezvousEvent::ObserveResponseReceived {
                from: addr,
                observed,
            },
        )),
        Ok(Frame::PunchReq { target }) => auto_forward_punch(host, addr, target),
        Ok(Frame::PunchForward { initiator }) => auto_send_punch(host, addr, initiator),
    }
}

fn auto_reply_observe(host: Host, addr: UdpAddr) -> Io<Error, (RendezvousNode, RendezvousEvent)> {
    let frame = Frame::ObserveResp { observed: addr };
    Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
        host.send(addr, bytes).map(move |host| {
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
fn auto_forward_punch(
    host: Host,
    from: UdpAddr,
    target: UdpAddr,
) -> Io<Error, (RendezvousNode, RendezvousEvent)> {
    if host.is_established(target) {
        let frame = Frame::PunchForward { initiator: from };
        Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
            host.send(target, bytes).map(move |host| {
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

/// The bare byte we send as a punch.  Any single byte works; we use
/// `0x00` as a stable marker.  Receivers see this as a malformed
/// datagram (length 1, not [`MESSAGE_1_LEN`]) and surface
/// [`HostEvent::Rejected`].
///
/// [`MESSAGE_1_LEN`]: libp2p_cat_noise::MESSAGE_1_LEN
/// [`HostEvent::Rejected`]: libp2p_cat_host::HostEvent::Rejected
const PUNCH_BYTE: u8 = 0x00;
