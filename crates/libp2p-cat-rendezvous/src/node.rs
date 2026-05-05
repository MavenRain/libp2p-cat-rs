//! [`RendezvousNode`]: a [`Host`] that auto-answers inbound
//! `OBSERVE_REQ` frames and exposes a synchronous
//! [`RendezvousNode::observe_self`] method to ask a remote
//! rendezvous what address it sees this node coming from.
//!
//! Pass 5 keeps the surface deliberately thin: every node plays
//! both client and server roles symmetrically, the way
//! [`KademliaNode`](libp2p_cat_kad::KademliaNode) plays both PING
//! roles.  Pass 6 will add `PUNCH` coordination on top of this.

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

    /// Receive one event.  Inbound `OBSERVE_REQ`s are auto-answered
    /// before the corresponding "received" variant is emitted.
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
        Err(e) => Io::pure((
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
