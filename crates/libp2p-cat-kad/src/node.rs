//! [`KademliaNode`]: a [`Host`] paired with a [`RoutingTable`] that
//! auto-answers inbound `PING` and `FIND_NODE` RPCs.
//!
//! Pass 2 keeps the surface deliberately thin:
//!
//! - [`KademliaNode::dial`] and [`KademliaNode::recv_one`] mirror the
//!   matching [`Host`] methods; every received event is also
//!   translated into a [`KadEvent`] for the caller's loop.
//! - [`KademliaNode::ping`] / [`KademliaNode::find_node`] send
//!   single-shot RPCs; the corresponding response surfaces later as
//!   [`KadEvent::PingResponseReceived`] /
//!   [`KadEvent::FindNodeResponseReceived`].
//! - On every observation (handshake completion, inbound RPC), the
//!   peer is auto-inserted into the local routing table.
//!
//! Iterative lookup driven by `FIND_NODE` responses is deferred to
//! pass 3.

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_types::{Error, PeerId, UdpAddr};

use crate::codec::{Frame, decode, encode};
use crate::event::KadEvent;
use crate::node_id::NodeId;
use crate::routing_table::RoutingTable;

/// A [`Host`] augmented with a Kademlia [`RoutingTable`] and
/// `PING` / `FIND_NODE` auto-answer logic.
#[must_use]
pub struct KademliaNode {
    host: Host,
    table: RoutingTable,
}

impl KademliaNode {
    /// Build a node from a [`Host`] and a replication factor `k`.
    /// The local [`NodeId`] is derived from the host's
    /// [`PeerId`](libp2p_cat_host::Host::peer_id).
    pub fn new(host: Host, k: usize) -> Self {
        let self_node_id = NodeId::from_peer_id(host.peer_id());
        Self {
            host,
            table: RoutingTable::new(self_node_id, k),
        }
    }

    /// Local libp2p-compatible [`PeerId`].
    pub fn peer_id(&self) -> &PeerId {
        self.host.peer_id()
    }

    /// Local Kademlia [`NodeId`].
    pub fn node_id(&self) -> &NodeId {
        self.table.self_id()
    }

    /// Borrow the underlying [`Host`].
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Borrow the local routing table.
    pub fn routing_table(&self) -> &RoutingTable {
        &self.table
    }

    /// Local UDP address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot report the local address.
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
        let Self { host, table } = self;
        host.dial(addr, ephemeral_seed)
            .map(move |host| Self { host, table })
    }

    /// Send a `PING_REQ` to an already-established peer.  The
    /// corresponding response will surface later as
    /// [`KadEvent::PingResponseReceived`].
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `peer` is not established.
    /// - Noise / UDP errors propagate transparently.
    #[must_use]
    pub fn ping(self, peer: UdpAddr) -> Io<Error, Self> {
        send_frame(self, peer, Frame::PingReq)
    }

    /// Send a `FIND_NODE_REQ` to an already-established peer asking
    /// for up to `k` peers closest to `target`.  The corresponding
    /// response will surface later as
    /// [`KadEvent::FindNodeResponseReceived`].
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `peer` is not established.
    /// - Noise / UDP errors propagate transparently.
    #[must_use]
    pub fn find_node(self, peer: UdpAddr, target: NodeId) -> Io<Error, Self> {
        send_frame(self, peer, Frame::FindNodeReq { target })
    }

    /// Receive one event.  Inbound `PING` and `FIND_NODE` requests
    /// are auto-answered before the corresponding "Received" variant
    /// is emitted; observed peers are auto-inserted into the routing
    /// table.
    ///
    /// # Errors
    ///
    /// Underlying socket failures propagate as `Err`; per-peer issues
    /// surface as [`KadEvent::Rejected`].
    #[must_use]
    pub fn recv_one(self, ephemeral_seed: [u8; 32]) -> Io<Error, (Self, KadEvent)> {
        let Self { host, table } = self;
        host.recv_one(ephemeral_seed)
            .flat_map(move |(host, host_event)| handle_host_event(host, table, host_event))
    }
}

fn send_frame(node: KademliaNode, peer: UdpAddr, frame: Frame) -> Io<Error, KademliaNode> {
    let KademliaNode { host, table } = node;
    Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
        host.send(peer, bytes)
            .map(move |host| KademliaNode { host, table })
    })
}

fn handle_host_event(
    host: Host,
    table: RoutingTable,
    event: HostEvent,
) -> Io<Error, (KademliaNode, KadEvent)> {
    match event {
        HostEvent::HandshakeProgress { addr } => Io::pure((
            KademliaNode { host, table },
            KadEvent::HandshakeProgress { addr },
        )),
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
            remote_peer_id,
        } => {
            let remote_node_id = NodeId::from_peer_id(&remote_peer_id);
            let (table, _outcome) = table.insert(remote_node_id, addr);
            Io::pure((
                KademliaNode { host, table },
                KadEvent::HandshakeComplete {
                    addr,
                    remote_static,
                    remote_peer_id,
                    remote_node_id,
                },
            ))
        }
        HostEvent::Rejected { addr, reason } => Io::pure((
            KademliaNode { host, table },
            KadEvent::Rejected { addr, reason },
        )),
        HostEvent::DatagramDelivered { addr, plaintext } => {
            handle_datagram(host, table, addr, &plaintext)
        }
    }
}

fn handle_datagram(
    host: Host,
    table: RoutingTable,
    addr: UdpAddr,
    plaintext: &[u8],
) -> Io<Error, (KademliaNode, KadEvent)> {
    match decode(plaintext) {
        Err(e) => Io::pure((
            KademliaNode { host, table },
            KadEvent::Rejected {
                addr,
                reason: format!("kad decode failed: {e}"),
            },
        )),
        Ok(frame) => {
            // Auto-insert the peer into the routing table on every
            // observed RPC, gated by the host's verified PeerId so we
            // never insert spoofed entries.
            let table = match host.remote_peer_id_of(addr) {
                Some(peer_id) => {
                    let node_id = NodeId::from_peer_id(peer_id);
                    table.insert(node_id, addr).0
                }
                None => table,
            };
            dispatch_frame(host, table, addr, frame)
        }
    }
}

fn dispatch_frame(
    host: Host,
    table: RoutingTable,
    addr: UdpAddr,
    frame: Frame,
) -> Io<Error, (KademliaNode, KadEvent)> {
    match frame {
        Frame::PingReq => auto_reply_ping(host, table, addr),
        Frame::PingResp => Io::pure((
            KademliaNode { host, table },
            KadEvent::PingResponseReceived { from: addr },
        )),
        Frame::FindNodeReq { target } => auto_reply_find_node(host, table, addr, target),
        Frame::FindNodeResp { peers } => {
            // Insert every peer the responder advertised.  Pass 3
            // will filter on liveness here.
            let table = peers.iter().fold(table, |acc, (id, peer_addr)| {
                if id == acc.self_id() {
                    acc
                } else {
                    acc.insert(*id, *peer_addr).0
                }
            });
            Io::pure((
                KademliaNode { host, table },
                KadEvent::FindNodeResponseReceived { from: addr, peers },
            ))
        }
    }
}

fn auto_reply_ping(
    host: Host,
    table: RoutingTable,
    addr: UdpAddr,
) -> Io<Error, (KademliaNode, KadEvent)> {
    Io::suspend(move || encode(&Frame::PingResp)).flat_map(move |bytes| {
        host.send(addr, bytes).map(move |host| {
            (
                KademliaNode { host, table },
                KadEvent::PingRequestReceived { from: addr },
            )
        })
    })
}

fn auto_reply_find_node(
    host: Host,
    table: RoutingTable,
    addr: UdpAddr,
    target: NodeId,
) -> Io<Error, (KademliaNode, KadEvent)> {
    let peers = table.closest_to(&target, table.k());
    let returned = peers.len();
    let frame = Frame::FindNodeResp { peers };
    Io::suspend(move || encode(&frame)).flat_map(move |bytes| {
        host.send(addr, bytes).map(move |host| {
            (
                KademliaNode { host, table },
                KadEvent::FindNodeRequestReceived {
                    from: addr,
                    target,
                    returned,
                },
            )
        })
    })
}
