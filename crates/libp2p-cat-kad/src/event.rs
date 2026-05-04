//! Outcomes surfaced by [`crate::KademliaNode::recv_one`].
//!
//! Pass-through variants carry the same shape as their
//! [`HostEvent`](libp2p_cat_host::HostEvent) sources; Kad-specific
//! variants describe RPC-level events.  Auto-replies (`PING_RESP`
//! after a `PING_REQ`, `FIND_NODE_RESP` after a `FIND_NODE_REQ`) are
//! handled inside `recv_one` *before* the corresponding "received"
//! event is emitted, so a caller never has to ack inbound RPCs by
//! hand.

use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::{PeerId, UdpAddr};

use crate::node_id::NodeId;

/// What happened during one [`crate::KademliaNode::recv_one`] step.
#[derive(Clone, Debug)]
#[must_use]
pub enum KadEvent {
    /// Pass-through from
    /// [`HostEvent::HandshakeProgress`](libp2p_cat_host::HostEvent::HandshakeProgress).
    HandshakeProgress {
        /// Address of the peer the handshake is with.
        addr: UdpAddr,
    },

    /// Pass-through from
    /// [`HostEvent::HandshakeComplete`](libp2p_cat_host::HostEvent::HandshakeComplete),
    /// augmented with the peer's [`NodeId`] (derived from the
    /// verified [`PeerId`]).  The local routing table has already
    /// been updated to include this peer.
    HandshakeComplete {
        /// Address of the peer.
        addr: UdpAddr,
        /// The peer's authenticated long-lived X25519 static public
        /// key.
        remote_static: StaticPublicKey,
        /// The peer's libp2p-compatible [`PeerId`], derived from the
        /// verified `SignedStaticKey` trailer in the handshake.
        remote_peer_id: PeerId,
        /// The peer's Kademlia [`NodeId`], derived from
        /// `remote_peer_id`.
        remote_node_id: NodeId,
    },

    /// A peer sent us a `PING` request.  We have already sent a
    /// `PING_RESP` back; this event is purely informational.
    PingRequestReceived {
        /// Address of the peer that sent the PING.
        from: UdpAddr,
    },

    /// A peer responded to one of our `PING` requests.
    PingResponseReceived {
        /// Address of the responding peer.
        from: UdpAddr,
    },

    /// A peer sent us a `FIND_NODE` request and we have already sent
    /// our reply.  This event is purely informational.
    FindNodeRequestReceived {
        /// Address of the requesting peer.
        from: UdpAddr,
        /// Target [`NodeId`] the peer asked for closest peers to.
        target: NodeId,
        /// Number of peers we returned in our auto-reply.
        returned: usize,
    },

    /// A peer responded to one of our `FIND_NODE` requests.  The
    /// inbound peers have already been inserted into the local
    /// routing table; the caller can use them to drive an iterative
    /// lookup (deferred to pass 3).
    FindNodeResponseReceived {
        /// Address of the responding peer.
        from: UdpAddr,
        /// Peers the responder reported as closest to the original
        /// target.  May be empty.
        peers: Vec<(NodeId, UdpAddr)>,
    },

    /// An inbound datagram was rejected.  Per-peer issues (decrypt
    /// failure, malformed handshake, malformed RPC) surface as this
    /// event rather than as `Result::Err`, so a long-running event
    /// loop survives misbehaving peers.
    Rejected {
        /// Address of the peer.
        addr: UdpAddr,
        /// Description of why the datagram was rejected.
        reason: String,
    },
}
