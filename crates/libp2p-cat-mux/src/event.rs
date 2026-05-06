//! Outcomes surfaced by [`crate::MultiProtocolNode::recv_one`].
//!
//! Flat-enumerated rather than nested-by-protocol so callers can
//! match without first branching on a protocol tag.  Pass-through
//! variants carry the same shape as their
//! [`HostEvent`](libp2p_cat_host::HostEvent) sources; protocol-
//! specific variants describe the inbound RPC after the mux's outer
//! kind-byte envelope has been peeled.

use libp2p_cat_kad::NodeId;
use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_pubsub::Topic;
use libp2p_cat_types::{PeerId, UdpAddr};

/// What happened during one [`crate::MultiProtocolNode::recv_one`]
/// step.
#[derive(Debug)]
#[must_use]
pub enum MultiProtocolEvent {
    /// Pass-through from
    /// [`HostEvent::HandshakeProgress`](libp2p_cat_host::HostEvent::HandshakeProgress).
    HandshakeProgress {
        /// Address of the peer the handshake is with.
        addr: UdpAddr,
    },

    /// Pass-through from
    /// [`HostEvent::HandshakeComplete`](libp2p_cat_host::HostEvent::HandshakeComplete),
    /// augmented with the peer's Kademlia [`NodeId`] (derived from
    /// the verified [`PeerId`]).  The mux's local routing table has
    /// already been updated to include this peer.
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

    /// A raw app-data plaintext arrived (the [`crate::KIND_APP`]
    /// path).
    AppData {
        /// Source peer address.
        addr: UdpAddr,
        /// The application bytes (kind byte already stripped).
        bytes: Vec<u8>,
    },

    /// A pubsub piece was absorbed into a local decoder but the
    /// generation is not yet complete.
    PubsubAbsorbed {
        /// Source peer address.
        addr: UdpAddr,
        /// Topic the piece belonged to.
        topic: Topic,
    },

    /// A pubsub piece completed a topic decoder.
    PubsubDelivered {
        /// Source peer address.
        addr: UdpAddr,
        /// Topic the message was delivered on.
        topic: Topic,
        /// Reconstructed original bytes.
        data: Vec<u8>,
    },

    /// A pubsub piece was added to a local recoder, recoded, and
    /// fanned out to `fanout_count` peers.
    PubsubRelayed {
        /// Address that delivered the inbound piece.
        from: UdpAddr,
        /// Topic the piece belonged to.
        topic: Topic,
        /// Number of peers the recoded piece was forwarded to.
        fanout_count: usize,
    },

    /// A peer sent us a `PING` request.  We have already sent a
    /// `PING_RESP` back; this event is purely informational.
    KadPingRequestReceived {
        /// Address of the peer that sent the PING.
        from: UdpAddr,
    },

    /// A peer responded to one of our `PING` requests.
    KadPingResponseReceived {
        /// Address of the responding peer.
        from: UdpAddr,
    },

    /// A peer sent us a `FIND_NODE` request and we have already
    /// sent our reply.
    KadFindNodeRequestReceived {
        /// Address of the requesting peer.
        from: UdpAddr,
        /// Target [`NodeId`] the peer asked for closest peers to.
        target: NodeId,
        /// Number of peers we returned in our auto-reply.
        returned: usize,
    },

    /// A peer responded to one of our `FIND_NODE` requests.  The
    /// inbound peers have already been inserted into the local
    /// routing table.
    KadFindNodeResponseReceived {
        /// Address of the responding peer.
        from: UdpAddr,
        /// Peers the responder reported as closest to the original
        /// target.
        peers: Vec<(NodeId, UdpAddr)>,
    },

    /// A peer asked us for an `OBSERVE` reply.  We have already
    /// sent the response (carrying `from`); this event is purely
    /// informational.
    ObserveRequestReceived {
        /// Address of the peer that asked.
        from: UdpAddr,
    },

    /// A rendezvous server responded to one of our `OBSERVE_REQ`
    /// calls.
    ObserveResponseReceived {
        /// Address of the responding server.
        from: UdpAddr,
        /// The address the server says it observed our packet
        /// arriving from.
        observed: UdpAddr,
    },

    /// A peer (acting as a client) asked us (acting as a rendezvous
    /// server) to relay a punch request to `target`.  If
    /// `forwarded` is true we sent the corresponding
    /// `PUNCH_FORWARD` to `target`; otherwise `target` was not
    /// established and the request was dropped.
    PunchRequestReceived {
        /// Address of the peer that asked.
        from: UdpAddr,
        /// Address of the peer the requester wants to reach.
        target: UdpAddr,
        /// Whether the server actually forwarded the request.
        forwarded: bool,
    },

    /// A rendezvous server forwarded a punch request originating
    /// at `initiator`.  We have already fired a 1-byte bare-
    /// datagram punch at `initiator`.
    PunchForwardReceived {
        /// Address of the rendezvous server that forwarded the
        /// request.
        from: UdpAddr,
        /// Address of the peer that originated the punch request.
        initiator: UdpAddr,
    },

    /// An inbound datagram was rejected.  Covers decrypt failures,
    /// unknown kind bytes, malformed protocol frames, and
    /// authenticator-tag rejections.  Per-peer issues surface here
    /// rather than as `Result::Err` so a long-running event loop
    /// survives misbehaving peers.
    Rejected {
        /// Source peer address.
        addr: UdpAddr,
        /// Description of the rejection.
        reason: String,
    },
}
