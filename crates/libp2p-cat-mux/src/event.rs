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

    /// A pubsub piece verified but was linearly dependent on pieces
    /// this relay had already absorbed, so it was neither stored nor
    /// re-broadcast (the relay rank gate; see
    /// `libp2p_cat_pubsub::MuxEvent::PubsubRedundant`).
    PubsubRedundant {
        /// Source peer address.
        addr: UdpAddr,
        /// Topic the piece belonged to.
        topic: Topic,
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

    /// A peer asked us (acting as a relay server) to forward a
    /// `RELAY_DATA_REQ` payload to `target`.  If `forwarded` is
    /// true the relay actually delivered the payload to `target`;
    /// otherwise a `RELAY_FAIL` was sent back to the requester.
    RelayForwarded {
        /// Address of the peer that asked.
        from: UdpAddr,
        /// Address the relay forwarded to (or tried to).
        target: UdpAddr,
        /// Whether the relay actually delivered the payload.
        forwarded: bool,
        /// Number of payload bytes the relay handled.
        payload_len: usize,
    },

    /// A relay server forwarded an opaque payload from
    /// `originator` to us.
    RelayReceived {
        /// Address of the relay server that forwarded the payload.
        from: UdpAddr,
        /// Address of the peer that originated the payload, as
        /// observed by the relay server.
        originator: UdpAddr,
        /// Opaque forwarded bytes.
        payload: Vec<u8>,
    },

    /// A relay server replied that it could not forward our
    /// previous `RELAY_DATA_REQ` to `peer`.
    RelayFailed {
        /// Address of the relay server that replied.
        from: UdpAddr,
        /// Address the relay attempt targeted.
        peer: UdpAddr,
        /// UTF-8 description of why the forward failed.
        reason: String,
    },

    /// A `KIND_RPC` plaintext arrived.  The mux peels the kind byte
    /// and surfaces the remaining bytes (a serialized
    /// [`tarpc_cat::protocol::Envelope`](https://docs.rs/tarpc-cat))
    /// without parsing them; callers using
    /// [`libp2p-cat-rpc`](https://crates.io/crates/libp2p-cat-rpc)
    /// decode the body and dispatch.
    RpcDatagram {
        /// Source peer address.
        peer: UdpAddr,
        /// Bytes after the `KIND_RPC` envelope byte (a serialized
        /// JSON envelope).
        body: Vec<u8>,
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
