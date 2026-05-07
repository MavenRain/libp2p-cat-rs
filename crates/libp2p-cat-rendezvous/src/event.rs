//! Outcomes surfaced by [`crate::RendezvousNode::recv_one`].
//!
//! Pass-through variants carry the same shape as their
//! [`HostEvent`](libp2p_cat_host::HostEvent) sources; rendezvous-
//! specific variants describe RPC-level events.  Auto-replies
//! (`OBSERVE_RESP` after an `OBSERVE_REQ`) are handled inside
//! `recv_one` *before* the corresponding "received" event is
//! emitted, so a caller never has to ack inbound RPCs by hand.

use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::{PeerId, UdpAddr};

/// What happened during one [`crate::RendezvousNode::recv_one`] step.
#[derive(Clone, Debug)]
#[must_use]
pub enum RendezvousEvent {
    /// Pass-through from
    /// [`HostEvent::HandshakeProgress`](libp2p_cat_host::HostEvent::HandshakeProgress).
    HandshakeProgress {
        /// Address of the peer the handshake is with.
        addr: UdpAddr,
    },

    /// Pass-through from
    /// [`HostEvent::HandshakeComplete`](libp2p_cat_host::HostEvent::HandshakeComplete).
    HandshakeComplete {
        /// Address of the peer.
        addr: UdpAddr,
        /// The peer's authenticated long-lived X25519 static public
        /// key.
        remote_static: StaticPublicKey,
        /// The peer's libp2p-compatible [`PeerId`], derived from the
        /// verified `SignedStaticKey` trailer in the handshake.
        remote_peer_id: PeerId,
    },

    /// A peer asked us for an `OBSERVE` reply.  We have already sent
    /// the response (carrying `from`); this event is purely
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
    /// `forwarded` is true we sent the corresponding `PUNCH_FORWARD`
    /// to `target` over an established session; otherwise `target`
    /// was not established and the request was dropped.
    PunchRequestReceived {
        /// Address of the peer that asked.
        from: UdpAddr,
        /// Address of the peer the requester wants to reach.
        target: UdpAddr,
        /// Whether the server actually forwarded the request.
        forwarded: bool,
    },

    /// A rendezvous server forwarded a punch request originating at
    /// `initiator`.  We have already fired a 1-byte bare-datagram
    /// punch at `initiator` to open our NAT mapping; this event is
    /// purely informational.
    PunchForwardReceived {
        /// Address of the rendezvous server that forwarded the
        /// request.
        from: UdpAddr,
        /// Address of the peer that originated the punch request.
        initiator: UdpAddr,
    },

    /// A peer asked us (acting as a relay server) to forward a
    /// `RELAY_DATA` payload to `target`.  If `forwarded` is true we
    /// have already sent the corresponding `RELAY_DATA` to `target`
    /// and the local action is complete; otherwise `target` was not
    /// established and a `RELAY_FAIL` was sent back to the
    /// requester.
    RelayForwarded {
        /// Address of the peer that asked.
        from: UdpAddr,
        /// Address of the peer the requester wanted to reach.
        target: UdpAddr,
        /// Whether the relay actually forwarded the payload.
        forwarded: bool,
        /// Number of payload bytes the relay handled.
        payload_len: usize,
    },

    /// A relay server forwarded a `RELAY_DATA` payload to us.
    /// `originator` is the address the relay observed the payload
    /// arriving from; the caller treats `payload` as opaque
    /// application bytes (or layers a separate protocol on top —
    /// the relay sees these bytes in plaintext).
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
    /// previous `RELAY_DATA` to `peer`.
    RelayFailed {
        /// Address of the relay server that replied.
        from: UdpAddr,
        /// Address the relay attempt targeted.
        peer: UdpAddr,
        /// UTF-8 description of why the forward failed.
        reason: String,
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
