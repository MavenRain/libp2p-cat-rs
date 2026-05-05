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
