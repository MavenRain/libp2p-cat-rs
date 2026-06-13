//! Outcomes of a single [`crate::Host::recv_one`] call.
//!
//! Transient peer issues (malformed handshake, decrypt failure,
//! replay, fresh datagram from an unknown source that's not a valid
//! `msg1`) surface as the [`HostEvent::Rejected`] variant rather than
//! `Result::Err`, so a long-running event loop never has to disambiguate
//! between fatal I/O failures and a single misbehaving peer.

use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::{PeerId, UdpAddr};

/// What happened while processing one inbound datagram.
#[derive(Clone, Debug)]
#[must_use]
pub enum HostEvent {
    /// A handshake step succeeded but the connection is not yet
    /// established.  One of: we answered a bare `msg1` with a
    /// stateless cookie challenge, we answered a cookie challenge by
    /// re-sending `msg1 || cookie`, we sent `msg2` in response to a
    /// cookie-validated `msg1`, or we sent `msg3` and are waiting on
    /// the peer to confirm receipt by sending us a transport
    /// datagram.
    HandshakeProgress {
        /// Address of the peer the handshake is with.
        addr: UdpAddr,
    },

    /// A handshake completed and the peer's
    /// [`libp2p_cat_identity::SignedStaticKey`] binding verified
    /// against the X25519 static key Noise authenticated.  The peer
    /// is now in the host's `established` table.
    ///
    /// [`libp2p_cat_identity::SignedStaticKey`]: https://docs.rs/libp2p-cat-identity
    HandshakeComplete {
        /// Address of the peer.
        addr: UdpAddr,
        /// The peer's authenticated long-lived X25519 static public
        /// key.
        remote_static: StaticPublicKey,
        /// The peer's libp2p-compatible [`PeerId`], derived from the
        /// Ed25519 public key in the verified
        /// `SignedStaticKey` trailer.
        remote_peer_id: PeerId,
    },

    /// A post-handshake plaintext datagram arrived.
    DatagramDelivered {
        /// Source peer address.
        addr: UdpAddr,
        /// The decrypted plaintext.
        plaintext: Vec<u8>,
    },

    /// An inbound datagram was rejected.  The host's connection
    /// state is unchanged.
    Rejected {
        /// Source address (informational; may be spoofed for fresh
        /// peers).
        addr: UdpAddr,
        /// Description of why the datagram was rejected.
        reason: String,
    },
}
