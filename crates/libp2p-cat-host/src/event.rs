//! Outcomes of a single [`crate::Host::recv_one`] call.
//!
//! Transient peer issues (malformed handshake, decrypt failure,
//! replay, fresh datagram from an unknown source that's not a valid
//! `msg1`) surface as the [`HostEvent::Rejected`] variant rather than
//! `Result::Err`, so a long-running event loop never has to disambiguate
//! between fatal I/O failures and a single misbehaving peer.

use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::UdpAddr;

/// What happened while processing one inbound datagram.
#[derive(Clone, Debug)]
#[must_use]
pub enum HostEvent {
    /// A handshake step succeeded but the connection is not yet
    /// established.  Either we just sent `msg2` in response to a
    /// fresh `msg1`, or we just sent `msg3` and are waiting on the
    /// peer to confirm receipt by sending us a transport datagram.
    HandshakeProgress {
        /// Address of the peer the handshake is with.
        addr: UdpAddr,
    },

    /// A handshake completed.  The peer is now in the host's
    /// `established` table and a [`StaticPublicKey`] authenticated
    /// during the handshake is reported.
    HandshakeComplete {
        /// Address of the peer.
        addr: UdpAddr,
        /// The peer's authenticated long-lived X25519 static public
        /// key.  Combine with an out-of-band identity binding (e.g.
        /// the libp2p signed-Noise-extension, deferred for v1) to
        /// resolve a [`libp2p_cat_types::PeerId`].
        remote_static: StaticPublicKey,
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
