//! Workspace-wide error type.
//!
//! Every fallible operation across the `libp2p-cat-rs` crates returns
//! this [`Error`].  Layered crates add their own variants by upstreaming
//! changes here rather than introducing per-crate error types.

use core::fmt;

/// The error type for every crate in the `libp2p-cat-rs` workspace.
#[derive(Debug)]
pub enum Error {
    /// An I/O error from the underlying socket or address parser.
    Io(std::io::Error),

    /// A protocol identifier failed validation.
    InvalidProtocolId {
        /// The offending input string.
        input: String,
    },

    /// A peer identifier could not be constructed from the supplied
    /// public-key bytes.
    InvalidPeerId {
        /// Description of the failure.
        reason: String,
    },

    /// A datagram exceeded the configured maximum send size.
    DatagramTooLarge {
        /// The size that was attempted, in bytes.
        attempted: usize,
        /// The configured maximum, in bytes.
        maximum: usize,
    },

    /// A Noise handshake or transport message could not be authenticated
    /// or decrypted.  Carries no detail by design: the AEAD failure
    /// reason is uniformly "tag mismatch" and any leak of additional
    /// state risks giving an attacker an oracle.
    NoiseDecrypt,

    /// A Noise message violated the protocol: wrong length, wrong
    /// state, or malformed token sequence.
    NoiseProtocol {
        /// Description of the violation.
        reason: String,
    },

    /// A Noise transport datagram was rejected by the replay window:
    /// either the nonce was below the window's lower edge, or it had
    /// already been seen.
    NoiseReplay {
        /// The rejected nonce.
        nonce: u64,
    },

    /// An error from the RLNC encoding / decoding / gossip layer.
    /// `rlnc-cat-rs` types cannot be wrapped directly here without
    /// breaking this crate's no-`comp-cat-rs`-dep invariant, so the
    /// error is stringified at the boundary.
    RlncLayer {
        /// Description of the underlying RLNC error.
        reason: String,
    },

    /// A pubsub-layer protocol violation: malformed frame, unknown
    /// peer, unregistered topic, or any other shape mismatch.
    PubsubProtocol {
        /// Description of the violation.
        reason: String,
    },

    /// A host-layer state violation: send to an address with no
    /// established connection, dial of an address with an in-flight
    /// handshake already, or any other shape mismatch in the host's
    /// connection bookkeeping.
    HostState {
        /// Description of the violation.
        reason: String,
    },

    /// An identity-layer verification failure: malformed Ed25519
    /// public key bytes, signature shape mismatch, signature did not
    /// verify against the claimed public key, or wire-format
    /// truncation.
    IdentityVerify {
        /// Description of the failure.
        reason: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidProtocolId { input } => {
                write!(f, "invalid protocol id: {input:?}")
            }
            Self::InvalidPeerId { reason } => {
                write!(f, "invalid peer id: {reason}")
            }
            Self::DatagramTooLarge { attempted, maximum } => write!(
                f,
                "datagram too large: attempted {attempted} bytes, maximum {maximum}"
            ),
            Self::NoiseDecrypt => f.write_str("noise decryption failed"),
            Self::NoiseProtocol { reason } => write!(f, "noise protocol violation: {reason}"),
            Self::NoiseReplay { nonce } => {
                write!(f, "noise replay or out-of-window datagram: nonce {nonce}")
            }
            Self::RlncLayer { reason } => write!(f, "rlnc layer error: {reason}"),
            Self::PubsubProtocol { reason } => {
                write!(f, "pubsub protocol violation: {reason}")
            }
            Self::HostState { reason } => write!(f, "host state violation: {reason}"),
            Self::IdentityVerify { reason } => {
                write!(f, "identity verification failed: {reason}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::InvalidProtocolId { .. }
            | Self::InvalidPeerId { .. }
            | Self::DatagramTooLarge { .. }
            | Self::NoiseDecrypt
            | Self::NoiseProtocol { .. }
            | Self::NoiseReplay { .. }
            | Self::RlncLayer { .. }
            | Self::PubsubProtocol { .. }
            | Self::HostState { .. }
            | Self::IdentityVerify { .. } => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
