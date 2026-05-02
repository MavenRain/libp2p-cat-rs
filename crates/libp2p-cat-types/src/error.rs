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
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::InvalidProtocolId { .. }
            | Self::InvalidPeerId { .. }
            | Self::DatagramTooLarge { .. } => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
