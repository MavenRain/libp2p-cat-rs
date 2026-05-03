//! Wire-level extension of [`rlnc_cat_rs::auth::Authenticator`].
//!
//! [`WireAuthenticator`] adds four serialisation hooks so a
//! [`crate::PubsubMux`] can carry its commitment and tag over UDP
//! frames without knowing the concrete `Authenticator` type.  The
//! `*_from_bytes` hooks parse from the start of a buffer and report
//! how many bytes they consumed, so an authenticator with
//! variable-length tags (e.g. lattice-LHS, whose signature is a
//! length-prefixed `Z^m` vector) composes cleanly with one whose
//! tags are fixed width (e.g. [`KeyedHashAuthenticator`], 32 bytes).
//!
//! Implementations are provided for the three stock authenticators
//! in `rlnc-cat-rs`:
//!
//! - [`NullAuthenticator`]: commitment and tag are both unit and
//!   occupy zero wire bytes.  Suitable for tests and trust-the-peer
//!   deployments.
//! - [`KeyedHashAuthenticator`]: commitment and tag are each 32-byte
//!   BLAKE3 keyed-hash outputs.  Suitable for permissioned networks
//!   where every relay holds the shared key.
//! - [`LatticeHomomorphicAuthenticator`]: commitment is a 32-byte
//!   BLAKE3 fingerprint of `(pk, metadata, σ_originals)`; tag is a
//!   length-prefixed `Z^m` integer vector.  The combine operation
//!   is public, so a relay holding only the public transcript can
//!   re-tag recoded pieces without the source's secret key.
//!
//! [`PubsubAuth`] is the super-trait that bundles the bounds the mux
//! needs (`Authenticator`, `WireAuthenticator`, `Send + Sync +
//! 'static`, plus the same on the associated types).  Library users
//! generally do not implement it directly; a blanket impl picks it
//! up automatically once they implement [`Authenticator`] and
//! [`WireAuthenticator`].

use libp2p_cat_types::Error;
use rlnc_cat_rs::auth::{
    Authenticator, KeyedHashAuthenticator, KeyedHashCommitment, KeyedHashTag, NullAuthenticator,
};
use rlnc_cat_rs::lattice::ZVec;
use rlnc_cat_rs::lhs::{
    Commitment as LhsCommitment, LatticeHomomorphicAuthenticator, Signature as LhsSignature,
};

/// Width of the BLAKE3 fingerprint used by both
/// [`KeyedHashAuthenticator`] and [`LatticeHomomorphicAuthenticator`]
/// for their commitments.
const BLAKE3_FINGERPRINT_LEN: usize = 32;

/// Width of the keyed-BLAKE3 MAC tag emitted by
/// [`KeyedHashAuthenticator`].
const KEYED_HASH_TAG_LEN: usize = 32;

/// Width of the big-endian length prefix preceding an LHS
/// signature on the wire.
const LHS_TAG_LEN_PREFIX: usize = 4;

/// Width of one signed integer entry in an LHS signature when
/// serialised to bytes.
const LHS_TAG_ENTRY_LEN: usize = 8;

/// Extension of [`Authenticator`] that knows how to serialise its
/// associated types to and from a byte cursor.
pub trait WireAuthenticator: Authenticator {
    /// Serialise a commitment.  The receiver reconstructs via
    /// [`WireAuthenticator::commitment_from_bytes`].
    fn commitment_to_vec(commitment: &Self::Commitment) -> Vec<u8>;

    /// Parse a commitment from the start of `bytes`.  Returns the
    /// commitment and the number of bytes consumed; the caller
    /// advances by that count to reach the next field.
    ///
    /// # Errors
    ///
    /// - [`Error::PubsubProtocol`] if `bytes` is too short or
    ///   structurally invalid.
    fn commitment_from_bytes(bytes: &[u8]) -> Result<(Self::Commitment, usize), Error>;

    /// Serialise a tag.  The receiver reconstructs via
    /// [`WireAuthenticator::tag_from_bytes`].
    fn tag_to_vec(tag: &Self::Tag) -> Vec<u8>;

    /// Parse a tag from the start of `bytes`.  Returns the tag and
    /// the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// - [`Error::PubsubProtocol`] if `bytes` is too short or
    ///   structurally invalid.
    fn tag_from_bytes(bytes: &[u8]) -> Result<(Self::Tag, usize), Error>;
}

/// Trait alias bundling every bound a [`crate::PubsubMux`] needs
/// from its authenticator type.  A blanket impl satisfies this for
/// any `A` that already implements [`Authenticator`] and
/// [`WireAuthenticator`] with the right additional bounds, so users
/// generally do not implement [`PubsubAuth`] directly.
pub trait PubsubAuth: Authenticator + WireAuthenticator + Send + Sync + 'static
where
    Self::Commitment: Clone + Send + Sync + 'static,
    Self::Tag: Clone + Send + Sync + 'static,
{
}

impl<A> PubsubAuth for A
where
    A: Authenticator + WireAuthenticator + Send + Sync + 'static,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
}

impl WireAuthenticator for NullAuthenticator {
    fn commitment_to_vec(_commitment: &()) -> Vec<u8> {
        Vec::new()
    }

    fn commitment_from_bytes(_bytes: &[u8]) -> Result<((), usize), Error> {
        Ok(((), 0))
    }

    fn tag_to_vec(_tag: &()) -> Vec<u8> {
        Vec::new()
    }

    fn tag_from_bytes(_bytes: &[u8]) -> Result<((), usize), Error> {
        Ok(((), 0))
    }
}

impl WireAuthenticator for KeyedHashAuthenticator {
    fn commitment_to_vec(commitment: &KeyedHashCommitment) -> Vec<u8> {
        commitment.as_bytes().to_vec()
    }

    fn commitment_from_bytes(bytes: &[u8]) -> Result<(KeyedHashCommitment, usize), Error> {
        let head = bytes
            .get(..BLAKE3_FINGERPRINT_LEN)
            .ok_or_else(|| Error::PubsubProtocol {
                reason: format!(
                    "KeyedHashAuthenticator commitment needs {BLAKE3_FINGERPRINT_LEN} bytes, got {}",
                    bytes.len()
                ),
            })?;
        let arr: [u8; BLAKE3_FINGERPRINT_LEN] =
            head.try_into().map_err(|_| Error::PubsubProtocol {
                reason: format!(
                    "KeyedHashAuthenticator commitment slice not {BLAKE3_FINGERPRINT_LEN} bytes wide"
                ),
            })?;
        Ok((KeyedHashCommitment::from(arr), BLAKE3_FINGERPRINT_LEN))
    }

    fn tag_to_vec(tag: &KeyedHashTag) -> Vec<u8> {
        tag.as_bytes().to_vec()
    }

    fn tag_from_bytes(bytes: &[u8]) -> Result<(KeyedHashTag, usize), Error> {
        let head = bytes
            .get(..KEYED_HASH_TAG_LEN)
            .ok_or_else(|| Error::PubsubProtocol {
                reason: format!(
                    "KeyedHashAuthenticator tag needs {KEYED_HASH_TAG_LEN} bytes, got {}",
                    bytes.len()
                ),
            })?;
        let arr: [u8; KEYED_HASH_TAG_LEN] = head.try_into().map_err(|_| Error::PubsubProtocol {
            reason: format!("KeyedHashAuthenticator tag slice not {KEYED_HASH_TAG_LEN} bytes wide"),
        })?;
        Ok((KeyedHashTag::from(arr), KEYED_HASH_TAG_LEN))
    }
}

impl<const Q: u32> WireAuthenticator for LatticeHomomorphicAuthenticator<Q> {
    fn commitment_to_vec(commitment: &LhsCommitment) -> Vec<u8> {
        commitment.as_bytes().to_vec()
    }

    fn commitment_from_bytes(bytes: &[u8]) -> Result<(LhsCommitment, usize), Error> {
        let head = bytes
            .get(..BLAKE3_FINGERPRINT_LEN)
            .ok_or_else(|| Error::PubsubProtocol {
                reason: format!(
                    "LHS commitment needs {BLAKE3_FINGERPRINT_LEN} bytes, got {}",
                    bytes.len()
                ),
            })?;
        let arr: [u8; BLAKE3_FINGERPRINT_LEN] =
            head.try_into().map_err(|_| Error::PubsubProtocol {
                reason: format!("LHS commitment slice not {BLAKE3_FINGERPRINT_LEN} bytes wide"),
            })?;
        Ok((LhsCommitment::from(arr), BLAKE3_FINGERPRINT_LEN))
    }

    fn tag_to_vec(tag: &LhsSignature) -> Vec<u8> {
        let entries = tag.sigma().entries();
        // Caps at u32::MAX as a graceful non-panicking fallback for
        // implausibly long signatures (>4G entries, ~32 GiB on the
        // wire).  Real LHS params produce m on the order of 10^3.
        let len_prefix: u32 = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        len_prefix
            .to_be_bytes()
            .into_iter()
            .chain(entries.iter().flat_map(|&e| e.to_le_bytes()))
            .collect()
    }

    fn tag_from_bytes(bytes: &[u8]) -> Result<(LhsSignature, usize), Error> {
        let len_slice = bytes
            .get(..LHS_TAG_LEN_PREFIX)
            .ok_or_else(|| Error::PubsubProtocol {
                reason: format!(
                    "LHS tag needs {LHS_TAG_LEN_PREFIX}-byte length prefix, got {}",
                    bytes.len()
                ),
            })?;
        let len_arr: [u8; LHS_TAG_LEN_PREFIX] =
            len_slice.try_into().map_err(|_| Error::PubsubProtocol {
                reason: format!("LHS tag length-prefix slice not {LHS_TAG_LEN_PREFIX} bytes wide"),
            })?;
        let entry_count_u32 = u32::from_be_bytes(len_arr);
        let entry_count = usize::try_from(entry_count_u32).map_err(|_| Error::PubsubProtocol {
            reason: format!("LHS tag entry count {entry_count_u32} does not fit usize"),
        })?;
        let body_len = entry_count.checked_mul(LHS_TAG_ENTRY_LEN).ok_or_else(|| {
            Error::PubsubProtocol {
                reason: format!(
                    "LHS tag entry count {entry_count} overflows when scaled by {LHS_TAG_ENTRY_LEN}"
                ),
            }
        })?;
        let body_end =
            LHS_TAG_LEN_PREFIX
                .checked_add(body_len)
                .ok_or_else(|| Error::PubsubProtocol {
                    reason: format!(
                        "LHS tag body end overflows: {LHS_TAG_LEN_PREFIX} + {body_len}"
                    ),
                })?;
        let body =
            bytes
                .get(LHS_TAG_LEN_PREFIX..body_end)
                .ok_or_else(|| Error::PubsubProtocol {
                    reason: format!(
                        "LHS tag body needs {body_len} bytes after length prefix, got {}",
                        bytes.len().saturating_sub(LHS_TAG_LEN_PREFIX)
                    ),
                })?;
        let entries: Vec<i64> = body
            .chunks_exact(LHS_TAG_ENTRY_LEN)
            .map(|chunk| {
                let arr: [u8; LHS_TAG_ENTRY_LEN] =
                    chunk.try_into().map_err(|_| Error::PubsubProtocol {
                        reason: format!(
                            "LHS tag entry chunk not {LHS_TAG_ENTRY_LEN} bytes wide (unreachable)"
                        ),
                    })?;
                Ok::<i64, Error>(i64::from_le_bytes(arr))
            })
            .collect::<Result<Vec<i64>, Error>>()?;
        Ok((LhsSignature::new(ZVec::new(entries)), body_end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::PubsubProtocol { reason: reason() })
        }
    }

    #[test]
    fn null_round_trip() -> Result<(), Error> {
        let commitment_bytes = NullAuthenticator::commitment_to_vec(&());
        check(commitment_bytes.is_empty(), || {
            "Null commitment should be 0 bytes".to_owned()
        })?;
        let ((), c_consumed) = NullAuthenticator::commitment_from_bytes(&[])?;
        check(c_consumed == 0, || {
            format!("Null commitment consumed {c_consumed}, want 0")
        })?;
        let tag_bytes = NullAuthenticator::tag_to_vec(&());
        check(tag_bytes.is_empty(), || {
            "Null tag should be 0 bytes".to_owned()
        })?;
        let ((), t_consumed) = NullAuthenticator::tag_from_bytes(&[])?;
        check(t_consumed == 0, || {
            format!("Null tag consumed {t_consumed}, want 0")
        })
    }

    #[test]
    fn null_consumes_zero_from_non_empty_buffer() -> Result<(), Error> {
        // Cursor-style: NullAuthenticator owns no bytes, so it parses
        // its zero-byte commitment from any input (including a
        // non-empty buffer) and reports 0 bytes consumed.
        let ((), c_consumed) = NullAuthenticator::commitment_from_bytes(&[0xAA, 0xBB])?;
        check(c_consumed == 0, || {
            format!("Null commitment consumed {c_consumed} from non-empty buffer, want 0")
        })?;
        let ((), t_consumed) = NullAuthenticator::tag_from_bytes(&[0xCC])?;
        check(t_consumed == 0, || {
            format!("Null tag consumed {t_consumed} from non-empty buffer, want 0")
        })
    }

    #[test]
    fn keyed_hash_round_trip() -> Result<(), Error> {
        let commitment_bytes = [7u8; 32];
        let (commitment, c_consumed) =
            KeyedHashAuthenticator::commitment_from_bytes(&commitment_bytes)?;
        check(c_consumed == 32, || {
            format!("KeyedHash commitment consumed {c_consumed}, want 32")
        })?;
        let serialised = KeyedHashAuthenticator::commitment_to_vec(&commitment);
        check(serialised == commitment_bytes, || {
            "commitment round trip mismatch".to_owned()
        })?;
        let tag_bytes = [9u8; 32];
        let (tag, t_consumed) = KeyedHashAuthenticator::tag_from_bytes(&tag_bytes)?;
        check(t_consumed == 32, || {
            format!("KeyedHash tag consumed {t_consumed}, want 32")
        })?;
        let serialised = KeyedHashAuthenticator::tag_to_vec(&tag);
        check(serialised == tag_bytes, || {
            "tag round trip mismatch".to_owned()
        })
    }

    #[test]
    fn keyed_hash_rejects_short_commitment() -> Result<(), Error> {
        match KeyedHashAuthenticator::commitment_from_bytes(&[0u8; 31]) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseDecrypt
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::RlncLayer { .. }
                | Error::HostState { .. }
                | Error::IdentityVerify { .. }),
            ) => Err(Error::PubsubProtocol {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
            Ok((parsed, consumed)) => Err(Error::PubsubProtocol {
                reason: format!(
                    "expected rejection of 31-byte commitment, got Ok({parsed:?}, {consumed})"
                ),
            }),
        }
    }

    #[test]
    fn keyed_hash_decode_with_trailing_bytes() -> Result<(), Error> {
        // A commitment block followed by other fields: the decoder
        // consumes exactly 32 bytes and leaves the rest for the
        // caller to advance past.
        let mut buf = [0u8; 35];
        buf[..32].copy_from_slice(&[7u8; 32]);
        let (commitment, consumed) = KeyedHashAuthenticator::commitment_from_bytes(&buf)?;
        check(consumed == 32, || {
            format!("expected 32 bytes consumed, got {consumed}")
        })?;
        check(commitment.as_bytes() == &[7u8; 32], || {
            "commitment bytes mismatch".to_owned()
        })
    }

    #[test]
    fn lhs_tag_round_trip() -> Result<(), Error> {
        let entries = vec![1i64, -2, 3, -4, 5];
        let original = LhsSignature::new(ZVec::new(entries.clone()));
        let bytes = LatticeHomomorphicAuthenticator::<257>::tag_to_vec(&original);
        let expected_len = LHS_TAG_LEN_PREFIX + entries.len() * LHS_TAG_ENTRY_LEN;
        check(bytes.len() == expected_len, || {
            format!(
                "LHS tag wire length {} differs from expected {expected_len}",
                bytes.len()
            )
        })?;
        let (recovered, consumed) = LatticeHomomorphicAuthenticator::<257>::tag_from_bytes(&bytes)?;
        check(consumed == expected_len, || {
            format!("LHS tag consumed {consumed}, want {expected_len}")
        })?;
        check(recovered.sigma().entries() == entries, || {
            format!(
                "LHS tag entries round-trip mismatch: {:?}",
                recovered.sigma().entries()
            )
        })
    }

    #[test]
    fn lhs_tag_decode_rejects_truncated_body() -> Result<(), Error> {
        let entries = vec![1i64, 2, 3];
        let original = LhsSignature::new(ZVec::new(entries));
        let bytes = LatticeHomomorphicAuthenticator::<257>::tag_to_vec(&original);
        let truncated = bytes
            .get(..bytes.len() - 1)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        match LatticeHomomorphicAuthenticator::<257>::tag_from_bytes(&truncated) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseDecrypt
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::RlncLayer { .. }
                | Error::HostState { .. }
                | Error::IdentityVerify { .. }),
            ) => Err(Error::PubsubProtocol {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
            Ok((parsed, consumed)) => Err(Error::PubsubProtocol {
                reason: format!(
                    "expected rejection of truncated LHS tag, got Ok({:?}, {consumed})",
                    parsed.sigma().entries()
                ),
            }),
        }
    }

    #[test]
    fn lhs_commitment_round_trip() -> Result<(), Error> {
        let bytes = [0xAAu8; 32];
        let original = LhsCommitment::from(bytes);
        let serialised = LatticeHomomorphicAuthenticator::<257>::commitment_to_vec(&original);
        check(serialised == bytes, || {
            "LHS commitment serialisation mismatch".to_owned()
        })?;
        let (recovered, consumed) =
            LatticeHomomorphicAuthenticator::<257>::commitment_from_bytes(&serialised)?;
        check(consumed == 32, || {
            format!("LHS commitment consumed {consumed}, want 32")
        })?;
        check(recovered.as_bytes() == &bytes, || {
            "LHS commitment round-trip bytes differ".to_owned()
        })
    }
}
