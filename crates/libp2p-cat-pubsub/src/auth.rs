//! Wire-level extension of [`rlnc_cat_rs::auth::Authenticator`].
//!
//! [`WireAuthenticator`] adds two associated constants
//! ([`WireAuthenticator::COMMITMENT_LEN`] /
//! [`WireAuthenticator::TAG_LEN`]) and four serialisation hooks so a
//! [`crate::PubsubMux`] can carry its commitment and tag over UDP
//! frames without knowing the concrete `Authenticator` type.
//!
//! Implementations are provided for the two stock authenticators in
//! `rlnc-cat-rs`:
//!
//! - [`NullAuthenticator`]: commitment and tag are both unit and
//!   occupy zero wire bytes.  Suitable for tests and trust-the-peer
//!   deployments.
//! - [`KeyedHashAuthenticator`]: commitment and tag are each 32-byte
//!   BLAKE3 keyed-hash outputs.  Suitable for permissioned networks
//!   where every relay holds the shared key.
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

/// Extension of [`Authenticator`] that knows how to serialise its
/// associated types onto a fixed-size wire envelope.
pub trait WireAuthenticator: Authenticator {
    /// Number of bytes an [`Authenticator::Commitment`] occupies on
    /// the wire.
    const COMMITMENT_LEN: usize;

    /// Number of bytes an [`Authenticator::Tag`] occupies on the wire.
    const TAG_LEN: usize;

    /// Serialise a commitment into a freshly-allocated byte vector
    /// of length exactly [`Self::COMMITMENT_LEN`].
    fn commitment_to_vec(commitment: &Self::Commitment) -> Vec<u8>;

    /// Deserialise a commitment from `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PubsubProtocol`] if `bytes.len()` is not
    /// exactly [`Self::COMMITMENT_LEN`].
    fn commitment_from_bytes(bytes: &[u8]) -> Result<Self::Commitment, Error>;

    /// Serialise a tag into a freshly-allocated byte vector of length
    /// exactly [`Self::TAG_LEN`].
    fn tag_to_vec(tag: &Self::Tag) -> Vec<u8>;

    /// Deserialise a tag from `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PubsubProtocol`] if `bytes.len()` is not
    /// exactly [`Self::TAG_LEN`].
    fn tag_from_bytes(bytes: &[u8]) -> Result<Self::Tag, Error>;
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
    const COMMITMENT_LEN: usize = 0;
    const TAG_LEN: usize = 0;

    fn commitment_to_vec(_commitment: &()) -> Vec<u8> {
        Vec::new()
    }

    fn commitment_from_bytes(bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(Error::PubsubProtocol {
                reason: format!(
                    "NullAuthenticator commitment must be 0 bytes, got {}",
                    bytes.len()
                ),
            })
        }
    }

    fn tag_to_vec(_tag: &()) -> Vec<u8> {
        Vec::new()
    }

    fn tag_from_bytes(bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(Error::PubsubProtocol {
                reason: format!("NullAuthenticator tag must be 0 bytes, got {}", bytes.len()),
            })
        }
    }
}

impl WireAuthenticator for KeyedHashAuthenticator {
    const COMMITMENT_LEN: usize = 32;
    const TAG_LEN: usize = 32;

    fn commitment_to_vec(commitment: &KeyedHashCommitment) -> Vec<u8> {
        commitment.as_bytes().to_vec()
    }

    fn commitment_from_bytes(bytes: &[u8]) -> Result<KeyedHashCommitment, Error> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::PubsubProtocol {
            reason: format!(
                "KeyedHashAuthenticator commitment must be 32 bytes, got {}",
                bytes.len()
            ),
        })?;
        Ok(KeyedHashCommitment::from(arr))
    }

    fn tag_to_vec(tag: &KeyedHashTag) -> Vec<u8> {
        tag.as_bytes().to_vec()
    }

    fn tag_from_bytes(bytes: &[u8]) -> Result<KeyedHashTag, Error> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::PubsubProtocol {
            reason: format!(
                "KeyedHashAuthenticator tag must be 32 bytes, got {}",
                bytes.len()
            ),
        })?;
        Ok(KeyedHashTag::from(arr))
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
        NullAuthenticator::commitment_from_bytes(&[])?;
        let tag_bytes = NullAuthenticator::tag_to_vec(&());
        check(tag_bytes.is_empty(), || {
            "Null tag should be 0 bytes".to_owned()
        })?;
        NullAuthenticator::tag_from_bytes(&[])
    }

    #[test]
    fn null_rejects_extra_bytes() -> Result<(), Error> {
        match NullAuthenticator::commitment_from_bytes(&[0u8]) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            other => Err(Error::PubsubProtocol {
                reason: format!("expected rejection, got {other:?}"),
            }),
        }
    }

    #[test]
    fn keyed_hash_round_trip() -> Result<(), Error> {
        let commitment_bytes = [7u8; 32];
        let commitment = KeyedHashAuthenticator::commitment_from_bytes(&commitment_bytes)?;
        let serialised = KeyedHashAuthenticator::commitment_to_vec(&commitment);
        check(serialised == commitment_bytes, || {
            "commitment round trip mismatch".to_owned()
        })?;
        let tag_bytes = [9u8; 32];
        let tag = KeyedHashAuthenticator::tag_from_bytes(&tag_bytes)?;
        let serialised = KeyedHashAuthenticator::tag_to_vec(&tag);
        check(serialised == tag_bytes, || {
            "tag round trip mismatch".to_owned()
        })
    }

    #[test]
    fn keyed_hash_rejects_wrong_size() -> Result<(), Error> {
        match KeyedHashAuthenticator::commitment_from_bytes(&[0u8; 31]) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            other => Err(Error::PubsubProtocol {
                reason: format!("expected rejection, got {other:?}"),
            }),
        }
    }
}
