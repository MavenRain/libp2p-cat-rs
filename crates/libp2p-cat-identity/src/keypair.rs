//! Ed25519 keypair and signature newtypes.
//!
//! [`Ed25519Keypair`] wraps an [`ed25519_dalek::SigningKey`] derived
//! deterministically from a 32-byte seed; the corresponding
//! [`Ed25519PublicKey`] is exposed for transmission and the
//! associated [`PeerId`] is derived via
//! [`PeerId::from_ed25519`](libp2p_cat_types::PeerId::from_ed25519).
//!
//! Signature production uses the
//! [`signature::Signer::try_sign`] entry point so we never rely on
//! the panicking `sign` shortcut.  Verification uses
//! [`ed25519_dalek::VerifyingKey::verify_strict`] to reject
//! malleable signatures and weak public keys.

use ed25519_dalek::{
    SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature as DalekSignature, SigningKey, VerifyingKey,
    ed25519::signature::Signer,
};
use libp2p_cat_types::{Error, PeerId};

/// Domain separator prefixed to the signed input before Ed25519
/// signing.  Distinct from libp2p's `noise-libp2p-static-key:`
/// prefix because libp2p-cat is a non-interoperable wire fork.
pub const DOMAIN_TAG: &[u8] = b"libp2p-cat-identity-static-key:";

/// Length of an Ed25519 public key on the wire.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature on the wire.
pub const ED25519_SIGNATURE_LEN: usize = SIGNATURE_LENGTH;

/// Ed25519 public verification key.
///
/// Stored as the canonical 32-byte compressed encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl Ed25519PublicKey {
    /// Borrow the canonical 32-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Build from raw bytes without verifying that they decode to a
    /// valid curve point.  Verification of the underlying point
    /// happens at the `verify` boundary, where the `VerifyingKey` is
    /// reconstructed from these bytes.
    pub(crate) fn from_bytes(bytes: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Derive the libp2p-compatible [`PeerId`] for this key.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_ed25519(&self.0)
    }

    /// Reconstruct the curve-aware [`VerifyingKey`] used by
    /// `verify_strict`.
    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        VerifyingKey::from_bytes(&self.0).map_err(|e| Error::IdentityVerify {
            reason: format!("ed25519 public key bytes are not a valid curve point: {e}"),
        })
    }
}

impl From<[u8; ED25519_PUBLIC_KEY_LEN]> for Ed25519PublicKey {
    fn from(bytes: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// Ed25519 detached signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Ed25519Signature([u8; ED25519_SIGNATURE_LEN]);

impl Ed25519Signature {
    /// Borrow the 64-byte signature encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; ED25519_SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn to_dalek(self) -> DalekSignature {
        DalekSignature::from_bytes(&self.0)
    }
}

impl From<[u8; ED25519_SIGNATURE_LEN]> for Ed25519Signature {
    fn from(bytes: [u8; ED25519_SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }
}

/// Ed25519 signing keypair.
///
/// Derives deterministically from a 32-byte seed; the same seed
/// always yields the same public key and produces the same
/// signature for a given message (Ed25519 is deterministic per
/// RFC 8032).
#[must_use]
pub struct Ed25519Keypair {
    signing_key: SigningKey,
    public_key: Ed25519PublicKey,
}

impl Ed25519Keypair {
    /// Build the keypair from a 32-byte seed.  The same seed always
    /// produces the same public key.
    pub fn from_seed(seed: [u8; SECRET_KEY_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            public_key,
        }
    }

    /// Borrow the public key.
    pub fn public(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// Derive the libp2p-compatible [`PeerId`] for this keypair.
    pub fn peer_id(&self) -> PeerId {
        self.public_key.peer_id()
    }

    /// Sign `message` with the secret key.
    ///
    /// # Errors
    ///
    /// - [`Error::IdentityVerify`] if `try_sign` reports a failure.
    ///   Ed25519 signing is not expected to fail in practice; the
    ///   error path exists so this layer is panic-free.
    pub fn try_sign(&self, message: &[u8]) -> Result<Ed25519Signature, Error> {
        self.signing_key
            .try_sign(message)
            .map(|s| Ed25519Signature::from_bytes(s.to_bytes()))
            .map_err(|e| Error::IdentityVerify {
                reason: format!("ed25519 try_sign failed: {e}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::IdentityVerify { reason: reason() })
        }
    }

    #[test]
    fn keypair_is_deterministic_from_seed() -> Result<(), Error> {
        let kp_a = Ed25519Keypair::from_seed([3u8; 32]);
        let kp_b = Ed25519Keypair::from_seed([3u8; 32]);
        check(kp_a.public().as_bytes() == kp_b.public().as_bytes(), || {
            "same seed produced different public keys".to_owned()
        })
    }

    #[test]
    fn distinct_seeds_produce_distinct_public_keys() -> Result<(), Error> {
        let kp_a = Ed25519Keypair::from_seed([3u8; 32]);
        let kp_b = Ed25519Keypair::from_seed([4u8; 32]);
        check(kp_a.public().as_bytes() != kp_b.public().as_bytes(), || {
            "distinct seeds produced equal public keys".to_owned()
        })
    }

    #[test]
    fn signing_is_deterministic_per_rfc_8032() -> Result<(), Error> {
        let kp = Ed25519Keypair::from_seed([5u8; 32]);
        let msg = b"payload to be signed twice";
        let sig_a = kp.try_sign(msg)?;
        let sig_b = kp.try_sign(msg)?;
        check(sig_a.as_bytes() == sig_b.as_bytes(), || {
            "two signings of the same message under the same key differ".to_owned()
        })
    }

    #[test]
    fn peer_id_matches_public_key_path() -> Result<(), Error> {
        let kp = Ed25519Keypair::from_seed([6u8; 32]);
        let direct = kp.peer_id();
        let via_pub = kp.public().peer_id();
        check(direct == via_pub, || {
            "Keypair::peer_id and PublicKey::peer_id disagree".to_owned()
        })
    }
}
