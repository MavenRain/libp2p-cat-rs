//! Domain-separated Ed25519 binding of a Noise XX
//! [`StaticPublicKey`].
//!
//! The source emits a [`SignedStaticKey`] carrying its Ed25519
//! public key plus an Ed25519 signature over
//! [`DOMAIN_TAG`] || `x25519_static_pubkey`.  A peer that receives
//! the payload (out-of-band, or as a Noise handshake extension)
//! reconstructs the signed input from the X25519 static key it
//! already learned during the handshake, validates the signature
//! against the embedded Ed25519 public key with `verify_strict`,
//! and on success derives the [`PeerId`].

use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::{Error, PeerId};

use crate::keypair::{
    DOMAIN_TAG, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519Keypair, Ed25519PublicKey,
    Ed25519Signature,
};

/// Width of the X25519 static public key (32 bytes).
const X25519_KEY_LEN: usize = 32;

/// Number of bytes in [`DOMAIN_TAG`].
const DOMAIN_TAG_LEN: usize = DOMAIN_TAG.len();

/// Wire-format width of a [`SignedStaticKey`]: 32-byte Ed25519
/// public key + 64-byte signature.
const SIGNED_STATIC_KEY_LEN: usize = ED25519_PUBLIC_KEY_LEN + ED25519_SIGNATURE_LEN;

/// Width of the buffer fed into Ed25519 sign / verify.
const SIGNED_INPUT_LEN: usize = DOMAIN_TAG_LEN + X25519_KEY_LEN;

/// Compute the byte string that is fed into Ed25519 sign / verify.
fn signed_input(static_pub: &StaticPublicKey) -> [u8; SIGNED_INPUT_LEN] {
    let static_bytes = static_pub.as_bytes();
    core::array::from_fn(|i| match i {
        j if j < DOMAIN_TAG_LEN => DOMAIN_TAG.get(j).copied().unwrap_or(0),
        j => static_bytes.get(j - DOMAIN_TAG_LEN).copied().unwrap_or(0),
    })
}

/// An Ed25519 binding of a Noise XX [`StaticPublicKey`].
///
/// Produced by the holder of the X25519 keypair that owns the
/// static key, and verified by anyone who learns the X25519 public
/// key during handshake.  After successful verification the peer
/// holds an authenticated link between the X25519 key it just
/// completed Noise with and the [`PeerId`] derived from the Ed25519
/// public key inside this payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct SignedStaticKey {
    public_key: Ed25519PublicKey,
    signature: Ed25519Signature,
}

impl SignedStaticKey {
    /// Wire-format width in bytes (96).
    pub const WIRE_LEN: usize = SIGNED_STATIC_KEY_LEN;

    /// Build a binding that asserts the Ed25519 identity in
    /// `keypair` consents to use of `static_pub` as its Noise XX
    /// static key.
    ///
    /// # Errors
    ///
    /// - [`Error::IdentityVerify`] if the underlying Ed25519
    ///   `try_sign` reports a failure (not expected in practice for
    ///   a well-formed keypair).
    pub fn create(keypair: &Ed25519Keypair, static_pub: &StaticPublicKey) -> Result<Self, Error> {
        let input = signed_input(static_pub);
        let signature = keypair.try_sign(&input)?;
        Ok(Self {
            public_key: *keypair.public(),
            signature,
        })
    }

    /// The asserted Ed25519 public key.  Trust this only after
    /// [`SignedStaticKey::verify`] returns Ok for the X25519 key
    /// the local Noise session actually completed against.
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The detached signature over `DOMAIN_TAG || x25519_pub`.
    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Verify the binding against the X25519 static key the local
    /// Noise session completed against.
    ///
    /// On success returns the verified Ed25519 public key (a copy
    /// of [`SignedStaticKey::public_key`]) and the [`PeerId`]
    /// derived from it.
    ///
    /// # Errors
    ///
    /// - [`Error::IdentityVerify`] if the embedded public key bytes
    ///   are not a valid curve point or if the signature does not
    ///   verify (`verify_strict`) against it.
    pub fn verify(
        &self,
        static_pub: &StaticPublicKey,
    ) -> Result<(Ed25519PublicKey, PeerId), Error> {
        let verifying_key = self.public_key.verifying_key()?;
        let input = signed_input(static_pub);
        verifying_key
            .verify_strict(&input, &self.signature.to_dalek())
            .map_err(|e| Error::IdentityVerify {
                reason: format!("ed25519 signature did not verify: {e}"),
            })?;
        Ok((self.public_key, self.public_key.peer_id()))
    }

    /// Encode the binding as a fixed-width byte payload.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNED_STATIC_KEY_LEN] {
        let pk = self.public_key.as_bytes();
        let sig = self.signature.as_bytes();
        core::array::from_fn(|i| match i {
            j if j < ED25519_PUBLIC_KEY_LEN => pk.get(j).copied().unwrap_or(0),
            j => sig.get(j - ED25519_PUBLIC_KEY_LEN).copied().unwrap_or(0),
        })
    }

    /// Decode a binding from its wire bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::IdentityVerify`] if `bytes.len()` is not exactly
    ///   [`SignedStaticKey::WIRE_LEN`], or the slices cannot be
    ///   converted to fixed-size arrays.  No curve-point or
    ///   signature checks happen here; call
    ///   [`SignedStaticKey::verify`] for those.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let pk_slice =
            bytes
                .get(..ED25519_PUBLIC_KEY_LEN)
                .ok_or_else(|| Error::IdentityVerify {
                    reason: format!(
                        "SignedStaticKey wire payload needs {SIGNED_STATIC_KEY_LEN} bytes, got {}",
                        bytes.len()
                    ),
                })?;
        let sig_slice = bytes
            .get(ED25519_PUBLIC_KEY_LEN..SIGNED_STATIC_KEY_LEN)
            .ok_or_else(|| Error::IdentityVerify {
                reason: format!(
                    "SignedStaticKey wire payload needs {SIGNED_STATIC_KEY_LEN} bytes, got {}",
                    bytes.len()
                ),
            })?;
        let pk_arr: [u8; ED25519_PUBLIC_KEY_LEN] =
            pk_slice.try_into().map_err(|_| Error::IdentityVerify {
                reason: format!(
                    "SignedStaticKey public-key slice not {ED25519_PUBLIC_KEY_LEN} bytes wide"
                ),
            })?;
        let sig_arr: [u8; ED25519_SIGNATURE_LEN] =
            sig_slice.try_into().map_err(|_| Error::IdentityVerify {
                reason: format!(
                    "SignedStaticKey signature slice not {ED25519_SIGNATURE_LEN} bytes wide"
                ),
            })?;
        Ok(Self {
            public_key: Ed25519PublicKey::from(pk_arr),
            signature: Ed25519Signature::from(sig_arr),
        })
    }
}

#[cfg(test)]
mod tests {
    use libp2p_cat_noise::StaticKeypair;

    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::IdentityVerify { reason: reason() })
        }
    }

    fn fixtures() -> (Ed25519Keypair, StaticKeypair) {
        let identity = Ed25519Keypair::from_seed([7u8; 32]);
        let static_keypair = StaticKeypair::from_private_bytes([9u8; 32]);
        (identity, static_keypair)
    }

    #[test]
    fn create_then_verify_returns_matching_peer_id() -> Result<(), Error> {
        let (identity, static_keypair) = fixtures();
        let signed = SignedStaticKey::create(&identity, static_keypair.public())?;
        let (verified_public, verified_peer_id) = signed.verify(static_keypair.public())?;
        check(verified_public == *identity.public(), || {
            "verified public key does not match signing identity".to_owned()
        })?;
        check(verified_peer_id == identity.peer_id(), || {
            "verified peer id does not match signing identity".to_owned()
        })
    }

    #[test]
    fn wire_round_trip_preserves_payload() -> Result<(), Error> {
        let (identity, static_keypair) = fixtures();
        let signed = SignedStaticKey::create(&identity, static_keypair.public())?;
        let bytes = signed.to_bytes();
        check(bytes.len() == SignedStaticKey::WIRE_LEN, || {
            format!(
                "wire payload {} bytes, expected {}",
                bytes.len(),
                SignedStaticKey::WIRE_LEN
            )
        })?;
        let parsed = SignedStaticKey::from_bytes(&bytes)?;
        check(parsed == signed, || {
            "decoded SignedStaticKey differs from original".to_owned()
        })
    }

    #[test]
    fn verify_rejects_mismatched_static_key() -> Result<(), Error> {
        let (identity, alice_static) = fixtures();
        let bob_static = StaticKeypair::from_private_bytes([0xAAu8; 32]);
        // Sign Alice's X25519 public key but try to verify against
        // Bob's: the input bytes that produce the expected signature
        // differ, so verify must reject.
        let signed = SignedStaticKey::create(&identity, alice_static.public())?;
        match signed.verify(bob_static.public()) {
            Err(Error::IdentityVerify { .. }) => Ok(()),
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseDecrypt
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::RlncLayer { .. }
                | Error::PubsubProtocol { .. }
                | Error::HostState { .. }),
            ) => Err(Error::IdentityVerify {
                reason: format!("expected IdentityVerify, got {other:?}"),
            }),
            Ok((_pk, _peer_id)) => Err(Error::IdentityVerify {
                reason: "verify should have rejected mismatched X25519 key".to_owned(),
            }),
        }
    }

    #[test]
    fn verify_rejects_tampered_signature() -> Result<(), Error> {
        let (identity, static_keypair) = fixtures();
        let signed = SignedStaticKey::create(&identity, static_keypair.public())?;
        let original = signed.to_bytes();
        // Flip the first signature byte.
        let bytes: [u8; SignedStaticKey::WIRE_LEN] = core::array::from_fn(|i| {
            let raw = original.get(i).copied().unwrap_or(0);
            if i == ED25519_PUBLIC_KEY_LEN {
                raw ^ 0x80
            } else {
                raw
            }
        });
        let tampered = SignedStaticKey::from_bytes(&bytes)?;
        match tampered.verify(static_keypair.public()) {
            Err(Error::IdentityVerify { .. }) => Ok(()),
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseDecrypt
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::RlncLayer { .. }
                | Error::PubsubProtocol { .. }
                | Error::HostState { .. }),
            ) => Err(Error::IdentityVerify {
                reason: format!("expected IdentityVerify, got {other:?}"),
            }),
            Ok((_pk, _peer_id)) => Err(Error::IdentityVerify {
                reason: "verify should have rejected tampered signature".to_owned(),
            }),
        }
    }

    #[test]
    fn from_bytes_rejects_short_payload() -> Result<(), Error> {
        let too_short = [0u8; SignedStaticKey::WIRE_LEN - 1];
        match SignedStaticKey::from_bytes(&too_short) {
            Err(Error::IdentityVerify { .. }) => Ok(()),
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseDecrypt
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::RlncLayer { .. }
                | Error::PubsubProtocol { .. }
                | Error::HostState { .. }),
            ) => Err(Error::IdentityVerify {
                reason: format!("expected IdentityVerify, got {other:?}"),
            }),
            Ok(parsed) => Err(Error::IdentityVerify {
                reason: format!("from_bytes should have rejected short input, got {parsed:?}"),
            }),
        }
    }

    #[test]
    fn distinct_static_keys_produce_distinct_signatures() -> Result<(), Error> {
        let identity = Ed25519Keypair::from_seed([7u8; 32]);
        let static_a = StaticKeypair::from_private_bytes([9u8; 32]);
        let static_b = StaticKeypair::from_private_bytes([0xBBu8; 32]);
        let signed_a = SignedStaticKey::create(&identity, static_a.public())?;
        let signed_b = SignedStaticKey::create(&identity, static_b.public())?;
        check(
            signed_a.signature().as_bytes() != signed_b.signature().as_bytes(),
            || "signatures over distinct static keys collided".to_owned(),
        )
    }
}
