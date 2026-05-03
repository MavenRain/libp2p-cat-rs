//! Noise `SymmetricState` built on BLAKE3 keyed-mode and ChaCha20-Poly1305.
//!
//! Internal to the crate: only [`crate::handshake`] composes these
//! operations.  Every method consumes `self` and returns a new state.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use libp2p_cat_types::Error;

use crate::primitives::{DhOutput, KEY_LEN};

/// Protocol name for our suite, written verbatim into the initial
/// handshake hash.  Exactly 32 ASCII bytes long, so no padding or
/// hashing is needed at initialisation.
pub(crate) const PROTOCOL_NAME: &[u8; KEY_LEN] = b"Noise_XX_25519_ChaChaPoly_BLAKE3";

/// Length of the AEAD authentication tag (Poly1305).
pub(crate) const AEAD_TAG_LEN: usize = 16;

/// The Noise running state during a handshake: chaining key, hash,
/// optional cipher key, and a per-AEAD-instance nonce counter.
pub(crate) struct SymmetricState {
    chaining_key: [u8; KEY_LEN],
    hash: [u8; KEY_LEN],
    cipher_key: Option<[u8; KEY_LEN]>,
    nonce: u64,
}

impl SymmetricState {
    /// Initialise from the protocol name.  Equivalent to
    /// `InitializeSymmetric` in the Noise spec; for our suite the
    /// protocol name is exactly 32 bytes so `h := protocol_name` and
    /// `ck := h`.
    pub(crate) fn initialize() -> Self {
        Self {
            chaining_key: *PROTOCOL_NAME,
            hash: *PROTOCOL_NAME,
            cipher_key: None,
            nonce: 0,
        }
    }

    /// Mix arbitrary bytes (typically a public key or ciphertext) into
    /// the running hash.
    pub(crate) fn mix_hash(self, data: &[u8]) -> Self {
        let next_hash = blake3_hash_two(&self.hash, data);
        Self {
            hash: next_hash,
            ..self
        }
    }

    /// Mix a 32-byte secret (typically a DH output) into the chaining
    /// key, deriving a fresh cipher key and resetting the nonce.
    pub(crate) fn mix_key(self, input: &DhOutput) -> Self {
        let (next_chaining_key, next_cipher_key) = kdf_two(&self.chaining_key, input.as_bytes());
        Self {
            chaining_key: next_chaining_key,
            cipher_key: Some(next_cipher_key),
            nonce: 0,
            ..self
        }
    }

    /// Encrypt `plaintext` with the current cipher key (using the
    /// running hash as AAD), mix the ciphertext into the running hash,
    /// and return the result.  When no cipher key is set, this acts as
    /// `mix_hash(plaintext)` and returns the plaintext verbatim.
    pub(crate) fn encrypt_and_hash(self, plaintext: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        match self.cipher_key {
            None => {
                let ciphertext = plaintext.to_vec();
                let next = self.mix_hash(&ciphertext);
                Ok((next, ciphertext))
            }
            Some(key) => {
                let aad = self.hash;
                let ciphertext = aead_encrypt(&key, self.nonce, &aad, plaintext)?;
                let next = Self {
                    nonce: self.nonce + 1,
                    cipher_key: Some(key),
                    ..self
                }
                .mix_hash(&ciphertext);
                Ok((next, ciphertext))
            }
        }
    }

    /// The dual of [`encrypt_and_hash`].  When no cipher key is set,
    /// this is `mix_hash(ciphertext)` and returns the ciphertext as
    /// the plaintext.
    ///
    /// [`encrypt_and_hash`]: SymmetricState::encrypt_and_hash
    pub(crate) fn decrypt_and_hash(self, ciphertext: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        match self.cipher_key {
            None => {
                let plaintext = ciphertext.to_vec();
                let next = self.mix_hash(ciphertext);
                Ok((next, plaintext))
            }
            Some(key) => {
                let aad = self.hash;
                let plaintext = aead_decrypt(&key, self.nonce, &aad, ciphertext)?;
                let next = Self {
                    nonce: self.nonce + 1,
                    cipher_key: Some(key),
                    ..self
                }
                .mix_hash(ciphertext);
                Ok((next, plaintext))
            }
        }
    }

    /// Derive the two transport cipher keys from the final chaining
    /// key.  The Noise spec calls this `Split()`; the first output is
    /// keyed for traffic from initiator to responder, the second for
    /// the reverse direction.
    pub(crate) fn split(self) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        kdf_two(&self.chaining_key, &[])
    }
}

/// Two-output BLAKE3 keyed-mode KDF.
///
/// Replaces Noise's HKDF: BLAKE3-keyed is itself a PRF, so we use its
/// XOF mode to extract 64 bytes (split into two 32-byte halves).
fn kdf_two(key: &[u8; KEY_LEN], input: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; KEY_LEN * 2];
    reader.fill(&mut out);
    let first: [u8; KEY_LEN] = core::array::from_fn(|i| out.get(i).copied().unwrap_or(0));
    let second: [u8; KEY_LEN] =
        core::array::from_fn(|i| out.get(i + KEY_LEN).copied().unwrap_or(0));
    (first, second)
}

/// Plain BLAKE3 hash of `previous_hash || data`, producing the next
/// running hash for `mix_hash`.
fn blake3_hash_two(previous_hash: &[u8; KEY_LEN], data: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(previous_hash);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// ChaCha20-Poly1305 nonce derivation: 4 zero bytes, then the 8-byte
/// little-endian counter, matching Noise's transport encoding.
fn chacha_nonce(counter: u64) -> [u8; 12] {
    let counter_bytes = counter.to_le_bytes();
    core::array::from_fn(|i| match i {
        0..=3 => 0,
        n => counter_bytes.get(n - 4).copied().unwrap_or(0),
    })
}

pub(crate) fn aead_encrypt(
    key: &[u8; KEY_LEN],
    nonce: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = chacha_nonce(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt((&nonce_bytes).into(), payload)
        .map_err(|_| Error::NoiseDecrypt)
}

pub(crate) fn aead_decrypt(
    key: &[u8; KEY_LEN],
    nonce: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = chacha_nonce(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt((&nonce_bytes).into(), payload)
        .map_err(|_| Error::NoiseDecrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::NoiseProtocol { reason: reason() })
        }
    }

    #[test]
    fn aead_round_trip_through_helpers() -> Result<(), Error> {
        let key = [9u8; KEY_LEN];
        let aad = b"associated-data";
        let plaintext = b"the quick brown fox";
        let ciphertext = aead_encrypt(&key, 17, aad, plaintext)?;
        let recovered = aead_decrypt(&key, 17, aad, &ciphertext)?;
        check(recovered == plaintext, || {
            format!("decrypted bytes do not match plaintext: {recovered:?}")
        })
    }

    #[test]
    fn aead_decrypt_rejects_wrong_nonce() -> Result<(), Error> {
        let key = [9u8; KEY_LEN];
        let aad = b"";
        let ciphertext = aead_encrypt(&key, 1, aad, b"hello")?;
        match aead_decrypt(&key, 2, aad, &ciphertext) {
            Err(Error::NoiseDecrypt) => Ok(()),
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::RlncLayer { .. }
                | Error::PubsubProtocol { .. }
                | Error::HostState { .. }
                | Error::IdentityVerify { .. }),
            ) => Err(Error::NoiseProtocol {
                reason: format!("expected NoiseDecrypt, got {other:?}"),
            }),
            Ok(bytes) => Err(Error::NoiseProtocol {
                reason: format!("expected NoiseDecrypt, got Ok({bytes:?})"),
            }),
        }
    }

    #[test]
    fn kdf_outputs_are_deterministic_and_distinct() -> Result<(), Error> {
        let key = [1u8; KEY_LEN];
        let (a, b) = kdf_two(&key, b"input");
        let (a2, b2) = kdf_two(&key, b"input");
        check(a == a2, || "first kdf output not deterministic".to_owned())?;
        check(b == b2, || "second kdf output not deterministic".to_owned())?;
        check(a != b, || "kdf halves must be distinct".to_owned())
    }
}
