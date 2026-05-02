//! Authenticated transport: post-handshake encryption with explicit
//! 8-byte nonces and a 64-bit sliding replay window.
//!
//! # Datagram format
//!
//! Every transport datagram is laid out as:
//!
//! ```text
//! +-------------------+---------------------------+--------------+
//! | nonce (8 bytes BE)| ciphertext (n bytes)      | tag (16 B)   |
//! +-------------------+---------------------------+--------------+
//! ```
//!
//! Total wire overhead is [`TRANSPORT_OVERHEAD`] bytes.
//!
//! # Replay protection
//!
//! Receivers maintain a 64-bit window of recently-accepted nonces
//! relative to the highest nonce they have ever observed.  Datagrams
//! whose nonce is below the window's lower edge or whose corresponding
//! window bit is already set are rejected with [`Error::NoiseReplay`].

use libp2p_cat_types::Error;

use crate::primitives::KEY_LEN;
use crate::symmetric::{AEAD_TAG_LEN, aead_decrypt, aead_encrypt};

/// Bytes of nonce prefixed to every transport datagram.
pub const TRANSPORT_NONCE_PREFIX_LEN: usize = 8;

/// Total per-datagram wire overhead: nonce prefix + AEAD tag.
pub const TRANSPORT_OVERHEAD: usize = TRANSPORT_NONCE_PREFIX_LEN + AEAD_TAG_LEN;

/// Width of the anti-replay sliding window in bits.
pub const REPLAY_WINDOW_BITS: usize = 64;

/// Post-handshake authenticated transport.
///
/// Linear state-threading: every [`encrypt`] and [`decrypt`] call
/// consumes `self` and returns a new state.  Send and receive nonce
/// counters are managed independently; senders never need to track
/// their peer's receive state.
///
/// [`encrypt`]: TransportState::encrypt
/// [`decrypt`]: TransportState::decrypt
#[must_use]
pub struct TransportState {
    send_key: [u8; KEY_LEN],
    send_nonce: u64,
    recv_key: [u8; KEY_LEN],
    recv_max_nonce: u64,
    recv_replay_window: u64,
}

impl TransportState {
    /// Construct fresh transport state from the two cipher keys
    /// produced by `SymmetricState::split`.
    pub(crate) fn new(send_key: [u8; KEY_LEN], recv_key: [u8; KEY_LEN]) -> Self {
        Self {
            send_key,
            send_nonce: 0,
            recv_key,
            recv_max_nonce: 0,
            recv_replay_window: 0,
        }
    }

    /// Current outbound nonce counter.  The next call to [`encrypt`]
    /// will tag the datagram with this value.
    ///
    /// [`encrypt`]: TransportState::encrypt
    #[must_use]
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce
    }

    /// Highest receive nonce ever accepted on this transport.
    #[must_use]
    pub fn recv_max_nonce(&self) -> u64 {
        self.recv_max_nonce
    }

    /// Encrypt `plaintext` into a single datagram.  The returned
    /// datagram carries an 8-byte big-endian nonce prefix; the same
    /// nonce is fed to the AEAD as its 12-byte ChaCha20-Poly1305 nonce.
    ///
    /// # Errors
    ///
    /// - [`Error::NoiseDecrypt`] propagates AEAD encryption failures
    ///   (in practice this only happens when the AEAD library refuses
    ///   an oversized plaintext).
    /// - [`Error::NoiseProtocol`] if the send-side nonce counter has
    ///   wrapped past `u64::MAX`, which would compromise security.
    pub fn encrypt(self, plaintext: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        let nonce = self.send_nonce;
        let ciphertext = aead_encrypt(&self.send_key, nonce, &[], plaintext)?;
        let datagram: Vec<u8> = nonce.to_be_bytes().into_iter().chain(ciphertext).collect();
        let next_nonce = nonce.checked_add(1).ok_or_else(|| Error::NoiseProtocol {
            reason: "send nonce counter exhausted".to_owned(),
        })?;
        Ok((
            Self {
                send_nonce: next_nonce,
                ..self
            },
            datagram,
        ))
    }

    /// Decrypt a datagram, applying replay-window checks before and
    /// after the AEAD step.
    ///
    /// # Errors
    ///
    /// - [`Error::NoiseProtocol`] if `datagram` is too short to even
    ///   contain a nonce prefix and an AEAD tag.
    /// - [`Error::NoiseReplay`] if the nonce is below the lower edge
    ///   of the replay window, or its window bit is already set.
    /// - [`Error::NoiseDecrypt`] if AEAD authentication fails.
    pub fn decrypt(self, datagram: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        let total = datagram.len();
        if total < TRANSPORT_OVERHEAD {
            Err(Error::NoiseProtocol {
                reason: format!(
                    "transport datagram too short: {total} bytes, need at least {TRANSPORT_OVERHEAD}"
                ),
            })
        } else {
            let nonce_slice = datagram.get(0..TRANSPORT_NONCE_PREFIX_LEN).ok_or_else(|| {
                Error::NoiseProtocol {
                    reason: "missing nonce prefix".to_owned(),
                }
            })?;
            let ciphertext =
                datagram
                    .get(TRANSPORT_NONCE_PREFIX_LEN..)
                    .ok_or_else(|| Error::NoiseProtocol {
                        reason: "missing ciphertext".to_owned(),
                    })?;
            let nonce_arr: [u8; TRANSPORT_NONCE_PREFIX_LEN] =
                nonce_slice.try_into().map_err(|_| Error::NoiseProtocol {
                    reason: "nonce prefix wrong length".to_owned(),
                })?;
            let nonce = u64::from_be_bytes(nonce_arr);
            nonce_acceptable(self.recv_replay_window, self.recv_max_nonce, nonce)?;
            let plaintext = aead_decrypt(&self.recv_key, nonce, &[], ciphertext)?;
            let (new_window, new_max) =
                advance_window(self.recv_replay_window, self.recv_max_nonce, nonce);
            Ok((
                Self {
                    recv_max_nonce: new_max,
                    recv_replay_window: new_window,
                    ..self
                },
                plaintext,
            ))
        }
    }
}

/// Read-only check: would `incoming` be a fresh, in-window nonce?
fn nonce_acceptable(window: u64, max_nonce: u64, incoming: u64) -> Result<(), Error> {
    if incoming > max_nonce {
        Ok(())
    } else {
        let distance = max_nonce - incoming;
        let too_old = distance >= REPLAY_WINDOW_BITS as u64;
        if too_old {
            Err(Error::NoiseReplay { nonce: incoming })
        } else {
            let bit = 1u64 << distance;
            if window & bit != 0 {
                Err(Error::NoiseReplay { nonce: incoming })
            } else {
                Ok(())
            }
        }
    }
}

/// Update the window after a successful AEAD decryption.
///
/// Caller must have already passed [`nonce_acceptable`].
fn advance_window(window: u64, max_nonce: u64, incoming: u64) -> (u64, u64) {
    if incoming > max_nonce {
        let shift = incoming - max_nonce;
        let new_window = if shift >= REPLAY_WINDOW_BITS as u64 {
            1
        } else {
            (window << shift) | 1
        };
        (new_window, incoming)
    } else {
        let distance = max_nonce - incoming;
        let bit = 1u64 << distance;
        (window | bit, max_nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_window_accepts_nonce_zero() {
        assert!(nonce_acceptable(0, 0, 0).is_ok());
    }

    #[test]
    fn replay_after_first_acceptance() {
        let (window, max) = advance_window(0, 0, 0);
        assert!(matches!(
            nonce_acceptable(window, max, 0),
            Err(Error::NoiseReplay { nonce: 0 })
        ));
    }

    #[test]
    fn out_of_order_within_window_is_accepted() {
        let (window, max) = advance_window(0, 0, 5);
        assert!(nonce_acceptable(window, max, 3).is_ok());
        let (window, max) = advance_window(window, max, 3);
        // Replaying 3 now fails.
        assert!(matches!(
            nonce_acceptable(window, max, 3),
            Err(Error::NoiseReplay { nonce: 3 })
        ));
        // Nonce 5 is also a replay.
        assert!(matches!(
            nonce_acceptable(window, max, 5),
            Err(Error::NoiseReplay { nonce: 5 })
        ));
    }

    #[test]
    fn way_old_nonce_is_rejected() {
        let (window, max) = advance_window(0, 0, 200);
        assert!(matches!(
            nonce_acceptable(window, max, 50),
            Err(Error::NoiseReplay { nonce: 50 })
        ));
    }

    #[test]
    fn jump_beyond_window_clears_lower_bits() {
        let (window, max) = advance_window(0, 0, 1);
        let (window, max) = advance_window(window, max, 100);
        assert_eq!(max, 100);
        // Window should now be just bit 0 set (only nonce 100 known).
        assert_eq!(window, 1);
        // Nonce 1 is now too old.
        assert!(matches!(
            nonce_acceptable(window, max, 1),
            Err(Error::NoiseReplay { nonce: 1 })
        ));
    }
}
