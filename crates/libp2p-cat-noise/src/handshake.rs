//! Type-state machine for the Noise XX handshake.
//!
//! Each phase is a distinct public type so illegal sequences fail to
//! compile.  Every transition consumes the previous type and returns
//! the next one (plus, where appropriate, the on-wire bytes).
//!
//! # Wire-format constants
//!
//! - Message 1 (initiator → responder): 32 bytes — `e`.
//! - Message 2 (responder → initiator): 96 bytes — `e || enc(s) || enc(empty payload)`.
//! - Message 3 (initiator → responder): 64 bytes — `enc(s) || enc(empty payload)`.
//!
//! # Token interpretation
//!
//! Noise's `ee`, `es`, `se` tokens are framed by initiator/responder
//! roles (first letter = initiator's key, second = responder's).
//! Internally we use [`crate::primitives::dh_ee`] / `dh_es` / `dh_se`
//! named by which side is private and which is public:
//!
//! | Noise token | Initiator side                 | Responder side                |
//! |-------------|--------------------------------|-------------------------------|
//! | `ee`        | `dh_ee(own_eph, remote_eph)`   | `dh_ee(own_eph, remote_eph)`  |
//! | `es`        | `dh_es(own_eph, remote_static)`| `dh_se(own_static, remote_eph)` |
//! | `se`        | `dh_se(own_static, remote_eph)`| `dh_es(own_eph, remote_static)` |

use libp2p_cat_types::Error;

use crate::primitives::{
    EphemeralPrivateKey, EphemeralPublicKey, KEY_LEN, StaticKeypair, StaticPublicKey, dh_ee, dh_es,
    dh_se,
};
use crate::symmetric::{AEAD_TAG_LEN, SymmetricState};
use crate::transport::TransportState;

/// Length of an X25519 public key on the wire, in bytes.
const EPH_PUBLIC_LEN: usize = KEY_LEN;

/// Length of an encrypted-and-tagged static public key on the wire.
const ENC_STATIC_LEN: usize = KEY_LEN + AEAD_TAG_LEN;

/// Length of an encrypted empty-payload trailer (just the AEAD tag).
const ENC_EMPTY_PAYLOAD_LEN: usize = AEAD_TAG_LEN;

/// Wire length of the first handshake message (initiator → responder).
pub const MESSAGE_1_LEN: usize = EPH_PUBLIC_LEN;

/// Wire length of the second handshake message (responder → initiator).
pub const MESSAGE_2_LEN: usize = EPH_PUBLIC_LEN + ENC_STATIC_LEN + ENC_EMPTY_PAYLOAD_LEN;

/// Wire length of the third handshake message (initiator → responder).
pub const MESSAGE_3_LEN: usize = ENC_STATIC_LEN + ENC_EMPTY_PAYLOAD_LEN;

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

/// Initial state for an XX initiator: holds its long-lived keypair
/// and the freshly-initialised symmetric state.
#[must_use]
pub struct Initiator {
    static_keypair: StaticKeypair,
    sym: SymmetricState,
}

impl Initiator {
    /// Begin a fresh handshake as the initiator.
    pub fn new(static_keypair: StaticKeypair) -> Self {
        Self {
            static_keypair,
            sym: SymmetricState::initialize(),
        }
    }

    /// Write the first handshake message (token: `e`).
    ///
    /// `ephemeral_seed` is 32 bytes that the caller has sourced from a
    /// cryptographically secure RNG.  This function never reads from
    /// the system entropy source itself.
    ///
    /// # Errors
    ///
    /// Currently infallible; the result type is preserved for symmetry
    /// with later transitions and in case a future variant attaches a
    /// non-empty handshake payload.
    pub fn write_e(
        self,
        ephemeral_seed: [u8; KEY_LEN],
    ) -> Result<(InitiatorAfterE, Vec<u8>), Error> {
        let eph_private = EphemeralPrivateKey::from_seed(ephemeral_seed);
        let eph_public = eph_private.public();
        let sym = self.sym.mix_hash(eph_public.as_bytes());
        let (sym, trailing) = sym.encrypt_and_hash(&[])?;
        let msg: Vec<u8> = eph_public
            .as_bytes()
            .iter()
            .copied()
            .chain(trailing)
            .collect();
        Ok((
            InitiatorAfterE {
                static_keypair: self.static_keypair,
                eph_private,
                sym,
            },
            msg,
        ))
    }
}

/// Initiator state after sending message 1, awaiting message 2.
#[must_use]
pub struct InitiatorAfterE {
    static_keypair: StaticKeypair,
    eph_private: EphemeralPrivateKey,
    sym: SymmetricState,
}

impl InitiatorAfterE {
    /// Read the responder's reply (tokens: `e, ee, s, es`).
    ///
    /// On success returns an [`InitiatorAfterResponse`] from which the
    /// remote static public key can be inspected before the final
    /// outbound message is written.
    ///
    /// # Errors
    ///
    /// - [`Error::NoiseProtocol`] if `msg.len()` is not exactly
    ///   [`MESSAGE_2_LEN`] or any internal slice fails to parse.
    /// - [`Error::NoiseDecrypt`] if the AEAD on the encrypted static
    ///   key or the trailing payload fails to authenticate.
    pub fn read_response(self, msg: &[u8]) -> Result<InitiatorAfterResponse, Error> {
        let total_len = msg.len();
        if total_len == MESSAGE_2_LEN {
            let e_slice = msg
                .get(0..EPH_PUBLIC_LEN)
                .ok_or_else(|| protocol_error("missing remote ephemeral"))?;
            let enc_static_slice = msg
                .get(EPH_PUBLIC_LEN..EPH_PUBLIC_LEN + ENC_STATIC_LEN)
                .ok_or_else(|| protocol_error("missing encrypted static"))?;
            let enc_payload_slice = msg
                .get(EPH_PUBLIC_LEN + ENC_STATIC_LEN..)
                .ok_or_else(|| protocol_error("missing trailing payload"))?;

            let remote_eph = EphemeralPublicKey::from_bytes(parse_32(e_slice)?);
            // ee
            let sym = self.sym.mix_hash(remote_eph.as_bytes());
            let sym = sym.mix_key(&dh_ee(&self.eph_private, &remote_eph));
            // s
            let (sym, remote_static_plain) = sym.decrypt_and_hash(enc_static_slice)?;
            let remote_static = StaticPublicKey::from_bytes(parse_32(&remote_static_plain)?);
            // es: dh(initiator_e, responder_s) — initiator side: dh_es(own_eph, remote_static)
            let sym = sym.mix_key(&dh_es(&self.eph_private, &remote_static));
            // empty payload trailer
            let (sym, _empty) = sym.decrypt_and_hash(enc_payload_slice)?;
            Ok(InitiatorAfterResponse {
                static_keypair: self.static_keypair,
                remote_eph,
                remote_static,
                sym,
            })
        } else {
            Err(Error::NoiseProtocol {
                reason: format!(
                    "expected {MESSAGE_2_LEN}-byte handshake message 2, got {total_len}"
                ),
            })
        }
    }
}

/// Initiator state after reading message 2.  At this point the
/// remote's static public key is authenticated and accessible via
/// [`InitiatorAfterResponse::remote_static`].
#[must_use]
pub struct InitiatorAfterResponse {
    static_keypair: StaticKeypair,
    remote_eph: EphemeralPublicKey,
    remote_static: StaticPublicKey,
    sym: SymmetricState,
}

impl InitiatorAfterResponse {
    /// Borrow the remote peer's authenticated static public key.
    pub fn remote_static(&self) -> &StaticPublicKey {
        &self.remote_static
    }

    /// Write the third handshake message (tokens: `s, se`) and
    /// transition into the post-handshake transport state.
    ///
    /// Returns the [`TransportState`], the on-wire bytes, and the
    /// remote's authenticated static public key.
    ///
    /// # Errors
    ///
    /// - [`Error::NoiseDecrypt`] if AEAD encryption fails.
    pub fn write_s(self) -> Result<(TransportState, Vec<u8>, StaticPublicKey), Error> {
        // s
        let (sym, enc_static) = self
            .sym
            .encrypt_and_hash(self.static_keypair.public().as_bytes())?;
        // se: dh(initiator_s, responder_e) — initiator side: dh_se(own_static, remote_eph)
        let sym = sym.mix_key(&dh_se(self.static_keypair.private(), &self.remote_eph));
        // empty payload trailer
        let (sym, enc_payload) = sym.encrypt_and_hash(&[])?;
        let (initiator_to_responder, responder_to_initiator) = sym.split();
        let transport = TransportState::new(initiator_to_responder, responder_to_initiator);
        let msg: Vec<u8> = enc_static.into_iter().chain(enc_payload).collect();
        Ok((transport, msg, self.remote_static))
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// Initial state for an XX responder: holds its long-lived keypair
/// and the freshly-initialised symmetric state.
#[must_use]
pub struct Responder {
    static_keypair: StaticKeypair,
    sym: SymmetricState,
}

impl Responder {
    /// Begin a fresh handshake as the responder.
    pub fn new(static_keypair: StaticKeypair) -> Self {
        Self {
            static_keypair,
            sym: SymmetricState::initialize(),
        }
    }

    /// Read the initiator's first message (token: `e`).
    ///
    /// # Errors
    ///
    /// - [`Error::NoiseProtocol`] if `msg.len()` is not [`MESSAGE_1_LEN`].
    pub fn read_e(self, msg: &[u8]) -> Result<ResponderAfterE, Error> {
        let total_len = msg.len();
        if total_len == MESSAGE_1_LEN {
            let e_slice = msg
                .get(0..EPH_PUBLIC_LEN)
                .ok_or_else(|| protocol_error("missing remote ephemeral"))?;
            let remote_eph = EphemeralPublicKey::from_bytes(parse_32(e_slice)?);
            let sym = self.sym.mix_hash(remote_eph.as_bytes());
            // Mirror the initiator's `encrypt_and_hash(b"")` trailer so
            // both sides advance the running hash by the same `MixHash`
            // call.  With `k` unset this acts as `mix_hash(b"")`.
            let (sym, _empty) = sym.decrypt_and_hash(&[])?;
            Ok(ResponderAfterE {
                static_keypair: self.static_keypair,
                remote_eph,
                sym,
            })
        } else {
            Err(Error::NoiseProtocol {
                reason: format!(
                    "expected {MESSAGE_1_LEN}-byte handshake message 1, got {total_len}"
                ),
            })
        }
    }
}

/// Responder state after reading message 1, ready to write message 2.
#[must_use]
pub struct ResponderAfterE {
    static_keypair: StaticKeypair,
    remote_eph: EphemeralPublicKey,
    sym: SymmetricState,
}

impl ResponderAfterE {
    /// Write the responder's reply (tokens: `e, ee, s, es`).
    ///
    /// `ephemeral_seed` is 32 bytes from a CSPRNG.
    ///
    /// # Errors
    ///
    /// - [`Error::NoiseDecrypt`] if AEAD encryption fails.
    pub fn write_response(
        self,
        ephemeral_seed: [u8; KEY_LEN],
    ) -> Result<(ResponderAfterResponse, Vec<u8>), Error> {
        let eph_private = EphemeralPrivateKey::from_seed(ephemeral_seed);
        let eph_public = eph_private.public();
        // e
        let sym = self.sym.mix_hash(eph_public.as_bytes());
        // ee: dh(initiator_e, responder_e) — responder side: dh_ee(own_eph, remote_eph)
        let sym = sym.mix_key(&dh_ee(&eph_private, &self.remote_eph));
        // s
        let (sym, enc_static) = sym.encrypt_and_hash(self.static_keypair.public().as_bytes())?;
        // es: dh(initiator_e, responder_s) — responder side: dh_se(own_static, remote_eph)
        let sym = sym.mix_key(&dh_se(self.static_keypair.private(), &self.remote_eph));
        // empty payload trailer
        let (sym, enc_payload) = sym.encrypt_and_hash(&[])?;
        let msg: Vec<u8> = eph_public
            .as_bytes()
            .iter()
            .copied()
            .chain(enc_static)
            .chain(enc_payload)
            .collect();
        Ok((ResponderAfterResponse { eph_private, sym }, msg))
    }
}

/// Responder state after writing message 2, awaiting message 3.
#[must_use]
pub struct ResponderAfterResponse {
    eph_private: EphemeralPrivateKey,
    sym: SymmetricState,
}

impl ResponderAfterResponse {
    /// Read the initiator's final message (tokens: `s, se`) and
    /// transition into the post-handshake transport state.
    ///
    /// Returns the [`TransportState`] and the initiator's
    /// authenticated static public key.
    ///
    /// # Errors
    ///
    /// - [`Error::NoiseProtocol`] if `msg.len()` is not [`MESSAGE_3_LEN`].
    /// - [`Error::NoiseDecrypt`] if AEAD authentication fails.
    pub fn read_s(self, msg: &[u8]) -> Result<(TransportState, StaticPublicKey), Error> {
        let total_len = msg.len();
        if total_len == MESSAGE_3_LEN {
            let enc_static_slice = msg
                .get(0..ENC_STATIC_LEN)
                .ok_or_else(|| protocol_error("missing encrypted static"))?;
            let enc_payload_slice = msg
                .get(ENC_STATIC_LEN..)
                .ok_or_else(|| protocol_error("missing trailing payload"))?;
            // s
            let (sym, remote_static_plain) = self.sym.decrypt_and_hash(enc_static_slice)?;
            let remote_static = StaticPublicKey::from_bytes(parse_32(&remote_static_plain)?);
            // se: dh(initiator_s, responder_e) — responder side: dh_es(own_eph, remote_static)
            let sym = sym.mix_key(&dh_es(&self.eph_private, &remote_static));
            // empty payload trailer
            let (sym, _empty) = sym.decrypt_and_hash(enc_payload_slice)?;
            let (initiator_to_responder, responder_to_initiator) = sym.split();
            // Responder sends r->i and receives i->r.
            let transport = TransportState::new(responder_to_initiator, initiator_to_responder);
            Ok((transport, remote_static))
        } else {
            Err(Error::NoiseProtocol {
                reason: format!(
                    "expected {MESSAGE_3_LEN}-byte handshake message 3, got {total_len}"
                ),
            })
        }
    }
}

fn protocol_error(reason: &str) -> Error {
    Error::NoiseProtocol {
        reason: reason.to_owned(),
    }
}

fn parse_32(slice: &[u8]) -> Result<[u8; KEY_LEN], Error> {
    <[u8; KEY_LEN]>::try_from(slice).map_err(|_| Error::NoiseProtocol {
        reason: format!("expected {KEY_LEN} bytes, got {}", slice.len()),
    })
}
