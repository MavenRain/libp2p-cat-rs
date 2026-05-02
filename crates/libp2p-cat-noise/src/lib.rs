//! Noise XX handshake and authenticated transport for `libp2p-cat-rs`.
//!
//! # Suite
//!
//! This crate implements **`Noise_XX_25519_ChaChaPoly_BLAKE3`** — a
//! deliberate non-standard variant of the canonical Noise framework.
//! BLAKE3 replaces SHA-256 / SHA-512 / BLAKE2 for both the symmetric
//! state's running hash and the key-derivation step (`MixKey`,
//! `Split`).  The choice is motivated by:
//!
//! - `blake3` is already in this workspace's dependency graph via
//!   `rlnc-cat-rs`.  Adding `sha2` for one consumer would inflate the
//!   crypto surface.
//! - The wire is UDP-only and not interoperable with golibp2p's
//!   TCP/QUIC Noise sessions, so departing from the canonical suite
//!   costs nothing in terms of cross-implementation interop.
//!
//! BLAKE3 keyed-mode is used as the underlying PRF for `MixKey` and
//! `Split`: `blake3::Hasher::new_keyed(ck).update(input).finalize_xof()`
//! is read for the required output bytes.  This is sound because
//! BLAKE3-keyed is a PRF; the mechanical structure of the Noise spec's
//! `HKDF` is replaced but the security goal (independent keys derived
//! from a shared secret) is preserved.
//!
//! # Datagram framing
//!
//! Post-handshake transport messages are wire-encoded as
//! `nonce_be8 || ciphertext` where the AEAD nonce on the wire is an
//! 8-byte big-endian counter; the ChaCha20-Poly1305 nonce is the
//! 12-byte form `0x00 0x00 0x00 0x00 || counter_le8`.  The receiver
//! maintains a 64-bit sliding replay window keyed on the highest
//! observed nonce; out-of-order datagrams within the window are
//! accepted, replays and below-window arrivals are rejected with
//! [`Error::NoiseReplay`].
//!
//! # Type-state API
//!
//! Each phase of the handshake is a distinct public type so illegal
//! sequences fail to compile:
//!
//! ```text
//! Initiator    -- write_e -->  InitiatorAfterE
//! InitiatorAfterE          -- read_response -->  InitiatorAfterResponse
//! InitiatorAfterResponse   -- write_s -->  TransportState
//!
//! Responder    -- read_e -->  ResponderAfterE
//! ResponderAfterE          -- write_response -->  ResponderAfterResponse
//! ResponderAfterResponse   -- read_s -->  TransportState
//! ```
//!
//! Every method consumes `self`; nothing is mutated in place.
//!
//! # Out of scope (for now)
//!
//! - **Prologue.**  Standard Noise allows mixing arbitrary bytes into
//!   `h` before the first message; not currently exposed.
//! - **Handshake payloads.**  Standard Noise allows attaching a
//!   plaintext payload to each handshake message; not exposed.
//! - **Identity binding.**  X25519 static keys here are not yet linked
//!   to libp2p Ed25519 `PeerId`s; the libp2p signed-Noise-extension
//!   binding is planned for `libp2p-cat-host`.
//!
//! [`Error::NoiseReplay`]: libp2p_cat_types::Error::NoiseReplay

#![forbid(unsafe_code)]

mod handshake;
mod primitives;
mod symmetric;
mod transport;

pub use handshake::{
    Initiator, InitiatorAfterE, InitiatorAfterResponse, MESSAGE_1_LEN, MESSAGE_2_LEN,
    MESSAGE_3_LEN, Responder, ResponderAfterE, ResponderAfterResponse,
};
pub use primitives::{StaticKeypair, StaticPrivateKey, StaticPublicKey};
pub use transport::{
    REPLAY_WINDOW_BITS, TRANSPORT_NONCE_PREFIX_LEN, TRANSPORT_OVERHEAD, TransportState,
};
