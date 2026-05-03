//! Ed25519 identity layer for `libp2p-cat-rs`.
//!
//! This crate binds an Ed25519 identity keypair to the X25519
//! [`StaticPublicKey`](libp2p_cat_noise::StaticPublicKey) used by
//! the Noise XX handshake.  The bridge is a domain-separated
//! Ed25519 signature over the X25519 static key bytes; a verifier
//! holding the wire payload reconstructs the signed input, checks
//! the signature against the embedded Ed25519 public key, and
//! derives the libp2p-compatible
//! [`PeerId`](libp2p_cat_types::PeerId) on success.
//!
//! # Wire format
//!
//! [`SignedStaticKey::to_bytes`] emits a fixed 96-byte payload:
//!
//! ```text
//! +-------------------------+----------------------------+
//! | ed25519_public_key (32) | ed25519_signature (64)     |
//! +-------------------------+----------------------------+
//! ```
//!
//! No length prefix, no protobuf wrapping.  The libp2p
//! interoperability story is solely at the
//! [`PeerId`](libp2p_cat_types::PeerId) layer; this binding payload
//! is a libp2p-cat-only construction.
//!
//! # Domain separation
//!
//! The signed input is `DOMAIN_TAG || x25519_static_pubkey` where
//! [`DOMAIN_TAG`] is a fixed ASCII prefix.  The prefix prevents an
//! attacker from replaying a libp2p-cat identity signature into a
//! different Ed25519 use site (or the converse).
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use libp2p_cat_identity::{Ed25519Keypair, SignedStaticKey};
//! use libp2p_cat_noise::StaticKeypair;
//!
//! let identity = Ed25519Keypair::from_seed([7u8; 32]);
//! let static_keypair = StaticKeypair::from_private_bytes([9u8; 32]);
//!
//! let signed = SignedStaticKey::create(&identity, static_keypair.public())?;
//! let bytes = signed.to_bytes();
//!
//! let parsed = SignedStaticKey::from_bytes(&bytes)?;
//! let (public_key, peer_id) = parsed.verify(static_keypair.public())?;
//! (public_key.as_bytes() == identity.public().as_bytes())
//!     .then_some(())
//!     .ok_or("verified key does not match signing identity")?;
//! (peer_id == identity.peer_id())
//!     .then_some(())
//!     .ok_or("verified peer id does not match signing identity")?;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

mod keypair;
mod signed_static_key;

pub use keypair::{
    DOMAIN_TAG, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519Keypair, Ed25519PublicKey,
    Ed25519Signature,
};
pub use signed_static_key::SignedStaticKey;
