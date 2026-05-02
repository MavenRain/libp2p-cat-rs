//! Peer identifier matching libp2p's multihash-of-public-key convention.
//!
//! A [`PeerId`] is the multihash of a protobuf-encoded libp2p
//! `PublicKey` message:
//!
//! ```text
//! message PublicKey {
//!   KeyType Type = 1;   // varint enum: RSA=0, Ed25519=1, Secp256k1=2, ECDSA=3
//!   bytes   Data = 2;
//! }
//! ```
//!
//! For protobuf encodings of at most [`MAX_INLINE_KEY_BYTES`] bytes the
//! multihash code is `0x00` (identity, i.e. the bytes are embedded
//! verbatim); above that threshold libp2p uses sha256 (code `0x12`).
//!
//! This module currently implements the identity-multihash path, which
//! covers Ed25519 (38-byte `PeerId`), Secp256k1, and the X25519 keys we
//! intend to use during the Noise handshake.  The sha256 path is left
//! to a future crate that takes a hash-function dependency.
//!
//! # Examples
//!
//! ```
//! use libp2p_cat_types::PeerId;
//!
//! // 32 zero bytes is a perfectly fine input shape, even if it's not a
//! // real Ed25519 public key.  PeerId construction is a syntactic
//! // operation; key validity is checked elsewhere.
//! let zero_key = [0u8; 32];
//! let id = PeerId::from_ed25519(&zero_key);
//! assert_eq!(id.as_bytes().len(), 38);
//! // Identity multihash code, then varint length 36, then the
//! // protobuf-encoded PublicKey.
//! assert_eq!(id.as_bytes().get(..2), Some(&[0x00, 0x24][..]));
//! ```

use core::fmt;

use crate::error::Error;

/// libp2p threshold above which `PublicKey` protobufs are sha256-hashed
/// rather than embedded verbatim in the multihash.
pub const MAX_INLINE_KEY_BYTES: usize = 42;

/// libp2p `KeyType` enum value for Ed25519.
const KEY_TYPE_ED25519: u8 = 1;

/// Multihash code for the identity (no-hash) function.
const IDENTITY_MULTIHASH_CODE: u8 = 0x00;

/// Length of an Ed25519 public key in bytes.
const ED25519_KEY_LEN: usize = 32;

/// Length of the protobuf-encoded `PublicKey` for Ed25519:
/// 2-byte tag for `Type`, plus 2-byte length-prefix for `Data`,
/// plus the 32-byte key.
const ED25519_PROTOBUF_LEN: usize = 4 + ED25519_KEY_LEN;

/// Length of an Ed25519 [`PeerId`] in bytes: identity multihash code,
/// single-byte varint length, plus the protobuf payload.
const ED25519_PEER_ID_LEN: usize = 2 + ED25519_PROTOBUF_LEN;

/// A peer identifier: the multihash of a protobuf-encoded libp2p
/// `PublicKey` message.
///
/// Stores the raw multihash bytes (code + length-prefix + digest) so
/// that two `PeerId`s compare for equality byte-for-byte and hash by
/// the same bytes that travel on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[must_use]
pub struct PeerId(Box<[u8]>);

impl PeerId {
    /// Construct a `PeerId` from a 32-byte raw Ed25519 public key.
    ///
    /// This is infallible: Ed25519 keys produce a 36-byte protobuf,
    /// which fits comfortably under [`MAX_INLINE_KEY_BYTES`] and so
    /// always uses the identity multihash.
    pub fn from_ed25519(key: &[u8; ED25519_KEY_LEN]) -> Self {
        let pb = ed25519_protobuf(key);
        let mh = identity_multihash_from_array(&pb);
        Self(Box::from(mh.as_slice()))
    }

    /// Construct a `PeerId` from a fully-encoded libp2p `PublicKey`
    /// protobuf message.
    ///
    /// Uses the identity multihash if `pb.len() <= MAX_INLINE_KEY_BYTES`.
    /// Longer keys would require sha256, which this crate does not
    /// currently provide; callers in that range receive an error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPeerId`] if the protobuf exceeds the
    /// inline-multihash threshold.
    pub fn from_public_key_protobuf(pb: &[u8]) -> Result<Self, Error> {
        let len = pb.len();
        u8::try_from(len)
            .ok()
            .filter(|&n| usize::from(n) <= MAX_INLINE_KEY_BYTES && n < 0x80)
            .map(|n| {
                let bytes: Vec<u8> = [IDENTITY_MULTIHASH_CODE, n]
                    .into_iter()
                    .chain(pb.iter().copied())
                    .collect();
                Self(bytes.into_boxed_slice())
            })
            .ok_or_else(|| Error::InvalidPeerId {
                reason: format!(
                    "public-key protobuf of {len} bytes exceeds the inline-multihash limit \
                     of {MAX_INLINE_KEY_BYTES}; sha256-hashed PeerIds are not yet supported"
                ),
            })
    }

    /// Borrow the raw multihash bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Total length of the multihash in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the multihash is empty.  Always false for a
    /// well-constructed `PeerId`; provided for `is_empty` consistency.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for PeerId {
    /// Hex-encoded multihash bytes, prefixed with `mh:` to make the
    /// non-canonical encoding obvious.
    ///
    /// libp2p's canonical `PeerId` rendering is base58btc of the
    /// multihash; that encoding is intentionally deferred to a later
    /// crate with a `multibase` dependency.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mh:")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Encode an Ed25519 public key as the libp2p `PublicKey` protobuf:
/// `[0x08, 0x01, 0x12, 0x20] || key`.
fn ed25519_protobuf(key: &[u8; ED25519_KEY_LEN]) -> [u8; ED25519_PROTOBUF_LEN] {
    let key_len = u8::try_from(ED25519_KEY_LEN).unwrap_or(0);
    core::array::from_fn(|i| match i {
        0 => 0x08,
        1 => KEY_TYPE_ED25519,
        2 => 0x12,
        3 => key_len,
        n => key.get(n - 4).copied().unwrap_or(0),
    })
}

/// Build the identity multihash for a fixed-size payload, returning a
/// stack-allocated array sized for the Ed25519 case.
///
/// Single-byte varint length encoding is sufficient because
/// `ED25519_PROTOBUF_LEN` is 36, well below the 128-byte single-byte
/// varint ceiling.
fn identity_multihash_from_array(pb: &[u8; ED25519_PROTOBUF_LEN]) -> [u8; ED25519_PEER_ID_LEN] {
    let len_byte = u8::try_from(ED25519_PROTOBUF_LEN).unwrap_or(0);
    core::array::from_fn(|i| match i {
        0 => IDENTITY_MULTIHASH_CODE,
        1 => len_byte,
        n => pb.get(n - 2).copied().unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_peer_id_has_canonical_38_byte_shape() {
        let key = [0u8; 32];
        let id = PeerId::from_ed25519(&key);
        let bytes = id.as_bytes();
        assert_eq!(bytes.len(), 38);
        // Identity multihash code, varint length 36.
        assert_eq!(bytes.first(), Some(&0x00));
        assert_eq!(bytes.get(1), Some(&0x24));
        // Protobuf header: tag1=Ed25519, tag2=len-prefixed 32 bytes.
        assert_eq!(bytes.get(2..6), Some(&[0x08, 0x01, 0x12, 0x20][..]));
        // Embedded key bytes are zero in this test.
        assert!(bytes.get(6..).is_some_and(|s| s.iter().all(|&b| b == 0)));
    }

    #[test]
    fn ed25519_peer_id_embeds_supplied_key_bytes() {
        let key: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        let id = PeerId::from_ed25519(&key);
        let bytes = id.as_bytes();
        assert_eq!(bytes.get(6..), Some(&key[..]));
    }

    #[test]
    fn equality_is_by_multihash_bytes() {
        let key = [7u8; 32];
        let a = PeerId::from_ed25519(&key);
        let b = PeerId::from_ed25519(&key);
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_keys_produce_distinct_peer_ids() {
        let a = PeerId::from_ed25519(&[1u8; 32]);
        let b = PeerId::from_ed25519(&[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn from_public_key_protobuf_accepts_inline_payloads() -> Result<(), Error> {
        // Build the same protobuf the Ed25519 path produces.
        let key = [9u8; 32];
        let pb: Vec<u8> = [0x08u8, 0x01, 0x12, 0x20]
            .into_iter()
            .chain(key.iter().copied())
            .collect();
        let id = PeerId::from_public_key_protobuf(&pb)?;
        assert_eq!(id, PeerId::from_ed25519(&key));
        Ok(())
    }

    #[test]
    fn from_public_key_protobuf_rejects_oversized_payloads() {
        let oversized = vec![0u8; MAX_INLINE_KEY_BYTES + 1];
        let r = PeerId::from_public_key_protobuf(&oversized);
        assert!(matches!(r, Err(Error::InvalidPeerId { .. })));
    }

    #[test]
    fn display_emits_mh_prefixed_hex() {
        let id = PeerId::from_ed25519(&[0u8; 32]);
        let s = id.to_string();
        assert!(s.starts_with("mh:"));
        // 3 prefix characters + 2 chars per byte * 38 bytes = 79.
        assert_eq!(s.len(), 3 + 2 * 38);
    }
}
