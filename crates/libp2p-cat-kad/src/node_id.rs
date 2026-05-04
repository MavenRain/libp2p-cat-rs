//! Fixed-width Kademlia identifier derived from a libp2p
//! [`PeerId`](libp2p_cat_types::PeerId).

use core::fmt;

use libp2p_cat_types::PeerId;

use crate::distance::Distance;

/// Width of a [`NodeId`] in bytes.
pub const NODE_ID_LEN: usize = 32;

/// Width of a [`NodeId`] in bits.  This also fixes the number of
/// k-buckets in a [`crate::RoutingTable`].
pub const NODE_ID_BITS: usize = NODE_ID_LEN * 8;

/// 256-bit Kademlia identifier.
///
/// Construct via [`NodeId::from_peer_id`] (the canonical path) or
/// [`NodeId::from_bytes`] (for tests and serialisation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[must_use]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    /// Derive a [`NodeId`] from a [`PeerId`] by hashing its multihash
    /// bytes with BLAKE3 and truncating to 32 bytes (BLAKE3's default
    /// output width).
    pub fn from_peer_id(peer_id: &PeerId) -> Self {
        Self(*blake3::hash(peer_id.as_bytes()).as_bytes())
    }

    /// Build a [`NodeId`] directly from its 32 raw bytes.  Useful for
    /// tests and for parsing wire-format identifiers in pass 2.
    pub fn from_bytes(bytes: [u8; NODE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32-byte identifier.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    /// XOR distance to another [`NodeId`].  Symmetric and zero iff
    /// `self == other`.
    pub fn distance(&self, other: &Self) -> Distance {
        Distance::from_bytes(core::array::from_fn(|i| {
            let a = self.0.get(i).copied().unwrap_or(0);
            let b = other.0.get(i).copied().unwrap_or(0);
            a ^ b
        }))
    }
}

impl From<[u8; NODE_ID_LEN]> for NodeId {
    fn from(bytes: [u8; NODE_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for NodeId {
    /// Hex-encoded 32-byte identifier, prefixed with `kad:` to make
    /// the encoding obvious at sight.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("kad:")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use libp2p_cat_types::Error;

    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    #[test]
    fn from_peer_id_is_deterministic() -> Result<(), Error> {
        let pid = PeerId::from_ed25519(&[3u8; 32]);
        let a = NodeId::from_peer_id(&pid);
        let b = NodeId::from_peer_id(&pid);
        check(a == b, || {
            "same PeerId produced different NodeIds".to_owned()
        })
    }

    #[test]
    fn distinct_peer_ids_produce_distinct_node_ids() -> Result<(), Error> {
        let pa = PeerId::from_ed25519(&[3u8; 32]);
        let pb = PeerId::from_ed25519(&[4u8; 32]);
        let a = NodeId::from_peer_id(&pa);
        let b = NodeId::from_peer_id(&pb);
        check(a != b, || {
            "distinct PeerIds collided to one NodeId".to_owned()
        })
    }

    #[test]
    fn distance_to_self_is_zero() -> Result<(), Error> {
        let id = NodeId::from_bytes([0x55; NODE_ID_LEN]);
        let d = id.distance(&id);
        check(d.is_zero(), || {
            "distance from a NodeId to itself must be zero".to_owned()
        })
    }

    #[test]
    fn distance_is_symmetric() -> Result<(), Error> {
        let a = NodeId::from_bytes([0xAA; NODE_ID_LEN]);
        let b = NodeId::from_bytes([0x33; NODE_ID_LEN]);
        check(a.distance(&b) == b.distance(&a), || {
            "XOR distance must be symmetric".to_owned()
        })
    }

    #[test]
    fn display_emits_kad_prefixed_hex() -> Result<(), Error> {
        let id = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let s = id.to_string();
        check(s.starts_with("kad:"), || {
            format!("display should be kad:-prefixed hex, got {s}")
        })?;
        check(s.len() == 4 + 2 * NODE_ID_LEN, || {
            format!("unexpected display length {}", s.len())
        })
    }
}
