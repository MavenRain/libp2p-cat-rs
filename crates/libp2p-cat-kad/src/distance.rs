//! XOR distance metric on [`NodeId`](crate::NodeId)s.
//!
//! Distance is interpreted as a 256-bit big-endian unsigned integer.
//! [`Ord`] therefore matches the Kademlia "closer means smaller XOR"
//! convention without further interpretation.

use core::fmt;

use crate::node_id::{NODE_ID_BITS, NODE_ID_LEN};

/// XOR distance between two [`NodeId`](crate::NodeId)s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[must_use]
pub struct Distance([u8; NODE_ID_LEN]);

impl Distance {
    /// Construct a distance from its raw 32 bytes.  Public so that
    /// callers can synthesise distances in tests; the canonical path
    /// is [`crate::NodeId::distance`].
    pub fn from_bytes(bytes: [u8; NODE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The all-zero distance, equivalent to a self-distance.
    pub const ZERO: Distance = Distance([0u8; NODE_ID_LEN]);

    /// Borrow the raw 32-byte big-endian distance.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    /// Whether the distance is zero (i.e. the two `NodeId`s were equal).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Number of leading zero bits across the 32-byte big-endian
    /// distance.  Returns [`NODE_ID_BITS`] for a zero distance, in
    /// which case the value is also a sentinel for "no bucket
    /// applies."
    #[must_use]
    pub fn leading_zeros(&self) -> usize {
        self.0
            .iter()
            .enumerate()
            .find(|&(_, &byte)| byte != 0)
            .map_or(NODE_ID_BITS, |(byte_idx, &byte)| {
                byte_idx * 8 + usize::try_from(byte.leading_zeros()).unwrap_or(0)
            })
    }

    /// Bucket index for a peer at this distance, in the convention
    /// "bucket `i` holds peers whose highest-set distance bit is at
    /// position `i` (0-indexed from the LSB)."  Returns [`None`] for
    /// a zero distance (the local node has no bucket).
    ///
    /// Equivalently: `Some(NODE_ID_BITS - 1 - leading_zeros)` when
    /// non-zero.
    #[must_use]
    pub fn bucket_index(&self) -> Option<usize> {
        (!self.is_zero()).then(|| NODE_ID_BITS - 1 - self.leading_zeros())
    }
}

impl fmt::Display for Distance {
    /// Hex-encoded 32-byte distance, prefixed with `xor:`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xor:")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use libp2p_cat_types::Error;

    use super::*;
    use crate::node_id::NodeId;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    #[test]
    fn zero_distance_has_full_leading_zeros() -> Result<(), Error> {
        let d = Distance::ZERO;
        check(d.leading_zeros() == NODE_ID_BITS, || {
            format!(
                "expected {} leading zeros, got {}",
                NODE_ID_BITS,
                d.leading_zeros()
            )
        })?;
        check(d.bucket_index().is_none(), || {
            "zero distance should have no bucket index".to_owned()
        })
    }

    #[test]
    fn one_in_lsb_lives_in_bucket_zero() -> Result<(), Error> {
        let mut bytes = [0u8; NODE_ID_LEN];
        let last = bytes.last_mut().ok_or_else(|| Error::HostState {
            reason: "NODE_ID_LEN must be > 0".to_owned(),
        })?;
        *last = 1;
        let d = Distance::from_bytes(bytes);
        check(d.leading_zeros() == NODE_ID_BITS - 1, || {
            format!("leading zeros for distance 1 should be {NODE_ID_BITS} - 1")
        })?;
        check(d.bucket_index() == Some(0), || {
            format!(
                "distance 1 should land in bucket 0, got {:?}",
                d.bucket_index()
            )
        })
    }

    #[test]
    fn high_bit_set_lives_in_top_bucket() -> Result<(), Error> {
        let mut bytes = [0u8; NODE_ID_LEN];
        let first = bytes.first_mut().ok_or_else(|| Error::HostState {
            reason: "NODE_ID_LEN must be > 0".to_owned(),
        })?;
        *first = 0x80;
        let d = Distance::from_bytes(bytes);
        check(d.leading_zeros() == 0, || {
            "distance with MSB set should have 0 leading zeros".to_owned()
        })?;
        check(d.bucket_index() == Some(NODE_ID_BITS - 1), || {
            format!(
                "distance with MSB set should land in bucket {}, got {:?}",
                NODE_ID_BITS - 1,
                d.bucket_index()
            )
        })
    }

    #[test]
    fn ord_matches_unsigned_integer_compare() -> Result<(), Error> {
        let small = Distance::from_bytes(core::array::from_fn(|i| u8::from(i == NODE_ID_LEN - 1)));
        let bigger = Distance::from_bytes([0xFFu8; NODE_ID_LEN]);
        check(small < bigger, || {
            "1 should be less than 2^256 - 1 under big-endian byte order".to_owned()
        })
    }

    #[test]
    fn xor_distance_is_zero_iff_equal() -> Result<(), Error> {
        let a = NodeId::from_bytes([0x12; NODE_ID_LEN]);
        let b = NodeId::from_bytes([0x12; NODE_ID_LEN]);
        let c = NodeId::from_bytes([0x13; NODE_ID_LEN]);
        check(a.distance(&b).is_zero(), || {
            "equal NodeIds should have zero distance".to_owned()
        })?;
        check(!a.distance(&c).is_zero(), || {
            "distinct NodeIds should have non-zero distance".to_owned()
        })
    }
}
