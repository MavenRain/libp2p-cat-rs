//! A single Kademlia k-bucket.
//!
//! A [`Bucket`] holds up to `capacity` `(NodeId, UdpAddr)` entries,
//! ordered most-recently-seen-first.  Pass 1 is offline: the bucket
//! has no concept of "ping the LRU" (no wire), so when an insert
//! arrives at a full bucket the bucket reports the LRU candidate via
//! [`InsertOutcome::BucketFull`] and lets the caller decide.  Pass 2
//! will hook a wire-side ping callback under the same enum surface.

use libp2p_cat_types::UdpAddr;

use crate::node_id::NodeId;

/// Default replication factor recommended by the Kademlia paper.
pub const DEFAULT_K: usize = 20;

/// What happened when a peer was offered to a bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum InsertOutcome {
    /// The peer was new and the bucket had room; it was added at the
    /// most-recently-seen end.
    Added,
    /// The peer was already present; it was moved to the
    /// most-recently-seen end.  No size change.
    Updated,
    /// The bucket was full and the new peer was *not* added.  The
    /// caller may want to ping `lru_candidate` and, if it does not
    /// respond, evict it and re-offer the new peer.
    BucketFull {
        /// The least-recently-seen peer currently in the bucket.
        lru_candidate: NodeId,
    },
}

/// A k-bucket: an LRU-ordered, size-capped list of peers.
#[derive(Clone, Debug)]
#[must_use]
pub struct Bucket {
    capacity: usize,
    /// Most-recently-seen first; oldest at the back.
    entries: Vec<(NodeId, UdpAddr)>,
}

impl Bucket {
    /// Build an empty bucket with the given capacity.  The capacity
    /// is also the bucket's `k` parameter.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Replication-factor (`k`) for this bucket.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of peers currently in the bucket.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the bucket holds zero peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the bucket is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.entries.len() == self.capacity
    }

    /// Iterate over `(NodeId, UdpAddr)` pairs in most-recently-seen-first order.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &UdpAddr)> {
        self.entries.iter().map(|(id, addr)| (id, addr))
    }

    /// Whether `node` is currently a member of the bucket.
    #[must_use]
    pub fn contains(&self, node: &NodeId) -> bool {
        self.entries.iter().any(|(id, _)| id == node)
    }

    /// Offer a peer to the bucket.  Consumes `self` and returns the
    /// updated bucket alongside the [`InsertOutcome`].
    pub fn insert(self, node: NodeId, addr: UdpAddr) -> (Self, InsertOutcome) {
        let Self {
            capacity,
            mut entries,
        } = self;
        let existing_idx = entries.iter().position(|(id, _)| id == &node);
        match existing_idx {
            Some(idx) => {
                let removed = entries.remove(idx);
                let refreshed = (removed.0, addr);
                let next: Vec<(NodeId, UdpAddr)> =
                    core::iter::once(refreshed).chain(entries).collect();
                (
                    Self {
                        capacity,
                        entries: next,
                    },
                    InsertOutcome::Updated,
                )
            }
            None => {
                if entries.len() < capacity {
                    let next: Vec<(NodeId, UdpAddr)> =
                        core::iter::once((node, addr)).chain(entries).collect();
                    (
                        Self {
                            capacity,
                            entries: next,
                        },
                        InsertOutcome::Added,
                    )
                } else {
                    let lru = entries.last().map_or_else(
                        || NodeId::from_bytes([0u8; crate::NODE_ID_LEN]),
                        |(id, _)| *id,
                    );
                    (
                        Self { capacity, entries },
                        InsertOutcome::BucketFull { lru_candidate: lru },
                    )
                }
            }
        }
    }

    /// Remove a peer from the bucket if present.  Consumes `self` and
    /// returns the updated bucket; the result is unchanged when
    /// `node` was not a member.
    pub fn remove(self, node: &NodeId) -> Self {
        let Self { capacity, entries } = self;
        let next: Vec<(NodeId, UdpAddr)> =
            entries.into_iter().filter(|(id, _)| id != node).collect();
        Self {
            capacity,
            entries: next,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use libp2p_cat_types::Error;

    use super::*;
    use crate::node_id::NODE_ID_LEN;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    fn addr_for_port(port: u16) -> UdpAddr {
        UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn id_for_byte(b: u8) -> NodeId {
        NodeId::from_bytes([b; NODE_ID_LEN])
    }

    #[test]
    fn empty_bucket_reports_zero_len_and_not_full() -> Result<(), Error> {
        let bucket = Bucket::new(3);
        check(bucket.is_empty(), || {
            "fresh bucket should be empty".to_owned()
        })?;
        check(!bucket.is_full(), || {
            "fresh bucket of capacity 3 should not be full".to_owned()
        })
    }

    #[test]
    fn first_insert_into_empty_bucket_reports_added() -> Result<(), Error> {
        let (bucket, outcome) = Bucket::new(3).insert(id_for_byte(1), addr_for_port(1));
        check(outcome == InsertOutcome::Added, || {
            format!("expected Added, got {outcome:?}")
        })?;
        check(bucket.len() == 1, || {
            format!("expected len 1, got {}", bucket.len())
        })
    }

    #[test]
    fn re_inserting_same_node_reports_updated_and_moves_to_front() -> Result<(), Error> {
        let (bucket, _) = Bucket::new(3).insert(id_for_byte(1), addr_for_port(1));
        let (bucket, _) = bucket.insert(id_for_byte(2), addr_for_port(2));
        let (bucket, outcome) = bucket.insert(id_for_byte(1), addr_for_port(11));
        check(outcome == InsertOutcome::Updated, || {
            format!("expected Updated, got {outcome:?}")
        })?;
        check(bucket.len() == 2, || {
            format!("expected len still 2, got {}", bucket.len())
        })?;
        let mut iter = bucket.iter();
        let first = iter.next().ok_or_else(|| Error::HostState {
            reason: "bucket should have a front entry after Updated".to_owned(),
        })?;
        check(first.0 == &id_for_byte(1), || {
            "re-inserted peer should be at the most-recently-seen end".to_owned()
        })?;
        check(first.1 == &addr_for_port(11), || {
            "re-inserted peer's address should reflect the latest insert".to_owned()
        })
    }

    #[test]
    fn full_bucket_reports_lru_candidate() -> Result<(), Error> {
        // Fill capacity 2 with peers 1 then 2 (so 1 is LRU, 2 is MRU).
        let (bucket, _) = Bucket::new(2).insert(id_for_byte(1), addr_for_port(1));
        let (bucket, _) = bucket.insert(id_for_byte(2), addr_for_port(2));
        check(bucket.is_full(), || {
            "bucket should be full after two inserts at capacity 2".to_owned()
        })?;
        let (bucket, outcome) = bucket.insert(id_for_byte(3), addr_for_port(3));
        match outcome {
            InsertOutcome::BucketFull { lru_candidate } => {
                check(lru_candidate == id_for_byte(1), || {
                    format!("expected LRU = id_for_byte(1), got {lru_candidate}")
                })?
            }
            other @ (InsertOutcome::Added | InsertOutcome::Updated) => {
                return Err(Error::HostState {
                    reason: format!("expected BucketFull, got {other:?}"),
                });
            }
        }
        check(!bucket.contains(&id_for_byte(3)), || {
            "rejected peer must not be in the bucket".to_owned()
        })?;
        check(bucket.len() == 2, || {
            format!("bucket size should still be 2, got {}", bucket.len())
        })
    }

    #[test]
    fn remove_drops_the_peer() -> Result<(), Error> {
        let (bucket, _) = Bucket::new(3).insert(id_for_byte(1), addr_for_port(1));
        let (bucket, _) = bucket.insert(id_for_byte(2), addr_for_port(2));
        let bucket = bucket.remove(&id_for_byte(1));
        check(!bucket.contains(&id_for_byte(1)), || {
            "removed peer must no longer be present".to_owned()
        })?;
        check(bucket.contains(&id_for_byte(2)), || {
            "untouched peer must remain present".to_owned()
        })?;
        check(bucket.len() == 1, || {
            format!("expected len 1 after one removal, got {}", bucket.len())
        })
    }

    #[test]
    fn remove_is_a_no_op_for_unknown_peer() -> Result<(), Error> {
        let (bucket, _) = Bucket::new(3).insert(id_for_byte(1), addr_for_port(1));
        let bucket = bucket.remove(&id_for_byte(99));
        check(bucket.contains(&id_for_byte(1)), || {
            "removing an unknown peer must not affect existing entries".to_owned()
        })?;
        check(bucket.len() == 1, || {
            format!("expected len 1 after no-op removal, got {}", bucket.len())
        })
    }
}
