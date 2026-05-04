//! Kademlia [`RoutingTable`]: 256 k-buckets indexed by XOR distance.
//!
//! Each peer lives in the bucket whose index matches the position of
//! the highest 1-bit in `distance(self, peer)`.  Pass 1 is offline:
//! the table tracks `(NodeId, UdpAddr)` pairs and answers
//! [`RoutingTable::closest_to`] queries; pass 2 will hook in the
//! ping-on-bucket-full logic as wire RPCs become available.

use libp2p_cat_types::UdpAddr;

use crate::bucket::{Bucket, InsertOutcome};
use crate::distance::Distance;
use crate::node_id::{NODE_ID_BITS, NodeId};

/// A Kademlia routing table for a node whose own identifier is
/// [`RoutingTable::self_id`].
#[derive(Clone, Debug)]
#[must_use]
pub struct RoutingTable {
    self_id: NodeId,
    k: usize,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    /// Build an empty routing table for `self_id` with bucket size `k`.
    pub fn new(self_id: NodeId, k: usize) -> Self {
        let buckets: Vec<Bucket> = (0..NODE_ID_BITS).map(|_| Bucket::new(k)).collect();
        Self {
            self_id,
            k,
            buckets,
        }
    }

    /// Borrow the local node's identifier.
    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    /// Replication factor `k` (size cap of every bucket).
    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    /// Total number of peers across all buckets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(Bucket::len).sum()
    }

    /// Whether the table holds zero peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(Bucket::is_empty)
    }

    /// Whether `peer` is currently tracked in some bucket.
    #[must_use]
    pub fn contains(&self, peer: &NodeId) -> bool {
        self.buckets.iter().any(|b| b.contains(peer))
    }

    /// Offer a peer to the appropriate bucket.  Consumes `self` and
    /// returns the updated table plus the bucket-level
    /// [`InsertOutcome`].  Inserting [`Self::self_id`] is a no-op
    /// reported as [`InsertOutcome::Updated`] (no peer changes).
    pub fn insert(self, peer: NodeId, addr: UdpAddr) -> (Self, InsertOutcome) {
        let Self {
            self_id,
            k,
            buckets,
        } = self;
        let dist = self_id.distance(&peer);
        match dist.bucket_index() {
            None => (
                Self {
                    self_id,
                    k,
                    buckets,
                },
                InsertOutcome::Updated,
            ),
            Some(idx) => insert_into_bucket(self_id, k, buckets, idx, peer, addr),
        }
    }

    /// Remove a peer from the table.  Consumes `self`.  No-op for
    /// peers not currently tracked or for [`Self::self_id`].
    pub fn remove(self, peer: &NodeId) -> Self {
        let Self {
            self_id,
            k,
            buckets,
        } = self;
        let dist = self_id.distance(peer);
        match dist.bucket_index() {
            None => Self {
                self_id,
                k,
                buckets,
            },
            Some(idx) => {
                let next_buckets: Vec<Bucket> = buckets
                    .into_iter()
                    .enumerate()
                    .map(|(i, bucket)| {
                        if i == idx {
                            bucket.remove(peer)
                        } else {
                            bucket
                        }
                    })
                    .collect();
                Self {
                    self_id,
                    k,
                    buckets: next_buckets,
                }
            }
        }
    }

    /// Return up to `max_count` known peers sorted by ascending XOR
    /// distance to `target`.  Pulls from every bucket and sorts; for
    /// realistic table sizes (`k * NODE_ID_BITS = 5120` entries at
    /// `k=20`) this is a non-issue.
    #[must_use]
    pub fn closest_to(&self, target: &NodeId, max_count: usize) -> Vec<(NodeId, UdpAddr)> {
        let mut all: Vec<(Distance, NodeId, UdpAddr)> = self
            .buckets
            .iter()
            .flat_map(Bucket::iter)
            .map(|(id, addr)| (id.distance(target), *id, *addr))
            .collect();
        all.sort_by_key(|(dist, _, _)| *dist);
        all.into_iter()
            .take(max_count)
            .map(|(_, id, addr)| (id, addr))
            .collect()
    }
}

fn insert_into_bucket(
    self_id: NodeId,
    k: usize,
    buckets: Vec<Bucket>,
    idx: usize,
    peer: NodeId,
    addr: UdpAddr,
) -> (RoutingTable, InsertOutcome) {
    let total = buckets.len();
    let (next_buckets, outcome) = buckets.into_iter().enumerate().fold(
        (Vec::with_capacity(total), None),
        |(mut acc, mut maybe_outcome), (i, bucket)| {
            if i == idx {
                let (updated, outcome) = bucket.insert(peer, addr);
                acc.push(updated);
                maybe_outcome = Some(outcome);
            } else {
                acc.push(bucket);
            }
            (acc, maybe_outcome)
        },
    );
    let outcome = outcome.unwrap_or(InsertOutcome::Updated);
    (
        RoutingTable {
            self_id,
            k,
            buckets: next_buckets,
        },
        outcome,
    )
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
    fn fresh_table_is_empty() -> Result<(), Error> {
        let table = RoutingTable::new(id_for_byte(0), 20);
        check(table.is_empty(), || {
            "fresh table should be empty".to_owned()
        })
    }

    #[test]
    fn insert_unique_peers_grows_the_table() -> Result<(), Error> {
        let table = RoutingTable::new(id_for_byte(0), 20);
        let (table, _) = table.insert(id_for_byte(1), addr_for_port(1));
        let (table, _) = table.insert(id_for_byte(2), addr_for_port(2));
        let (table, _) = table.insert(id_for_byte(3), addr_for_port(3));
        check(table.len() == 3, || {
            format!("expected 3 peers, got {}", table.len())
        })?;
        check(table.contains(&id_for_byte(2)), || {
            "peer 2 should be present".to_owned()
        })
    }

    #[test]
    fn inserting_self_is_a_noop() -> Result<(), Error> {
        let me = id_for_byte(7);
        let table = RoutingTable::new(me, 20);
        let (table, outcome) = table.insert(me, addr_for_port(1));
        check(outcome == InsertOutcome::Updated, || {
            format!("inserting self should report Updated, got {outcome:?}")
        })?;
        check(table.is_empty(), || {
            "inserting self should not add a peer".to_owned()
        })
    }

    #[test]
    fn closest_to_returns_at_most_max_count() -> Result<(), Error> {
        let table = RoutingTable::new(id_for_byte(0), 20);
        let table = (1u8..=10).fold(table, |acc, b| {
            acc.insert(id_for_byte(b), addr_for_port(u16::from(b))).0
        });
        let closest = table.closest_to(&id_for_byte(0), 3);
        check(closest.len() == 3, || {
            format!("expected 3 nearest, got {}", closest.len())
        })?;
        // Distances must be ascending.
        let dists: Vec<Distance> = closest
            .iter()
            .map(|(id, _)| id.distance(&id_for_byte(0)))
            .collect();
        let monotone = dists.windows(2).all(|pair| {
            let left = pair.first().copied().unwrap_or(Distance::ZERO);
            let right = pair.get(1).copied().unwrap_or(Distance::ZERO);
            left <= right
        });
        check(monotone, || {
            "closest_to results must be sorted by ascending distance".to_owned()
        })
    }

    #[test]
    fn closest_to_empty_table_returns_empty() -> Result<(), Error> {
        let table = RoutingTable::new(id_for_byte(0), 20);
        let closest = table.closest_to(&id_for_byte(99), 5);
        check(closest.is_empty(), || {
            "closest_to on empty table should return empty".to_owned()
        })
    }

    #[test]
    fn remove_drops_the_peer() -> Result<(), Error> {
        let table = RoutingTable::new(id_for_byte(0), 20);
        let (table, _) = table.insert(id_for_byte(1), addr_for_port(1));
        let (table, _) = table.insert(id_for_byte(2), addr_for_port(2));
        let table = table.remove(&id_for_byte(1));
        check(!table.contains(&id_for_byte(1)), || {
            "removed peer should be gone".to_owned()
        })?;
        check(table.contains(&id_for_byte(2)), || {
            "untouched peer should remain".to_owned()
        })?;
        check(table.len() == 1, || {
            format!("expected len 1 after remove, got {}", table.len())
        })
    }

    #[test]
    fn re_inserting_a_peer_does_not_grow_len() -> Result<(), Error> {
        let table = RoutingTable::new(id_for_byte(0), 20);
        let (table, _) = table.insert(id_for_byte(1), addr_for_port(1));
        let (table, outcome) = table.insert(id_for_byte(1), addr_for_port(11));
        check(outcome == InsertOutcome::Updated, || {
            format!("re-insert should report Updated, got {outcome:?}")
        })?;
        check(table.len() == 1, || {
            format!("expected len 1 after re-insert, got {}", table.len())
        })
    }
}
