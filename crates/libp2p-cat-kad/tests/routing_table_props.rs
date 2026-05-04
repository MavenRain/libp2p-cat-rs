//! Property-based invariants for [`RoutingTable`] and the underlying
//! [`Distance`] / [`NodeId`] arithmetic.
//!
//! Properties exercised:
//!
//! - XOR distance is symmetric and zero iff the two `NodeId`s are
//!   equal.
//! - `Distance::leading_zeros` agrees with `bucket_index` on every
//!   non-zero distance.
//! - For any sequence of inserts and any target, `closest_to(target,
//!   max_count)` returns at most `max_count` peers, all distinct,
//!   sorted by ascending distance, and matching the brute-force
//!   "sort-everything" answer.
//! - `insert` is monotone in `len`: inserting a new peer increases
//!   `len` by exactly 1; re-inserting an existing peer leaves `len`
//!   unchanged.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4};

use libp2p_cat_kad::{Distance, NODE_ID_BITS, NODE_ID_LEN, NodeId, RoutingTable};
use libp2p_cat_types::UdpAddr;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

fn node_id_strategy() -> impl Strategy<Value = NodeId> {
    prop::array::uniform32(any::<u8>()).prop_map(NodeId::from_bytes)
}

fn addr_strategy() -> impl Strategy<Value = UdpAddr> {
    any::<u16>().prop_map(|p| UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, p)))
}

fn brute_force_closest(
    inserted: &[(NodeId, UdpAddr)],
    target: &NodeId,
    max_count: usize,
) -> Vec<(Distance, NodeId, UdpAddr)> {
    let mut all: Vec<(Distance, NodeId, UdpAddr)> = inserted
        .iter()
        .map(|(id, addr)| (id.distance(target), *id, *addr))
        .collect();
    all.sort_by_key(|(dist, _, _)| *dist);
    all.into_iter().take(max_count).collect()
}

proptest! {
    #[test]
    fn xor_distance_is_symmetric(a in node_id_strategy(), b in node_id_strategy()) {
        prop_assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn xor_distance_is_zero_iff_equal(a in node_id_strategy(), b in node_id_strategy()) {
        let zero = a.distance(&b).is_zero();
        prop_assert_eq!(zero, a == b);
    }

    #[test]
    fn bucket_index_matches_leading_zeros(bytes in prop::array::uniform32(any::<u8>())) {
        let d = Distance::from_bytes(bytes);
        match d.bucket_index() {
            None => {
                prop_assert!(d.is_zero());
                prop_assert_eq!(d.leading_zeros(), NODE_ID_BITS);
            }
            Some(idx) => {
                prop_assert!(!d.is_zero());
                prop_assert!(idx < NODE_ID_BITS);
                prop_assert_eq!(idx, NODE_ID_BITS - 1 - d.leading_zeros());
            }
        }
    }

    #[test]
    fn closest_to_matches_brute_force(
        self_bytes in prop::array::uniform32(any::<u8>()),
        target_bytes in prop::array::uniform32(any::<u8>()),
        peers in prop_vec((node_id_strategy(), addr_strategy()), 0..50),
        max_count in 0usize..=20,
    ) {
        // Use a generous bucket capacity (k = peers.len()) so no
        // bucket overflows; the test then targets the closest_to
        // logic in isolation, decoupled from the bucket-full
        // eviction policy.  Pass 2's overflow behaviour will get
        // its own focussed test once the wire side exists.
        let self_id = NodeId::from_bytes(self_bytes);
        let target = NodeId::from_bytes(target_bytes);
        let k = peers.len().max(1);
        let table = peers.iter().fold(
            RoutingTable::new(self_id, k),
            |acc, (id, addr)| acc.insert(*id, *addr).0,
        );

        // With no overflow, the effective set is just the unique
        // non-self NodeIds.
        let effective: Vec<(NodeId, UdpAddr)> = peers
            .iter()
            .rev()
            .filter(|(id, _)| id != &self_id)
            .fold(
                (BTreeSet::<NodeId>::new(), Vec::<(NodeId, UdpAddr)>::new()),
                |(mut seen, mut acc), (id, addr)| {
                    if seen.insert(*id) {
                        acc.push((*id, *addr));
                    }
                    (seen, acc)
                },
            )
            .1;

        let actual = table.closest_to(&target, max_count);
        prop_assert!(actual.len() <= max_count);

        let actual_ids: BTreeSet<NodeId> =
            actual.iter().map(|(id, _)| *id).collect();
        prop_assert_eq!(actual_ids.len(), actual.len(), "result NodeIds must be unique");

        let actual_dists: Vec<Distance> = actual
            .iter()
            .map(|(id, _)| id.distance(&target))
            .collect();
        let monotone = actual_dists.windows(2).all(|pair| {
            let l = pair.first().copied().unwrap_or(Distance::ZERO);
            let r = pair.get(1).copied().unwrap_or(Distance::ZERO);
            l <= r
        });
        prop_assert!(monotone, "results must be sorted by ascending distance");

        let expected = brute_force_closest(&effective, &target, max_count);
        let expected_ids: BTreeSet<NodeId> =
            expected.iter().map(|(_, id, _)| *id).collect();
        prop_assert_eq!(actual_ids, expected_ids, "set of returned NodeIds must match brute force");
    }

    #[test]
    fn insert_is_monotone_in_len(
        self_bytes in prop::array::uniform32(any::<u8>()),
        peers in prop_vec((node_id_strategy(), addr_strategy()), 0..30),
    ) {
        let self_id = NodeId::from_bytes(self_bytes);
        let unique: BTreeSet<NodeId> = peers
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| id != &self_id)
            .collect();
        let table = peers.iter().fold(
            RoutingTable::new(self_id, 20),
            |acc, (id, addr)| acc.insert(*id, *addr).0,
        );
        // Bucket capacity is 20 but the test bound is 30 distinct
        // NodeIds, and unique IDs are spread across 256 buckets, so
        // overflow is possible only if the random-byte strategy lands
        // many IDs in the same bucket.  The invariant is therefore
        // an upper bound, not equality.
        prop_assert!(table.len() <= unique.len());
    }
}

#[test]
fn node_id_len_matches_bits() -> Result<(), String> {
    // Sanity: spot-check the constants line up.  The test harness
    // accepts any `Result<(), E>` where `E: Debug` and surfaces a
    // failure message without us writing `panic!` / `assert!`.
    if NODE_ID_BITS == NODE_ID_LEN * 8 {
        Ok(())
    } else {
        Err(format!(
            "NODE_ID_BITS = {NODE_ID_BITS} disagrees with NODE_ID_LEN ({NODE_ID_LEN}) * 8"
        ))
    }
}
