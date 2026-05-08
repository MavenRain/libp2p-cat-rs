//! Criterion baseline for [`RoutingTable::closest_to`].
//!
//! Populates a routing table with `N` random peers (deterministic
//! seed for reproducibility), then measures the cost of a single
//! `closest_to(target, k=20)` query — the operation a kad node
//! runs once per inbound `FIND_NODE` request.
//!
//! Run with `cargo bench -p libp2p-cat-kad --bench routing_table`.

use std::net::{Ipv4Addr, SocketAddrV4};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use libp2p_cat_kad::{NODE_ID_LEN, NodeId, RoutingTable};
use libp2p_cat_types::UdpAddr;

const KAD_K: usize = 20;
const POPULATION: u64 = 256;

fn deterministic_node_id(seed: u64) -> NodeId {
    let lo = seed.to_le_bytes();
    let mut bytes = [0u8; NODE_ID_LEN];
    bytes
        .iter_mut()
        .take(lo.len())
        .zip(lo.iter())
        .for_each(|(slot, b)| *slot = *b);
    NodeId::from_bytes(bytes)
}

fn deterministic_addr(seed: u16) -> UdpAddr {
    UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, seed.max(1)))
}

fn populated_table() -> RoutingTable {
    let self_id = deterministic_node_id(0);
    (1..=POPULATION).fold(RoutingTable::new(self_id, KAD_K), |acc, seed| {
        let id = deterministic_node_id(seed);
        let port = u16::try_from(seed % u64::from(u16::MAX)).unwrap_or(1);
        acc.insert(id, deterministic_addr(port)).0
    })
}

fn bench_closest_to(c: &mut Criterion) {
    let table = populated_table();
    let target = deterministic_node_id(0xDEAD_BEEF_DEAD_BEEF);
    c.bench_function("routing_table_closest_to_k20_pop256", |b| {
        b.iter(|| {
            let result = table.closest_to(black_box(&target), black_box(KAD_K));
            black_box(result);
        });
    });
}

criterion_group!(benches, bench_closest_to);
criterion_main!(benches);
