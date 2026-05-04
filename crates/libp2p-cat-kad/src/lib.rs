//! Kademlia DHT primitives for `libp2p-cat-rs`.
//!
//! This crate ships in passes; pass 1 (this crate version) covers
//! only the offline data structures: a fixed-width [`NodeId`] derived
//! from a [`PeerId`](libp2p_cat_types::PeerId), the XOR
//! [`Distance`] metric, k-buckets, and a [`RoutingTable`] indexed by
//! distance.  No wire, no RPCs, no lookup driver yet.
//!
//! # Identifier choice
//!
//! [`NodeId`] is `blake3(PeerId.as_bytes())` truncated to 32 bytes.
//! This gives a uniform 256-bit ID space regardless of the
//! underlying `PeerId` shape (Ed25519 today, Secp256k1 / sha256-
//! hashed later).  We use BLAKE3 rather than libp2p's SHA-256 to
//! match the rest of the workspace's hash dependency; the wire is
//! already a libp2p fork.
//!
//! # Routing-table shape
//!
//! 256 buckets of capacity `k` (default [`DEFAULT_K`] = 20).  A peer
//! `p` lives in bucket `i` where `i` is the position of the highest
//! 1-bit in `distance(self, p)` (0-indexed from the LSB).  Pass 2
//! will hook a wire-side ping under the bucket-full eviction policy;
//! pass 1's [`Bucket::insert`] just reports
//! [`InsertOutcome::BucketFull`] and lets the caller decide.
//!
//! [`PeerId`]: libp2p_cat_types::PeerId

#![forbid(unsafe_code)]

mod bucket;
mod distance;
mod node_id;
mod routing_table;

pub use bucket::{Bucket, DEFAULT_K, InsertOutcome};
pub use distance::Distance;
pub use node_id::{NODE_ID_BITS, NODE_ID_LEN, NodeId};
pub use routing_table::RoutingTable;
