//! Kademlia DHT primitives for `libp2p-cat-rs`.
//!
//! Pass 1 shipped the offline data structures: a fixed-width
//! [`NodeId`] derived from a [`PeerId`](libp2p_cat_types::PeerId),
//! the XOR [`Distance`] metric, k-buckets, and a [`RoutingTable`]
//! indexed by distance.
//!
//! Pass 2 added the wire side: a single-byte-opcode [`Frame`]
//! encoding for `PING` / `FIND_NODE` RPCs, and a [`KademliaNode`]
//! driver wrapping a [`Host`](libp2p_cat_host::Host) that auto-
//! answers inbound `PING` and `FIND_NODE` requests, auto-inserts
//! observed peers into the routing table, and surfaces [`KadEvent`]s
//! for the caller to consume.
//!
//! Pass 3 (this version) adds [`KademliaNode::lookup_node`], a
//! synchronous iterative `FIND_NODE` lookup that runs to completion
//! and returns up to `k` peers closest to a target.  See
//! [`LookupConfig`] and the [`lookup`] module for
//! tunables and v1 limitations (in particular, the lookup only
//! queries peers with an active established Host connection; pass 4
//! will fold transparent dialing of newly-discovered peers into the
//! lookup itself).
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
mod codec;
mod distance;
mod event;
pub mod lookup;
mod node;
mod node_id;
mod routing_table;

pub use bucket::{Bucket, DEFAULT_K, InsertOutcome};
pub use codec::{ENTRY_V4_LEN, ENTRY_V6_LEN, Frame, MAX_PEERS_PER_RESP, Opcode, decode, encode};
pub use distance::Distance;
pub use event::KadEvent;
pub use lookup::{Lookup, LookupConfig, LookupEntry, LookupStatus};
pub use node::KademliaNode;
pub use node_id::{NODE_ID_BITS, NODE_ID_LEN, NodeId};
pub use routing_table::RoutingTable;
