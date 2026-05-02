//! Shared types for the `libp2p-cat-rs` workspace.
//!
//! This crate is the data-modelling layer used by every effectful crate
//! in the stack ([`libp2p-cat-udp`], future `libp2p-cat-noise`,
//! `libp2p-cat-pubsub`, and so on).  It has **no** `comp-cat-rs`
//! dependency: every type here is a value, not an effect.
//!
//! # What's here
//!
//! - [`UdpAddr`]: the only transport address admissible in the stack.
//!   Variants for IPv4 and IPv6 only — TCP / QUIC / WebSocket addresses
//!   are not representable.
//! - [`PeerId`]: a peer identifier built as the multihash of a
//!   protobuf-encoded libp2p `PublicKey`.  Bytes are the same shape
//!   that `go-libp2p` and `rust-libp2p` produce, so identities are
//!   recognisable across implementations.
//! - [`ProtocolId`]: a validated protocol-name newtype.
//! - [`Error`]: the workspace-wide error enum used by every crate.
//!
//! [`libp2p-cat-udp`]: https://crates.io/crates/libp2p-cat-udp

#![forbid(unsafe_code)]

pub mod addr;
pub mod error;
pub mod peer_id;
pub mod protocol_id;

pub use addr::UdpAddr;
pub use error::Error;
pub use peer_id::{MAX_INLINE_KEY_BYTES, PeerId};
pub use protocol_id::ProtocolId;
