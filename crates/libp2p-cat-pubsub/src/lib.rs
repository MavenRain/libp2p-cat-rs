//! RLNC-coded pubsub on top of `libp2p-cat-udp` + `libp2p-cat-noise`.
//!
//! This crate plugs the gossip combinators from
//! [`rlnc_cat_rs::gossip`] (`source` / `receive`) into the
//! authenticated UDP transport built up in the rest of the workspace.
//! The result is a node that can multicast a generation of
//! [`OriginalData`] to a set of peers as RLNC-coded [`WirePiece`]s
//! and reconstruct generations sent by other peers.
//!
//! # Wire format
//!
//! Each pubsub frame (the *plaintext* fed to
//! [`libp2p_cat_noise::TransportState::encrypt`]) is laid out as:
//!
//! ```text
//! +-------------+--------------+-------------+-------------+--------------+
//! | topic_len:1 | topic_bytes  | k: u32 BE   | b: u32 BE   | piece bytes  |
//! |             | (≤ MAX_TOPIC)| (4 bytes)   | (4 bytes)   | (k + b)      |
//! +-------------+--------------+-------------+-------------+--------------+
//! ```
//!
//! `k + b` are the RLNC piece-count and per-piece byte length.  The
//! piece bytes are produced by [`rlnc_cat_rs::coding::piece::CodedPiece::to_bytes`]
//! and parsed back via `CodedPiece::from_bytes(_, piece_count)`.
//!
//! # Scope
//!
//! v1 is intentionally small:
//!
//! - **Source + receive only**: every node can broadcast and decode,
//!   but no node performs RLNC recoding for relay.  Recode/relay
//!   roles will land in a follow-up.
//! - **`NullAuthenticator` only**: the rlnc commitment / tag fields
//!   are zero bytes on the wire.  Switching to keyed-hash or LHS
//!   authentication is a codec change plus generic plumbing.
//! - **One generation per topic**: when a topic decodes successfully
//!   the corresponding decoder is consumed; callers re-register the
//!   topic to receive another generation.
//!
//! [`OriginalData`]: rlnc_cat_rs::coding::piece::OriginalData
//! [`WirePiece`]: rlnc_cat_rs::gossip::WirePiece

#![forbid(unsafe_code)]

mod codec;
mod node;
mod peer_table;
mod topic;

pub use codec::{MAX_TOPIC_LEN, PubsubFrame, decode, encode};
pub use node::{DeliveredMessage, PubsubNode};
pub use peer_table::PeerTable;
pub use topic::Topic;
