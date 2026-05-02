//! RLNC-coded pubsub layered on top of [`libp2p_cat_host::Host`].
//!
//! This crate plugs the gossip combinators from
//! [`rlnc_cat_rs::gossip`] (`source` / `receive`) into the
//! authenticated UDP transport managed by `libp2p-cat-host`.  The
//! result is a multiplexer that can carry both raw application
//! datagrams and RLNC-coded pubsub frames over a single Noise
//! session per peer.
//!
//! # Wire format
//!
//! Each plaintext fed to [`libp2p_cat_host::Host::send`] is
//! prefixed with a one-byte kind discriminator
//! ([`KIND_APP`] / [`KIND_PUBSUB`]).  Pubsub frames use the layout
//!
//! ```text
//! +-------------+--------------+-------------+-------------+--------------+
//! | topic_len:1 | topic_bytes  | k: u32 BE   | b: u32 BE   | piece bytes  |
//! |             | (≤ MAX_TOPIC)| (4 bytes)   | (4 bytes)   | (k + b)      |
//! +-------------+--------------+-------------+-------------+--------------+
//! ```
//!
//! after the kind byte.  Piece bytes are produced by
//! [`rlnc_cat_rs::coding::piece::CodedPiece::to_bytes`] and parsed
//! back via `CodedPiece::from_bytes(_, piece_count)`; the `(k, b)`
//! integers in the header carry the dimensions a receiver needs to
//! instantiate its decoder before a single piece arrives.
//!
//! # Scope
//!
//! v1 is intentionally small:
//!
//! - **Source + receive only**: every node can broadcast and decode,
//!   but no node performs RLNC recoding for relay.  Recode/relay
//!   roles are a follow-up.
//! - **`NullAuthenticator` only**: the rlnc commitment / tag fields
//!   are zero bytes on the wire.  Switching to keyed-hash or LHS
//!   authentication is a codec change plus generic plumbing.
//! - **One generation per topic**: when a topic decodes successfully
//!   the corresponding decoder is consumed; callers re-register the
//!   topic to receive another generation.

#![forbid(unsafe_code)]

mod codec;
mod mux;
mod topic;

pub use codec::{MAX_TOPIC_LEN, PubsubFrame, decode, encode};
pub use mux::{KIND_APP, KIND_PUBSUB, MuxEvent, PubsubMux};
pub use topic::Topic;
