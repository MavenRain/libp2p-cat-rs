//! RLNC-coded pubsub layered on top of [`libp2p_cat_host::Host`].
//!
//! This crate plugs the gossip combinators from
//! [`rlnc_cat_rs::gossip`] (`source` / `receive`) into the
//! authenticated UDP transport managed by `libp2p-cat-host`.  The
//! result is a multiplexer that can carry both raw application
//! datagrams and RLNC-coded pubsub frames over a single Noise
//! session per peer, with pluggable per-frame authentication.
//!
//! # Wire format
//!
//! Each plaintext fed to [`libp2p_cat_host::Host::send`] is
//! prefixed with a one-byte kind discriminator
//! ([`KIND_APP`] / [`KIND_PUBSUB`]).  Pubsub frames use the layout
//!
//! ```text
//! +-------------+--------------+-------------+-------------+--------------+--------+--------------+
//! | topic_len:1 | topic_bytes  | k: u32 BE   | b: u32 BE   | commitment   | tag    | piece bytes  |
//! |             | (≤ MAX_TOPIC)| (4 bytes)   | (4 bytes)   | (auth-sized) | (sized)| (k + b)      |
//! +-------------+--------------+-------------+-------------+--------------+--------+--------------+
//! ```
//!
//! after the kind byte.  The `commitment` and `tag` widths come from
//! the [`WireAuthenticator`] in use; for [`rlnc_cat_rs::auth::NullAuthenticator`]
//! both are zero bytes, so the format collapses to its earlier shape.
//! Piece bytes are produced by
//! [`rlnc_cat_rs::coding::piece::CodedPiece::to_bytes`] and parsed
//! back via `CodedPiece::from_bytes(_, piece_count)`; the `(k, b)`
//! integers in the header carry the dimensions a receiver needs to
//! instantiate its decoder before a single piece arrives.
//!
//! # Scope
//!
//! - **Source + decoder + relay roles** per topic per node, registered via
//!   [`PubsubMux::broadcast`], [`PubsubMux::register_topic`], and
//!   [`PubsubMux::register_relay`] respectively.
//! - **Pluggable authenticators** via the [`WireAuthenticator`] /
//!   [`PubsubAuth`] traits.  Stock impls cover
//!   [`rlnc_cat_rs::auth::NullAuthenticator`] (no auth, zero wire
//!   overhead) and [`rlnc_cat_rs::auth::KeyedHashAuthenticator`]
//!   (32-byte commitment + 32-byte BLAKE3-keyed-hash tag).  The
//!   keyed-hash construction is **not homomorphic**: a relay needs
//!   the shared key to verify inbound pieces and re-tag the recoded
//!   outbound pieces.  Suitable for permissioned networks; future
//!   homomorphic-signature impls will lift that constraint.
//! - **One generation per topic**: when a topic decodes successfully
//!   the corresponding decoder is consumed; callers re-register the
//!   topic to receive another generation.

#![forbid(unsafe_code)]

mod auth;
mod codec;
mod mux;
mod topic;

pub use auth::{PubsubAuth, WireAuthenticator};
pub use codec::{MAX_TOPIC_LEN, PubsubFrame, decode, encode};
pub use mux::{KIND_APP, KIND_PUBSUB, MuxEvent, PubsubMux, unused_relay_rng};
pub use topic::Topic;
