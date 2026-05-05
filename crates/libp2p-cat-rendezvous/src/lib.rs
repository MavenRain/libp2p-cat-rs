//! Rendezvous primitives for `libp2p-cat-rs`.
//!
//! This crate ships in passes; pass 5 (this version) covers
//! STUN-style address observation only.  A peer asks a publicly-
//! reachable rendezvous what address its UDP packets appear to be
//! coming from, useful as a foundation for NAT-aware peer discovery
//! (full-cone NATs can advertise the observed address directly;
//! restricted-cone and symmetric NATs need more, deferred to pass
//! 6's `PUNCH` coordination).
//!
//! # Roles
//!
//! Every [`RendezvousNode`] plays both client and server roles
//! symmetrically: it auto-answers inbound `OBSERVE_REQ` frames and
//! exposes [`RendezvousNode::observe_self`] for issuing them.  The
//! "rendezvous server" is just a node that's reachable by the
//! peers asking it questions.
//!
//! # Wire format
//!
//! See [`Frame`] and the documentation on [`encode`] / [`decode`].
//! Frames sit on top of a Noise-XX transport state managed by
//! [`Host`](libp2p_cat_host::Host); the AEAD authenticates the full
//! plaintext, so no length-prefixing is needed at this layer.

#![forbid(unsafe_code)]

mod codec;
mod event;
mod node;

pub use codec::{Frame, OBSERVE_RESP_V4_LEN, OBSERVE_RESP_V6_LEN, Opcode, decode, encode};
pub use event::RendezvousEvent;
pub use node::RendezvousNode;
