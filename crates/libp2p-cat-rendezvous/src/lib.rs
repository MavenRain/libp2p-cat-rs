//! Rendezvous primitives for `libp2p-cat-rs`.
//!
//! Pass 5 covered STUN-style address observation: a peer asks a
//! publicly-reachable rendezvous what address its UDP packets
//! appear to be coming from, useful for full-cone NAT advertisement.
//!
//! Pass 6 (this version) adds `PUNCH` coordination: a client peer
//! asks the rendezvous to forward a punch request to a target peer;
//! the target peer auto-fires a bare-datagram punch back at the
//! initiator, opening a NAT mapping for the initiator's subsequent
//! dial.  Restricted-cone and port-restricted NATs work end-to-end
//! once the initiator dials; symmetric NATs still need a TURN-style
//! relay, deferred indefinitely.
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
