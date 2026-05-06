//! Multi-protocol mux for `libp2p-cat-rs`.
//!
//! [`MultiProtocolNode`] holds one [`libp2p_cat_host::Host`]
//! alongside [`libp2p_cat_pubsub::PubsubState`] and
//! [`libp2p_cat_kad::RoutingTable`], sharing one UDP socket across
//! pubsub, Kademlia, and rendezvous.  Inbound datagrams are
//! dispatched on a 1-byte kind-byte prefix; outbound calls prepend
//! the same byte before encryption.
//!
//! Rendezvous owns no protocol state beyond the
//! [`libp2p_cat_host::Host`], so it has no slot of its own; the mux
//! invokes its dispatch logic directly.
//!
//! # Wire envelope
//!
//! Every plaintext that the mux hands to
//! [`libp2p_cat_host::Host::send`] is prefixed with a one-byte
//! discriminator:
//!
//! - [`KIND_APP`]        (`0x00`): the rest is raw app data.
//! - [`KIND_PUBSUB`]     (`0x01`): the rest is a pubsub frame.
//! - [`KIND_KAD`]        (`0x02`): the rest is a Kademlia frame.
//! - [`KIND_RENDEZVOUS`] (`0x03`): the rest is a rendezvous frame.
//! - [`KIND_RPC`]        (`0x04`): the rest is a serialized RPC
//!   envelope handled by [`libp2p-cat-rpc`].
//!
//! [`libp2p-cat-rpc`]: https://crates.io/crates/libp2p-cat-rpc
//!
//! `KIND_APP` and `KIND_PUBSUB` use the same byte values as
//! [`libp2p_cat_pubsub`]'s standalone wire format, so a mux peer
//! that only exercises those two kinds is wire-compatible with a
//! standalone [`libp2p_cat_pubsub::PubsubMux`] peer.  The Kademlia
//! and rendezvous standalone wire formats carry no kind byte, so a
//! mux peer using those kinds is *not* wire-compatible with a
//! standalone [`libp2p_cat_kad::KademliaNode`] /
//! [`libp2p_cat_rendezvous::RendezvousNode`] peer.
//!
//! # Pubsub integration
//!
//! For [`KIND_APP`] / [`KIND_PUBSUB`] inbound the mux delegates
//! directly to [`libp2p_cat_pubsub::PubsubMux::process_plaintext`],
//! reconstituted on the fly from the mux's
//! [`libp2p_cat_host::Host`] and [`libp2p_cat_pubsub::PubsubState`].
//! Outbound app data and broadcast similarly delegate to
//! [`libp2p_cat_pubsub::PubsubMux::send_app`] /
//! [`libp2p_cat_pubsub::PubsubMux::broadcast`], which already
//! prepend the matching kind byte.
//!
//! # Kademlia and rendezvous integration
//!
//! The Kademlia and rendezvous standalone codecs do not include a
//! kind byte, so the mux re-implements their dispatch (decode +
//! auto-reply with the matching kind byte prepended) rather than
//! delegating to [`libp2p_cat_kad::KademliaNode::process_plaintext`]
//! / [`libp2p_cat_rendezvous::RendezvousNode::process_plaintext`].
//! The standalone `process_plaintext` methods remain in their crates
//! for the standalone deployment.

#![forbid(unsafe_code)]

mod event;
mod node;

pub use event::MultiProtocolEvent;
pub use node::MultiProtocolNode;

/// Plaintext discriminator for raw application data.
pub const KIND_APP: u8 = 0x00;

/// Plaintext discriminator for RLNC pubsub frames.
pub const KIND_PUBSUB: u8 = 0x01;

/// Plaintext discriminator for Kademlia DHT frames.
pub const KIND_KAD: u8 = 0x02;

/// Plaintext discriminator for rendezvous RPC frames.
pub const KIND_RENDEZVOUS: u8 = 0x03;

/// Plaintext discriminator for `tarpc-cat`-style RPC envelope
/// frames.  The mux surfaces inbound `KIND_RPC` plaintexts as
/// [`MultiProtocolEvent::RpcDatagram`] without parsing the
/// envelope; callers using [`libp2p-cat-rpc`] decode the body
/// into a [`tarpc_cat::protocol::Envelope`].
///
/// [`libp2p-cat-rpc`]: https://crates.io/crates/libp2p-cat-rpc
/// [`tarpc_cat::protocol::Envelope`]: https://docs.rs/tarpc-cat
pub const KIND_RPC: u8 = 0x04;
