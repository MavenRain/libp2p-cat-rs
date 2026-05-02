//! Categorical, UDP-only, RLNC-native peer-to-peer stack.
//!
//! `libp2p-cat-rs` is an umbrella crate.  It re-exports the public
//! surface of every crate in the workspace under a single namespace
//! so callers can write `use libp2p_cat_rs::*` without juggling five
//! direct dependencies.
//!
//! # Layering
//!
//! ```text
//! +-------------------------------------+    application protocols
//! |                                     |
//! |   libp2p-cat-pubsub  (RLNC gossip)  |    multi-peer broadcast
//! |   libp2p-cat-host    (connections)  |    dial / send / recv loop
//! |                                     |
//! +-------------------------------------+
//! |   libp2p-cat-noise   (XX + AEAD)    |    pairwise authenticated
//! |                                     |    transport
//! +-------------------------------------+
//! |   libp2p-cat-udp     (datagrams)    |    Io-shaped UDP socket
//! +-------------------------------------+
//! |   libp2p-cat-types   (PeerId, etc.) |    pure data
//! +-------------------------------------+
//! ```
//!
//! Each layer's API consumes `self` and returns a new value
//! (linear-state-threading) so nothing is mutated in place.  Only the
//! UDP layer touches the OS; everything above composes through
//! [`comp_cat_rs::effect::io::Io`] and stays inside the effect until
//! the outermost `run`.
//!
//! # Quick tour
//!
//! - [`Host`] is the top-level handle: dial a peer, run a recv loop,
//!   send authenticated plaintext.  The `examples/chat` binary in
//!   the workspace demonstrates a full two-peer chat session built
//!   from this single type.
//! - [`PubsubNode`] adds RLNC-coded multicast on top of a peer table
//!   that mirrors what the host maintains internally.  Today pubsub
//!   owns its own socket; layering it on top of [`Host`] is the next
//!   architectural step.
//! - The lower-level building blocks ([`UdpTransport`],
//!   [`Initiator`] / [`Responder`], [`TransportState`], [`PeerId`])
//!   are re-exported here so callers building bespoke nodes can drop
//!   into any layer without re-importing.
//!
//! [`comp_cat_rs::effect::io::Io`]: https://docs.rs/comp-cat-rs

#![forbid(unsafe_code)]

pub use libp2p_cat_host::{Host, HostEvent};
pub use libp2p_cat_noise::{
    Initiator, InitiatorAfterE, InitiatorAfterResponse, MESSAGE_1_LEN, MESSAGE_2_LEN,
    MESSAGE_3_LEN, REPLAY_WINDOW_BITS, Responder, ResponderAfterE, ResponderAfterResponse,
    StaticKeypair, StaticPrivateKey, StaticPublicKey, TRANSPORT_NONCE_PREFIX_LEN,
    TRANSPORT_OVERHEAD, TransportState,
};
pub use libp2p_cat_pubsub::{
    DeliveredMessage, MAX_TOPIC_LEN, PeerTable, PubsubFrame, PubsubNode, Topic,
    decode as decode_pubsub_frame, encode as encode_pubsub_frame,
};
pub use libp2p_cat_types::{Error, MAX_INLINE_KEY_BYTES, PeerId, ProtocolId, UdpAddr};
pub use libp2p_cat_udp::{DEFAULT_MAX_DATAGRAM, MAX_UDP_PAYLOAD, UdpTransport};
