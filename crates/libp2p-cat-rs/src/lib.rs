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
//! +-----------------------------------------+   application protocols
//! |                                         |
//! |   libp2p-cat-pubsub  (PubsubMux)        |   multiplexed RLNC + raw
//! |                                         |   app data on one host
//! |                                         |
//! +-----------------------------------------+
//! |   libp2p-cat-host    (connections)      |   dial / send / recv loop
//! +-----------------------------------------+
//! |   libp2p-cat-noise   (XX + AEAD)        |   pairwise authenticated
//! |                                         |   transport
//! +-----------------------------------------+
//! |   libp2p-cat-udp     (datagrams)        |   Io-shaped UDP socket
//! +-----------------------------------------+
//! |   libp2p-cat-types   (PeerId, etc.)     |   pure data
//! +-----------------------------------------+
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
//! - [`Host`] is the connection-management handle: dial a peer, run a
//!   recv loop, send authenticated plaintext.  The `examples/chat`
//!   binary in the workspace demonstrates a full two-peer chat
//!   session built from this single type.
//! - [`PubsubMux`] wraps a [`Host`] and multiplexes raw application
//!   bytes ([`KIND_APP`]) and RLNC-coded pubsub frames
//!   ([`KIND_PUBSUB`]) onto the same authenticated socket.  Use this
//!   when one node needs both broadcast and chat-style traffic.
//! - The lower-level building blocks ([`UdpTransport`],
//!   [`Initiator`] / [`Responder`], [`TransportState`], [`PeerId`])
//!   are re-exported here so callers building bespoke nodes can drop
//!   into any layer without re-importing.
//!
//! [`comp_cat_rs::effect::io::Io`]: https://docs.rs/comp-cat-rs

#![forbid(unsafe_code)]

pub use libp2p_cat_host::{Host, HostEvent};
pub use libp2p_cat_identity::{
    DOMAIN_TAG as IDENTITY_DOMAIN_TAG, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
    Ed25519Keypair, Ed25519PublicKey, Ed25519Signature, SignedStaticKey,
};
pub use libp2p_cat_kad::{
    Bucket as KadBucket, DEFAULT_K as KAD_DEFAULT_K, Distance as KadDistance,
    ENTRY_V4_LEN as KAD_ENTRY_V4_LEN, ENTRY_V6_LEN as KAD_ENTRY_V6_LEN, Frame as KadFrame,
    InsertOutcome as KadInsertOutcome, KadEvent, KademliaNode, Lookup as KadLookup, LookupConfig,
    LookupEntry, LookupStatus, MAX_PEERS_PER_RESP as KAD_MAX_PEERS_PER_RESP,
    NODE_ID_BITS as KAD_NODE_ID_BITS, NODE_ID_LEN as KAD_NODE_ID_LEN, NodeId as KadNodeId,
    Opcode as KadOpcode, RoutingTable as KadRoutingTable, decode as decode_kad_frame,
    encode as encode_kad_frame,
};
pub use libp2p_cat_noise::{
    Initiator, InitiatorAfterE, InitiatorAfterResponse, MESSAGE_1_LEN, MESSAGE_2_OVERHEAD_LEN,
    MESSAGE_3_OVERHEAD_LEN, REPLAY_WINDOW_BITS, Responder, ResponderAfterE, ResponderAfterResponse,
    StaticKeypair, StaticPrivateKey, StaticPublicKey, TRANSPORT_NONCE_PREFIX_LEN,
    TRANSPORT_OVERHEAD, TransportState,
};
pub use libp2p_cat_pubsub::{
    KIND_APP, KIND_PUBSUB, MAX_TOPIC_LEN, MuxEvent, PubsubFrame, PubsubMux, Topic,
    decode as decode_pubsub_frame, encode as encode_pubsub_frame, unused_relay_rng,
};
pub use libp2p_cat_rendezvous::{
    Frame as RendezvousFrame, OBSERVE_RESP_V4_LEN, OBSERVE_RESP_V6_LEN, Opcode as RendezvousOpcode,
    RendezvousEvent, RendezvousNode, decode as decode_rendezvous_frame,
    encode as encode_rendezvous_frame,
};
pub use libp2p_cat_types::{Error, MAX_INLINE_KEY_BYTES, PeerId, ProtocolId, UdpAddr};
pub use libp2p_cat_udp::{DEFAULT_MAX_DATAGRAM, MAX_UDP_PAYLOAD, UdpTransport};
