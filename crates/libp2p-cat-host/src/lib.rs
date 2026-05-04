//! Connection-managing host that drives Noise XX over UDP and routes
//! plaintext datagrams.
//!
//! A [`Host`] owns one [`UdpTransport`], a long-lived
//! [`StaticKeypair`], and a precomputed [`SignedStaticKey`] binding
//! that ties the X25519 static key to an [`Ed25519Keypair`] identity.
//! Every Noise XX handshake the host runs sends the binding as the
//! encrypted trailer of message 2 (responder side) or message 3
//! (initiator side); the remote's binding is verified against the
//! X25519 key Noise authenticates, so [`HostEvent::HandshakeComplete`]
//! always carries a verified libp2p-compatible
//! [`PeerId`](libp2p_cat_types::PeerId).  A peer that fails to send a
//! valid binding is rejected.
//!
//! Two address-keyed tables track in-flight handshakes and
//! post-handshake transport states.  All effectful operations consume
//! `self` and return a new host; nothing mutates in place.
//!
//! # Event-loop shape
//!
//! ```text
//! loop {
//!     let (host, event) = host.recv_one(next_seed()).run()?;
//!     match event {
//!         HostEvent::HandshakeProgress { .. }   => /* wait for next datagram */,
//!         HostEvent::HandshakeComplete { addr, remote_static, remote_peer_id } => {
//!             // peer authenticated; record (addr, remote_peer_id)
//!         }
//!         HostEvent::DatagramDelivered { addr, plaintext } => {
//!             // application-level handling
//!         }
//!         HostEvent::Rejected { addr, reason } => /* log and continue */,
//!     }
//! }
//! ```
//!
//! # Why a seed per `recv_one` call?
//!
//! When an inbound datagram is a fresh `msg1` from a brand-new peer,
//! the host immediately writes `msg2` and that requires a 32-byte
//! ephemeral seed.  Other inbound shapes (post-handshake datagrams,
//! advancing an in-flight handshake we initiated) do not need a
//! seed.  The host has no way to peek before recv'ing, so the caller
//! supplies a seed unconditionally; unused seeds are dropped.
//!
//! [`UdpTransport`]: libp2p_cat_udp::UdpTransport
//! [`StaticKeypair`]: libp2p_cat_noise::StaticKeypair
//! [`SignedStaticKey`]: libp2p_cat_identity::SignedStaticKey
//! [`Ed25519Keypair`]: libp2p_cat_identity::Ed25519Keypair

#![forbid(unsafe_code)]

mod event;
mod host;
mod state;

pub use event::HostEvent;
pub use host::Host;
