//! Connection-managing host that drives Noise XX over UDP and routes
//! plaintext datagrams.
//!
//! A [`Host`] owns one [`UdpTransport`], a long-lived
//! [`StaticKeypair`] (X25519 only — Ed25519 ↔ X25519 binding via the
//! libp2p signed-Noise-extension is deferred), and two address-keyed
//! tables: handshakes still in flight, and post-handshake transport
//! states.  All effectful operations consume `self` and return a new
//! host; nothing mutates in place.
//!
//! # Event-loop shape
//!
//! ```text
//! loop {
//!     let (host, event) = host.recv_one(next_seed()).run()?;
//!     match event {
//!         HostEvent::HandshakeProgress { .. }   => /* wait for next datagram */,
//!         HostEvent::HandshakeComplete { addr, remote_static } => {
//!             // peer authenticated; record (addr, remote_static)
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

#![forbid(unsafe_code)]

mod event;
mod host;
mod state;

pub use event::HostEvent;
pub use host::Host;
