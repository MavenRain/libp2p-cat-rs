//! UDP datagram transport for `libp2p-cat-rs`.
//!
//! This crate provides exactly one effectful primitive — [`UdpTransport`]
//! — and a pair of capacity constants.  Higher layers (Noise handshake,
//! pubsub, control-plane RPC) compose [`UdpTransport::send`] and
//! [`UdpTransport::recv`] to drive the categorical effect pipeline; this
//! is the only place blocking I/O reaches the OS.
//!
//! The transport mirrors the linear-state-threading convention used by
//! `tarpc-cat::Transport`: each operation consumes the transport and
//! returns it on success.  This avoids `&mut self` in user-facing APIs
//! while keeping the effect surface synchronous and explicit.
//!
//! See [`UdpTransport`] for the API and `tests/roundtrip.rs` for an
//! end-to-end loopback example.

#![forbid(unsafe_code)]

pub mod transport;

pub use transport::{DEFAULT_MAX_DATAGRAM, MAX_UDP_PAYLOAD, UdpTransport};
