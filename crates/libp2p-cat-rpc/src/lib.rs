//! RPC integration for `libp2p-cat-rs`.
//!
//! Adapts [`tarpc-cat`](https://crates.io/crates/tarpc-cat) — a
//! categorical RPC framework built on
//! [`comp-cat-rs`](https://crates.io/crates/comp-cat-rs) — to run
//! over `libp2p-cat-rs`'s authenticated UDP + Noise + identity
//! stack instead of `tarpc-cat`'s default TCP transport.
//!
//! # What this gives you
//!
//! - **`HostTransport`** — implements [`tarpc_cat::transport::Transport`]
//!   over a [`libp2p_cat_host::Host`] anchored to a single peer.
//!   Drop it into [`tarpc_cat::client::call_on`] to run a single
//!   request/response exchange against an established peer.
//! - **[`serve_one`]** — a server-side helper that drives one RPC
//!   request through a [`tarpc_cat::serve::Serve`] implementation
//!   and sends the response back.  Caller loops over `serve_one`
//!   themselves; this matches the workspace's "stay inside `Io`,
//!   call `run` only at the boundary" idiom.
//! - **[`MUX_KIND_RPC`]** — the kind-byte the multi-protocol mux
//!   uses to dispatch RPC frames; same byte the standalone
//!   `HostTransport` prepends to its sends.
//!
//! # Wire envelope
//!
//! Every RPC plaintext that the transport hands to
//! [`libp2p_cat_host::Host::send`] is prefixed with [`MUX_KIND_RPC`]
//! (`0x04`).  The remainder is a length-delimited
//! [`tarpc_cat::protocol::Envelope`] (JSON-encoded via the
//! `tarpc-cat` codec).
//!
//! [`tarpc_cat::transport::Transport`]: tarpc_cat::transport::Transport
//! [`tarpc_cat::client::call_on`]: tarpc_cat::client::call_on
//! [`tarpc_cat::serve::Serve`]: tarpc_cat::serve::Serve
//! [`tarpc_cat::protocol::Envelope`]: tarpc_cat::protocol::Envelope

#![forbid(unsafe_code)]

mod serve;
mod transport;

pub use serve::{ServeEvent, serve_one};
pub use transport::HostTransport;

/// Multi-protocol mux kind-byte for RPC frames.  Extends the four
/// kind bytes in [`libp2p_cat_mux`] (`KIND_APP`/`KIND_PUBSUB`/
/// `KIND_KAD`/`KIND_RENDEZVOUS`).  Also used by the standalone
/// [`HostTransport`] so RPC frames are wire-compatible whether
/// they arrive at a [`MultiProtocolNode`](libp2p_cat_mux::MultiProtocolNode)
/// or a bare [`libp2p_cat_host::Host`] running just RPC.
pub const MUX_KIND_RPC: u8 = 0x04;
