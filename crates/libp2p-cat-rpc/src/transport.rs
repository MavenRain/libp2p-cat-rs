//! [`HostTransport`]: implements [`tarpc_cat::transport::Transport`]
//! over a [`Host`] anchored to a single peer address.
//!
//! [`tarpc_cat::transport::Transport`]: tarpc_cat::transport::Transport

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_types::{Error as LibError, UdpAddr};

use tarpc_cat::error::Error as TarpcError;
use tarpc_cat::protocol::Envelope;
use tarpc_cat::transport::Transport;

use crate::MUX_KIND_RPC;

/// A [`tarpc_cat::transport::Transport`] backed by a
/// [`libp2p_cat_host::Host`] anchored to a single peer address.
///
/// `send` prepends [`MUX_KIND_RPC`] and calls [`Host::send`].  `recv`
/// drains [`Host::recv_one`] until a `KIND_RPC`-prefixed
/// `DatagramDelivered` from the anchored peer arrives; non-RPC
/// events (handshakes, datagrams from other peers, decrypt
/// failures) are silently absorbed but the underlying [`Host`]
/// state still updates.
///
/// `seed_factory` is used per drain step to supply
/// [`Host::recv_one`]'s `ephemeral_seed`.  In a single-peer RPC
/// scenario the seed is rarely consumed (only an unrelated fresh
/// `msg1` would consume it); a deterministic factory like
/// `|| [0u8; 32]` is acceptable for tests, while production
/// callers should pass `getrandom`-backed factories.
///
/// [`Host`]: libp2p_cat_host::Host
/// [`Host::send`]: libp2p_cat_host::Host::send
/// [`Host::recv_one`]: libp2p_cat_host::Host::recv_one
#[must_use]
pub struct HostTransport<F> {
    host: Host,
    peer: UdpAddr,
    seed_factory: F,
}

impl<F> HostTransport<F>
where
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    /// Build a transport anchored to `(host, peer)`.  The host must
    /// already have an established connection to `peer` for
    /// subsequent sends to succeed.
    pub fn new(host: Host, peer: UdpAddr, seed_factory: F) -> Self {
        Self {
            host,
            peer,
            seed_factory,
        }
    }

    /// Borrow the underlying host (read-only).
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The anchored peer address.
    pub fn peer(&self) -> UdpAddr {
        self.peer
    }

    /// Decompose into the host plus peer address, dropping the
    /// seed factory.
    pub fn into_parts(self) -> (Host, UdpAddr) {
        (self.host, self.peer)
    }
}

impl<F> Transport for HostTransport<F>
where
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    fn send(self, envelope: Envelope) -> Io<TarpcError, Self> {
        let Self {
            host,
            peer,
            seed_factory,
        } = self;
        Io::suspend(move || serde_json::to_vec(&envelope).map_err(TarpcError::from_serialize))
            .flat_map(move |body| {
                let framed: Vec<u8> = core::iter::once(MUX_KIND_RPC).chain(body).collect();
                host.send(peer, framed)
                    .map_error(lib_error_to_tarpc)
                    .map(move |host| Self {
                        host,
                        peer,
                        seed_factory,
                    })
            })
    }

    fn recv(self) -> Io<TarpcError, (Envelope, Self)> {
        let Self {
            host,
            peer,
            seed_factory,
        } = self;
        drain_for_rpc(host, peer, seed_factory)
    }
}

fn drain_for_rpc<F>(
    host: Host,
    peer: UdpAddr,
    seed_factory: F,
) -> Io<TarpcError, (Envelope, HostTransport<F>)>
where
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    let seed = seed_factory();
    host.recv_one(seed)
        .map_error(lib_error_to_tarpc)
        .flat_map(move |(host, ev)| match ev {
            HostEvent::DatagramDelivered { addr, plaintext }
                if addr == peer && plaintext.first() == Some(&MUX_KIND_RPC) =>
            {
                Io::suspend(move || {
                    let body = plaintext.get(1..).unwrap_or(&[]);
                    let envelope = serde_json::from_slice::<Envelope>(body)
                        .map_err(TarpcError::from_deserialize)?;
                    Ok((
                        envelope,
                        HostTransport {
                            host,
                            peer,
                            seed_factory,
                        },
                    ))
                })
            }
            HostEvent::HandshakeProgress { .. }
            | HostEvent::HandshakeComplete { .. }
            | HostEvent::Rejected { .. }
            | HostEvent::DatagramDelivered { .. } => drain_for_rpc(host, peer, seed_factory),
        })
}

/// Convert a [`libp2p_cat_types::Error`] into a
/// [`tarpc_cat::error::Error`] for surface back to RPC callers.
/// I/O errors map directly; everything else collapses to
/// [`TarpcError::Server`] with a descriptive message.
pub(crate) fn lib_error_to_tarpc(e: LibError) -> TarpcError {
    match e {
        LibError::Io(io) => TarpcError::Io(io),
        e @ (LibError::InvalidProtocolId { .. }
        | LibError::InvalidPeerId { .. }
        | LibError::DatagramTooLarge { .. }
        | LibError::NoiseDecrypt
        | LibError::NoiseProtocol { .. }
        | LibError::NoiseReplay { .. }
        | LibError::RlncLayer { .. }
        | LibError::PubsubProtocol { .. }
        | LibError::HostState { .. }
        | LibError::IdentityVerify { .. }) => TarpcError::Server {
            message: format!("libp2p error: {e}"),
        },
    }
}
