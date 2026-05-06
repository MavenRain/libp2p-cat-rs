//! [`serve_one`]: drive one RPC request through a
//! [`tarpc_cat::serve::Serve`] implementation and send the response
//! back to the caller.
//!
//! Mirrors the structure of `tarpc-cat`'s own `process_one_request`
//! but reads / writes through a [`libp2p_cat_host::Host`] rather
//! than a [`std::net::TcpStream`].  The caller drives the server
//! loop themselves (typically `try_fold` over `0..usize::MAX`),
//! which matches the workspace's "stay inside `Io`, run at the
//! boundary" idiom.
//!
//! [`tarpc_cat::serve::Serve`]: tarpc_cat::serve::Serve

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::{Error as LibError, PeerId, UdpAddr};

use tarpc_cat::error::Error as TarpcError;
use tarpc_cat::protocol::{Envelope, RequestId};
use tarpc_cat::serve::Serve;

use crate::MUX_KIND_RPC;

/// Outcome of one [`serve_one`] step.
#[derive(Debug)]
#[must_use]
pub enum ServeEvent {
    /// A request was decoded, dispatched to the service handler,
    /// and a response (or [`Envelope::Error`]) was sent back to
    /// `peer`.
    Handled {
        /// Address of the client that issued the request.
        peer: UdpAddr,
        /// Correlation id from the request envelope.
        request_id: RequestId,
    },
    /// The inbound datagram was a non-RPC plaintext (wrong kind
    /// byte), a malformed envelope, or an unexpected envelope
    /// variant (`Response` / `Error` from a peer that should be
    /// the client).
    Rejected {
        /// Address the datagram came from.
        peer: UdpAddr,
        /// Description of the rejection.
        reason: String,
    },
    /// Pass-through from
    /// [`HostEvent::HandshakeProgress`](libp2p_cat_host::HostEvent::HandshakeProgress).
    HandshakeProgress {
        /// Address of the peer the handshake is with.
        peer: UdpAddr,
    },
    /// Pass-through from
    /// [`HostEvent::HandshakeComplete`](libp2p_cat_host::HostEvent::HandshakeComplete).
    HandshakeComplete {
        /// Address of the peer.
        peer: UdpAddr,
        /// The peer's authenticated long-lived X25519 static public
        /// key.
        remote_static: StaticPublicKey,
        /// The peer's libp2p-compatible [`PeerId`].
        remote_peer_id: PeerId,
    },
    /// A connection-level rejection from
    /// [`HostEvent::Rejected`](libp2p_cat_host::HostEvent::Rejected).
    HostRejected {
        /// Address of the peer.
        peer: UdpAddr,
        /// Description of why the datagram was rejected.
        reason: String,
    },
}

/// Drive one server-side RPC step over a [`libp2p_cat_host::Host`].
///
/// Reads one datagram via [`Host::recv_one`].  If the datagram is a
/// `MUX_KIND_RPC`-prefixed [`Envelope::Request`], the request is
/// deserialized, dispatched to `service`, and the response (or an
/// [`Envelope::Error`] on handler failure) is sent back over the
/// same authenticated session.  All other inbound shapes
/// (handshake progress, non-RPC plaintexts, rejections) surface as
/// the matching [`ServeEvent`] variant without changing host
/// state beyond what `recv_one` already does.
///
/// Use in a loop:
///
/// ```rust,ignore
/// (0..usize::MAX).try_fold(host, |host, _| {
///     let (host, _ev) = serve_one(host, service.clone(), seed).run()?;
///     Ok::<_, Error>(host)
/// })?;
/// ```
///
/// # Errors
///
/// Underlying socket / Noise errors propagate transparently from
/// [`Host::recv_one`] / [`Host::send`].  Per-request
/// deserialization or service-handler errors do **not** propagate;
/// they are encoded into an [`Envelope::Error`] and sent back to
/// the client, surfacing as [`ServeEvent::Handled`] locally.
///
/// [`Host`]: libp2p_cat_host::Host
/// [`Host::recv_one`]: libp2p_cat_host::Host::recv_one
/// [`Host::send`]: libp2p_cat_host::Host::send
#[must_use]
pub fn serve_one<S>(
    host: Host,
    service: S,
    ephemeral_seed: [u8; 32],
) -> Io<LibError, (Host, ServeEvent)>
where
    S: Serve,
{
    host.recv_one(ephemeral_seed)
        .flat_map(move |(host, ev)| match ev {
            HostEvent::DatagramDelivered { addr, plaintext } => {
                handle_rpc_datagram(host, service, addr, plaintext)
            }
            HostEvent::HandshakeProgress { addr } => {
                Io::pure((host, ServeEvent::HandshakeProgress { peer: addr }))
            }
            HostEvent::HandshakeComplete {
                addr,
                remote_static,
                remote_peer_id,
            } => Io::pure((
                host,
                ServeEvent::HandshakeComplete {
                    peer: addr,
                    remote_static,
                    remote_peer_id,
                },
            )),
            HostEvent::Rejected { addr, reason } => {
                Io::pure((host, ServeEvent::HostRejected { peer: addr, reason }))
            }
        })
}

#[allow(clippy::needless_pass_by_value)]
fn handle_rpc_datagram<S>(
    host: Host,
    service: S,
    peer: UdpAddr,
    plaintext: Vec<u8>,
) -> Io<LibError, (Host, ServeEvent)>
where
    S: Serve,
{
    match plaintext.first().copied() {
        Some(MUX_KIND_RPC) => {
            let body = plaintext.get(1..).unwrap_or(&[]);
            match serde_json::from_slice::<Envelope>(body) {
                Err(e) => Io::pure((
                    host,
                    ServeEvent::Rejected {
                        peer,
                        reason: format!("envelope decode failed: {e}"),
                    },
                )),
                Ok(Envelope::Request { id, payload }) => {
                    dispatch_request(host, service, peer, id, payload)
                }
                Ok(Envelope::Response { .. } | Envelope::Error { .. }) => Io::pure((
                    host,
                    ServeEvent::Rejected {
                        peer,
                        reason: "expected Envelope::Request from client".to_owned(),
                    },
                )),
            }
        }
        Some(other_kind) => Io::pure((
            host,
            ServeEvent::Rejected {
                peer,
                reason: format!("non-RPC kind byte 0x{other_kind:02x}"),
            },
        )),
        None => Io::pure((
            host,
            ServeEvent::Rejected {
                peer,
                reason: "empty plaintext (no kind byte)".to_owned(),
            },
        )),
    }
}

/// Build the response (or error) envelope for `payload` by
/// dispatching to `service.handle` and serialize it back into a
/// `KIND_RPC`-prefixed plaintext for [`Host::send`].
///
/// Mirrors `tarpc_cat::server::deserialize_and_handle`: any
/// deserialization, handler, or response-serialization error is
/// caught and surfaces as [`Envelope::Error`] sent back to the
/// client.  Only socket / Noise failures propagate as `Err`.
fn dispatch_request<S>(
    host: Host,
    service: S,
    peer: UdpAddr,
    id: RequestId,
    payload: String,
) -> Io<LibError, (Host, ServeEvent)>
where
    S: Serve,
{
    let envelope_io = Io::suspend(move || {
        let envelope = serde_json::from_str::<S::Request>(&payload)
            .map_err(TarpcError::from_deserialize)
            .and_then(|request| service.handle(request).run())
            .and_then(|response| {
                serde_json::to_string(&response)
                    .map_err(TarpcError::from_serialize)
                    .map(|resp_payload| Envelope::Response {
                        id,
                        payload: resp_payload,
                    })
            })
            .unwrap_or_else(|e| Envelope::Error {
                id,
                message: e.to_string(),
            });
        Ok(envelope)
    });
    envelope_io.flat_map(move |envelope| {
        Io::suspend(move || {
            let body = serde_json::to_vec(&envelope).map_err(|e| LibError::PubsubProtocol {
                reason: format!("rpc envelope serialize: {e}"),
            })?;
            Ok(body)
        })
        .flat_map(move |body| {
            let framed: Vec<u8> = core::iter::once(MUX_KIND_RPC).chain(body).collect();
            host.send(peer, framed).map(move |host| {
                (
                    host,
                    ServeEvent::Handled {
                        peer,
                        request_id: id,
                    },
                )
            })
        })
    })
}
