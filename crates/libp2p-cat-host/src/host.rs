//! The [`Host`] type and its `dial` / `recv_one` / `send` operations.
//!
//! Linear state-threading throughout: every method consumes `self`
//! and returns a new host.  Internal `BTreeMap`s are mutated only
//! through the destructure-and-rebuild pattern used in
//! [`libp2p_cat_pubsub::PeerTable`], so a single `let mut` per method
//! is the only mutation surface.
//!
//! [`libp2p_cat_pubsub::PeerTable`]: https://crates.io/crates/libp2p-cat-pubsub

use std::collections::BTreeMap;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_identity::{Ed25519Keypair, SignedStaticKey};
use libp2p_cat_noise::{Initiator, MESSAGE_1_LEN, Responder, StaticKeypair, StaticPublicKey};
use libp2p_cat_types::{Error, PeerId, UdpAddr};
use libp2p_cat_udp::UdpTransport;

use crate::event::HostEvent;
use crate::state::{EstablishedConnection, InFlightHandshake};

/// Long-lived identity bundle: the X25519 keypair Noise runs against,
/// the precomputed Ed25519 [`SignedStaticKey`] this host sends as the
/// XX handshake trailer, and the libp2p-compatible [`PeerId`] that
/// binding resolves to.
///
/// Cloned cheaply on every event-loop step; the X25519 private key is
/// the only secret material it carries.
#[derive(Clone)]
struct HostIdentity {
    static_keypair: StaticKeypair,
    signed_static_key: SignedStaticKey,
    peer_id: PeerId,
}

/// Connection-managing host.
///
/// Construct with [`Host::new`], advance with [`Host::dial`],
/// [`Host::recv_one`], and [`Host::send`].  Every method consumes
/// `self`; a long-running event loop rebinds the host on each step.
#[must_use]
pub struct Host {
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
}

impl Host {
    /// Build a host from a bound UDP socket, a long-lived X25519
    /// static keypair, and an Ed25519 identity keypair that signs the
    /// static key.
    ///
    /// The signed binding is computed once and reused for every
    /// handshake; the `identity` reference is dropped after
    /// construction.  The caller can keep their own copy of the
    /// keypair if they need to sign other things later.
    ///
    /// # Errors
    ///
    /// - [`Error::IdentityVerify`] if the underlying Ed25519
    ///   `try_sign` reports a failure.  Ed25519 signing is
    ///   deterministic per RFC 8032 and is not expected to fail in
    ///   practice; the error path exists to keep this layer
    ///   panic-free.
    pub fn new(
        socket: UdpTransport,
        static_keypair: StaticKeypair,
        identity: &Ed25519Keypair,
    ) -> Result<Self, Error> {
        let signed_static_key = SignedStaticKey::create(identity, static_keypair.public())?;
        let peer_id = identity.peer_id();
        Ok(Self {
            socket,
            identity: HostIdentity {
                static_keypair,
                signed_static_key,
                peer_id,
            },
            handshakes: BTreeMap::new(),
            established: BTreeMap::new(),
        })
    }

    /// Borrow the underlying socket (read-only).
    pub fn socket(&self) -> &UdpTransport {
        &self.socket
    }

    /// Borrow the host's long-lived X25519 static public key.
    pub fn static_public(&self) -> &StaticPublicKey {
        self.identity.static_keypair.public()
    }

    /// Borrow the host's libp2p-compatible [`PeerId`].
    pub fn peer_id(&self) -> &PeerId {
        &self.identity.peer_id
    }

    /// Borrow the host's precomputed [`SignedStaticKey`] binding.
    /// Useful for peers that want to record the same payload they
    /// will see in the handshake trailer.
    pub fn signed_static_key(&self) -> &SignedStaticKey {
        &self.identity.signed_static_key
    }

    /// Local UDP address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot report the local address.
    pub fn local_addr(&self) -> Result<UdpAddr, Error> {
        self.socket.local_addr()
    }

    /// Number of in-flight handshakes.
    #[must_use]
    pub fn handshakes_in_flight(&self) -> usize {
        self.handshakes.len()
    }

    /// Number of established connections.
    #[must_use]
    pub fn established_connections(&self) -> usize {
        self.established.len()
    }

    /// Whether `addr` has a fully-established connection.
    #[must_use]
    pub fn is_established(&self, addr: UdpAddr) -> bool {
        self.established.contains_key(&addr)
    }

    /// The remote static public key authenticated for `addr`, if the
    /// connection is established.
    #[must_use]
    pub fn remote_static_of(&self, addr: UdpAddr) -> Option<&StaticPublicKey> {
        self.established.get(&addr).map(|conn| &conn.remote_static)
    }

    /// The remote peer's libp2p-compatible [`PeerId`] for `addr`, if
    /// the connection is established.
    #[must_use]
    pub fn remote_peer_id_of(&self, addr: UdpAddr) -> Option<&PeerId> {
        self.established.get(&addr).map(|conn| &conn.remote_peer_id)
    }

    /// A snapshot of every peer address with an established
    /// post-handshake transport.
    ///
    /// Useful for layers above the host (e.g. pubsub broadcast
    /// fan-out) that need to enumerate active connections.
    #[must_use]
    pub fn established_addrs(&self) -> Vec<UdpAddr> {
        self.established.keys().copied().collect()
    }

    /// Initiate a Noise XX handshake with the peer at `addr`.
    ///
    /// Sends `msg1` over the wire and stores the `InitiatorAfterE`
    /// state, awaiting `msg2`.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `addr` already has an in-flight
    ///   handshake or an established connection.
    /// - [`Error::Io`] / [`Error::DatagramTooLarge`] from the socket.
    /// - [`Error::NoiseProtocol`] from the noise layer.
    #[must_use]
    pub fn dial(self, addr: UdpAddr, ephemeral_seed: [u8; 32]) -> Io<Error, Self> {
        Io::suspend(move || prepare_dial(self, addr, ephemeral_seed)).flat_map(move |prepared| {
            let DialPrepared {
                socket,
                identity,
                handshakes,
                established,
                after_e,
                msg1,
            } = prepared;
            socket.send(addr, msg1).map(move |socket| {
                let mut handshakes = handshakes;
                handshakes.insert(addr, InFlightHandshake::InitiatorAwaitingResponse(after_e));
                Self {
                    socket,
                    identity,
                    handshakes,
                    established,
                }
            })
        })
    }

    /// Send `plaintext` as one authenticated datagram to an
    /// already-established peer.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `addr` is not established.
    /// - Noise / UDP errors propagate transparently.
    #[must_use]
    pub fn send(self, addr: UdpAddr, plaintext: Vec<u8>) -> Io<Error, Self> {
        Io::suspend(move || prepare_send(self, addr, &plaintext)).flat_map(move |prepared| {
            let SendPrepared {
                socket,
                identity,
                handshakes,
                mut established,
                conn,
                datagram,
            } = prepared;
            established.insert(addr, conn);
            socket.send(addr, datagram).map(move |socket| Self {
                socket,
                identity,
                handshakes,
                established,
            })
        })
    }

    /// Receive one datagram and dispatch it.
    ///
    /// `ephemeral_seed` is consumed only if the inbound datagram is a
    /// fresh `msg1` from a previously-unknown peer (the host
    /// immediately writes `msg2` in response).
    ///
    /// # Errors
    ///
    /// Underlying socket failures propagate as `Err`.  Per-peer
    /// problems (decrypt failures, malformed handshakes, replays,
    /// out-of-state datagrams, identity-binding rejection) surface as
    /// [`HostEvent::Rejected`] rather than `Err`, so a long-running
    /// loop survives misbehaving peers.
    #[must_use]
    pub fn recv_one(self, ephemeral_seed: [u8; 32]) -> Io<Error, (Self, HostEvent)> {
        let Self {
            socket,
            identity,
            handshakes,
            established,
        } = self;
        socket.recv().flat_map(move |((from, datagram), socket)| {
            dispatch_inbound(
                socket,
                identity,
                handshakes,
                established,
                from,
                datagram,
                ephemeral_seed,
            )
        })
    }
}

/// Bundled output of [`prepare_dial`].
struct DialPrepared {
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    after_e: libp2p_cat_noise::InitiatorAfterE,
    msg1: Vec<u8>,
}

/// Validate the dial preconditions and produce the `msg1` bytes plus
/// all the host fields, packaged for the post-send rebuild.
fn prepare_dial(
    host: Host,
    addr: UdpAddr,
    ephemeral_seed: [u8; 32],
) -> Result<DialPrepared, Error> {
    let Host {
        socket,
        identity,
        handshakes,
        established,
    } = host;
    if handshakes.contains_key(&addr) || established.contains_key(&addr) {
        Err(Error::HostState {
            reason: format!("dial: address {addr} already known to host"),
        })
    } else {
        let initiator = Initiator::new(identity.static_keypair.clone());
        let (after_e, msg1) = initiator.write_e(ephemeral_seed)?;
        Ok(DialPrepared {
            socket,
            identity,
            handshakes,
            established,
            after_e,
            msg1,
        })
    }
}

/// Bundled output of [`prepare_send`].
struct SendPrepared {
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    conn: EstablishedConnection,
    datagram: Vec<u8>,
}

/// Validate the send preconditions and encrypt `plaintext` against
/// the established connection's transport state.
fn prepare_send(host: Host, addr: UdpAddr, plaintext: &[u8]) -> Result<SendPrepared, Error> {
    let Host {
        socket,
        identity,
        handshakes,
        mut established,
    } = host;
    let conn = established.remove(&addr).ok_or_else(|| Error::HostState {
        reason: format!("send: no established connection for {addr}"),
    })?;
    let (transport, datagram) = conn.transport.encrypt(plaintext)?;
    let next_conn = EstablishedConnection {
        transport,
        remote_static: conn.remote_static,
        remote_peer_id: conn.remote_peer_id,
    };
    Ok(SendPrepared {
        socket,
        identity,
        handshakes,
        established,
        conn: next_conn,
        datagram,
    })
}

/// Dispatch one received datagram to the right path:
/// established → decrypt; in-flight → advance; otherwise → maybe
/// start a responder.  Each sub-path returns a fully-rebuilt host.
fn dispatch_inbound(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    datagram: Vec<u8>,
    ephemeral_seed: [u8; 32],
) -> Io<Error, (Host, HostEvent)> {
    if established.contains_key(&from) {
        decrypt_established(socket, identity, handshakes, established, from, datagram)
    } else if handshakes.contains_key(&from) {
        advance_in_flight(socket, identity, handshakes, established, from, datagram)
    } else {
        try_responder_msg1(
            socket,
            identity,
            handshakes,
            established,
            from,
            &datagram,
            ephemeral_seed,
        )
    }
}

// `datagram: Vec<u8>` is required: the decrypt closure below captures
// the bytes by `move` for its `'static` bound.  Switching to `&[u8]`
// would force the closure to outlive the borrow, which doesn't match
// `Io::suspend`'s `+ 'static` requirement.
#[allow(clippy::needless_pass_by_value)]
fn decrypt_established(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    mut established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    datagram: Vec<u8>,
) -> Io<Error, (Host, HostEvent)> {
    // The `contains_key` check in the dispatcher guarantees this
    // remove succeeds; we still combinator-handle the Option to keep
    // the no-panicking-indexing rule intact.
    let conn = established.remove(&from).ok_or_else(|| Error::HostState {
        reason: "established entry vanished mid-dispatch".to_owned(),
    });
    Io::suspend(move || conn).map(move |conn| {
        let outcome = conn.transport.decrypt(&datagram);
        let remote_static = conn.remote_static;
        let remote_peer_id = conn.remote_peer_id;
        match outcome {
            Ok((transport, plaintext)) => {
                established.insert(
                    from,
                    EstablishedConnection {
                        transport,
                        remote_static,
                        remote_peer_id,
                    },
                );
                (
                    rebuild_host(socket, identity, handshakes, established),
                    HostEvent::DatagramDelivered {
                        addr: from,
                        plaintext,
                    },
                )
            }
            Err(e) => {
                // V1 policy: drop the connection on tamper / replay.
                // The transport state was consumed by `decrypt`, so
                // we cannot keep using it without a rollback that the
                // current API doesn't expose.  A future iteration can
                // expose a non-consuming `peek_decrypt` to keep the
                // session alive across single bad datagrams.
                (
                    rebuild_host(socket, identity, handshakes, established),
                    HostEvent::Rejected {
                        addr: from,
                        reason: format!("transport decrypt failed: {e}; connection dropped"),
                    },
                )
            }
        }
    })
}

fn advance_in_flight(
    socket: UdpTransport,
    identity: HostIdentity,
    mut handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    datagram: Vec<u8>,
) -> Io<Error, (Host, HostEvent)> {
    let removed = handshakes.remove(&from).ok_or_else(|| Error::HostState {
        reason: "in-flight entry vanished mid-dispatch".to_owned(),
    });
    Io::suspend(move || removed).flat_map(move |state| match state {
        InFlightHandshake::InitiatorAwaitingResponse(after_e) => initiator_consume_msg2(
            socket,
            identity,
            handshakes,
            established,
            from,
            after_e,
            &datagram,
        ),
        InFlightHandshake::ResponderAwaitingFinalize(after_resp) => responder_consume_msg3(
            socket,
            identity,
            handshakes,
            established,
            from,
            after_resp,
            &datagram,
        ),
    })
}

fn initiator_consume_msg2(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    after_e: libp2p_cat_noise::InitiatorAfterE,
    datagram: &[u8],
) -> Io<Error, (Host, HostEvent)> {
    let result = after_e
        .read_response(datagram)
        .and_then(|(after_resp, msg2_payload)| {
            let remote_static_for_verify = after_resp.remote_static().clone();
            verify_binding(&msg2_payload, &remote_static_for_verify).and_then(|remote_peer_id| {
                after_resp
                    .write_s(&identity.signed_static_key.to_bytes())
                    .map(|(transport, msg3, remote_static)| {
                        (transport, msg3, remote_static, remote_peer_id)
                    })
            })
        });
    match result {
        Ok((transport, msg3, remote_static, remote_peer_id)) => {
            socket.send(from, msg3).map(move |socket| {
                let mut established = established;
                established.insert(
                    from,
                    EstablishedConnection {
                        transport,
                        remote_static: remote_static.clone(),
                        remote_peer_id: remote_peer_id.clone(),
                    },
                );
                (
                    rebuild_host(socket, identity, handshakes, established),
                    HostEvent::HandshakeComplete {
                        addr: from,
                        remote_static,
                        remote_peer_id,
                    },
                )
            })
        }
        Err(e) => Io::pure((
            rebuild_host(socket, identity, handshakes, established),
            HostEvent::Rejected {
                addr: from,
                reason: format!("initiator: failed to advance on msg2: {e}"),
            },
        )),
    }
}

fn responder_consume_msg3(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    mut established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    after_resp: libp2p_cat_noise::ResponderAfterResponse,
    datagram: &[u8],
) -> Io<Error, (Host, HostEvent)> {
    let outcome =
        after_resp
            .read_s(datagram)
            .and_then(|(transport, remote_static, msg3_payload)| {
                verify_binding(&msg3_payload, &remote_static)
                    .map(|remote_peer_id| (transport, remote_static, remote_peer_id))
            });
    match outcome {
        Ok((transport, remote_static, remote_peer_id)) => {
            established.insert(
                from,
                EstablishedConnection {
                    transport,
                    remote_static: remote_static.clone(),
                    remote_peer_id: remote_peer_id.clone(),
                },
            );
            Io::pure((
                rebuild_host(socket, identity, handshakes, established),
                HostEvent::HandshakeComplete {
                    addr: from,
                    remote_static,
                    remote_peer_id,
                },
            ))
        }
        Err(e) => Io::pure((
            rebuild_host(socket, identity, handshakes, established),
            HostEvent::Rejected {
                addr: from,
                reason: format!("responder: failed to finalize on msg3: {e}"),
            },
        )),
    }
}

fn try_responder_msg1(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    datagram: &[u8],
    ephemeral_seed: [u8; 32],
) -> Io<Error, (Host, HostEvent)> {
    if datagram.len() == MESSAGE_1_LEN {
        let responder = Responder::new(identity.static_keypair.clone());
        let trailer = identity.signed_static_key.to_bytes();
        match responder
            .read_e(datagram)
            .and_then(|after_e| after_e.write_response(ephemeral_seed, &trailer))
        {
            Ok((after_resp, msg2)) => socket.send(from, msg2).map(move |socket| {
                let mut handshakes = handshakes;
                handshakes.insert(
                    from,
                    InFlightHandshake::ResponderAwaitingFinalize(after_resp),
                );
                (
                    rebuild_host(socket, identity, handshakes, established),
                    HostEvent::HandshakeProgress { addr: from },
                )
            }),
            Err(e) => Io::pure((
                rebuild_host(socket, identity, handshakes, established),
                HostEvent::Rejected {
                    addr: from,
                    reason: format!("responder: failed to start handshake: {e}"),
                },
            )),
        }
    } else {
        Io::pure((
            rebuild_host(socket, identity, handshakes, established),
            HostEvent::Rejected {
                addr: from,
                reason: format!(
                    "datagram from new peer is not a {MESSAGE_1_LEN}-byte handshake msg1: {} bytes",
                    datagram.len()
                ),
            },
        ))
    }
}

/// Parse the handshake-trailer bytes as a [`SignedStaticKey`] and
/// verify that it binds the X25519 static key Noise just
/// authenticated.  Returns the resulting [`PeerId`] on success.
fn verify_binding(payload: &[u8], remote_static: &StaticPublicKey) -> Result<PeerId, Error> {
    let signed = SignedStaticKey::from_bytes(payload)?;
    let (_pk, peer_id) = signed.verify(remote_static)?;
    Ok(peer_id)
}

fn rebuild_host(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
) -> Host {
    Host {
        socket,
        identity,
        handshakes,
        established,
    }
}
