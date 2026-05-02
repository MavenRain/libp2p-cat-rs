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

use libp2p_cat_noise::{Initiator, MESSAGE_1_LEN, Responder, StaticKeypair, StaticPublicKey};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;

use crate::event::HostEvent;
use crate::state::{EstablishedConnection, InFlightHandshake};

/// Connection-managing host.
///
/// Construct with [`Host::new`], advance with [`Host::dial`],
/// [`Host::recv_one`], and [`Host::send`].  Every method consumes
/// `self`; a long-running event loop rebinds the host on each step.
#[must_use]
pub struct Host {
    socket: UdpTransport,
    static_keypair: StaticKeypair,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
}

impl Host {
    /// Build a host from a bound UDP socket and a long-lived static
    /// keypair.
    pub fn new(socket: UdpTransport, static_keypair: StaticKeypair) -> Self {
        Self {
            socket,
            static_keypair,
            handshakes: BTreeMap::new(),
            established: BTreeMap::new(),
        }
    }

    /// Borrow the underlying socket (read-only).
    pub fn socket(&self) -> &UdpTransport {
        &self.socket
    }

    /// Borrow the host's long-lived static public key.
    pub fn static_public(&self) -> &StaticPublicKey {
        self.static_keypair.public()
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
                static_keypair,
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
                    static_keypair,
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
                static_keypair,
                handshakes,
                mut established,
                conn,
                datagram,
            } = prepared;
            established.insert(addr, conn);
            socket.send(addr, datagram).map(move |socket| Self {
                socket,
                static_keypair,
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
    /// out-of-state datagrams) surface as
    /// [`HostEvent::Rejected`] rather than `Err`, so a long-running
    /// loop survives misbehaving peers.
    #[must_use]
    pub fn recv_one(self, ephemeral_seed: [u8; 32]) -> Io<Error, (Self, HostEvent)> {
        let Self {
            socket,
            static_keypair,
            handshakes,
            established,
        } = self;
        socket.recv().flat_map(move |((from, datagram), socket)| {
            dispatch_inbound(
                socket,
                static_keypair,
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
    static_keypair: StaticKeypair,
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
        static_keypair,
        handshakes,
        established,
    } = host;
    if handshakes.contains_key(&addr) || established.contains_key(&addr) {
        Err(Error::HostState {
            reason: format!("dial: address {addr} already known to host"),
        })
    } else {
        let initiator = Initiator::new(static_keypair.clone());
        let (after_e, msg1) = initiator.write_e(ephemeral_seed)?;
        Ok(DialPrepared {
            socket,
            static_keypair,
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
    static_keypair: StaticKeypair,
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
        static_keypair,
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
    };
    Ok(SendPrepared {
        socket,
        static_keypair,
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
    static_keypair: StaticKeypair,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    datagram: Vec<u8>,
    ephemeral_seed: [u8; 32],
) -> Io<Error, (Host, HostEvent)> {
    if established.contains_key(&from) {
        decrypt_established(
            socket,
            static_keypair,
            handshakes,
            established,
            from,
            datagram,
        )
    } else if handshakes.contains_key(&from) {
        advance_in_flight(
            socket,
            static_keypair,
            handshakes,
            established,
            from,
            datagram,
        )
    } else {
        try_responder_msg1(
            socket,
            static_keypair,
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
    static_keypair: StaticKeypair,
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
        match outcome {
            Ok((transport, plaintext)) => {
                established.insert(
                    from,
                    EstablishedConnection {
                        transport,
                        remote_static,
                    },
                );
                (
                    rebuild_host(socket, static_keypair, handshakes, established),
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
                    rebuild_host(socket, static_keypair, handshakes, established),
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
    static_keypair: StaticKeypair,
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
            static_keypair,
            handshakes,
            established,
            from,
            after_e,
            &datagram,
        ),
        InFlightHandshake::ResponderAwaitingFinalize(after_resp) => responder_consume_msg3(
            socket,
            static_keypair,
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
    static_keypair: StaticKeypair,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    after_e: libp2p_cat_noise::InitiatorAfterE,
    datagram: &[u8],
) -> Io<Error, (Host, HostEvent)> {
    let result = after_e
        .read_response(datagram)
        .and_then(libp2p_cat_noise::InitiatorAfterResponse::write_s);
    match result {
        Ok((transport, msg3, remote_static)) => socket.send(from, msg3).map(move |socket| {
            let mut established = established;
            established.insert(
                from,
                EstablishedConnection {
                    transport,
                    remote_static: remote_static.clone(),
                },
            );
            (
                rebuild_host(socket, static_keypair, handshakes, established),
                HostEvent::HandshakeComplete {
                    addr: from,
                    remote_static,
                },
            )
        }),
        Err(e) => Io::pure((
            rebuild_host(socket, static_keypair, handshakes, established),
            HostEvent::Rejected {
                addr: from,
                reason: format!("initiator: failed to advance on msg2: {e}"),
            },
        )),
    }
}

fn responder_consume_msg3(
    socket: UdpTransport,
    static_keypair: StaticKeypair,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    mut established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    after_resp: libp2p_cat_noise::ResponderAfterResponse,
    datagram: &[u8],
) -> Io<Error, (Host, HostEvent)> {
    match after_resp.read_s(datagram) {
        Ok((transport, remote_static)) => {
            established.insert(
                from,
                EstablishedConnection {
                    transport,
                    remote_static: remote_static.clone(),
                },
            );
            Io::pure((
                rebuild_host(socket, static_keypair, handshakes, established),
                HostEvent::HandshakeComplete {
                    addr: from,
                    remote_static,
                },
            ))
        }
        Err(e) => Io::pure((
            rebuild_host(socket, static_keypair, handshakes, established),
            HostEvent::Rejected {
                addr: from,
                reason: format!("responder: failed to finalize on msg3: {e}"),
            },
        )),
    }
}

fn try_responder_msg1(
    socket: UdpTransport,
    static_keypair: StaticKeypair,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    from: UdpAddr,
    datagram: &[u8],
    ephemeral_seed: [u8; 32],
) -> Io<Error, (Host, HostEvent)> {
    if datagram.len() == MESSAGE_1_LEN {
        let responder = Responder::new(static_keypair.clone());
        match responder
            .read_e(datagram)
            .and_then(|after_e| after_e.write_response(ephemeral_seed))
        {
            Ok((after_resp, msg2)) => socket.send(from, msg2).map(move |socket| {
                let mut handshakes = handshakes;
                handshakes.insert(
                    from,
                    InFlightHandshake::ResponderAwaitingFinalize(after_resp),
                );
                (
                    rebuild_host(socket, static_keypair, handshakes, established),
                    HostEvent::HandshakeProgress { addr: from },
                )
            }),
            Err(e) => Io::pure((
                rebuild_host(socket, static_keypair, handshakes, established),
                HostEvent::Rejected {
                    addr: from,
                    reason: format!("responder: failed to start handshake: {e}"),
                },
            )),
        }
    } else {
        Io::pure((
            rebuild_host(socket, static_keypair, handshakes, established),
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

fn rebuild_host(
    socket: UdpTransport,
    static_keypair: StaticKeypair,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
) -> Host {
    Host {
        socket,
        static_keypair,
        handshakes,
        established,
    }
}
