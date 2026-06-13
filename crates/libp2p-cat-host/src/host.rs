//! The [`Host`] type and its `dial` / `recv_one` / `send` operations.
//!
//! Linear state-threading throughout: every method consumes `self`
//! and returns a new host.  Internal `BTreeMap`s are mutated only
//! through the destructure-and-rebuild pattern used in
//! [`libp2p_cat_pubsub::PeerTable`], so a single `let mut` per method
//! is the only mutation surface.
//!
//! # Capacity and eviction (pass 9.1)
//!
//! Both `BTreeMap`s are bounded by a [`Capacity`] supplied at
//! construction.  Each entry carries a `last_activity` tick set
//! whenever the entry is touched (dial / send / recv); when an
//! insert would exceed the matching cap, the LRU entry is evicted
//! to make room.  Future datagrams from an evicted peer surface as
//! [`HostEvent::Rejected`] when they fail the established / in-
//! flight lookups; eviction itself is silent.
//!
//! Callers can also evict explicitly with [`Host::evict`] or sweep
//! all entries idle longer than a threshold with
//! [`Host::evict_idle`].
//!
//! [`libp2p_cat_pubsub::PeerTable`]: https://crates.io/crates/libp2p-cat-pubsub

use std::collections::BTreeMap;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_identity::{Ed25519Keypair, SignedStaticKey};
use libp2p_cat_noise::{Initiator, MESSAGE_1_LEN, Responder, StaticKeypair, StaticPublicKey};
use libp2p_cat_types::{Error, PeerId, UdpAddr};
use libp2p_cat_udp::UdpTransport;

use crate::capacity::Capacity;
use crate::cookie;
use crate::event::HostEvent;
use crate::state::{EstablishedConnection, HandshakeState, InFlightHandshake};

/// Long-lived identity bundle: the X25519 keypair Noise runs against,
/// the precomputed Ed25519 [`SignedStaticKey`] this host sends as the
/// XX handshake trailer, the libp2p-compatible [`PeerId`] that
/// binding resolves to, and the secret keying the stateless
/// source-address-validation cookies (see [`crate::cookie`]).
///
/// Cloned cheaply on every event-loop step; the X25519 private key
/// and the cookie secret are the only secret material it carries.
#[derive(Clone)]
struct HostIdentity {
    static_keypair: StaticKeypair,
    signed_static_key: SignedStaticKey,
    peer_id: PeerId,
    cookie_secret: [u8; 32],
}

/// Connection-managing host.
///
/// Construct with [`Host::new`] (default [`Capacity`]) or
/// [`Host::with_capacity`] (explicit caps).  Advance with
/// [`Host::dial`], [`Host::recv_one`], and [`Host::send`].  Every
/// method consumes `self`; a long-running event loop rebinds the
/// host on each step.
#[must_use]
pub struct Host {
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
}

impl Host {
    /// Build a host from a bound UDP socket, a long-lived X25519
    /// static keypair, and an Ed25519 identity keypair that signs the
    /// static key.  Uses the default [`Capacity`].
    ///
    /// The signed binding is computed once and reused for every
    /// handshake; the `identity` reference is dropped after
    /// construction.  The caller can keep their own copy of the
    /// keypair if they need to sign other things later.
    ///
    /// `cookie_secret` is 32 bytes that the caller has sourced from a
    /// cryptographically secure RNG (the same caller-provides-entropy
    /// contract as the per-call ephemeral seeds).  It keys the
    /// stateless source-address-validation cookies this host mints
    /// when answering a bare `msg1`; see [`crate::cookie`].
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
        cookie_secret: [u8; 32],
    ) -> Result<Self, Error> {
        Self::with_capacity(
            socket,
            static_keypair,
            identity,
            cookie_secret,
            Capacity::default(),
        )
    }

    /// Build a host with an explicit [`Capacity`] for both the
    /// in-flight handshake and established-connection tables.
    ///
    /// `cookie_secret` follows the [`Self::new`] contract.
    ///
    /// # Errors
    ///
    /// - [`Error::IdentityVerify`] if Ed25519 signing reports a
    ///   failure (see [`Self::new`]).
    pub fn with_capacity(
        socket: UdpTransport,
        static_keypair: StaticKeypair,
        identity: &Ed25519Keypair,
        cookie_secret: [u8; 32],
        capacity: Capacity,
    ) -> Result<Self, Error> {
        let signed_static_key = SignedStaticKey::create(identity, static_keypair.public())?;
        let peer_id = identity.peer_id();
        Ok(Self {
            socket,
            identity: HostIdentity {
                static_keypair,
                signed_static_key,
                peer_id,
                cookie_secret,
            },
            handshakes: BTreeMap::new(),
            established: BTreeMap::new(),
            capacity,
            tick: 0,
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

    /// Borrow the host's [`Capacity`] caps.
    pub fn capacity(&self) -> &Capacity {
        &self.capacity
    }

    /// Current monotonic tick.  Incremented on every state-touching
    /// operation (`dial` / `send` / `send_raw` / handshake step /
    /// decrypted datagram).  Useful as the threshold input to
    /// [`Self::evict_idle`].
    #[must_use]
    pub fn tick(&self) -> u64 {
        self.tick
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
                capacity,
                tick,
                after_e,
                msg1,
            } = prepared;
            let msg1_retained = msg1.clone();
            socket.send(addr, msg1).map(move |socket| {
                let next_tick = tick.wrapping_add(1);
                let entry = InFlightHandshake {
                    state: HandshakeState::InitiatorAwaitingResponse {
                        after_e,
                        msg1: msg1_retained,
                    },
                    last_activity: next_tick,
                };
                let handshakes = insert_handshake_with_lru(
                    handshakes,
                    addr,
                    entry,
                    capacity.max_handshakes_in_flight(),
                );
                Self {
                    socket,
                    identity,
                    handshakes,
                    established,
                    capacity,
                    tick: next_tick,
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
                capacity,
                tick,
                conn,
                datagram,
            } = prepared;
            let next_tick = tick.wrapping_add(1);
            let next_conn = EstablishedConnection {
                transport: conn.transport,
                remote_static: conn.remote_static,
                remote_peer_id: conn.remote_peer_id,
                last_activity: next_tick,
            };
            established.insert(addr, next_conn);
            socket.send(addr, datagram).map(move |socket| Self {
                socket,
                identity,
                handshakes,
                established,
                capacity,
                tick: next_tick,
            })
        })
    }

    /// Send `bytes` to `addr` as a bare UDP datagram, bypassing the
    /// Noise transport entirely.  Has no effect on connection state:
    /// no handshake is started, no transport-state nonce advances,
    /// no encryption happens.
    ///
    /// Intended for niche uses where the application needs to emit
    /// a packet that the receiver will *not* interpret as a Noise
    /// handshake or transport datagram, the canonical case being
    /// rendezvous-style hole punching where a peer fires an
    /// undersized "punch" datagram at a NAT to open the mapping
    /// without starting a handshake.  Receivers see such datagrams
    /// as [`HostEvent::Rejected`] (the dispatcher's
    /// `try_responder_msg1` path rejects anything that is neither a
    /// bare `msg1` nor a `msg1 || cookie`; callers should keep punch
    /// datagrams away from those two lengths so they are not
    /// mistaken for handshake traffic).
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] / [`Error::DatagramTooLarge`] from the socket.
    #[must_use]
    pub fn send_raw(self, addr: UdpAddr, bytes: Vec<u8>) -> Io<Error, Self> {
        let Self {
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick,
        } = self;
        socket.send(addr, bytes).map(move |socket| Self {
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick: tick.wrapping_add(1),
        })
    }

    /// Receive one datagram and dispatch it.
    ///
    /// `ephemeral_seed` is consumed only if the inbound datagram is a
    /// cookie-validated `msg1 || cookie` from a previously-unknown
    /// peer (the host then writes `msg2` in response).  A bare
    /// `msg1` is answered with a stateless cookie challenge that
    /// consumes no seed and creates no state; see [`crate::cookie`].
    ///
    /// # Errors
    ///
    /// Underlying socket failures propagate as `Err`.  Per-peer
    /// problems (decrypt failures, malformed handshakes, replays,
    /// out-of-state datagrams, identity-binding rejection) surface as
    /// [`HostEvent::Rejected`] rather than `Err`, so a long-running
    /// loop survives misbehaving peers.  Neither a failed transport
    /// decrypt nor a failed handshake advance tears down the
    /// corresponding state: a single corrupted or spoofed datagram
    /// costs only itself.
    #[must_use]
    pub fn recv_one(self, ephemeral_seed: [u8; 32]) -> Io<Error, (Self, HostEvent)> {
        let Self {
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick,
        } = self;
        socket.recv().flat_map(move |((from, datagram), socket)| {
            dispatch_inbound(
                socket,
                identity,
                handshakes,
                established,
                capacity,
                tick,
                from,
                datagram,
                ephemeral_seed,
            )
        })
    }

    /// Drop any in-flight handshake or established connection for
    /// `addr`.  Returns the host with the entry removed; if `addr`
    /// was unknown, the host is returned unchanged.
    pub fn evict(self, addr: UdpAddr) -> Self {
        let Self {
            socket,
            identity,
            mut handshakes,
            mut established,
            capacity,
            tick,
        } = self;
        handshakes.remove(&addr);
        established.remove(&addr);
        Self {
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick,
        }
    }

    /// Evict every entry whose `last_activity` is more than
    /// `max_idle_ticks` ticks behind the host's current
    /// [`Self::tick`].  Returns the host plus the addresses that
    /// were swept.
    ///
    /// `max_idle_ticks` is in the host's monotonic-tick units, not
    /// wall-clock seconds; see [`Self::tick`] for the increment
    /// semantics.
    pub fn evict_idle(self, max_idle_ticks: u64) -> (Self, Vec<UdpAddr>) {
        let Self {
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick,
        } = self;
        let cutoff = tick.saturating_sub(max_idle_ticks);
        let (handshakes, evicted_h) = sweep_idle_handshakes(handshakes, cutoff);
        let (established, evicted_e) = sweep_idle_established(established, cutoff);
        let evicted: Vec<UdpAddr> = evicted_h.into_iter().chain(evicted_e).collect();
        (
            Self {
                socket,
                identity,
                handshakes,
                established,
                capacity,
                tick,
            },
            evicted,
        )
    }
}

/// Bundled output of [`prepare_dial`].
struct DialPrepared {
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
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
        capacity,
        tick,
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
            capacity,
            tick,
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
    capacity: Capacity,
    tick: u64,
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
        capacity,
        tick,
    } = host;
    let conn = established.remove(&addr).ok_or_else(|| Error::HostState {
        reason: format!("send: no established connection for {addr}"),
    })?;
    let (transport, datagram) = conn.transport.encrypt(plaintext)?;
    let next_conn = EstablishedConnection {
        transport,
        remote_static: conn.remote_static,
        remote_peer_id: conn.remote_peer_id,
        last_activity: conn.last_activity,
    };
    Ok(SendPrepared {
        socket,
        identity,
        handshakes,
        established,
        capacity,
        tick,
        conn: next_conn,
        datagram,
    })
}

/// Dispatch one received datagram to the right path:
/// established → decrypt; in-flight → advance; otherwise → maybe
/// start a responder.  Each sub-path returns a fully-rebuilt host.
#[allow(clippy::too_many_arguments)]
fn dispatch_inbound(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
    from: UdpAddr,
    datagram: Vec<u8>,
    ephemeral_seed: [u8; 32],
) -> Io<Error, (Host, HostEvent)> {
    if established.contains_key(&from) {
        decrypt_established(
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick,
            from,
            datagram,
        )
    } else if handshakes.contains_key(&from) {
        advance_in_flight(
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick,
            from,
            datagram,
        )
    } else {
        try_responder_msg1(
            socket,
            identity,
            handshakes,
            established,
            capacity,
            tick,
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
#[allow(clippy::too_many_arguments)]
fn decrypt_established(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    mut established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
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
        let EstablishedConnection {
            transport,
            remote_static,
            remote_peer_id,
            last_activity,
        } = conn;
        // `decrypt` returns the transport state unchanged on failure,
        // so the session survives corrupted, replayed, and spoofed
        // datagrams: an off-path attacker can no longer reset an
        // established connection with a single junk packet.  A
        // rejected datagram refreshes neither this entry's
        // `last_activity` NOR the host's monotonic `tick`, so a junk
        // flood from a spoofed source can neither keep an idle
        // connection alive nor advance the logical clock to
        // prematurely idle-evict other live-but-quiet connections.
        let (transport, outcome) = transport.decrypt(&datagram);
        let next_tick = tick.wrapping_add(1);
        let (entry_activity, host_tick, event) = outcome.map_or_else(
            |e| {
                (
                    last_activity,
                    tick,
                    HostEvent::Rejected {
                        addr: from,
                        reason: format!(
                            "transport decrypt failed: {e}; datagram dropped, connection kept"
                        ),
                    },
                )
            },
            |plaintext| {
                (
                    next_tick,
                    next_tick,
                    HostEvent::DatagramDelivered {
                        addr: from,
                        plaintext,
                    },
                )
            },
        );
        established.insert(
            from,
            EstablishedConnection {
                transport,
                remote_static,
                remote_peer_id,
                last_activity: entry_activity,
            },
        );
        (
            rebuild_host(
                socket,
                identity,
                handshakes,
                established,
                capacity,
                host_tick,
            ),
            event,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn advance_in_flight(
    socket: UdpTransport,
    identity: HostIdentity,
    mut handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
    from: UdpAddr,
    datagram: Vec<u8>,
) -> Io<Error, (Host, HostEvent)> {
    let removed = handshakes.remove(&from).ok_or_else(|| Error::HostState {
        reason: "in-flight entry vanished mid-dispatch".to_owned(),
    });
    Io::suspend(move || removed).flat_map(move |entry| {
        let InFlightHandshake {
            state,
            last_activity,
        } = entry;
        match state {
            HandshakeState::InitiatorAwaitingResponse { after_e, msg1 } => {
                if cookie::is_challenge(&datagram) {
                    answer_cookie_challenge(
                        socket,
                        identity,
                        handshakes,
                        established,
                        capacity,
                        tick,
                        from,
                        after_e,
                        msg1,
                        last_activity,
                        &datagram,
                    )
                } else {
                    initiator_consume_msg2(
                        socket,
                        identity,
                        handshakes,
                        established,
                        capacity,
                        tick,
                        from,
                        after_e,
                        msg1,
                        last_activity,
                        &datagram,
                    )
                }
            }
            HandshakeState::ResponderAwaitingFinalize(after_resp) => responder_consume_msg3(
                socket,
                identity,
                handshakes,
                established,
                capacity,
                tick,
                from,
                after_resp,
                last_activity,
                &datagram,
            ),
        }
    })
}

/// Answer a responder's stateless cookie challenge by re-sending the
/// retained `msg1` with the cookie MAC appended.  The handshake
/// state is unchanged (the cookie exchange is invisible to the Noise
/// transcript).
///
/// A cookie challenge is unauthenticated to the initiator, so a
/// spoofed one (from an attacker that knows the dialed peer's
/// address) can reach this path.  To deny that any leverage, neither
/// the entry's `last_activity` nor the host's `tick` advances here:
/// the handshake ages from its dial time regardless of cookie
/// chatter, so a spoofed-challenge flood can neither pin a stale
/// dial alive nor perturb the eviction clock.  A genuine handshake
/// still completes well within the idle window in its normal two
/// round trips.
#[allow(clippy::too_many_arguments)]
fn answer_cookie_challenge(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
    from: UdpAddr,
    after_e: libp2p_cat_noise::InitiatorAfterE,
    msg1: Vec<u8>,
    last_activity: u64,
    datagram: &[u8],
) -> Io<Error, (Host, HostEvent)> {
    let mac = datagram.get(1..).map(<[u8]>::to_vec).unwrap_or_default();
    let msg1_with_cookie: Vec<u8> = msg1.iter().copied().chain(mac).collect();
    socket.send(from, msg1_with_cookie).map(move |socket| {
        let entry = InFlightHandshake {
            state: HandshakeState::InitiatorAwaitingResponse { after_e, msg1 },
            last_activity,
        };
        let handshakes =
            insert_handshake_with_lru(handshakes, from, entry, capacity.max_handshakes_in_flight());
        (
            rebuild_host(socket, identity, handshakes, established, capacity, tick),
            HostEvent::HandshakeProgress { addr: from },
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn initiator_consume_msg2(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
    from: UdpAddr,
    after_e: libp2p_cat_noise::InitiatorAfterE,
    msg1: Vec<u8>,
    last_activity: u64,
    datagram: &[u8],
) -> Io<Error, (Host, HostEvent)> {
    // Retain a copy of the awaiting state: if the datagram fails to
    // advance the handshake (corrupted, spoofed, or out-of-state), the
    // entry is re-stored so a later genuine msg2 can still complete.
    // The failed attempt emitted nothing on the wire, so the retained
    // copy can never reuse a nonce.
    let retained = after_e.clone();
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
    let next_tick = tick.wrapping_add(1);
    match result {
        Ok((transport, msg3, remote_static, remote_peer_id)) => {
            socket.send(from, msg3).map(move |socket| {
                let conn = EstablishedConnection {
                    transport,
                    remote_static: remote_static.clone(),
                    remote_peer_id: remote_peer_id.clone(),
                    last_activity: next_tick,
                };
                let established = insert_established_with_lru(
                    established,
                    from,
                    conn,
                    capacity.max_established(),
                );
                (
                    rebuild_host(
                        socket,
                        identity,
                        handshakes,
                        established,
                        capacity,
                        next_tick,
                    ),
                    HostEvent::HandshakeComplete {
                        addr: from,
                        remote_static,
                        remote_peer_id,
                    },
                )
            })
        }
        Err(e) => {
            let entry = InFlightHandshake {
                state: HandshakeState::InitiatorAwaitingResponse {
                    after_e: retained,
                    msg1,
                },
                last_activity,
            };
            let handshakes = insert_handshake_with_lru(
                handshakes,
                from,
                entry,
                capacity.max_handshakes_in_flight(),
            );
            Io::pure((
                rebuild_host(
                    socket,
                    identity,
                    handshakes,
                    established,
                    capacity,
                    next_tick,
                ),
                HostEvent::Rejected {
                    addr: from,
                    reason: format!("initiator: failed to advance on msg2: {e}; handshake kept"),
                },
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn responder_consume_msg3(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
    from: UdpAddr,
    after_resp: libp2p_cat_noise::ResponderAfterResponse,
    last_activity: u64,
    datagram: &[u8],
) -> Io<Error, (Host, HostEvent)> {
    // Retain a copy of the awaiting state so a corrupted or spoofed
    // datagram cannot kill the in-flight handshake; see the matching
    // note in `initiator_consume_msg2`.
    let retained = after_resp.clone();
    let outcome =
        after_resp
            .read_s(datagram)
            .and_then(|(transport, remote_static, msg3_payload)| {
                verify_binding(&msg3_payload, &remote_static)
                    .map(|remote_peer_id| (transport, remote_static, remote_peer_id))
            });
    let next_tick = tick.wrapping_add(1);
    match outcome {
        Ok((transport, remote_static, remote_peer_id)) => {
            let conn = EstablishedConnection {
                transport,
                remote_static: remote_static.clone(),
                remote_peer_id: remote_peer_id.clone(),
                last_activity: next_tick,
            };
            let established =
                insert_established_with_lru(established, from, conn, capacity.max_established());
            Io::pure((
                rebuild_host(
                    socket,
                    identity,
                    handshakes,
                    established,
                    capacity,
                    next_tick,
                ),
                HostEvent::HandshakeComplete {
                    addr: from,
                    remote_static,
                    remote_peer_id,
                },
            ))
        }
        Err(e) => {
            let entry = InFlightHandshake {
                state: HandshakeState::ResponderAwaitingFinalize(retained),
                last_activity,
            };
            let handshakes = insert_handshake_with_lru(
                handshakes,
                from,
                entry,
                capacity.max_handshakes_in_flight(),
            );
            Io::pure((
                rebuild_host(
                    socket,
                    identity,
                    handshakes,
                    established,
                    capacity,
                    next_tick,
                ),
                HostEvent::Rejected {
                    addr: from,
                    reason: format!("responder: failed to finalize on msg3: {e}; handshake kept"),
                },
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn try_responder_msg1(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
    from: UdpAddr,
    datagram: &[u8],
    ephemeral_seed: [u8; 32],
) -> Io<Error, (Host, HostEvent)> {
    let next_tick = tick.wrapping_add(1);
    match () {
        // A bare msg1 proves nothing about its source address, so it
        // is answered with a stateless cookie challenge: no handshake
        // state, no Diffie-Hellman, and a reply barely larger than
        // the datagram that elicited it.  Spoofed-source floods cost
        // this host one small send each and cannot flush the
        // handshake table (see `crate::cookie`).
        () if datagram.len() == MESSAGE_1_LEN => {
            let reply = cookie::challenge(&identity.cookie_secret, from, datagram);
            socket.send(from, reply).map(move |socket| {
                (
                    rebuild_host(
                        socket,
                        identity,
                        handshakes,
                        established,
                        capacity,
                        next_tick,
                    ),
                    HostEvent::HandshakeProgress { addr: from },
                )
            })
        }
        // msg1 with an echoed cookie: verify statelessly, then spend
        // the DH work and handshake-table slot only on a source that
        // has proven it can receive at its claimed address.
        () if datagram.len() == cookie::MSG1_WITH_COOKIE_LEN => {
            let e_bytes = datagram.get(..MESSAGE_1_LEN).unwrap_or(&[]);
            let mac = datagram.get(MESSAGE_1_LEN..).unwrap_or(&[]);
            if cookie::verify(&identity.cookie_secret, from, e_bytes, mac) {
                respond_to_validated_msg1(
                    socket,
                    identity,
                    handshakes,
                    established,
                    capacity,
                    tick,
                    from,
                    e_bytes,
                    ephemeral_seed,
                )
            } else {
                Io::pure((
                    rebuild_host(
                        socket,
                        identity,
                        handshakes,
                        established,
                        capacity,
                        next_tick,
                    ),
                    HostEvent::Rejected {
                        addr: from,
                        reason: "msg1 cookie failed verification".to_owned(),
                    },
                ))
            }
        }
        () => Io::pure((
            rebuild_host(
                socket,
                identity,
                handshakes,
                established,
                capacity,
                next_tick,
            ),
            HostEvent::Rejected {
                addr: from,
                reason: format!(
                    "datagram from new peer is neither a {MESSAGE_1_LEN}-byte bare msg1 nor a {}-byte msg1-with-cookie: {} bytes",
                    cookie::MSG1_WITH_COOKIE_LEN,
                    datagram.len()
                ),
            },
        )),
    }
}

/// The original responder flow, reached only after the source
/// address passed cookie verification: read `e`, perform the DH
/// work, write `msg2`, and store the awaiting-finalize state.
#[allow(clippy::too_many_arguments)]
fn respond_to_validated_msg1(
    socket: UdpTransport,
    identity: HostIdentity,
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    capacity: Capacity,
    tick: u64,
    from: UdpAddr,
    e_bytes: &[u8],
    ephemeral_seed: [u8; 32],
) -> Io<Error, (Host, HostEvent)> {
    let next_tick = tick.wrapping_add(1);
    let responder = Responder::new(identity.static_keypair.clone());
    let trailer = identity.signed_static_key.to_bytes();
    match responder
        .read_e(e_bytes)
        .and_then(|after_e| after_e.write_response(ephemeral_seed, &trailer))
    {
        Ok((after_resp, msg2)) => socket.send(from, msg2).map(move |socket| {
            let entry = InFlightHandshake {
                state: HandshakeState::ResponderAwaitingFinalize(after_resp),
                last_activity: next_tick,
            };
            let handshakes = insert_handshake_with_lru(
                handshakes,
                from,
                entry,
                capacity.max_handshakes_in_flight(),
            );
            (
                rebuild_host(
                    socket,
                    identity,
                    handshakes,
                    established,
                    capacity,
                    next_tick,
                ),
                HostEvent::HandshakeProgress { addr: from },
            )
        }),
        Err(e) => Io::pure((
            rebuild_host(
                socket,
                identity,
                handshakes,
                established,
                capacity,
                next_tick,
            ),
            HostEvent::Rejected {
                addr: from,
                reason: format!("responder: failed to start handshake: {e}"),
            },
        )),
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
    capacity: Capacity,
    tick: u64,
) -> Host {
    Host {
        socket,
        identity,
        handshakes,
        established,
        capacity,
        tick,
    }
}

/// Insert `entry` at `addr` into a handshake map bounded by `cap`.
/// If `cap` is already reached and `addr` is not already present,
/// the LRU entry (lowest `last_activity`) is removed first.
fn insert_handshake_with_lru(
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    addr: UdpAddr,
    entry: InFlightHandshake,
    cap: usize,
) -> BTreeMap<UdpAddr, InFlightHandshake> {
    let mut map = handshakes;
    if !map.contains_key(&addr)
        && map.len() >= cap
        && let Some(victim) = lru_handshake_addr(&map)
    {
        map.remove(&victim);
    }
    map.insert(addr, entry);
    map
}

/// Insert `conn` at `addr` into an established map bounded by `cap`.
/// LRU eviction policy mirrors [`insert_handshake_with_lru`].
fn insert_established_with_lru(
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    addr: UdpAddr,
    conn: EstablishedConnection,
    cap: usize,
) -> BTreeMap<UdpAddr, EstablishedConnection> {
    let mut map = established;
    if !map.contains_key(&addr)
        && map.len() >= cap
        && let Some(victim) = lru_established_addr(&map)
    {
        map.remove(&victim);
    }
    map.insert(addr, conn);
    map
}

fn lru_handshake_addr(map: &BTreeMap<UdpAddr, InFlightHandshake>) -> Option<UdpAddr> {
    map.iter()
        .min_by_key(|(_, entry)| entry.last_activity)
        .map(|(addr, _)| *addr)
}

fn lru_established_addr(map: &BTreeMap<UdpAddr, EstablishedConnection>) -> Option<UdpAddr> {
    map.iter()
        .min_by_key(|(_, conn)| conn.last_activity)
        .map(|(addr, _)| *addr)
}

fn sweep_idle_handshakes(
    handshakes: BTreeMap<UdpAddr, InFlightHandshake>,
    cutoff: u64,
) -> (BTreeMap<UdpAddr, InFlightHandshake>, Vec<UdpAddr>) {
    let evicted: Vec<UdpAddr> = handshakes
        .iter()
        .filter(|(_, entry)| entry.last_activity < cutoff)
        .map(|(addr, _)| *addr)
        .collect();
    let kept: BTreeMap<UdpAddr, InFlightHandshake> = handshakes
        .into_iter()
        .filter(|(_, entry)| entry.last_activity >= cutoff)
        .collect();
    (kept, evicted)
}

fn sweep_idle_established(
    established: BTreeMap<UdpAddr, EstablishedConnection>,
    cutoff: u64,
) -> (BTreeMap<UdpAddr, EstablishedConnection>, Vec<UdpAddr>) {
    let evicted: Vec<UdpAddr> = established
        .iter()
        .filter(|(_, conn)| conn.last_activity < cutoff)
        .map(|(addr, _)| *addr)
        .collect();
    let kept: BTreeMap<UdpAddr, EstablishedConnection> = established
        .into_iter()
        .filter(|(_, conn)| conn.last_activity >= cutoff)
        .collect();
    (kept, evicted)
}
