//! [`MultiProtocolNode`]: a [`Host`] joined with
//! [`PubsubState<A>`] and a Kademlia [`RoutingTable`], dispatching
//! inbound plaintexts on a 1-byte kind-byte prefix and prepending
//! the same byte on outbound calls.

use std::sync::Arc;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_kad::{NodeId, RoutingTable};
use libp2p_cat_pubsub::{MuxEvent as PubsubMuxEvent, PubsubAuth, PubsubMux, PubsubState, Topic};
use libp2p_cat_types::{Error, PeerId, UdpAddr};

use rlnc_cat_rs::coding::piece::OriginalData;

use crate::event::MultiProtocolEvent;
use crate::{KIND_APP, KIND_KAD, KIND_PUBSUB, KIND_RENDEZVOUS};

/// 1-byte bare-datagram punch payload.  Mirrors the value used by
/// [`libp2p_cat_rendezvous`] in standalone mode; the precise byte
/// is irrelevant — receivers see a 1-byte datagram (not the
/// `MESSAGE_1_LEN`-byte handshake) and surface
/// [`HostEvent::Rejected`].
const PUNCH_BYTE: u8 = 0x00;

/// A [`Host`] joined with [`PubsubState<A>`] and a Kademlia
/// [`RoutingTable`], driving all three protocols over one socket.
#[must_use]
pub struct MultiProtocolNode<A: PubsubAuth>
where
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
}

impl<A> MultiProtocolNode<A>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    /// Build a fresh mux around an existing [`Host`], an
    /// authenticator for pubsub, and a Kademlia replication factor
    /// `k`.  The kad routing table's local [`NodeId`] is derived
    /// from `host.peer_id()`.
    pub fn new(host: Host, auth: Arc<A>, k: usize) -> Self {
        let self_node_id = NodeId::from_peer_id(host.peer_id());
        Self {
            host,
            pubsub_state: PubsubState::new(auth),
            kad_table: RoutingTable::new(self_node_id, k),
        }
    }

    /// Local libp2p-compatible [`PeerId`].
    pub fn peer_id(&self) -> &PeerId {
        self.host.peer_id()
    }

    /// Local Kademlia [`NodeId`].
    pub fn node_id(&self) -> &NodeId {
        self.kad_table.self_id()
    }

    /// Borrow the underlying [`Host`].
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Borrow the pubsub protocol state.
    pub fn pubsub_state(&self) -> &PubsubState<A> {
        &self.pubsub_state
    }

    /// Borrow the kad routing table.
    pub fn kad_table(&self) -> &RoutingTable {
        &self.kad_table
    }

    /// Local UDP address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot report the local
    /// address.
    pub fn local_addr(&self) -> Result<UdpAddr, Error> {
        self.host.local_addr()
    }

    /// Whether `addr` has a fully-established connection.
    #[must_use]
    pub fn is_established(&self, addr: UdpAddr) -> bool {
        self.host.is_established(addr)
    }

    /// Compute the commitment for a fresh pubsub generation.
    #[must_use]
    pub fn commit(&self, original: &OriginalData) -> A::Commitment {
        self.pubsub_state.commit(original)
    }

    /// Initiate a Noise XX handshake with the peer at `addr`.
    /// Pass-through to [`Host::dial`].
    ///
    /// # Errors
    ///
    /// Propagates [`Host::dial`] errors.
    #[must_use]
    pub fn dial(self, addr: UdpAddr, ephemeral_seed: [u8; 32]) -> Io<Error, Self> {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        host.dial(addr, ephemeral_seed).map(move |host| Self {
            host,
            pubsub_state,
            kad_table,
        })
    }

    /// Pre-register a topic for the **decoder** role.  Pass-through
    /// to [`PubsubState::register_topic`].
    pub fn register_topic(
        self,
        topic: Topic,
        piece_count: usize,
        piece_byte_len: usize,
        commitment: A::Commitment,
    ) -> Self {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        Self {
            host,
            pubsub_state: pubsub_state.register_topic(
                topic,
                piece_count,
                piece_byte_len,
                commitment,
            ),
            kad_table,
        }
    }

    /// Pre-register a topic for the **relay** role.  Pass-through
    /// to [`PubsubState::register_relay`].
    pub fn register_relay(
        self,
        topic: Topic,
        piece_count: usize,
        piece_byte_len: usize,
        commitment: A::Commitment,
    ) -> Self {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        Self {
            host,
            pubsub_state: pubsub_state.register_relay(
                topic,
                piece_count,
                piece_byte_len,
                commitment,
            ),
            kad_table,
        }
    }

    /// Send `payload` as a raw app-data plaintext to an established
    /// peer.  Delegates to [`PubsubMux::send_app`], which prepends
    /// [`KIND_APP`] (the same byte value the mux uses).
    ///
    /// # Errors
    ///
    /// Propagates [`PubsubMux::send_app`] errors.
    #[must_use]
    pub fn send_app(self, addr: UdpAddr, payload: &[u8]) -> Io<Error, Self> {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        let pubsub_mux = PubsubMux::join(host, pubsub_state);
        pubsub_mux.send_app(addr, payload).map(move |pubsub_mux| {
            let (host, pubsub_state) = pubsub_mux.split();
            Self {
                host,
                pubsub_state,
                kad_table,
            }
        })
    }

    /// Broadcast `data` on `topic` to every established peer as
    /// `num_pieces` RLNC-coded frames.  Delegates to
    /// [`PubsubMux::broadcast`], which prepends [`KIND_PUBSUB`].
    ///
    /// # Errors
    ///
    /// Propagates [`PubsubMux::broadcast`] errors.
    #[must_use]
    pub fn broadcast<F>(
        self,
        topic: Topic,
        data: OriginalData,
        num_pieces: usize,
        rng_factory: F,
    ) -> Io<Error, (Self, A::Commitment)>
    where
        F: Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static,
    {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        let pubsub_mux = PubsubMux::join(host, pubsub_state);
        pubsub_mux
            .broadcast(topic, data, num_pieces, rng_factory)
            .map(move |(pubsub_mux, commitment)| {
                let (host, pubsub_state) = pubsub_mux.split();
                (
                    Self {
                        host,
                        pubsub_state,
                        kad_table,
                    },
                    commitment,
                )
            })
    }

    /// Send a `PING_REQ` to an already-established peer.  The
    /// corresponding response will surface later as
    /// [`MultiProtocolEvent::KadPingResponseReceived`].
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `peer` is not established.
    /// - Noise / UDP errors propagate transparently.
    #[must_use]
    pub fn kad_ping(self, peer: UdpAddr) -> Io<Error, Self> {
        self.send_kad_frame(peer, libp2p_cat_kad::Frame::PingReq)
    }

    /// Send a `FIND_NODE_REQ` to an already-established peer asking
    /// for up to `k` peers closest to `target`.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `peer` is not established.
    /// - Noise / UDP errors propagate transparently.
    #[must_use]
    pub fn kad_find_node(self, peer: UdpAddr, target: NodeId) -> Io<Error, Self> {
        self.send_kad_frame(peer, libp2p_cat_kad::Frame::FindNodeReq { target })
    }

    /// Send an `OBSERVE_REQ` to a rendezvous server.  The matching
    /// `OBSERVE_RESP` will surface later as
    /// [`MultiProtocolEvent::ObserveResponseReceived`].
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `server` is not established.
    /// - Noise / UDP / encoding errors propagate transparently.
    #[must_use]
    pub fn send_observe_req(self, server: UdpAddr) -> Io<Error, Self> {
        self.send_rendezvous_frame(server, libp2p_cat_rendezvous::Frame::ObserveReq)
    }

    /// Send a `PUNCH_REQ` to a rendezvous server asking it to
    /// forward a punch request to `target`.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `server` is not established.
    /// - Noise / UDP / encoding errors propagate transparently.
    #[must_use]
    pub fn send_punch_req(self, server: UdpAddr, target: UdpAddr) -> Io<Error, Self> {
        self.send_rendezvous_frame(server, libp2p_cat_rendezvous::Frame::PunchReq { target })
    }

    fn send_kad_frame(self, peer: UdpAddr, frame: libp2p_cat_kad::Frame) -> Io<Error, Self> {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        Io::suspend(move || libp2p_cat_kad::encode(&frame)).flat_map(move |body| {
            send_with_kind(host, peer, KIND_KAD, body).map(move |host| Self {
                host,
                pubsub_state,
                kad_table,
            })
        })
    }

    fn send_rendezvous_frame(
        self,
        peer: UdpAddr,
        frame: libp2p_cat_rendezvous::Frame,
    ) -> Io<Error, Self> {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        Io::suspend(move || libp2p_cat_rendezvous::encode(&frame)).flat_map(move |body| {
            send_with_kind(host, peer, KIND_RENDEZVOUS, body).map(move |host| Self {
                host,
                pubsub_state,
                kad_table,
            })
        })
    }

    /// Receive one datagram and dispatch it.
    ///
    /// `ephemeral_seed` follows the [`Host::recv_one`] contract: it
    /// is consumed only when an inbound `msg1` triggers a fresh
    /// responder.
    ///
    /// `relay_rng` is consumed at most once — when a pubsub piece
    /// arrives for a relay-registered topic.  Pure
    /// decoder/sender/non-pubsub callers can pass
    /// [`libp2p_cat_pubsub::unused_relay_rng`].
    ///
    /// # Errors
    ///
    /// Underlying socket failures propagate as `Err`.  Per-peer
    /// problems surface as [`MultiProtocolEvent::Rejected`].
    #[must_use]
    pub fn recv_one<R>(
        self,
        ephemeral_seed: [u8; 32],
        relay_rng: R,
    ) -> Io<Error, (Self, MultiProtocolEvent)>
    where
        R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
    {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        host.recv_one(ephemeral_seed)
            .flat_map(move |(host, host_event)| {
                handle_host_event(host, pubsub_state, kad_table, host_event, relay_rng)
            })
    }
}

/// Build the `[kind, payload...]` plaintext.
fn prefix_kind(kind: u8, payload: Vec<u8>) -> Vec<u8> {
    core::iter::once(kind).chain(payload).collect()
}

/// Wrap `body` with `kind` and call [`Host::send`].
fn send_with_kind(host: Host, addr: UdpAddr, kind: u8, body: Vec<u8>) -> Io<Error, Host> {
    let plaintext = prefix_kind(kind, body);
    host.send(addr, plaintext)
}

/// Auto-insert a peer into `table` gated on the host's verified
/// `PeerId` for `addr`.  Returns the (possibly-updated) table.
fn auto_insert_kad(host: &Host, table: RoutingTable, addr: UdpAddr) -> RoutingTable {
    match host.remote_peer_id_of(addr) {
        Some(peer_id) => {
            let node_id = NodeId::from_peer_id(peer_id);
            table.insert(node_id, addr).0
        }
        None => table,
    }
}

fn handle_host_event<A, R>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    event: HostEvent,
    relay_rng: R,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
{
    match event {
        HostEvent::HandshakeProgress { addr } => Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::HandshakeProgress { addr },
        )),
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
            remote_peer_id,
        } => {
            let remote_node_id = NodeId::from_peer_id(&remote_peer_id);
            let (kad_table, _outcome) = kad_table.insert(remote_node_id, addr);
            Io::pure((
                MultiProtocolNode {
                    host,
                    pubsub_state,
                    kad_table,
                },
                MultiProtocolEvent::HandshakeComplete {
                    addr,
                    remote_static,
                    remote_peer_id,
                    remote_node_id,
                },
            ))
        }
        HostEvent::Rejected { addr, reason } => Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::Rejected { addr, reason },
        )),
        HostEvent::DatagramDelivered { addr, plaintext } => {
            dispatch_plaintext(host, pubsub_state, kad_table, addr, &plaintext, relay_rng)
        }
    }
}

fn dispatch_plaintext<A, R>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
    plaintext: &[u8],
    relay_rng: R,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
{
    let kind = plaintext.first().copied();
    match () {
        () if kind == Some(KIND_APP) || kind == Some(KIND_PUBSUB) => {
            dispatch_pubsub(host, pubsub_state, kad_table, addr, plaintext, relay_rng)
        }
        () if kind == Some(KIND_KAD) => {
            let body = plaintext.get(1..).unwrap_or(&[]);
            dispatch_kad(host, pubsub_state, kad_table, addr, body)
        }
        () if kind == Some(KIND_RENDEZVOUS) => {
            let body = plaintext.get(1..).unwrap_or(&[]);
            dispatch_rendezvous(host, pubsub_state, kad_table, addr, body)
        }
        () if kind.is_none() => Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::Rejected {
                addr,
                reason: "datagram plaintext was empty (no kind byte)".to_owned(),
            },
        )),
        () => {
            let unknown = kind.unwrap_or(0);
            Io::pure((
                MultiProtocolNode {
                    host,
                    pubsub_state,
                    kad_table,
                },
                MultiProtocolEvent::Rejected {
                    addr,
                    reason: format!("unknown plaintext kind byte 0x{unknown:02x}"),
                },
            ))
        }
    }
}

fn dispatch_pubsub<A, R>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
    plaintext: &[u8],
    relay_rng: R,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
{
    let pubsub_mux = PubsubMux::join(host, pubsub_state);
    pubsub_mux
        .process_plaintext(addr, plaintext, relay_rng)
        .map(move |(pubsub_mux, ev)| {
            let (host, pubsub_state) = pubsub_mux.split();
            let node = MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            };
            (node, lift_pubsub_event(ev))
        })
}

fn lift_pubsub_event(ev: PubsubMuxEvent) -> MultiProtocolEvent {
    match ev {
        PubsubMuxEvent::AppData { addr, bytes } => MultiProtocolEvent::AppData { addr, bytes },
        PubsubMuxEvent::PubsubAbsorbed { addr, topic } => {
            MultiProtocolEvent::PubsubAbsorbed { addr, topic }
        }
        PubsubMuxEvent::PubsubDelivered { addr, topic, data } => {
            MultiProtocolEvent::PubsubDelivered { addr, topic, data }
        }
        PubsubMuxEvent::PubsubRelayed {
            from,
            topic,
            fanout_count,
        } => MultiProtocolEvent::PubsubRelayed {
            from,
            topic,
            fanout_count,
        },
        PubsubMuxEvent::HandshakeProgress { addr } => MultiProtocolEvent::Rejected {
            addr,
            reason: "pubsub HandshakeProgress surfaced inside dispatch_pubsub (unexpected)"
                .to_owned(),
        },
        PubsubMuxEvent::HandshakeComplete { addr, .. } => MultiProtocolEvent::Rejected {
            addr,
            reason: "pubsub HandshakeComplete surfaced inside dispatch_pubsub (unexpected)"
                .to_owned(),
        },
        PubsubMuxEvent::Rejected { addr, reason } => MultiProtocolEvent::Rejected { addr, reason },
    }
}

fn dispatch_kad<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
    body: &[u8],
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    match libp2p_cat_kad::decode(body) {
        Err(
            e @ (Error::Io(_)
            | Error::InvalidProtocolId { .. }
            | Error::InvalidPeerId { .. }
            | Error::DatagramTooLarge { .. }
            | Error::NoiseDecrypt
            | Error::NoiseProtocol { .. }
            | Error::NoiseReplay { .. }
            | Error::RlncLayer { .. }
            | Error::PubsubProtocol { .. }
            | Error::HostState { .. }
            | Error::IdentityVerify { .. }),
        ) => Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::Rejected {
                addr,
                reason: format!("kad decode failed: {e}"),
            },
        )),
        Ok(frame) => {
            let kad_table = auto_insert_kad(&host, kad_table, addr);
            dispatch_kad_frame(host, pubsub_state, kad_table, addr, frame)
        }
    }
}

fn dispatch_kad_frame<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
    frame: libp2p_cat_kad::Frame,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    match frame {
        libp2p_cat_kad::Frame::PingReq => kad_auto_reply_ping(host, pubsub_state, kad_table, addr),
        libp2p_cat_kad::Frame::PingResp => Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::KadPingResponseReceived { from: addr },
        )),
        libp2p_cat_kad::Frame::FindNodeReq { target } => {
            kad_auto_reply_find_node(host, pubsub_state, kad_table, addr, target)
        }
        libp2p_cat_kad::Frame::FindNodeResp { peers } => {
            let kad_table = peers.iter().fold(kad_table, |acc, (id, peer_addr)| {
                if id == acc.self_id() {
                    acc
                } else {
                    acc.insert(*id, *peer_addr).0
                }
            });
            Io::pure((
                MultiProtocolNode {
                    host,
                    pubsub_state,
                    kad_table,
                },
                MultiProtocolEvent::KadFindNodeResponseReceived { from: addr, peers },
            ))
        }
    }
}

fn kad_auto_reply_ping<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    Io::suspend(move || libp2p_cat_kad::encode(&libp2p_cat_kad::Frame::PingResp)).flat_map(
        move |body| {
            send_with_kind(host, addr, KIND_KAD, body).map(move |host| {
                (
                    MultiProtocolNode {
                        host,
                        pubsub_state,
                        kad_table,
                    },
                    MultiProtocolEvent::KadPingRequestReceived { from: addr },
                )
            })
        },
    )
}

fn kad_auto_reply_find_node<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
    target: NodeId,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    let peers = kad_table.closest_to(&target, kad_table.k());
    let returned = peers.len();
    let frame = libp2p_cat_kad::Frame::FindNodeResp { peers };
    Io::suspend(move || libp2p_cat_kad::encode(&frame)).flat_map(move |body| {
        send_with_kind(host, addr, KIND_KAD, body).map(move |host| {
            (
                MultiProtocolNode {
                    host,
                    pubsub_state,
                    kad_table,
                },
                MultiProtocolEvent::KadFindNodeRequestReceived {
                    from: addr,
                    target,
                    returned,
                },
            )
        })
    })
}

fn dispatch_rendezvous<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
    body: &[u8],
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    match libp2p_cat_rendezvous::decode(body) {
        Err(
            e @ (Error::Io(_)
            | Error::InvalidProtocolId { .. }
            | Error::InvalidPeerId { .. }
            | Error::DatagramTooLarge { .. }
            | Error::NoiseDecrypt
            | Error::NoiseProtocol { .. }
            | Error::NoiseReplay { .. }
            | Error::RlncLayer { .. }
            | Error::PubsubProtocol { .. }
            | Error::HostState { .. }
            | Error::IdentityVerify { .. }),
        ) => Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::Rejected {
                addr,
                reason: format!("rendezvous decode failed: {e}"),
            },
        )),
        Ok(libp2p_cat_rendezvous::Frame::ObserveReq) => {
            rendezvous_auto_reply_observe(host, pubsub_state, kad_table, addr)
        }
        Ok(libp2p_cat_rendezvous::Frame::ObserveResp { observed }) => Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::ObserveResponseReceived {
                from: addr,
                observed,
            },
        )),
        Ok(libp2p_cat_rendezvous::Frame::PunchReq { target }) => {
            rendezvous_auto_forward_punch(host, pubsub_state, kad_table, addr, target)
        }
        Ok(libp2p_cat_rendezvous::Frame::PunchForward { initiator }) => {
            rendezvous_auto_send_punch(host, pubsub_state, kad_table, addr, initiator)
        }
    }
}

fn rendezvous_auto_reply_observe<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    addr: UdpAddr,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    let frame = libp2p_cat_rendezvous::Frame::ObserveResp { observed: addr };
    Io::suspend(move || libp2p_cat_rendezvous::encode(&frame)).flat_map(move |body| {
        send_with_kind(host, addr, KIND_RENDEZVOUS, body).map(move |host| {
            (
                MultiProtocolNode {
                    host,
                    pubsub_state,
                    kad_table,
                },
                MultiProtocolEvent::ObserveRequestReceived { from: addr },
            )
        })
    })
}

fn rendezvous_auto_forward_punch<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    from: UdpAddr,
    target: UdpAddr,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    if host.is_established(target) {
        let frame = libp2p_cat_rendezvous::Frame::PunchForward { initiator: from };
        Io::suspend(move || libp2p_cat_rendezvous::encode(&frame)).flat_map(move |body| {
            send_with_kind(host, target, KIND_RENDEZVOUS, body).map(move |host| {
                (
                    MultiProtocolNode {
                        host,
                        pubsub_state,
                        kad_table,
                    },
                    MultiProtocolEvent::PunchRequestReceived {
                        from,
                        target,
                        forwarded: true,
                    },
                )
            })
        })
    } else {
        Io::pure((
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::PunchRequestReceived {
                from,
                target,
                forwarded: false,
            },
        ))
    }
}

fn rendezvous_auto_send_punch<A>(
    host: Host,
    pubsub_state: PubsubState<A>,
    kad_table: RoutingTable,
    from: UdpAddr,
    initiator: UdpAddr,
) -> Io<Error, (MultiProtocolNode<A>, MultiProtocolEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    host.send_raw(initiator, vec![PUNCH_BYTE]).map(move |host| {
        (
            MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            },
            MultiProtocolEvent::PunchForwardReceived { from, initiator },
        )
    })
}
