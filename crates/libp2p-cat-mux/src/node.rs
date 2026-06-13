//! [`MultiProtocolNode`]: a [`Host`] joined with
//! [`PubsubState<A>`] and a Kademlia [`RoutingTable`], dispatching
//! inbound plaintexts on a 1-byte kind-byte prefix and prepending
//! the same byte on outbound calls.

use std::sync::Arc;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_kad::{KadEvent, KademliaNode, NodeId, RoutingTable};
use libp2p_cat_pubsub::{MuxEvent as PubsubMuxEvent, PubsubAuth, PubsubMux, PubsubState, Topic};
use libp2p_cat_rendezvous::{RendezvousEvent, RendezvousNode};
use libp2p_cat_types::{Error, PeerId, UdpAddr};

use rlnc_cat_rs::coding::piece::OriginalData;

use crate::event::MultiProtocolEvent;
use crate::{KIND_APP, KIND_KAD, KIND_PUBSUB, KIND_RENDEZVOUS, KIND_RPC};

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

    /// Drop the decoder registered for `topic`.  Pass-through to
    /// [`PubsubState::unregister_topic`].
    pub fn unregister_topic(self, topic: &Topic) -> Self {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        Self {
            host,
            pubsub_state: pubsub_state.unregister_topic(topic),
            kad_table,
        }
    }

    /// Drop the recoder registered for `topic`.  Pass-through to
    /// [`PubsubState::unregister_relay`].
    pub fn unregister_relay(self, topic: &Topic) -> Self {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        Self {
            host,
            pubsub_state: pubsub_state.unregister_relay(topic),
            kad_table,
        }
    }

    /// Sweep every decoder whose `last_activity` is more than
    /// `max_idle_ticks` ticks behind the current pubsub-state
    /// tick.  Returns the node plus the topics that were swept.
    pub fn evict_idle_topics(self, max_idle_ticks: u64) -> (Self, Vec<Topic>) {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        let (pubsub_state, evicted) = pubsub_state.evict_idle_topics(max_idle_ticks);
        (
            Self {
                host,
                pubsub_state,
                kad_table,
            },
            evicted,
        )
    }

    /// Sweep every recoder whose `last_activity` is more than
    /// `max_idle_ticks` ticks behind the current pubsub-state
    /// tick.  Returns the node plus the topics that were swept.
    pub fn evict_idle_relays(self, max_idle_ticks: u64) -> (Self, Vec<Topic>) {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        let (pubsub_state, evicted) = pubsub_state.evict_idle_relays(max_idle_ticks);
        (
            Self {
                host,
                pubsub_state,
                kad_table,
            },
            evicted,
        )
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

    /// Run an iterative `FIND_NODE` lookup for `target` to
    /// completion, returning up to `config.k` peers closest to the
    /// target.  Mirrors [`KademliaNode::lookup_node`] but drains
    /// inbound traffic through [`Self::recv_one`], so non-kad
    /// frames (`KIND_APP`, `KIND_PUBSUB`, `KIND_RENDEZVOUS`)
    /// arriving during the lookup window still land in their
    /// respective protocols' state.  The corresponding events are
    /// silently consumed by the lookup driver — only the lookup
    /// result is surfaced — so callers should expect to *see* only
    /// kad-related state changes mid-lookup.
    ///
    /// `seed_factory` is called once per outbound transparent dial
    /// and once per drain step; the standalone seed contract
    /// applies.
    ///
    /// **Limitation**: relay-registered pubsub topics are not
    /// supported during a lookup — the drain uses
    /// [`libp2p_cat_pubsub::unused_relay_rng`], which errors if a
    /// piece arrives for a recoder.  Callers that have registered
    /// relay topics with [`Self::register_relay`] should not call
    /// `lookup_node` until they un-register, or the lookup may
    /// surface a relay-rng error.
    ///
    /// # Errors
    ///
    /// Underlying socket / Noise errors propagate transparently;
    /// per-peer issues during drain are silently absorbed and the
    /// lookup proceeds.
    #[must_use]
    pub fn lookup_node<F>(
        self,
        target: NodeId,
        config: libp2p_cat_kad::LookupConfig,
        seed_factory: F,
    ) -> Io<Error, (Self, Vec<(NodeId, UdpAddr)>)>
    where
        F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
    {
        let self_id = *self.node_id();
        let initial = self.kad_table.closest_to(&target, config.k);
        let lookup = libp2p_cat_kad::Lookup::new(self_id, target, config, &initial);
        drive_lookup_rounds(self, lookup, seed_factory, config.max_rounds)
            .map(|(node, lookup)| (node, lookup.top_k_results()))
    }

    /// Send a serialized RPC envelope (the bytes produced by
    /// `serde_json::to_vec` over a [`tarpc_cat::protocol::Envelope`])
    /// to an established peer.  Prepends [`KIND_RPC`].  The matching
    /// reply (if this is a request) will surface later as
    /// [`MultiProtocolEvent::RpcDatagram`] with the response body.
    ///
    /// # Errors
    ///
    /// - [`Error::HostState`] if `peer` is not established.
    /// - Noise / UDP errors propagate transparently.
    ///
    /// [`tarpc_cat::protocol::Envelope`]: https://docs.rs/tarpc-cat
    #[must_use]
    pub fn send_rpc(self, peer: UdpAddr, body: &[u8]) -> Io<Error, Self> {
        let Self {
            host,
            pubsub_state,
            kad_table,
        } = self;
        let plaintext = prefix_kind(KIND_RPC, body.to_vec());
        host.send(peer, plaintext).map(move |host| Self {
            host,
            pubsub_state,
            kad_table,
        })
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

/// Wrap closure used by the kad / rendezvous protocol crates'
/// `process_plaintext_with_wrap` paths to share their auto-reply
/// frame bytes with the mux's outer kind-byte envelope.
fn kind_wrap(kind: u8) -> impl FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static {
    move |bytes| core::iter::once(kind).chain(bytes).collect()
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
        () if kind == Some(KIND_RPC) => {
            let body: Vec<u8> = plaintext.get(1..).unwrap_or(&[]).to_vec();
            Io::pure((
                MultiProtocolNode {
                    host,
                    pubsub_state,
                    kad_table,
                },
                MultiProtocolEvent::RpcDatagram { peer: addr, body },
            ))
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
        PubsubMuxEvent::PubsubRedundant { addr, topic } => {
            MultiProtocolEvent::PubsubRedundant { addr, topic }
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
    let kad_node = KademliaNode::join(host, kad_table);
    kad_node
        .process_plaintext_with_wrap(addr, body, kind_wrap(KIND_KAD))
        .map(move |(kad_node, ev)| {
            let (host, kad_table) = kad_node.split();
            let node = MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            };
            (node, lift_kad_event(ev))
        })
}

fn lift_kad_event(ev: KadEvent) -> MultiProtocolEvent {
    match ev {
        KadEvent::PingRequestReceived { from } => {
            MultiProtocolEvent::KadPingRequestReceived { from }
        }
        KadEvent::PingResponseReceived { from } => {
            MultiProtocolEvent::KadPingResponseReceived { from }
        }
        KadEvent::FindNodeRequestReceived {
            from,
            target,
            returned,
        } => MultiProtocolEvent::KadFindNodeRequestReceived {
            from,
            target,
            returned,
        },
        KadEvent::FindNodeResponseReceived { from, peers } => {
            MultiProtocolEvent::KadFindNodeResponseReceived { from, peers }
        }
        KadEvent::Rejected { addr, reason } => MultiProtocolEvent::Rejected { addr, reason },
        KadEvent::HandshakeProgress { addr } => MultiProtocolEvent::Rejected {
            addr,
            reason: "kad HandshakeProgress surfaced inside dispatch_kad (unreachable)".to_owned(),
        },
        KadEvent::HandshakeComplete { addr, .. } => MultiProtocolEvent::Rejected {
            addr,
            reason: "kad HandshakeComplete surfaced inside dispatch_kad (unreachable)".to_owned(),
        },
    }
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
    let rendezvous_node = RendezvousNode::new(host);
    rendezvous_node
        .process_plaintext_with_wrap(addr, body, kind_wrap(KIND_RENDEZVOUS))
        .map(move |(rendezvous_node, ev)| {
            let (host, ()) = rendezvous_node.split();
            let node = MultiProtocolNode {
                host,
                pubsub_state,
                kad_table,
            };
            (node, lift_rendezvous_event(ev))
        })
}

fn lift_rendezvous_event(ev: RendezvousEvent) -> MultiProtocolEvent {
    match ev {
        RendezvousEvent::ObserveRequestReceived { from } => {
            MultiProtocolEvent::ObserveRequestReceived { from }
        }
        RendezvousEvent::ObserveResponseReceived { from, observed } => {
            MultiProtocolEvent::ObserveResponseReceived { from, observed }
        }
        RendezvousEvent::PunchRequestReceived {
            from,
            target,
            forwarded,
        } => MultiProtocolEvent::PunchRequestReceived {
            from,
            target,
            forwarded,
        },
        RendezvousEvent::PunchForwardReceived { from, initiator } => {
            MultiProtocolEvent::PunchForwardReceived { from, initiator }
        }
        RendezvousEvent::RelayForwarded {
            from,
            target,
            forwarded,
            payload_len,
        } => MultiProtocolEvent::RelayForwarded {
            from,
            target,
            forwarded,
            payload_len,
        },
        RendezvousEvent::RelayReceived {
            from,
            originator,
            payload,
        } => MultiProtocolEvent::RelayReceived {
            from,
            originator,
            payload,
        },
        RendezvousEvent::RelayFailed { from, peer, reason } => {
            MultiProtocolEvent::RelayFailed { from, peer, reason }
        }
        RendezvousEvent::Rejected { addr, reason } => MultiProtocolEvent::Rejected { addr, reason },
        RendezvousEvent::HandshakeProgress { addr } => MultiProtocolEvent::Rejected {
            addr,
            reason:
                "rendezvous HandshakeProgress surfaced inside dispatch_rendezvous (unreachable)"
                    .to_owned(),
        },
        RendezvousEvent::HandshakeComplete { addr, .. } => MultiProtocolEvent::Rejected {
            addr,
            reason:
                "rendezvous HandshakeComplete surfaced inside dispatch_rendezvous (unreachable)"
                    .to_owned(),
        },
    }
}

/// One outbound action queued for a peer in the current lookup
/// round.  Mirrors the private `RoundAction` in
/// [`libp2p_cat_kad::lookup`]; the multi-protocol mux re-implements
/// the driver because its outbound `find_node` send wraps the kad
/// frame in the mux's `KIND_KAD` envelope (delegated to
/// [`MultiProtocolNode::kad_find_node`]) and its drain consumes
/// [`MultiProtocolEvent`] rather than [`KadEvent`].
#[derive(Clone, Copy, Debug)]
enum RoundAction {
    /// Peer is already established; send `FIND_NODE_REQ` via the
    /// mux's kad-find-node path.
    Query { addr: UdpAddr },
    /// Peer is not established; transparently dial with the
    /// pre-allocated ephemeral seed.
    Dial { addr: UdpAddr, seed: [u8; 32] },
}

fn drive_lookup_rounds<A, F>(
    node: MultiProtocolNode<A>,
    lookup: libp2p_cat_kad::Lookup,
    seed_factory: F,
    rounds_left: usize,
) -> Io<Error, (MultiProtocolNode<A>, libp2p_cat_kad::Lookup)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    match () {
        () if rounds_left == 0 || lookup.is_done() => Io::pure((node, lookup)),
        () => drive_lookup_round_pick(node, lookup, seed_factory, rounds_left),
    }
}

fn drive_lookup_round_pick<A, F>(
    node: MultiProtocolNode<A>,
    lookup: libp2p_cat_kad::Lookup,
    seed_factory: F,
    rounds_left: usize,
) -> Io<Error, (MultiProtocolNode<A>, libp2p_cat_kad::Lookup)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    let to_act = lookup.pick_next_alpha();
    match () {
        () if to_act.is_empty() => Io::pure((node, lookup)),
        () => {
            // Decide each picked peer's action up front (queries
            // need no seed; dials get a fresh ephemeral seed) so
            // the closure chain below can move owned values cleanly.
            let actions: Vec<(NodeId, RoundAction)> = to_act
                .iter()
                .map(|(id, addr)| {
                    let action = if node.host().is_established(*addr) {
                        RoundAction::Query { addr: *addr }
                    } else {
                        RoundAction::Dial {
                            addr: *addr,
                            seed: seed_factory(),
                        }
                    };
                    (*id, action)
                })
                .collect();
            let lookup_after_marks =
                actions
                    .iter()
                    .fold(lookup, |acc, (id, action)| match action {
                        RoundAction::Query { addr } => acc.mark_in_flight(*id, *addr),
                        RoundAction::Dial { addr, .. } => acc.mark_dialing(*id, *addr),
                    });
            let target = *lookup_after_marks.target();
            let send_chain: Io<Error, MultiProtocolNode<A>> =
                actions.iter().fold(Io::pure(node), |acc, (_, action)| {
                    let action = *action;
                    acc.flat_map(move |n| match action {
                        RoundAction::Query { addr } => n.kad_find_node(addr, target),
                        RoundAction::Dial { addr, seed } => n.dial(addr, seed),
                    })
                });
            let factory_for_drain = seed_factory.clone();
            let factory_for_recurse = seed_factory;
            send_chain.flat_map(move |node| {
                let budget = lookup_after_marks.config().max_recv_per_round;
                drain_lookup_responses(node, lookup_after_marks, factory_for_drain, budget)
                    .flat_map(move |(node, lookup_after_drain)| {
                        let lookup = lookup_after_drain
                            .skip_pending_queries()
                            .skip_pending_dials();
                        drive_lookup_rounds(node, lookup, factory_for_recurse, rounds_left - 1)
                    })
            })
        }
    }
}

fn drain_lookup_responses<A, F>(
    node: MultiProtocolNode<A>,
    lookup: libp2p_cat_kad::Lookup,
    seed_factory: F,
    budget: usize,
) -> Io<Error, (MultiProtocolNode<A>, libp2p_cat_kad::Lookup)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    match () {
        () if budget == 0 || !lookup.has_pending() => Io::pure((node, lookup)),
        () => {
            let seed = seed_factory();
            node.recv_one(seed, libp2p_cat_pubsub::unused_relay_rng())
                .flat_map(move |(node, ev)| {
                    let next_lookup = absorb_lookup_event(lookup, ev);
                    drain_lookup_responses(node, next_lookup, seed_factory, budget - 1)
                })
        }
    }
}

/// Update `lookup` based on a single inbound
/// [`MultiProtocolEvent`].  Lookup-relevant variants
/// (`KadFindNodeResponseReceived`, `HandshakeComplete` for a peer
/// with a pending dial) advance the state machine; everything else
/// is silently absorbed.
fn absorb_lookup_event(
    lookup: libp2p_cat_kad::Lookup,
    ev: MultiProtocolEvent,
) -> libp2p_cat_kad::Lookup {
    match ev {
        MultiProtocolEvent::KadFindNodeResponseReceived { from, peers } => {
            let (next, _matched) = lookup.record_response(from, &peers);
            next
        }
        MultiProtocolEvent::HandshakeComplete { addr, .. } if lookup.is_pending_dial(addr) => {
            lookup.complete_dial(addr)
        }
        MultiProtocolEvent::HandshakeProgress { .. }
        | MultiProtocolEvent::HandshakeComplete { .. }
        | MultiProtocolEvent::AppData { .. }
        | MultiProtocolEvent::PubsubAbsorbed { .. }
        | MultiProtocolEvent::PubsubDelivered { .. }
        | MultiProtocolEvent::PubsubRelayed { .. }
        | MultiProtocolEvent::PubsubRedundant { .. }
        | MultiProtocolEvent::KadPingRequestReceived { .. }
        | MultiProtocolEvent::KadPingResponseReceived { .. }
        | MultiProtocolEvent::KadFindNodeRequestReceived { .. }
        | MultiProtocolEvent::ObserveRequestReceived { .. }
        | MultiProtocolEvent::ObserveResponseReceived { .. }
        | MultiProtocolEvent::PunchRequestReceived { .. }
        | MultiProtocolEvent::PunchForwardReceived { .. }
        | MultiProtocolEvent::RelayForwarded { .. }
        | MultiProtocolEvent::RelayReceived { .. }
        | MultiProtocolEvent::RelayFailed { .. }
        | MultiProtocolEvent::RpcDatagram { .. }
        | MultiProtocolEvent::Rejected { .. } => lookup,
    }
}
