//! Iterative `FIND_NODE` lookup driver.
//!
//! [`KademliaNode::lookup_node`] is *synchronous*: a single call
//! drains the entire lookup to completion before yielding control
//! back to the caller's event loop.  Other inbound RPCs (e.g. `PING`s
//! from unrelated peers) are still auto-answered by
//! [`KademliaNode::recv_one`] underneath; only the *return* from
//! `lookup_node` is delayed until the lookup converges.
//!
//! # Transparent dialing (pass 4)
//!
//! When the lookup picks a peer that has no established Host
//! connection, it transparently dials that peer (sends Noise XX
//! `msg1`).  The corresponding `HandshakeComplete` event is consumed
//! during the round's drain, the peer is transitioned back to
//! [`LookupStatus::Unqueried`], and the *next* round picks them up
//! and sends `FIND_NODE_REQ`.  This costs one extra round per dial
//! step but keeps the round structure simple: each peer is touched
//! at most twice (once to dial, once to query).
//!
//! Dial parallelism is bounded by `alpha` (default 3): each round
//! kicks off at most `alpha` outbound actions, each of which is
//! either a dial or a query, depending on whether the picked peer is
//! already established.

use std::collections::BTreeMap;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_types::{Error, UdpAddr};

use crate::distance::Distance;
use crate::event::KadEvent;
use crate::node::KademliaNode;
use crate::node_id::NodeId;

/// Tunables for [`KademliaNode::lookup_node`].
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct LookupConfig {
    /// Parallelism per round: how many peers to query simultaneously.
    /// The Kademlia paper's standard value is 3.
    pub alpha: usize,
    /// Desired result count (and shortlist depth).  Typically equal
    /// to the routing table's `k`.
    pub k: usize,
    /// Maximum number of query rounds before the lookup gives up.
    /// Caps the worst-case latency in the face of unresponsive peers.
    pub max_rounds: usize,
    /// Maximum number of [`KademliaNode::recv_one`] calls per round
    /// while draining responses.  Each `recv_one` call counts whether
    /// it surfaces a relevant `FIND_NODE` response, a transparent
    /// dial's `HandshakeComplete`, or unrelated traffic.
    pub max_recv_per_round: usize,
}

impl Default for LookupConfig {
    /// Standard Kademlia defaults: `alpha = 3`, `k = 20`, plus
    /// generous safety caps on rounds and per-round drains.
    fn default() -> Self {
        Self {
            alpha: 3,
            k: crate::bucket::DEFAULT_K,
            max_rounds: 32,
            max_recv_per_round: 24,
        }
    }
}

/// Per-peer state inside a [`Lookup`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum LookupStatus {
    /// Discovered but not yet sent any outbound action.  Eligible
    /// for both transparent dialing (if not yet established) and
    /// direct querying (if already established).
    Unqueried,
    /// Transparent dial in flight: `msg1` has been sent and the
    /// peer's `HandshakeComplete` event is pending.  Once the
    /// handshake finishes, the peer transitions back to
    /// [`LookupStatus::Unqueried`] so the next round picks them up
    /// and queries them.
    Dialing,
    /// `FIND_NODE_REQ` has been sent; awaiting response.
    InFlight,
    /// Response received and merged into the shortlist.
    Done,
    /// Skipped because the per-round drain budget expired before the
    /// peer's dial or response landed.
    Skipped,
}

/// One peer in the lookup shortlist.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct LookupEntry {
    /// Peer identifier.
    pub node_id: NodeId,
    /// Peer transport address.
    pub addr: UdpAddr,
    /// Current per-peer status within the lookup.
    pub status: LookupStatus,
}

/// In-progress lookup state machine.  Internal to
/// [`KademliaNode::lookup_node`]; exposed publicly only for tests
/// that want to inspect intermediate behaviour.
#[derive(Clone, Debug)]
#[must_use]
pub struct Lookup {
    /// The local node's own [`NodeId`].  Filtered out of any
    /// merged peer list so the lookup never tries to dial or query
    /// itself.
    self_id: NodeId,
    target: NodeId,
    config: LookupConfig,
    /// Peers seen for this lookup, keyed by distance to `target` so
    /// `BTreeMap`'s natural ordering produces "closest first."
    entries: BTreeMap<Distance, LookupEntry>,
    /// Peers we have sent `FIND_NODE_REQ` to and are awaiting
    /// `FIND_NODE_RESP` from.  `addr -> node_id`.
    pending_queries: BTreeMap<UdpAddr, NodeId>,
    /// Peers we have transparently dialed and are awaiting
    /// `HandshakeComplete` for.  `addr -> node_id`.
    pending_dials: BTreeMap<UdpAddr, NodeId>,
}

impl Lookup {
    /// Build a fresh lookup seeded from `initial_peers`, all marked
    /// [`LookupStatus::Unqueried`].  Entries whose `NodeId` equals
    /// `self_id` are dropped so the lookup never targets the local
    /// node.
    pub fn new(
        self_id: NodeId,
        target: NodeId,
        config: LookupConfig,
        initial_peers: &[(NodeId, UdpAddr)],
    ) -> Self {
        let entries: BTreeMap<Distance, LookupEntry> = initial_peers
            .iter()
            .filter(|(id, _)| *id != self_id)
            .map(|(id, addr)| {
                (
                    id.distance(&target),
                    LookupEntry {
                        node_id: *id,
                        addr: *addr,
                        status: LookupStatus::Unqueried,
                    },
                )
            })
            .collect();
        Self {
            self_id,
            target,
            config,
            entries,
            pending_queries: BTreeMap::new(),
            pending_dials: BTreeMap::new(),
        }
    }

    /// The target this lookup is converging on.
    pub fn target(&self) -> &NodeId {
        &self.target
    }

    /// Iterate over shortlist entries in ascending distance order.
    pub fn entries(&self) -> impl Iterator<Item = &LookupEntry> {
        self.entries.values()
    }

    /// Total shortlist size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the shortlist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The top-`k` entries, sorted by ascending distance to target.
    /// Ignores [`LookupStatus`]; callers receive whichever peers the
    /// lookup learned about, regardless of contact status.
    #[must_use]
    pub fn top_k_results(&self) -> Vec<(NodeId, UdpAddr)> {
        self.entries
            .values()
            .take(self.config.k)
            .map(|entry| (entry.node_id, entry.addr))
            .collect()
    }

    /// Lookup is done when no top-`k` peer is still
    /// [`LookupStatus::Unqueried`] and no outbound action (dial or
    /// query) is in flight.
    #[must_use]
    pub fn is_done(&self) -> bool {
        let no_pending = self.pending_queries.is_empty() && self.pending_dials.is_empty();
        let no_unqueried_in_top_k = self
            .entries
            .values()
            .take(self.config.k)
            .all(|entry| entry.status != LookupStatus::Unqueried);
        no_pending && no_unqueried_in_top_k
    }

    /// Pick up to `alpha` [`LookupStatus::Unqueried`] peers from the
    /// top-`k`, in ascending distance order.  The driver chooses
    /// dial-vs-query for each picked peer at the action step.
    #[must_use]
    pub fn pick_next_alpha(&self) -> Vec<(NodeId, UdpAddr)> {
        self.entries
            .values()
            .take(self.config.k)
            .filter(|entry| entry.status == LookupStatus::Unqueried)
            .take(self.config.alpha)
            .map(|entry| (entry.node_id, entry.addr))
            .collect()
    }

    /// Mark a peer as [`LookupStatus::InFlight`] and record the
    /// `(addr -> node_id)` mapping for later attribution.
    pub fn mark_in_flight(self, peer: NodeId, addr: UdpAddr) -> Self {
        let Self {
            self_id,
            target,
            config,
            mut entries,
            mut pending_queries,
            pending_dials,
        } = self;
        let dist = peer.distance(&target);
        if let Some(entry) = entries.get_mut(&dist) {
            entry.status = LookupStatus::InFlight;
        }
        pending_queries.insert(addr, peer);
        Self {
            self_id,
            target,
            config,
            entries,
            pending_queries,
            pending_dials,
        }
    }

    /// Mark a peer as [`LookupStatus::Dialing`] and record the
    /// `(addr -> node_id)` mapping for later attribution from the
    /// matching `HandshakeComplete` event.
    pub fn mark_dialing(self, peer: NodeId, addr: UdpAddr) -> Self {
        let Self {
            self_id,
            target,
            config,
            mut entries,
            pending_queries,
            mut pending_dials,
        } = self;
        let dist = peer.distance(&target);
        if let Some(entry) = entries.get_mut(&dist) {
            entry.status = LookupStatus::Dialing;
        }
        pending_dials.insert(addr, peer);
        Self {
            self_id,
            target,
            config,
            entries,
            pending_queries,
            pending_dials,
        }
    }

    /// Whether `addr` is currently in the pending-dials set.  Used
    /// by the drain step to attribute `HandshakeComplete` events.
    #[must_use]
    pub fn is_pending_dial(&self, addr: UdpAddr) -> bool {
        self.pending_dials.contains_key(&addr)
    }

    /// Record a [`KadEvent::HandshakeComplete`] for a peer we
    /// transparently dialed.  The peer transitions back to
    /// [`LookupStatus::Unqueried`] so the next round's
    /// [`Self::pick_next_alpha`] picks them up and queries them.
    pub fn complete_dial(self, addr: UdpAddr) -> Self {
        let Self {
            self_id,
            target,
            config,
            mut entries,
            pending_queries,
            mut pending_dials,
        } = self;
        let removed = pending_dials.remove(&addr);
        if let Some(node_id) = removed {
            let dist = node_id.distance(&target);
            if let Some(entry) = entries.get_mut(&dist) {
                entry.status = LookupStatus::Unqueried;
            }
        }
        Self {
            self_id,
            target,
            config,
            entries,
            pending_queries,
            pending_dials,
        }
    }

    /// Record a [`KadEvent::FindNodeResponseReceived`].  If `from`
    /// matches a pending query, the responder is marked
    /// [`LookupStatus::Done`] and any newly-advertised peers are
    /// merged into the shortlist as [`LookupStatus::Unqueried`].
    /// Returns the next state and a boolean indicating whether the
    /// response actually matched a pending query.
    pub fn record_response(self, from: UdpAddr, peers: &[(NodeId, UdpAddr)]) -> (Self, bool) {
        let Self {
            self_id,
            target,
            config,
            mut entries,
            mut pending_queries,
            pending_dials,
        } = self;
        let matched = pending_queries.remove(&from);
        let merged = peers.iter().filter(|(id, _)| *id != self_id).fold(
            entries,
            |mut acc, (id, peer_addr)| {
                let dist = id.distance(&target);
                acc.entry(dist).or_insert(LookupEntry {
                    node_id: *id,
                    addr: *peer_addr,
                    status: LookupStatus::Unqueried,
                });
                acc
            },
        );
        entries = merged;
        let was_pending = matched.is_some();
        if let Some(node_id) = matched {
            let dist = node_id.distance(&target);
            if let Some(entry) = entries.get_mut(&dist) {
                entry.status = LookupStatus::Done;
            }
        }
        (
            Self {
                self_id,
                target,
                config,
                entries,
                pending_queries,
                pending_dials,
            },
            was_pending,
        )
    }

    /// Mark every still-pending query as [`LookupStatus::Skipped`].
    /// Called when the per-round drain budget runs out; without
    /// this, an unresponsive peer would block the lookup forever.
    pub fn skip_pending_queries(self) -> Self {
        let Self {
            self_id,
            target,
            config,
            entries,
            pending_queries,
            pending_dials,
        } = self;
        let entries = pending_queries.values().fold(entries, |mut acc, node_id| {
            let dist = node_id.distance(&target);
            if let Some(entry) = acc.get_mut(&dist) {
                entry.status = LookupStatus::Skipped;
            }
            acc
        });
        Self {
            self_id,
            target,
            config,
            entries,
            pending_queries: BTreeMap::new(),
            pending_dials,
        }
    }

    /// Mark every still-pending dial as [`LookupStatus::Skipped`].
    /// Called when the per-round drain budget runs out before a
    /// dialed peer's `HandshakeComplete` arrived.
    pub fn skip_pending_dials(self) -> Self {
        let Self {
            self_id,
            target,
            config,
            entries,
            pending_queries,
            pending_dials,
        } = self;
        let entries = pending_dials.values().fold(entries, |mut acc, node_id| {
            let dist = node_id.distance(&target);
            if let Some(entry) = acc.get_mut(&dist) {
                entry.status = LookupStatus::Skipped;
            }
            acc
        });
        Self {
            self_id,
            target,
            config,
            entries,
            pending_queries,
            pending_dials: BTreeMap::new(),
        }
    }
}

/// One outbound action queued for a peer in the current round.
#[derive(Clone, Copy, Debug)]
enum RoundAction {
    /// Peer is already established; send `FIND_NODE_REQ`.
    Query { addr: UdpAddr },
    /// Peer is not established; transparently dial with the
    /// pre-allocated ephemeral seed.
    Dial { addr: UdpAddr, seed: [u8; 32] },
}

/// Drive a synchronous lookup to completion.
///
/// Each round: pick `alpha` `Unqueried` peers from the top-`k`,
/// dispatch each to either a dial or a query depending on whether
/// they are already established, drain responses (capped by
/// `max_recv_per_round`), then loop until the lookup is done or
/// `max_rounds` is exhausted.
///
/// # Errors
///
/// Underlying socket / Noise errors propagate transparently; per-peer
/// issues during drain are surfaced as [`KadEvent::Rejected`] events
/// and ignored by the lookup driver.
pub(crate) fn run_lookup<F>(
    node: KademliaNode,
    target: NodeId,
    config: LookupConfig,
    seed_factory: F,
) -> Io<Error, (KademliaNode, Vec<(NodeId, UdpAddr)>)>
where
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    let self_id = *node.node_id();
    let initial: Vec<(NodeId, UdpAddr)> = node.routing_table().closest_to(&target, config.k);
    let lookup = Lookup::new(self_id, target, config, &initial);
    drive_rounds(node, lookup, seed_factory, config.max_rounds)
        .map(|(node, lookup)| (node, lookup.top_k_results()))
}

fn drive_rounds<F>(
    node: KademliaNode,
    lookup: Lookup,
    seed_factory: F,
    rounds_left: usize,
) -> Io<Error, (KademliaNode, Lookup)>
where
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    if rounds_left == 0 || lookup.is_done() {
        Io::pure((node, lookup))
    } else {
        let to_act = lookup.pick_next_alpha();
        if to_act.is_empty() {
            Io::pure((node, lookup))
        } else {
            // Decide each picked peer's action up front (queries
            // need no seed; dials get a fresh ephemeral seed) so the
            // closure chain below can move owned values cleanly.
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
            let send_chain: Io<Error, KademliaNode> =
                actions.iter().fold(Io::pure(node), |acc, (_, action)| {
                    let action = *action;
                    acc.flat_map(move |n| match action {
                        RoundAction::Query { addr } => n.find_node(addr, target),
                        RoundAction::Dial { addr, seed } => n.dial(addr, seed),
                    })
                });
            let factory_for_drain = seed_factory.clone();
            let factory_for_recurse = seed_factory;
            send_chain.flat_map(move |node| {
                let budget = lookup_after_marks.config.max_recv_per_round;
                drain_responses(node, lookup_after_marks, factory_for_drain, budget).flat_map(
                    move |(node, lookup_after_drain)| {
                        let lookup = lookup_after_drain
                            .skip_pending_queries()
                            .skip_pending_dials();
                        drive_rounds(node, lookup, factory_for_recurse, rounds_left - 1)
                    },
                )
            })
        }
    }
}

fn drain_responses<F>(
    node: KademliaNode,
    lookup: Lookup,
    seed_factory: F,
    budget: usize,
) -> Io<Error, (KademliaNode, Lookup)>
where
    F: Fn() -> [u8; 32] + Clone + Send + Sync + 'static,
{
    if budget == 0 || (lookup.pending_queries.is_empty() && lookup.pending_dials.is_empty()) {
        Io::pure((node, lookup))
    } else {
        let seed = seed_factory();
        node.recv_one(seed).flat_map(move |(node, ev)| {
            let next_lookup = match ev {
                KadEvent::FindNodeResponseReceived { from, peers } => {
                    let (next, _matched) = lookup.record_response(from, &peers);
                    next
                }
                KadEvent::HandshakeComplete { addr, .. } if lookup.is_pending_dial(addr) => {
                    lookup.complete_dial(addr)
                }
                KadEvent::HandshakeProgress { .. }
                | KadEvent::HandshakeComplete { .. }
                | KadEvent::PingRequestReceived { .. }
                | KadEvent::PingResponseReceived { .. }
                | KadEvent::FindNodeRequestReceived { .. }
                | KadEvent::Rejected { .. } => lookup,
            };
            drain_responses(node, next_lookup, seed_factory, budget - 1)
        })
    }
}
