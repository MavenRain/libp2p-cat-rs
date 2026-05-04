//! Iterative `FIND_NODE` lookup driver.
//!
//! Pass 3 ships a *synchronous* lookup: a single
//! [`KademliaNode::lookup_node`] call drains the entire lookup to
//! completion before yielding control back to the caller's event
//! loop.  Other inbound RPCs (e.g. `PING`s from unrelated peers) are
//! still auto-answered by [`KademliaNode::recv_one`] underneath; only
//! the *return* from `lookup_node` is delayed until the lookup
//! converges.
//!
//! # Limitations
//!
//! Pass 3 only queries peers with an active established Host
//! connection.  Peers added to the shortlist but not yet established
//! are tagged [`LookupStatus::Skipped`] and never receive a
//! `FIND_NODE_REQ` from this lookup.  Newly-discovered peers from
//! responses are added to the shortlist (and may be returned in the
//! final result), but the lookup does not transparently dial them.
//!
//! Callers who want full iterative behaviour over previously-unknown
//! peers should:
//!
//! 1. Run [`KademliaNode::lookup_node`] to discover new peer
//!    addresses.
//! 2. [`KademliaNode::dial`] the new peers of interest.
//! 3. Run another lookup; the just-dialled peers are now eligible to
//!    be queried.
//!
//! Pass 4 will fold transparent dialing into the lookup itself.

use std::collections::BTreeMap;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::Host;
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
    /// it surfaces a relevant `FIND_NODE` response or unrelated
    /// traffic.
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
    /// Discovered but not yet sent a `FIND_NODE_REQ`.
    Unqueried,
    /// `FIND_NODE_REQ` has been sent; awaiting response.
    InFlight,
    /// Response received and merged into the shortlist.
    Done,
    /// Skipped because the peer has no established Host connection,
    /// or because the per-round drain budget expired before a response
    /// arrived.
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
    target: NodeId,
    config: LookupConfig,
    /// Peers seen for this lookup, keyed by distance to `target` so
    /// `BTreeMap`'s natural ordering produces "closest first."
    entries: BTreeMap<Distance, LookupEntry>,
    /// Maps `from` (the address we sent `FIND_NODE_REQ` to) to the
    /// peer's `NodeId`, so an inbound `FindNodeResponseReceived` can
    /// be attributed back to a shortlist entry.
    pending: BTreeMap<UdpAddr, NodeId>,
}

impl Lookup {
    /// Build a fresh lookup seeded from `initial_peers`, all marked
    /// [`LookupStatus::Unqueried`].
    pub fn new(target: NodeId, config: LookupConfig, initial_peers: &[(NodeId, UdpAddr)]) -> Self {
        let entries: BTreeMap<Distance, LookupEntry> = initial_peers
            .iter()
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
            target,
            config,
            entries,
            pending: BTreeMap::new(),
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
    /// [`LookupStatus::Unqueried`] and no query is in flight.
    #[must_use]
    pub fn is_done(&self) -> bool {
        let no_pending = self.pending.is_empty();
        let no_unqueried_in_top_k = self
            .entries
            .values()
            .take(self.config.k)
            .all(|entry| entry.status != LookupStatus::Unqueried);
        no_pending && no_unqueried_in_top_k
    }

    /// Pick up to `alpha` [`LookupStatus::Unqueried`] peers from the
    /// top-`k`, restricted to those with an active established Host
    /// connection.  Returns the picked peers in distance order.
    #[must_use]
    pub fn pick_next_alpha(&self, host: &Host) -> Vec<(NodeId, UdpAddr)> {
        self.entries
            .values()
            .take(self.config.k)
            .filter(|entry| entry.status == LookupStatus::Unqueried)
            .filter(|entry| host.is_established(entry.addr))
            .take(self.config.alpha)
            .map(|entry| (entry.node_id, entry.addr))
            .collect()
    }

    /// Mark every Unqueried peer in the top-`k` whose address is *not*
    /// established as [`LookupStatus::Skipped`].  Without this, the
    /// loop would spin: top-k contains an unqueried-non-established
    /// peer, `pick_next_alpha` returns nothing, and `is_done` says no.
    pub fn skip_unestablished_top_k(self, host: &Host) -> Self {
        let Self {
            target,
            config,
            entries,
            pending,
        } = self;
        let entries = entries
            .into_iter()
            .enumerate()
            .map(|(rank, (dist, entry))| {
                let in_top_k = rank < config.k;
                let unqueried = entry.status == LookupStatus::Unqueried;
                let unestablished = !host.is_established(entry.addr);
                if in_top_k && unqueried && unestablished {
                    (
                        dist,
                        LookupEntry {
                            status: LookupStatus::Skipped,
                            ..entry
                        },
                    )
                } else {
                    (dist, entry)
                }
            })
            .collect();
        Self {
            target,
            config,
            entries,
            pending,
        }
    }

    /// Mark a peer as [`LookupStatus::InFlight`] and record the
    /// `(addr -> node_id)` mapping for later attribution.
    pub fn mark_in_flight(self, peer: NodeId, addr: UdpAddr) -> Self {
        let Self {
            target,
            config,
            mut entries,
            mut pending,
        } = self;
        let dist = peer.distance(&target);
        if let Some(entry) = entries.get_mut(&dist) {
            entry.status = LookupStatus::InFlight;
        }
        pending.insert(addr, peer);
        Self {
            target,
            config,
            entries,
            pending,
        }
    }

    /// Record a [`KadEvent::FindNodeResponseReceived`].  If `from`
    /// matches a pending query, the responder is marked
    /// [`LookupStatus::Done`] and any newly-advertised peers are
    /// merged into the shortlist as
    /// [`LookupStatus::Unqueried`].  Returns the next state and a
    /// boolean indicating whether the response actually matched a
    /// pending query.
    pub fn record_response(self, from: UdpAddr, peers: &[(NodeId, UdpAddr)]) -> (Self, bool) {
        let Self {
            target,
            config,
            mut entries,
            mut pending,
        } = self;
        let matched = pending.remove(&from);
        let merged = peers.iter().fold(entries, |mut acc, (id, peer_addr)| {
            let dist = id.distance(&target);
            acc.entry(dist).or_insert(LookupEntry {
                node_id: *id,
                addr: *peer_addr,
                status: LookupStatus::Unqueried,
            });
            acc
        });
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
                target,
                config,
                entries,
                pending,
            },
            was_pending,
        )
    }

    /// Mark every still-pending peer as [`LookupStatus::Skipped`].
    /// Called when the per-round drain budget runs out; without
    /// this, an unresponsive peer would block the lookup forever.
    pub fn skip_pending(self) -> Self {
        let Self {
            target,
            config,
            entries,
            pending,
        } = self;
        let entries = pending.values().fold(entries, |mut acc, node_id| {
            let dist = node_id.distance(&target);
            if let Some(entry) = acc.get_mut(&dist) {
                entry.status = LookupStatus::Skipped;
            }
            acc
        });
        Self {
            target,
            config,
            entries,
            pending: BTreeMap::new(),
        }
    }
}

/// Drive a synchronous lookup to completion.
///
/// Each round: pick `alpha` `Unqueried` established peers from the
/// top-`k`, send `FIND_NODE_REQ` to each, drain responses (capped by
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
    let initial: Vec<(NodeId, UdpAddr)> = node.routing_table().closest_to(&target, config.k);
    let lookup = Lookup::new(target, config, &initial);
    let lookup = lookup.skip_unestablished_top_k(node.host());
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
        let to_query = lookup.pick_next_alpha(node.host());
        if to_query.is_empty() {
            Io::pure((node, lookup))
        } else {
            let lookup_with_pending = to_query
                .iter()
                .fold(lookup, |acc, (id, addr)| acc.mark_in_flight(*id, *addr));
            let send_queries: Io<Error, KademliaNode> =
                to_query.iter().fold(Io::pure(node), |acc, (_id, addr)| {
                    let target_for_closure = *lookup_with_pending.target();
                    let addr_for_closure = *addr;
                    acc.flat_map(move |n| n.find_node(addr_for_closure, target_for_closure))
                });
            let factory_for_drain = seed_factory.clone();
            let factory_for_recurse = seed_factory;
            send_queries.flat_map(move |node| {
                let budget = lookup_with_pending.config.max_recv_per_round;
                drain_responses(node, lookup_with_pending, factory_for_drain, budget).flat_map(
                    move |(node, lookup_after_drain)| {
                        let lookup = lookup_after_drain
                            .skip_pending()
                            .skip_unestablished_top_k(node.host());
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
    if budget == 0 || lookup.pending.is_empty() {
        Io::pure((node, lookup))
    } else {
        let seed = seed_factory();
        node.recv_one(seed).flat_map(move |(node, ev)| {
            let next_lookup = match ev {
                KadEvent::FindNodeResponseReceived { from, peers } => {
                    let (next, _matched) = lookup.record_response(from, &peers);
                    next
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
