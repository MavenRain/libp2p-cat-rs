//! End-to-end iterative `FIND_NODE` lookup over four loopback nodes.
//!
//! Topology before alice's lookup:
//!
//! ```text
//!   alice <-> bob <-> carol <-> dave
//! ```
//!
//! Each peer in this chain has shaken hands only with its immediate
//! neighbour(s).  Alice asks her local node to
//! `lookup_node(target = dave's NodeId)`.
//!
//! Pass 3's lookup queries only peers with an established connection,
//! so:
//!
//! 1. Round 1: alice queries bob (her only established peer).  Bob's
//!    response advertises both of his neighbours, so alice's
//!    shortlist gains carol.  Carol is not established with alice,
//!    so the lookup tags her [`LookupStatus::Skipped`].
//! 2. The lookup terminates.  Result includes bob and carol.  Dave
//!    is **not** in the result because alice has no way to reach
//!    anyone who shook hands with him.
//!
//! Pass 4 will fold transparent dialing into the lookup; until then
//! the integration test verifies the v1 semantics: alice learns
//! carol's address and could dial her in a follow-up.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;

use libp2p_cat_host::Host;
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_kad::{KadEvent, KademliaNode, LookupConfig};
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;

fn loopback_v4() -> UdpAddr {
    UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::HostState { reason: reason() })
    }
}

fn build_node(static_seed: u8, identity_seed: u8) -> Result<(KademliaNode, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let static_kp = StaticKeypair::from_private_bytes([static_seed; 32]);
    let identity = Ed25519Keypair::from_seed([identity_seed; 32]);
    let host = Host::new(socket, static_kp, &identity)?;
    Ok((KademliaNode::new(host, 20), addr))
}

fn expect_progress(ev: KadEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        KadEvent::HandshakeProgress { addr } if addr == expected_addr => Ok(()),
        other @ (KadEvent::HandshakeProgress { .. }
        | KadEvent::HandshakeComplete { .. }
        | KadEvent::PingRequestReceived { .. }
        | KadEvent::PingResponseReceived { .. }
        | KadEvent::FindNodeRequestReceived { .. }
        | KadEvent::FindNodeResponseReceived { .. }
        | KadEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_complete(ev: KadEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        KadEvent::HandshakeComplete { addr, .. } if addr == expected_addr => Ok(()),
        other @ (KadEvent::HandshakeProgress { .. }
        | KadEvent::HandshakeComplete { .. }
        | KadEvent::PingRequestReceived { .. }
        | KadEvent::PingResponseReceived { .. }
        | KadEvent::FindNodeRequestReceived { .. }
        | KadEvent::FindNodeResponseReceived { .. }
        | KadEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected_addr}), got {other:?}"),
        }),
    }
}

fn handshake_pair(
    initiator: KademliaNode,
    responder: KademliaNode,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(KademliaNode, KademliaNode), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    let (responder, ev_progress) = responder.recv_one(responder_seed).run()?;
    expect_progress(ev_progress, initiator_addr)?;
    let (initiator, ev_initiator) = initiator.recv_one([0; 32]).run()?;
    expect_complete(ev_initiator, responder_addr)?;
    let (responder, ev_responder) = responder.recv_one([0; 32]).run()?;
    expect_complete(ev_responder, initiator_addr)?;
    Ok((initiator, responder))
}

/// Spawn a daemon-style responder thread that drives
/// `node.recv_one` for an effectively-infinite number of iterations.
/// No join handle is returned: the thread blocks on the UDP socket
/// on its final iteration, and the OS reaps it when the test
/// process exits.  This keeps the test shape simple at the cost of a
/// single leaked thread per `lookup_walks_the_known_subgraph`
/// invocation.
///
/// `usize::MAX` is used as the iteration cap so a fold can thread
/// `node` linearly without a `let mut` binding; on a 64-bit host the
/// cap is `2^64`, comfortably beyond any test's actual recv count.
fn spawn_responder(node: KademliaNode) {
    thread::spawn(move || -> Result<(), Error> {
        let _final = (0..usize::MAX).try_fold(node, |acc, _| {
            let (next, _ev) = acc.recv_one([0; 32]).run()?;
            Ok::<_, Error>(next)
        })?;
        Ok(())
    });
}

#[test]
fn lookup_walks_the_known_subgraph() -> Result<(), Error> {
    let (alice, alice_addr) = build_node(0xA1, 0x11)?;
    let (bob, bob_addr) = build_node(0xB2, 0x22)?;
    let (carol, carol_addr) = build_node(0xC3, 0x33)?;
    let (dave, dave_addr) = build_node(0xD4, 0x44)?;

    let bob_node_id = *bob.node_id();
    let carol_node_id = *carol.node_id();
    let dave_node_id = *dave.node_id();

    // alice <-> bob
    let (alice, bob) = handshake_pair(alice, bob, alice_addr, bob_addr, [0xE1; 32], [0xE2; 32])?;
    // bob <-> carol
    let (bob, carol) = handshake_pair(bob, carol, bob_addr, carol_addr, [0xE3; 32], [0xE4; 32])?;
    // carol <-> dave
    let (_carol, _dave) =
        handshake_pair(carol, dave, carol_addr, dave_addr, [0xE5; 32], [0xE6; 32])?;

    // Sanity: alice knows only bob.
    check(alice.routing_table().contains(&bob_node_id), || {
        "alice should know bob".to_owned()
    })?;
    check(!alice.routing_table().contains(&carol_node_id), || {
        "alice should NOT yet know carol".to_owned()
    })?;
    check(!alice.routing_table().contains(&dave_node_id), || {
        "alice should NOT yet know dave".to_owned()
    })?;

    // Bob has both alice and carol in his table.  Park him in a
    // daemon thread so he answers alice's FIND_NODE_REQ while
    // alice's lookup is in flight.  The thread leaks; the OS reaps
    // it when the test process exits.
    spawn_responder(bob);

    // Alice runs her synchronous lookup for dave.  Round 1 queries
    // bob; bob responds with [alice, carol]; alice's table absorbs
    // carol.  No further queryable peer remains (carol is not
    // established), so the lookup terminates.
    let (alice, peers) = alice
        .lookup_node(dave_node_id, LookupConfig::default(), || [0u8; 32])
        .run()?;

    // The result should mention bob (queried directly) and carol
    // (advertised by bob).  Dave is *not* surfaced because no peer
    // alice can query has shaken hands with him directly.
    let mentions_bob = peers.iter().any(|(id, _)| *id == bob_node_id);
    let mentions_carol = peers
        .iter()
        .any(|(id, addr)| *id == carol_node_id && *addr == carol_addr);
    let mentions_dave = peers.iter().any(|(id, _)| *id == dave_node_id);
    check(mentions_bob, || {
        format!("lookup result should mention bob, got {peers:?}")
    })?;
    check(mentions_carol, || {
        format!("lookup result should mention carol with her address, got {peers:?}")
    })?;
    check(!mentions_dave, || {
        "pass 3 lookup should not surface dave (no path through alice)".to_owned()
    })?;
    check(alice.routing_table().contains(&carol_node_id), || {
        "alice's table should know carol after the lookup".to_owned()
    })
}
