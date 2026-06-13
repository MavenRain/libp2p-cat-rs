//! End-to-end `FIND_NODE` between three [`KademliaNode`]s over real
//! loopback UDP.
//!
//! Topology: Bob is in the middle.  Bob handshakes with Alice and
//! Carol.  Bob's routing table now contains both peers.  Alice asks
//! Bob `FIND_NODE(target = Carol's NodeId)`; Bob's auto-reply
//! returns Carol (and Alice) and Alice learns Carol's address by
//! side-effect of `recv_one`.  Carol does not directly participate
//! in the RPC flow.

use std::net::{Ipv4Addr, SocketAddrV4};

use libp2p_cat_host::Host;
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_kad::{KadEvent, KademliaNode, NodeId};
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
    let host = Host::new(socket, static_kp, &identity, [0x4A; 32])?;
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

fn expect_complete(ev: KadEvent, expected_addr: UdpAddr) -> Result<NodeId, Error> {
    match ev {
        KadEvent::HandshakeComplete {
            addr,
            remote_node_id,
            ..
        } if addr == expected_addr => Ok(remote_node_id),
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

/// Drive a Noise XX handshake to completion between two
/// [`KademliaNode`]s where `initiator` calls `dial` first.
fn handshake_pair(
    initiator: KademliaNode,
    responder: KademliaNode,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(KademliaNode, KademliaNode), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    // step1: responder answers bare msg1 with a cookie challenge (no state created).
    let (responder, ev_cookie_challenge) = responder.recv_one(responder_seed).run()?;
    expect_progress(ev_cookie_challenge, initiator_addr)?;
    // step2: initiator echoes the cookie (re-sends msg1||cookie).
    let (initiator, ev_cookie_echo) = initiator.recv_one([0; 32]).run()?;
    expect_progress(ev_cookie_echo, responder_addr)?;
    // step3: responder validates the cookie, consumes msg1, writes msg2.
    let (responder, ev_progress) = responder.recv_one(responder_seed).run()?;
    expect_progress(ev_progress, initiator_addr)?;
    // step4: initiator consumes msg2, writes msg3.
    let (initiator, ev_initiator_complete) = initiator.recv_one([0; 32]).run()?;
    let _ = expect_complete(ev_initiator_complete, responder_addr)?;
    // step5: responder consumes msg3.
    let (responder, ev_responder_complete) = responder.recv_one([0; 32]).run()?;
    let _ = expect_complete(ev_responder_complete, initiator_addr)?;
    Ok((initiator, responder))
}

#[test]
fn find_node_returns_peers_from_responders_routing_table() -> Result<(), Error> {
    let (alice, alice_addr) = build_node(0xA1, 0x11)?;
    let (bob, bob_addr) = build_node(0xB2, 0x22)?;
    let (carol, carol_addr) = build_node(0xC3, 0x33)?;

    let carol_node_id = *carol.node_id();
    let alice_node_id = *alice.node_id();

    // 1. Alice ↔ Bob handshake (Alice initiates).
    let (alice, bob) = handshake_pair(alice, bob, alice_addr, bob_addr, [0xE1; 32], [0xE2; 32])?;

    // 2. Bob ↔ Carol handshake (Bob initiates).
    let (bob, carol) = handshake_pair(bob, carol, bob_addr, carol_addr, [0xE3; 32], [0xE4; 32])?;
    let _carol_unused = carol; // Carol does not participate in the FIND_NODE flow.

    // Sanity: bob's table should now hold both alice and carol.
    check(bob.routing_table().contains(&alice_node_id), || {
        "bob's table should contain alice".to_owned()
    })?;
    check(bob.routing_table().contains(&carol_node_id), || {
        "bob's table should contain carol".to_owned()
    })?;
    check(!alice.routing_table().contains(&carol_node_id), || {
        "alice's table should NOT yet contain carol (she has not heard of carol)".to_owned()
    })?;

    // 3. Alice asks Bob FIND_NODE(target = carol_node_id).
    let alice = alice.find_node(bob_addr, carol_node_id).run()?;

    // 4. Bob receives FIND_NODE_REQ, auto-replies, surfaces
    //    FindNodeRequestReceived.
    let (_bob, ev_bob) = bob.recv_one([0; 32]).run()?;
    let returned = match ev_bob {
        KadEvent::FindNodeRequestReceived {
            from,
            target,
            returned,
        } if from == alice_addr && target == carol_node_id => Ok(returned),
        other @ (KadEvent::HandshakeProgress { .. }
        | KadEvent::HandshakeComplete { .. }
        | KadEvent::PingRequestReceived { .. }
        | KadEvent::PingResponseReceived { .. }
        | KadEvent::FindNodeRequestReceived { .. }
        | KadEvent::FindNodeResponseReceived { .. }
        | KadEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!(
                "bob: expected FindNodeRequestReceived(from={alice_addr}), got {other:?}"
            ),
        }),
    }?;
    check(returned == 2, || {
        format!("bob should have returned 2 peers (alice + carol), got {returned}")
    })?;

    // 5. Alice receives FIND_NODE_RESP and her table absorbs carol.
    let (alice, ev_alice) = alice.recv_one([0; 32]).run()?;
    let peers = match ev_alice {
        KadEvent::FindNodeResponseReceived { from, peers } if from == bob_addr => Ok(peers),
        other @ (KadEvent::HandshakeProgress { .. }
        | KadEvent::HandshakeComplete { .. }
        | KadEvent::PingRequestReceived { .. }
        | KadEvent::PingResponseReceived { .. }
        | KadEvent::FindNodeRequestReceived { .. }
        | KadEvent::FindNodeResponseReceived { .. }
        | KadEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!(
                "alice: expected FindNodeResponseReceived(from={bob_addr}), got {other:?}"
            ),
        }),
    }?;
    check(peers.len() == 2, || {
        format!("response should hold 2 peers, got {}", peers.len())
    })?;
    let mentions_carol = peers
        .iter()
        .any(|(id, addr)| *id == carol_node_id && *addr == carol_addr);
    check(mentions_carol, || {
        "response should mention carol with her actual address".to_owned()
    })?;
    check(alice.routing_table().contains(&carol_node_id), || {
        "alice's table should now contain carol after observing bob's response".to_owned()
    })
}
