//! End-to-end `PING` between two [`KademliaNode`]s over real
//! loopback UDP.
//!
//! Alice dials Bob, both sides drive their handshake to completion,
//! then Alice issues a `PING`.  Bob's `recv_one` consumes the
//! `PING_REQ`, auto-replies with `PING_RESP`, and surfaces
//! [`KadEvent::PingRequestReceived`].  Alice's next `recv_one`
//! consumes the `PING_RESP` and surfaces
//! [`KadEvent::PingResponseReceived`].  Both sides end up with the
//! other in their routing tables.

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

fn handshake_pair(
    initiator: KademliaNode,
    responder: KademliaNode,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(KademliaNode, KademliaNode, NodeId, NodeId), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    let (responder, ev_progress) = responder.recv_one(responder_seed).run()?;
    expect_progress(ev_progress, initiator_addr)?;
    let (initiator, ev_initiator_complete) = initiator.recv_one([0; 32]).run()?;
    let initiator_observed_responder_id = expect_complete(ev_initiator_complete, responder_addr)?;
    let (responder, ev_responder_complete) = responder.recv_one([0; 32]).run()?;
    let responder_observed_initiator_id = expect_complete(ev_responder_complete, initiator_addr)?;
    Ok((
        initiator,
        responder,
        initiator_observed_responder_id,
        responder_observed_initiator_id,
    ))
}

#[test]
fn alice_pings_bob_and_observes_pong() -> Result<(), Error> {
    let (alice, alice_addr) = build_node(0xC1, 0x11)?;
    let (bob, bob_addr) = build_node(0xC2, 0x22)?;

    let (alice, bob, alice_view_bob_node_id, bob_view_alice_node_id) =
        handshake_pair(alice, bob, alice_addr, bob_addr, [0xE1; 32], [0xE2; 32])?;

    // Both sides should now have the peer in their routing tables.
    check(
        alice.routing_table().contains(&alice_view_bob_node_id),
        || "alice's table should contain bob after handshake".to_owned(),
    )?;
    check(
        bob.routing_table().contains(&bob_view_alice_node_id),
        || "bob's table should contain alice after handshake".to_owned(),
    )?;

    // Alice pings bob.
    let alice = alice.ping(bob_addr).run()?;

    // Bob receives PING_REQ, auto-replies, surfaces PingRequestReceived.
    let (_bob, ev_bob) = bob.recv_one([0; 32]).run()?;
    match ev_bob {
        KadEvent::PingRequestReceived { from } if from == alice_addr => Ok(()),
        other @ (KadEvent::HandshakeProgress { .. }
        | KadEvent::HandshakeComplete { .. }
        | KadEvent::PingRequestReceived { .. }
        | KadEvent::PingResponseReceived { .. }
        | KadEvent::FindNodeRequestReceived { .. }
        | KadEvent::FindNodeResponseReceived { .. }
        | KadEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("bob: expected PingRequestReceived(from={alice_addr}), got {other:?}"),
        }),
    }?;

    // Alice receives PING_RESP, surfaces PingResponseReceived.
    let (_alice, ev_alice) = alice.recv_one([0; 32]).run()?;
    match ev_alice {
        KadEvent::PingResponseReceived { from } if from == bob_addr => Ok(()),
        other @ (KadEvent::HandshakeProgress { .. }
        | KadEvent::HandshakeComplete { .. }
        | KadEvent::PingRequestReceived { .. }
        | KadEvent::PingResponseReceived { .. }
        | KadEvent::FindNodeRequestReceived { .. }
        | KadEvent::FindNodeResponseReceived { .. }
        | KadEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("alice: expected PingResponseReceived(from={bob_addr}), got {other:?}"),
        }),
    }
}
