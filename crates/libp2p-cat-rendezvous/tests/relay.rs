//! End-to-end test for [`RendezvousNode::relay_via`] (pass 9.7
//! TURN-style relay fallback).
//!
//! Topology: alice (client), relay (server), bob (destination).
//! All three handshake pairwise via the rendezvous server.  Alice
//! calls `relay_via(relay_addr, bob_addr, b"hi via relay")`.  The
//! relay forwards the payload to bob; bob's `recv_one` surfaces
//! [`RendezvousEvent::RelayReceived`] carrying alice's address as
//! the originator.
//!
//! A second case verifies the failure path: alice tries to relay
//! to a peer the relay has no session with; the relay replies
//! `RELAY_FAIL`, surfaced at alice as
//! [`RendezvousEvent::RelayFailed`].

use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;

use libp2p_cat_host::Host;
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_rendezvous::{RendezvousEvent, RendezvousNode};
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

fn build_node(static_seed: u8, identity_seed: u8) -> Result<(RendezvousNode, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let static_kp = StaticKeypair::from_private_bytes([static_seed; 32]);
    let identity = Ed25519Keypair::from_seed([identity_seed; 32]);
    let host = Host::new(socket, static_kp, &identity, [0x4A; 32])?;
    Ok((RendezvousNode::new(host), addr))
}

fn handshake_pair(
    initiator: RendezvousNode,
    responder: RendezvousNode,
    _initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(RendezvousNode, RendezvousNode), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    // step1: responder answers bare msg1 with a cookie challenge (no state created).
    let (responder, _) = responder.recv_one(responder_seed).run()?;
    // step2: initiator echoes the cookie (re-sends msg1||cookie).
    let (initiator, _) = initiator.recv_one([0; 32]).run()?;
    // step3: responder validates the cookie, consumes msg1, writes msg2.
    let (responder, _) = responder.recv_one(responder_seed).run()?;
    // step4: initiator consumes msg2, writes msg3.
    let (initiator, _) = initiator.recv_one([0; 32]).run()?;
    // step5: responder consumes msg3.
    let (responder, _) = responder.recv_one([0; 32]).run()?;
    Ok((initiator, responder))
}

/// Spawn a daemon-style responder thread that drives `recv_one`
/// for an effectively-infinite number of iterations.  The thread
/// blocks on the UDP socket on its final iteration; the OS reaps
/// it on test exit.
fn spawn_responder(node: RendezvousNode, ephemeral_seed: [u8; 32]) {
    thread::spawn(move || -> Result<(), Error> {
        let _final = (0..usize::MAX).try_fold(node, |acc, _| {
            let (next, _ev) = acc.recv_one(ephemeral_seed).run()?;
            Ok::<_, Error>(next)
        })?;
        Ok(())
    });
}

#[test]
fn relay_via_forwards_payload_through_server_to_target() -> Result<(), Error> {
    let (alice, alice_addr) = build_node(0xA1, 0x11)?;
    let (relay, relay_addr) = build_node(0xC3, 0x33)?;
    let (bob, bob_addr) = build_node(0xB2, 0x22)?;

    // alice <-> relay, bob <-> relay
    let (alice, relay) =
        handshake_pair(alice, relay, alice_addr, relay_addr, [0xE1; 32], [0xE2; 32])?;
    let (bob, relay) = handshake_pair(bob, relay, bob_addr, relay_addr, [0xE3; 32], [0xE4; 32])?;

    // Alice asks the relay to forward "hi via relay" to bob.
    let payload = b"hi via relay";
    let _alice_after = alice
        .relay_via(relay_addr, bob_addr, payload.to_vec())
        .run()?;

    // Foreground-drive the relay's recv_one to consume alice's
    // RELAY_DATA_REQ and forward to bob.
    let (_relay_after, relay_ev) = relay.recv_one([0xF1; 32]).run()?;
    match relay_ev {
        RendezvousEvent::RelayForwarded {
            from,
            target,
            forwarded,
            payload_len,
        } => {
            check(from == alice_addr, || {
                format!("relay: expected from = alice, got {from}")
            })?;
            check(target == bob_addr, || {
                format!("relay: expected target = bob, got {target}")
            })?;
            check(forwarded, || "relay: expected forwarded = true".to_owned())?;
            check(payload_len == payload.len(), || {
                format!(
                    "relay: expected payload_len = {}, got {payload_len}",
                    payload.len()
                )
            })?;
        }
        other @ (RendezvousEvent::HandshakeProgress { .. }
        | RendezvousEvent::HandshakeComplete { .. }
        | RendezvousEvent::ObserveRequestReceived { .. }
        | RendezvousEvent::ObserveResponseReceived { .. }
        | RendezvousEvent::PunchRequestReceived { .. }
        | RendezvousEvent::PunchForwardReceived { .. }
        | RendezvousEvent::RelayReceived { .. }
        | RendezvousEvent::RelayFailed { .. }
        | RendezvousEvent::Rejected { .. }) => {
            return Err(Error::HostState {
                reason: format!("relay: expected RelayForwarded, got {other:?}"),
            });
        }
    }

    // Foreground-drive bob's recv_one to receive the forwarded
    // RELAY_DATA_DELIVER from the relay.
    let (_bob_after, bob_ev) = bob.recv_one([0xF2; 32]).run()?;
    match bob_ev {
        RendezvousEvent::RelayReceived {
            from,
            originator,
            payload: received,
        } => {
            check(from == relay_addr, || {
                format!("bob: expected from = relay, got {from}")
            })?;
            check(originator == alice_addr, || {
                format!("bob: expected originator = alice, got {originator}")
            })?;
            check(received == payload, || {
                format!("bob: payload mismatch: {received:?}")
            })
        }
        other @ (RendezvousEvent::HandshakeProgress { .. }
        | RendezvousEvent::HandshakeComplete { .. }
        | RendezvousEvent::ObserveRequestReceived { .. }
        | RendezvousEvent::ObserveResponseReceived { .. }
        | RendezvousEvent::PunchRequestReceived { .. }
        | RendezvousEvent::PunchForwardReceived { .. }
        | RendezvousEvent::RelayForwarded { .. }
        | RendezvousEvent::RelayFailed { .. }
        | RendezvousEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("bob: expected RelayReceived, got {other:?}"),
        }),
    }
}

#[test]
fn relay_via_unknown_target_replies_with_fail() -> Result<(), Error> {
    let (alice, alice_addr) = build_node(0xA1, 0x11)?;
    let (relay, relay_addr) = build_node(0xC3, 0x33)?;

    // alice <-> relay
    let (alice, relay) =
        handshake_pair(alice, relay, alice_addr, relay_addr, [0xE1; 32], [0xE2; 32])?;

    // Park relay in a daemon thread.
    spawn_responder(relay, [0xF1; 32]);

    // Alice asks the relay to forward to a peer the relay has
    // never heard of (a phantom address bound to nothing).
    let phantom = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4242));
    let alice = alice
        .relay_via(relay_addr, phantom, b"this will fail".to_vec())
        .run()?;

    // Drain alice's recv_one until RELAY_FAIL arrives.
    let (_alice_after, ev) = alice.recv_one([0; 32]).run()?;
    match ev {
        RendezvousEvent::RelayFailed { from, peer, reason } => {
            check(from == relay_addr, || {
                format!("expected from = relay_addr, got {from}")
            })?;
            check(peer == phantom, || {
                format!("expected peer = phantom, got {peer}")
            })?;
            check(!reason.is_empty(), || {
                "expected non-empty reason in RELAY_FAIL".to_owned()
            })
        }
        other @ (RendezvousEvent::HandshakeProgress { .. }
        | RendezvousEvent::HandshakeComplete { .. }
        | RendezvousEvent::ObserveRequestReceived { .. }
        | RendezvousEvent::ObserveResponseReceived { .. }
        | RendezvousEvent::PunchRequestReceived { .. }
        | RendezvousEvent::PunchForwardReceived { .. }
        | RendezvousEvent::RelayForwarded { .. }
        | RendezvousEvent::RelayReceived { .. }
        | RendezvousEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected RelayFailed, got {other:?}"),
        }),
    }
}
