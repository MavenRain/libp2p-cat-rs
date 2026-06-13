//! Post-handshake message exchange between two [`Host`]s.
//!
//! Drives the XX handshake (with its cookie round trip) to
//! completion via `dial` / `recv_one`, then exercises [`Host::send`]
//! / [`Host::recv_one`] on real loopback UDP datagrams in both
//! directions.  Separate tests confirm that junk datagrams surface
//! as [`HostEvent::Rejected`] without tearing down any state: an
//! established session survives a garbage datagram from its peer's
//! address.

use std::net::{Ipv4Addr, SocketAddrV4};

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_identity::Ed25519Keypair;
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

/// Drive the XX handshake (cookie challenge, cookie echo, then the
/// three Noise messages) to completion between two hosts and return
/// them in `(initiator, responder)` order alongside their loopback
/// addresses.
fn established_pair() -> Result<(Host, Host, UdpAddr, UdpAddr), Error> {
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let alice_addr = alice_socket.local_addr()?;
    let bob_addr = bob_socket.local_addr()?;

    let alice_kp = StaticKeypair::from_private_bytes([0xC1; 32]);
    let bob_kp = StaticKeypair::from_private_bytes([0xC2; 32]);
    let alice_id = Ed25519Keypair::from_seed([0x31; 32]);
    let bob_id = Ed25519Keypair::from_seed([0x32; 32]);

    let alice = Host::new(alice_socket, alice_kp, &alice_id, [0x3A; 32])?
        .dial(bob_addr, [0xE1; 32])
        .run()?;
    let bob = Host::new(bob_socket, bob_kp, &bob_id, [0x3B; 32])?;
    let (bob, _ev_challenge) = bob.recv_one([0xE2; 32]).run()?;
    let (alice, _ev_echo) = alice.recv_one([0; 32]).run()?;
    let (bob, _ev1) = bob.recv_one([0xE2; 32]).run()?;
    let (alice, _ev2) = alice.recv_one([0; 32]).run()?;
    let (bob, _ev3) = bob.recv_one([0; 32]).run()?;

    check(alice.is_established(bob_addr), || {
        "alice should be established with bob after handshake".to_owned()
    })?;
    check(bob.is_established(alice_addr), || {
        "bob should be established with alice after handshake".to_owned()
    })?;

    Ok((alice, bob, alice_addr, bob_addr))
}

fn expect_delivered(
    event: HostEvent,
    expected_addr: UdpAddr,
    expected_plaintext: &[u8],
) -> Result<(), Error> {
    match event {
        HostEvent::DatagramDelivered { addr, plaintext }
            if addr == expected_addr && plaintext == expected_plaintext =>
        {
            Ok(())
        }
        HostEvent::DatagramDelivered { addr, plaintext } => Err(Error::HostState {
            reason: format!(
                "DatagramDelivered shape mismatch: addr={addr}, plaintext={plaintext:?}"
            ),
        }),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected DatagramDelivered, got {other:?}"),
        }),
    }
}

fn expect_rejected(event: HostEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match event {
        HostEvent::Rejected { addr, .. } if addr == expected_addr => Ok(()),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected Rejected({expected_addr}), got {other:?}"),
        }),
    }
}

#[test]
fn established_hosts_round_trip_a_message_each_way() -> Result<(), Error> {
    let (alice, bob, alice_addr, bob_addr) = established_pair()?;

    // Alice -> Bob.
    let alice = alice.send(bob_addr, b"hello bob".to_vec()).run()?;
    let (bob, ev_a2b) = bob.recv_one([0; 32]).run()?;
    expect_delivered(ev_a2b, alice_addr, b"hello bob")?;

    // Bob -> Alice.
    let bob = bob.send(alice_addr, b"hi alice".to_vec()).run()?;
    let (alice, ev_b2a) = alice.recv_one([0; 32]).run()?;
    expect_delivered(ev_b2a, bob_addr, b"hi alice")?;

    // Both sides should still be established and have one peer each.
    check(alice.established_connections() == 1, || {
        "alice should have 1 established connection".to_owned()
    })?;
    check(bob.established_connections() == 1, || {
        "bob should have 1 established connection".to_owned()
    })
}

#[test]
fn send_to_unknown_peer_errors() -> Result<(), Error> {
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let alice_kp = StaticKeypair::from_private_bytes([0xD1; 32]);
    let alice_id = Ed25519Keypair::from_seed([0x33; 32]);
    let alice = Host::new(alice_socket, alice_kp, &alice_id, [0x3C; 32])?;

    // bind+drop bob's socket so we have a "valid" addr to target
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_addr = bob_socket.local_addr()?;
    drop(bob_socket);

    match alice.send(bob_addr, b"nope".to_vec()).run() {
        Err(Error::HostState { .. }) => Ok(()),
        Ok(_) => Err(Error::HostState {
            reason: "send to non-established peer should have failed".to_owned(),
        }),
        Err(other) => Err(Error::HostState {
            reason: format!("expected HostState error, got {other:?}"),
        }),
    }
}

#[test]
fn junk_from_unknown_peer_is_rejected() -> Result<(), Error> {
    let (alice, bob, _alice_addr, bob_addr) = established_pair()?;

    // A fresh socket forges an unauthenticated 24-byte datagram
    // (TRANSPORT_OVERHEAD bytes) to bob.  From bob's perspective it
    // comes from a brand-new peer and is neither a bare msg1 (32
    // bytes) nor a msg1-with-cookie (64 bytes), so the dispatcher
    // rejects it without creating any state.
    let attacker_socket = UdpTransport::bind(loopback_v4()).run()?;
    let attacker_addr = attacker_socket.local_addr()?;
    let _attacker_after = attacker_socket
        .send(bob_addr, vec![0u8; libp2p_cat_noise::TRANSPORT_OVERHEAD])
        .run()?;

    let (bob, ev) = bob.recv_one([0; 32]).run()?;
    expect_rejected(ev, attacker_addr)?;
    check(bob.handshakes_in_flight() == 0, || {
        "junk from an unknown peer must not create handshake state".to_owned()
    })?;

    // Alice's connection to bob is still intact since we never
    // tampered with traffic from her actual socket.
    check(alice.is_established(bob_addr), || {
        "alice's connection to bob should be unaffected".to_owned()
    })
}

#[test]
fn session_survives_junk_from_established_address() -> Result<(), Error> {
    let (alice, bob, alice_addr, bob_addr) = established_pair()?;

    // Junk arriving from an *established* peer's address (here sent
    // via alice's real socket with `send_raw`, exactly what an
    // off-path attacker spoofing her address would produce) must not
    // tear down the session: the datagram is dropped, the connection
    // and its replay window stay intact, and genuine traffic still
    // flows afterwards.
    let alice = alice
        .send_raw(
            bob_addr,
            vec![0xFF; libp2p_cat_noise::TRANSPORT_OVERHEAD + 7],
        )
        .run()?;
    let (bob, ev_junk) = bob.recv_one([0; 32]).run()?;
    expect_rejected(ev_junk, alice_addr)?;
    check(bob.is_established(alice_addr), || {
        "bob must keep the established session after a junk datagram".to_owned()
    })?;

    let _alice = alice.send(bob_addr, b"still here".to_vec()).run()?;
    let (bob, ev_real) = bob.recv_one([0; 32]).run()?;
    expect_delivered(ev_real, alice_addr, b"still here")?;
    check(bob.is_established(alice_addr), || {
        "session should remain established after recovery".to_owned()
    })
}
