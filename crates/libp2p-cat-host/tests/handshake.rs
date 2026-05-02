//! End-to-end Noise XX handshake driven over real loopback UDP by
//! two [`Host`]s.
//!
//! Alice dials Bob.  Bob's first `recv_one` consumes `msg1` and
//! sends `msg2`, emitting `HandshakeProgress`.  Alice's next
//! `recv_one` consumes `msg2`, sends `msg3`, and emits
//! `HandshakeComplete` with Bob's authenticated static public key.
//! Bob's next `recv_one` consumes `msg3` and emits
//! `HandshakeComplete` with Alice's authenticated static public key.

use std::net::{Ipv4Addr, SocketAddrV4};

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_noise::{StaticKeypair, StaticPublicKey};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;

fn loopback_v4() -> UdpAddr {
    UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

/// Result-returning equivalent of `assert!`: produces
/// `Err(Error::HostState { reason })` instead of panicking on a false
/// condition.
fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::HostState { reason: reason() })
    }
}

fn expect_handshake_progress(event: HostEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match event {
        HostEvent::HandshakeProgress { addr } if addr == expected_addr => Ok(()),
        other => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_handshake_complete(
    event: HostEvent,
    expected_addr: UdpAddr,
) -> Result<StaticPublicKey, Error> {
    match event {
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
        } if addr == expected_addr => Ok(remote_static),
        other => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_rejected(event: HostEvent, expected_addr: UdpAddr) -> Result<String, Error> {
    match event {
        HostEvent::Rejected { addr, reason } if addr == expected_addr => Ok(reason),
        other => Err(Error::HostState {
            reason: format!("expected Rejected({expected_addr}), got {other:?}"),
        }),
    }
}

#[test]
fn two_hosts_complete_xx_handshake_over_loopback() -> Result<(), Error> {
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let alice_addr = alice_socket.local_addr()?;
    let bob_addr = bob_socket.local_addr()?;

    let alice_kp = StaticKeypair::from_private_bytes([0xA1; 32]);
    let bob_kp = StaticKeypair::from_private_bytes([0xB2; 32]);
    let alice_pub = alice_kp.public().clone();
    let bob_pub = bob_kp.public().clone();

    // Step 1: Alice dials Bob (sends msg1).
    let alice_host = Host::new(alice_socket, alice_kp)
        .dial(bob_addr, [0xE1; 32])
        .run()?;
    check(alice_host.handshakes_in_flight() == 1, || {
        format!(
            "expected 1 in-flight handshake on alice, got {}",
            alice_host.handshakes_in_flight()
        )
    })?;
    check(alice_host.established_connections() == 0, || {
        format!(
            "expected 0 established on alice, got {}",
            alice_host.established_connections()
        )
    })?;

    // Step 2: Bob receives msg1, writes msg2 → HandshakeProgress.
    let bob_host = Host::new(bob_socket, bob_kp);
    let (bob_host, ev_bob_1) = bob_host.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev_bob_1, alice_addr)?;
    check(bob_host.handshakes_in_flight() == 1, || {
        format!(
            "expected 1 in-flight on bob after msg1, got {}",
            bob_host.handshakes_in_flight()
        )
    })?;

    // Step 3: Alice receives msg2, writes msg3 → HandshakeComplete.
    let (alice_host, ev_alice_1) = alice_host.recv_one([0; 32]).run()?;
    let alice_observed_bob = expect_handshake_complete(ev_alice_1, bob_addr)?;
    check(alice_observed_bob == bob_pub, || {
        "alice's view of bob's static key does not match".to_owned()
    })?;
    check(alice_host.handshakes_in_flight() == 0, || {
        "alice should have no in-flight handshakes after completion".to_owned()
    })?;
    check(alice_host.established_connections() == 1, || {
        "alice should have one established connection".to_owned()
    })?;
    check(alice_host.is_established(bob_addr), || {
        "alice should report bob_addr as established".to_owned()
    })?;

    // Step 4: Bob receives msg3 → HandshakeComplete.
    let (bob_host, ev_bob_2) = bob_host.recv_one([0; 32]).run()?;
    let bob_observed_alice = expect_handshake_complete(ev_bob_2, alice_addr)?;
    check(bob_observed_alice == alice_pub, || {
        "bob's view of alice's static key does not match".to_owned()
    })?;
    check(bob_host.handshakes_in_flight() == 0, || {
        "bob should have no in-flight handshakes after completion".to_owned()
    })?;
    check(bob_host.established_connections() == 1, || {
        "bob should have one established connection".to_owned()
    })?;
    check(bob_host.is_established(alice_addr), || {
        "bob should report alice_addr as established".to_owned()
    })?;

    Ok(())
}

#[test]
fn dial_rejects_duplicate_address() -> Result<(), Error> {
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_addr = bob_socket.local_addr()?;
    // Keep Bob's socket alive so msg1 has somewhere to land.
    let _bob_keep = bob_socket;

    let alice_kp = StaticKeypair::from_private_bytes([0xA1; 32]);
    let alice_host = Host::new(alice_socket, alice_kp)
        .dial(bob_addr, [0xE1; 32])
        .run()?;

    let outcome = alice_host.dial(bob_addr, [0xE2; 32]).run();
    match outcome {
        Err(Error::HostState { .. }) => Ok(()),
        Ok(_) => Err(Error::HostState {
            reason: "second dial should have been rejected as duplicate".to_owned(),
        }),
        Err(other) => Err(Error::HostState {
            reason: format!("expected HostState error, got {other:?}"),
        }),
    }
}

#[test]
fn fresh_garbage_datagram_is_rejected_not_errored() -> Result<(), Error> {
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let alice_addr = alice_socket.local_addr()?;

    // Alice sends a junk 5-byte datagram to Bob from her socket.
    let alice_socket = alice_socket
        .send(bob_socket.local_addr()?, b"hello".to_vec())
        .run()?;
    drop(alice_socket);

    let bob_kp = StaticKeypair::from_private_bytes([0xB2; 32]);
    let bob_host = Host::new(bob_socket, bob_kp);
    let (_bob_host, ev) = bob_host.recv_one([0xE2; 32]).run()?;
    let _reason = expect_rejected(ev, alice_addr)?;
    Ok(())
}
