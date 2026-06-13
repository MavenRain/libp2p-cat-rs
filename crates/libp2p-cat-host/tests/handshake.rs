//! End-to-end Noise XX handshake driven over real loopback UDP by
//! two [`Host`]s.
//!
//! Alice dials Bob.  Bob's first `recv_one` consumes the bare `msg1`
//! and answers with a stateless cookie challenge (no handshake state
//! is created).  Alice's `recv_one` consumes the challenge and
//! re-sends `msg1 || cookie`.  Bob's next `recv_one` verifies the
//! cookie, consumes `msg1`, and sends `msg2`, emitting
//! `HandshakeProgress`.  Alice's next `recv_one` consumes `msg2`,
//! sends `msg3`, and emits `HandshakeComplete` with Bob's
//! authenticated static public key.  Bob's next `recv_one` consumes
//! `msg3` and emits `HandshakeComplete` with Alice's authenticated
//! static public key.

use std::net::{Ipv4Addr, SocketAddrV4};

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_noise::{StaticKeypair, StaticPublicKey};
use libp2p_cat_types::{Error, PeerId, UdpAddr};
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
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_handshake_complete(
    event: HostEvent,
    expected_addr: UdpAddr,
) -> Result<(StaticPublicKey, PeerId), Error> {
    match event {
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
            remote_peer_id,
        } if addr == expected_addr => Ok((remote_static, remote_peer_id)),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_rejected(event: HostEvent, expected_addr: UdpAddr) -> Result<String, Error> {
    match event {
        HostEvent::Rejected { addr, reason } if addr == expected_addr => Ok(reason),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
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
    let alice_id = Ed25519Keypair::from_seed([0x11; 32]);
    let bob_id = Ed25519Keypair::from_seed([0x22; 32]);
    let alice_pub = alice_kp.public().clone();
    let bob_pub = bob_kp.public().clone();
    let alice_peer_id = alice_id.peer_id();
    let bob_peer_id = bob_id.peer_id();

    // Step 1: Alice dials Bob (sends msg1).
    let alice_host = Host::new(alice_socket, alice_kp, &alice_id, [0x43; 32])?
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

    // Step 2: Bob receives the bare msg1 and answers with a
    // stateless cookie challenge: HandshakeProgress, but NO state.
    let bob_host = Host::new(bob_socket, bob_kp, &bob_id, [0x44; 32])?;
    let (bob_host, ev_bob_cookie) = bob_host.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev_bob_cookie, alice_addr)?;
    check(bob_host.handshakes_in_flight() == 0, || {
        format!(
            "a bare msg1 must create no handshake state on bob, got {}",
            bob_host.handshakes_in_flight()
        )
    })?;

    // Step 2b: Alice receives the challenge and re-sends
    // msg1 || cookie, keeping her in-flight state.
    let (alice_host, ev_alice_echo) = alice_host.recv_one([0; 32]).run()?;
    expect_handshake_progress(ev_alice_echo, bob_addr)?;
    check(alice_host.handshakes_in_flight() == 1, || {
        "alice should still have her in-flight handshake after the cookie echo".to_owned()
    })?;

    // Step 2c: Bob verifies the cookie, consumes msg1, writes msg2
    // → HandshakeProgress, and only now creates handshake state.
    let (bob_host, ev_bob_1) = bob_host.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev_bob_1, alice_addr)?;
    check(bob_host.handshakes_in_flight() == 1, || {
        format!(
            "expected 1 in-flight on bob after validated msg1, got {}",
            bob_host.handshakes_in_flight()
        )
    })?;

    // Step 3: Alice receives msg2, writes msg3 → HandshakeComplete.
    let (alice_host, ev_alice_1) = alice_host.recv_one([0; 32]).run()?;
    let (alice_observed_bob, alice_observed_bob_peer) =
        expect_handshake_complete(ev_alice_1, bob_addr)?;
    check(alice_observed_bob == bob_pub, || {
        "alice's view of bob's static key does not match".to_owned()
    })?;
    check(alice_observed_bob_peer == bob_peer_id, || {
        "alice's view of bob's peer id does not match".to_owned()
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
    let (bob_observed_alice, bob_observed_alice_peer) =
        expect_handshake_complete(ev_bob_2, alice_addr)?;
    check(bob_observed_alice == alice_pub, || {
        "bob's view of alice's static key does not match".to_owned()
    })?;
    check(bob_observed_alice_peer == alice_peer_id, || {
        "bob's view of alice's peer id does not match".to_owned()
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
    let alice_id = Ed25519Keypair::from_seed([0x11; 32]);
    let alice_host = Host::new(alice_socket, alice_kp, &alice_id, [0x44; 32])?
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
    let bob_id = Ed25519Keypair::from_seed([0x22; 32]);
    let bob_host = Host::new(bob_socket, bob_kp, &bob_id, [0x44; 32])?;
    let (_bob_host, ev) = bob_host.recv_one([0xE2; 32]).run()?;
    let _reason = expect_rejected(ev, alice_addr)?;
    Ok(())
}

#[test]
fn forged_cookie_echo_is_rejected_statelessly() -> Result<(), Error> {
    // A msg1 || cookie whose MAC was not minted by this host (an
    // off-path guess, or a cookie minted for a different address)
    // must be rejected without performing DH or creating state.
    let attacker_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let attacker_addr = attacker_socket.local_addr()?;

    let forged: Vec<u8> = [0xE1; 32].into_iter().chain([0xAB; 32]).collect();
    let _attacker_after = attacker_socket
        .send(bob_socket.local_addr()?, forged)
        .run()?;

    let bob_kp = StaticKeypair::from_private_bytes([0xB2; 32]);
    let bob_id = Ed25519Keypair::from_seed([0x22; 32]);
    let bob_host = Host::new(bob_socket, bob_kp, &bob_id, [0x44; 32])?;
    let (bob_host, ev) = bob_host.recv_one([0xE2; 32]).run()?;
    let reason = expect_rejected(ev, attacker_addr)?;
    check(reason.contains("cookie"), || {
        format!("rejection reason should mention the cookie: {reason}")
    })?;
    check(bob_host.handshakes_in_flight() == 0, || {
        "a forged cookie echo must create no handshake state".to_owned()
    })
}

#[test]
fn responder_rejects_initiator_with_empty_identity_trailer() -> Result<(), Error> {
    // An attacker that drives Noise XX without sending a SignedStaticKey
    // trailer (empty payload, the libp2p-cat-noise-only path) must not
    // be able to establish with a Host.  The host computes a verified
    // PeerId from the trailer; absence is fail-closed.
    use libp2p_cat_noise::Initiator;

    let attacker_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let attacker_addr = attacker_socket.local_addr()?;
    let bob_addr = bob_socket.local_addr()?;

    let attacker_kp = StaticKeypair::from_private_bytes([0x91; 32]);
    let bob_kp = StaticKeypair::from_private_bytes([0xB2; 32]);
    let bob_id = Ed25519Keypair::from_seed([0x22; 32]);

    // Drive the attacker side by hand; the noise crate still accepts
    // empty trailers, so the wire flow completes from Noise's view.
    let (attacker_after_e, msg1) = Initiator::new(attacker_kp).write_e([0xE1; 32])?;
    let msg1_retained = msg1.clone();
    let attacker_socket = attacker_socket.send(bob_addr, msg1).run()?;

    // Bob answers the bare msg1 with a stateless cookie challenge.
    let bob_host = Host::new(bob_socket, bob_kp, &bob_id, [0x44; 32])?;
    let (bob_host, ev_challenge) = bob_host.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev_challenge, attacker_addr)?;

    // The attacker echoes the cookie (it really does control its
    // source address) by re-sending msg1 with the MAC appended.
    let (challenge, attacker_socket) = recv_one_from(attacker_socket)?;
    let mac = challenge.get(1..).map(<[u8]>::to_vec).unwrap_or_default();
    let msg1_with_cookie: Vec<u8> = msg1_retained.into_iter().chain(mac).collect();
    let attacker_socket = attacker_socket.send(bob_addr, msg1_with_cookie).run()?;

    // Bob's host validates the cookie, consumes msg1, and writes msg2
    // (with its real identity trailer) -> HandshakeProgress.
    let (bob_host, ev_progress) = bob_host.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev_progress, attacker_addr)?;

    // Attacker reads Bob's msg2 and writes msg3 with an empty trailer.
    let (msg2, attacker_socket) = recv_one_from(attacker_socket)?;
    let (attacker_after_resp, _bob_payload) = attacker_after_e.read_response(&msg2)?;
    let (_attacker_transport, msg3, _bob_static) = attacker_after_resp.write_s(&[])?;
    let _attacker_socket = attacker_socket.send(bob_addr, msg3).run()?;

    // Bob receives msg3.  The noise layer accepts (transport derives
    // OK), but the empty trailer fails to parse as a SignedStaticKey,
    // so Host surfaces Rejected, and the connection is not
    // established.
    let (bob_host, ev_reject) = bob_host.recv_one([0; 32]).run()?;
    let reason = expect_rejected(ev_reject, attacker_addr)?;
    check(
        reason.contains("identity verification failed")
            || reason.contains("SignedStaticKey")
            || reason.contains("IdentityVerify"),
        || format!("rejection reason did not mention identity: {reason}"),
    )?;
    check(!bob_host.is_established(attacker_addr), || {
        "bob should not have established with attacker that sent empty trailer".to_owned()
    })
}

#[test]
fn in_flight_initiator_handshake_survives_corrupted_msg2() -> Result<(), Error> {
    // An initiator awaiting msg2 must not lose its handshake to a
    // corrupted or spoofed datagram from the dialed peer's address:
    // the bad datagram is rejected, the slot is kept, and a later
    // genuine msg2 still completes.  We force a garbage datagram to
    // arrive at alice ahead of the real msg2 by having bob emit it
    // with send_raw before he writes msg2.
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let alice_addr = alice_socket.local_addr()?;
    let bob_addr = bob_socket.local_addr()?;

    let alice_kp = StaticKeypair::from_private_bytes([0xA1; 32]);
    let bob_kp = StaticKeypair::from_private_bytes([0xB2; 32]);
    let alice_id = Ed25519Keypair::from_seed([0x11; 32]);
    let bob_id = Ed25519Keypair::from_seed([0x22; 32]);
    let bob_pub = bob_kp.public().clone();
    let bob_peer_id = bob_id.peer_id();

    // Cookie round-trip: alice dials, bob challenges, alice echoes.
    let alice = Host::new(alice_socket, alice_kp, &alice_id, [0x43; 32])?
        .dial(bob_addr, [0xE1; 32])
        .run()?;
    let bob = Host::new(bob_socket, bob_kp, &bob_id, [0x44; 32])?;
    let (bob, ev) = bob.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev, alice_addr)?;
    let (alice, ev) = alice.recv_one([0; 32]).run()?;
    expect_handshake_progress(ev, bob_addr)?;

    // Garbage from bob's address, queued at alice BEFORE the real
    // msg2 bob is about to write.
    let bob = bob.send_raw(alice_addr, vec![0xEE; 100]).run()?;
    let (bob, ev) = bob.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev, alice_addr)?;

    // Alice reads the garbage first: rejected, handshake kept.
    let (alice, ev) = alice.recv_one([0; 32]).run()?;
    let reason = expect_rejected(ev, bob_addr)?;
    check(reason.contains("handshake kept"), || {
        format!("expected a retention reason, got: {reason}")
    })?;
    check(alice.handshakes_in_flight() == 1, || {
        "the in-flight handshake must survive a corrupted msg2".to_owned()
    })?;
    check(!alice.is_established(bob_addr), || {
        "alice must not be established after a corrupted msg2".to_owned()
    })?;

    // Alice's next read is the genuine msg2 and completes the handshake.
    let (alice, ev) = alice.recv_one([0; 32]).run()?;
    let (observed_static, observed_peer) = expect_handshake_complete(ev, bob_addr)?;
    check(observed_static == bob_pub, || {
        "alice's view of bob's static key must match after recovery".to_owned()
    })?;
    check(observed_peer == bob_peer_id, || {
        "alice's view of bob's peer id must match after recovery".to_owned()
    })?;
    check(alice.is_established(bob_addr), || {
        "alice should be established after the genuine msg2".to_owned()
    })?;
    let _bob_keep = bob;
    Ok(())
}

#[test]
fn in_flight_responder_handshake_survives_corrupted_msg3() -> Result<(), Error> {
    // Mirror of the initiator test for the responder awaiting msg3:
    // a corrupted datagram from the initiator's address is rejected
    // without tearing down the half-open handshake, and the genuine
    // msg3 still completes it.
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let alice_addr = alice_socket.local_addr()?;
    let bob_addr = bob_socket.local_addr()?;

    let alice_kp = StaticKeypair::from_private_bytes([0xA1; 32]);
    let bob_kp = StaticKeypair::from_private_bytes([0xB2; 32]);
    let alice_id = Ed25519Keypair::from_seed([0x11; 32]);
    let bob_id = Ed25519Keypair::from_seed([0x22; 32]);
    let alice_pub = alice_kp.public().clone();
    let alice_peer_id = alice_id.peer_id();

    // Drive through to bob having written msg2 (bob is now awaiting
    // msg3); alice has consumed msg2 and is about to write msg3.
    let alice = Host::new(alice_socket, alice_kp, &alice_id, [0x43; 32])?
        .dial(bob_addr, [0xE1; 32])
        .run()?;
    let bob = Host::new(bob_socket, bob_kp, &bob_id, [0x44; 32])?;
    let (bob, ev) = bob.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev, alice_addr)?;
    let (alice, ev) = alice.recv_one([0; 32]).run()?;
    expect_handshake_progress(ev, bob_addr)?;
    let (bob, ev) = bob.recv_one([0xE2; 32]).run()?;
    expect_handshake_progress(ev, alice_addr)?;

    // Garbage from alice's address, queued at bob BEFORE alice's
    // genuine msg3.
    let alice = alice.send_raw(bob_addr, vec![0xEE; 100]).run()?;
    let (alice, ev) = alice.recv_one([0; 32]).run()?;
    let (_alice_view_static, _alice_view_peer) = expect_handshake_complete(ev, bob_addr)?;

    // Bob reads the garbage first: rejected, handshake kept.
    let (bob, ev) = bob.recv_one([0; 32]).run()?;
    let reason = expect_rejected(ev, alice_addr)?;
    check(reason.contains("handshake kept"), || {
        format!("expected a retention reason, got: {reason}")
    })?;
    check(bob.handshakes_in_flight() == 1, || {
        "the half-open handshake must survive a corrupted msg3".to_owned()
    })?;
    check(!bob.is_established(alice_addr), || {
        "bob must not be established after a corrupted msg3".to_owned()
    })?;

    // Bob's next read is the genuine msg3 and completes the handshake.
    let (bob, ev) = bob.recv_one([0; 32]).run()?;
    let (observed_static, observed_peer) = expect_handshake_complete(ev, alice_addr)?;
    check(observed_static == alice_pub, || {
        "bob's view of alice's static key must match after recovery".to_owned()
    })?;
    check(observed_peer == alice_peer_id, || {
        "bob's view of alice's peer id must match after recovery".to_owned()
    })?;
    check(bob.is_established(alice_addr), || {
        "bob should be established after the genuine msg3".to_owned()
    })?;
    let _alice_keep = alice;
    Ok(())
}

fn recv_one_from(socket: UdpTransport) -> Result<(Vec<u8>, UdpTransport), Error> {
    let ((_from, datagram), socket) = socket.recv().run()?;
    Ok((datagram, socket))
}
