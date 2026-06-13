//! Pass 9.1 integration tests for [`Host::evict`], [`Host::evict_idle`],
//! and the LRU eviction that fires when a [`Capacity`] cap is hit.
//!
//! [`Host::evict`]: libp2p_cat_host::Host::evict
//! [`Host::evict_idle`]: libp2p_cat_host::Host::evict_idle
//! [`Capacity`]: libp2p_cat_host::Capacity

use std::net::{Ipv4Addr, SocketAddrV4};

use libp2p_cat_host::{Capacity, Host, HostEvent};
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

fn build_host(seed: u8, capacity: Capacity) -> Result<(Host, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let kp = StaticKeypair::from_private_bytes([seed; 32]);
    let id = Ed25519Keypair::from_seed([seed.wrapping_add(1); 32]);
    let host = Host::with_capacity(socket, kp, &id, [seed.wrapping_add(2); 32], capacity)?;
    Ok((host, addr))
}

fn build_host_default(seed: u8) -> Result<(Host, UdpAddr), Error> {
    build_host(seed, Capacity::default())
}

/// Drive a single Noise XX handshake (including the cookie round
/// trip) to completion between two hosts over real UDP datagrams.
fn handshake_pair(
    initiator: Host,
    responder: Host,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
) -> Result<(Host, Host), Error> {
    let initiator = initiator.dial(responder_addr, [0x44; 32]).run()?;
    let (responder, ev) = responder.recv_one([0x55; 32]).run()?;
    expect_handshake_progress(ev, initiator_addr)?;
    let (initiator, ev) = initiator.recv_one([0; 32]).run()?;
    expect_handshake_progress(ev, responder_addr)?;
    let (responder, ev) = responder.recv_one([0x55; 32]).run()?;
    expect_handshake_progress(ev, initiator_addr)?;
    let (initiator, ev) = initiator.recv_one([0; 32]).run()?;
    expect_handshake_complete(ev, responder_addr)?;
    let (responder, ev) = responder.recv_one([0; 32]).run()?;
    expect_handshake_complete(ev, initiator_addr)?;
    Ok((initiator, responder))
}

fn expect_handshake_progress(ev: HostEvent, expected: UdpAddr) -> Result<(), Error> {
    match ev {
        HostEvent::HandshakeProgress { addr } if addr == expected => Ok(()),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected}), got {other:?}"),
        }),
    }
}

fn expect_handshake_complete(ev: HostEvent, expected: UdpAddr) -> Result<(), Error> {
    match ev {
        HostEvent::HandshakeComplete { addr, .. } if addr == expected => Ok(()),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected}), got {other:?}"),
        }),
    }
}

#[test]
fn explicit_evict_removes_peer() -> Result<(), Error> {
    let (alice, alice_addr) = build_host_default(0xA1)?;
    let (bob, bob_addr) = build_host_default(0xB2)?;
    let (alice, _bob) = handshake_pair(alice, bob, alice_addr, bob_addr)?;

    check(alice.is_established(bob_addr), || {
        "alice should be established with bob after handshake".to_owned()
    })?;

    let alice = alice.evict(bob_addr);
    check(!alice.is_established(bob_addr), || {
        "alice.evict(bob_addr) should drop the established entry".to_owned()
    })?;
    check(alice.established_connections() == 0, || {
        format!(
            "expected 0 established after evict, got {}",
            alice.established_connections()
        )
    })?;

    Ok(())
}

#[test]
fn evict_unknown_address_is_a_noop() -> Result<(), Error> {
    let (alice, _alice_addr) = build_host_default(0xA1)?;
    let phantom = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4242));
    let alice = alice.evict(phantom);
    check(alice.established_connections() == 0, || {
        "evict on unknown peer should leave established empty".to_owned()
    })
}

#[test]
fn lru_evicts_oldest_established_when_cap_is_hit() -> Result<(), Error> {
    // Alice's established cap is 2.  After three handshakes complete,
    // the LRU established (the first peer Alice handshook with) must
    // be evicted to make room for the third.
    let alice_capacity = Capacity::new(8, 2).ok_or_else(|| Error::HostState {
        reason: "Capacity::new(8, 2) should be Some".to_owned(),
    })?;
    let (alice, alice_addr) = build_host(0xA1, alice_capacity)?;
    let (bob, bob_addr) = build_host_default(0xB2)?;
    let (carol, carol_addr) = build_host_default(0xC3)?;
    let (dave, dave_addr) = build_host_default(0xD4)?;

    let (alice, _bob) = handshake_pair(alice, bob, alice_addr, bob_addr)?;
    let (alice, _carol) = handshake_pair(alice, carol, alice_addr, carol_addr)?;
    check(alice.established_connections() == 2, || {
        format!(
            "expected 2 established before third handshake, got {}",
            alice.established_connections()
        )
    })?;
    let (alice, _dave) = handshake_pair(alice, dave, alice_addr, dave_addr)?;

    check(alice.established_connections() == 2, || {
        format!(
            "expected 2 established after LRU eviction, got {}",
            alice.established_connections()
        )
    })?;
    check(!alice.is_established(bob_addr), || {
        "bob (LRU) should have been evicted to make room for dave".to_owned()
    })?;
    check(alice.is_established(carol_addr), || {
        "carol should still be established".to_owned()
    })?;
    check(alice.is_established(dave_addr), || {
        "dave (newest) should be established".to_owned()
    })?;

    Ok(())
}

#[test]
fn evict_idle_sweeps_quiet_peers() -> Result<(), Error> {
    // Alice handshakes with Bob; the handshake completes at some
    // tick T_b.  Alice then handshakes with Carol; the second
    // handshake completes at tick T_c > T_b.  evict_idle with a
    // threshold tighter than (current_tick - T_b) but looser than
    // (current_tick - T_c) drops Bob and keeps Carol.
    let (alice, alice_addr) = build_host_default(0xA1)?;
    let (bob, bob_addr) = build_host_default(0xB2)?;
    let (carol, carol_addr) = build_host_default(0xC3)?;

    let (alice, _bob) = handshake_pair(alice, bob, alice_addr, bob_addr)?;
    let bob_completion_tick = alice.tick();
    let (alice, _carol) = handshake_pair(alice, carol, alice_addr, carol_addr)?;

    let now = alice.tick();
    let bob_idle = now - bob_completion_tick;
    // Pick a threshold strictly less than bob_idle so bob is past
    // cutoff, and verify carol (touched at tick `now`) survives.
    let threshold = bob_idle.saturating_sub(1);
    let (alice, evicted) = alice.evict_idle(threshold);

    check(evicted.contains(&bob_addr), || {
        format!("expected bob_addr in evicted list, got {evicted:?}")
    })?;
    check(!alice.is_established(bob_addr), || {
        "bob should be evicted by evict_idle".to_owned()
    })?;
    check(alice.is_established(carol_addr), || {
        "carol (recently active) should survive evict_idle".to_owned()
    })?;

    Ok(())
}

#[test]
fn tick_advances_on_state_changing_calls() -> Result<(), Error> {
    let (alice, _alice_addr) = build_host_default(0xA1)?;
    let start_tick = alice.tick();
    check(start_tick == 0, || {
        format!("fresh host should start at tick 0, got {start_tick}")
    })?;

    // dial advances the tick (records the new in-flight handshake).
    let (bob, bob_addr) = build_host_default(0xB2)?;
    let alice = alice.dial(bob_addr, [0x77; 32]).run()?;
    check(alice.tick() > start_tick, || {
        format!(
            "dial should advance tick from {start_tick} to >0, got {}",
            alice.tick()
        )
    })?;
    let _bob_keep = bob;
    Ok(())
}
