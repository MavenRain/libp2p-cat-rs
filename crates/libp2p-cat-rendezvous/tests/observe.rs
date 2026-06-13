//! End-to-end STUN-style address observation between two
//! [`RendezvousNode`]s over real loopback UDP.
//!
//! Alice plays client; the server peer parks in a daemon thread
//! that runs `recv_one` indefinitely.  Alice handshakes with the
//! server, calls `observe_self`, and asserts the returned address
//! equals her own bind address.  On loopback this is the only way
//! `observed` can possibly come out: the server sees alice's
//! packets coming from her bind port, with the loopback IP.  The
//! test verifies the wire round-trip; verifying actual NAT
//! traversal requires real or simulated NAT and is out of scope
//! for this crate's tests.

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

fn expect_progress(ev: RendezvousEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        RendezvousEvent::HandshakeProgress { addr } if addr == expected_addr => Ok(()),
        other @ (RendezvousEvent::HandshakeProgress { .. }
        | RendezvousEvent::HandshakeComplete { .. }
        | RendezvousEvent::ObserveRequestReceived { .. }
        | RendezvousEvent::ObserveResponseReceived { .. }
        | RendezvousEvent::PunchRequestReceived { .. }
        | RendezvousEvent::PunchForwardReceived { .. }
        | RendezvousEvent::RelayForwarded { .. }
        | RendezvousEvent::RelayReceived { .. }
        | RendezvousEvent::RelayFailed { .. }
        | RendezvousEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_complete(ev: RendezvousEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        RendezvousEvent::HandshakeComplete { addr, .. } if addr == expected_addr => Ok(()),
        other @ (RendezvousEvent::HandshakeProgress { .. }
        | RendezvousEvent::HandshakeComplete { .. }
        | RendezvousEvent::ObserveRequestReceived { .. }
        | RendezvousEvent::ObserveResponseReceived { .. }
        | RendezvousEvent::PunchRequestReceived { .. }
        | RendezvousEvent::PunchForwardReceived { .. }
        | RendezvousEvent::RelayForwarded { .. }
        | RendezvousEvent::RelayReceived { .. }
        | RendezvousEvent::RelayFailed { .. }
        | RendezvousEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected_addr}), got {other:?}"),
        }),
    }
}

fn handshake_pair(
    initiator: RendezvousNode,
    responder: RendezvousNode,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(RendezvousNode, RendezvousNode), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    // step1: responder answers bare msg1 with a cookie challenge (no state created).
    let (responder, ev_progress1) = responder.recv_one(responder_seed).run()?;
    expect_progress(ev_progress1, initiator_addr)?;
    // step2: initiator echoes the cookie (re-sends msg1||cookie).
    let (initiator, ev_progress2) = initiator.recv_one([0; 32]).run()?;
    expect_progress(ev_progress2, responder_addr)?;
    // step3: responder validates the cookie, consumes msg1, writes msg2.
    let (responder, ev_progress3) = responder.recv_one(responder_seed).run()?;
    expect_progress(ev_progress3, initiator_addr)?;
    // step4: initiator consumes msg2, writes msg3.
    let (initiator, ev_initiator) = initiator.recv_one([0; 32]).run()?;
    expect_complete(ev_initiator, responder_addr)?;
    // step5: responder consumes msg3.
    let (responder, ev_responder) = responder.recv_one([0; 32]).run()?;
    expect_complete(ev_responder, initiator_addr)?;
    Ok((initiator, responder))
}

/// Spawn a daemon-style responder thread that drives `recv_one` for
/// an effectively-infinite number of iterations.  The OS reaps the
/// thread when the test process exits.
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
fn observe_self_returns_clients_bind_address() -> Result<(), Error> {
    let (alice, alice_addr) = build_node(0xA1, 0x11)?;
    let (server, server_addr) = build_node(0xB2, 0x22)?;

    // alice <-> server
    let (alice, server) = handshake_pair(
        alice,
        server,
        alice_addr,
        server_addr,
        [0xE1; 32],
        [0xE2; 32],
    )?;

    // Park server in a daemon thread so it answers alice's
    // OBSERVE_REQ in real time.
    spawn_responder(server, [0xF1; 32]);

    // Alice asks the server "what address do you see me coming from?"
    // and the synchronous observe_self drains until the matching
    // OBSERVE_RESP arrives.
    let (_alice, observed) = alice.observe_self(server_addr, || [0u8; 32]).run()?;

    check(observed == alice_addr, || {
        format!("observed address {observed} should equal alice's bind address {alice_addr}")
    })
}
