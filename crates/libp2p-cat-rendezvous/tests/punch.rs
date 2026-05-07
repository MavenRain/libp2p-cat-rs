//! End-to-end punch coordination via a rendezvous server.
//!
//! Topology:
//!
//! ```text
//!   alice <-> server <-> bob
//! ```
//!
//! Alice and bob each handshake with the rendezvous server.  Server
//! and bob then run as daemon-thread responders.  Alice calls
//! `punch_via(server_addr, bob_addr)`.  The server's daemon decodes
//! the inbound `PUNCH_REQ`, sees bob is established, and sends a
//! `PUNCH_FORWARD { initiator: alice_addr }` to bob.  Bob's daemon
//! decodes the forward and auto-fires a 1-byte bare-datagram punch
//! at alice via [`Host::send_raw`](libp2p_cat_host::Host::send_raw).
//! Alice's next `recv_one` surfaces a [`RendezvousEvent::Rejected`]
//! event whose `addr` equals bob's address, confirming the punch
//! landed.
//!
//! On loopback this verifies the wire protocol; in real deployment
//! the punch's role is to open bob's NAT mapping for an inbound
//! dial from alice.

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

fn build_node(static_seed: u8, identity_seed: u8) -> Result<(RendezvousNode, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let static_kp = StaticKeypair::from_private_bytes([static_seed; 32]);
    let identity = Ed25519Keypair::from_seed([identity_seed; 32]);
    let host = Host::new(socket, static_kp, &identity)?;
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
    let (responder, ev_progress) = responder.recv_one(responder_seed).run()?;
    expect_progress(ev_progress, initiator_addr)?;
    let (initiator, ev_initiator) = initiator.recv_one([0; 32]).run()?;
    expect_complete(ev_initiator, responder_addr)?;
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
fn punch_via_forwards_and_target_punches_back() -> Result<(), Error> {
    let (alice, alice_addr) = build_node(0xA1, 0x11)?;
    let (bob, bob_addr) = build_node(0xB2, 0x22)?;
    let (server, server_addr) = build_node(0xC3, 0x33)?;

    // alice <-> server
    let (alice, server) = handshake_pair(
        alice,
        server,
        alice_addr,
        server_addr,
        [0xE1; 32],
        [0xE2; 32],
    )?;
    // bob <-> server (bob initiates, server responds)
    let (bob, server) = handshake_pair(bob, server, bob_addr, server_addr, [0xE3; 32], [0xE4; 32])?;

    // Park server and bob in daemon threads so they auto-handle the
    // PUNCH_REQ forward and the PUNCH_FORWARD bare-datagram emission
    // in real time.
    spawn_responder(server, [0xF1; 32]);
    spawn_responder(bob, [0xF2; 32]);

    // Alice asks the server to relay a punch request to bob.  The
    // call is fire-and-forget; the actual punch lands on alice's
    // socket when bob's daemon processes the forwarded request.
    let alice = alice.punch_via(server_addr, bob_addr).run()?;

    // Alice's next recv_one should surface a Rejected event for
    // bob's bare-datagram punch (1 byte, not a 32-byte handshake
    // msg1, so Host's try_responder_msg1 rejects it).
    let (_alice, ev) = alice.recv_one([0; 32]).run()?;
    match ev {
        RendezvousEvent::Rejected { addr, .. } if addr == bob_addr => Ok(()),
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
            reason: format!(
                "expected Rejected event from bob ({bob_addr}) carrying the bare punch, got {other:?}"
            ),
        }),
    }
}
