//! End-to-end iterative `FIND_NODE` lookup over three loopback
//! [`MultiProtocolNode`]s, verifying that pass 9.4's mux-side
//! lookup driver walks the kad chain through the multi-protocol
//! envelope without breaking the shared-socket model.
//!
//! Topology before alice's lookup:
//!
//! ```text
//!   alice <-> bob <-> carol
//! ```
//!
//! Alice has only handshaken with Bob.  Alice asks her local mux
//! to `lookup_node(target = carol's NodeId)`.  The driver:
//!
//! 1. Round 1: alice queries bob; bob's response advertises carol.
//! 2. Round 2: alice transparently dials carol through the mux's
//!    Noise XX path.
//! 3. Round 3: alice queries carol; lookup terminates with the
//!    top-`k` shortlist mentioning bob and carol.
//!
//! Bob and carol run their `recv_one` loops in daemon threads so
//! they answer alice's queries in real time.  Each daemon uses a
//! distinct ephemeral seed so concurrent handshakes don't collide.
//!
//! [`MultiProtocolNode`]: libp2p_cat_mux::MultiProtocolNode

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::thread;

use libp2p_cat_host::Host;
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_kad::{LookupConfig, NodeId};
use libp2p_cat_mux::{MultiProtocolEvent, MultiProtocolNode};
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_pubsub::unused_relay_rng;
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use rlnc_cat_rs::auth::NullAuthenticator;

type NullMux = MultiProtocolNode<NullAuthenticator>;

const KAD_K: usize = 20;

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

fn build_mux(seed: u8) -> Result<(NullMux, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let kp = StaticKeypair::from_private_bytes([seed; 32]);
    let id = Ed25519Keypair::from_seed([seed.wrapping_add(1); 32]);
    let auth = Arc::new(NullAuthenticator);
    Ok((
        MultiProtocolNode::new(Host::new(socket, kp, &id)?, auth, KAD_K),
        addr,
    ))
}

fn handshake_pair(
    initiator: NullMux,
    responder: NullMux,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(NullMux, NullMux), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    let (responder, ev) = responder
        .recv_one(responder_seed, unused_relay_rng())
        .run()?;
    expect_handshake_progress(ev, initiator_addr)?;
    let (initiator, ev) = initiator.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_handshake_complete(ev, responder_addr)?;
    let (responder, ev) = responder.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_handshake_complete(ev, initiator_addr)?;
    Ok((initiator, responder))
}

fn expect_handshake_progress(ev: MultiProtocolEvent, expected: UdpAddr) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::HandshakeProgress { addr } if addr == expected => Ok(()),
        other @ (MultiProtocolEvent::HandshakeProgress { .. }
        | MultiProtocolEvent::HandshakeComplete { .. }
        | MultiProtocolEvent::AppData { .. }
        | MultiProtocolEvent::PubsubAbsorbed { .. }
        | MultiProtocolEvent::PubsubDelivered { .. }
        | MultiProtocolEvent::PubsubRelayed { .. }
        | MultiProtocolEvent::KadPingRequestReceived { .. }
        | MultiProtocolEvent::KadPingResponseReceived { .. }
        | MultiProtocolEvent::KadFindNodeRequestReceived { .. }
        | MultiProtocolEvent::KadFindNodeResponseReceived { .. }
        | MultiProtocolEvent::ObserveRequestReceived { .. }
        | MultiProtocolEvent::ObserveResponseReceived { .. }
        | MultiProtocolEvent::PunchRequestReceived { .. }
        | MultiProtocolEvent::PunchForwardReceived { .. }
        | MultiProtocolEvent::RpcDatagram { .. }
        | MultiProtocolEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected}), got {other:?}"),
        }),
    }
}

fn expect_handshake_complete(ev: MultiProtocolEvent, expected: UdpAddr) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::HandshakeComplete { addr, .. } if addr == expected => Ok(()),
        other @ (MultiProtocolEvent::HandshakeProgress { .. }
        | MultiProtocolEvent::HandshakeComplete { .. }
        | MultiProtocolEvent::AppData { .. }
        | MultiProtocolEvent::PubsubAbsorbed { .. }
        | MultiProtocolEvent::PubsubDelivered { .. }
        | MultiProtocolEvent::PubsubRelayed { .. }
        | MultiProtocolEvent::KadPingRequestReceived { .. }
        | MultiProtocolEvent::KadPingResponseReceived { .. }
        | MultiProtocolEvent::KadFindNodeRequestReceived { .. }
        | MultiProtocolEvent::KadFindNodeResponseReceived { .. }
        | MultiProtocolEvent::ObserveRequestReceived { .. }
        | MultiProtocolEvent::ObserveResponseReceived { .. }
        | MultiProtocolEvent::PunchRequestReceived { .. }
        | MultiProtocolEvent::PunchForwardReceived { .. }
        | MultiProtocolEvent::RpcDatagram { .. }
        | MultiProtocolEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected}), got {other:?}"),
        }),
    }
}

/// Spawn a daemon-style responder thread that drives `mux.recv_one`
/// for an effectively-infinite number of iterations.  No join
/// handle: the thread blocks on the UDP socket on its final
/// iteration and the OS reaps it on test exit.
fn spawn_responder(node: NullMux, ephemeral_seed: [u8; 32]) {
    thread::spawn(move || -> Result<(), Error> {
        let _final = (0..usize::MAX).try_fold(node, |acc, _| {
            let (next, _ev) = acc.recv_one(ephemeral_seed, unused_relay_rng()).run()?;
            Ok::<_, Error>(next)
        })?;
        Ok(())
    });
}

#[test]
fn mux_lookup_walks_the_chain() -> Result<(), Error> {
    let (alice, alice_addr) = build_mux(0xA1)?;
    let (bob, bob_addr) = build_mux(0xB2)?;
    let (carol, carol_addr) = build_mux(0xC3)?;

    let bob_node_id = *bob.node_id();
    let carol_node_id = *carol.node_id();

    // alice <-> bob
    let (alice, bob) = handshake_pair(alice, bob, alice_addr, bob_addr, [0xE1; 32], [0xE2; 32])?;
    // bob <-> carol
    let (bob, carol) = handshake_pair(bob, carol, bob_addr, carol_addr, [0xE3; 32], [0xE4; 32])?;

    // Sanity: alice knows only bob.
    check(alice.kad_table().contains(&bob_node_id), || {
        "alice should know bob".to_owned()
    })?;
    check(!alice.kad_table().contains(&carol_node_id), || {
        "alice should NOT yet know carol".to_owned()
    })?;

    // Park bob and carol in daemon threads so they answer every
    // inbound RPC (including the transparent dial alice initiates
    // mid-lookup) in real time.
    spawn_responder(bob, [0xF1; 32]);
    spawn_responder(carol, [0xF2; 32]);

    // Alice runs her synchronous lookup for carol's NodeId.  The
    // mux driver transparently dials carol through the mux's
    // Noise XX path, queries her, and returns the shortlist.
    let (alice, peers): (NullMux, Vec<(NodeId, UdpAddr)>) = alice
        .lookup_node(carol_node_id, LookupConfig::default(), || [0u8; 32])
        .run()?;

    let mentions_bob = peers.iter().any(|(id, _)| *id == bob_node_id);
    let mentions_carol = peers
        .iter()
        .any(|(id, addr)| *id == carol_node_id && *addr == carol_addr);
    check(mentions_bob, || {
        format!("lookup result should mention bob, got {peers:?}")
    })?;
    check(mentions_carol, || {
        format!("lookup result should mention carol, got {peers:?}")
    })?;
    check(alice.kad_table().contains(&carol_node_id), || {
        "alice's kad table should know carol after the lookup".to_owned()
    })
}
