//! End-to-end two-peer test exercising all three protocols
//! ([`crate::KIND_APP`] / pubsub / kad / rendezvous) over a single
//! UDP socket per peer through [`MultiProtocolNode`].
//!
//! The test runs:
//!
//! 1. A real Noise XX handshake between alice and bob.
//! 2. A `KIND_APP` round trip: alice → bob, bob receives
//!    [`MultiProtocolEvent::AppData`].
//! 3. A `KIND_KAD` round trip: alice sends `PING_REQ`, bob auto-
//!    replies `PING_RESP`, alice receives
//!    [`MultiProtocolEvent::KadPingResponseReceived`].
//! 4. A `KIND_RENDEZVOUS` round trip: alice sends `OBSERVE_REQ`,
//!    bob auto-replies `OBSERVE_RESP { observed: alice_addr }`,
//!    alice receives
//!    [`MultiProtocolEvent::ObserveResponseReceived`].
//! 5. A `KIND_PUBSUB` broadcast: bob registers the topic, alice
//!    broadcasts 2 pieces, bob's decoder absorbs the first piece
//!    and decodes on the second, surfacing
//!    [`MultiProtocolEvent::PubsubDelivered`].
//!
//! All five exchanges share the same encrypted UDP session per
//! peer, demonstrating that the kind-byte mux fans out across
//! protocols correctly.
//!
//! [`MultiProtocolNode`]: libp2p_cat_mux::MultiProtocolNode
//! [`MultiProtocolEvent::AppData`]:
//!     libp2p_cat_mux::MultiProtocolEvent::AppData
//! [`MultiProtocolEvent::KadPingResponseReceived`]:
//!     libp2p_cat_mux::MultiProtocolEvent::KadPingResponseReceived
//! [`MultiProtocolEvent::ObserveResponseReceived`]:
//!     libp2p_cat_mux::MultiProtocolEvent::ObserveResponseReceived
//! [`MultiProtocolEvent::PubsubDelivered`]:
//!     libp2p_cat_mux::MultiProtocolEvent::PubsubDelivered

// expect_* helpers below take `MultiProtocolEvent` by value so the
// happy-path arm enumerates exhaustively without forcing a manual
// `&pat` syntax on every variant; clippy can't see that the value
// is structurally inspected through the wildcard arm's `{ev:?}`
// formatting.
#![allow(clippy::needless_pass_by_value)]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libp2p_cat_host::Host;
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_mux::{MultiProtocolEvent, MultiProtocolNode};
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_pubsub::{Topic, unused_relay_rng};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use rlnc_cat_rs::auth::NullAuthenticator;
use rlnc_cat_rs::coding::piece::OriginalData;

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
    let keypair = StaticKeypair::from_private_bytes([seed; 32]);
    let identity = Ed25519Keypair::from_seed([seed.wrapping_add(1); 32]);
    let auth = Arc::new(NullAuthenticator);
    Ok((
        MultiProtocolNode::new(Host::new(socket, keypair, &identity)?, auth, KAD_K),
        addr,
    ))
}

/// Drive a single Noise XX handshake to completion between two
/// muxes over real UDP datagrams.
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
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected}), got {ev:?}"),
        }),
    }
}

fn expect_handshake_complete(ev: MultiProtocolEvent, expected: UdpAddr) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::HandshakeComplete { addr, .. } if addr == expected => Ok(()),
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected}), got {ev:?}"),
        }),
    }
}

fn expect_app_data(
    ev: MultiProtocolEvent,
    expected_addr: UdpAddr,
    expected_bytes: &[u8],
) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::AppData { addr, bytes }
            if addr == expected_addr && bytes == expected_bytes =>
        {
            Ok(())
        }
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected AppData({expected_addr}, {expected_bytes:?}), got {ev:?}"),
        }),
    }
}

fn expect_kad_ping_request(ev: MultiProtocolEvent, expected_from: UdpAddr) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::KadPingRequestReceived { from } if from == expected_from => Ok(()),
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected KadPingRequestReceived({expected_from}), got {ev:?}"),
        }),
    }
}

fn expect_kad_ping_response(ev: MultiProtocolEvent, expected_from: UdpAddr) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::KadPingResponseReceived { from } if from == expected_from => Ok(()),
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected KadPingResponseReceived({expected_from}), got {ev:?}"),
        }),
    }
}

fn expect_observe_request(ev: MultiProtocolEvent, expected_from: UdpAddr) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::ObserveRequestReceived { from } if from == expected_from => Ok(()),
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected ObserveRequestReceived({expected_from}), got {ev:?}"),
        }),
    }
}

fn expect_observe_response(
    ev: MultiProtocolEvent,
    expected_from: UdpAddr,
    expected_observed: UdpAddr,
) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::ObserveResponseReceived { from, observed }
            if from == expected_from && observed == expected_observed =>
        {
            Ok(())
        }
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!(
                "expected ObserveResponseReceived({expected_from}, observed={expected_observed}), got {ev:?}"
            ),
        }),
    }
}

fn expect_pubsub_absorbed(ev: MultiProtocolEvent, expected_topic: &Topic) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::PubsubAbsorbed { topic, .. } if &topic == expected_topic => Ok(()),
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected PubsubAbsorbed for {expected_topic}, got {ev:?}"),
        }),
    }
}

fn expect_pubsub_delivered(
    ev: MultiProtocolEvent,
    expected_topic: &Topic,
    expected_payload: &[u8],
) -> Result<(), Error> {
    match ev {
        MultiProtocolEvent::PubsubDelivered { topic, data, .. } if &topic == expected_topic => {
            let prefix = data
                .get(..expected_payload.len())
                .ok_or_else(|| Error::HostState {
                    reason: "delivered bytes shorter than expected payload".to_owned(),
                })?;
            check(prefix == expected_payload, || {
                format!("delivered payload mismatch: got {prefix:?}, want {expected_payload:?}")
            })
        }
        MultiProtocolEvent::HandshakeProgress { .. }
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
        | MultiProtocolEvent::Rejected { .. } => Err(Error::HostState {
            reason: format!("expected PubsubDelivered for {expected_topic}, got {ev:?}"),
        }),
    }
}

/// Standard-basis-vector `rng_factory` so the `n` pieces sent to a
/// k-of-n decoder are trivially linearly independent.
fn standard_basis_rng()
-> impl Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static {
    let counter = Arc::new(AtomicUsize::new(0));
    move |n: usize| -> Result<Vec<u8>, rlnc_cat_rs::error::Error> {
        let i = counter.fetch_add(1, Ordering::Relaxed);
        Ok((0..n).map(|j| u8::from(j == (i % n))).collect())
    }
}

#[test]
fn mux_carries_app_kad_rendezvous_pubsub_over_one_socket() -> Result<(), Error> {
    // 1. Build muxes.
    let (alice, alice_addr) = build_mux(0xA1)?;
    let (bob, bob_addr) = build_mux(0xB2)?;

    // 2. Pairwise Noise XX handshake.
    let (alice, bob) = handshake_pair(alice, bob, alice_addr, bob_addr, [0x44; 32], [0x55; 32])?;
    check(alice.is_established(bob_addr), || {
        "alice should be established with bob".to_owned()
    })?;
    check(bob.is_established(alice_addr), || {
        "bob should be established with alice".to_owned()
    })?;

    // 3. KIND_APP round trip.
    let alice = alice.send_app(bob_addr, b"hello via mux").run()?;
    let (bob, ev) = bob.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_app_data(ev, alice_addr, b"hello via mux")?;

    // 4. KIND_KAD round trip: alice → bob → alice.
    let alice = alice.kad_ping(bob_addr).run()?;
    let (bob, ev) = bob.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_kad_ping_request(ev, alice_addr)?;
    let (alice, ev) = alice.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_kad_ping_response(ev, bob_addr)?;

    // 5. KIND_RENDEZVOUS round trip: alice asks bob what it sees,
    //    bob auto-replies with alice's bound address.
    let alice = alice.send_observe_req(bob_addr).run()?;
    let (bob, ev) = bob.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_observe_request(ev, alice_addr)?;
    let (alice, ev) = alice.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_observe_response(ev, bob_addr, alice_addr)?;

    // 6. KIND_PUBSUB broadcast: bob registers, alice broadcasts 2
    //    pieces, bob's decoder absorbs the first and decodes on the
    //    second.
    let topic: Topic = "/mux/test".try_into()?;
    let payload: &[u8] = b"hello mux pubsub";
    let piece_count: usize = 2;
    let data = OriginalData::from_bytes(payload, piece_count).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();
    let bob = bob.register_topic(topic.clone(), piece_count, piece_byte_len, ());

    let (_alice_after, ()) = alice
        .broadcast(topic.clone(), data, piece_count, standard_basis_rng())
        .run()?;

    let (bob, ev) = bob.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_pubsub_absorbed(ev, &topic)?;
    let (_bob_after, ev) = bob.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_pubsub_delivered(ev, &topic, payload)?;

    Ok(())
}
