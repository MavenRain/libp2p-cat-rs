//! End-to-end three-node RLNC pubsub broadcast over real loopback UDP,
//! driven through [`PubsubMux`] which itself sits on top of
//! [`libp2p_cat_host::Host`].  The Noise XX handshakes for each
//! Alice-Bob and Alice-Carol pair run as real on-the-wire exchanges,
//! not the in-memory shortcut used in earlier iterations.
//!
//! Bob and Carol register the topic `/chat/v1` with `k = 3, b = 8`
//! after handshakes complete.  Alice broadcasts an `OriginalData` of
//! 18 bytes split into 3 pieces.  Each receiver pulls three datagrams
//! off its socket; the third absorbed piece completes the decoder
//! and emits `MuxEvent::PubsubDelivered` carrying the reconstructed
//! payload.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libp2p_cat_host::Host;
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_pubsub::{MuxEvent, PubsubMux, Topic, unused_relay_rng};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use rlnc_cat_rs::coding::piece::OriginalData;

fn loopback_v4() -> UdpAddr {
    UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::PubsubProtocol { reason: reason() })
    }
}

fn expect_handshake_progress(ev: MuxEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        MuxEvent::HandshakeProgress { addr } if addr == expected_addr => Ok(()),
        other => Err(Error::PubsubProtocol {
            reason: format!("expected HandshakeProgress({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_handshake_complete(ev: MuxEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        MuxEvent::HandshakeComplete { addr, .. } if addr == expected_addr => Ok(()),
        other => Err(Error::PubsubProtocol {
            reason: format!("expected HandshakeComplete({expected_addr}), got {other:?}"),
        }),
    }
}

/// Standard-basis-vector `rng_factory`: emits `[0,...,0,1,0,...,0]`
/// with the `1` at position `i mod n`, so the first `n` requested
/// vectors are trivially linearly independent and a receiver decodes
/// after exactly `n` pieces.
fn standard_basis_rng()
-> impl Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static {
    let counter = Arc::new(AtomicUsize::new(0));
    move |n: usize| -> Result<Vec<u8>, rlnc_cat_rs::error::Error> {
        let i = counter.fetch_add(1, Ordering::Relaxed);
        Ok((0..n).map(|j| u8::from(j == (i % n))).collect())
    }
}

/// Bind a socket, derive a static keypair from the seed, wrap the
/// pair in a [`PubsubMux`].
fn build_mux(seed: u8) -> Result<(PubsubMux, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let keypair = StaticKeypair::from_private_bytes([seed; 32]);
    Ok((PubsubMux::new(Host::new(socket, keypair)), addr))
}

/// Drive a single Noise XX handshake to completion between two muxes
/// over real UDP datagrams.
fn handshake_pair(
    initiator: PubsubMux,
    responder: PubsubMux,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(PubsubMux, PubsubMux), Error> {
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

/// Pull `n` events off `mux` and find the [`MuxEvent::PubsubDelivered`]
/// that matches `topic`.  Returns the reconstructed payload bytes.
fn drain_until_delivery(
    mux: PubsubMux,
    n: usize,
    topic: &Topic,
) -> Result<(PubsubMux, Vec<u8>), Error> {
    let (mux, events) = (0..n).try_fold(
        (mux, Vec::<MuxEvent>::new()),
        |(mux, events), _| -> Result<(PubsubMux, Vec<MuxEvent>), Error> {
            let (mux, ev) = mux.recv_one([0; 32], unused_relay_rng()).run()?;
            let next: Vec<MuxEvent> = events.into_iter().chain(core::iter::once(ev)).collect();
            Ok((mux, next))
        },
    )?;
    let delivered = events
        .into_iter()
        .find_map(|ev| match ev {
            MuxEvent::PubsubDelivered { topic: t, data, .. } if t == *topic => Some(data),
            MuxEvent::PubsubDelivered { .. }
            | MuxEvent::PubsubAbsorbed { .. }
            | MuxEvent::PubsubRelayed { .. }
            | MuxEvent::AppData { .. }
            | MuxEvent::HandshakeProgress { .. }
            | MuxEvent::HandshakeComplete { .. }
            | MuxEvent::Rejected { .. } => None,
        })
        .ok_or_else(|| Error::PubsubProtocol {
            reason: format!("no PubsubDelivered event for topic {topic} in stream"),
        })?;
    Ok((mux, delivered))
}

#[test]
fn three_node_rlnc_broadcast_decodes_at_both_receivers() -> Result<(), Error> {
    // 1. Build muxes for Alice, Bob, Carol with stable static keys.
    let (alice, alice_addr) = build_mux(0xA1)?;
    let (bob, bob_addr) = build_mux(0xB2)?;
    let (carol, carol_addr) = build_mux(0xC3)?;

    // 2. Pairwise handshakes over real UDP.  Each pair completes the
    // 3-message XX flow before we start broadcasting.
    let (alice, bob) = handshake_pair(alice, bob, alice_addr, bob_addr, [0x44; 32], [0x55; 32])?;
    let (alice, carol) =
        handshake_pair(alice, carol, alice_addr, carol_addr, [0x66; 32], [0x77; 32])?;

    check(alice.is_established(bob_addr), || {
        "alice should be established with bob".to_owned()
    })?;
    check(alice.is_established(carol_addr), || {
        "alice should be established with carol".to_owned()
    })?;
    check(bob.is_established(alice_addr), || {
        "bob should be established with alice".to_owned()
    })?;
    check(carol.is_established(alice_addr), || {
        "carol should be established with alice".to_owned()
    })?;

    // 3. Receivers register the topic so inbound pubsub frames can be
    // absorbed into a freshly-initialised decoder.
    let topic: Topic = "/chat/v1".try_into()?;
    let payload: &[u8] = b"hello pubsub world";
    let piece_count: usize = 3;
    let data = OriginalData::from_bytes(payload, piece_count).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();
    let bob = bob.register_topic(topic.clone(), piece_count, piece_byte_len);
    let carol = carol.register_topic(topic.clone(), piece_count, piece_byte_len);

    // 4. Alice broadcasts piece_count frames, fanned out to both peers.
    let _alice_after = alice
        .broadcast(topic.clone(), data, piece_count, standard_basis_rng())
        .run()?;

    // 5. Each receiver pulls piece_count events; one of them should
    // be the PubsubDelivered carrying the decoded payload.
    let (_bob_after, bob_data) = drain_until_delivery(bob, piece_count, &topic)?;
    let (_carol_after, carol_data) = drain_until_delivery(carol, piece_count, &topic)?;

    let bob_prefix = bob_data
        .get(..payload.len())
        .ok_or_else(|| Error::PubsubProtocol {
            reason: "bob's reconstructed bytes shorter than payload".to_owned(),
        })?;
    let carol_prefix = carol_data
        .get(..payload.len())
        .ok_or_else(|| Error::PubsubProtocol {
            reason: "carol's reconstructed bytes shorter than payload".to_owned(),
        })?;
    check(bob_prefix == payload, || "bob payload mismatch".to_owned())?;
    check(carol_prefix == payload, || {
        "carol payload mismatch".to_owned()
    })
}

#[test]
fn app_data_passes_through_mux() -> Result<(), Error> {
    // Two muxes, full handshake, then an app-data round trip.  Proves
    // the KIND_APP path works alongside the pubsub path.
    let (alice, alice_addr) = build_mux(0xD1)?;
    let (bob, bob_addr) = build_mux(0xE2)?;
    let (alice, bob) = handshake_pair(alice, bob, alice_addr, bob_addr, [0x10; 32], [0x20; 32])?;

    let _alice_after = alice.send_app(bob_addr, b"hello via mux").run()?;
    let (_bob_after, ev) = bob.recv_one([0; 32], unused_relay_rng()).run()?;
    match ev {
        MuxEvent::AppData { addr, bytes } if addr == alice_addr && bytes == b"hello via mux" => {
            Ok(())
        }
        other => Err(Error::PubsubProtocol {
            reason: format!("expected AppData, got {other:?}"),
        }),
    }
}
