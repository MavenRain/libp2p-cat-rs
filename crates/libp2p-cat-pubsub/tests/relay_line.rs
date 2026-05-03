//! Three-node line topology with an RLNC relay in the middle:
//!
//! ```text
//! +-------+        +---------+        +-----+
//! | alice | -----> |  relay  | -----> | bob |
//! +-------+        +---------+        +-----+
//! ```
//!
//! Alice has only one peer (the relay).  Bob has only one peer (also
//! the relay).  Alice and Bob are not directly connected.
//!
//! Alice broadcasts a 3-piece generation on a topic.  The relay is
//! registered with [`PubsubMux::register_relay`] for that topic, so
//! every inbound piece is added to a local recoder, recoded by
//! taking a fresh random linear combination of the buffered pieces,
//! and forwarded to every peer except the source.  In our line
//! topology the only such peer is Bob, who is registered as the
//! decoder for the topic.
//!
//! Determinism: the relay uses an "all ones" `rng_factory`.  After
//! buffering `i+1` pieces, the recoded coding vector is `[1; i+1]`,
//! so the i-th recoded piece is the sum of the first `i+1` original
//! pieces.  The three coding vectors `(1,0,0)`, `(1,1,0)`, `(1,1,1)`
//! form a lower-triangular matrix with non-zero determinant in
//! GF(2^8); Bob receives three linearly-independent pieces and
//! decodes the original.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libp2p_cat_host::Host;
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_pubsub::{MuxEvent, PubsubMux, Topic, unused_relay_rng};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use rlnc_cat_rs::auth::NullAuthenticator;
use rlnc_cat_rs::coding::piece::OriginalData;

type NullMux = PubsubMux<NullAuthenticator>;

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

fn build_mux(seed: u8) -> Result<(NullMux, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let keypair = StaticKeypair::from_private_bytes([seed; 32]);
    let auth = Arc::new(NullAuthenticator);
    Ok((PubsubMux::new(Host::new(socket, keypair), auth), addr))
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

/// Drive a Noise XX handshake to completion between two muxes over
/// real UDP datagrams.
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

/// Standard-basis-vector rng for the source: emits `[0,...,1,...,0]`
/// with the `1` at position `i mod n`, so the first `n` requested
/// vectors are linearly independent.
fn standard_basis_rng()
-> impl Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static {
    let counter = Arc::new(AtomicUsize::new(0));
    move |n: usize| -> Result<Vec<u8>, rlnc_cat_rs::error::Error> {
        let i = counter.fetch_add(1, Ordering::Relaxed);
        Ok((0..n).map(|j| u8::from(j == (i % n))).collect())
    }
}

/// All-ones `rng_factory` for the relay: every coefficient is `1`.
/// Each call returns a fresh `FnOnce` of length `n`.
fn ones_rng_once()
-> impl FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static {
    |n: usize| Ok(vec![1u8; n])
}

#[test]
fn relay_line_decodes_at_downstream() -> Result<(), Error> {
    // 1. Build muxes.
    let (alice, alice_addr) = build_mux(0xA1)?;
    let (relay, relay_addr) = build_mux(0xB2)?;
    let (bob, bob_addr) = build_mux(0xC3)?;

    // 2. Two pairwise handshakes: alice<->relay and bob<->relay.
    let (alice, relay) =
        handshake_pair(alice, relay, alice_addr, relay_addr, [0x44; 32], [0x55; 32])?;
    let (bob, relay) = handshake_pair(bob, relay, bob_addr, relay_addr, [0x66; 32], [0x77; 32])?;

    check(alice.is_established(relay_addr), || {
        "alice should be established with the relay".to_owned()
    })?;
    check(bob.is_established(relay_addr), || {
        "bob should be established with the relay".to_owned()
    })?;
    check(relay.is_established(alice_addr), || {
        "relay should be established with alice".to_owned()
    })?;
    check(relay.is_established(bob_addr), || {
        "relay should be established with bob".to_owned()
    })?;

    // 3. Topic registration: relay as recoder, bob as decoder.  Alice
    // does not register; she's a pure source.
    let topic: Topic = "/chat/v1".try_into()?;
    let payload: &[u8] = b"hello via relay";
    let piece_count: usize = 3;
    let data = OriginalData::from_bytes(payload, piece_count).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();
    let relay = relay.register_relay(topic.clone(), piece_count, piece_byte_len, ());
    let bob = bob.register_topic(topic.clone(), piece_count, piece_byte_len, ());

    // 4. Alice broadcasts piece_count frames; her only peer is the
    // relay, so all three datagrams land at the relay's inbox.
    let (_alice_after, ()) = alice
        .broadcast(topic.clone(), data, piece_count, standard_basis_rng())
        .run()?;

    // 5. Relay drains piece_count datagrams.  For each, the recoder
    // adds the piece, recodes by random linear combination, and
    // forwards the recoded piece to every peer except the source —
    // i.e. just bob.  Each call yields a `PubsubRelayed` event with
    // `fanout_count == 1`.
    let relay_after = (0..piece_count).try_fold(relay, |relay, idx| -> Result<NullMux, Error> {
        let (relay, ev) = relay.recv_one([0; 32], ones_rng_once()).run()?;
        match ev {
            MuxEvent::PubsubRelayed {
                from,
                topic: t,
                fanout_count,
            } if from == alice_addr && t == topic && fanout_count == 1 => Ok(relay),
            other => Err(Error::PubsubProtocol {
                reason: format!(
                    "relay piece {idx}: expected PubsubRelayed(from=alice, fanout=1), got {other:?}"
                ),
            }),
        }
    })?;
    drop(relay_after);

    // 6. Bob drains piece_count datagrams.  The third absorbed piece
    // completes the decoder.
    let (_bob_after, bob_data) = (0..piece_count).try_fold(
        (bob, None::<Vec<u8>>),
        |(bob, acc), idx| -> Result<(NullMux, Option<Vec<u8>>), Error> {
            let (bob, ev) = bob.recv_one([0; 32], unused_relay_rng()).run()?;
            match ev {
                MuxEvent::PubsubAbsorbed { addr, topic: t } if addr == relay_addr && t == topic => {
                    Ok((bob, acc))
                }
                MuxEvent::PubsubDelivered {
                    addr,
                    topic: t,
                    data,
                } if addr == relay_addr && t == topic => Ok((bob, Some(data))),
                other => Err(Error::PubsubProtocol {
                    reason: format!("bob piece {idx}: unexpected event {other:?}"),
                }),
            }
        },
    )?;

    let bob_data = bob_data.ok_or_else(|| Error::PubsubProtocol {
        reason: "bob never observed a PubsubDelivered".to_owned(),
    })?;
    let bob_prefix = bob_data
        .get(..payload.len())
        .ok_or_else(|| Error::PubsubProtocol {
            reason: "bob's reconstructed bytes shorter than payload".to_owned(),
        })?;
    check(bob_prefix == payload, || {
        format!("bob payload mismatch: got {bob_prefix:?}")
    })
}
