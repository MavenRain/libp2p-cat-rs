//! Authenticated three-node relay using
//! [`rlnc_cat_rs::auth::KeyedHashAuthenticator`].
//!
//! Same line topology as `relay_line.rs` (alice → relay → bob), but
//! every party shares a 32-byte BLAKE3 keyed-hash key.  Each
//! source-emitted piece carries a (commitment, tag) pair the relay
//! and bob can verify; the relay re-tags its recoded outputs with
//! the shared key.  Without the key, an attacker cannot inject a
//! piece that the relay accepts: the second test in this file
//! demonstrates rejection of a tampered piece.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libp2p_cat_host::Host;
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_pubsub::{MuxEvent, PubsubMux, Topic, unused_relay_rng};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use rlnc_cat_rs::auth::{KeyedHashAuthenticator, KeyedHashCommitment};
use rlnc_cat_rs::coding::piece::OriginalData;

type KeyedMux = PubsubMux<KeyedHashAuthenticator>;

const SHARED_KEY: [u8; 32] = [0x42; 32];

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

fn build_mux(seed: u8) -> Result<(KeyedMux, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let keypair = StaticKeypair::from_private_bytes([seed; 32]);
    let identity = Ed25519Keypair::from_seed([seed.wrapping_add(1); 32]);
    let auth = Arc::new(KeyedHashAuthenticator::new(SHARED_KEY));
    Ok((
        PubsubMux::new(Host::new(socket, keypair, &identity)?, auth),
        addr,
    ))
}

fn expect_handshake_progress(ev: MuxEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        MuxEvent::HandshakeProgress { addr } if addr == expected_addr => Ok(()),
        other @ (MuxEvent::HandshakeProgress { .. }
        | MuxEvent::HandshakeComplete { .. }
        | MuxEvent::AppData { .. }
        | MuxEvent::PubsubAbsorbed { .. }
        | MuxEvent::PubsubDelivered { .. }
        | MuxEvent::PubsubRelayed { .. }
        | MuxEvent::Rejected { .. }) => Err(Error::PubsubProtocol {
            reason: format!("expected HandshakeProgress({expected_addr}), got {other:?}"),
        }),
    }
}

fn expect_handshake_complete(ev: MuxEvent, expected_addr: UdpAddr) -> Result<(), Error> {
    match ev {
        MuxEvent::HandshakeComplete { addr, .. } if addr == expected_addr => Ok(()),
        other @ (MuxEvent::HandshakeProgress { .. }
        | MuxEvent::HandshakeComplete { .. }
        | MuxEvent::AppData { .. }
        | MuxEvent::PubsubAbsorbed { .. }
        | MuxEvent::PubsubDelivered { .. }
        | MuxEvent::PubsubRelayed { .. }
        | MuxEvent::Rejected { .. }) => Err(Error::PubsubProtocol {
            reason: format!("expected HandshakeComplete({expected_addr}), got {other:?}"),
        }),
    }
}

fn handshake_pair(
    initiator: KeyedMux,
    responder: KeyedMux,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(KeyedMux, KeyedMux), Error> {
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

fn standard_basis_rng()
-> impl Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static {
    let counter = Arc::new(AtomicUsize::new(0));
    move |n: usize| -> Result<Vec<u8>, rlnc_cat_rs::error::Error> {
        let i = counter.fetch_add(1, Ordering::Relaxed);
        Ok((0..n).map(|j| u8::from(j == (i % n))).collect())
    }
}

fn ones_rng_once()
-> impl FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static {
    |n: usize| Ok(vec![1u8; n])
}

#[test]
fn keyed_hash_relay_decodes_at_downstream() -> Result<(), Error> {
    // Build the three nodes; all share the same BLAKE3 key.
    let (alice, alice_addr) = build_mux(0xA1)?;
    let (relay, relay_addr) = build_mux(0xB2)?;
    let (bob, bob_addr) = build_mux(0xC3)?;

    let (alice, relay) =
        handshake_pair(alice, relay, alice_addr, relay_addr, [0x44; 32], [0x55; 32])?;
    let (bob, relay) = handshake_pair(bob, relay, bob_addr, relay_addr, [0x66; 32], [0x77; 32])?;

    // Out-of-band: compute the commitment from the original data.
    // In a real deployment this would be published alongside the
    // topic name itself.
    let topic: Topic = "/secret-chat/v1".try_into()?;
    let payload: &[u8] = b"hello via authenticated relay";
    let piece_count: usize = 3;
    let data = OriginalData::from_bytes(payload, piece_count).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();
    // Receivers must register before any piece arrives, so the
    // commitment is computed from alice's mux ahead of broadcast.
    let commitment = alice.commit(&data);

    let relay = relay.register_relay(topic.clone(), piece_count, piece_byte_len, commitment);
    let bob = bob.register_topic(topic.clone(), piece_count, piece_byte_len, commitment);

    // Alice broadcasts.  Source signs each piece with the shared
    // BLAKE3 key, and the returned commitment must match the one we
    // registered with the receivers.
    let (_alice_after, broadcast_commitment) = alice
        .broadcast(topic.clone(), data, piece_count, standard_basis_rng())
        .run()?;
    check(
        broadcast_commitment.as_bytes() == commitment.as_bytes(),
        || "broadcast commitment differs from pre-broadcast commitment".to_owned(),
    )?;

    // Relay drains piece_count datagrams.  For each, it verifies the
    // tag, recodes, re-tags with the shared key, and forwards.
    let _relay_after =
        (0..piece_count).try_fold(relay, |relay, idx| -> Result<KeyedMux, Error> {
            let (relay, ev) = relay.recv_one([0; 32], ones_rng_once()).run()?;
            match ev {
                MuxEvent::PubsubRelayed {
                    from,
                    topic: t,
                    fanout_count,
                } if from == alice_addr && t == topic && fanout_count == 1 => Ok(relay),
                other @ (MuxEvent::PubsubRelayed { .. }
                | MuxEvent::PubsubAbsorbed { .. }
                | MuxEvent::PubsubDelivered { .. }
                | MuxEvent::AppData { .. }
                | MuxEvent::HandshakeProgress { .. }
                | MuxEvent::HandshakeComplete { .. }
                | MuxEvent::Rejected { .. }) => Err(Error::PubsubProtocol {
                    reason: format!(
                        "relay piece {idx}: expected PubsubRelayed(from=alice, fanout=1), got {other:?}"
                    ),
                }),
            }
        })?;

    // Bob drains piece_count datagrams.  Each verifies against the
    // shared commitment + key; the third completes the decoder.
    let (_bob_after, bob_data) = (0..piece_count).try_fold(
        (bob, None::<Vec<u8>>),
        |(bob, acc), idx| -> Result<(KeyedMux, Option<Vec<u8>>), Error> {
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
                other @ (MuxEvent::PubsubAbsorbed { .. }
                | MuxEvent::PubsubDelivered { .. }
                | MuxEvent::PubsubRelayed { .. }
                | MuxEvent::AppData { .. }
                | MuxEvent::HandshakeProgress { .. }
                | MuxEvent::HandshakeComplete { .. }
                | MuxEvent::Rejected { .. }) => Err(Error::PubsubProtocol {
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

#[test]
fn keyed_hash_relay_rejects_wrong_commitment() -> Result<(), Error> {
    // The relay registers a different (made-up) commitment from the
    // one alice's pieces will carry.  Every piece's tag will fail
    // verification because the keyed-hash MAC binds (commitment,
    // coding_vector, data) — substituting a different commitment
    // produces a different expected tag.  All three pieces are
    // rejected, none is forwarded.
    let (alice, alice_addr) = build_mux(0xA1)?;
    let (relay, relay_addr) = build_mux(0xB2)?;
    let (bob, bob_addr) = build_mux(0xC3)?;
    let (alice, relay) =
        handshake_pair(alice, relay, alice_addr, relay_addr, [0x44; 32], [0x55; 32])?;
    let (_bob_handshaked, relay) =
        handshake_pair(bob, relay, bob_addr, relay_addr, [0x66; 32], [0x77; 32])?;

    let topic: Topic = "/secret-chat/v1".try_into()?;
    let payload: &[u8] = b"this should be authenticated";
    let piece_count: usize = 3;
    let data = OriginalData::from_bytes(payload, piece_count).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();

    // Wrong commitment: not derived from `data`.
    let wrong_commitment = KeyedHashCommitment::from([0xFFu8; 32]);
    let relay = relay.register_relay(topic.clone(), piece_count, piece_byte_len, wrong_commitment);

    let (_alice_after, _real_commitment) = alice
        .broadcast(topic.clone(), data, piece_count, standard_basis_rng())
        .run()?;

    // Drain piece_count events; each must be MuxEvent::Rejected.
    let _final_relay =
        (0..piece_count).try_fold(relay, |relay, idx| -> Result<KeyedMux, Error> {
            let (relay, ev) = relay.recv_one([0; 32], ones_rng_once()).run()?;
            match ev {
                MuxEvent::Rejected { addr, ref reason }
                    if addr == alice_addr && reason.contains("auth verify failed") =>
                {
                    Ok(relay)
                }
                other @ (MuxEvent::Rejected { .. }
                | MuxEvent::AppData { .. }
                | MuxEvent::PubsubAbsorbed { .. }
                | MuxEvent::PubsubDelivered { .. }
                | MuxEvent::PubsubRelayed { .. }
                | MuxEvent::HandshakeProgress { .. }
                | MuxEvent::HandshakeComplete { .. }) => Err(Error::PubsubProtocol {
                    reason: format!(
                        "piece {idx}: expected Rejected(auth verify failed), got {other:?}"
                    ),
                }),
            }
        })?;
    Ok(())
}
