//! Homomorphic three-node relay using
//! [`rlnc_cat_rs::lhs::LatticeHomomorphicAuthenticator`].
//!
//! Same line topology as `keyed_hash_relay.rs` (alice → relay → bob),
//! but with a critical difference: the relay holds **no** secret key.
//! It re-tags the recoded pieces it forwards using only the public
//! transcript `(pk, metadata, σ_originals)` it received out-of-band
//! from the source.  The combine operation
//! `σ = Σ cv_i · σ_originals_i` lifts to a new valid signature on the
//! recoded piece without ever touching `sk`, so a passive relay
//! cannot forge new signatures and an active relay can only authenticate
//! pieces that lie in the linear span of the source's originals.
//!
//! The second test exercises the rejection path: when a relay is
//! registered with a commitment from a *different* generation
//! (different metadata), every inbound piece's commitment differs
//! from the registered one and verification fails before recoding.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use libp2p_cat_host::Host;
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_pubsub::{MuxEvent, PubsubMux, Topic, unused_relay_rng};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use rlnc_cat_rs::coding::piece::OriginalData;
use rlnc_cat_rs::lhs::{
    LatticeHomomorphicAuthenticator, LhsParams, PublicKey, SecretKey, Signature, keygen,
};

/// Modulus for the test scheme; small enough to keep the lattice
/// arithmetic fast.
const Q: u32 = 97;

/// `n`: rows of the public matrix `A`.
const PARAM_N: usize = 2;

/// `m0`: width of the primary block `A_0`.
const PARAM_M0: usize = 2;

/// `k_pieces`: number of original pieces in the generation.  Must
/// match the `piece_count` argument we pass to
/// [`OriginalData::from_bytes`] below.
const PARAM_K: usize = 3;

/// Squared norm bound for verification.  The readme example uses
/// `10_000_000`; we go higher for headroom on the small `Q` we
/// chose.
const SIG_NORM_BOUND_SQ: u128 = 100_000_000;

/// Klein-sampler width.  3.0 is comfortable for `Q ≤ 2^16`.
const SIGMA_G: f64 = 3.0;

type LhsAuth = LatticeHomomorphicAuthenticator<Q>;
type LhsMux = PubsubMux<LhsAuth>;

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

/// Deterministic counter-driven RNG for reproducible tests.  Each
/// call increments an atomic counter, packs the running counter as
/// little-endian bytes, and returns the requested length.
fn counter_rng(
    seed: u64,
) -> impl Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static {
    let counter = Arc::new(AtomicU64::new(seed));
    move |n: usize| {
        let blocks = n.div_ceil(8);
        let bytes: Vec<u8> = (0..blocks)
            .flat_map(|_| counter.fetch_add(1, Ordering::Relaxed).to_le_bytes())
            .take(n)
            .collect();
        Ok(bytes)
    }
}

fn lhs_params() -> Result<LhsParams<Q>, Error> {
    LhsParams::<Q>::new(PARAM_N, PARAM_M0, PARAM_K, SIG_NORM_BOUND_SQ, SIGMA_G).map_err(|e| {
        Error::RlncLayer {
            reason: e.to_string(),
        }
    })
}

fn lhs_keygen(seed: u64) -> Result<(PublicKey<Q>, SecretKey<Q>), Error> {
    let params = lhs_params()?;
    let rng = counter_rng(seed);
    keygen(params, &rng).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })
}

fn source_auth(
    pk: PublicKey<Q>,
    sk: &SecretKey<Q>,
    metadata: &[u8],
    rng_seed: u64,
) -> Result<LhsAuth, Error> {
    let rng = counter_rng(rng_seed);
    LatticeHomomorphicAuthenticator::<Q>::new(pk, sk, metadata, &rng).map_err(|e| {
        Error::RlncLayer {
            reason: e.to_string(),
        }
    })
}

fn public_auth(
    pk: PublicKey<Q>,
    metadata: &[u8],
    signed_originals: Vec<Signature>,
) -> Result<LhsAuth, Error> {
    LatticeHomomorphicAuthenticator::<Q>::from_public_artifacts(pk, metadata, signed_originals)
        .map_err(|e| Error::RlncLayer {
            reason: e.to_string(),
        })
}

fn build_mux(seed: u8, auth: Arc<LhsAuth>) -> Result<(LhsMux, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let keypair = StaticKeypair::from_private_bytes([seed; 32]);
    let identity = Ed25519Keypair::from_seed([seed.wrapping_add(1); 32]);
    Ok((
        PubsubMux::new(
            Host::new(socket, keypair, &identity, [seed.wrapping_add(2); 32])?,
            auth,
        ),
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
        | MuxEvent::PubsubRedundant { .. }
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
        | MuxEvent::PubsubRedundant { .. }
        | MuxEvent::Rejected { .. }) => Err(Error::PubsubProtocol {
            reason: format!("expected HandshakeComplete({expected_addr}), got {other:?}"),
        }),
    }
}

fn handshake_pair(
    initiator: LhsMux,
    responder: LhsMux,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(LhsMux, LhsMux), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    // Cookie round-trip then the three Noise messages.
    let (responder, ev) = responder
        .recv_one(responder_seed, unused_relay_rng())
        .run()?;
    expect_handshake_progress(ev, initiator_addr)?;
    let (initiator, ev) = initiator.recv_one([0; 32], unused_relay_rng()).run()?;
    expect_handshake_progress(ev, responder_addr)?;
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
fn lhs_relay_decodes_at_downstream_with_public_only_relay() -> Result<(), Error> {
    // 1. Out-of-band setup: keygen, source signs the originals, the
    // public transcript (pk, metadata, signed_originals) is shared
    // with the relay and bob.
    let (pk, sk) = lhs_keygen(0xCAFE)?;
    let metadata: &[u8] = b"libp2p-cat lhs relay test/v1";
    let alice_auth = source_auth(pk.clone(), &sk, metadata, 0x00C0_FFEE)?;
    let signed_originals = alice_auth.signed_originals().to_vec();

    // 2. Relay and bob rebuild from the public transcript: no sk.
    let relay_auth = public_auth(pk.clone(), metadata, signed_originals.clone())?;
    let bob_auth = public_auth(pk, metadata, signed_originals)?;

    // 3. Build muxes and complete handshakes.
    let (alice, alice_addr) = build_mux(0xA1, Arc::new(alice_auth))?;
    let (relay, relay_addr) = build_mux(0xB2, Arc::new(relay_auth))?;
    let (bob, bob_addr) = build_mux(0xC3, Arc::new(bob_auth))?;
    let (alice, relay) =
        handshake_pair(alice, relay, alice_addr, relay_addr, [0x44; 32], [0x55; 32])?;
    let (bob, relay) = handshake_pair(bob, relay, bob_addr, relay_addr, [0x66; 32], [0x77; 32])?;

    // 4. The original payload, padded to PARAM_K pieces.
    let topic: Topic = "/lhs/v1".try_into()?;
    let payload: &[u8] = b"hello via homomorphic relay";
    let data = OriginalData::from_bytes(payload, PARAM_K).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();
    let commitment = alice.commit(&data);
    let relay = relay.register_relay(topic.clone(), PARAM_K, piece_byte_len, commitment);
    let bob = bob.register_topic(topic.clone(), PARAM_K, piece_byte_len, commitment);

    // 5. Alice broadcasts.  The source-side auth signs each emitted
    // piece with sk-derived material, but the wire only carries
    // (commitment, σ_combined) and the receivers verify with the
    // public artefacts they already hold.
    let (_alice_after, broadcast_commitment) = alice
        .broadcast(topic.clone(), data, PARAM_K, standard_basis_rng())
        .run()?;
    check(
        broadcast_commitment.as_bytes() == commitment.as_bytes(),
        || "broadcast commitment differs from pre-broadcast commitment".to_owned(),
    )?;

    // 6. Relay drains PARAM_K datagrams.  For each, it verifies the
    // tag against the registered commitment, recodes by random
    // linear combination, **homomorphically** re-tags using only
    // (pk, metadata, σ_originals), and forwards.
    let _relay_after = (0..PARAM_K).try_fold(relay, |relay, idx| -> Result<LhsMux, Error> {
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
            | MuxEvent::PubsubRedundant { .. }
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

    // 7. Bob drains PARAM_K datagrams.  Each verifies against the
    // shared commitment + LHS public key; the third completes the
    // decoder.
    let (_bob_after, bob_data) = (0..PARAM_K).try_fold(
        (bob, None::<Vec<u8>>),
        |(bob, acc), idx| -> Result<(LhsMux, Option<Vec<u8>>), Error> {
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
                | MuxEvent::PubsubRedundant { .. }
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
fn lhs_relay_rejects_pieces_from_a_different_generation() -> Result<(), Error> {
    // Setup two independent generations under the same keypair: one
    // that alice will broadcast, and one whose commitment the relay
    // is registered with.  Every inbound tag verifies against
    // alice's commitment, never the relay's, so verify rejects every
    // piece before the recoder gets to add it.
    let (pk, sk) = lhs_keygen(0xCAFE)?;
    let metadata_alice: &[u8] = b"libp2p-cat lhs relay test/genA";
    let metadata_other: &[u8] = b"libp2p-cat lhs relay test/genB";
    let alice_auth = source_auth(pk.clone(), &sk, metadata_alice, 0x00C0_FFEE)?;
    let alice_originals = alice_auth.signed_originals().to_vec();

    // The relay holds a different generation's transcript.
    let other_auth_for_relay = source_auth(pk.clone(), &sk, metadata_other, 0xDEAD)?;
    let other_originals = other_auth_for_relay.signed_originals().to_vec();
    let relay_auth = public_auth(pk.clone(), metadata_other, other_originals)?;
    let bob_auth = public_auth(pk, metadata_alice, alice_originals)?;
    let other_commitment = *other_auth_for_relay.commitment();

    let (alice, alice_addr) = build_mux(0xA1, Arc::new(alice_auth))?;
    let (relay, relay_addr) = build_mux(0xB2, Arc::new(relay_auth))?;
    let (bob, bob_addr) = build_mux(0xC3, Arc::new(bob_auth))?;
    let (alice, relay) =
        handshake_pair(alice, relay, alice_addr, relay_addr, [0x44; 32], [0x55; 32])?;
    let (_bob_handshaked, relay) =
        handshake_pair(bob, relay, bob_addr, relay_addr, [0x66; 32], [0x77; 32])?;

    let topic: Topic = "/lhs/v1".try_into()?;
    let payload: &[u8] = b"this should be rejected at relay";
    let data = OriginalData::from_bytes(payload, PARAM_K).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();

    // The relay registers under the *other* generation's
    // commitment.
    let relay = relay.register_relay(topic.clone(), PARAM_K, piece_byte_len, other_commitment);

    let (_alice_after, _alice_commitment) = alice
        .broadcast(topic.clone(), data, PARAM_K, standard_basis_rng())
        .run()?;

    // Drain PARAM_K events; each must be MuxEvent::Rejected with a
    // verify-failure reason.
    let _final_relay = (0..PARAM_K).try_fold(relay, |relay, idx| -> Result<LhsMux, Error> {
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
            | MuxEvent::PubsubRedundant { .. }
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
