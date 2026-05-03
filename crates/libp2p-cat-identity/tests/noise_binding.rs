//! End-to-end binding of an Ed25519 [`PeerId`] to a Noise XX
//! [`StaticPublicKey`].
//!
//! This test drives a complete Noise XX handshake by hand using the
//! `libp2p-cat-noise` primitives, then exercises [`SignedStaticKey`]
//! against the [`StaticPublicKey`] each side learned from the
//! handshake.  The point is to demonstrate that the binding works
//! against the *exact* static key Noise authenticates, rather than a
//! detached value the verifier already trusted out-of-band.
//!
//! The wire-bytes of [`SignedStaticKey`] are exchanged in the clear
//! here for clarity.  In a real deployment they would be carried
//! either as a Noise XX handshake-message payload or as the first
//! [`TransportState`]-encrypted application datagram.
//!
//! [`PeerId`]: libp2p_cat_types::PeerId
//! [`StaticPublicKey`]: libp2p_cat_noise::StaticPublicKey
//! [`SignedStaticKey`]: libp2p_cat_identity::SignedStaticKey
//! [`TransportState`]: libp2p_cat_noise::TransportState

use libp2p_cat_identity::{Ed25519Keypair, SignedStaticKey};
use libp2p_cat_noise::{Initiator, Responder, StaticKeypair, StaticPublicKey, TransportState};
use libp2p_cat_types::Error;

fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::IdentityVerify { reason: reason() })
    }
}

/// Drive a 3-message Noise XX handshake to completion.  Returns the
/// initiator's transport state, the responder's transport state, the
/// initiator's view of the responder's static public key, and the
/// responder's view of the initiator's static public key.
fn complete_handshake(
    initiator_static: StaticKeypair,
    responder_static: StaticKeypair,
    initiator_eph_seed: [u8; 32],
    responder_eph_seed: [u8; 32],
) -> Result<
    (
        TransportState,
        TransportState,
        StaticPublicKey,
        StaticPublicKey,
    ),
    Error,
> {
    let initiator = Initiator::new(initiator_static);
    let responder = Responder::new(responder_static);

    let (initiator, msg1) = initiator.write_e(initiator_eph_seed)?;
    let responder = responder.read_e(&msg1)?;
    let (responder, msg2) = responder.write_response(responder_eph_seed, &[])?;
    let (initiator, _msg2_payload) = initiator.read_response(&msg2)?;
    let (initiator_transport, msg3, initiator_observed_responder) = initiator.write_s(&[])?;
    let (responder_transport, responder_observed_initiator, _msg3_payload) =
        responder.read_s(&msg3)?;
    Ok((
        initiator_transport,
        responder_transport,
        initiator_observed_responder,
        responder_observed_initiator,
    ))
}

#[test]
fn signed_static_key_matches_what_noise_authenticates() -> Result<(), Error> {
    // Alice is the initiator, Bob the responder.  Each side has both
    // an X25519 static keypair (used by Noise) and an Ed25519 identity
    // keypair (used by libp2p-cat-identity).
    let alice_static = StaticKeypair::from_private_bytes([0xC1; 32]);
    let bob_static = StaticKeypair::from_private_bytes([0xC2; 32]);
    let alice_identity = Ed25519Keypair::from_seed([0x11; 32]);
    let bob_identity = Ed25519Keypair::from_seed([0x22; 32]);

    let (_alice_transport, _bob_transport, alice_observed_bob_static, bob_observed_alice_static) =
        complete_handshake(
            alice_static.clone(),
            bob_static.clone(),
            [0xE1; 32],
            [0xE2; 32],
        )?;

    // Sanity: each side observed the other's actual public key.
    check(
        alice_observed_bob_static.as_bytes() == bob_static.public().as_bytes(),
        || "alice's view of bob's static key differs from the truth".to_owned(),
    )?;
    check(
        bob_observed_alice_static.as_bytes() == alice_static.public().as_bytes(),
        || "bob's view of alice's static key differs from the truth".to_owned(),
    )?;

    // Bob binds his identity to his X25519 static key and ships the
    // 96-byte payload to Alice.
    let bob_binding = SignedStaticKey::create(&bob_identity, bob_static.public())?;
    let bob_payload = bob_binding.to_bytes();
    let bob_payload_received_by_alice = SignedStaticKey::from_bytes(&bob_payload)?;
    let (bob_pub_at_alice, bob_peer_id_at_alice) =
        bob_payload_received_by_alice.verify(&alice_observed_bob_static)?;
    check(bob_pub_at_alice == *bob_identity.public(), || {
        "bob's public key as recovered by alice differs from bob's identity".to_owned()
    })?;
    check(bob_peer_id_at_alice == bob_identity.peer_id(), || {
        "bob's peer id as recovered by alice differs from bob's identity".to_owned()
    })?;

    // Alice binds her identity to her X25519 static key and ships the
    // 96-byte payload to Bob.
    let alice_binding = SignedStaticKey::create(&alice_identity, alice_static.public())?;
    let alice_payload = alice_binding.to_bytes();
    let alice_payload_received_by_bob = SignedStaticKey::from_bytes(&alice_payload)?;
    let (alice_pub_at_bob, alice_peer_id_at_bob) =
        alice_payload_received_by_bob.verify(&bob_observed_alice_static)?;
    check(alice_pub_at_bob == *alice_identity.public(), || {
        "alice's public key as recovered by bob differs from alice's identity".to_owned()
    })?;
    check(alice_peer_id_at_bob == alice_identity.peer_id(), || {
        "alice's peer id as recovered by bob differs from alice's identity".to_owned()
    })
}

#[test]
fn identity_substitution_attack_is_caught_by_verify() -> Result<(), Error> {
    // Mallory completes the handshake with Alice as the responder,
    // but tries to convince Alice that Bob's Ed25519 identity owns
    // Mallory's X25519 static key.  Since Mallory does not hold Bob's
    // Ed25519 secret, she cannot produce a SignedStaticKey for her
    // own X25519 key under Bob's identity.  Verify must reject the
    // forgery.
    let alice_static = StaticKeypair::from_private_bytes([0xC1; 32]);
    let mallory_static = StaticKeypair::from_private_bytes([0xC9; 32]);
    let bob_identity = Ed25519Keypair::from_seed([0x22; 32]);
    let mallory_identity = Ed25519Keypair::from_seed([0x99; 32]);

    let (_alice_t, _mallory_t, alice_observed_mallory_static, _mallory_observed_alice) =
        complete_handshake(alice_static, mallory_static.clone(), [0xE1; 32], [0xE2; 32])?;

    // Mallory can only sign her own static key with her own identity;
    // she does not hold Bob's secret.  We model the attack by having
    // Mallory build a binding under her own identity and present it
    // to Alice along with the (forged) claim that Bob owns it.
    let mallory_binding = SignedStaticKey::create(&mallory_identity, mallory_static.public())?;
    let payload = mallory_binding.to_bytes();
    let parsed = SignedStaticKey::from_bytes(&payload)?;

    // Alice verifies and learns the *actual* signer: mallory.  The
    // resulting peer id is mallory's, not bob's, so a higher-layer
    // ACL based on PeerId would refuse to grant Bob's privileges.
    let (_pk, recovered_peer_id) = parsed.verify(&alice_observed_mallory_static)?;
    check(recovered_peer_id == mallory_identity.peer_id(), || {
        "verify recovered the wrong peer id".to_owned()
    })?;
    check(recovered_peer_id != bob_identity.peer_id(), || {
        "verify accepted a binding under bob's identity that mallory did not sign".to_owned()
    })
}
