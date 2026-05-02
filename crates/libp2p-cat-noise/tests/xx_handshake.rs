//! End-to-end Noise XX handshake tests.
//!
//! Drives both sides of the handshake to completion using fixed seeds
//! so the test is fully deterministic, then exchanges a transport
//! datagram in each direction to confirm the derived keys agree.

use libp2p_cat_noise::{Initiator, Responder, StaticKeypair, StaticPublicKey};
use libp2p_cat_types::Error;

const ALICE_PRIVATE: [u8; 32] = [0x11; 32];
const BOB_PRIVATE: [u8; 32] = [0x22; 32];
const ALICE_EPH: [u8; 32] = [0x33; 32];
const BOB_EPH: [u8; 32] = [0x44; 32];

fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::NoiseProtocol { reason: reason() })
    }
}

fn check_static_key_eq(
    actual: &StaticPublicKey,
    expected: &StaticPublicKey,
    label: &str,
) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::NoiseProtocol {
            reason: format!("{label}: static key mismatch"),
        })
    }
}

fn expect_noise_protocol<T>(outcome: Result<T, Error>) -> Result<(), Error> {
    match outcome {
        Err(Error::NoiseProtocol { .. }) => Ok(()),
        Err(other) => Err(Error::NoiseProtocol {
            reason: format!("expected NoiseProtocol, got error {other:?}"),
        }),
        Ok(_) => Err(Error::NoiseProtocol {
            reason: "expected NoiseProtocol, got Ok".to_owned(),
        }),
    }
}

fn expect_noise_decrypt<T>(outcome: Result<T, Error>) -> Result<(), Error> {
    match outcome {
        Err(Error::NoiseDecrypt) => Ok(()),
        Err(other) => Err(Error::NoiseProtocol {
            reason: format!("expected NoiseDecrypt, got error {other:?}"),
        }),
        Ok(_) => Err(Error::NoiseProtocol {
            reason: "expected NoiseDecrypt, got Ok".to_owned(),
        }),
    }
}

#[test]
fn xx_handshake_completes_and_keys_agree() -> Result<(), Error> {
    let alice = StaticKeypair::from_private_bytes(ALICE_PRIVATE);
    let bob = StaticKeypair::from_private_bytes(BOB_PRIVATE);

    let alice_pub = alice.public().clone();
    let bob_pub = bob.public().clone();

    let (alice_after_e, msg1) = Initiator::new(alice).write_e(ALICE_EPH)?;

    let bob_after_e = Responder::new(bob).read_e(&msg1)?;
    let (bob_after_response, msg2) = bob_after_e.write_response(BOB_EPH)?;

    let alice_after_response = alice_after_e.read_response(&msg2)?;
    check_static_key_eq(
        alice_after_response.remote_static(),
        &bob_pub,
        "initiator after msg2",
    )?;
    let (alice_transport, msg3, alice_observed_bob_static) = alice_after_response.write_s()?;
    check_static_key_eq(&alice_observed_bob_static, &bob_pub, "write_s output")?;

    let (bob_transport, bob_observed_alice_static) = bob_after_response.read_s(&msg3)?;
    check_static_key_eq(
        &bob_observed_alice_static,
        &alice_pub,
        "responder after msg3",
    )?;

    // Round-trip a payload in each direction.
    let alice_to_bob = b"alice -> bob".to_vec();
    let bob_to_alice = b"bob -> alice (longer message with entropy)".to_vec();

    let (alice_transport, datagram_a2b) = alice_transport.encrypt(&alice_to_bob)?;
    let (bob_transport, recovered_a2b) = bob_transport.decrypt(&datagram_a2b)?;
    check(recovered_a2b == alice_to_bob, || {
        format!("a->b mismatch: got {recovered_a2b:?}")
    })?;

    let (_bob_transport, datagram_b2a) = bob_transport.encrypt(&bob_to_alice)?;
    let (_alice_transport, recovered_b2a) = alice_transport.decrypt(&datagram_b2a)?;
    check(recovered_b2a == bob_to_alice, || {
        format!("b->a mismatch: got {recovered_b2a:?}")
    })
}

#[test]
fn xx_rejects_truncated_message_2() -> Result<(), Error> {
    let alice = StaticKeypair::from_private_bytes(ALICE_PRIVATE);
    let bob = StaticKeypair::from_private_bytes(BOB_PRIVATE);
    let (alice_after_e, msg1) = Initiator::new(alice).write_e(ALICE_EPH)?;
    let bob_after_e = Responder::new(bob).read_e(&msg1)?;
    let (_bob_after_response, msg2) = bob_after_e.write_response(BOB_EPH)?;

    let truncated = msg2
        .get(..msg2.len() - 1)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    expect_noise_protocol(alice_after_e.read_response(&truncated))
}

#[test]
fn xx_rejects_tampered_message_2() -> Result<(), Error> {
    let alice = StaticKeypair::from_private_bytes(ALICE_PRIVATE);
    let bob = StaticKeypair::from_private_bytes(BOB_PRIVATE);
    let (alice_after_e, msg1) = Initiator::new(alice).write_e(ALICE_EPH)?;
    let bob_after_e = Responder::new(bob).read_e(&msg1)?;
    let (_bob_after_response, msg2) = bob_after_e.write_response(BOB_EPH)?;

    // Flip the last byte of the encrypted-static segment.
    let tampered: Vec<u8> = msg2
        .iter()
        .enumerate()
        .map(|(i, &b)| if i == 32 + 47 { b ^ 0x01 } else { b })
        .collect();
    expect_noise_decrypt(alice_after_e.read_response(&tampered))
}

#[test]
fn xx_rejects_message_1_with_wrong_length() -> Result<(), Error> {
    let bob = StaticKeypair::from_private_bytes(BOB_PRIVATE);
    expect_noise_protocol(Responder::new(bob).read_e(&[0u8; 31]))
}

#[test]
fn xx_initiator_sees_bob_public_before_writing_message_3() -> Result<(), Error> {
    let alice = StaticKeypair::from_private_bytes(ALICE_PRIVATE);
    let bob = StaticKeypair::from_private_bytes(BOB_PRIVATE);
    let bob_pub = bob.public().clone();

    let (alice_after_e, msg1) = Initiator::new(alice).write_e(ALICE_EPH)?;
    let bob_after_e = Responder::new(bob).read_e(&msg1)?;
    let (_bob_after_response, msg2) = bob_after_e.write_response(BOB_EPH)?;
    let alice_after_response = alice_after_e.read_response(&msg2)?;

    check_static_key_eq(
        alice_after_response.remote_static(),
        &bob_pub,
        "initiator should authenticate bob before msg3",
    )
}
