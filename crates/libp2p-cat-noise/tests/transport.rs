//! Transport-layer tests: encryption round-trip, tamper rejection,
//! replay rejection, out-of-order acceptance.
//!
//! Drives the XX handshake to completion with fixed seeds, then
//! exercises [`TransportState`] directly.

use libp2p_cat_noise::{Initiator, Responder, StaticKeypair, TransportState};
use libp2p_cat_types::Error;

const ALICE_PRIVATE: [u8; 32] = [0x55; 32];
const BOB_PRIVATE: [u8; 32] = [0x66; 32];
const ALICE_EPH: [u8; 32] = [0x77; 32];
const BOB_EPH: [u8; 32] = [0x88; 32];

fn established_pair() -> Result<(TransportState, TransportState), Error> {
    let alice = StaticKeypair::from_private_bytes(ALICE_PRIVATE);
    let bob = StaticKeypair::from_private_bytes(BOB_PRIVATE);
    let (alice_after_e, msg1) = Initiator::new(alice).write_e(ALICE_EPH)?;
    let bob_after_e = Responder::new(bob).read_e(&msg1)?;
    let (bob_after_response, msg2) = bob_after_e.write_response(BOB_EPH)?;
    let alice_after_response = alice_after_e.read_response(&msg2)?;
    let (alice_transport, msg3, _) = alice_after_response.write_s()?;
    let (bob_transport, _) = bob_after_response.read_s(&msg3)?;
    Ok((alice_transport, bob_transport))
}

fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::NoiseProtocol { reason: reason() })
    }
}

fn expect_decrypt_failure(outcome: Result<(TransportState, Vec<u8>), Error>) -> Result<(), Error> {
    match outcome {
        Err(Error::NoiseDecrypt) => Ok(()),
        Err(
            other @ (Error::Io(_)
            | Error::InvalidProtocolId { .. }
            | Error::InvalidPeerId { .. }
            | Error::DatagramTooLarge { .. }
            | Error::NoiseProtocol { .. }
            | Error::NoiseReplay { .. }
            | Error::RlncLayer { .. }
            | Error::PubsubProtocol { .. }
            | Error::HostState { .. }),
        ) => Err(Error::NoiseProtocol {
            reason: format!("expected NoiseDecrypt, got {other:?}"),
        }),
        Ok((_state, _bytes)) => Err(Error::NoiseProtocol {
            reason: "expected NoiseDecrypt, got Ok".to_owned(),
        }),
    }
}

fn expect_replay(
    outcome: Result<(TransportState, Vec<u8>), Error>,
    expected_nonce: u64,
) -> Result<(), Error> {
    match outcome {
        Err(Error::NoiseReplay { nonce }) if nonce == expected_nonce => Ok(()),
        Err(
            other @ (Error::Io(_)
            | Error::InvalidProtocolId { .. }
            | Error::InvalidPeerId { .. }
            | Error::DatagramTooLarge { .. }
            | Error::NoiseDecrypt
            | Error::NoiseProtocol { .. }
            | Error::NoiseReplay { .. }
            | Error::RlncLayer { .. }
            | Error::PubsubProtocol { .. }
            | Error::HostState { .. }),
        ) => Err(Error::NoiseProtocol {
            reason: format!("expected NoiseReplay {{ nonce: {expected_nonce} }}, got {other:?}"),
        }),
        Ok((_state, _bytes)) => Err(Error::NoiseProtocol {
            reason: format!("expected NoiseReplay, got Ok at nonce {expected_nonce}"),
        }),
    }
}

fn expect_protocol_violation(
    outcome: Result<(TransportState, Vec<u8>), Error>,
) -> Result<(), Error> {
    match outcome {
        Err(Error::NoiseProtocol { .. }) => Ok(()),
        Err(
            other @ (Error::Io(_)
            | Error::InvalidProtocolId { .. }
            | Error::InvalidPeerId { .. }
            | Error::DatagramTooLarge { .. }
            | Error::NoiseDecrypt
            | Error::NoiseReplay { .. }
            | Error::RlncLayer { .. }
            | Error::PubsubProtocol { .. }
            | Error::HostState { .. }),
        ) => Err(Error::NoiseProtocol {
            reason: format!("expected NoiseProtocol, got {other:?}"),
        }),
        Ok((_state, _bytes)) => Err(Error::NoiseProtocol {
            reason: "expected NoiseProtocol, got Ok".to_owned(),
        }),
    }
}

#[test]
fn encrypt_decrypt_round_trip() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let plaintext = b"the quick brown fox".to_vec();
    let expected = plaintext.clone();
    let (_alice, datagram) = alice.encrypt(&plaintext)?;
    let (_bob, recovered) = bob.decrypt(&datagram)?;
    check(recovered == expected, || {
        format!("round-trip mismatch: {recovered:?}")
    })
}

#[test]
fn tampered_ciphertext_is_rejected() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let (_alice, datagram) = alice.encrypt(b"hello")?;
    let tampered: Vec<u8> = datagram
        .iter()
        .enumerate()
        .map(|(i, &b)| if i == 10 { b ^ 0x80 } else { b })
        .collect();
    expect_decrypt_failure(bob.decrypt(&tampered))
}

#[test]
fn replayed_datagram_is_rejected() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let (_alice, datagram) = alice.encrypt(b"once")?;
    let (bob, _first) = bob.decrypt(&datagram)?;
    expect_replay(bob.decrypt(&datagram), 0)
}

#[test]
fn out_of_order_within_window_is_accepted() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let (alice, dg0) = alice.encrypt(b"first")?;
    let (alice, dg1) = alice.encrypt(b"second")?;
    let (_alice, dg2) = alice.encrypt(b"third")?;
    let (bob, p2) = bob.decrypt(&dg2)?;
    check(p2 == b"third", || format!("p2 mismatch: {p2:?}"))?;
    let (bob, p0) = bob.decrypt(&dg0)?;
    check(p0 == b"first", || format!("p0 mismatch: {p0:?}"))?;
    let (_bob, p1) = bob.decrypt(&dg1)?;
    check(p1 == b"second", || format!("p1 mismatch: {p1:?}"))
}

#[test]
fn datagram_below_window_is_rejected() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let (alice, early_datagram) = alice.encrypt(b"early")?;
    let advanced = (1u64..=70).try_fold(alice, |state, i| -> Result<TransportState, Error> {
        let (next, _) = state.encrypt(format!("filler {i}").as_bytes())?;
        Ok(next)
    })?;
    let (_alice_final, far_datagram) = advanced.encrypt(b"far ahead")?;
    let (bob, _) = bob.decrypt(&far_datagram)?;
    expect_replay(bob.decrypt(&early_datagram), 0)
}

#[test]
fn rejects_truncated_datagram() -> Result<(), Error> {
    let (_alice, bob) = established_pair()?;
    expect_protocol_violation(bob.decrypt(&[0u8; 8]))
}
