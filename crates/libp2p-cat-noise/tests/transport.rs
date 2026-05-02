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

#[test]
fn encrypt_decrypt_round_trip() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let plaintext = b"the quick brown fox".to_vec();
    let expected = plaintext.clone();
    let (_alice, datagram) = alice.encrypt(&plaintext)?;
    let (_bob, recovered) = bob.decrypt(&datagram)?;
    assert_eq!(recovered, expected);
    Ok(())
}

#[test]
fn tampered_ciphertext_is_rejected() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let (_alice, datagram) = alice.encrypt(b"hello")?;
    // Flip a bit deep in the ciphertext (skip the 8-byte nonce prefix).
    let tampered: Vec<u8> = datagram
        .iter()
        .enumerate()
        .map(|(i, &b)| if i == 10 { b ^ 0x80 } else { b })
        .collect();
    let outcome = bob.decrypt(&tampered);
    assert!(matches!(outcome, Err(Error::NoiseDecrypt)));
    Ok(())
}

#[test]
fn replayed_datagram_is_rejected() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    let (_alice, datagram) = alice.encrypt(b"once")?;
    let (bob, _first) = bob.decrypt(&datagram)?;
    let outcome = bob.decrypt(&datagram);
    assert!(matches!(outcome, Err(Error::NoiseReplay { nonce: 0 })));
    Ok(())
}

#[test]
fn out_of_order_within_window_is_accepted() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    // Encrypt three datagrams without delivering them yet.
    let (alice, dg0) = alice.encrypt(b"first")?;
    let (alice, dg1) = alice.encrypt(b"second")?;
    let (_alice, dg2) = alice.encrypt(b"third")?;
    // Deliver out of order: 2 then 0 then 1.  All three should decrypt.
    let (bob, p2) = bob.decrypt(&dg2)?;
    assert_eq!(p2, b"third");
    let (bob, p0) = bob.decrypt(&dg0)?;
    assert_eq!(p0, b"first");
    let (_bob, p1) = bob.decrypt(&dg1)?;
    assert_eq!(p1, b"second");
    Ok(())
}

#[test]
fn datagram_below_window_is_rejected() -> Result<(), Error> {
    let (alice, bob) = established_pair()?;
    // Capture an early datagram (nonce 0) but don't deliver it.
    let (alice, early_datagram) = alice.encrypt(b"early")?;
    // Advance alice 70 more steps so the next datagram's nonce is well
    // outside the 64-bit replay window.
    let advanced = (1u64..=70).try_fold(alice, |state, i| -> Result<TransportState, Error> {
        let (next, _) = state.encrypt(format!("filler {i}").as_bytes())?;
        Ok(next)
    })?;
    let (_alice_final, far_datagram) = advanced.encrypt(b"far ahead")?;
    // Deliver the far-ahead datagram first to advance bob's state.
    let (bob, _) = bob.decrypt(&far_datagram)?;
    // Now the early datagram (nonce 0) is below the window edge.
    let outcome = bob.decrypt(&early_datagram);
    assert!(matches!(outcome, Err(Error::NoiseReplay { nonce: 0 })));
    Ok(())
}

#[test]
fn rejects_truncated_datagram() -> Result<(), Error> {
    let (_alice, bob) = established_pair()?;
    let outcome = bob.decrypt(&[0u8; 8]); // nonce only, no tag
    assert!(matches!(outcome, Err(Error::NoiseProtocol { .. })));
    Ok(())
}
