//! Property-based invariants for the pubsub wire codec.
//!
//! The codec is generic over the [`PubsubAuth`] authenticator;
//! we instantiate with [`NullAuthenticator`] (zero-byte commitment +
//! tag) so the property-test piece body is exactly `k + b` bytes,
//! decoupled from authenticator-specific framing which has its own
//! unit tests in `auth.rs`.
//!
//! Properties exercised:
//!
//! - **Round trip**: any well-formed `(topic, k, b, WirePiece)`
//!   survives `encode` followed by `decode` unchanged.
//! - **No-panic on adversarial input**: arbitrary byte sequences
//!   either decode or surface an [`Error::PubsubProtocol`] /
//!   [`Error::RlncLayer`] error; nothing else.
//!
//! [`PubsubAuth`]: libp2p_cat_pubsub::PubsubAuth
//! [`NullAuthenticator`]: rlnc_cat_rs::auth::NullAuthenticator

use libp2p_cat_pubsub::{Topic, decode, encode};
use libp2p_cat_types::Error;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use rlnc_cat_rs::auth::NullAuthenticator;
use rlnc_cat_rs::coding::piece::{CodedPiece, CodingVector};
use rlnc_cat_rs::gossip::WirePiece;
use rlnc_cat_rs::vector::GfVec;

/// Topic strategy: 1..=32 printable ASCII bytes (the workspace
/// validation rule).  Filtered through [`Topic::try_from`] to skip
/// the rare regex-generated string the validator rejects.
fn topic_strategy() -> impl Strategy<Value = Topic> {
    "[!-~]{1,32}".prop_filter_map("invalid topic", |s: String| Topic::try_from(s).ok())
}

/// Random `(k, b, coded_piece)` triple with small bounds for test
/// throughput.  k = coding-vector length, b = data length.
fn coded_piece_strategy() -> impl Strategy<Value = (u32, u32, CodedPiece)> {
    (1usize..=8, 1usize..=32).prop_flat_map(|(k, b)| {
        (prop_vec(any::<u8>(), k..=k), prop_vec(any::<u8>(), b..=b)).prop_map(
            move |(cv_bytes, data_bytes)| {
                let cv = CodingVector::from_bytes(&cv_bytes);
                let data = GfVec::from_bytes(&data_bytes);
                let piece = CodedPiece::new(cv, data);
                let k_u32 = u32::try_from(k).unwrap_or(0);
                let b_u32 = u32::try_from(b).unwrap_or(0);
                (k_u32, b_u32, piece)
            },
        )
    })
}

proptest! {
    #[test]
    fn null_round_trip(
        topic in topic_strategy(),
        triple in coded_piece_strategy(),
    ) {
        let (k, b, piece) = triple;
        let wp: WirePiece<NullAuthenticator> = WirePiece::new((), piece.clone(), ());
        let bytes = encode::<NullAuthenticator>(
            &topic,
            usize::try_from(k).unwrap_or(0),
            usize::try_from(b).unwrap_or(0),
            &wp,
        )
        .map_err(|e| TestCaseError::fail(format!("encode failed: {e}")))?;
        let (frame, parsed) = decode::<NullAuthenticator>(&bytes)
            .map_err(|e| TestCaseError::fail(format!("decode failed: {e}")))?;
        prop_assert_eq!(frame.topic, topic);
        prop_assert_eq!(frame.piece_count, k);
        prop_assert_eq!(frame.piece_byte_len, b);
        prop_assert_eq!(parsed.piece(), &piece);
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in prop_vec(any::<u8>(), 0..1024)) {
        match decode::<NullAuthenticator>(&bytes) {
            Ok(_) | Err(Error::PubsubProtocol { .. } | Error::RlncLayer { .. }) => {}
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseDecrypt
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::HostState { .. }
                | Error::IdentityVerify { .. }),
            ) => {
                prop_assert!(
                    false,
                    "decode produced unexpected error variant {other:?}"
                );
            }
        }
    }
}
