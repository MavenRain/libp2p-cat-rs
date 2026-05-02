//! Wire codec for pubsub frames.
//!
//! Each frame is the *plaintext* that
//! [`libp2p_cat_noise::TransportState::encrypt`] later wraps into a
//! Noise-authenticated datagram.  The layout, all big-endian integers:
//!
//! ```text
//! +-------------+--------------+-------------+-------------+--------------+
//! | topic_len:1 | topic_bytes  | k: u32      | b: u32      | piece bytes  |
//! |             | (≤ MAX_TOPIC)| (4 bytes)   | (4 bytes)   | (k + b)      |
//! +-------------+--------------+-------------+-------------+--------------+
//! ```
//!
//! Piece bytes are produced by [`CodedPiece::to_bytes`] and parsed by
//! `CodedPiece::from_bytes(_, piece_count)`; the `(k, b)` integers in
//! the header carry the dimensions a receiver needs to instantiate its
//! decoder before a single piece arrives.

use libp2p_cat_types::Error;

use rlnc_cat_rs::auth::NullAuthenticator;
use rlnc_cat_rs::coding::piece::CodedPiece;
use rlnc_cat_rs::gossip::WirePiece;

use crate::topic::Topic;

/// Maximum number of bytes a topic name may occupy on the wire.
pub const MAX_TOPIC_LEN: usize = 255;

/// Number of bytes in the fixed prefix preceding the variable-length
/// piece bytes: 1 byte topic length + (≤255) topic bytes + 4 bytes `k`
/// + 4 bytes `b`.
const FIXED_TAIL: usize = 8; // k(4) + b(4)

/// A parsed pubsub frame.
///
/// Public so callers can inspect frames in tests; production paths
/// drive directly through [`encode`] / [`decode`].
#[derive(Clone, Debug)]
#[must_use]
pub struct PubsubFrame {
    /// Topic this frame belongs to.
    pub topic: Topic,
    /// RLNC piece count `k` (number of original pieces in the
    /// generation).
    pub piece_count: u32,
    /// Per-piece byte length `b`.
    pub piece_byte_len: u32,
    /// The on-the-wire piece bytes: `coding_vector || data`.
    pub piece_bytes: Vec<u8>,
}

/// Encode a frame to bytes.
///
/// # Errors
///
/// - [`Error::PubsubProtocol`] if `k` or `b` does not fit in `u32`,
///   or if the frame would exceed `usize::MAX` bytes.
pub fn encode(
    topic: &Topic,
    piece_count: usize,
    piece_byte_len: usize,
    wire_piece: &WirePiece<NullAuthenticator>,
) -> Result<Vec<u8>, Error> {
    let topic_bytes = topic.as_bytes();
    let topic_len_byte = u8::try_from(topic_bytes.len()).map_err(|_| Error::PubsubProtocol {
        reason: format!("topic length {} exceeds u8 range", topic_bytes.len()),
    })?;
    let k = u32::try_from(piece_count).map_err(|_| Error::PubsubProtocol {
        reason: format!("piece_count {piece_count} exceeds u32 range"),
    })?;
    let b = u32::try_from(piece_byte_len).map_err(|_| Error::PubsubProtocol {
        reason: format!("piece_byte_len {piece_byte_len} exceeds u32 range"),
    })?;
    let piece_bytes = wire_piece.piece().to_bytes();
    let header_iter = [topic_len_byte]
        .into_iter()
        .chain(topic_bytes.iter().copied())
        .chain(k.to_be_bytes())
        .chain(b.to_be_bytes());
    let frame: Vec<u8> = header_iter.chain(piece_bytes).collect();
    Ok(frame)
}

/// Decode a frame from bytes back into a [`PubsubFrame`] and the
/// reconstructed [`WirePiece`].
///
/// # Errors
///
/// - [`Error::PubsubProtocol`] if the frame is shorter than the
///   header demands, the topic length byte is zero, or the topic is
///   not valid printable ASCII.
/// - [`Error::RlncLayer`] if the piece bytes do not match `k + b`
///   (parsed via [`CodedPiece::from_bytes`]).
pub fn decode(bytes: &[u8]) -> Result<(PubsubFrame, WirePiece<NullAuthenticator>), Error> {
    let topic_len_byte = bytes
        .first()
        .copied()
        .ok_or_else(|| Error::PubsubProtocol {
            reason: "frame missing topic length byte".to_owned(),
        })?;
    let topic_len = usize::from(topic_len_byte);
    let header_end = 1 + topic_len + FIXED_TAIL;
    if bytes.len() < header_end {
        Err(Error::PubsubProtocol {
            reason: format!(
                "frame too short: {} bytes, header needs {header_end}",
                bytes.len()
            ),
        })
    } else {
        let topic_slice = bytes
            .get(1..1 + topic_len)
            .ok_or_else(|| Error::PubsubProtocol {
                reason: "frame topic slice unreadable".to_owned(),
            })?;
        let topic_string = core::str::from_utf8(topic_slice)
            .map_err(|_| Error::PubsubProtocol {
                reason: "topic slice is not valid UTF-8".to_owned(),
            })?
            .to_owned();
        let topic = Topic::new(topic_string)?;
        let k_slice =
            bytes
                .get(1 + topic_len..1 + topic_len + 4)
                .ok_or_else(|| Error::PubsubProtocol {
                    reason: "frame missing piece-count field".to_owned(),
                })?;
        let b_slice = bytes
            .get(1 + topic_len + 4..1 + topic_len + 8)
            .ok_or_else(|| Error::PubsubProtocol {
                reason: "frame missing piece-byte-len field".to_owned(),
            })?;
        let piece_count = u32::from_be_bytes(parse_4(k_slice)?);
        let piece_byte_len = u32::from_be_bytes(parse_4(b_slice)?);
        let piece_bytes = bytes
            .get(header_end..)
            .ok_or_else(|| Error::PubsubProtocol {
                reason: "frame missing piece body".to_owned(),
            })?
            .to_vec();
        let piece_count_us = usize_from_u32(piece_count)?;
        let coded =
            CodedPiece::from_bytes(&piece_bytes, piece_count_us).map_err(|e| Error::RlncLayer {
                reason: e.to_string(),
            })?;
        let wire_piece = WirePiece::<NullAuthenticator>::new((), coded, ());
        Ok((
            PubsubFrame {
                topic,
                piece_count,
                piece_byte_len,
                piece_bytes,
            },
            wire_piece,
        ))
    }
}

fn parse_4(slice: &[u8]) -> Result<[u8; 4], Error> {
    <[u8; 4]>::try_from(slice).map_err(|_| Error::PubsubProtocol {
        reason: format!("expected 4 bytes, got {}", slice.len()),
    })
}

fn usize_from_u32(n: u32) -> Result<usize, Error> {
    usize::try_from(n).map_err(|_| Error::PubsubProtocol {
        reason: format!("u32 value {n} does not fit in usize on this platform"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlnc_cat_rs::coding::piece::CodingVector;
    use rlnc_cat_rs::vector::GfVec;

    fn sample_wire_piece() -> WirePiece<NullAuthenticator> {
        let cv = CodingVector::from_bytes(&[1, 0, 0]);
        let data = GfVec::from_bytes(&[7, 8, 9, 10]);
        let piece = CodedPiece::new(cv, data);
        WirePiece::new((), piece, ())
    }

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::PubsubProtocol { reason: reason() })
        }
    }

    fn expect_pubsub_rejection<T>(outcome: Result<T, Error>) -> Result<(), Error> {
        match outcome {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            Err(other) => Err(Error::PubsubProtocol {
                reason: format!("expected PubsubProtocol, got error {other:?}"),
            }),
            Ok(_) => Err(Error::PubsubProtocol {
                reason: "expected PubsubProtocol, got Ok".to_owned(),
            }),
        }
    }

    #[test]
    fn encode_decode_round_trip() -> Result<(), Error> {
        let topic: Topic = "/chat/v1".try_into()?;
        let wp = sample_wire_piece();
        let bytes = encode(&topic, 3, 4, &wp)?;
        let (frame, decoded) = decode(&bytes)?;
        check(frame.topic == topic, || {
            format!("topic mismatch: {}", frame.topic)
        })?;
        check(frame.piece_count == 3, || {
            format!("piece_count mismatch: {}", frame.piece_count)
        })?;
        check(frame.piece_byte_len == 4, || {
            format!("piece_byte_len mismatch: {}", frame.piece_byte_len)
        })?;
        check(decoded.piece() == wp.piece(), || {
            "decoded piece does not equal original".to_owned()
        })
    }

    #[test]
    fn decode_rejects_truncated_header() -> Result<(), Error> {
        expect_pubsub_rejection(decode(&[5u8, b'x']))
    }

    #[test]
    fn decode_rejects_invalid_topic_bytes() -> Result<(), Error> {
        let bad: Vec<u8> = [3u8, b'a', 0x01, b'b']
            .into_iter()
            .chain([0u8; 8])
            .chain([0u8; 4])
            .collect();
        expect_pubsub_rejection(decode(&bad))
    }
}
