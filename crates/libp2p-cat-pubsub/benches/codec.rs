//! Criterion baseline for the pubsub wire codec.
//!
//! Measures the cost of `encode`, `decode`, and a round trip on a
//! [`WirePiece<NullAuthenticator>`] with `k = 8` coding-vector
//! length, `b = 1024` data bytes — the per-frame work a relay /
//! decoder runs on every received pubsub piece.
//!
//! Run with `cargo bench -p libp2p-cat-pubsub --bench codec`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use libp2p_cat_pubsub::{Topic, decode, encode};
use rlnc_cat_rs::auth::NullAuthenticator;
use rlnc_cat_rs::coding::piece::{CodedPiece, CodingVector};
use rlnc_cat_rs::gossip::WirePiece;
use rlnc_cat_rs::vector::GfVec;

const PIECE_COUNT: usize = 8;
const PIECE_BYTE_LEN: usize = 1024;

fn build_topic() -> Option<Topic> {
    Topic::try_from("/bench/v1").ok()
}

fn build_wire_piece() -> WirePiece<NullAuthenticator> {
    let cv_bytes: Vec<u8> = (0..PIECE_COUNT)
        .map(|i| u8::try_from(i % 255).unwrap_or(0))
        .collect();
    let data_bytes: Vec<u8> = (0..PIECE_BYTE_LEN)
        .map(|i| u8::try_from(i % 255).unwrap_or(0))
        .collect();
    let cv = CodingVector::from_bytes(&cv_bytes);
    let data = GfVec::from_bytes(&data_bytes);
    WirePiece::new((), CodedPiece::new(cv, data), ())
}

fn bench_encode(c: &mut Criterion) {
    let wp = build_wire_piece();
    let _ = build_topic().map(|topic| {
        c.bench_function("pubsub_encode_null_k8_b1024", |b| {
            b.iter(|| {
                let bytes = encode::<NullAuthenticator>(
                    black_box(&topic),
                    PIECE_COUNT,
                    PIECE_BYTE_LEN,
                    black_box(&wp),
                );
                black_box(bytes.ok());
            });
        });
    });
}

fn bench_decode(c: &mut Criterion) {
    let wp = build_wire_piece();
    let _ = build_topic()
        .and_then(|topic| {
            encode::<NullAuthenticator>(&topic, PIECE_COUNT, PIECE_BYTE_LEN, &wp).ok()
        })
        .map(|bytes| {
            c.bench_function("pubsub_decode_null_k8_b1024", |b| {
                b.iter(|| {
                    let result = decode::<NullAuthenticator>(black_box(&bytes));
                    black_box(result.ok());
                });
            });
        });
}

fn bench_round_trip(c: &mut Criterion) {
    let wp = build_wire_piece();
    let _ = build_topic().map(|topic| {
        c.bench_function("pubsub_codec_round_trip_null_k8_b1024", |b| {
            b.iter(|| {
                let encoded = encode::<NullAuthenticator>(
                    black_box(&topic),
                    PIECE_COUNT,
                    PIECE_BYTE_LEN,
                    black_box(&wp),
                );
                let bytes = encoded.ok().unwrap_or_default();
                let result = decode::<NullAuthenticator>(black_box(&bytes));
                black_box(result.ok());
            });
        });
    });
}

criterion_group!(benches, bench_encode, bench_decode, bench_round_trip);
criterion_main!(benches);
