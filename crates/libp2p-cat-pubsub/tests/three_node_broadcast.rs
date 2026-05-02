//! End-to-end three-node RLNC pubsub broadcast over real loopback UDP.
//!
//! Alice, Bob, and Carol each bind a UDP socket on `127.0.0.1`.
//! Pairwise Noise XX handshakes are run in memory (the wire-level
//! handshake itself is exercised in `libp2p-cat-noise`'s integration
//! tests; here we use the resulting [`TransportState`]s directly).
//!
//! Bob and Carol register the topic `/chat/v1` with `k = 3, b = 8`.
//! Alice broadcasts an `OriginalData` of 18 bytes split into 3
//! pieces, fanning out to both peers.  Each receiver pulls three
//! datagrams off its socket and the third is expected to deliver the
//! reconstructed message.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libp2p_cat_noise::{Initiator, Responder, StaticKeypair, TransportState};
use libp2p_cat_pubsub::{DeliveredMessage, PubsubNode, Topic};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use rlnc_cat_rs::coding::piece::OriginalData;

fn loopback_v4() -> UdpAddr {
    UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

/// Drive a Noise XX handshake between two parties entirely in memory
/// and return the two resulting [`TransportState`]s.
fn paired_handshake(
    a: StaticKeypair,
    b: StaticKeypair,
    a_eph: [u8; 32],
    b_eph: [u8; 32],
) -> Result<(TransportState, TransportState), Error> {
    let (a_after_e, msg1) = Initiator::new(a).write_e(a_eph)?;
    let b_after_e = Responder::new(b).read_e(&msg1)?;
    let (b_after_resp, msg2) = b_after_e.write_response(b_eph)?;
    let a_after_resp = a_after_e.read_response(&msg2)?;
    let (a_transport, msg3, _) = a_after_resp.write_s()?;
    let (b_transport, _) = b_after_resp.read_s(&msg3)?;
    Ok((a_transport, b_transport))
}

/// Returns a counter-driven `rng_factory` that emits standard basis
/// vectors `[0,...,0,1,0,...,0]` with the `1` at position `i mod n`
/// for the i-th call.  The first `n` outputs are trivially linearly
/// independent, so a receiver decodes after exactly `n` pieces.
fn standard_basis_rng()
-> impl Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static {
    let counter = Arc::new(AtomicUsize::new(0));
    move |n: usize| -> Result<Vec<u8>, rlnc_cat_rs::error::Error> {
        let i = counter.fetch_add(1, Ordering::Relaxed);
        Ok((0..n).map(|j| u8::from(j == (i % n))).collect())
    }
}

/// Pull `n` datagrams off `node`'s socket, returning the final node
/// and the list of any deliveries that occurred during the loop.
fn drain_recv(node: PubsubNode, n: usize) -> Result<(PubsubNode, Vec<DeliveredMessage>), Error> {
    (0..n).try_fold(
        (node, Vec::<DeliveredMessage>::new()),
        |(node, deliveries), _| {
            node.recv_one().run().map(|(next_node, maybe)| {
                let merged: Vec<DeliveredMessage> = deliveries.into_iter().chain(maybe).collect();
                (next_node, merged)
            })
        },
    )
}

#[test]
fn three_node_rlnc_broadcast_decodes_at_both_receivers() -> Result<(), Error> {
    // 1. Bind sockets.
    let alice_socket = UdpTransport::bind(loopback_v4()).run()?;
    let bob_socket = UdpTransport::bind(loopback_v4()).run()?;
    let carol_socket = UdpTransport::bind(loopback_v4()).run()?;
    let alice_addr = alice_socket.local_addr()?;
    let bob_addr = bob_socket.local_addr()?;
    let carol_addr = carol_socket.local_addr()?;

    // 2. Static keys + pairwise handshakes (in memory).
    let alice_kp = StaticKeypair::from_private_bytes([0x11; 32]);
    let bob_kp = StaticKeypair::from_private_bytes([0x22; 32]);
    let carol_kp = StaticKeypair::from_private_bytes([0x33; 32]);
    let (alice_to_bob, bob_to_alice) =
        paired_handshake(alice_kp.clone(), bob_kp, [0x44; 32], [0x55; 32])?;
    let (alice_to_carol, carol_to_alice) =
        paired_handshake(alice_kp, carol_kp, [0x66; 32], [0x77; 32])?;

    // 3. Build pubsub nodes and register the topic on receivers.
    let topic: Topic = "/chat/v1".try_into()?;
    let payload: &[u8] = b"hello pubsub world";
    let piece_count: usize = 3;
    let data = OriginalData::from_bytes(payload, piece_count).map_err(|e| Error::RlncLayer {
        reason: e.to_string(),
    })?;
    let piece_byte_len = data.piece_byte_len();

    let alice_node = PubsubNode::new(alice_socket);
    let (alice_node, _bob_idx) = alice_node.add_peer(bob_addr, alice_to_bob);
    let (alice_node, _carol_idx) = alice_node.add_peer(carol_addr, alice_to_carol);

    let bob_node = PubsubNode::new(bob_socket);
    let (bob_node, _alice_idx_b) = bob_node.add_peer(alice_addr, bob_to_alice);
    let bob_node = bob_node.register_topic(topic.clone(), piece_count, piece_byte_len);

    let carol_node = PubsubNode::new(carol_socket);
    let (carol_node, _alice_idx_c) = carol_node.add_peer(alice_addr, carol_to_alice);
    let carol_node = carol_node.register_topic(topic.clone(), piece_count, piece_byte_len);

    // 4. Alice broadcasts piece_count frames, fanned out to both peers.
    let _alice_after = alice_node
        .broadcast(topic.clone(), data, piece_count, standard_basis_rng())
        .run()?;

    // 5. Bob and Carol each pull piece_count datagrams off the socket.
    let (_bob_after, bob_deliveries) = drain_recv(bob_node, piece_count)?;
    let (_carol_after, carol_deliveries) = drain_recv(carol_node, piece_count)?;

    // The third absorbed piece on each side should have completed the
    // decoder.
    let bob_msg = bob_deliveries
        .into_iter()
        .next()
        .ok_or_else(|| Error::PubsubProtocol {
            reason: "bob did not decode the message".to_owned(),
        })?;
    let carol_msg = carol_deliveries
        .into_iter()
        .next()
        .ok_or_else(|| Error::PubsubProtocol {
            reason: "carol did not decode the message".to_owned(),
        })?;

    let check = |cond: bool, reason: &str| -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::PubsubProtocol {
                reason: reason.to_owned(),
            })
        }
    };
    check(bob_msg.topic == topic, "bob topic mismatch")?;
    check(carol_msg.topic == topic, "carol topic mismatch")?;
    let bob_prefix = bob_msg
        .data
        .get(..payload.len())
        .ok_or_else(|| Error::PubsubProtocol {
            reason: "bob's reconstructed bytes shorter than original payload".to_owned(),
        })?;
    let carol_prefix =
        carol_msg
            .data
            .get(..payload.len())
            .ok_or_else(|| Error::PubsubProtocol {
                reason: "carol's reconstructed bytes shorter than original payload".to_owned(),
            })?;
    check(bob_prefix == payload, "bob payload mismatch")?;
    check(carol_prefix == payload, "carol payload mismatch")?;
    Ok(())
}
