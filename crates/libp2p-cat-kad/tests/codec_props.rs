//! Property-based invariants for the Kademlia wire codec.
//!
//! - **Round trip**: every well-formed [`Frame`] survives `encode`
//!   followed by `decode` unchanged.
//! - **No-panic on adversarial input**: arbitrary byte sequences
//!   either decode or surface an [`Error::PubsubProtocol`]; nothing
//!   else.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use libp2p_cat_kad::{Frame, NODE_ID_LEN, NodeId, decode, encode};
use libp2p_cat_types::{Error, UdpAddr};
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

fn node_id_strategy() -> impl Strategy<Value = NodeId> {
    prop::array::uniform32(any::<u8>()).prop_map(NodeId::from_bytes)
}

fn addr_v4_strategy() -> impl Strategy<Value = UdpAddr> {
    (any::<[u8; 4]>(), any::<u16>())
        .prop_map(|(octets, port)| UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)))
}

fn addr_v6_strategy() -> impl Strategy<Value = UdpAddr> {
    (any::<[u8; 16]>(), any::<u16>()).prop_map(|(octets, port)| {
        UdpAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0))
    })
}

fn addr_strategy() -> impl Strategy<Value = UdpAddr> {
    prop_oneof![addr_v4_strategy(), addr_v6_strategy()]
}

fn peers_strategy() -> impl Strategy<Value = Vec<(NodeId, UdpAddr)>> {
    // 1-byte count cap is 255, but keep the bound small for test
    // throughput; broad coverage of the count axis happens at the
    // unit-test level.
    prop_vec((node_id_strategy(), addr_strategy()), 0..16)
}

fn frame_strategy() -> impl Strategy<Value = Frame> {
    prop_oneof![
        Just(Frame::PingReq),
        Just(Frame::PingResp),
        node_id_strategy().prop_map(|target| Frame::FindNodeReq { target }),
        peers_strategy().prop_map(|peers| Frame::FindNodeResp { peers }),
    ]
}

proptest! {
    #[test]
    fn encode_decode_round_trip(frame in frame_strategy()) {
        let bytes = encode(&frame).map_err(|e| TestCaseError::fail(format!("encode failed: {e}")))?;
        let parsed = decode(&bytes).map_err(|e| TestCaseError::fail(format!("decode failed: {e}")))?;
        prop_assert_eq!(parsed, frame);
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in prop_vec(any::<u8>(), 0..1024)) {
        match decode(&bytes) {
            Ok(_) | Err(Error::PubsubProtocol { .. }) => {}
            Err(
                other @ (Error::Io(_)
                | Error::InvalidProtocolId { .. }
                | Error::InvalidPeerId { .. }
                | Error::DatagramTooLarge { .. }
                | Error::NoiseDecrypt
                | Error::NoiseProtocol { .. }
                | Error::NoiseReplay { .. }
                | Error::RlncLayer { .. }
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

    #[test]
    fn find_node_req_round_trip_target_recovered(bytes in prop::array::uniform32(any::<u8>())) {
        // Targeted property: the 32-byte target NodeId in a
        // FindNodeReq survives encode + decode bit-exact.
        let target = NodeId::from_bytes(bytes);
        let frame = Frame::FindNodeReq { target };
        let encoded = encode(&frame).map_err(|e| TestCaseError::fail(format!("encode failed: {e}")))?;
        prop_assert_eq!(encoded.len(), 1 + NODE_ID_LEN);
        let parsed = decode(&encoded).map_err(|e| TestCaseError::fail(format!("decode failed: {e}")))?;
        prop_assert_eq!(parsed, frame);
    }
}
