//! Property-based invariants for the rendezvous wire codec.
//!
//! Properties exercised:
//!
//! - **Round trip**: every well-formed [`Frame`] survives
//!   `encode` followed by `decode` unchanged.
//! - **No-panic on adversarial input**: arbitrary byte sequences
//!   either decode to a valid [`Frame`] or surface an
//!   [`Error::PubsubProtocol`]; nothing else (no panic, no
//!   `Error::Io`, no `Error::NoiseDecrypt`, etc.).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use libp2p_cat_rendezvous::{Frame, decode, encode};
use libp2p_cat_types::{Error, UdpAddr};
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

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

fn frame_strategy() -> impl Strategy<Value = Frame> {
    prop_oneof![
        Just(Frame::ObserveReq),
        addr_strategy().prop_map(|observed| Frame::ObserveResp { observed }),
        addr_strategy().prop_map(|target| Frame::PunchReq { target }),
        addr_strategy().prop_map(|initiator| Frame::PunchForward { initiator }),
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
    fn decode_never_panics_on_arbitrary_bytes(bytes in prop_vec(any::<u8>(), 0..256)) {
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
}
