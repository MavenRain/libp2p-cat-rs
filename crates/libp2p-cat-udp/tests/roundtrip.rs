//! End-to-end UDP datagram roundtrips.
//!
//! These tests bind two transports to ephemeral loopback ports, send a
//! datagram from one to the other, and check that the receiver
//! observes both the payload and the sender's address.  The pipeline
//! is built as a single `Io` value and `run` is called exactly once at
//! the boundary, exercising the linear-state-threading API.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use comp_cat_rs::effect::io::Io;
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;

fn loopback_v4() -> UdpAddr {
    UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn loopback_v6() -> UdpAddr {
    UdpAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
}

/// Build an `Io` pipeline that:
///
/// 1. Binds a sender and a receiver to ephemeral ports of `family`.
/// 2. Reads the sender's bound address (so we can verify the source
///    address the receiver observes).
/// 3. Reads the receiver's bound address and sends `payload` to it.
/// 4. Receives one datagram on the receiver and yields the source
///    address, payload bytes, and the sender's expected address.
fn roundtrip_pipeline(family: UdpAddr, payload: Vec<u8>) -> Io<Error, (UdpAddr, Vec<u8>, UdpAddr)> {
    UdpTransport::bind(family).flat_map(move |sender| {
        UdpTransport::bind(family).flat_map(move |receiver| {
            let receiver_addr_lookup = receiver.local_addr().map(|to| (receiver, to));
            Io::suspend(move || receiver_addr_lookup).flat_map(move |(receiver, to)| {
                let sender_addr_lookup = sender.local_addr().map(|from| (sender, from));
                Io::suspend(move || sender_addr_lookup).flat_map(move |(sender, sender_addr)| {
                    sender.send(to, payload).flat_map(move |_sender_back| {
                        receiver
                            .recv()
                            .map(move |((from, bytes), _receiver_back)| (from, bytes, sender_addr))
                    })
                })
            })
        })
    })
}

#[test]
fn datagram_roundtrip_v4() -> Result<(), Error> {
    let payload: Vec<u8> = b"hello libp2p-cat".to_vec();
    let expected = payload.clone();
    let (observed_from, observed_bytes, sender_addr) =
        roundtrip_pipeline(loopback_v4(), payload).run()?;
    assert_eq!(observed_bytes, expected);
    assert_eq!(observed_from, sender_addr);
    Ok(())
}

#[test]
fn datagram_roundtrip_v6() -> Result<(), Error> {
    let payload: Vec<u8> = (0u8..=63).collect();
    let expected = payload.clone();
    let (observed_from, observed_bytes, sender_addr) =
        roundtrip_pipeline(loopback_v6(), payload).run()?;
    assert_eq!(observed_bytes, expected);
    assert_eq!(observed_from, sender_addr);
    Ok(())
}

#[test]
fn empty_datagram_roundtrips() -> Result<(), Error> {
    let (observed_from, observed_bytes, sender_addr) =
        roundtrip_pipeline(loopback_v4(), Vec::new()).run()?;
    assert!(observed_bytes.is_empty());
    assert_eq!(observed_from, sender_addr);
    Ok(())
}
