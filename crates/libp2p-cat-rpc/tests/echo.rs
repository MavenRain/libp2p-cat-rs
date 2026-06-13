//! End-to-end RPC test: an `EchoService` running on a libp2p-cat-rs
//! [`Host`] (server) is reached by a client using [`HostTransport`]
//! and [`tarpc_cat::client::call_on`].
//!
//! Topology: alice (client) and bob (server), each on their own
//! loopback UDP socket, connected by a Noise XX handshake.  Bob
//! runs `serve_one` in a daemon thread; alice issues a single
//! `call_on(transport, EchoRequest { message: "hello" })` and
//! checks the response.
//!
//! [`Host`]: libp2p_cat_host::Host
//! [`HostTransport`]: libp2p_cat_rpc::HostTransport

use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;

use comp_cat_rs::effect::io::Io;
use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_identity::Ed25519Keypair;
use libp2p_cat_noise::StaticKeypair;
use libp2p_cat_rpc::{HostTransport, serve_one};
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;
use serde::{Deserialize, Serialize};
use tarpc_cat::client::call_on;
use tarpc_cat::error::Error as TarpcError;
use tarpc_cat::serve::Serve;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct EchoRequest {
    message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct EchoResponse {
    echo: String,
}

#[derive(Clone)]
struct EchoService;

impl Serve for EchoService {
    type Request = EchoRequest;
    type Response = EchoResponse;

    fn handle(&self, request: EchoRequest) -> Io<TarpcError, EchoResponse> {
        Io::pure(EchoResponse {
            echo: request.message,
        })
    }
}

fn loopback_v4() -> UdpAddr {
    UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::HostState { reason: reason() })
    }
}

fn build_host(seed: u8) -> Result<(Host, UdpAddr), Error> {
    let socket = UdpTransport::bind(loopback_v4()).run()?;
    let addr = socket.local_addr()?;
    let kp = StaticKeypair::from_private_bytes([seed; 32]);
    let id = Ed25519Keypair::from_seed([seed.wrapping_add(1); 32]);
    let host = Host::new(socket, kp, &id, [seed.wrapping_add(2); 32])?;
    Ok((host, addr))
}

fn handshake_pair(
    initiator: Host,
    responder: Host,
    initiator_addr: UdpAddr,
    responder_addr: UdpAddr,
    initiator_seed: [u8; 32],
    responder_seed: [u8; 32],
) -> Result<(Host, Host), Error> {
    let initiator = initiator.dial(responder_addr, initiator_seed).run()?;
    let (responder, ev) = responder.recv_one(responder_seed).run()?;
    expect_handshake_progress(ev, initiator_addr)?;
    let (initiator, ev) = initiator.recv_one([0; 32]).run()?;
    expect_handshake_progress(ev, responder_addr)?;
    let (responder, ev) = responder.recv_one(responder_seed).run()?;
    expect_handshake_progress(ev, initiator_addr)?;
    let (initiator, ev) = initiator.recv_one([0; 32]).run()?;
    expect_handshake_complete(ev, responder_addr)?;
    let (responder, ev) = responder.recv_one([0; 32]).run()?;
    expect_handshake_complete(ev, initiator_addr)?;
    Ok((initiator, responder))
}

fn expect_handshake_progress(ev: HostEvent, expected: UdpAddr) -> Result<(), Error> {
    match ev {
        HostEvent::HandshakeProgress { addr } if addr == expected => Ok(()),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeProgress({expected}), got {other:?}"),
        }),
    }
}

fn expect_handshake_complete(ev: HostEvent, expected: UdpAddr) -> Result<(), Error> {
    match ev {
        HostEvent::HandshakeComplete { addr, .. } if addr == expected => Ok(()),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete({expected}), got {other:?}"),
        }),
    }
}

/// Daemon-style server thread: drive `serve_one` for an
/// effectively-infinite number of iterations.  The thread blocks
/// on the UDP socket on its final iteration; the OS reaps it on
/// test exit.
fn spawn_server(host: Host, service: EchoService, seed: [u8; 32]) {
    thread::spawn(move || -> Result<(), Error> {
        let _final = (0..usize::MAX).try_fold(host, |acc, _| {
            let (next, _ev) = serve_one(acc, service.clone(), seed).run()?;
            Ok::<_, Error>(next)
        })?;
        Ok(())
    });
}

#[test]
fn rpc_echo_round_trip_over_libp2p_host() -> Result<(), Error> {
    let (alice, alice_addr) = build_host(0xA1)?;
    let (bob, bob_addr) = build_host(0xB2)?;

    // Pairwise Noise XX handshake.
    let (alice, bob) = handshake_pair(alice, bob, alice_addr, bob_addr, [0xE1; 32], [0xE2; 32])?;
    check(alice.is_established(bob_addr), || {
        "alice should be established with bob".to_owned()
    })?;
    check(bob.is_established(alice_addr), || {
        "bob should be established with alice".to_owned()
    })?;

    // Park bob in a daemon thread serving the echo service.
    spawn_server(bob, EchoService, [0xF2; 32]);

    // Alice wraps her host in a HostTransport and calls echo.
    let transport = HostTransport::new(alice, bob_addr, || [0xC1; 32]);
    let request = EchoRequest {
        message: "hello".to_owned(),
    };
    let (response, _transport): (EchoResponse, _) =
        call_on(transport, request)
            .run()
            .map_err(|e| Error::HostState {
                reason: format!("rpc call failed: {e}"),
            })?;

    check(response.echo == "hello", || {
        format!("expected echo == \"hello\", got {response:?}")
    })
}
