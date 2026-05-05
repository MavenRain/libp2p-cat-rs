//! One-shot rendezvous client that asks the server "what address
//! did you see me coming from?" and prints the answer.
//!
//! # Usage
//!
//! ```text
//! # in terminal 1
//! cargo run --bin rendezvous-server -- 127.0.0.1:5000
//!
//! # in terminal 2
//! cargo run --bin rendezvous-observe -- 127.0.0.1:0 127.0.0.1:5000
//! ```
//!
//! `BIND_ADDR` (the first arg) controls the local socket the
//! observe call goes out from.  `127.0.0.1:0` lets the OS pick a
//! random port, which is useful for confirming the server reports
//! that exact ephemeral port back to us.  `SERVER_ADDR` (the
//! second arg) is the rendezvous server's bind address from
//! terminal 1.

use std::env;
use std::io::{Write, stdout};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;

use libp2p_cat_rs::{
    Ed25519Keypair, Error, Host, HostEvent, RendezvousNode, StaticKeypair, UdpAddr, UdpTransport,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "rendezvous-observe: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let args = parse_args()?;
    let socket = UdpTransport::bind(args.bind).run()?;
    let bound_addr = socket.local_addr()?;
    let static_kp = derive_static_keypair_from_bytes([0xA1; 32]);
    let identity = derive_identity_from_bytes([0x11; 32]);
    let host = Host::new(socket, static_kp, &identity)?;

    writeln!(
        stdout(),
        "rendezvous-observe: bound to {bound_addr}\nlocal peer id = {peer_id}",
        peer_id = host.peer_id(),
    )
    .map_err(Error::from)?;

    // 1. Handshake with the server (Noise XX, initiator side).
    let host = host.dial(args.server, fresh_seed()?).run()?;
    let (host, ev) = host.recv_one(fresh_seed()?).run()?;
    let _remote_peer_id = expect_handshake_complete(ev, args.server)?;

    // 2. Wrap the established Host in a RendezvousNode, then call
    //    observe_self to query the server for our observed address.
    let node = RendezvousNode::new(host);
    let (_node, observed) = node.observe_self(args.server, fresh_seed_factory()).run()?;

    writeln!(stdout(), "observed address = {observed}").map_err(Error::from)?;
    Ok(())
}

struct Args {
    bind: UdpAddr,
    server: UdpAddr,
}

fn parse_args() -> Result<Args, Error> {
    let mut iter = env::args().skip(1);
    let bind_arg = iter.next().ok_or_else(|| Error::HostState {
        reason: "usage: rendezvous-observe BIND_ADDR SERVER_ADDR".to_owned(),
    })?;
    let server_arg = iter.next().ok_or_else(|| Error::HostState {
        reason: "usage: rendezvous-observe BIND_ADDR SERVER_ADDR".to_owned(),
    })?;
    let bind = parse_addr(&bind_arg)?;
    let server = parse_addr(&server_arg)?;
    Ok(Args { bind, server })
}

fn parse_addr(s: &str) -> Result<UdpAddr, Error> {
    SocketAddr::from_str(s)
        .map(UdpAddr::from)
        .map_err(|e| Error::HostState {
            reason: format!("could not parse {s:?} as a socket address: {e}"),
        })
}

fn expect_handshake_complete(
    ev: HostEvent,
    expected: UdpAddr,
) -> Result<libp2p_cat_rs::PeerId, Error> {
    match ev {
        HostEvent::HandshakeComplete {
            addr,
            remote_peer_id,
            ..
        } if addr == expected => Ok(remote_peer_id),
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete from {expected}, got {other:?}"),
        }),
    }
}

fn derive_static_keypair_from_bytes(seed: [u8; 32]) -> StaticKeypair {
    StaticKeypair::from_private_bytes(seed)
}

fn derive_identity_from_bytes(seed: [u8; 32]) -> Ed25519Keypair {
    Ed25519Keypair::from_seed(seed)
}

fn fresh_seed() -> Result<[u8; 32], Error> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| Error::HostState {
        reason: format!("getrandom failed: {e}"),
    })?;
    Ok(seed)
}

/// A `Fn() -> [u8; 32]` factory whose calls panic-free fall back to
/// a zero seed if `getrandom` ever fails.  `observe_self` only
/// consults the seed for an unrelated fresh peer's `msg1` arriving
/// during the drain, which is implausible during a one-shot
/// client; the zero fallback is acceptable for the demo.
fn fresh_seed_factory() -> impl Fn() -> [u8; 32] + Clone + Send + Sync + 'static {
    || fresh_seed().unwrap_or([0u8; 32])
}
