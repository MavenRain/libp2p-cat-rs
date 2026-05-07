//! Long-running rendezvous server.
//!
//! Binds to the supplied UDP address and drives
//! [`RendezvousNode::recv_one`] forever, auto-answering inbound
//! `OBSERVE_REQ` (and forwarding inbound `PUNCH_REQ` to known peers,
//! firing punches on `PUNCH_FORWARD` per pass 6 — though for a
//! pure-server role the punch-forward path is not exercised).
//!
//! Each successful handshake and rendezvous event is logged to
//! stdout so the operator can watch peer activity.
//!
//! # Usage
//!
//! ```text
//! cargo run --bin rendezvous-server -- 127.0.0.1:5000
//! ```

use std::env;
use std::io::{Write, stdout};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;

use libp2p_cat_rs::{
    Ed25519Keypair, Error, Host, RendezvousEvent, RendezvousNode, StaticKeypair, UdpAddr,
    UdpTransport,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "rendezvous-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let bind = parse_bind_arg()?;
    let socket = UdpTransport::bind(bind).run()?;
    let bound_addr = socket.local_addr()?;
    let static_kp = derive_static_keypair(bind);
    let identity = derive_identity(bind);
    let host = Host::new(socket, static_kp, &identity)?;
    let node = RendezvousNode::new(host);

    writeln!(
        stdout(),
        "rendezvous server bound to {bound_addr}\nlocal peer id = {peer_id}",
        peer_id = node.peer_id(),
    )
    .map_err(Error::from)?;

    serve_forever(node)
}

/// Drive `recv_one` forever, logging each event.  Each iteration
/// pulls a fresh ephemeral seed for the (rare) case where an
/// inbound `msg1` from an unknown peer requires us to play
/// responder.
fn serve_forever(initial: RendezvousNode) -> Result<(), Error> {
    let _final = (0..usize::MAX).try_fold(initial, |node, _| {
        let seed = fresh_seed()?;
        let (next, event) = node.recv_one(seed).run()?;
        log_event(&event)?;
        Ok::<_, Error>(next)
    })?;
    Ok(())
}

fn log_event(event: &RendezvousEvent) -> Result<(), Error> {
    let line = match event {
        RendezvousEvent::HandshakeProgress { addr } => {
            format!("[handshake-progress] addr={addr}")
        }
        RendezvousEvent::HandshakeComplete {
            addr,
            remote_peer_id,
            ..
        } => format!("[handshake-complete] addr={addr} peer_id={remote_peer_id}"),
        RendezvousEvent::ObserveRequestReceived { from } => {
            format!("[observe-req] from={from}; replied with {from}")
        }
        RendezvousEvent::ObserveResponseReceived { from, observed } => {
            format!("[observe-resp] from={from} observed={observed}")
        }
        RendezvousEvent::PunchRequestReceived {
            from,
            target,
            forwarded,
        } => format!("[punch-req] from={from} target={target} forwarded={forwarded}"),
        RendezvousEvent::PunchForwardReceived { from, initiator } => {
            format!("[punch-forward] from={from} initiator={initiator}")
        }
        RendezvousEvent::RelayForwarded {
            from,
            target,
            forwarded,
            payload_len,
        } => format!(
            "[relay-fwd] from={from} target={target} forwarded={forwarded} payload_len={payload_len}"
        ),
        RendezvousEvent::RelayReceived {
            from,
            originator,
            payload,
        } => format!(
            "[relay-recv] from={from} originator={originator} payload_len={}",
            payload.len()
        ),
        RendezvousEvent::RelayFailed { from, peer, reason } => {
            format!("[relay-fail] from={from} peer={peer} reason={reason}")
        }
        RendezvousEvent::Rejected { addr, reason } => {
            format!("[rejected] addr={addr} reason={reason}")
        }
    };
    writeln!(stdout(), "{line}").map_err(Error::from)?;
    Ok(())
}

fn parse_bind_arg() -> Result<UdpAddr, Error> {
    let arg = env::args().nth(1).ok_or_else(|| Error::HostState {
        reason: "usage: rendezvous-server BIND_ADDR".to_owned(),
    })?;
    SocketAddr::from_str(&arg)
        .map(UdpAddr::from)
        .map_err(|e| Error::HostState {
            reason: format!("could not parse {arg:?} as a socket address: {e}"),
        })
}

/// Stable static keypair derived from the bind port so the server
/// presents the same X25519 identity across restarts of the demo.
fn derive_static_keypair(addr: UdpAddr) -> StaticKeypair {
    StaticKeypair::from_private_bytes(seed_from_port(addr, 0xC0))
}

/// Stable Ed25519 identity keypair, domain-separated from the
/// X25519 seed.
fn derive_identity(addr: UdpAddr) -> Ed25519Keypair {
    Ed25519Keypair::from_seed(seed_from_port(addr, 0xED))
}

fn seed_from_port(addr: UdpAddr, domain: u8) -> [u8; 32] {
    let port = match addr {
        UdpAddr::V4(s) => s.port(),
        UdpAddr::V6(s) => s.port(),
    };
    let port_bytes = port.to_be_bytes();
    core::array::from_fn(|i| match i {
        0 => domain,
        j => port_bytes.get(j - 1).copied().unwrap_or(0),
    })
}

fn fresh_seed() -> Result<[u8; 32], Error> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| Error::HostState {
        reason: format!("getrandom failed: {e}"),
    })?;
    Ok(seed)
}
