//! Two-peer authenticated chat over UDP+Noise built on
//! [`libp2p_cat_rs::Host`].
//!
//! # Usage
//!
//! Run two instances on the same machine.  The first binds to a port
//! and waits; the second binds and dials the first.
//!
//! ```text
//! # terminal 1 (responder)
//! cargo run -p libp2p-cat-rs-example-chat -- 127.0.0.1:4001
//!
//! # terminal 2 (initiator)
//! cargo run -p libp2p-cat-rs-example-chat -- 127.0.0.1:4002 127.0.0.1:4001
//! ```
//!
//! Each instance reads lines from stdin and ships them to the peer as
//! authenticated datagrams.  Whoever dialled sends first; the other
//! side listens first.  After that, the two sides alternate.
//!
//! # Identity
//!
//! For demo reproducibility both the static X25519 keypair and the
//! Ed25519 identity keypair are derived deterministically from the
//! bind port (so peers can recognise each other across runs) while
//! ephemeral seeds come from `getrandom`.  Each peer prints the
//! [`PeerId`] derived from its own identity at startup, and the
//! peer's [`PeerId`] (verified against the X25519 key Noise
//! authenticated) on `HandshakeComplete`.  Production deployments
//! should source both keys from a real key store instead.
//!
//! [`PeerId`]: libp2p_cat_rs::PeerId

use std::env;
use std::io::{BufRead, Write, stdin, stdout};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;

use libp2p_cat_rs::{
    Ed25519Keypair, Error, Host, HostEvent, PeerId, StaticKeypair, UdpAddr, UdpTransport,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Writing to stderr is allowed at the binary boundary.
            let _ = writeln!(std::io::stderr(), "chat: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let args = parse_args()?;
    let bind = args.bind;
    let socket = UdpTransport::bind(bind).run()?;
    let keypair = derive_keypair(bind);
    let identity = derive_identity(bind);
    let host = Host::new(socket, keypair, &identity, [0x4A; 32])?;

    print_banner(bind, args.peer.as_ref(), host.peer_id())?;

    let (host, peer_addr, first_turn) = match args.peer {
        Some(remote) => initiator_handshake(host, remote).map(|h| (h, remote, Turn::Send))?,
        None => responder_handshake(host).map(|(h, p)| (h, p, Turn::Recv))?,
    };

    chat_step(host, peer_addr, first_turn)
}

/// Whose turn it is to act on the chat socket.  The two peers
/// alternate: after sending, the next thing to do is recv; after
/// recv, the next thing is send.
#[derive(Clone, Copy)]
enum Turn {
    /// Read a line from stdin and send it.
    Send,
    /// Block on the socket and surface what arrives.
    Recv,
}

struct Args {
    bind: UdpAddr,
    peer: Option<UdpAddr>,
}

fn parse_args() -> Result<Args, Error> {
    let mut iter = env::args().skip(1);
    let bind_arg = iter.next().ok_or_else(|| Error::HostState {
        reason: "usage: chat BIND_ADDR [PEER_ADDR]".to_owned(),
    })?;
    let peer_arg = iter.next();
    let bind = parse_addr(&bind_arg)?;
    let peer = peer_arg.map(|s| parse_addr(&s)).transpose()?;
    Ok(Args { bind, peer })
}

fn parse_addr(s: &str) -> Result<UdpAddr, Error> {
    SocketAddr::from_str(s)
        .map(UdpAddr::from)
        .map_err(|e| Error::HostState {
            reason: format!("could not parse {s:?} as a socket address: {e}"),
        })
}

/// Stable static keypair derived from the bind port so two instances
/// running on different ports recognise each other across restarts.
fn derive_keypair(addr: UdpAddr) -> StaticKeypair {
    StaticKeypair::from_private_bytes(seed_from_port(addr, 0xC0))
}

/// Stable Ed25519 identity keypair derived from the bind port,
/// domain-separated from the X25519 static seed.
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

fn print_banner(bind: UdpAddr, peer: Option<&UdpAddr>, peer_id: &PeerId) -> Result<(), Error> {
    let role = match peer {
        Some(p) => format!("dialer (will reach {p})"),
        None => "listener (waiting for incoming dial)".to_owned(),
    };
    writeln!(
        stdout(),
        "libp2p-cat-rs chat: bound to {bind} as {role}\nlocal peer id = {peer_id}"
    )
    .map_err(Error::from)?;
    Ok(())
}

fn initiator_handshake(host: Host, peer: UdpAddr) -> Result<Host, Error> {
    let host = host.dial(peer, fresh_seed()?).run()?;
    // The Noise XX handshake now opens with a stateless
    // source-address-validation cookie round-trip, so the initiator
    // observes one or more `HandshakeProgress` events (echoing the
    // cookie) before the terminal `HandshakeComplete`.  Absorb the
    // progress events until the handshake completes.
    drive_handshake_to_completion(host, peer)
}

fn responder_handshake(host: Host) -> Result<(Host, UdpAddr), Error> {
    let (host, ev1) = host.recv_one(fresh_seed()?).run()?;
    let peer = match ev1 {
        HostEvent::HandshakeProgress { addr } => Ok(addr),
        other @ (HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeProgress, got {other:?}"),
        }),
    }?;
    // After the initial cookie challenge the responder validates the
    // echoed cookie (another `HandshakeProgress`) before writing msg2
    // and finally observing `HandshakeComplete`.  Recurse over the
    // intermediate progress events until completion.
    drive_handshake_to_completion(host, peer).map(|host| (host, peer))
}

/// Step `recv_one` until the handshake with `peer` reports
/// `HandshakeComplete`, absorbing any intermediate
/// `HandshakeProgress` events emitted by the cookie round-trip.
fn drive_handshake_to_completion(host: Host, peer: UdpAddr) -> Result<Host, Error> {
    let (host, ev) = host.recv_one(fresh_seed()?).run()?;
    match ev {
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
            remote_peer_id,
        } if addr == peer => {
            announce_handshake(&remote_static, &remote_peer_id)?;
            Ok(host)
        }
        HostEvent::HandshakeProgress { addr } if addr == peer => {
            drive_handshake_to_completion(host, peer)
        }
        other @ (HostEvent::HandshakeProgress { .. }
        | HostEvent::HandshakeComplete { .. }
        | HostEvent::DatagramDelivered { .. }
        | HostEvent::Rejected { .. }) => Err(Error::HostState {
            reason: format!("expected HandshakeComplete from {peer}, got {other:?}"),
        }),
    }
}

fn announce_handshake(
    remote_static: &libp2p_cat_rs::StaticPublicKey,
    remote_peer_id: &PeerId,
) -> Result<(), Error> {
    writeln!(
        stdout(),
        "handshake complete\n  remote peer id = {remote_peer_id}\n  remote static  = {:02x?}",
        remote_static.as_bytes()
    )
    .map_err(Error::from)?;
    Ok(())
}

/// Recursive event loop: alternates between [`Turn::Send`] (read a
/// stdin line and ship it) and [`Turn::Recv`] (block on the socket
/// and surface what arrives).
fn chat_step(host: Host, peer: UdpAddr, turn: Turn) -> Result<(), Error> {
    match turn {
        Turn::Send => send_step(host, peer),
        Turn::Recv => recv_step(host, peer),
    }
}

fn send_step(host: Host, peer: UdpAddr) -> Result<(), Error> {
    let line = read_line("you> ")?;
    if line.is_empty() {
        Ok(())
    } else {
        let host = host.send(peer, line.into_bytes()).run()?;
        chat_step(host, peer, Turn::Recv)
    }
}

fn recv_step(host: Host, peer: UdpAddr) -> Result<(), Error> {
    let (host, ev) = host.recv_one(fresh_seed()?).run()?;
    match ev {
        HostEvent::DatagramDelivered { addr, plaintext } if addr == peer => {
            print_incoming(&plaintext)?;
            chat_step(host, peer, Turn::Send)
        }
        HostEvent::DatagramDelivered { addr, .. } => {
            warn(&format!("ignoring datagram from unexpected peer {addr}"))?;
            chat_step(host, peer, Turn::Recv)
        }
        HostEvent::Rejected { addr, reason } => {
            warn(&format!("rejected datagram from {addr}: {reason}"))?;
            chat_step(host, peer, Turn::Recv)
        }
        HostEvent::HandshakeProgress { addr } => {
            warn(&format!(
                "unexpected mid-chat HandshakeProgress from {addr}"
            ))?;
            chat_step(host, peer, Turn::Recv)
        }
        HostEvent::HandshakeComplete { addr, .. } => {
            warn(&format!(
                "unexpected mid-chat HandshakeComplete from {addr}"
            ))?;
            chat_step(host, peer, Turn::Recv)
        }
    }
}

fn read_line(prompt: &str) -> Result<String, Error> {
    write!(stdout(), "{prompt}").map_err(Error::from)?;
    stdout().flush().map_err(Error::from)?;
    let mut buffer = String::new();
    let read = stdin().lock().read_line(&mut buffer).map_err(Error::from)?;
    if read == 0 {
        // EOF; treat as empty line and let the caller exit.
        Ok(String::new())
    } else {
        Ok(buffer.trim_end_matches(['\n', '\r']).to_owned())
    }
}

fn print_incoming(bytes: &[u8]) -> Result<(), Error> {
    let text = String::from_utf8_lossy(bytes);
    writeln!(stdout(), "peer> {text}").map_err(Error::from)?;
    Ok(())
}

fn warn(msg: &str) -> Result<(), Error> {
    writeln!(std::io::stderr(), "[warn] {msg}").map_err(Error::from)?;
    Ok(())
}
