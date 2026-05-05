//! Wire encoding for rendezvous RPC frames.
//!
//! Frames are sent as the *plaintext* of a [`Host::send`] transport
//! datagram (Noise encrypts and authenticates the full plaintext
//! once on each side).
//!
//! [`Host::send`]: libp2p_cat_host::Host::send
//!
//! # Frame layout
//!
//! ```text
//! +---------+--------------------+
//! | op (1)  | body (variable)    |
//! +---------+--------------------+
//! ```
//!
//! Opcodes (see [`Opcode`]):
//!
//! - [`Opcode::ObserveReq`] (`0x00`): 0-byte body.
//! - [`Opcode::ObserveResp`] (`0x01`): a `UdpAddr`-shaped body
//!   (1-byte addr-kind + IPv4(4) / IPv6(16) + 2-byte BE port).
//!   7 bytes for V4, 19 for V6.
//! - [`Opcode::PunchReq`] (`0x02`): a `UdpAddr`-shaped body carrying
//!   the target peer's address; the requester is asking the
//!   recipient to relay a punch request to that target.
//! - [`Opcode::PunchForward`] (`0x03`): a `UdpAddr`-shaped body
//!   carrying the original initiator's address; the receiver should
//!   fire a bare-datagram "punch" at that address to open its NAT
//!   mapping.
//!
//! IPv6 `flowinfo` and `scope_id` fields are encoded as `0`; non-zero
//! values supplied by the caller are dropped on the wire.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use libp2p_cat_types::{Error, UdpAddr};

/// Opcode tag occupying the first byte of every frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub enum Opcode {
    /// Caller is asking the recipient to report the address it
    /// observed the inbound packet coming from.
    ObserveReq,
    /// Recipient's reply, carrying the observed [`UdpAddr`].
    ObserveResp,
    /// Caller is asking the recipient (a rendezvous server) to
    /// relay a punch request to the carried target address.
    PunchReq,
    /// Server is forwarding a `PunchReq` to the carried initiator
    /// address; the receiver should fire a punch datagram at that
    /// initiator.
    PunchForward,
}

impl Opcode {
    /// Wire-byte for this opcode.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::ObserveReq => 0x00,
            Self::ObserveResp => 0x01,
            Self::PunchReq => 0x02,
            Self::PunchForward => 0x03,
        }
    }

    /// Parse an opcode byte.
    ///
    /// # Errors
    ///
    /// - [`Error::PubsubProtocol`] (used as the workspace's generic
    ///   "wire protocol violation" carrier) for any unknown opcode.
    pub fn from_byte(byte: u8) -> Result<Self, Error> {
        match byte {
            0x00 => Ok(Self::ObserveReq),
            0x01 => Ok(Self::ObserveResp),
            0x02 => Ok(Self::PunchReq),
            0x03 => Ok(Self::PunchForward),
            n => Err(protocol_error(format!(
                "unknown rendezvous opcode 0x{n:02x}"
            ))),
        }
    }
}

/// A decoded rendezvous frame.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum Frame {
    /// Empty-body request: "what address do you see me coming from?"
    ObserveReq,
    /// Reply carrying the address the responder observed.
    ObserveResp {
        /// The address the responder saw the inbound packet
        /// coming from.
        observed: UdpAddr,
    },
    /// Asks the recipient (a rendezvous server) to forward a punch
    /// request to `target`.
    PunchReq {
        /// Address of the peer the requester wants to reach.
        target: UdpAddr,
    },
    /// Server is forwarding a punch request that originated at
    /// `initiator`.  The receiver should fire a bare punch datagram
    /// at `initiator` to open its NAT mapping.
    PunchForward {
        /// Address of the peer that asked the server for the
        /// punch.
        initiator: UdpAddr,
    },
}

const ADDR_KIND_V4: u8 = 0x04;
const ADDR_KIND_V6: u8 = 0x06;
const ADDR_V4_BODY_LEN: usize = 4 + 2;
const ADDR_V6_BODY_LEN: usize = 16 + 2;

/// Wire size of an `OBSERVE_RESP` frame carrying an IPv4 address:
/// 1-byte opcode + 1-byte addr kind + 4-byte IPv4 + 2-byte port.
pub const OBSERVE_RESP_V4_LEN: usize = 1 + 1 + ADDR_V4_BODY_LEN;

/// Wire size of an `OBSERVE_RESP` frame carrying an IPv6 address:
/// 1-byte opcode + 1-byte addr kind + 16-byte IPv6 + 2-byte port.
pub const OBSERVE_RESP_V6_LEN: usize = 1 + 1 + ADDR_V6_BODY_LEN;

/// Serialise a [`Frame`] to its wire bytes.
///
/// # Errors
///
/// Currently infallible; the result type is preserved for API
/// symmetry with the kad codec and in case a future variant fails to
/// encode (e.g. a bound on advertised peer counts).
pub fn encode(frame: &Frame) -> Result<Vec<u8>, Error> {
    match frame {
        Frame::ObserveReq => Ok(vec![Opcode::ObserveReq.to_byte()]),
        Frame::ObserveResp { observed } => Ok(core::iter::once(Opcode::ObserveResp.to_byte())
            .chain(encode_addr(observed))
            .collect()),
        Frame::PunchReq { target } => Ok(core::iter::once(Opcode::PunchReq.to_byte())
            .chain(encode_addr(target))
            .collect()),
        Frame::PunchForward { initiator } => Ok(core::iter::once(Opcode::PunchForward.to_byte())
            .chain(encode_addr(initiator))
            .collect()),
    }
}

fn encode_addr(addr: &UdpAddr) -> Vec<u8> {
    match addr {
        UdpAddr::V4(s) => core::iter::once(ADDR_KIND_V4)
            .chain(s.ip().octets())
            .chain(s.port().to_be_bytes())
            .collect(),
        UdpAddr::V6(s) => core::iter::once(ADDR_KIND_V6)
            .chain(s.ip().octets())
            .chain(s.port().to_be_bytes())
            .collect(),
    }
}

/// Parse a wire frame from a freshly-decrypted Host plaintext.
///
/// # Errors
///
/// - [`Error::PubsubProtocol`] for any structural violation: empty
///   buffer, unknown opcode, body too short for the declared shape,
///   or trailing bytes after a fully-parsed frame.
pub fn decode(bytes: &[u8]) -> Result<Frame, Error> {
    let opcode_byte = bytes
        .first()
        .copied()
        .ok_or_else(|| protocol_error("rendezvous frame is empty".to_owned()))?;
    let opcode = Opcode::from_byte(opcode_byte)?;
    let body = bytes.get(1..).unwrap_or(&[]);
    match opcode {
        Opcode::ObserveReq => decode_observe_req(body),
        Opcode::ObserveResp => decode_addr_body(body, |observed| Frame::ObserveResp { observed }),
        Opcode::PunchReq => decode_addr_body(body, |target| Frame::PunchReq { target }),
        Opcode::PunchForward => {
            decode_addr_body(body, |initiator| Frame::PunchForward { initiator })
        }
    }
}

fn decode_observe_req(body: &[u8]) -> Result<Frame, Error> {
    if body.is_empty() {
        Ok(Frame::ObserveReq)
    } else {
        Err(protocol_error(format!(
            "ObserveReq expects an empty body, got {} bytes",
            body.len()
        )))
    }
}

/// Parse a body that consists of exactly one [`UdpAddr`] and wrap
/// the result in a [`Frame`] via `wrap`.  Used for `OBSERVE_RESP`,
/// `PUNCH_REQ`, and `PUNCH_FORWARD`.
fn decode_addr_body<F>(body: &[u8], wrap: F) -> Result<Frame, Error>
where
    F: FnOnce(UdpAddr) -> Frame,
{
    let (addr, consumed) = decode_addr(body)?;
    let trailing = body.get(consumed..).unwrap_or(&[]);
    if trailing.is_empty() {
        Ok(wrap(addr))
    } else {
        Err(protocol_error(format!(
            "addr-bearing frame has {} unexpected trailing bytes",
            trailing.len()
        )))
    }
}

fn decode_addr(buf: &[u8]) -> Result<(UdpAddr, usize), Error> {
    let kind = buf
        .first()
        .copied()
        .ok_or_else(|| protocol_error("addr kind byte missing".to_owned()))?;
    let body = buf.get(1..).unwrap_or(&[]);
    match kind {
        ADDR_KIND_V4 => decode_addr_v4(body).map(|addr| (addr, 1 + ADDR_V4_BODY_LEN)),
        ADDR_KIND_V6 => decode_addr_v6(body).map(|addr| (addr, 1 + ADDR_V6_BODY_LEN)),
        other => Err(protocol_error(format!("unknown addr kind 0x{other:02x}"))),
    }
}

fn decode_addr_v4(body: &[u8]) -> Result<UdpAddr, Error> {
    let ip_slice = body
        .get(..4)
        .ok_or_else(|| protocol_error("V4 addr needs 4 IP bytes".to_owned()))?;
    let port_slice = body
        .get(4..ADDR_V4_BODY_LEN)
        .ok_or_else(|| protocol_error("V4 addr needs 2 port bytes".to_owned()))?;
    let ip_arr: [u8; 4] = ip_slice
        .try_into()
        .map_err(|_| protocol_error("V4 IP slice not 4 bytes wide".to_owned()))?;
    let port_arr: [u8; 2] = port_slice
        .try_into()
        .map_err(|_| protocol_error("V4 port slice not 2 bytes wide".to_owned()))?;
    let port = u16::from_be_bytes(port_arr);
    Ok(UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip_arr), port)))
}

fn decode_addr_v6(body: &[u8]) -> Result<UdpAddr, Error> {
    let ip_slice = body
        .get(..16)
        .ok_or_else(|| protocol_error("V6 addr needs 16 IP bytes".to_owned()))?;
    let port_slice = body
        .get(16..ADDR_V6_BODY_LEN)
        .ok_or_else(|| protocol_error("V6 addr needs 2 port bytes".to_owned()))?;
    let ip_arr: [u8; 16] = ip_slice
        .try_into()
        .map_err(|_| protocol_error("V6 IP slice not 16 bytes wide".to_owned()))?;
    let port_arr: [u8; 2] = port_slice
        .try_into()
        .map_err(|_| protocol_error("V6 port slice not 2 bytes wide".to_owned()))?;
    let port = u16::from_be_bytes(port_arr);
    Ok(UdpAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(ip_arr),
        port,
        0,
        0,
    )))
}

fn protocol_error(reason: String) -> Error {
    Error::PubsubProtocol { reason }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use libp2p_cat_types::Error;

    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    #[test]
    fn observe_req_round_trip() -> Result<(), Error> {
        let bytes = encode(&Frame::ObserveReq)?;
        check(bytes == vec![0x00], || {
            format!("expected [0x00], got {bytes:?}")
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == Frame::ObserveReq, || {
            format!("decode mismatch: {parsed:?}")
        })
    }

    #[test]
    fn observe_resp_v4_round_trip() -> Result<(), Error> {
        let observed = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4242));
        let frame = Frame::ObserveResp { observed };
        let bytes = encode(&frame)?;
        check(bytes.len() == OBSERVE_RESP_V4_LEN, || {
            format!(
                "expected wire length {OBSERVE_RESP_V4_LEN}, got {}",
                bytes.len()
            )
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == frame, || format!("decode mismatch: {parsed:?}"))
    }

    #[test]
    fn observe_resp_v6_round_trip() -> Result<(), Error> {
        let observed = UdpAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7777, 0, 0));
        let frame = Frame::ObserveResp { observed };
        let bytes = encode(&frame)?;
        check(bytes.len() == OBSERVE_RESP_V6_LEN, || {
            format!(
                "expected wire length {OBSERVE_RESP_V6_LEN}, got {}",
                bytes.len()
            )
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == frame, || format!("decode mismatch: {parsed:?}"))
    }

    #[test]
    fn empty_buffer_is_rejected() -> Result<(), Error> {
        match decode(&[]) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
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
            ) => Err(Error::HostState {
                reason: format!("expected PubsubProtocol, got {other:?}"),
            }),
            Ok(parsed) => Err(Error::HostState {
                reason: format!("expected rejection, got Ok({parsed:?})"),
            }),
        }
    }

    #[test]
    fn unknown_opcode_is_rejected() -> Result<(), Error> {
        expect_protocol_rejection(decode(&[0xFF]))
    }

    #[test]
    fn observe_req_rejects_trailing_bytes() -> Result<(), Error> {
        expect_protocol_rejection(decode(&[0x00, 0xAA]))
    }

    #[test]
    fn observe_resp_rejects_unknown_addr_kind() -> Result<(), Error> {
        // opcode 0x01, addr_kind 0x09 (unknown), 6 zero bytes.
        let bytes: Vec<u8> = core::iter::once(0x01u8)
            .chain(core::iter::once(0x09u8))
            .chain([0u8; 6])
            .collect();
        expect_protocol_rejection(decode(&bytes))
    }

    #[test]
    fn observe_resp_rejects_truncated_v4() -> Result<(), Error> {
        // opcode 0x01, V4 kind, only 5 trailing bytes (need 6).
        let bytes: Vec<u8> = core::iter::once(0x01u8)
            .chain(core::iter::once(ADDR_KIND_V4))
            .chain([0u8; 5])
            .collect();
        expect_protocol_rejection(decode(&bytes))
    }

    #[test]
    fn punch_req_round_trip() -> Result<(), Error> {
        let target = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 4242));
        let frame = Frame::PunchReq { target };
        let bytes = encode(&frame)?;
        check(bytes.first() == Some(&0x02), || {
            format!("expected PUNCH_REQ opcode 0x02, got {:?}", bytes.first())
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == frame, || format!("decode mismatch: {parsed:?}"))
    }

    #[test]
    fn punch_forward_round_trip() -> Result<(), Error> {
        let initiator = UdpAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        let frame = Frame::PunchForward { initiator };
        let bytes = encode(&frame)?;
        check(bytes.first() == Some(&0x03), || {
            format!(
                "expected PUNCH_FORWARD opcode 0x03, got {:?}",
                bytes.first()
            )
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == frame, || format!("decode mismatch: {parsed:?}"))
    }

    #[test]
    fn punch_req_rejects_truncated_addr() -> Result<(), Error> {
        // opcode 0x02, V4 kind, only 5 trailing bytes (need 6).
        let bytes: Vec<u8> = core::iter::once(0x02u8)
            .chain(core::iter::once(ADDR_KIND_V4))
            .chain([0u8; 5])
            .collect();
        expect_protocol_rejection(decode(&bytes))
    }

    #[test]
    fn punch_forward_rejects_trailing_bytes() -> Result<(), Error> {
        let initiator = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242));
        let frame = Frame::PunchForward { initiator };
        let bytes = encode(&frame)?;
        let extended: Vec<u8> = bytes.into_iter().chain(core::iter::once(0xAAu8)).collect();
        expect_protocol_rejection(decode(&extended))
    }

    /// Helper: assert that `outcome` is `Err(Error::PubsubProtocol)`,
    /// enumerating every other `Error` variant and the `Ok` case
    /// explicitly so a new variant cannot silently slip through.
    fn expect_protocol_rejection(outcome: Result<Frame, Error>) -> Result<(), Error> {
        match outcome {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
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
            ) => Err(Error::HostState {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
            Ok(parsed) => Err(Error::HostState {
                reason: format!("expected rejection, got Ok({parsed:?})"),
            }),
        }
    }
}
