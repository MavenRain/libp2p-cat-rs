//! Wire encoding for Kademlia RPC frames.
//!
//! All frames are sent as the *plaintext* of a [`Host::send`]
//! transport datagram (i.e. they are encrypted by Noise once and
//! parsed once on the other side).  No length-prefixing is needed
//! at this layer: the AEAD already authenticates the full plaintext
//! length.
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
//! - [`Opcode::PingReq`] (`0x00`): 0-byte body.
//! - [`Opcode::PingResp`] (`0x01`): 0-byte body.
//! - [`Opcode::FindNodeReq`] (`0x02`): 32-byte target [`NodeId`].
//! - [`Opcode::FindNodeResp`] (`0x03`): 1-byte count, then `count`
//!   entries each shaped as `[NodeId (32) | addr_kind (1) | IP | port_be (2)]`.
//!
//! IPv4 entries take 32 + 1 + 4 + 2 = 39 bytes; IPv6 entries take
//! 32 + 1 + 16 + 2 = 51 bytes.  At a typical `k = 20` and pure-IPv6
//! responses the maximum body is `1 + 20 * 51 = 1021` bytes, well
//! within Noise's per-datagram budget.
//!
//! IPv6 `flowinfo` and `scope_id` fields are encoded as `0`; any
//! non-zero values supplied by the caller are dropped on the wire.
//! Pass 2 does not target link-local IPv6.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use libp2p_cat_types::{Error, UdpAddr};

use crate::node_id::{NODE_ID_LEN, NodeId};

/// Opcode tag occupying the first byte of every frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub enum Opcode {
    /// Caller is asking the recipient to confirm liveness.
    PingReq,
    /// Recipient confirms liveness.
    PingResp,
    /// Caller is asking the recipient to return up to `k` peers
    /// closest to the supplied target [`NodeId`].
    FindNodeReq,
    /// Recipient's answer to a `FindNodeReq`.
    FindNodeResp,
}

impl Opcode {
    /// Wire-byte for this opcode.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::PingReq => 0x00,
            Self::PingResp => 0x01,
            Self::FindNodeReq => 0x02,
            Self::FindNodeResp => 0x03,
        }
    }

    /// Parse an opcode byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PubsubProtocol`] (re-used as a generic
    /// "wire protocol violation" carrier in this workspace) for any
    /// unknown opcode.
    pub fn from_byte(byte: u8) -> Result<Self, Error> {
        match byte {
            0x00 => Ok(Self::PingReq),
            0x01 => Ok(Self::PingResp),
            0x02 => Ok(Self::FindNodeReq),
            0x03 => Ok(Self::FindNodeResp),
            n => Err(protocol_error(format!("unknown kad opcode 0x{n:02x}"))),
        }
    }
}

/// A decoded Kademlia frame.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum Frame {
    /// Empty-body PING request.
    PingReq,
    /// Empty-body PING response.
    PingResp,
    /// `target` is the [`NodeId`] the requester wants closest peers to.
    FindNodeReq { target: NodeId },
    /// Up to `k` peers closest to the original `target`.
    FindNodeResp { peers: Vec<(NodeId, UdpAddr)> },
}

/// Maximum number of peers that may appear in a single
/// [`Frame::FindNodeResp`].  Limited by the 1-byte count prefix.
pub const MAX_PEERS_PER_RESP: usize = 255;

const ADDR_KIND_V4: u8 = 0x04;
const ADDR_KIND_V6: u8 = 0x06;
const ADDR_V4_BODY_LEN: usize = 4 + 2;
const ADDR_V6_BODY_LEN: usize = 16 + 2;

/// Wire size of a single `(NodeId, UdpAddr::V4)` entry inside a
/// [`Frame::FindNodeResp`]: 32-byte `NodeId` + 1-byte addr kind +
/// 4-byte IPv4 + 2-byte port.
pub const ENTRY_V4_LEN: usize = NODE_ID_LEN + 1 + ADDR_V4_BODY_LEN;

/// Wire size of a single `(NodeId, UdpAddr::V6)` entry inside a
/// [`Frame::FindNodeResp`]: 32-byte `NodeId` + 1-byte addr kind +
/// 16-byte IPv6 + 2-byte port.
pub const ENTRY_V6_LEN: usize = NODE_ID_LEN + 1 + ADDR_V6_BODY_LEN;

/// Serialise a [`Frame`] to its wire bytes.
///
/// # Errors
///
/// - [`Error::PubsubProtocol`] if a [`Frame::FindNodeResp`] holds more
///   than [`MAX_PEERS_PER_RESP`] entries.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, Error> {
    match frame {
        Frame::PingReq => Ok(vec![Opcode::PingReq.to_byte()]),
        Frame::PingResp => Ok(vec![Opcode::PingResp.to_byte()]),
        Frame::FindNodeReq { target } => Ok(core::iter::once(Opcode::FindNodeReq.to_byte())
            .chain(target.as_bytes().iter().copied())
            .collect()),
        Frame::FindNodeResp { peers } => encode_find_node_resp(peers),
    }
}

fn encode_find_node_resp(peers: &[(NodeId, UdpAddr)]) -> Result<Vec<u8>, Error> {
    let count = u8::try_from(peers.len()).map_err(|_| {
        protocol_error(format!(
            "FindNodeResp peer count {} exceeds the 1-byte cap of {MAX_PEERS_PER_RESP}",
            peers.len()
        ))
    })?;
    let bytes: Vec<u8> = core::iter::once(Opcode::FindNodeResp.to_byte())
        .chain(core::iter::once(count))
        .chain(peers.iter().flat_map(|(id, addr)| encode_entry(id, addr)))
        .collect();
    Ok(bytes)
}

fn encode_entry(id: &NodeId, addr: &UdpAddr) -> Vec<u8> {
    let id_bytes = id.as_bytes().iter().copied();
    let addr_bytes = encode_addr(addr);
    id_bytes.chain(addr_bytes).collect()
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
        .ok_or_else(|| protocol_error("kad frame is empty".to_owned()))?;
    let opcode = Opcode::from_byte(opcode_byte)?;
    let body = bytes.get(1..).unwrap_or(&[]);
    match opcode {
        Opcode::PingReq | Opcode::PingResp => decode_no_body(opcode, body),
        Opcode::FindNodeReq => decode_find_node_req(body),
        Opcode::FindNodeResp => decode_find_node_resp(body),
    }
}

fn decode_no_body(opcode: Opcode, body: &[u8]) -> Result<Frame, Error> {
    if body.is_empty() {
        match opcode {
            Opcode::PingReq => Ok(Frame::PingReq),
            Opcode::PingResp => Ok(Frame::PingResp),
            Opcode::FindNodeReq | Opcode::FindNodeResp => Err(protocol_error(format!(
                "decode_no_body called with body-bearing opcode {opcode:?}"
            ))),
        }
    } else {
        Err(protocol_error(format!(
            "{opcode:?} expects an empty body, got {} bytes",
            body.len()
        )))
    }
}

fn decode_find_node_req(body: &[u8]) -> Result<Frame, Error> {
    let target_slice = body.get(..NODE_ID_LEN).ok_or_else(|| {
        protocol_error(format!(
            "FindNodeReq needs {NODE_ID_LEN} bytes, got {}",
            body.len()
        ))
    })?;
    let trailing = body.get(NODE_ID_LEN..).unwrap_or(&[]);
    if trailing.is_empty() {
        let arr: [u8; NODE_ID_LEN] = target_slice
            .try_into()
            .map_err(|_| protocol_error("FindNodeReq target slice not 32 bytes wide".to_owned()))?;
        Ok(Frame::FindNodeReq {
            target: NodeId::from_bytes(arr),
        })
    } else {
        Err(protocol_error(format!(
            "FindNodeReq has {} unexpected trailing bytes",
            trailing.len()
        )))
    }
}

fn decode_find_node_resp(body: &[u8]) -> Result<Frame, Error> {
    let count_byte = body
        .first()
        .copied()
        .ok_or_else(|| protocol_error("FindNodeResp missing count byte".to_owned()))?;
    let count = usize::from(count_byte);
    let entries_slice = body.get(1..).unwrap_or(&[]);
    let (peers, consumed) = decode_entries(entries_slice, count)?;
    let trailing = entries_slice.get(consumed..).unwrap_or(&[]);
    if trailing.is_empty() {
        Ok(Frame::FindNodeResp { peers })
    } else {
        Err(protocol_error(format!(
            "FindNodeResp has {} unexpected trailing bytes after {count} entries",
            trailing.len()
        )))
    }
}

fn decode_entries(buf: &[u8], count: usize) -> Result<(Vec<(NodeId, UdpAddr)>, usize), Error> {
    (0..count).try_fold(
        (Vec::with_capacity(count), 0usize),
        |(mut acc, offset), idx| {
            let chunk = buf.get(offset..).unwrap_or(&[]);
            let (entry, consumed) = decode_entry(chunk).map_err(|e| {
                protocol_error(format!("FindNodeResp entry {idx} decode failed: {e}"))
            })?;
            acc.push(entry);
            Ok((acc, offset + consumed))
        },
    )
}

fn decode_entry(buf: &[u8]) -> Result<((NodeId, UdpAddr), usize), Error> {
    let id_slice = buf.get(..NODE_ID_LEN).ok_or_else(|| {
        protocol_error(format!(
            "entry NodeId needs {NODE_ID_LEN} bytes, got {}",
            buf.len()
        ))
    })?;
    let id_arr: [u8; NODE_ID_LEN] = id_slice
        .try_into()
        .map_err(|_| protocol_error("entry NodeId slice not 32 bytes wide".to_owned()))?;
    let id = NodeId::from_bytes(id_arr);
    let after_id = buf.get(NODE_ID_LEN..).unwrap_or(&[]);
    let (addr, addr_consumed) = decode_addr(after_id)?;
    Ok(((id, addr), NODE_ID_LEN + addr_consumed))
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
    fn ping_req_round_trip() -> Result<(), Error> {
        let bytes = encode(&Frame::PingReq)?;
        check(bytes == vec![0x00], || {
            format!("expected [0x00], got {bytes:?}")
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == Frame::PingReq, || {
            format!("decode mismatch: {parsed:?}")
        })
    }

    #[test]
    fn ping_resp_round_trip() -> Result<(), Error> {
        let bytes = encode(&Frame::PingResp)?;
        check(bytes == vec![0x01], || {
            format!("expected [0x01], got {bytes:?}")
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == Frame::PingResp, || {
            format!("decode mismatch: {parsed:?}")
        })
    }

    #[test]
    fn find_node_req_round_trip() -> Result<(), Error> {
        let target = NodeId::from_bytes([7u8; NODE_ID_LEN]);
        let frame = Frame::FindNodeReq { target };
        let bytes = encode(&frame)?;
        check(bytes.len() == 1 + NODE_ID_LEN, || {
            format!("FindNodeReq wire length should be 33, got {}", bytes.len())
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == frame, || format!("decode mismatch: {parsed:?}"))
    }

    #[test]
    fn find_node_resp_v4_round_trip() -> Result<(), Error> {
        let peers = vec![
            (
                NodeId::from_bytes([1u8; NODE_ID_LEN]),
                UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000)),
            ),
            (
                NodeId::from_bytes([2u8; NODE_ID_LEN]),
                UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6000)),
            ),
        ];
        let frame = Frame::FindNodeResp {
            peers: peers.clone(),
        };
        let bytes = encode(&frame)?;
        let expected = 1 + 1 + peers.len() * ENTRY_V4_LEN;
        check(bytes.len() == expected, || {
            format!("expected wire length {expected}, got {}", bytes.len())
        })?;
        let parsed = decode(&bytes)?;
        check(parsed == frame, || format!("decode mismatch: {parsed:?}"))
    }

    #[test]
    fn find_node_resp_v6_round_trip() -> Result<(), Error> {
        let peers = vec![(
            NodeId::from_bytes([0xAB; NODE_ID_LEN]),
            UdpAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7000, 0, 0)),
        )];
        let frame = Frame::FindNodeResp {
            peers: peers.clone(),
        };
        let bytes = encode(&frame)?;
        let expected = 1 + 1 + peers.len() * ENTRY_V6_LEN;
        check(bytes.len() == expected, || {
            format!("expected wire length {expected}, got {}", bytes.len())
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
        match decode(&[0xFF]) {
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
    fn ping_req_rejects_trailing_bytes() -> Result<(), Error> {
        // PingReq has an empty body; trailing bytes must be rejected
        // so an attacker cannot smuggle a PING-shaped frame with a
        // payload past the parser.
        match decode(&[0x00, 0xAA]) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            other => Err(Error::HostState {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
        }
    }

    #[test]
    fn find_node_req_rejects_short_target() -> Result<(), Error> {
        // 1 (opcode) + 31 zeros (one byte short of NODE_ID_LEN).
        let truncated: Vec<u8> = core::iter::once(0x02u8).chain([0u8; 31]).collect();
        match decode(&truncated) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            other => Err(Error::HostState {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
        }
    }

    #[test]
    fn find_node_resp_rejects_count_underflow() -> Result<(), Error> {
        // count=2 but only one entry's worth of body.
        let mut bytes = vec![0x03u8, 0x02u8];
        bytes.extend(core::iter::repeat_n(0u8, ENTRY_V4_LEN));
        match decode(&bytes) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            other => Err(Error::HostState {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
        }
    }

    #[test]
    fn find_node_resp_rejects_unknown_addr_kind() -> Result<(), Error> {
        // count=1, NodeId zeros, addr_kind=0x09 (unknown), then 6 zero bytes.
        let bytes: Vec<u8> = core::iter::once(0x03u8)
            .chain(core::iter::once(0x01u8))
            .chain([0u8; NODE_ID_LEN])
            .chain(core::iter::once(0x09u8))
            .chain([0u8; 6])
            .collect();
        match decode(&bytes) {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            other => Err(Error::HostState {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
        }
    }
}
