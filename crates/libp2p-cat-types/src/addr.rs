//! UDP-only transport address.
//!
//! libp2p's full `Multiaddr` is intentionally *not* mirrored: this crate
//! exposes only the UDP path, so TCP / QUIC / WebSocket addresses are
//! unrepresentable in the type system.  Higher layers cannot accidentally
//! accept a non-UDP transport.
//!
//! # Examples
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use std::net::{Ipv4Addr, SocketAddrV4};
//! use libp2p_cat_types::UdpAddr;
//!
//! let a = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4001));
//! (a.to_string() == "/ip4/127.0.0.1/udp/4001")
//!     .then_some(())
//!     .ok_or("display does not match expected multiaddr form")?;
//! # Ok(()) }
//! ```

use core::fmt;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

/// A UDP transport address.
///
/// Only IPv4 and IPv6 socket addresses are representable.  Conversion
/// to and from [`std::net::SocketAddr`] is total; conversion from
/// other transports is not provided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[must_use]
pub enum UdpAddr {
    /// IPv4 UDP address.
    V4(SocketAddrV4),
    /// IPv6 UDP address.
    V6(SocketAddrV6),
}

impl From<SocketAddrV4> for UdpAddr {
    fn from(a: SocketAddrV4) -> Self {
        Self::V4(a)
    }
}

impl From<SocketAddrV6> for UdpAddr {
    fn from(a: SocketAddrV6) -> Self {
        Self::V6(a)
    }
}

impl From<SocketAddr> for UdpAddr {
    fn from(a: SocketAddr) -> Self {
        match a {
            SocketAddr::V4(s) => Self::V4(s),
            SocketAddr::V6(s) => Self::V6(s),
        }
    }
}

impl From<UdpAddr> for SocketAddr {
    fn from(a: UdpAddr) -> Self {
        match a {
            UdpAddr::V4(s) => Self::V4(s),
            UdpAddr::V6(s) => Self::V6(s),
        }
    }
}

impl fmt::Display for UdpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(s) => write!(f, "/ip4/{}/udp/{}", s.ip(), s.port()),
            Self::V6(s) => write!(f, "/ip6/{}/udp/{}", s.ip(), s.port()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    #[test]
    fn v4_roundtrip_through_socket_addr() -> Result<(), Error> {
        let original = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4001));
        let socket = SocketAddr::from(original);
        let back = UdpAddr::from(socket);
        check(original == back, || {
            format!("v4 roundtrip mismatch: {original:?} != {back:?}")
        })
    }

    #[test]
    fn v6_roundtrip_through_socket_addr() -> Result<(), Error> {
        let original = UdpAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 4001, 0, 0));
        let socket = SocketAddr::from(original);
        let back = UdpAddr::from(socket);
        check(original == back, || {
            format!("v6 roundtrip mismatch: {original:?} != {back:?}")
        })
    }

    #[test]
    fn display_uses_multiaddr_style() -> Result<(), Error> {
        let a = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4001));
        let rendered = a.to_string();
        check(rendered == "/ip4/10.0.0.1/udp/4001", || {
            format!("unexpected display: {rendered}")
        })
    }
}
