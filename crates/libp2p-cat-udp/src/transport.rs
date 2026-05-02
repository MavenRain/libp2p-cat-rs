//! Linear-state-threaded UDP transport.
//!
//! The single public type [`UdpTransport`] wraps a [`std::net::UdpSocket`]
//! and exposes its operations as `Io<Error, _>` arrows.  Every effectful
//! operation consumes the transport and returns it, so callers thread
//! the value through `flat_map` chains without ever holding a `&mut`.
//!
//! Datagram size limits are explicit: `max_send_payload` is enforced on
//! [`send`], and `recv_buf_size` bounds the receive scratch buffer.  By
//! default the receive ceiling is [`MAX_UDP_PAYLOAD`] so the kernel
//! never silently truncates an inbound datagram.
//!
//! [`send`]: UdpTransport::send

use std::net::{SocketAddr, UdpSocket};

use comp_cat_rs::effect::io::Io;
use libp2p_cat_types::{Error, UdpAddr};

/// Default outbound payload ceiling, in bytes.
///
/// Matches QUIC's initial-packet IPv6 minimum (1200) plus typical
/// Ethernet headroom — well under any plausible path MTU.  Higher
/// layers should fragment above this.
pub const DEFAULT_MAX_DATAGRAM: usize = 1500;

/// Hard ceiling on the receive buffer, in bytes.
///
/// `65_507 = 65_535 - 8 (UDP header) - 20 (IPv4 header)` — the maximum
/// payload a single UDP datagram can carry over IPv4.  Sized to
/// guarantee the kernel never truncates an inbound datagram.
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// A bound UDP socket, exposed as a linear `Io`-shaped transport.
///
/// Construct one with [`bind`] or [`bind_with_limits`] and thread it
/// through `flat_map` chains using [`send`] and [`recv`].
///
/// [`bind`]: UdpTransport::bind
/// [`bind_with_limits`]: UdpTransport::bind_with_limits
/// [`send`]: UdpTransport::send
/// [`recv`]: UdpTransport::recv
#[must_use]
pub struct UdpTransport {
    socket: UdpSocket,
    max_send_payload: usize,
    recv_buf_size: usize,
}

impl UdpTransport {
    /// Bind to `addr` with the default datagram limits
    /// ([`DEFAULT_MAX_DATAGRAM`] outbound, [`MAX_UDP_PAYLOAD`] inbound).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot bind the socket.
    #[must_use]
    pub fn bind(addr: UdpAddr) -> Io<Error, Self> {
        Self::bind_with_limits(addr, DEFAULT_MAX_DATAGRAM, MAX_UDP_PAYLOAD)
    }

    /// Bind with explicit send and receive payload limits.
    ///
    /// `max_send_payload` is enforced on every [`send`] call; oversized
    /// payloads are rejected with [`Error::DatagramTooLarge`] before
    /// touching the socket.  `recv_buf_size` sizes the scratch buffer
    /// allocated for each [`recv`] call; datagrams larger than this
    /// would be truncated by the kernel, so callers should leave it at
    /// [`MAX_UDP_PAYLOAD`] unless they know their peers send strictly
    /// smaller datagrams and they want the smaller allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot bind the socket.
    ///
    /// [`send`]: UdpTransport::send
    /// [`recv`]: UdpTransport::recv
    #[must_use]
    pub fn bind_with_limits(
        addr: UdpAddr,
        max_send_payload: usize,
        recv_buf_size: usize,
    ) -> Io<Error, Self> {
        Io::suspend(move || {
            UdpSocket::bind(SocketAddr::from(addr))
                .map(|socket| Self {
                    socket,
                    max_send_payload,
                    recv_buf_size,
                })
                .map_err(Error::from)
        })
    }

    /// The local address this transport is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot report the local address.
    pub fn local_addr(&self) -> Result<UdpAddr, Error> {
        self.socket
            .local_addr()
            .map(UdpAddr::from)
            .map_err(Error::from)
    }

    /// The configured outbound payload ceiling, in bytes.
    #[must_use]
    pub fn max_send_payload(&self) -> usize {
        self.max_send_payload
    }

    /// The configured inbound scratch buffer size, in bytes.
    #[must_use]
    pub fn recv_buf_size(&self) -> usize {
        self.recv_buf_size
    }

    /// Send `payload` as a single datagram to `to`, returning the
    /// transport for re-use.
    ///
    /// # Errors
    ///
    /// - [`Error::DatagramTooLarge`] if `payload.len()` exceeds the
    ///   configured outbound ceiling.
    /// - [`Error::Io`] if the underlying socket call fails.
    #[must_use]
    pub fn send(self, to: UdpAddr, payload: Vec<u8>) -> Io<Error, Self> {
        Io::suspend(move || {
            let attempted = payload.len();
            let maximum = self.max_send_payload;
            if attempted > maximum {
                Err(Error::DatagramTooLarge { attempted, maximum })
            } else {
                self.socket
                    .send_to(&payload, SocketAddr::from(to))
                    .map(|_| self)
                    .map_err(Error::from)
            }
        })
    }

    /// Receive one datagram, returning the source address, the payload,
    /// and the transport for re-use.
    ///
    /// Blocks until a datagram arrives.  The returned payload is
    /// exactly the bytes the kernel reported; if a peer sends a
    /// datagram larger than the configured `recv_buf_size`, the kernel
    /// truncates silently and the truncated bytes appear here.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the underlying socket call fails.
    #[must_use]
    pub fn recv(self) -> Io<Error, ((UdpAddr, Vec<u8>), Self)> {
        Io::suspend(move || {
            let mut buf = vec![0u8; self.recv_buf_size];
            let (n, from) = self.socket.recv_from(&mut buf)?;
            let payload = buf.get(..n).map(<[u8]>::to_vec).unwrap_or_default();
            Ok(((UdpAddr::from(from), payload), self))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn loopback_v4() -> UdpAddr {
        UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    #[test]
    fn bind_reports_local_addr() -> Result<(), Error> {
        let transport = UdpTransport::bind(loopback_v4()).run()?;
        let addr = transport.local_addr()?;
        match addr {
            UdpAddr::V4(s) => {
                assert_eq!(s.ip(), &Ipv4Addr::LOCALHOST);
                assert_ne!(s.port(), 0);
                Ok(())
            }
            UdpAddr::V6(_) => Err(Error::InvalidPeerId {
                reason: "loopback v4 bind returned a v6 address".to_owned(),
            }),
        }
    }

    #[test]
    fn send_rejects_oversized_payloads() -> Result<(), Error> {
        let transport = UdpTransport::bind_with_limits(loopback_v4(), 16, MAX_UDP_PAYLOAD).run()?;
        let local = transport.local_addr()?;
        let oversized = vec![0u8; 17];
        let outcome = transport.send(local, oversized).run();
        assert!(matches!(
            outcome,
            Err(Error::DatagramTooLarge {
                attempted: 17,
                maximum: 16
            })
        ));
        Ok(())
    }
}
