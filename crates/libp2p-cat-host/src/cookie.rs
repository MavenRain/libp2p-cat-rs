//! Stateless source-address validation cookies.
//!
//! A bare 32-byte Noise `msg1` proves nothing about its source
//! address: UDP sources are trivially spoofable, so answering `msg1`
//! directly with `msg2` hands an attacker a reflection amplifier
//! (small spoofed datagram in, larger datagram out toward the
//! victim) and lets a spray of spoofed `msg1`s flush the responder's
//! bounded handshake table.  The cookie exchange closes both holes
//! the same way QUIC's Retry token and `WireGuard`'s cookie reply do:
//!
//! 1. Responder receives a bare `msg1` from an unknown address and
//!    answers with a [`COOKIE_REPLY_LEN`]-byte challenge: a marker
//!    byte plus `keyed_blake3(secret, domain || source_addr || e)`.
//!    No state is created, no Diffie-Hellman is performed, and the
//!    reply is barely larger than the datagram that elicited it, so
//!    there is nothing to amplify and nothing to exhaust.
//! 2. The initiator echoes the challenge by re-sending
//!    `msg1 || cookie` ([`MSG1_WITH_COOKIE_LEN`] bytes).
//! 3. The responder recomputes the MAC, still statelessly.  Only a
//!    source that actually received the challenge at the claimed
//!    address can echo it, so handshake state and the `msg2` reply
//!    are spent exclusively on addresses that have proven
//!    reachability.
//!
//! The cookie travels outside the Noise transcript: both sides hash
//! exactly the bytes of the original `msg1`, so the exchange is
//! invisible to the handshake's symmetric state.
//!
//! The MAC is a keyed-BLAKE3 hash truncated to [`COOKIE_MAC_LEN`]
//! bytes.  Truncation keeps the challenge ([`COOKIE_REPLY_LEN`]
//! bytes) strictly smaller than the [`MESSAGE_1_LEN`]-byte `msg1`
//! that elicits it, so the responder never emits more bytes than it
//! received: the challenge path is not itself a reflection
//! amplifier.  16 bytes is the standard `WireGuard` cookie MAC width
//! and is ample against online forgery, where each wrong guess
//! simply fails and must be retried against a fresh challenge.
//!
//! The MAC key is a 32-byte secret supplied at host construction
//! from the caller's CSPRNG (the same caller-provides-entropy
//! contract as the per-call ephemeral seeds).
//!
//! # Guarantees and residual risk
//!
//! What the cookie closes: a **blind-spoof** attacker that cannot
//! receive at the address it forges can neither elicit a `msg2`
//! (reflection) nor create responder handshake state (table
//! exhaustion), because it can never echo a valid cookie.
//!
//! What the cookie does NOT close: a **return-routable** attacker
//! (one that controls even a single real address, or a block of
//! them) can complete the round-trip and then create genuine
//! handshake state per `(source_addr, ephemeral_key)`.  The secret
//! does not rotate, so a captured `msg1 || cookie` also replays for
//! the host's lifetime.  This stack is deliberately runtime-free and
//! holds no clock, so it binds no expiry epoch; bounding the rate of
//! handshake creation per source-IP prefix is left to the operator
//! or an outer layer, exactly as QUIC Retry and `WireGuard` leave
//! per-peer rate limiting to their deployments.

use std::net::{IpAddr, SocketAddr};

use libp2p_cat_noise::MESSAGE_1_LEN;
use libp2p_cat_types::UdpAddr;

/// Length of the truncated cookie MAC, in bytes.  Chosen so the
/// challenge stays smaller than the `msg1` that elicits it (no
/// reflection amplification) while remaining wide enough that online
/// forgery is infeasible.
pub const COOKIE_MAC_LEN: usize = 16;

/// Marker byte prefixed to every cookie challenge so the reply is
/// length- and content-distinguishable from every other datagram
/// shape an initiator can receive.
pub const COOKIE_REPLY_MARKER: u8 = 0xC0;

/// Wire length of a cookie challenge: marker byte plus MAC.
pub const COOKIE_REPLY_LEN: usize = 1 + COOKIE_MAC_LEN;

/// Wire length of a `msg1` with its echoed cookie appended.
pub const MSG1_WITH_COOKIE_LEN: usize = MESSAGE_1_LEN + COOKIE_MAC_LEN;

/// Domain-separation prefix for the cookie MAC input.
const COOKIE_DOMAIN: &[u8] = b"libp2p-cat-host cookie v1";

/// Compute the cookie MAC binding `from` and the ephemeral key bytes
/// `e` under `secret`, truncated to [`COOKIE_MAC_LEN`] bytes.
pub(crate) fn mint(secret: &[u8; 32], from: UdpAddr, e: &[u8]) -> [u8; COOKIE_MAC_LEN] {
    let input: Vec<u8> = COOKIE_DOMAIN
        .iter()
        .copied()
        .chain(addr_bytes(from))
        .chain(e.iter().copied())
        .collect();
    let full = blake3::keyed_hash(secret, &input);
    let bytes = full.as_bytes();
    core::array::from_fn(|i| bytes.get(i).copied().unwrap_or(0))
}

/// Build the on-wire cookie challenge for a bare `msg1`.
pub(crate) fn challenge(secret: &[u8; 32], from: UdpAddr, e: &[u8]) -> Vec<u8> {
    [COOKIE_REPLY_MARKER]
        .into_iter()
        .chain(mint(secret, from, e))
        .collect()
}

/// Whether `datagram` has the exact shape of a cookie challenge.
pub(crate) fn is_challenge(datagram: &[u8]) -> bool {
    datagram.len() == COOKIE_REPLY_LEN && datagram.first() == Some(&COOKIE_REPLY_MARKER)
}

/// Constant-time verification of an echoed cookie MAC against a
/// recomputation for (`from`, `e`).
pub(crate) fn verify(secret: &[u8; 32], from: UdpAddr, e: &[u8], mac: &[u8]) -> bool {
    <[u8; COOKIE_MAC_LEN]>::try_from(mac).is_ok_and(|echoed| {
        // Constant-time compare: XOR-accumulate every byte (no
        // early exit) and check the difference is zero, so a partial
        // match leaks no timing signal.
        let expected = mint(secret, from, e);
        let diff = expected
            .iter()
            .zip(echoed.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y));
        diff == 0
    })
}

/// Stable byte encoding of a source address for the MAC input: a
/// one-byte address-family tag, then the IP octets, then the
/// big-endian port.  The family tag domain-separates the V4 and V6
/// encodings unambiguously regardless of length.  IPv4-mapped IPv6
/// addresses (`::ffff:a.b.c.d`) are canonicalized to their V4 form
/// so the same peer reaching the host over a dual-stack socket
/// cannot occupy two distinct cookie / handshake identities.
///
/// `scope_id` / `flowinfo` are intentionally excluded: they are
/// local routing hints, not part of the peer's identity, and a peer
/// that legitimately changes interface is treated as the same
/// source.
fn addr_bytes(addr: UdpAddr) -> Vec<u8> {
    let tag_v4: u8 = 0x04;
    let tag_v6: u8 = 0x06;
    let socket = SocketAddr::from(addr);
    let port = socket.port();
    // `to_canonical` maps an IPv4-mapped V6 address (`::ffff:a.b.c.d`)
    // to its V4 form and leaves every other address unchanged.
    let canonical = match socket.ip() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6.to_canonical(),
    };
    match canonical {
        IpAddr::V4(v4) => [tag_v4]
            .into_iter()
            .chain(v4.octets())
            .chain(port.to_be_bytes())
            .collect(),
        IpAddr::V6(v6) => [tag_v6]
            .into_iter()
            .chain(v6.octets())
            .chain(port.to_be_bytes())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use libp2p_cat_types::{Error, UdpAddr};

    use super::{
        COOKIE_MAC_LEN, COOKIE_REPLY_LEN, COOKIE_REPLY_MARKER, MSG1_WITH_COOKIE_LEN, challenge,
        is_challenge, mint, verify,
    };
    use libp2p_cat_noise::MESSAGE_1_LEN;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    fn addr(port: u16) -> UdpAddr {
        UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn echoed_cookie_verifies() -> Result<(), Error> {
        let secret = [0x42; 32];
        let e = [0xE1; 32];
        let mac = mint(&secret, addr(4000), &e);
        check(verify(&secret, addr(4000), &e, &mac), || {
            "freshly minted cookie should verify".to_owned()
        })
    }

    #[test]
    fn cookie_is_bound_to_source_address() -> Result<(), Error> {
        let secret = [0x42; 32];
        let e = [0xE1; 32];
        let mac = mint(&secret, addr(4000), &e);
        check(!verify(&secret, addr(4001), &e, &mac), || {
            "cookie minted for one address must not verify for another".to_owned()
        })
    }

    #[test]
    fn challenge_is_smaller_than_the_msg1_that_elicits_it() -> Result<(), Error> {
        // The whole point of truncating the MAC: the responder must
        // never emit more bytes than it received, or the challenge
        // path itself becomes a reflection amplifier.
        check(COOKIE_REPLY_LEN < MESSAGE_1_LEN, || {
            format!(
                "cookie challenge ({COOKIE_REPLY_LEN} B) must be smaller than msg1 ({MESSAGE_1_LEN} B)"
            )
        })?;
        check(
            MSG1_WITH_COOKIE_LEN == MESSAGE_1_LEN + COOKIE_MAC_LEN,
            || "msg1-with-cookie length must be msg1 + mac".to_owned(),
        )
    }

    #[test]
    fn ipv4_mapped_v6_canonicalizes_to_v4() -> Result<(), Error> {
        // The same peer reaching a dual-stack host as ::ffff:a.b.c.d
        // must mint the same cookie as the plain V4 form, so it
        // cannot occupy two distinct cookie / handshake identities.
        let secret = [0x42; 32];
        let e = [0xE1; 32];
        let v4_ip = Ipv4Addr::new(192, 0, 2, 7);
        let v4 = UdpAddr::V4(SocketAddrV4::new(v4_ip, 4000));
        let mapped = UdpAddr::V6(SocketAddrV6::new(v4_ip.to_ipv6_mapped(), 4000, 0, 0));
        check(mint(&secret, v4, &e) == mint(&secret, mapped, &e), || {
            "an IPv4-mapped V6 source must canonicalize to its V4 form".to_owned()
        })?;
        check(verify(&secret, v4, &e, &mint(&secret, mapped, &e)), || {
            "a cookie minted for the mapped form must verify for the V4 form".to_owned()
        })
    }

    #[test]
    fn v4_and_genuine_v6_are_domain_separated() -> Result<(), Error> {
        // The family tag keeps a V4 address and a non-mapped V6
        // address from ever colliding regardless of byte layout.
        let secret = [0x42; 32];
        let e = [0xE1; 32];
        let v4 = UdpAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 4000));
        let v6 = UdpAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            4000,
            0,
            0,
        ));
        check(mint(&secret, v4, &e) != mint(&secret, v6, &e), || {
            "a V4 and a genuine V6 source must not mint the same cookie".to_owned()
        })
    }

    #[test]
    fn cookie_is_bound_to_ephemeral_key() -> Result<(), Error> {
        let secret = [0x42; 32];
        let mac = mint(&secret, addr(4000), &[0xE1; 32]);
        check(!verify(&secret, addr(4000), &[0xE2; 32], &mac), || {
            "cookie minted for one ephemeral must not verify for another".to_owned()
        })
    }

    #[test]
    fn cookie_is_bound_to_secret() -> Result<(), Error> {
        let e = [0xE1; 32];
        let mac = mint(&[0x42; 32], addr(4000), &e);
        check(!verify(&[0x43; 32], addr(4000), &e, &mac), || {
            "cookie minted under one secret must not verify under another".to_owned()
        })
    }

    #[test]
    fn wrong_length_mac_is_rejected() -> Result<(), Error> {
        let secret = [0x42; 32];
        let e = [0xE1; 32];
        check(!verify(&secret, addr(4000), &e, &[0u8; 31]), || {
            "a 31-byte MAC must be rejected".to_owned()
        })
    }

    #[test]
    fn challenge_shape_round_trips() -> Result<(), Error> {
        let secret = [0x42; 32];
        let e = [0xE1; 32];
        let reply = challenge(&secret, addr(4000), &e);
        check(reply.len() == COOKIE_REPLY_LEN, || {
            format!(
                "expected {COOKIE_REPLY_LEN}-byte challenge, got {}",
                reply.len()
            )
        })?;
        check(reply.first() == Some(&COOKIE_REPLY_MARKER), || {
            "challenge must start with the marker byte".to_owned()
        })?;
        check(is_challenge(&reply), || {
            "is_challenge must accept a freshly built challenge".to_owned()
        })?;
        check(
            !is_challenge(&reply.get(..32).map(<[u8]>::to_vec).unwrap_or_default()),
            || "is_challenge must reject a truncated challenge".to_owned(),
        )
    }
}
