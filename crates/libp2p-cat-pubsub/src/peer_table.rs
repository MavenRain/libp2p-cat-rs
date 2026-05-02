//! Mapping from a peer's [`PeerIndex`] to its [`UdpAddr`] and the
//! [`TransportState`] established with it.
//!
//! Linear-state-threading API: every operation that mutates the
//! transport state consumes `self` and returns the next table.  This
//! avoids `RefCell` / `Mutex` while keeping the per-peer Noise state
//! evolving correctly.

use std::collections::BTreeMap;

use libp2p_cat_noise::TransportState;
use libp2p_cat_types::{Error, UdpAddr};
use rlnc_cat_rs::gossip::PeerIndex;

/// One peer's entry: its UDP address and the post-handshake Noise
/// transport state shared with it.
struct PeerEntry {
    addr: UdpAddr,
    transport: TransportState,
}

/// A registry of peers and the Noise transports established with each.
///
/// Two indexes are maintained: a forward index from [`PeerIndex`] to
/// the entry, and a reverse index from [`UdpAddr`] back to
/// [`PeerIndex`] for inbound datagrams whose source address is the
/// only routing hint.
#[must_use]
pub struct PeerTable {
    peers: BTreeMap<usize, PeerEntry>,
    addr_to_index: BTreeMap<UdpAddr, usize>,
    next_index: usize,
}

impl PeerTable {
    /// Empty table.
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            addr_to_index: BTreeMap::new(),
            next_index: 0,
        }
    }

    /// Number of peers registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Snapshot of every registered peer's index.
    pub fn peer_indices(&self) -> Vec<PeerIndex> {
        self.peers.keys().copied().map(PeerIndex::from).collect()
    }

    /// Look up the [`UdpAddr`] for a peer index, if registered.
    #[must_use]
    pub fn addr_of(&self, peer: PeerIndex) -> Option<UdpAddr> {
        self.peers.get(&usize::from(peer)).map(|entry| entry.addr)
    }

    /// Add a peer and return the assigned [`PeerIndex`].
    ///
    /// Indices are assigned monotonically from zero.
    pub fn add(self, addr: UdpAddr, transport: TransportState) -> (Self, PeerIndex) {
        let Self {
            mut peers,
            mut addr_to_index,
            next_index,
        } = self;
        peers.insert(next_index, PeerEntry { addr, transport });
        addr_to_index.insert(addr, next_index);
        let peer = PeerIndex::from(next_index);
        (
            Self {
                peers,
                addr_to_index,
                next_index: next_index + 1,
            },
            peer,
        )
    }

    /// Encrypt `plaintext` for the named peer, returning the updated
    /// table, the destination address, and the on-wire datagram.
    ///
    /// # Errors
    ///
    /// - [`Error::PubsubProtocol`] if `peer` is not registered.
    /// - [`Error::NoiseDecrypt`] / [`Error::NoiseProtocol`] if the
    ///   Noise transport refuses to encrypt (e.g. nonce exhaustion).
    pub fn encrypt_for(
        self,
        peer: PeerIndex,
        plaintext: &[u8],
    ) -> Result<(Self, UdpAddr, Vec<u8>), Error> {
        let Self {
            mut peers,
            addr_to_index,
            next_index,
        } = self;
        let key = usize::from(peer);
        let entry = peers.remove(&key).ok_or_else(|| Error::PubsubProtocol {
            reason: format!("encrypt_for: unknown peer index {key}"),
        })?;
        let (next_transport, datagram) = entry.transport.encrypt(plaintext)?;
        let addr = entry.addr;
        peers.insert(
            key,
            PeerEntry {
                addr,
                transport: next_transport,
            },
        );
        Ok((
            Self {
                peers,
                addr_to_index,
                next_index,
            },
            addr,
            datagram,
        ))
    }

    /// Decrypt an inbound `datagram` whose UDP source address is `from`.
    ///
    /// # Errors
    ///
    /// - [`Error::PubsubProtocol`] if `from` is not a registered peer.
    /// - [`Error::NoiseDecrypt`], [`Error::NoiseReplay`], or
    ///   [`Error::NoiseProtocol`] propagating from the Noise transport.
    pub fn decrypt_from(
        self,
        from: UdpAddr,
        datagram: &[u8],
    ) -> Result<(Self, PeerIndex, Vec<u8>), Error> {
        let Self {
            mut peers,
            addr_to_index,
            next_index,
        } = self;
        let key = addr_to_index
            .get(&from)
            .copied()
            .ok_or_else(|| Error::PubsubProtocol {
                reason: format!("decrypt_from: no peer registered at address {from}"),
            })?;
        let entry = peers.remove(&key).ok_or_else(|| Error::PubsubProtocol {
            reason: format!("decrypt_from: peer {key} missing transport state"),
        })?;
        let (next_transport, plaintext) = entry.transport.decrypt(datagram)?;
        let addr = entry.addr;
        peers.insert(
            key,
            PeerEntry {
                addr,
                transport: next_transport,
            },
        );
        Ok((
            Self {
                peers,
                addr_to_index,
                next_index,
            },
            PeerIndex::from(key),
            plaintext,
        ))
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}
