//! `PubsubNode`: ties the UDP socket, the peer table, and a per-topic
//! decoder set into a single linear-state-threaded handle.
//!
//! v1 supports two roles per node:
//!
//! - **Source**: [`PubsubNode::broadcast`] takes an
//!   [`OriginalData`] generation and a number of pieces to emit, runs
//!   the [`rlnc_cat_rs::gossip::source`] stream, encodes each piece
//!   into a [`crate::codec::PubsubFrame`], and fans out the encrypted
//!   datagram to every registered peer.
//! - **Receiver**: [`PubsubNode::recv_one`] blocks on the socket,
//!   decrypts the inbound datagram, parses it as a pubsub frame, and
//!   absorbs the piece into the topic's decoder.  When the decoder is
//!   complete, the original bytes are delivered as a
//!   [`DeliveredMessage`].
//!
//! [`OriginalData`]: rlnc_cat_rs::coding::piece::OriginalData

use std::collections::BTreeMap;
use std::sync::Arc;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_noise::TransportState;
use libp2p_cat_types::{Error, UdpAddr};
use libp2p_cat_udp::UdpTransport;

use rlnc_cat_rs::auth::NullAuthenticator;
use rlnc_cat_rs::coding::decode::DecoderState;
use rlnc_cat_rs::coding::piece::OriginalData;
use rlnc_cat_rs::gossip::{PeerIndex, source};

use crate::codec::{self, PubsubFrame};
use crate::peer_table::PeerTable;
use crate::topic::Topic;

/// Pubsub message delivered after a topic decodes successfully.
#[derive(Clone, Debug)]
#[must_use]
pub struct DeliveredMessage {
    /// The peer index that contributed the piece that completed the
    /// decode.  Useful for logging; in v1 every piece for a topic is
    /// expected to arrive from the same source peer.
    pub from: PeerIndex,
    /// The topic the message was delivered on.
    pub topic: Topic,
    /// The reconstructed original bytes.
    pub data: Vec<u8>,
}

/// A node that can broadcast and receive RLNC-coded pubsub frames.
///
/// All effectful operations consume `self` and return a new node;
/// nothing is mutated in place.  The internal `decoders` map evolves
/// in lockstep with the linear state threading.
#[must_use]
pub struct PubsubNode {
    socket: UdpTransport,
    peers: PeerTable,
    decoders: BTreeMap<Topic, DecoderState>,
}

impl PubsubNode {
    /// Construct a node from a bound UDP socket and an empty peer
    /// table.
    pub fn new(socket: UdpTransport) -> Self {
        Self {
            socket,
            peers: PeerTable::new(),
            decoders: BTreeMap::new(),
        }
    }

    /// Borrow the underlying socket (read-only).
    pub fn socket(&self) -> &UdpTransport {
        &self.socket
    }

    /// Borrow the peer table (read-only).
    pub fn peers(&self) -> &PeerTable {
        &self.peers
    }

    /// Local UDP address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot report the local address.
    pub fn local_addr(&self) -> Result<UdpAddr, Error> {
        self.socket.local_addr()
    }

    /// Add a peer to the table.  The returned [`PeerIndex`] is what
    /// callers refer to the peer by in subsequent calls.
    pub fn add_peer(self, addr: UdpAddr, transport: TransportState) -> (Self, PeerIndex) {
        let Self {
            socket,
            peers,
            decoders,
        } = self;
        let (peers, idx) = peers.add(addr, transport);
        (
            Self {
                socket,
                peers,
                decoders,
            },
            idx,
        )
    }

    /// Pre-register a topic so inbound frames can be absorbed into a
    /// freshly-initialised decoder.  `piece_count` is the RLNC `k`
    /// and `piece_byte_len` is `b`.
    pub fn register_topic(self, topic: Topic, piece_count: usize, piece_byte_len: usize) -> Self {
        let Self {
            socket,
            peers,
            mut decoders,
        } = self;
        decoders.insert(topic, DecoderState::new(piece_count, piece_byte_len));
        Self {
            socket,
            peers,
            decoders,
        }
    }

    /// Broadcast `data` on `topic` as `num_pieces` RLNC-coded frames,
    /// fanned out to every registered peer.
    ///
    /// `rng_factory` produces a fresh `Vec<u8>` of `n` random GF(2^8)
    /// coefficients per requested coding vector; it is the only
    /// non-deterministic input.  Tests can pass a deterministic
    /// counter; production paths should pass a CSPRNG.
    ///
    /// # Errors
    ///
    /// Propagates RLNC encoding errors as [`Error::RlncLayer`], peer
    /// lookup or framing errors as [`Error::PubsubProtocol`], and
    /// Noise / UDP errors transparently.
    pub fn broadcast<F>(
        self,
        topic: Topic,
        data: OriginalData,
        num_pieces: usize,
        rng_factory: F,
    ) -> Io<Error, Self>
    where
        F: Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static,
    {
        let piece_count = data.piece_count();
        let piece_byte_len = data.piece_byte_len();
        let auth = Arc::new(NullAuthenticator);
        let (_commitment, stream) = source(auth, data, rng_factory);
        stream
            .take(num_pieces)
            .collect()
            .map_error(|e| Error::RlncLayer {
                reason: e.to_string(),
            })
            .flat_map(move |pieces| {
                let frames = pieces
                    .iter()
                    .map(|wp| codec::encode(&topic, piece_count, piece_byte_len, wp))
                    .collect::<Result<Vec<Vec<u8>>, Error>>();
                Io::suspend(move || frames).flat_map(move |frames| fan_out(self, frames))
            })
    }

    /// Receive one datagram and process it.
    ///
    /// Returns the (possibly identical) updated node and an
    /// `Option<DeliveredMessage>`: `Some` when the absorbed piece
    /// completed a topic's decoder, `None` when more pieces are still
    /// needed.  Datagrams from unknown source addresses, undecryptable
    /// datagrams, replays, and frames for unregistered topics are
    /// surfaced as `Err`.
    ///
    /// # Errors
    ///
    /// Propagates I/O, Noise, codec, and RLNC errors transparently.
    #[must_use]
    pub fn recv_one(self) -> Io<Error, (Self, Option<DeliveredMessage>)> {
        let Self {
            socket,
            peers,
            decoders,
        } = self;
        socket.recv().flat_map(move |((from, datagram), socket)| {
            Io::suspend(move || peers.decrypt_from(from, &datagram)).flat_map(
                move |(peers, peer_idx, plaintext)| {
                    Io::suspend(move || codec::decode(&plaintext)).flat_map(
                        move |(frame, wire_piece)| {
                            Io::suspend(move || absorb(decoders, &frame, &wire_piece, peer_idx))
                                .map(move |(decoders, delivered)| {
                                    (
                                        Self {
                                            socket,
                                            peers,
                                            decoders,
                                        },
                                        delivered,
                                    )
                                })
                        },
                    )
                },
            )
        })
    }
}

/// Fan out a list of frames to every peer in the table, encrypting
/// per-peer and sending each datagram synchronously.
fn fan_out(node: PubsubNode, frames: Vec<Vec<u8>>) -> Io<Error, PubsubNode> {
    frames.into_iter().fold(Io::pure(node), |acc, frame| {
        acc.flat_map(move |node| send_frame_to_all(node, &frame))
    })
}

fn send_frame_to_all(node: PubsubNode, frame: &[u8]) -> Io<Error, PubsubNode> {
    let peer_indices = node.peers.peer_indices();
    peer_indices.into_iter().fold(Io::pure(node), |acc, peer| {
        let frame_for_peer = frame.to_vec();
        acc.flat_map(move |node| send_frame_to_peer(node, peer, frame_for_peer))
    })
}

fn send_frame_to_peer(node: PubsubNode, peer: PeerIndex, frame: Vec<u8>) -> Io<Error, PubsubNode> {
    let PubsubNode {
        socket,
        peers,
        decoders,
    } = node;
    Io::suspend(move || peers.encrypt_for(peer, &frame)).flat_map(move |(peers, addr, datagram)| {
        socket.send(addr, datagram).map(move |socket| PubsubNode {
            socket,
            peers,
            decoders,
        })
    })
}

/// Absorb one received piece, returning the updated decoder map and
/// any delivered message.
fn absorb(
    mut decoders: BTreeMap<Topic, DecoderState>,
    frame: &PubsubFrame,
    wire_piece: &rlnc_cat_rs::gossip::WirePiece<NullAuthenticator>,
    from: PeerIndex,
) -> Result<(BTreeMap<Topic, DecoderState>, Option<DeliveredMessage>), Error> {
    let topic = frame.topic.clone();
    let decoder = decoders
        .remove(&topic)
        .ok_or_else(|| Error::PubsubProtocol {
            reason: format!("frame received for unregistered topic {topic}"),
        })?;
    let next = decoder
        .absorb(wire_piece.piece())
        .map_err(|e| Error::RlncLayer {
            reason: e.to_string(),
        })?;
    if next.is_complete() {
        let data = next.decode().map_err(|e| Error::RlncLayer {
            reason: e.to_string(),
        })?;
        Ok((decoders, Some(DeliveredMessage { from, topic, data })))
    } else {
        decoders.insert(topic, next);
        Ok((decoders, None))
    }
}
