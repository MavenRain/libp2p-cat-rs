//! [`PubsubMux`]: a thin layer over [`Host`] that multiplexes raw
//! application data and RLNC-coded pubsub frames onto a single
//! authenticated UDP socket.
//!
//! # Wire envelope
//!
//! Every plaintext that the mux hands to [`Host::send`] is prefixed
//! with a one-byte discriminator:
//!
//! - [`KIND_APP`]    (`0x00`): the rest of the plaintext is raw
//!   application data delivered as
//!   [`MuxEvent::AppData`].
//! - [`KIND_PUBSUB`] (`0x01`): the rest of the plaintext is a
//!   [`crate::PubsubFrame`] that the mux feeds into the matching
//!   topic decoder.
//!
//! Receivers route on the discriminator and surface either
//! [`MuxEvent::AppData`] or [`MuxEvent::PubsubAbsorbed`] /
//! [`MuxEvent::PubsubDelivered`].
//!
//! Other [`HostEvent`] variants pass through unchanged so a single
//! event loop can handle handshake progress, completion, and
//! per-peer rejections without unwrapping a wrapper.

use std::collections::BTreeMap;
use std::sync::Arc;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::{Error, UdpAddr};

use rlnc_cat_rs::auth::NullAuthenticator;
use rlnc_cat_rs::coding::decode::DecoderState;
use rlnc_cat_rs::coding::piece::OriginalData;
use rlnc_cat_rs::gossip::source;

use crate::codec;
use crate::topic::Topic;

/// Plaintext discriminator for raw application data.
pub const KIND_APP: u8 = 0x00;

/// Plaintext discriminator for RLNC pubsub frames.
pub const KIND_PUBSUB: u8 = 0x01;

/// Outcomes of [`PubsubMux::recv_one`].
///
/// Each call to `recv_one` returns exactly one event.  Variants that
/// look the same as [`HostEvent`]'s pass through transparently;
/// `AppData` and `PubsubAbsorbed` / `PubsubDelivered` arise from
/// dispatching by [`KIND_APP`] / [`KIND_PUBSUB`] on
/// [`HostEvent::DatagramDelivered`] plaintext.
#[derive(Debug)]
#[must_use]
pub enum MuxEvent {
    /// A raw app-data plaintext arrived (the `KIND_APP` path).
    AppData {
        /// Source peer address.
        addr: UdpAddr,
        /// The application bytes (kind byte already stripped).
        bytes: Vec<u8>,
    },

    /// A pubsub piece arrived and was absorbed but the topic decoder
    /// is not yet complete.
    PubsubAbsorbed {
        /// Source peer address.
        addr: UdpAddr,
        /// Topic the piece belonged to.
        topic: Topic,
    },

    /// A pubsub piece arrived and completed a topic decoder.  The
    /// reconstructed bytes are surfaced once; subsequent frames for
    /// the same topic require a fresh `register_topic` call.
    PubsubDelivered {
        /// Source peer address.
        addr: UdpAddr,
        /// Topic the message was delivered on.
        topic: Topic,
        /// Reconstructed original bytes.
        data: Vec<u8>,
    },

    /// Pass-through: a handshake step succeeded but is not complete.
    HandshakeProgress {
        /// Peer address the handshake is with.
        addr: UdpAddr,
    },

    /// Pass-through: a handshake completed.
    HandshakeComplete {
        /// Peer address.
        addr: UdpAddr,
        /// Authenticated remote static public key.
        remote_static: StaticPublicKey,
    },

    /// Pass-through: an inbound datagram was rejected.  The mux
    /// also emits this when a kind byte is unknown or a pubsub frame
    /// fails to parse / absorb.
    Rejected {
        /// Source peer address.
        addr: UdpAddr,
        /// Description of the rejection.
        reason: String,
    },
}

/// A [`Host`] paired with per-topic decoder state and a
/// kind-byte-tagged plaintext envelope.
///
/// Every effectful method consumes `self` and returns a new mux.
#[must_use]
pub struct PubsubMux {
    host: Host,
    decoders: BTreeMap<Topic, DecoderState>,
}

impl PubsubMux {
    /// Build a fresh mux around an existing host.  The host's
    /// connection state is preserved as-is.
    pub fn new(host: Host) -> Self {
        Self {
            host,
            decoders: BTreeMap::new(),
        }
    }

    /// Borrow the underlying host (read-only).
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Consume the mux and return its host, dropping pubsub state.
    pub fn into_host(self) -> Host {
        self.host
    }

    /// Local UDP address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the OS cannot report the local address.
    pub fn local_addr(&self) -> Result<UdpAddr, Error> {
        self.host.local_addr()
    }

    /// Whether `addr` has a fully-established connection.
    #[must_use]
    pub fn is_established(&self, addr: UdpAddr) -> bool {
        self.host.is_established(addr)
    }

    /// Initiate a Noise XX handshake with the peer at `addr`.
    /// Pass-through to [`Host::dial`].
    ///
    /// # Errors
    ///
    /// Propagates [`Host::dial`] errors.
    #[must_use]
    pub fn dial(self, addr: UdpAddr, ephemeral_seed: [u8; 32]) -> Io<Error, Self> {
        let Self { host, decoders } = self;
        host.dial(addr, ephemeral_seed)
            .map(move |host| Self { host, decoders })
    }

    /// Pre-register a topic so inbound pubsub frames for it can be
    /// absorbed into a freshly-initialised decoder.  Calling this on
    /// a topic with an in-progress decoder discards the partial state.
    pub fn register_topic(self, topic: Topic, piece_count: usize, piece_byte_len: usize) -> Self {
        let Self { host, mut decoders } = self;
        decoders.insert(topic, DecoderState::new(piece_count, piece_byte_len));
        Self { host, decoders }
    }

    /// Send `payload` as a raw app-data plaintext to an established
    /// peer.  The mux prepends [`KIND_APP`] before handing the bytes
    /// to [`Host::send`].
    ///
    /// # Errors
    ///
    /// Propagates [`Host::send`] errors.
    #[must_use]
    pub fn send_app(self, addr: UdpAddr, payload: &[u8]) -> Io<Error, Self> {
        let Self { host, decoders } = self;
        let framed = prefix_kind(KIND_APP, payload);
        host.send(addr, framed)
            .map(move |host| Self { host, decoders })
    }

    /// Broadcast `data` on `topic` to every established peer as
    /// `num_pieces` RLNC-coded frames.  Each frame is prefixed with
    /// [`KIND_PUBSUB`] before encryption.
    ///
    /// `rng_factory` produces a fresh `Vec<u8>` of `n` random GF(2^8)
    /// coefficients per coding-vector request; tests can pass a
    /// deterministic counter, production paths should pass a CSPRNG.
    ///
    /// # Errors
    ///
    /// - [`Error::RlncLayer`] for RLNC encoding failures.
    /// - [`Error::PubsubProtocol`] for framing-shape errors.
    /// - Noise / I/O errors propagate transparently from
    ///   [`Host::send`].
    #[must_use]
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

    /// Receive one datagram and dispatch it.
    ///
    /// `ephemeral_seed` follows the [`Host::recv_one`] contract: it
    /// is consumed only when an inbound `msg1` triggers a fresh
    /// responder.
    ///
    /// # Errors
    ///
    /// Propagates [`Host::recv_one`] errors.  Per-peer / per-frame
    /// problems surface as [`MuxEvent::Rejected`] rather than `Err`.
    #[must_use]
    pub fn recv_one(self, ephemeral_seed: [u8; 32]) -> Io<Error, (Self, MuxEvent)> {
        let Self { host, decoders } = self;
        host.recv_one(ephemeral_seed)
            .map(move |(host, host_event)| translate_event(Self { host, decoders }, host_event))
    }
}

/// Build the `[kind, payload...]` plaintext.
fn prefix_kind(kind: u8, payload: &[u8]) -> Vec<u8> {
    [kind].into_iter().chain(payload.iter().copied()).collect()
}

/// Fan a list of pubsub frames out to every established peer.
fn fan_out(mux: PubsubMux, frames: Vec<Vec<u8>>) -> Io<Error, PubsubMux> {
    frames.into_iter().fold(Io::pure(mux), |acc, frame| {
        acc.flat_map(move |mux| send_frame_to_all(mux, &frame))
    })
}

fn send_frame_to_all(mux: PubsubMux, frame: &[u8]) -> Io<Error, PubsubMux> {
    let addrs = mux.host.established_addrs();
    addrs.into_iter().fold(Io::pure(mux), |acc, addr| {
        let datagram = prefix_kind(KIND_PUBSUB, frame);
        acc.flat_map(move |mux| {
            let PubsubMux { host, decoders } = mux;
            host.send(addr, datagram)
                .map(move |host| PubsubMux { host, decoders })
        })
    })
}

/// Convert a [`HostEvent`] into a [`MuxEvent`], possibly absorbing a
/// pubsub piece into the matching decoder along the way.
fn translate_event(mux: PubsubMux, ev: HostEvent) -> (PubsubMux, MuxEvent) {
    match ev {
        HostEvent::HandshakeProgress { addr } => (mux, MuxEvent::HandshakeProgress { addr }),
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
        } => (
            mux,
            MuxEvent::HandshakeComplete {
                addr,
                remote_static,
            },
        ),
        HostEvent::Rejected { addr, reason } => (mux, MuxEvent::Rejected { addr, reason }),
        HostEvent::DatagramDelivered { addr, plaintext } => {
            dispatch_plaintext(mux, addr, &plaintext)
        }
    }
}

/// Inspect the `[kind, payload...]` envelope and produce the right
/// [`MuxEvent`].
fn dispatch_plaintext(mux: PubsubMux, addr: UdpAddr, plaintext: &[u8]) -> (PubsubMux, MuxEvent) {
    let kind = plaintext.first().copied();
    match () {
        () if kind == Some(KIND_APP) => {
            let bytes = plaintext.get(1..).map(<[u8]>::to_vec).unwrap_or_default();
            (mux, MuxEvent::AppData { addr, bytes })
        }
        () if kind == Some(KIND_PUBSUB) => {
            let body = plaintext.get(1..).unwrap_or(&[]);
            absorb_pubsub_body(mux, addr, body)
        }
        () if kind.is_none() => (
            mux,
            MuxEvent::Rejected {
                addr,
                reason: "datagram plaintext was empty (no kind byte)".to_owned(),
            },
        ),
        () => {
            let unknown = kind.unwrap_or(0);
            (
                mux,
                MuxEvent::Rejected {
                    addr,
                    reason: format!("unknown plaintext kind byte 0x{unknown:02x}"),
                },
            )
        }
    }
}

fn absorb_pubsub_body(mux: PubsubMux, addr: UdpAddr, body: &[u8]) -> (PubsubMux, MuxEvent) {
    let PubsubMux { host, mut decoders } = mux;
    let parsed = codec::decode(body);
    match parsed {
        Err(e) => (
            PubsubMux { host, decoders },
            MuxEvent::Rejected {
                addr,
                reason: format!("pubsub frame decode failed: {e}"),
            },
        ),
        Ok((frame, wire_piece)) => {
            let topic = frame.topic.clone();
            let removed = decoders.remove(&topic);
            match removed {
                None => (
                    PubsubMux { host, decoders },
                    MuxEvent::Rejected {
                        addr,
                        reason: format!("frame received for unregistered topic {topic}"),
                    },
                ),
                Some(decoder) => match decoder.absorb(wire_piece.piece()) {
                    Err(e) => (
                        PubsubMux { host, decoders },
                        MuxEvent::Rejected {
                            addr,
                            reason: format!("absorb failed: {e}"),
                        },
                    ),
                    Ok(next) => {
                        if next.is_complete() {
                            match next.decode() {
                                Ok(data) => (
                                    PubsubMux { host, decoders },
                                    MuxEvent::PubsubDelivered { addr, topic, data },
                                ),
                                Err(e) => (
                                    PubsubMux { host, decoders },
                                    MuxEvent::Rejected {
                                        addr,
                                        reason: format!("decode failed: {e}"),
                                    },
                                ),
                            }
                        } else {
                            decoders.insert(topic.clone(), next);
                            (
                                PubsubMux { host, decoders },
                                MuxEvent::PubsubAbsorbed { addr, topic },
                            )
                        }
                    }
                },
            }
        }
    }
}
