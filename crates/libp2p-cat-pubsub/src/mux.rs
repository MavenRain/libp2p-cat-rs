//! [`PubsubMux`]: a thin layer over [`Host`] that multiplexes raw
//! application data and RLNC-coded pubsub frames onto a single
//! authenticated UDP socket, with pluggable per-frame
//! authentication via [`PubsubAuth`].
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
//!   [`crate::PubsubFrame`] (commitment- and tag-tagged via the
//!   [`WireAuthenticator`] in use).  The mux dispatches it to either
//!   the matching topic decoder ([`MuxEvent::PubsubAbsorbed`] /
//!   [`MuxEvent::PubsubDelivered`]) or the matching recoder
//!   ([`MuxEvent::PubsubRelayed`]) **after** verifying the inbound
//!   piece's commitment + tag.
//!
//! # Topic roles
//!
//! For a given topic a node plays exactly one of three roles:
//!
//! - **source**: build pieces locally with [`PubsubMux::broadcast`].
//!   The mux's authenticator commits to the generation and tags
//!   each emitted piece.
//! - **decoder**: register with [`PubsubMux::register_topic`],
//!   supplying the commitment received out-of-band; absorb inbound
//!   pieces whose tag verifies against that commitment; surface a
//!   [`MuxEvent::PubsubDelivered`] when the generation is
//!   reconstructed.
//! - **relay**: register with [`PubsubMux::register_relay`],
//!   supplying the commitment; verify each inbound piece, add it to
//!   the local recoder, generate a fresh recoded piece by random
//!   linear combination of the buffered pieces, **re-tag** with the
//!   local authenticator, and forward to every peer except the
//!   source.  Surfaces a [`MuxEvent::PubsubRelayed`].
//!
//! Note: stock [`rlnc_cat_rs::auth::KeyedHashAuthenticator`] is *not
//! homomorphic*, so a relay can only re-tag if it holds the same
//! shared key as the source.  This matches the permissioned-network
//! deployment model documented on that authenticator.
//!
//! Registering both decoder and recoder for the same topic on the
//! same node is currently undefined; the second registration
//! replaces the first.

use std::collections::BTreeMap;
use std::sync::Arc;

use comp_cat_rs::effect::io::Io;

use libp2p_cat_host::{Host, HostEvent};
use libp2p_cat_noise::StaticPublicKey;
use libp2p_cat_types::{Error, UdpAddr};

use rlnc_cat_rs::coding::decode::DecoderState;
use rlnc_cat_rs::coding::piece::{CodedPiece, OriginalData};
use rlnc_cat_rs::coding::recode::Recoder;
use rlnc_cat_rs::gossip::{WirePiece, source};

use crate::auth::PubsubAuth;
use crate::codec;
use crate::topic::Topic;

/// Plaintext discriminator for raw application data.
pub const KIND_APP: u8 = 0x00;

/// Plaintext discriminator for RLNC pubsub frames.
pub const KIND_PUBSUB: u8 = 0x01;

/// Outcomes of [`PubsubMux::recv_one`].
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

    /// A pubsub piece was absorbed into a local decoder but the
    /// generation is not yet complete.
    PubsubAbsorbed {
        /// Source peer address.
        addr: UdpAddr,
        /// Topic the piece belonged to.
        topic: Topic,
    },

    /// A pubsub piece completed a topic decoder.  The reconstructed
    /// bytes are surfaced once; subsequent frames for the same topic
    /// require a fresh `register_topic` call.
    PubsubDelivered {
        /// Source peer address.
        addr: UdpAddr,
        /// Topic the message was delivered on.
        topic: Topic,
        /// Reconstructed original bytes.
        data: Vec<u8>,
    },

    /// A pubsub piece was added to a local recoder, a fresh recoded
    /// piece was produced by random linear combination of the
    /// buffered pieces, and that recoded piece was forwarded to
    /// `fanout_count` peers (every established peer except the
    /// source).
    PubsubRelayed {
        /// Address that delivered the inbound piece.
        from: UdpAddr,
        /// Topic the piece belonged to.
        topic: Topic,
        /// Number of peers the recoded piece was forwarded to.
        fanout_count: usize,
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

    /// An inbound datagram was rejected.  Also emitted when a kind
    /// byte is unknown, a pubsub frame fails to parse, the
    /// authenticator rejects a piece's tag, or a frame is addressed
    /// to a topic with no registered role.
    Rejected {
        /// Source peer address.
        addr: UdpAddr,
        /// Description of the rejection.
        reason: String,
    },
}

/// A [`Host`] paired with per-topic decoder and recoder state, an
/// authenticator, and a kind-byte-tagged plaintext envelope.
///
/// Generic over [`PubsubAuth`]; choose
/// [`rlnc_cat_rs::auth::NullAuthenticator`] when no per-frame
/// authentication is needed (zero wire overhead) or
/// [`rlnc_cat_rs::auth::KeyedHashAuthenticator`] for keyed-BLAKE3
/// MAC tagging.
///
/// Every effectful method consumes `self` and returns a new mux.
#[must_use]
pub struct PubsubMux<A: PubsubAuth>
where
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    host: Host,
    auth: Arc<A>,
    decoders: BTreeMap<Topic, (DecoderState, A::Commitment)>,
    recoders: BTreeMap<Topic, (Recoder, A::Commitment)>,
}

impl<A> PubsubMux<A>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    /// Build a fresh mux around an existing host with the given
    /// authenticator.  The host's connection state is preserved.
    pub fn new(host: Host, auth: Arc<A>) -> Self {
        Self {
            host,
            auth,
            decoders: BTreeMap::new(),
            recoders: BTreeMap::new(),
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

    /// Compute the commitment for a fresh generation.  Useful for
    /// nodes that want to publish the commitment out-of-band before
    /// broadcasting.
    #[must_use]
    pub fn commit(&self, original: &OriginalData) -> A::Commitment {
        self.auth.commit(original)
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
        let Self {
            host,
            auth,
            decoders,
            recoders,
        } = self;
        host.dial(addr, ephemeral_seed).map(move |host| Self {
            host,
            auth,
            decoders,
            recoders,
        })
    }

    /// Pre-register a topic for the **decoder** role: inbound pubsub
    /// frames for the topic will be verified against `commitment`
    /// and absorbed into a freshly-initialised decoder.
    pub fn register_topic(
        self,
        topic: Topic,
        piece_count: usize,
        piece_byte_len: usize,
        commitment: A::Commitment,
    ) -> Self {
        let Self {
            host,
            auth,
            mut decoders,
            recoders,
        } = self;
        decoders.insert(
            topic,
            (DecoderState::new(piece_count, piece_byte_len), commitment),
        );
        Self {
            host,
            auth,
            decoders,
            recoders,
        }
    }

    /// Pre-register a topic for the **relay** role: inbound pubsub
    /// frames for the topic will be verified against `commitment`,
    /// added to a local recoder, recoded by random linear
    /// combination, re-tagged with the local authenticator, and
    /// fanned out to all peers except the source.
    pub fn register_relay(
        self,
        topic: Topic,
        piece_count: usize,
        piece_byte_len: usize,
        commitment: A::Commitment,
    ) -> Self {
        let Self {
            host,
            auth,
            decoders,
            mut recoders,
        } = self;
        recoders.insert(
            topic,
            (Recoder::new(piece_count, piece_byte_len), commitment),
        );
        Self {
            host,
            auth,
            decoders,
            recoders,
        }
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
        let Self {
            host,
            auth,
            decoders,
            recoders,
        } = self;
        let framed = prefix_kind(KIND_APP, payload);
        host.send(addr, framed).map(move |host| Self {
            host,
            auth,
            decoders,
            recoders,
        })
    }

    /// Broadcast `data` on `topic` to every established peer as
    /// `num_pieces` RLNC-coded frames.  Each frame is committed and
    /// tagged with the mux's authenticator and prefixed with
    /// [`KIND_PUBSUB`] before encryption.
    ///
    /// Returns the new mux paired with the generation's
    /// [`Authenticator::Commitment`].  For non-stateful authenticators
    /// (e.g. [`rlnc_cat_rs::auth::NullAuthenticator`],
    /// [`rlnc_cat_rs::auth::KeyedHashAuthenticator`]) the same
    /// commitment is recoverable via [`PubsubMux::commit`].  For
    /// authenticators whose commitment binds per-generation signing
    /// state (e.g. lattice-LHS), this is the only way the source can
    /// observe its own commitment, since the receiver-side
    /// [`PubsubMux::register_topic`] /
    /// [`PubsubMux::register_relay`] need it out-of-band.
    ///
    /// [`Authenticator::Commitment`]: rlnc_cat_rs::auth::Authenticator::Commitment
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
    ) -> Io<Error, (Self, A::Commitment)>
    where
        F: Fn(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + Sync + 'static,
    {
        let piece_count = data.piece_count();
        let piece_byte_len = data.piece_byte_len();
        let auth_for_source = Arc::clone(&self.auth);
        let (commitment, stream) = source(auth_for_source, data, rng_factory);
        stream
            .take(num_pieces)
            .collect()
            .map_error(|e| Error::RlncLayer {
                reason: e.to_string(),
            })
            .flat_map(move |pieces| {
                let frames = pieces
                    .iter()
                    .map(|wp| codec::encode::<A>(&topic, piece_count, piece_byte_len, wp))
                    .collect::<Result<Vec<Vec<u8>>, Error>>();
                Io::suspend(move || frames).flat_map(move |frames| {
                    fan_out_all(self, frames).map(move |mux| (mux, commitment))
                })
            })
    }

    /// Receive one datagram and dispatch it.
    ///
    /// `ephemeral_seed` follows the [`Host::recv_one`] contract: it
    /// is consumed only when an inbound `msg1` triggers a fresh
    /// responder.
    ///
    /// `relay_rng` is consumed at most once: when a piece arrives
    /// for a topic registered with [`register_relay`], the closure
    /// is invoked to produce the random GF(2^8) coefficients for the
    /// recoded piece's coding vector.  Pure decoder / sender nodes
    /// can pass [`unused_relay_rng`].
    ///
    /// [`register_relay`]: PubsubMux::register_relay
    ///
    /// # Errors
    ///
    /// Propagates [`Host::recv_one`] errors.  Per-peer / per-frame
    /// problems (including auth tag rejection) surface as
    /// [`MuxEvent::Rejected`] rather than `Err`.
    #[must_use]
    pub fn recv_one<R>(self, ephemeral_seed: [u8; 32], relay_rng: R) -> Io<Error, (Self, MuxEvent)>
    where
        R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
    {
        let Self {
            host,
            auth,
            decoders,
            recoders,
        } = self;
        host.recv_one(ephemeral_seed)
            .flat_map(move |(host, host_event)| {
                process_event(host, auth, decoders, recoders, host_event, relay_rng)
            })
    }
}

/// Build the `[kind, payload...]` plaintext.
fn prefix_kind(kind: u8, payload: &[u8]) -> Vec<u8> {
    [kind].into_iter().chain(payload.iter().copied()).collect()
}

/// A relay-RNG that errors if invoked.  Use this from non-relay
/// callers as the `relay_rng` argument to
/// [`PubsubMux::recv_one`].  The error is only surfaced if a piece
/// actually arrives for a relay topic, which by definition cannot
/// happen on a node that has no recoders registered.
pub fn unused_relay_rng()
-> impl FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static {
    |_n| {
        Err(rlnc_cat_rs::error::Error::RandomGenerationFailed(
            "relay rng was invoked but no relay was expected".to_owned(),
        ))
    }
}

/// Fan a list of pubsub frames out to every established peer.
fn fan_out_all<A>(mux: PubsubMux<A>, frames: Vec<Vec<u8>>) -> Io<Error, PubsubMux<A>>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    frames.into_iter().fold(Io::pure(mux), |acc, frame| {
        acc.flat_map(move |mux| send_frame_to_all(mux, &frame))
    })
}

fn send_frame_to_all<A>(mux: PubsubMux<A>, frame: &[u8]) -> Io<Error, PubsubMux<A>>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    let addrs = mux.host.established_addrs();
    addrs.into_iter().fold(Io::pure(mux), |acc, addr| {
        let datagram = prefix_kind(KIND_PUBSUB, frame);
        acc.flat_map(move |mux| {
            let PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            } = mux;
            host.send(addr, datagram).map(move |host| PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            })
        })
    })
}

/// Fan a single pubsub frame out to every established peer except
/// `exclude`.  Returns the number of peers actually sent to.
fn send_frame_excluding<A>(
    mux: PubsubMux<A>,
    frame: &[u8],
    exclude: UdpAddr,
) -> Io<Error, (PubsubMux<A>, usize)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    let addrs: Vec<UdpAddr> = mux
        .host
        .established_addrs()
        .into_iter()
        .filter(|a| *a != exclude)
        .collect();
    let count = addrs.len();
    let mux_io = addrs.into_iter().fold(Io::pure(mux), |acc, addr| {
        let datagram = prefix_kind(KIND_PUBSUB, frame);
        acc.flat_map(move |mux| {
            let PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            } = mux;
            host.send(addr, datagram).map(move |host| PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            })
        })
    });
    mux_io.map(move |mux| (mux, count))
}

/// Process one [`HostEvent`] through the mux's bookkeeping.
fn process_event<A, R>(
    host: Host,
    auth: Arc<A>,
    decoders: BTreeMap<Topic, (DecoderState, A::Commitment)>,
    recoders: BTreeMap<Topic, (Recoder, A::Commitment)>,
    ev: HostEvent,
    relay_rng: R,
) -> Io<Error, (PubsubMux<A>, MuxEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
{
    match ev {
        HostEvent::HandshakeProgress { addr } => Io::pure((
            PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            },
            MuxEvent::HandshakeProgress { addr },
        )),
        HostEvent::HandshakeComplete {
            addr,
            remote_static,
        } => Io::pure((
            PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            },
            MuxEvent::HandshakeComplete {
                addr,
                remote_static,
            },
        )),
        HostEvent::Rejected { addr, reason } => Io::pure((
            PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            },
            MuxEvent::Rejected { addr, reason },
        )),
        HostEvent::DatagramDelivered { addr, plaintext } => {
            dispatch_plaintext(host, auth, decoders, recoders, addr, &plaintext, relay_rng)
        }
    }
}

fn dispatch_plaintext<A, R>(
    host: Host,
    auth: Arc<A>,
    decoders: BTreeMap<Topic, (DecoderState, A::Commitment)>,
    recoders: BTreeMap<Topic, (Recoder, A::Commitment)>,
    addr: UdpAddr,
    plaintext: &[u8],
    relay_rng: R,
) -> Io<Error, (PubsubMux<A>, MuxEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
{
    let kind = plaintext.first().copied();
    match () {
        () if kind == Some(KIND_APP) => {
            let bytes = plaintext.get(1..).map(<[u8]>::to_vec).unwrap_or_default();
            Io::pure((
                PubsubMux {
                    host,
                    auth,
                    decoders,
                    recoders,
                },
                MuxEvent::AppData { addr, bytes },
            ))
        }
        () if kind == Some(KIND_PUBSUB) => {
            let body = plaintext.get(1..).unwrap_or(&[]);
            handle_pubsub_body(host, auth, decoders, recoders, addr, body, relay_rng)
        }
        () if kind.is_none() => Io::pure((
            PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            },
            MuxEvent::Rejected {
                addr,
                reason: "datagram plaintext was empty (no kind byte)".to_owned(),
            },
        )),
        () => {
            let unknown = kind.unwrap_or(0);
            Io::pure((
                PubsubMux {
                    host,
                    auth,
                    decoders,
                    recoders,
                },
                MuxEvent::Rejected {
                    addr,
                    reason: format!("unknown plaintext kind byte 0x{unknown:02x}"),
                },
            ))
        }
    }
}

fn handle_pubsub_body<A, R>(
    host: Host,
    auth: Arc<A>,
    decoders: BTreeMap<Topic, (DecoderState, A::Commitment)>,
    recoders: BTreeMap<Topic, (Recoder, A::Commitment)>,
    addr: UdpAddr,
    body: &[u8],
    relay_rng: R,
) -> Io<Error, (PubsubMux<A>, MuxEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
{
    let parsed = codec::decode::<A>(body);
    match parsed {
        Err(e) => Io::pure((
            PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            },
            MuxEvent::Rejected {
                addr,
                reason: format!("pubsub frame decode failed: {e}"),
            },
        )),
        Ok((frame, wire_piece)) => {
            let topic = frame.topic.clone();
            // Relay role takes precedence over decoder role when both
            // are registered (last-write-wins is the documented policy).
            if recoders.contains_key(&topic) {
                relay_path(
                    host,
                    auth,
                    decoders,
                    recoders,
                    addr,
                    topic,
                    &wire_piece,
                    relay_rng,
                )
            } else if decoders.contains_key(&topic) {
                Io::pure(decoder_path(
                    host,
                    auth,
                    decoders,
                    recoders,
                    addr,
                    topic,
                    &wire_piece,
                ))
            } else {
                Io::pure((
                    PubsubMux {
                        host,
                        auth,
                        decoders,
                        recoders,
                    },
                    MuxEvent::Rejected {
                        addr,
                        reason: format!("frame received for unregistered topic {topic}"),
                    },
                ))
            }
        }
    }
}

fn decoder_path<A>(
    host: Host,
    auth: Arc<A>,
    mut decoders: BTreeMap<Topic, (DecoderState, A::Commitment)>,
    recoders: BTreeMap<Topic, (Recoder, A::Commitment)>,
    addr: UdpAddr,
    topic: Topic,
    wire_piece: &WirePiece<A>,
) -> (PubsubMux<A>, MuxEvent)
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    match decoders.remove(&topic) {
        None => (
            PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            },
            MuxEvent::Rejected {
                addr,
                reason: format!("decoder for topic {topic} vanished mid-dispatch"),
            },
        ),
        Some((decoder, commitment)) => {
            let verify_outcome = auth.verify(&commitment, wire_piece.piece(), wire_piece.tag());
            match verify_outcome {
                Err(e) => {
                    decoders.insert(topic.clone(), (decoder, commitment));
                    (
                        PubsubMux {
                            host,
                            auth,
                            decoders,
                            recoders,
                        },
                        MuxEvent::Rejected {
                            addr,
                            reason: format!("auth verify failed for topic {topic}: {e}"),
                        },
                    )
                }
                Ok(()) => match decoder.absorb(wire_piece.piece()) {
                    Err(e) => (
                        PubsubMux {
                            host,
                            auth,
                            decoders,
                            recoders,
                        },
                        MuxEvent::Rejected {
                            addr,
                            reason: format!("absorb failed: {e}"),
                        },
                    ),
                    Ok(next) if next.is_complete() => match next.decode() {
                        Ok(data) => (
                            PubsubMux {
                                host,
                                auth,
                                decoders,
                                recoders,
                            },
                            MuxEvent::PubsubDelivered { addr, topic, data },
                        ),
                        Err(e) => (
                            PubsubMux {
                                host,
                                auth,
                                decoders,
                                recoders,
                            },
                            MuxEvent::Rejected {
                                addr,
                                reason: format!("decode failed: {e}"),
                            },
                        ),
                    },
                    Ok(next) => {
                        decoders.insert(topic.clone(), (next, commitment));
                        (
                            PubsubMux {
                                host,
                                auth,
                                decoders,
                                recoders,
                            },
                            MuxEvent::PubsubAbsorbed { addr, topic },
                        )
                    }
                },
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn relay_path<A, R>(
    host: Host,
    auth: Arc<A>,
    decoders: BTreeMap<Topic, (DecoderState, A::Commitment)>,
    mut recoders: BTreeMap<Topic, (Recoder, A::Commitment)>,
    addr: UdpAddr,
    topic: Topic,
    wire_piece: &WirePiece<A>,
    relay_rng: R,
) -> Io<Error, (PubsubMux<A>, MuxEvent)>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
    R: FnOnce(usize) -> Result<Vec<u8>, rlnc_cat_rs::error::Error> + Send + 'static,
{
    match recoders.remove(&topic) {
        None => Io::pure((
            PubsubMux {
                host,
                auth,
                decoders,
                recoders,
            },
            MuxEvent::Rejected {
                addr,
                reason: format!("recoder for topic {topic} vanished mid-dispatch"),
            },
        )),
        Some((recoder, commitment)) => {
            let verify_outcome = auth.verify(&commitment, wire_piece.piece(), wire_piece.tag());
            match verify_outcome {
                Err(e) => {
                    recoders.insert(topic.clone(), (recoder, commitment));
                    Io::pure((
                        PubsubMux {
                            host,
                            auth,
                            decoders,
                            recoders,
                        },
                        MuxEvent::Rejected {
                            addr,
                            reason: format!("auth verify failed for topic {topic}: {e}"),
                        },
                    ))
                }
                Ok(()) => match recoder.add_piece(wire_piece.piece()) {
                    Err(e) => Io::pure((
                        PubsubMux {
                            host,
                            auth,
                            decoders,
                            recoders,
                        },
                        MuxEvent::Rejected {
                            addr,
                            reason: format!("recoder add_piece failed: {e}"),
                        },
                    )),
                    Ok(next_recoder) => {
                        let piece_count = wire_piece.piece().coding_vector().len();
                        let piece_byte_len = wire_piece.piece().data().len();
                        let recode_io = next_recoder.recode_one(relay_rng);
                        recoders.insert(topic.clone(), (next_recoder, commitment.clone()));
                        let auth_for_tag = Arc::clone(&auth);
                        recode_io
                            .map_error(|e| Error::RlncLayer {
                                reason: e.to_string(),
                            })
                            .flat_map(move |recoded: CodedPiece| {
                                let tag = auth_for_tag.tag(&commitment, &recoded);
                                let recoded_wire = WirePiece::<A>::new(commitment, recoded, tag);
                                let frame_result = codec::encode::<A>(
                                    &topic,
                                    piece_count,
                                    piece_byte_len,
                                    &recoded_wire,
                                );
                                Io::suspend(move || frame_result).flat_map(move |frame| {
                                    let mux = PubsubMux {
                                        host,
                                        auth,
                                        decoders,
                                        recoders,
                                    };
                                    send_frame_excluding(mux, &frame, addr).map(
                                        move |(mux, fanout_count)| {
                                            (
                                                mux,
                                                MuxEvent::PubsubRelayed {
                                                    from: addr,
                                                    topic,
                                                    fanout_count,
                                                },
                                            )
                                        },
                                    )
                                })
                            })
                    }
                },
            }
        }
    }
}
