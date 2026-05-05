//! [`PubsubState`]: the protocol-state companion to [`crate::PubsubMux`].
//!
//! Holds the authenticator plus the per-topic decoder and recoder
//! maps, separated from the underlying [`libp2p_cat_host::Host`] so a
//! multi-protocol mux can share one socket across kad / pubsub /
//! rendezvous.  [`crate::PubsubMux`] is the joined view of a
//! [`libp2p_cat_host::Host`] and a [`PubsubState<A>`];
//! [`crate::PubsubMux::split`] decomposes it into the two and
//! [`crate::PubsubMux::join`] reconstitutes it.

use std::collections::BTreeMap;
use std::sync::Arc;

use rlnc_cat_rs::coding::decode::DecoderState;
use rlnc_cat_rs::coding::piece::OriginalData;
use rlnc_cat_rs::coding::recode::Recoder;

use crate::auth::PubsubAuth;
use crate::topic::Topic;

/// Protocol-state companion of [`crate::PubsubMux`]: the
/// authenticator plus the per-topic decoder and recoder maps.
#[must_use]
pub struct PubsubState<A>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    pub(crate) auth: Arc<A>,
    pub(crate) decoders: BTreeMap<Topic, (DecoderState, A::Commitment)>,
    pub(crate) recoders: BTreeMap<Topic, (Recoder, A::Commitment)>,
}

impl<A> PubsubState<A>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    /// Build a fresh state with no registered topics.
    pub fn new(auth: Arc<A>) -> Self {
        Self {
            auth,
            decoders: BTreeMap::new(),
            recoders: BTreeMap::new(),
        }
    }

    /// Borrow the underlying authenticator.
    #[must_use]
    pub fn auth(&self) -> &A {
        &self.auth
    }

    /// Compute the commitment for a fresh generation.  Useful for
    /// nodes that want to publish the commitment out-of-band before
    /// broadcasting.
    #[must_use]
    pub fn commit(&self, original: &OriginalData) -> A::Commitment {
        self.auth.commit(original)
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
            auth,
            mut decoders,
            recoders,
        } = self;
        decoders.insert(
            topic,
            (DecoderState::new(piece_count, piece_byte_len), commitment),
        );
        Self {
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
            auth,
            decoders,
            mut recoders,
        } = self;
        recoders.insert(
            topic,
            (Recoder::new(piece_count, piece_byte_len), commitment),
        );
        Self {
            auth,
            decoders,
            recoders,
        }
    }
}
