//! [`PubsubState`]: the protocol-state companion to [`crate::PubsubMux`].
//!
//! Holds the authenticator plus the per-topic decoder and recoder
//! maps, separated from the underlying [`libp2p_cat_host::Host`] so a
//! multi-protocol mux can share one socket across kad / pubsub /
//! rendezvous.  [`crate::PubsubMux`] is the joined view of a
//! [`libp2p_cat_host::Host`] and a [`PubsubState<A>`];
//! [`crate::PubsubMux::split`] decomposes it into the two and
//! [`crate::PubsubMux::join`] reconstitutes it.
//!
//! # Generation lifecycle (pass 9.5)
//!
//! Each decoder / recoder entry carries a `last_activity` tick set
//! whenever the entry is touched (registered, absorbed a piece,
//! re-coded a piece).  [`PubsubState::evict_idle_topics`] /
//! [`PubsubState::evict_idle_relays`] sweep entries idle longer than
//! a caller-supplied threshold; [`PubsubState::unregister_topic`] /
//! [`PubsubState::unregister_relay`] remove entries explicitly.
//! Without these, decoders that never complete a generation (lost
//! pieces, tampered tags, peer left the topic) live forever — a
//! slow leak in long-running pubsub deployments.

use std::collections::BTreeMap;
use std::sync::Arc;

use rlnc_cat_rs::coding::decode::DecoderState;
use rlnc_cat_rs::coding::piece::OriginalData;
use rlnc_cat_rs::coding::recode::Recoder;

use crate::auth::PubsubAuth;
use crate::topic::Topic;

/// Stored decoder entry: protocol state, the commitment the
/// authenticator binds to, and the tick at which it was last
/// touched.
pub(crate) struct DecoderEntry<A>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    pub state: DecoderState,
    pub commitment: A::Commitment,
    pub last_activity: u64,
}

/// Stored recoder entry: protocol state, the commitment the
/// authenticator binds to, and the tick at which it was last
/// touched.
pub(crate) struct RecoderEntry<A>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    pub recoder: Recoder,
    pub commitment: A::Commitment,
    pub last_activity: u64,
}

/// Protocol-state companion of [`crate::PubsubMux`]: the
/// authenticator plus the per-topic decoder and recoder maps.
///
/// Carries a monotonic [`PubsubState::tick`] counter so external
/// drivers can use [`PubsubState::evict_idle_topics`] /
/// [`PubsubState::evict_idle_relays`] to GC topics that have been
/// idle for longer than a chosen threshold.
#[must_use]
pub struct PubsubState<A>
where
    A: PubsubAuth,
    A::Commitment: Clone + Send + Sync + 'static,
    A::Tag: Clone + Send + Sync + 'static,
{
    pub(crate) auth: Arc<A>,
    pub(crate) decoders: BTreeMap<Topic, DecoderEntry<A>>,
    pub(crate) recoders: BTreeMap<Topic, RecoderEntry<A>>,
    pub(crate) tick: u64,
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
            tick: 0,
        }
    }

    /// Borrow the underlying authenticator.
    #[must_use]
    pub fn auth(&self) -> &A {
        &self.auth
    }

    /// Current monotonic tick.  Incremented on every state-touching
    /// operation (register / unregister / successful absorb /
    /// successful recode / evict).  Useful as the threshold input to
    /// [`Self::evict_idle_topics`] / [`Self::evict_idle_relays`].
    #[must_use]
    pub fn tick(&self) -> u64 {
        self.tick
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
    /// and absorbed into a freshly-initialised decoder.  If a
    /// decoder is already registered for `topic`, it is replaced
    /// (use this to rotate to a new generation's commitment).
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
            tick,
        } = self;
        let next_tick = tick.wrapping_add(1);
        decoders.insert(
            topic,
            DecoderEntry {
                state: DecoderState::new(piece_count, piece_byte_len),
                commitment,
                last_activity: next_tick,
            },
        );
        Self {
            auth,
            decoders,
            recoders,
            tick: next_tick,
        }
    }

    /// Pre-register a topic for the **relay** role: inbound pubsub
    /// frames for the topic will be verified against `commitment`,
    /// added to a local recoder, recoded by random linear
    /// combination, re-tagged with the local authenticator, and
    /// fanned out to all peers except the source.  If a recoder is
    /// already registered for `topic`, it is replaced.
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
            tick,
        } = self;
        let next_tick = tick.wrapping_add(1);
        recoders.insert(
            topic,
            RecoderEntry {
                recoder: Recoder::new(piece_count, piece_byte_len),
                commitment,
                last_activity: next_tick,
            },
        );
        Self {
            auth,
            decoders,
            recoders,
            tick: next_tick,
        }
    }

    /// Drop the decoder registered for `topic`, if any.  Returns the
    /// state with the entry removed; if `topic` had no decoder the
    /// state is returned unchanged (but the tick still advances so
    /// the call is observable).
    pub fn unregister_topic(self, topic: &Topic) -> Self {
        let Self {
            auth,
            mut decoders,
            recoders,
            tick,
        } = self;
        decoders.remove(topic);
        Self {
            auth,
            decoders,
            recoders,
            tick: tick.wrapping_add(1),
        }
    }

    /// Drop the recoder registered for `topic`, if any.
    pub fn unregister_relay(self, topic: &Topic) -> Self {
        let Self {
            auth,
            decoders,
            mut recoders,
            tick,
        } = self;
        recoders.remove(topic);
        Self {
            auth,
            decoders,
            recoders,
            tick: tick.wrapping_add(1),
        }
    }

    /// Evict every decoder whose `last_activity` is more than
    /// `max_idle_ticks` ticks behind the current [`Self::tick`].
    /// Returns the state plus the list of topics that were swept.
    ///
    /// `max_idle_ticks` is in tick units (see [`Self::tick`] for the
    /// increment semantics), not wall-clock seconds.
    pub fn evict_idle_topics(self, max_idle_ticks: u64) -> (Self, Vec<Topic>) {
        let Self {
            auth,
            decoders,
            recoders,
            tick,
        } = self;
        let cutoff = tick.saturating_sub(max_idle_ticks);
        let evicted: Vec<Topic> = decoders
            .iter()
            .filter(|(_, entry)| entry.last_activity < cutoff)
            .map(|(topic, _)| topic.clone())
            .collect();
        let kept: BTreeMap<Topic, DecoderEntry<A>> = decoders
            .into_iter()
            .filter(|(_, entry)| entry.last_activity >= cutoff)
            .collect();
        (
            Self {
                auth,
                decoders: kept,
                recoders,
                tick: tick.wrapping_add(1),
            },
            evicted,
        )
    }

    /// Evict every recoder whose `last_activity` is more than
    /// `max_idle_ticks` ticks behind the current [`Self::tick`].
    pub fn evict_idle_relays(self, max_idle_ticks: u64) -> (Self, Vec<Topic>) {
        let Self {
            auth,
            decoders,
            recoders,
            tick,
        } = self;
        let cutoff = tick.saturating_sub(max_idle_ticks);
        let evicted: Vec<Topic> = recoders
            .iter()
            .filter(|(_, entry)| entry.last_activity < cutoff)
            .map(|(topic, _)| topic.clone())
            .collect();
        let kept: BTreeMap<Topic, RecoderEntry<A>> = recoders
            .into_iter()
            .filter(|(_, entry)| entry.last_activity >= cutoff)
            .collect();
        (
            Self {
                auth,
                decoders,
                recoders: kept,
                tick: tick.wrapping_add(1),
            },
            evicted,
        )
    }

    /// Number of currently-registered decoder topics.
    #[must_use]
    pub fn decoder_count(&self) -> usize {
        self.decoders.len()
    }

    /// Number of currently-registered relay topics.
    #[must_use]
    pub fn relay_count(&self) -> usize {
        self.recoders.len()
    }

    /// Whether `topic` has a registered decoder.
    #[must_use]
    pub fn is_decoder_registered(&self, topic: &Topic) -> bool {
        self.decoders.contains_key(topic)
    }

    /// Whether `topic` has a registered relay.
    #[must_use]
    pub fn is_relay_registered(&self, topic: &Topic) -> bool {
        self.recoders.contains_key(topic)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libp2p_cat_types::Error;
    use rlnc_cat_rs::auth::NullAuthenticator;

    use super::PubsubState;
    use crate::topic::Topic;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::PubsubProtocol { reason: reason() })
        }
    }

    fn topic(name: &str) -> Result<Topic, Error> {
        Topic::try_from(name)
    }

    fn fresh_state() -> PubsubState<NullAuthenticator> {
        PubsubState::new(Arc::new(NullAuthenticator))
    }

    #[test]
    fn fresh_state_starts_at_tick_zero() -> Result<(), Error> {
        let state = fresh_state();
        check(state.tick() == 0, || {
            format!("expected fresh tick = 0, got {}", state.tick())
        })?;
        check(state.decoder_count() == 0, || {
            "expected zero decoders".to_owned()
        })?;
        check(state.relay_count() == 0, || {
            "expected zero relays".to_owned()
        })
    }

    #[test]
    fn register_topic_advances_tick_and_records_decoder() -> Result<(), Error> {
        let t = topic("/chat/v1")?;
        let state = fresh_state().register_topic(t.clone(), 3, 4, ());
        check(state.tick() == 1, || {
            format!("expected tick = 1, got {}", state.tick())
        })?;
        check(state.decoder_count() == 1, || {
            format!("expected 1 decoder, got {}", state.decoder_count())
        })?;
        check(state.is_decoder_registered(&t), || {
            "expected decoder for /chat/v1".to_owned()
        })
    }

    #[test]
    fn unregister_topic_removes_decoder() -> Result<(), Error> {
        let t = topic("/chat/v1")?;
        let state = fresh_state()
            .register_topic(t.clone(), 3, 4, ())
            .unregister_topic(&t);
        check(state.decoder_count() == 0, || {
            "decoder should be gone after unregister".to_owned()
        })?;
        check(!state.is_decoder_registered(&t), || {
            "is_decoder_registered should be false".to_owned()
        })
    }

    #[test]
    fn evict_idle_topics_sweeps_old_entries() -> Result<(), Error> {
        let old_topic = topic("/old")?;
        let new_topic = topic("/new")?;
        // Register old_topic at tick 1, advance tick by 5
        // unregister cycles on a placeholder, then register
        // new_topic at tick 7.  evict_idle_topics(3) should sweep
        // old_topic (idle gap of 6 from tick 7) and keep new_topic
        // (idle gap of 0).
        let s0 = fresh_state().register_topic(old_topic.clone(), 3, 4, ());
        let s1 = (0..5).try_fold(s0, |acc, _| -> Result<_, Error> {
            let placeholder = topic("/x")?;
            Ok(acc.unregister_topic(&placeholder))
        })?;
        let s2 = s1.register_topic(new_topic.clone(), 3, 4, ());
        check(s2.tick() == 7, || {
            format!("expected tick = 7, got {}", s2.tick())
        })?;
        let (s3, evicted) = s2.evict_idle_topics(3);
        check(evicted.contains(&old_topic), || {
            format!("expected old_topic in evicted, got {evicted:?}")
        })?;
        check(!s3.is_decoder_registered(&old_topic), || {
            "old_topic should be gone after evict_idle".to_owned()
        })?;
        check(s3.is_decoder_registered(&new_topic), || {
            "new_topic should survive evict_idle".to_owned()
        })
    }

    #[test]
    fn register_relay_and_unregister_relay_round_trip() -> Result<(), Error> {
        let t = topic("/relay/v1")?;
        let state = fresh_state().register_relay(t.clone(), 3, 4, ());
        check(state.is_relay_registered(&t), || {
            "relay should be registered".to_owned()
        })?;
        let state = state.unregister_relay(&t);
        check(!state.is_relay_registered(&t), || {
            "relay should be gone after unregister".to_owned()
        })
    }
}
