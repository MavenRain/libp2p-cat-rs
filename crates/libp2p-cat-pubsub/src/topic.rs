//! Pubsub topic identifier.
//!
//! Topics are short UTF-8 strings carried in plaintext at the start of
//! every pubsub frame.  Validation rules:
//!
//! - Non-empty.
//! - At most [`MAX_TOPIC_LEN`] bytes.
//! - Only printable ASCII (`0x21..=0x7E`) — keeps wire bytes
//!   unambiguous and avoids whitespace / control-char surprises in
//!   logs.
//!
//! [`MAX_TOPIC_LEN`]: crate::MAX_TOPIC_LEN

use core::fmt;

use libp2p_cat_types::Error;

use crate::codec::MAX_TOPIC_LEN;

/// A validated pubsub topic name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[must_use]
pub struct Topic(String);

impl Topic {
    /// Construct a `Topic`, validating the input.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PubsubProtocol`] if `name` is empty, exceeds
    /// [`MAX_TOPIC_LEN`] bytes, or contains a non-printable-ASCII byte.
    ///
    /// [`MAX_TOPIC_LEN`]: crate::MAX_TOPIC_LEN
    pub fn new(name: String) -> Result<Self, Error> {
        let len = name.len();
        let printable = name.bytes().all(|b| (0x21..=0x7E).contains(&b));
        if len == 0 || len > MAX_TOPIC_LEN || !printable {
            Err(Error::PubsubProtocol {
                reason: format!(
                    "topic must be 1..={MAX_TOPIC_LEN} printable ASCII bytes, got {len}"
                ),
            })
        } else {
            Ok(Self(name))
        }
    }

    /// Borrow the topic string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Topic {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s.to_owned())
    }
}

impl TryFrom<String> for Topic {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::PubsubProtocol { reason: reason() })
        }
    }

    fn expect_pubsub_rejection(outcome: Result<Topic, Error>) -> Result<(), Error> {
        match outcome {
            Err(Error::PubsubProtocol { .. }) => Ok(()),
            Err(other) => Err(Error::PubsubProtocol {
                reason: format!("expected PubsubProtocol rejection, got {other:?}"),
            }),
            Ok(t) => Err(Error::PubsubProtocol {
                reason: format!("expected rejection, got Ok({t})"),
            }),
        }
    }

    #[test]
    fn accepts_typical_topic() -> Result<(), Error> {
        let t: Topic = "/chat/v1".try_into()?;
        check(t.as_str() == "/chat/v1", || {
            format!("unexpected stored name: {}", t.as_str())
        })
    }

    #[test]
    fn rejects_empty() -> Result<(), Error> {
        expect_pubsub_rejection(Topic::new(String::new()))
    }

    #[test]
    fn rejects_whitespace() -> Result<(), Error> {
        expect_pubsub_rejection(Topic::new("hello world".to_owned()))
    }

    #[test]
    fn rejects_oversized() -> Result<(), Error> {
        let oversized = "x".repeat(MAX_TOPIC_LEN + 1);
        expect_pubsub_rejection(Topic::new(oversized))
    }
}
