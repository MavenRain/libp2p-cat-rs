//! Protocol identifier for substream negotiation.
//!
//! Mirrors libp2p's protocol-name convention: a UTF-8 string that must
//! begin with `/` and contain only printable ASCII (bytes `0x21..=0x7E`),
//! e.g. `/libp2p-cat/pubsub/1.0.0`.  Wire-level whitespace and control
//! characters are forbidden so that a protocol name fits cleanly into a
//! length-prefixed framing without ambiguity.
//!
//! # Examples
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use libp2p_cat_types::ProtocolId;
//!
//! let p = ProtocolId::new("/libp2p-cat/pubsub/1.0.0".to_owned());
//! p.as_ref().map_err(|e| format!("rejected good name: {e}"))?;
//!
//! let bad = ProtocolId::new("no-leading-slash".to_owned());
//! bad.is_err()
//!     .then_some(())
//!     .ok_or("expected validation rejection")?;
//! # Ok(()) }
//! ```

use core::fmt;

use crate::error::Error;

/// A validated protocol identifier.
///
/// Construct via [`ProtocolId::new`] or `TryFrom<&str>` /
/// `TryFrom<String>`.  The inner string is private; use [`as_str`] to
/// borrow it.
///
/// [`as_str`]: ProtocolId::as_str
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[must_use]
pub struct ProtocolId(String);

impl ProtocolId {
    /// Construct a `ProtocolId` from a `String`, validating the input.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProtocolId`] if `name` does not start
    /// with `/` or contains a non-printable-ASCII byte.
    pub fn new(name: String) -> Result<Self, Error> {
        let valid = name.starts_with('/') && name.bytes().all(|b| (0x21..=0x7E).contains(&b));
        if valid {
            Ok(Self(name))
        } else {
            Err(Error::InvalidProtocolId { input: name })
        }
    }

    /// Borrow the underlying protocol-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ProtocolId {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for ProtocolId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s.to_owned())
    }
}

impl From<ProtocolId> for String {
    fn from(p: ProtocolId) -> Self {
        p.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    fn expect_invalid(outcome: Result<ProtocolId, Error>) -> Result<(), Error> {
        match outcome {
            Err(Error::InvalidProtocolId { .. }) => Ok(()),
            Ok(p) => Err(Error::HostState {
                reason: format!("expected validation rejection, got Ok({p})"),
            }),
            Err(other) => Err(Error::HostState {
                reason: format!("expected InvalidProtocolId, got {other:?}"),
            }),
        }
    }

    #[test]
    fn accepts_well_formed_name() -> Result<(), Error> {
        let p = ProtocolId::new("/libp2p-cat/pubsub/1.0.0".to_owned())?;
        check(p.as_str() == "/libp2p-cat/pubsub/1.0.0", || {
            format!("unexpected stored name: {}", p.as_str())
        })
    }

    #[test]
    fn rejects_missing_leading_slash() -> Result<(), Error> {
        expect_invalid(ProtocolId::new("libp2p-cat".to_owned()))
    }

    #[test]
    fn rejects_empty_string() -> Result<(), Error> {
        expect_invalid(ProtocolId::new(String::new()))
    }

    #[test]
    fn rejects_whitespace() -> Result<(), Error> {
        expect_invalid(ProtocolId::new("/libp2p cat/1.0.0".to_owned()))
    }

    #[test]
    fn rejects_control_characters() -> Result<(), Error> {
        expect_invalid(ProtocolId::new("/libp2p\n".to_owned()))
    }

    #[test]
    fn try_from_str_works() -> Result<(), Error> {
        let p: ProtocolId = "/x/1".try_into()?;
        check(p.as_str() == "/x/1", || {
            format!("unexpected stored name: {}", p.as_str())
        })
    }
}
