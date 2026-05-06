//! [`Capacity`]: cap on the host's two state tables.
//!
//! `Host` keeps `BTreeMap<UdpAddr, _>` for both in-flight handshakes
//! and post-handshake established connections.  Without a cap, both
//! grow without bound — a long-running rendezvous server or DHT
//! bootstrap node will eventually exhaust memory.
//!
//! [`Capacity`] gives the user a finite cap for each table.  When an
//! insert would exceed the cap, the host evicts the least-recently-
//! used entry from that table to make room.  Eviction is silent (no
//! [`HostEvent`](crate::HostEvent) variant): future datagrams from
//! the evicted peer surface as
//! [`HostEvent::Rejected`](crate::HostEvent::Rejected) when they fail
//! the established / in-flight lookups.
//!
//! Defaults are generous enough for tests and small deployments
//! (`max_handshakes_in_flight = 256`, `max_established = 1024`); a
//! production rendezvous or bootstrap node should call
//! [`crate::Host::with_capacity`] with values matched to its
//! resource budget.

/// Caps on the host's two state tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Capacity {
    max_handshakes_in_flight: usize,
    max_established: usize,
}

const DEFAULT_MAX_HANDSHAKES_IN_FLIGHT: usize = 256;
const DEFAULT_MAX_ESTABLISHED: usize = 1024;

impl Capacity {
    /// Build a [`Capacity`] with the supplied caps.  Both must be
    /// non-zero; a zero cap would refuse every insert.
    ///
    /// # Errors
    ///
    /// Returns `None` if either cap is zero.
    #[must_use]
    pub fn new(max_handshakes_in_flight: usize, max_established: usize) -> Option<Self> {
        match (max_handshakes_in_flight, max_established) {
            (0, _) | (_, 0) => None,
            (h, e) => Some(Self {
                max_handshakes_in_flight: h,
                max_established: e,
            }),
        }
    }

    /// Maximum number of in-flight handshakes the host will hold
    /// simultaneously before evicting the LRU.
    #[must_use]
    pub fn max_handshakes_in_flight(&self) -> usize {
        self.max_handshakes_in_flight
    }

    /// Maximum number of established connections the host will hold
    /// simultaneously before evicting the LRU.
    #[must_use]
    pub fn max_established(&self) -> usize {
        self.max_established
    }
}

impl Default for Capacity {
    fn default() -> Self {
        Self {
            max_handshakes_in_flight: DEFAULT_MAX_HANDSHAKES_IN_FLIGHT,
            max_established: DEFAULT_MAX_ESTABLISHED,
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p_cat_types::Error;

    use super::{Capacity, DEFAULT_MAX_ESTABLISHED, DEFAULT_MAX_HANDSHAKES_IN_FLIGHT};

    fn check(cond: bool, reason: impl FnOnce() -> String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::HostState { reason: reason() })
        }
    }

    #[test]
    fn default_uses_documented_caps() -> Result<(), Error> {
        let cap = Capacity::default();
        check(
            cap.max_handshakes_in_flight() == DEFAULT_MAX_HANDSHAKES_IN_FLIGHT,
            || {
                format!(
                    "expected default handshake cap {DEFAULT_MAX_HANDSHAKES_IN_FLIGHT}, got {}",
                    cap.max_handshakes_in_flight()
                )
            },
        )?;
        check(cap.max_established() == DEFAULT_MAX_ESTABLISHED, || {
            format!(
                "expected default established cap {DEFAULT_MAX_ESTABLISHED}, got {}",
                cap.max_established()
            )
        })
    }

    #[test]
    fn new_rejects_zero_handshake_cap() -> Result<(), Error> {
        check(Capacity::new(0, 1).is_none(), || {
            "Capacity::new(0, 1) should be None".to_owned()
        })
    }

    #[test]
    fn new_rejects_zero_established_cap() -> Result<(), Error> {
        check(Capacity::new(1, 0).is_none(), || {
            "Capacity::new(1, 0) should be None".to_owned()
        })
    }

    #[test]
    fn new_round_trips_caps() -> Result<(), Error> {
        let cap = Capacity::new(4, 7).ok_or_else(|| Error::HostState {
            reason: "Capacity::new(4, 7) should be Some".to_owned(),
        })?;
        check(cap.max_handshakes_in_flight() == 4, || {
            format!("expected 4, got {}", cap.max_handshakes_in_flight())
        })?;
        check(cap.max_established() == 7, || {
            format!("expected 7, got {}", cap.max_established())
        })
    }
}
