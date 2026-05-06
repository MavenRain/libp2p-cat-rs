//! Internal connection-state types: in-flight handshakes and
//! established post-handshake transports.  Each entry carries a
//! `last_activity: u64` field tied to the host's monotonic tick
//! counter, so the host can evict the least-recently-used entry
//! when it would otherwise exceed [`crate::Capacity`].
//!
//! Not exposed publicly.

use libp2p_cat_noise::{InitiatorAfterE, ResponderAfterResponse, StaticPublicKey, TransportState};
use libp2p_cat_types::PeerId;

/// A handshake that has sent its first message and is waiting on the
/// remote to advance it.  Two stable shapes; transient intermediate
/// states (`InitiatorAfterResponse`, `ResponderAfterE`) advance
/// immediately within a single `recv_one` call and are never stored.
pub(crate) enum HandshakeState {
    /// Initiator has sent `msg1`, waiting on `msg2` from the remote.
    InitiatorAwaitingResponse(InitiatorAfterE),
    /// Responder has sent `msg2`, waiting on `msg3` from the remote.
    ResponderAwaitingFinalize(ResponderAfterResponse),
}

/// Stored handshake entry: the protocol state plus the host tick at
/// which it was last touched.
pub(crate) struct InFlightHandshake {
    pub state: HandshakeState,
    pub last_activity: u64,
}

/// Established post-handshake state for a single peer.  Carries the
/// host tick at which it was last touched (any send / recv against
/// this peer) so the LRU eviction policy can pick the least active
/// entry when the [`crate::Capacity`] cap is hit.
pub(crate) struct EstablishedConnection {
    pub transport: TransportState,
    pub remote_static: StaticPublicKey,
    pub remote_peer_id: PeerId,
    pub last_activity: u64,
}
