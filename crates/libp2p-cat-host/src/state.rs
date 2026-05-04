//! Internal connection-state types: in-flight handshakes and
//! established post-handshake transports.  Not exposed publicly.

use libp2p_cat_noise::{InitiatorAfterE, ResponderAfterResponse, StaticPublicKey, TransportState};
use libp2p_cat_types::PeerId;

/// A handshake that has sent its first message and is waiting on the
/// remote to advance it.  Two stable shapes; transient intermediate
/// states (`InitiatorAfterResponse`, `ResponderAfterE`) advance
/// immediately within a single `recv_one` call and are never stored.
pub(crate) enum InFlightHandshake {
    /// Initiator has sent `msg1`, waiting on `msg2` from the remote.
    InitiatorAwaitingResponse(InitiatorAfterE),
    /// Responder has sent `msg2`, waiting on `msg3` from the remote.
    ResponderAwaitingFinalize(ResponderAfterResponse),
}

/// Established post-handshake state for a single peer.
pub(crate) struct EstablishedConnection {
    pub transport: TransportState,
    pub remote_static: StaticPublicKey,
    pub remote_peer_id: PeerId,
}
