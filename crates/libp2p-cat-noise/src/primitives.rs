//! Newtype wrappers around 32-byte X25519 keys, DH outputs, and the
//! intermediate values of the symmetric state.
//!
//! The point of this module is to use the type system to keep
//! semantically distinct 32-byte values from being mixed up.  A
//! [`StaticPrivateKey`] and an [`EphemeralPrivateKey`] both wrap a
//! `[u8; 32]` but cannot be passed in each other's place.

use core::fmt;

use x25519_dalek::{PublicKey, StaticSecret};

/// Length in bytes of an X25519 key (private or public) and of every
/// 32-byte working value in the symmetric state.
pub const KEY_LEN: usize = 32;

/// A long-lived X25519 private key used to authenticate this peer
/// during a Noise XX handshake.
///
/// Constructed from raw bytes via [`StaticPrivateKey::from_bytes`];
/// callers are responsible for sourcing those bytes from a
/// cryptographically secure RNG.  The bytes are stored as-is and
/// clamped at DH time by `x25519-dalek`.
#[derive(Clone)]
#[must_use]
pub struct StaticPrivateKey([u8; KEY_LEN]);

impl StaticPrivateKey {
    /// Wrap raw 32 bytes as a static private key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for StaticPrivateKey {
    /// Redacts the bytes; private keys must not appear in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticPrivateKey(<redacted>)")
    }
}

/// The X25519 public key derived from a [`StaticPrivateKey`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[must_use]
pub struct StaticPublicKey([u8; KEY_LEN]);

impl StaticPublicKey {
    /// Wrap raw 32 bytes as a static public key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// A bundled static private key and its derived public key.
///
/// Constructing one is the only way to start a Noise handshake.
#[derive(Clone)]
#[must_use]
pub struct StaticKeypair {
    private: StaticPrivateKey,
    public: StaticPublicKey,
}

impl StaticKeypair {
    /// Build a static keypair from 32 raw private bytes, deriving the
    /// public key automatically.
    pub fn from_private_bytes(private_bytes: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(private_bytes);
        let public = PublicKey::from(&secret);
        Self {
            private: StaticPrivateKey(private_bytes),
            public: StaticPublicKey(public.to_bytes()),
        }
    }

    /// Borrow the private half.
    pub fn private(&self) -> &StaticPrivateKey {
        &self.private
    }

    /// Borrow the public half.
    pub fn public(&self) -> &StaticPublicKey {
        &self.public
    }
}

impl fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("public", &self.public)
            .field("private", &self.private)
            .finish()
    }
}

/// A short-lived X25519 private key generated during a single Noise
/// handshake.
///
/// Internal to the crate: the caller never holds one of these
/// directly; they pass an `ephemeral_seed: [u8; 32]` and the type
/// disappears once the handshake completes.
#[derive(Clone)]
pub(crate) struct EphemeralPrivateKey([u8; KEY_LEN]);

impl EphemeralPrivateKey {
    pub(crate) fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        Self(seed)
    }

    pub(crate) fn public(&self) -> EphemeralPublicKey {
        let secret = StaticSecret::from(self.0);
        EphemeralPublicKey(PublicKey::from(&secret).to_bytes())
    }
}

/// The X25519 public key derived from an [`EphemeralPrivateKey`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EphemeralPublicKey([u8; KEY_LEN]);

impl EphemeralPublicKey {
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// The 32-byte output of an X25519 Diffie-Hellman.
///
/// Internal: never escapes the symmetric state.
pub(crate) struct DhOutput([u8; KEY_LEN]);

impl DhOutput {
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Compute X25519 DH between an ephemeral private key and a peer's
/// ephemeral public key.
pub(crate) fn dh_ee(private: &EphemeralPrivateKey, public: &EphemeralPublicKey) -> DhOutput {
    DhOutput(dh_raw(&private.0, &public.0))
}

/// Compute X25519 DH between an ephemeral private key and a peer's
/// static public key.
pub(crate) fn dh_es(private: &EphemeralPrivateKey, public: &StaticPublicKey) -> DhOutput {
    DhOutput(dh_raw(&private.0, &public.0))
}

/// Compute X25519 DH between a static private key and a peer's
/// ephemeral public key.
pub(crate) fn dh_se(private: &StaticPrivateKey, public: &EphemeralPublicKey) -> DhOutput {
    DhOutput(dh_raw(&private.0, &public.0))
}

fn dh_raw(private_bytes: &[u8; KEY_LEN], public_bytes: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let secret = StaticSecret::from(*private_bytes);
    let peer = PublicKey::from(*public_bytes);
    secret.diffie_hellman(&peer).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_derives_consistent_public() {
        let private = [7u8; KEY_LEN];
        let kp_a = StaticKeypair::from_private_bytes(private);
        let kp_b = StaticKeypair::from_private_bytes(private);
        assert_eq!(kp_a.public(), kp_b.public());
    }

    #[test]
    fn dh_is_symmetric() {
        let alice = StaticKeypair::from_private_bytes([1u8; KEY_LEN]);
        let bob = StaticKeypair::from_private_bytes([2u8; KEY_LEN]);
        let alice_eph = EphemeralPrivateKey::from_seed([3u8; KEY_LEN]);
        let bob_eph = EphemeralPrivateKey::from_seed([4u8; KEY_LEN]);

        let ee_a = dh_ee(&alice_eph, &bob_eph.public());
        let ee_b = dh_ee(&bob_eph, &alice_eph.public());
        assert_eq!(ee_a.as_bytes(), ee_b.as_bytes());

        // alice's static + bob's ephemeral matches bob's ephemeral + alice's static.
        let s_e = dh_se(alice.private(), &bob_eph.public());
        let e_s = dh_es(&bob_eph, alice.public());
        assert_eq!(s_e.as_bytes(), e_s.as_bytes());

        // The reverse pairing.
        let s_e = dh_se(bob.private(), &alice_eph.public());
        let e_s = dh_es(&alice_eph, bob.public());
        assert_eq!(s_e.as_bytes(), e_s.as_bytes());
    }
}
