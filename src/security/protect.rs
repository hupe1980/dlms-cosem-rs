//! Applying and removing protection.
//!
//! The composition rules are the part worth stating plainly, because the three modes
//! authenticate different things:
//!
//! | Security control | Additional authenticated data | Payload |
//! |---|---|---|
//! | authenticated **and** encrypted | `SC ‖ AK` | ciphertext ‖ tag |
//! | authenticated only | `SC ‖ AK ‖ plaintext` | plaintext ‖ tag |
//! | encrypted only | *(none)* | ciphertext |
//!
//! An implementation that authenticates the ciphertext in the second row, or omits the
//! authentication key from the first, produces frames that decode locally and are
//! rejected by every other stack.

use crate::codec::{Error, ErrorKind, Result};
use crate::xdlms::SecurityControl;

use super::keys::{Key, KeyRef, KeyUsage, SystemTitle, nonce};
use super::{CryptoProvider, SecuritySuite};

/// Which symmetric key set an association protects with.
///
/// One field rather than two flags: the three are alternatives, and "dedicated and
/// broadcast at once" would name a key nothing holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeySet {
    /// The global unicast encryption key — ordinary traffic, and everything that runs
    /// before an association has a key of its own.
    #[default]
    GlobalUnicast,
    /// The global broadcast encryption key, shared across a fleet.
    GlobalBroadcast,
    /// The key this association negotiated, delivered in the `InitiateRequest`.
    Dedicated,
}

impl KeySet {
    /// The key this set resolves to.
    #[must_use]
    pub const fn usage(self) -> KeyUsage {
        match self {
            Self::GlobalUnicast => KeyUsage::GlobalUnicastEncryption,
            Self::GlobalBroadcast => KeyUsage::GlobalBroadcastEncryption,
            Self::Dedicated => KeyUsage::Dedicated,
        }
    }

    /// Whether the security control byte's broadcast bit is set for this key set.
    #[must_use]
    pub const fn is_broadcast(self) -> bool {
        matches!(self, Self::GlobalBroadcast)
    }

    /// Whether this is the association's own negotiated key.
    #[must_use]
    pub const fn is_dedicated(self) -> bool {
        matches!(self, Self::Dedicated)
    }
}

/// What protection an association applies and demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityPolicy {
    /// The suite in use.
    pub suite: SecuritySuite,
    /// Whether outgoing APDUs are authenticated.
    pub authenticated: bool,
    /// Whether outgoing APDUs are encrypted.
    pub encrypted: bool,
    /// Which key set protects an APDU — and, on the receiving side, which one this end
    /// will *accept*.
    ///
    /// The security control byte's broadcast bit is the sender's claim. Letting it choose
    /// the key would hand an attacker that choice, and a broadcast key is shared with a
    /// whole fleet: a unicast exchange accepted under one lets any fleet member speak as
    /// the head-end, with a tag that verifies. So this states what is demanded, and a
    /// frame whose bit disagrees is refused before a key is touched.
    pub key_set: KeySet,
}

impl SecurityPolicy {
    /// No protection at all.
    pub const NONE: Self = Self {
        suite: SecuritySuite::Suite0,
        authenticated: false,
        encrypted: false,
        key_set: KeySet::GlobalUnicast,
    };

    /// Authenticated and encrypted with the given suite — what a ciphered association
    /// normally uses.
    #[must_use]
    pub const fn authenticated_encrypted(suite: SecuritySuite) -> Self {
        Self { suite, authenticated: true, encrypted: true, key_set: KeySet::GlobalUnicast }
    }

    /// The same protection on the **global unicast** key set.
    ///
    /// The `InitiateRequest` and `InitiateResponse` are always protected this way, even
    /// in an association that will use a dedicated key for everything afterwards: the
    /// dedicated key is *delivered* inside the ciphered `InitiateRequest`, so nothing
    /// can be protected with it before that message has been opened. The same holds for
    /// HLS, which runs before the association is open.
    #[must_use]
    pub const fn global(self) -> Self {
        Self { key_set: KeySet::GlobalUnicast, ..self }
    }

    /// The same protection with the dedicated key set, or back on the unicast one.
    #[must_use]
    pub const fn with_dedicated(self, dedicated: bool) -> Self {
        Self { key_set: if dedicated { KeySet::Dedicated } else { KeySet::GlobalUnicast }, ..self }
    }

    /// The same protection on the broadcast key set, or back on the unicast one.
    ///
    /// For a receiver this says which key set it will *accept*; see
    /// [`SecurityPolicy::key_set`].
    #[must_use]
    pub const fn with_broadcast(self, broadcast: bool) -> Self {
        Self { key_set: if broadcast { KeySet::GlobalBroadcast } else { KeySet::GlobalUnicast }, ..self }
    }

    /// True when this association uses the key it negotiated for itself.
    #[must_use]
    pub const fn dedicated(self) -> bool {
        self.key_set.is_dedicated()
    }

    /// True when this association uses the broadcast key set.
    #[must_use]
    pub const fn broadcast(self) -> bool {
        self.key_set.is_broadcast()
    }

    /// Which key this policy's key set resolves to.
    #[must_use]
    pub const fn key_usage(self) -> KeyUsage {
        self.key_set.usage()
    }

    /// The security control byte this policy produces.
    #[must_use]
    pub const fn control(self) -> SecurityControl {
        SecurityControl::new(self.suite.id(), self.authenticated, self.encrypted)
            .with_broadcast(self.key_set.is_broadcast())
    }

    /// True when nothing is applied.
    #[must_use]
    pub const fn is_none(self) -> bool {
        !self.authenticated && !self.encrypted
    }

    /// Check that a received security control byte is at least as strong as this
    /// policy demands.
    ///
    /// This is the downgrade check. A peer that stops encrypting, or drops to a weaker
    /// suite, is refused here rather than quietly accepted — which is the whole point
    /// of negotiating a policy in the first place.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] when the received protection is weaker, the
    /// suite differs, or the frame names a key set this policy did not ask for;
    /// [`ErrorKind::Unsupported`] when compression is claimed.
    pub fn check_received(self, control: SecurityControl) -> Result<()> {
        if control.compressed() {
            return Err(Error::new(ErrorKind::Unsupported, 0));
        }
        // Checked ahead of the `is_none` shortcut, because this bit does not describe
        // how *strongly* a frame is protected — it decides which key opens it, and a
        // receiver must never take that from the sender.
        if control.broadcast_key() != self.key_set.is_broadcast() {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        if self.is_none() {
            return Ok(());
        }
        if control.suite() != self.suite.id()
            || (self.authenticated && !control.authenticated())
            || (self.encrypted && !control.encrypted())
        {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        Ok(())
    }
}

/// Applies and removes protection for one association.
#[derive(Debug)]
pub struct Protector<P> {
    provider: P,
    policy: SecurityPolicy,
}

impl<P: CryptoProvider> Protector<P> {
    /// A protector over `provider` applying `policy`.
    pub const fn new(provider: P, policy: SecurityPolicy) -> Self {
        Self { provider, policy }
    }

    /// The policy in force for service APDUs.
    pub const fn policy(&self) -> SecurityPolicy {
        self.policy
    }

    /// Switch service APDUs between the global and the dedicated key set.
    ///
    /// A server learns which to use from the `InitiateRequest` — a client that delivers
    /// a dedicated key expects `ded-` tagged APDUs back — so this cannot be settled at
    /// construction. Both ends must agree, or every APDU decrypts to noise and fails its
    /// tag.
    pub const fn set_dedicated(&mut self, dedicated: bool) {
        self.policy = self.policy.with_dedicated(dedicated);
    }

    /// The provider, for operations that are not protection — challenges, key wrap.
    pub const fn provider(&self) -> &P {
        &self.provider
    }

    /// The provider, mutably — for installing the dedicated key of an association.
    pub const fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    /// The authentication key's bytes, which every protected APDU authenticates.
    pub fn auth_key(&self) -> Option<&[u8]> {
        self.provider.authentication_key()
    }

    /// Protect `plaintext` into `out`, returning the protected payload.
    ///
    /// The payload is what goes after the security control byte and invocation counter
    /// in a `glo-`/`ded-` APDU. `auth_key` is the authentication key's bytes, which are
    /// authenticated data rather than a cipher key.
    ///
    /// # Errors
    /// When the buffer is too small, or the provider cannot find the key.
    pub fn protect<'o>(
        &self,
        system_title: &SystemTitle,
        invocation_counter: u32,
        auth_key: &[u8],
        plaintext: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8]> {
        self.protect_as(self.policy, system_title, invocation_counter, auth_key, plaintext, out)
    }

    /// Protect under a policy other than this protector's — the Initiate exchange, which
    /// is global even in a dedicated association.
    ///
    /// # Errors
    /// As [`Protector::protect`].
    pub fn protect_as<'o>(
        &self,
        policy: SecurityPolicy,
        system_title: &SystemTitle,
        invocation_counter: u32,
        auth_key: &[u8],
        plaintext: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8]> {
        let control = policy.control();
        let iv = nonce(system_title, invocation_counter);
        let key = KeyRef::Usage(policy.key_usage());

        if policy.is_none() {
            let n = plaintext.len();
            out.get_mut(..n)
                .ok_or_else(|| Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))?
                .copy_from_slice(plaintext);
            return Ok(&out[..n]);
        }

        let needed = plaintext.len() + if policy.authenticated { SecuritySuite::TAG_LEN } else { 0 };
        if out.len() < needed {
            return Err(Error::new(ErrorKind::BufferTooSmall { needed: needed - out.len() }, 0));
        }
        out[..plaintext.len()].copy_from_slice(plaintext);

        if policy.authenticated && policy.encrypted {
            let mut aad = [0u8; 1 + Key::MAX_LEN];
            let aad = build_aad(&mut aad, control, auth_key)?;
            let tag = self.provider.aead_seal(key, policy.suite, &iv, aad, &mut out[..plaintext.len()])?;
            out[plaintext.len()..needed].copy_from_slice(&tag);
        } else if policy.authenticated {
            // Authentication only: the plaintext travels in the clear and is
            // authenticated as additional data.
            let tag = self.gmac_with(policy, control, auth_key, &iv, plaintext)?;
            out[plaintext.len()..needed].copy_from_slice(&tag);
        } else {
            let _ = self.provider.aead_seal(key, policy.suite, &iv, &[], &mut out[..plaintext.len()])?;
        }
        Ok(&out[..needed])
    }

    /// Remove protection from `payload` in place, returning the plaintext.
    ///
    /// The tag is verified before any plaintext is returned.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when authentication fails;
    /// [`ErrorKind::UnexpectedMessage`] when the protection is weaker than the policy
    /// demands.
    pub fn unprotect<'o>(
        &self,
        control: SecurityControl,
        system_title: &SystemTitle,
        invocation_counter: u32,
        auth_key: &[u8],
        payload: &'o mut [u8],
    ) -> Result<&'o [u8]> {
        self.unprotect_as(self.policy, control, system_title, invocation_counter, auth_key, payload)
    }

    /// Remove protection under a policy other than this protector's.
    ///
    /// # Errors
    /// As [`Protector::unprotect`].
    pub fn unprotect_as<'o>(
        &self,
        policy: SecurityPolicy,
        control: SecurityControl,
        system_title: &SystemTitle,
        invocation_counter: u32,
        auth_key: &[u8],
        payload: &'o mut [u8],
    ) -> Result<&'o [u8]> {
        policy.check_received(control)?;
        let iv = nonce(system_title, invocation_counter);
        let key = KeyRef::Usage(policy.key_usage());
        let suite = SecuritySuite::from_id(control.suite())?;

        if control.is_plain() {
            return Ok(payload);
        }
        if !control.authenticated() {
            self.provider.aead_open_unauthenticated(key, suite, &iv, payload)?;
            return Ok(payload);
        }

        let len = payload
            .len()
            .checked_sub(SecuritySuite::TAG_LEN)
            .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0))?;
        let mut tag = [0u8; SecuritySuite::TAG_LEN];
        tag.copy_from_slice(&payload[len..]);

        if control.encrypted() {
            let mut aad = [0u8; 1 + Key::MAX_LEN];
            let aad = build_aad(&mut aad, control, auth_key)?;
            self.provider.aead_open(key, suite, &iv, aad, &mut payload[..len], &tag)?;
        } else {
            let expected = self.gmac_with(policy, control, auth_key, &iv, &payload[..len])?;
            if !constant_time_eq(&expected, &tag) {
                return Err(Error::new(ErrorKind::BadTag, 0));
            }
        }
        Ok(&payload[..len])
    }

    /// A GMAC over the security control byte, the authentication key and `data`.
    ///
    /// This is both the authentication-only protection tag and the HLS mechanism 5
    /// response, which is why it is one function.
    ///
    /// The three parts are handed to the provider as segments rather than joined, so
    /// `data` may be a whole APDU of any size. Joining them into a fixed buffer here is
    /// how authentication-only protection quietly acquires a maximum PDU size that
    /// nothing in the standard has.
    ///
    /// # Errors
    /// When the provider fails or the suite is not one it implements.
    pub fn gmac_over(
        &self,
        control: SecurityControl,
        auth_key: &[u8],
        iv: &[u8; 12],
        data: &[u8],
    ) -> Result<[u8; 12]> {
        self.gmac_with(self.policy, control, auth_key, iv, data)
    }

    fn gmac_with(
        &self,
        policy: SecurityPolicy,
        control: SecurityControl,
        auth_key: &[u8],
        iv: &[u8; 12],
        data: &[u8],
    ) -> Result<[u8; 12]> {
        self.provider.gmac(
            KeyRef::Usage(policy.key_usage()),
            SecuritySuite::from_id(control.suite())?,
            iv,
            &[&[control.0][..], auth_key, data],
        )
    }

    /// The HLS mechanism 5 response to a challenge.
    ///
    /// Returns `SC ‖ IC ‖ tag`, which is what goes into
    /// `reply_to_HLS_authentication`. The nonce uses the *responder's* own system title
    /// and counter, so each side's answer is bound to its own identity.
    ///
    /// # Errors
    /// When the provider fails or the challenge is longer than the buffer allows.
    pub fn hls_gmac_response(
        &self,
        system_title: &SystemTitle,
        invocation_counter: u32,
        auth_key: &[u8],
        challenge: &[u8],
        out: &mut [u8; 17],
    ) -> Result<()> {
        let control = SecurityControl::new(self.policy.suite.id(), true, false);
        let iv = nonce(system_title, invocation_counter);
        // HLS runs before the association is open, so it is always the global key set:
        // a dedicated key delivered in the InitiateRequest is not yet in force.
        let tag = self.gmac_with(self.policy.global(), control, auth_key, &iv, challenge)?;
        out[0] = control.0;
        out[1..5].copy_from_slice(&invocation_counter.to_be_bytes());
        out[5..].copy_from_slice(&tag);
        Ok(())
    }

    /// Check the peer's HLS mechanism 5 response to a challenge we sent.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when the response does not match;
    /// [`ErrorKind::InvalidLength`] when it is not 17 bytes.
    pub fn verify_hls_gmac(
        &self,
        peer_title: &SystemTitle,
        auth_key: &[u8],
        challenge: &[u8],
        response: &[u8],
    ) -> Result<()> {
        if response.len() != 17 {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        }
        let control = SecurityControl(response[0]);
        // The reply's own security control byte is the peer's claim about how it
        // computed the tag, and every field of it feeds the tag we are about to
        // recompute. A peer that names a different suite, or sets the encryption,
        // broadcast or compression bits, is not answering the challenge that was sent —
        // and verifying under whatever it claimed would let it choose the construction.
        if !control.authenticated()
            || control.encrypted()
            || control.broadcast_key()
            || control.compressed()
            || control.suite() != self.policy.suite.id()
        {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        let ic = u32::from_be_bytes([response[1], response[2], response[3], response[4]]);
        let iv = nonce(peer_title, ic);
        let expected = self.gmac_with(self.policy.global(), control, auth_key, &iv, challenge)?;
        if constant_time_eq(&expected, &response[5..]) {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::BadTag, 0))
        }
    }
}

fn build_aad<'a>(
    buf: &'a mut [u8; 1 + Key::MAX_LEN],
    control: SecurityControl,
    auth_key: &[u8],
) -> Result<&'a [u8]> {
    let n = 1 + auth_key.len();
    if n > buf.len() {
        return Err(Error::new(ErrorKind::Unsupported, 0));
    }
    buf[0] = control.0;
    buf.get_mut(1..n).ok_or_else(|| Error::new(ErrorKind::Unsupported, 0))?.copy_from_slice(auth_key);
    Ok(buf.get(..n).unwrap_or(&[]))
}

/// Compare two byte strings without leaking where they differ.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    #[cfg(feature = "crypto")]
    {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }
    #[cfg(not(feature = "crypto"))]
    {
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

/// Decryption without authentication, which GCM makes possible and DLMS permits.
///
/// Split out because it is the one operation a caller should have to reach for by name:
/// there is no integrity guarantee, and a policy that demands authentication never
/// reaches it.
trait AeadOpenUnauthenticated {
    fn aead_open_unauthenticated(
        &self,
        key: KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        buf: &mut [u8],
    ) -> Result<()>;
}

impl<T: CryptoProvider> AeadOpenUnauthenticated for T {
    fn aead_open_unauthenticated(
        &self,
        key: KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        buf: &mut [u8],
    ) -> Result<()> {
        // GCM is counter mode: encrypting the ciphertext with the same nonce recovers
        // the plaintext. The tag the seal returns is discarded, which is exactly the
        // guarantee this mode does not offer.
        let _ = self.aead_seal(key, suite, nonce, &[], buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The broadcast bit chooses *which key* opens a frame, so a receiver must take it
    /// from its own configuration and never from the sender. A broadcast key is shared
    /// with a whole fleet by definition: a unicast exchange accepted under one lets any
    /// meter in that fleet answer as the head-end, with a tag that verifies.
    #[test]
    fn the_key_set_is_what_this_end_demands_not_what_the_frame_claims() {
        let unicast = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
        let broadcast = unicast.with_broadcast(true);

        assert_eq!(unicast.key_usage(), KeyUsage::GlobalUnicastEncryption);
        assert_eq!(broadcast.key_usage(), KeyUsage::GlobalBroadcastEncryption);
        assert!(broadcast.control().broadcast_key());
        assert!(!unicast.control().broadcast_key());

        // Each accepts its own bit and refuses the other's.
        assert!(unicast.check_received(unicast.control()).is_ok());
        assert!(broadcast.check_received(broadcast.control()).is_ok());
        assert_eq!(
            unicast.check_received(broadcast.control()).unwrap_err().kind,
            ErrorKind::UnexpectedMessage,
            "a frame naming the broadcast key set on a unicast association is a key downgrade"
        );
        assert_eq!(
            broadcast.check_received(unicast.control()).unwrap_err().kind,
            ErrorKind::UnexpectedMessage
        );
    }

    /// The bit is checked ahead of the "no protection demanded" shortcut, because it is
    /// not a statement about *how strongly* a frame is protected.
    #[test]
    fn an_unprotected_policy_still_refuses_a_key_set_it_did_not_ask_for() {
        assert!(SecurityPolicy::NONE.check_received(SecurityControl(0x00)).is_ok());
        assert_eq!(
            SecurityPolicy::NONE.check_received(SecurityControl(0x40)).unwrap_err().kind,
            ErrorKind::UnexpectedMessage
        );
    }

    /// HLS and the Initiate exchange both run before an association has a key set of its
    /// own, so `global()` has to mean the global *unicast* set and clear both switches.
    #[test]
    fn global_means_the_unicast_key_set() {
        let p = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite2)
            .with_dedicated(true)
            .with_broadcast(true);
        assert_eq!(p.global().key_usage(), KeyUsage::GlobalUnicastEncryption);
        assert_eq!(p.global().suite, SecuritySuite::Suite2, "and changes nothing else");
    }
}
