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

/// What protection an association applies and demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityPolicy {
    /// The suite in use.
    pub suite: SecuritySuite,
    /// Whether outgoing APDUs are authenticated.
    pub authenticated: bool,
    /// Whether outgoing APDUs are encrypted.
    pub encrypted: bool,
    /// Whether the dedicated key is used instead of the global one.
    pub dedicated: bool,
}

impl SecurityPolicy {
    /// No protection at all.
    pub const NONE: Self =
        Self { suite: SecuritySuite::Suite0, authenticated: false, encrypted: false, dedicated: false };

    /// Authenticated and encrypted with the given suite — what a ciphered association
    /// normally uses.
    #[must_use]
    pub const fn authenticated_encrypted(suite: SecuritySuite) -> Self {
        Self { suite, authenticated: true, encrypted: true, dedicated: false }
    }

    /// The same protection with the global key set instead of the dedicated one.
    ///
    /// The `InitiateRequest` and `InitiateResponse` are always protected globally, even
    /// in an association that will use a dedicated key for everything afterwards: the
    /// dedicated key is *delivered* inside the ciphered `InitiateRequest`, so nothing
    /// can be protected with it before that message has been opened.
    #[must_use]
    pub const fn global(self) -> Self {
        Self { dedicated: false, ..self }
    }

    /// The same protection with the dedicated key set.
    #[must_use]
    pub const fn with_dedicated(self, dedicated: bool) -> Self {
        Self { dedicated, ..self }
    }

    /// The security control byte this policy produces.
    #[must_use]
    pub const fn control(self) -> SecurityControl {
        SecurityControl::new(self.suite.id(), self.authenticated, self.encrypted)
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
    /// [`ErrorKind::UnexpectedMessage`] when the received protection is weaker, or the
    /// suite differs; [`ErrorKind::Unsupported`] when compression is claimed.
    pub fn check_received(self, control: SecurityControl) -> Result<()> {
        if control.compressed() {
            return Err(Error::new(ErrorKind::Unsupported, 0));
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
        self.policy.dedicated = dedicated;
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

    /// The key an APDU is protected with under `policy`.
    const fn key_for(policy: SecurityPolicy, broadcast: bool) -> KeyUsage {
        if policy.dedicated {
            KeyUsage::Dedicated
        } else if broadcast {
            KeyUsage::GlobalBroadcastEncryption
        } else {
            KeyUsage::GlobalUnicastEncryption
        }
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
        let key = KeyRef::Usage(Self::key_for(policy, false));

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
        let key = KeyRef::Usage(Self::key_for(policy, control.broadcast_key()));
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
            KeyRef::Usage(Self::key_for(policy, control.broadcast_key())),
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
