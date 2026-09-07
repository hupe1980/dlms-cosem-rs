//! The notification listener: decoding pushed data.
//!
//! A meter's customer interface emits a `DataNotification` on its own initiative,
//! usually ciphered under a key the customer holds. There is no association, no
//! handshake and nothing to correlate: the frame arrives, and the only thing that says
//! which key opens it is the system title inside it.
//!
//! This is the shape of the Austrian, Luxembourg and Dutch customer interfaces, and it
//! is the reason the listener exists separately from [`super::ClientSession`].

use crate::axdr::{Data, DateTime};
use crate::codec::{Decode, Error, ErrorKind, Reader, Result};
use crate::security::{CryptoProvider, KeyRing, Protector, ReplayWindow, SecurityPolicy, SystemTitle};
use crate::xdlms::{Apdu, ApduTag, CipheredService, DataNotification, SecurityControl};

/// Finds the keys for a meter, by its system title.
///
/// A listener in front of a single meter answers from one key ring; a head-end answers
/// from a database. Returning `None` is how an unknown meter is ignored rather than
/// treated as an error.
pub trait PushKeyLookup {
    /// The keys for this meter, if any are known.
    fn keys_for(&self, system_title: &SystemTitle) -> Option<&KeyRing>;

    /// The replay window for this meter.
    ///
    /// There is deliberately no default. A push frame carries no handshake and nothing
    /// to correlate, so the invocation counter is the *only* thing standing between a
    /// listener and a recorded frame replayed a year later; an implementation that
    /// forgets to keep one should not compile.
    ///
    /// Returning `None` for a meter whose keys are known means "accept nothing from it".
    fn replay_window(&mut self, system_title: &SystemTitle) -> Option<&mut ReplayWindow>;
}

/// A key ring and replay window for exactly one meter.
#[derive(Debug, Clone)]
pub struct SingleMeterKeys {
    /// Which meter.
    pub system_title: SystemTitle,
    /// Its keys.
    pub keys: KeyRing,
    /// Which counters have already been accepted from it. Persist
    /// [`ReplayWindow::highest`] and restore with [`ReplayWindow::resumed`], or a
    /// listener that restarts will accept every frame it has ever seen a second time.
    pub replay: ReplayWindow,
}

impl SingleMeterKeys {
    /// A lookup for one meter, accepting only strictly increasing counters.
    #[must_use]
    pub const fn new(system_title: SystemTitle, keys: KeyRing) -> Self {
        Self { system_title, keys, replay: ReplayWindow::strict() }
    }
}

impl PushKeyLookup for SingleMeterKeys {
    fn keys_for(&self, system_title: &SystemTitle) -> Option<&KeyRing> {
        (*system_title == self.system_title).then_some(&self.keys)
    }

    fn replay_window(&mut self, system_title: &SystemTitle) -> Option<&mut ReplayWindow> {
        (*system_title == self.system_title).then_some(&mut self.replay)
    }
}

/// What a notification carried.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReceivedNotification<'a> {
    /// Which meter sent it, when the frame said.
    pub system_title: Option<SystemTitle>,
    /// The counter it was sent under, for a protected notification.
    pub invocation_counter: Option<u32>,
    /// When the values were captured, if the meter said.
    pub captured_at: Option<DateTime>,
    /// The values — for a push setup with several objects, a structure with one field
    /// per object in the push object list.
    pub body: Data<'a>,
}

/// Decodes pushed notifications.
///
/// The listener is told up front what protection it *requires*, and that is the point.
/// A push frame is unsolicited: there is no association to have negotiated anything, so
/// the only statement about how a frame should have been protected is the one the
/// caller makes here. A listener that instead read the protection out of the frame it
/// was handed would authenticate exactly as much as the sender felt like — which for a
/// forged frame is nothing at all.
#[derive(Debug)]
pub struct NotificationListener<P, L> {
    provider: P,
    lookup: L,
    required: SecurityPolicy,
}

impl<P: CryptoProvider, L: PushKeyLookup> NotificationListener<P, L> {
    /// A listener over `provider` that finds keys with `lookup` and refuses any
    /// notification protected more weakly than `required`.
    ///
    /// Pass [`SecurityPolicy::authenticated_encrypted`] for the ordinary customer
    /// interface. [`SecurityPolicy::NONE`] accepts anything, including a completely
    /// unauthenticated frame, and is for decoding a capture rather than for trusting
    /// what arrives.
    ///
    /// A meter that pushes under the **broadcast** key set needs
    /// [`SecurityPolicy::with_broadcast`] here: which key set opens a frame is something
    /// the listener demands, not something it reads out of the frame's own header.
    pub const fn new(provider: P, lookup: L, required: SecurityPolicy) -> Self {
        Self { provider, lookup, required }
    }

    /// What this listener demands of a notification.
    #[must_use]
    pub const fn required(&self) -> SecurityPolicy {
        self.required
    }

    /// The key lookup, mutably — for adding meters, or persisting replay windows.
    pub const fn lookup_mut(&mut self) -> &mut L {
        &mut self.lookup
    }

    /// Decode one notification APDU.
    ///
    /// `buf` receives the deciphered APDU and the result borrows from it.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when the tag does not verify or the counter is a replay;
    /// [`ErrorKind::Unsupported`] when no key is known for the sender.
    pub fn handle<'b>(&mut self, apdu: &[u8], buf: &'b mut [u8]) -> Result<ReceivedNotification<'b>> {
        self.handle_inner(apdu, None, buf)
    }

    /// Decode one notification that arrived on a link whose peer is already known.
    ///
    /// `glo-event-notification` and `ded-event-notification` carry no system title of
    /// their own — they are sent inside an association, or over a link that serves one
    /// meter — so there is nothing in the frame to look a key up by. This is how the
    /// caller supplies the identity the frame omits. For `general-glo-ciphering`, which
    /// does carry a title, the frame's own title wins and `sender` is ignored.
    ///
    /// # Errors
    /// As [`NotificationListener::handle`].
    pub fn handle_from<'b>(
        &mut self,
        sender: SystemTitle,
        apdu: &[u8],
        buf: &'b mut [u8],
    ) -> Result<ReceivedNotification<'b>> {
        self.handle_inner(apdu, Some(sender), buf)
    }

    fn handle_inner<'b>(
        &mut self,
        apdu: &[u8],
        sender: Option<SystemTitle>,
        buf: &'b mut [u8],
    ) -> Result<ReceivedNotification<'b>> {
        let tag_byte = apdu.first().copied().unwrap_or(0);
        let tag = ApduTag::from_u8(tag_byte).ok_or(Error::new(ErrorKind::InvalidTag(tag_byte), 0))?;
        let mut r = Reader::new(apdu);
        r.skip(1)?;

        let (system_title, ciphered): (Option<SystemTitle>, Option<CipheredService<'_>>) = match tag {
            ApduTag::DataNotification => (None, None),
            ApduTag::GeneralGloCiphering | ApduTag::GeneralDedCiphering => {
                let g = crate::xdlms::GeneralGloCiphering::decode(&mut r)?;
                (Some(SystemTitle::from_slice(g.system_title)?), Some(g.ciphered))
            }
            ApduTag::GloEventNotification | ApduTag::DedEventNotification => {
                // A ciphered notification with no system title of its own. Only
                // `handle_from` can decode one, because only the caller knows which
                // meter the link belongs to.
                (sender, Some(CipheredService::decode(&mut r)?))
            }
            _ => return Err(Error::new(ErrorKind::UnexpectedMessage, 0)),
        };

        let plain: &[u8] = match ciphered {
            None => {
                // An unprotected notification. It carries no counter and no tag, so
                // there is nothing to check it against beyond the policy.
                if !self.required.is_none() {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
                let rest = r.take_rest();
                let n = rest.len();
                buf.get_mut(..n)
                    .ok_or(Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))?
                    .copy_from_slice(rest);
                &buf[..n]
            }
            Some(c) => {
                // The protection the frame claims must be at least what was demanded,
                // checked before a key is touched.
                self.required.check_received(c.security_control)?;
                let title = system_title.ok_or(Error::new(ErrorKind::Unsupported, 0))?;
                // The whole ring is taken, not two keys out of it: a `general-ded-`
                // frame is opened with the dedicated key and a broadcast one with the
                // GBEK, and a listener that only ever copied the unicast key would fail
                // those with `Unsupported` rather than with anything a caller can act on.
                // Which of the three it is comes from the tag and from the policy the
                // caller stated, never from the frame's broadcast bit.
                let keys = self.lookup.keys_for(&title).ok_or(Error::new(ErrorKind::Unsupported, 0))?.clone();
                let auth_key = keys
                    .get(crate::security::KeyUsage::Authentication)
                    .map(crate::security::Key::from_slice)
                    .transpose()?
                    .ok_or(Error::new(ErrorKind::Unsupported, 0))?;

                // Reject an obvious replay before doing any cryptography, but record
                // nothing yet: a forged frame that advanced the window would lock the
                // real meter out for good.
                self.lookup
                    .replay_window(&title)
                    .ok_or(Error::new(ErrorKind::Unsupported, 0))?
                    .check(c.invocation_counter)?;

                let n = c.payload.len();
                let body = buf.get_mut(..n).ok_or(Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))?;
                body.copy_from_slice(c.payload);

                // Unprotect under the policy that was *demanded*, not the one the frame
                // announced, so a downgraded frame fails here rather than sailing past.
                // The one thing the frame does decide is the *dedicated* key set, which
                // its tag names rather than a bit inside the protected header; the
                // broadcast key set is the caller's to demand, and `check_received` has
                // already refused a frame that disagrees with it.
                let mut policy = self.required;
                policy.suite = crate::security::SecuritySuite::from_id(c.security_control.suite())?;
                policy = policy.with_dedicated(
                    tag == ApduTag::GeneralDedCiphering || tag == ApduTag::DedEventNotification,
                );
                let protector = Protector::new(ProviderWithKeys { inner: &self.provider, keys }, policy);
                let len = protector
                    .unprotect(c.security_control, &title, c.invocation_counter, auth_key.expose(), body)?
                    .len();
                // The tag has verified: now the counter is spent.
                self.lookup
                    .replay_window(&title)
                    .ok_or(Error::new(ErrorKind::Unsupported, 0))?
                    .accept(c.invocation_counter)?;
                &buf[..len]
            }
        };

        // A ciphered notification's plaintext starts at the service tag.
        let mut pr = Reader::new(plain);
        let inner_tag = pr.peek_u8()?;
        let notification = if ApduTag::from_u8(inner_tag) == Some(ApduTag::DataNotification) {
            let apdu = Apdu::from_bytes(plain)?;
            match apdu {
                Apdu::DataNotification(n) => n,
                _ => return Err(Error::new(ErrorKind::UnexpectedMessage, 0)),
            }
        } else {
            DataNotification::decode(&mut pr)?
        };

        Ok(ReceivedNotification {
            system_title,
            invocation_counter: ciphered.map(|c| c.invocation_counter),
            captured_at: notification.date_time.0,
            body: notification.body,
        })
    }
}

/// A provider that answers key lookups from a ring supplied per message.
///
/// The listener holds one provider but many meters' keys, so the ring travels with the
/// message rather than living in the provider.
#[derive(Debug)]
struct ProviderWithKeys<'p, P> {
    inner: &'p P,
    keys: KeyRing,
}

impl<P: CryptoProvider> CryptoProvider for ProviderWithKeys<'_, P> {
    fn aead_seal(
        &self,
        key: crate::security::keys::KeyRef<'_>,
        suite: crate::security::SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 12]> {
        self.inner.aead_seal(self.resolve(key)?, suite, nonce, aad, buf)
    }

    fn aead_open(
        &self,
        key: crate::security::keys::KeyRef<'_>,
        suite: crate::security::SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 12],
    ) -> Result<()> {
        self.inner.aead_open(self.resolve(key)?, suite, nonce, aad, buf, tag)
    }

    fn gmac(
        &self,
        key: crate::security::keys::KeyRef<'_>,
        suite: crate::security::SecuritySuite,
        nonce: &[u8; 12],
        aad: &[&[u8]],
    ) -> Result<[u8; 12]> {
        self.inner.gmac(self.resolve(key)?, suite, nonce, aad)
    }

    fn random(&self, out: &mut [u8]) -> Result<()> {
        self.inner.random(out)
    }

    fn authentication_key(&self) -> Option<&[u8]> {
        self.keys.get(crate::security::KeyUsage::Authentication)
    }

    fn dedicated_key(&self) -> Option<&[u8]> {
        self.keys.get(crate::security::KeyUsage::Dedicated)
    }
}

impl<P> ProviderWithKeys<'_, P> {
    fn resolve<'k>(
        &'k self,
        key: crate::security::keys::KeyRef<'k>,
    ) -> Result<crate::security::keys::KeyRef<'k>> {
        match key {
            crate::security::keys::KeyRef::Raw(_) => Ok(key),
            crate::security::keys::KeyRef::Usage(u) => self
                .keys
                .get(u)
                .map(crate::security::keys::KeyRef::Raw)
                .ok_or(Error::new(ErrorKind::Unsupported, 0)),
        }
    }
}

impl SecurityControl {
    /// True when this control byte says the payload is protected at all.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        !self.is_plain()
    }
}
