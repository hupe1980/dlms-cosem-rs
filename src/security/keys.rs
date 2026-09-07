//! Keys, and the things that name them.

use core::fmt;

/// The eight-byte identity of a DLMS peer.
///
/// A system title is not a secret, but it is half of every nonce: reusing one across
/// two devices that share a key makes their nonces collide, which for GCM is a
/// key-recovery event rather than a privacy one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SystemTitle(pub [u8; 8]);

impl SystemTitle {
    /// From the eight bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// From a slice that must be exactly eight bytes.
    pub fn from_slice(bytes: &[u8]) -> crate::codec::Result<Self> {
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| crate::codec::Error::new(crate::codec::ErrorKind::InvalidLength, 0))?;
        Ok(Self(arr))
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// The three-character manufacturer identifier, when it is printable ASCII.
    #[must_use]
    pub fn manufacturer(&self) -> Option<&str> {
        core::str::from_utf8(&self.0[..3]).ok().filter(|s| s.is_ascii())
    }
}

impl fmt::Debug for SystemTitle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemTitle(")?;
        for b in &self.0 {
            write!(f, "{b:02X}")?;
        }
        f.write_str(")")
    }
}

impl fmt::Display for SystemTitle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

/// What a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyUsage {
    /// The global unicast encryption key, which protects ordinary traffic.
    GlobalUnicastEncryption,
    /// The global broadcast encryption key, used for messages to many meters at once.
    GlobalBroadcastEncryption,
    /// The authentication key, which is authenticated data rather than a cipher key.
    Authentication,
    /// The key-encrypting key, under which other keys are wrapped for transport.
    KeyEncrypting,
    /// The key negotiated for this association only, carried in the InitiateRequest.
    Dedicated,
}

impl KeyUsage {
    /// The `Key-Id` this usage has in `general-ciphering`'s identified-key form.
    ///
    /// `Key-Id` is an enumeration of exactly two values — `global-unicast-encryption-key`
    /// (0) and `global-broadcast-encryption-key` (1). Every other usage answers `None`
    /// rather than inventing a number: the authentication key in particular is *never* an
    /// identified key, because identified-key names the key that deciphers the content
    /// and the authentication key never does that.
    #[must_use]
    pub const fn key_id(self) -> Option<u8> {
        match self {
            Self::GlobalUnicastEncryption => Some(0),
            Self::GlobalBroadcastEncryption => Some(1),
            Self::Authentication | Self::KeyEncrypting | Self::Dedicated => None,
        }
    }
}

/// A reference to a key, without the key.
///
/// A provider resolves this to material it holds — bytes in memory, a slot in a secure
/// element, a handle in an HSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRef<'a> {
    /// One of the well-known keys of this association.
    Usage(KeyUsage),
    /// Raw bytes supplied by the caller, for one operation.
    Raw(&'a [u8]),
}

impl From<KeyUsage> for KeyRef<'_> {
    fn from(u: KeyUsage) -> Self {
        Self::Usage(u)
    }
}

/// A symmetric key: 16 bytes for suites 0 and 1, 32 for suite 2.
///
/// Fixed capacity, so it needs no allocator. `Debug` prints `[REDACTED]`, so a
/// structured log or a `defmt` trace of anything containing a key cannot leak it by
/// accident.
///
/// The bytes are cleared on drop **when the `crypto` feature is on**, which is what
/// brings in `zeroize`. Without it there is no way to clear them that the optimiser is
/// obliged to keep — a plain `fill(0)` on a value about to die is exactly the store a
/// compiler is allowed to delete — so the crate does not pretend to. Any build that
/// handles real keys has `crypto` on, because `suite0` implies it.
///
/// The length is carried rather than fixed by a type parameter because the suite decides
/// it and the suite arrives on the wire. A ring that could only hold 128-bit keys made
/// suite 2 unreachable through [`KeyRef::Usage`] — the only form the protection layer
/// uses — however completely the provider implemented AES-256.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    buf: [u8; Self::MAX_LEN],
    len: u8,
}

impl Key {
    /// The longest key this can hold: 256 bits, which is suite 2's.
    pub const MAX_LEN: usize = 32;

    /// A 128-bit key, the size suites 0 and 1 use.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        let mut buf = [0u8; Self::MAX_LEN];
        let mut i = 0;
        while i < 16 {
            buf[i] = bytes[i];
            i += 1;
        }
        Self { buf, len: 16 }
    }

    /// A 256-bit key, the size suite 2 uses.
    #[must_use]
    pub const fn new_256(bytes: [u8; 32]) -> Self {
        Self { buf: bytes, len: 32 }
    }

    /// A key from a slice that must be 16 or 32 bytes long.
    ///
    /// Any other length is refused rather than padded: a key silently zero-extended to
    /// the cipher's block size is a key nobody chose.
    ///
    /// # Errors
    /// [`crate::codec::ErrorKind::InvalidLength`] for any length but 16 or 32.
    pub fn from_slice(bytes: &[u8]) -> crate::codec::Result<Self> {
        if bytes.len() != 16 && bytes.len() != 32 {
            return Err(crate::codec::Error::new(crate::codec::ErrorKind::InvalidLength, 0));
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf.get_mut(..bytes.len())
            .ok_or_else(|| crate::codec::Error::new(crate::codec::ErrorKind::InvalidLength, 0))?
            .copy_from_slice(bytes);
        Ok(Self { buf, len: bytes.len() as u8 })
    }

    /// The bytes. Every call site is a place a key could escape, so there is exactly one
    /// and it is named.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// How many bytes the key has.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Always false; a key has at least sixteen bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "crypto")]
impl Drop for Key {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buf.zeroize();
    }
}

impl From<[u8; 16]> for Key {
    fn from(v: [u8; 16]) -> Self {
        Self::new(v)
    }
}

impl From<[u8; 32]> for Key {
    fn from(v: [u8; 32]) -> Self {
        Self::new_256(v)
    }
}

/// A variable-length credential: an LLS password, or an HLS shared secret.
///
/// Fixed capacity, so it needs no allocator, and 64 bytes because that is the longest
/// challenge the Blue Book allows. Like [`Key`] it prints as `[REDACTED]`, and clears
/// itself when dropped under the same condition and for the same reason.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    buf: [u8; Self::MAX_LEN],
    len: u8,
}

impl Secret {
    /// The longest secret this can hold.
    pub const MAX_LEN: usize = 64;

    /// Copy `bytes` into a secret.
    ///
    /// # Errors
    /// [`crate::codec::ErrorKind::InvalidLength`] when `bytes` is longer than
    /// [`Secret::MAX_LEN`].
    pub fn new(bytes: &[u8]) -> crate::codec::Result<Self> {
        if bytes.len() > Self::MAX_LEN {
            return Err(crate::codec::Error::new(crate::codec::ErrorKind::InvalidLength, 0));
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { buf, len: bytes.len() as u8 })
    }

    /// The bytes. Every call site is a place a secret could escape, so there is exactly
    /// one and it is named.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "crypto")]
impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buf.zeroize();
    }
}

/// The symmetric keys of one association.
///
/// Every entry is a [`Key`], so one ring serves suite 0, suite 1 and suite 2 without the
/// caller choosing a width at compile time.
#[derive(Debug, Clone, Default)]
pub struct KeyRing {
    /// Global unicast encryption key.
    pub guek: Option<Key>,
    /// Global broadcast encryption key.
    pub gbek: Option<Key>,
    /// Authentication key. Authenticated as additional data, never used as a cipher key.
    pub gak: Option<Key>,
    /// Key-encrypting key, also called the master key.
    pub kek: Option<Key>,
    /// The key for this association only, delivered inside the ciphered
    /// InitiateRequest. Dropped when the association is released.
    pub dedicated: Option<Key>,
}

impl KeyRing {
    /// A ring with the two 128-bit keys an ordinary suite-0 association needs.
    #[must_use]
    pub const fn new(guek: [u8; 16], gak: [u8; 16]) -> Self {
        Self { guek: Some(Key::new(guek)), gak: Some(Key::new(gak)), gbek: None, kek: None, dedicated: None }
    }

    /// A ring with the two 256-bit keys a suite-2 association needs.
    #[must_use]
    pub const fn new_256(guek: [u8; 32], gak: [u8; 32]) -> Self {
        Self {
            guek: Some(Key::new_256(guek)),
            gak: Some(Key::new_256(gak)),
            gbek: None,
            kek: None,
            dedicated: None,
        }
    }

    /// The key for a usage, if the ring holds it.
    #[must_use]
    pub fn get(&self, usage: KeyUsage) -> Option<&[u8]> {
        let slot = match usage {
            KeyUsage::GlobalUnicastEncryption => self.guek.as_ref(),
            KeyUsage::GlobalBroadcastEncryption => self.gbek.as_ref(),
            KeyUsage::Authentication => self.gak.as_ref(),
            KeyUsage::KeyEncrypting => self.kek.as_ref(),
            KeyUsage::Dedicated => self.dedicated.as_ref(),
        };
        slot.map(Key::expose)
    }

    /// Install a key for a usage.
    pub fn set(&mut self, usage: KeyUsage, key: Key) {
        match usage {
            KeyUsage::GlobalUnicastEncryption => self.guek = Some(key),
            KeyUsage::GlobalBroadcastEncryption => self.gbek = Some(key),
            KeyUsage::Authentication => self.gak = Some(key),
            KeyUsage::KeyEncrypting => self.kek = Some(key),
            KeyUsage::Dedicated => self.dedicated = Some(key),
        }
    }

    /// Install the dedicated key for an association.
    pub fn set_dedicated(&mut self, key: Key) {
        self.dedicated = Some(key);
    }

    /// Forget the dedicated key. Called when the association is released, so a key
    /// cannot outlive the association that negotiated it.
    pub fn clear_dedicated(&mut self) {
        self.dedicated = None;
    }
}

/// Build the twelve-byte GCM nonce: system title, then invocation counter.
#[must_use]
pub const fn nonce(system_title: &SystemTitle, invocation_counter: u32) -> [u8; 12] {
    let t = system_title.0;
    let c = invocation_counter.to_be_bytes();
    [t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], c[0], c[1], c[2], c[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Key-Id` is an enumeration of two values. The authentication key is not one of
    /// them — `identified-key` names the key that deciphers the content, and the
    /// authentication key never does that — so answering `2` would put a number the
    /// standard does not define into a `general-ciphering` header.
    #[test]
    fn only_the_two_ciphering_keys_have_a_key_id() {
        assert_eq!(KeyUsage::GlobalUnicastEncryption.key_id(), Some(0));
        assert_eq!(KeyUsage::GlobalBroadcastEncryption.key_id(), Some(1));
        assert_eq!(KeyUsage::Authentication.key_id(), None);
        assert_eq!(KeyUsage::KeyEncrypting.key_id(), None);
        assert_eq!(KeyUsage::Dedicated.key_id(), None);
    }

    #[test]
    fn a_nonce_is_the_title_then_the_counter() {
        let st = SystemTitle::new([0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E]);
        assert_eq!(
            nonce(&st, 0x0000_0001),
            [0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn a_system_title_shows_its_manufacturer() {
        let st = SystemTitle::new(*b"MMM\x00\x00\xbcaN");
        assert_eq!(st.manufacturer(), Some("MMM"));
    }

    #[test]
    fn a_secret_does_not_print_itself() {
        #[cfg(feature = "std")]
        {
            use std::format;
            let s = Key::new([0xAAu8; 16]);
            assert_eq!(format!("{s:?}"), "[REDACTED]");
            let ring = KeyRing::new([1; 16], [2; 16]);
            let printed = format!("{ring:?}");
            assert!(!printed.contains('1'), "no key bytes in a Debug rendering: {printed}");
        }
    }

    /// Suite 2 is 256-bit AES-GCM, and the ring has to be able to hold the key or the
    /// suite is unreachable however completely the provider implements it.
    #[test]
    fn a_ring_holds_keys_of_both_suite_widths() {
        let ring = KeyRing::new_256([7; 32], [8; 32]);
        assert_eq!(ring.get(KeyUsage::GlobalUnicastEncryption).map(<[u8]>::len), Some(32));
        let ring = KeyRing::new([7; 16], [8; 16]);
        assert_eq!(ring.get(KeyUsage::Authentication).map(<[u8]>::len), Some(16));
        // And a length no suite defines is refused rather than padded.
        assert!(Key::from_slice(&[0u8; 24]).is_err());
        assert!(Key::from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn a_dedicated_key_can_be_dropped_without_dropping_the_ring() {
        let mut ring = KeyRing::new([1; 16], [2; 16]);
        ring.set_dedicated(Key::new([3; 16]));
        assert!(ring.get(KeyUsage::Dedicated).is_some());
        ring.clear_dedicated();
        assert!(ring.get(KeyUsage::Dedicated).is_none());
        assert!(ring.get(KeyUsage::GlobalUnicastEncryption).is_some());
    }
}
