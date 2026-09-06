//! Information security: suites, keys, protection and authentication.
//!
//! Nothing here performs cryptography itself. [`CryptoProvider`] is the seam: the
//! default implementation is built on RustCrypto and keeps keys in zeroised memory, and
//! an implementation backed by a secure element, a TPM or a head-end HSM can hold them
//! somewhere the application core never sees. That is how certified meters are built,
//! and binding the algorithms into the stack is why two of the widely used C ports
//! cannot do the asymmetric suites at all.

pub mod counter;
pub mod keys;
mod protect;

// The two engines are the only callers, and either can be left out of a build: a
// head-end compiles no server and meter firmware compiles no client.
#[cfg(any(feature = "client", feature = "server"))]
pub(crate) mod wrap;

#[cfg(feature = "suite0")]
mod rustcrypto;

pub use counter::{InvocationCounter, REPLAY_WIDTH_MAX, REPLAY_WINDOW_MAX, ReplayWindow};
pub use keys::{Key, KeyRef, KeyRing, KeyUsage, Secret, SystemTitle};
pub use protect::{Protector, SecurityPolicy, constant_time_eq};

#[cfg(feature = "suite0")]
pub use rustcrypto::{FixedRandom, RandomSource, RustCryptoProvider};

use crate::codec::{Error, ErrorKind, Result};

/// Which algorithms an association uses.
///
/// The suite is carried in the low nibble of every security control byte, so both ends
/// can tell immediately which key lengths and which curve are in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum SecuritySuite {
    /// AES-GCM-128 with AES-128 key wrap. The only suite most meters implement.
    #[default]
    Suite0,
    /// ECDH and ECDSA on P-256 with AES-GCM-128 and SHA-256.
    Suite1,
    /// ECDH and ECDSA on P-384 with AES-GCM-256 and SHA-384.
    Suite2,
}

impl SecuritySuite {
    /// The suite id as it appears in the security control byte.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Suite0 => 0,
            Self::Suite1 => 1,
            Self::Suite2 => 2,
        }
    }

    /// From a security control byte's low nibble.
    pub fn from_id(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::Suite0,
            1 => Self::Suite1,
            2 => Self::Suite2,
            _ => return Err(Error::new(ErrorKind::Unsupported, 0)),
        })
    }

    /// The symmetric key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Suite0 | Self::Suite1 => 16,
            Self::Suite2 => 32,
        }
    }

    /// The authentication tag length in bytes. DLMS truncates GCM's tag to 96 bits.
    pub const TAG_LEN: usize = 12;

    /// The nonce length in bytes: an eight-byte system title and a four-byte counter.
    pub const NONCE_LEN: usize = 12;
}

/// The cryptographic operations the protocol needs.
///
/// Implementors hold the key material. A [`keys::KeyRef`] names a key without exposing
/// it, so a provider backed by a secure element can resolve it to a slot number.
pub trait CryptoProvider {
    /// Authenticated encryption in place, returning the truncated tag.
    ///
    /// `buf` is the plaintext on entry and the ciphertext on return. `aad` is
    /// authenticated but not encrypted.
    ///
    /// # Errors
    /// When the key is unknown to this provider, or the suite is not supported.
    fn aead_seal(
        &self,
        key: keys::KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 12]>;

    /// Verify and decrypt in place.
    ///
    /// The tag is checked before the caller sees any plaintext, and the comparison is
    /// constant time.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when the tag does not verify — the buffer's contents are
    /// then unspecified and must not be used.
    fn aead_open(
        &self,
        key: keys::KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 12],
    ) -> Result<()>;

    /// A GMAC tag over the concatenation of `aad`, with no plaintext — what
    /// authentication-only protection and HLS mechanism 5 both compute.
    ///
    /// The additional data arrives in **segments** rather than as one slice because in
    /// authentication-only protection it is `SC ‖ AK ‖ APDU`: a short prefix followed by
    /// a whole APDU that already sits in a buffer. Joining them would mean copying the
    /// APDU into a scratch buffer sized for the largest PDU the association negotiated,
    /// and an implementation that reaches for a fixed one instead silently stops working
    /// at whatever size it chose. The tag is over the segments joined end to end; how
    /// they are fed to the MAC is the provider's business.
    ///
    /// # Errors
    /// When the key is unknown to this provider, or the suite is not supported.
    fn gmac(
        &self,
        key: keys::KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[&[u8]],
    ) -> Result<[u8; 12]>;

    /// Wrap a key under a key-encrypting key, per RFC 3394.
    ///
    /// # Errors
    /// When the key is unknown, or the output buffer is too small.
    fn key_wrap(&self, _kek: keys::KeyRef<'_>, _key: &[u8], _out: &mut [u8]) -> Result<usize> {
        Err(Error::new(ErrorKind::Unsupported, 0))
    }

    /// Unwrap a key.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when the integrity check fails.
    fn key_unwrap(&self, _kek: keys::KeyRef<'_>, _wrapped: &[u8], _out: &mut [u8]) -> Result<usize> {
        Err(Error::new(ErrorKind::Unsupported, 0))
    }

    /// Fill `out` with random bytes.
    ///
    /// Used for HLS challenges and ephemeral keys. A provider that cannot produce
    /// randomness must fail rather than return anything predictable.
    ///
    /// # Errors
    /// When no entropy source is available.
    fn random(&self, out: &mut [u8]) -> Result<()>;

    /// The **bytes** of the authentication key.
    ///
    /// This is the one key the protocol needs as data rather than as a key: DLMS feeds
    /// `SC ‖ AK ‖ …` into GCM's additional authenticated data, so a stack that cannot
    /// read the authentication key cannot form the AAD at all — no arrangement of traits
    /// changes that, and pretending otherwise would mean a secure-element provider that
    /// silently authenticated the wrong bytes. Every other key stays behind
    /// [`keys::KeyRef`] and never leaves the provider.
    ///
    /// `None` when the provider holds none, which is right only for an association with
    /// no protection.
    fn authentication_key(&self) -> Option<&[u8]>;

    /// The dedicated key this end offers in its `InitiateRequest`, if the caller
    /// configured one.
    ///
    /// A client that returns `Some` here proposes a dedicated association; a server
    /// never offers one and may leave this at the default.
    fn dedicated_key(&self) -> Option<&[u8]> {
        None
    }

    /// Install the dedicated key an association just negotiated.
    ///
    /// The server calls this when a client delivers one inside the ciphered
    /// `InitiateRequest`. A provider that cannot hold one refuses, and the association
    /// then continues on the global key set rather than failing every message.
    ///
    /// # Errors
    /// [`ErrorKind::Unsupported`] when this provider cannot hold a dedicated key.
    fn set_dedicated_key(&mut self, _key: keys::Key) -> Result<()> {
        Err(Error::new(ErrorKind::Unsupported, 0))
    }

    /// Forget the dedicated key, so it cannot outlive the association that negotiated it.
    fn clear_dedicated_key(&mut self) {}
}
