//! The default [`CryptoProvider`], built on RustCrypto.

use aes::cipher::BlockEncrypt;
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aes::cipher::consts::U12;
use aes_gcm::{AesGcm, KeyInit};
use ghash::universal_hash::UniversalHash;

use crate::codec::{Error, ErrorKind, Result};

use super::keys::{KeyRef, KeyRing, KeyUsage};
use super::{CryptoProvider, SecuritySuite};

/// AES-128-GCM with the 96-bit nonce and 96-bit tag DLMS uses.
type Aes128Gcm96 = AesGcm<Aes128, U12, U12>;
/// AES-256-GCM with the same nonce and tag lengths, for suite 2.
type Aes256Gcm96 = AesGcm<Aes256, U12, U12>;

/// Keys in this process's memory, zeroised on drop.
///
/// Suitable for a head-end and for tests. On a meter, a provider backed by a secure
/// element keeps the key out of the application core entirely; that is the reason
/// [`CryptoProvider`] is a trait.
#[derive(Debug, Default)]
pub struct RustCryptoProvider<R = ()> {
    keys: KeyRing,
    rng: R,
}

impl RustCryptoProvider<()> {
    /// A provider over `keys` with no randomness source.
    ///
    /// [`CryptoProvider::random`] fails, so this cannot be used to generate an HLS
    /// challenge — deliberately, because a challenge from a predictable source is worse
    /// than no challenge.
    #[must_use]
    pub const fn new(keys: KeyRing) -> Self {
        Self { keys, rng: () }
    }
}

impl<R> RustCryptoProvider<R> {
    /// A provider over `keys` that draws randomness from `rng`.
    pub const fn with_rng(keys: KeyRing, rng: R) -> Self {
        Self { keys, rng }
    }

    /// The keys.
    pub const fn keys(&self) -> &KeyRing {
        &self.keys
    }

    /// The keys, mutably — for installing a dedicated key mid-association.
    pub const fn keys_mut(&mut self) -> &mut KeyRing {
        &mut self.keys
    }

    fn resolve<'k>(&'k self, key: KeyRef<'k>) -> Result<&'k [u8]> {
        match key {
            KeyRef::Raw(b) => Ok(b),
            KeyRef::Usage(u) => self.keys.get(u).ok_or_else(|| Error::new(ErrorKind::Unsupported, 0)),
        }
    }
}

fn tag_to_array(t: &[u8]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&t[..12]);
    out
}

impl<R: RandomSource> CryptoProvider for RustCryptoProvider<R> {
    fn aead_seal(
        &self,
        key: KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 12]> {
        let k = self.resolve(key)?;
        let nonce = &aes_gcm::Nonce::<U12>::from(*nonce);
        let tag = if suite == SecuritySuite::Suite2 {
            if k.len() != 32 {
                return Err(Error::new(ErrorKind::Unsupported, 0));
            }
            let c = Aes256Gcm96::new_from_slice(k).map_err(|_| Error::new(ErrorKind::Unsupported, 0))?;
            c.encrypt_in_place_detached(nonce, aad, buf).map_err(|_| Error::new(ErrorKind::Unsupported, 0))?
        } else {
            if k.len() != 16 {
                return Err(Error::new(ErrorKind::Unsupported, 0));
            }
            let c = Aes128Gcm96::new_from_slice(k).map_err(|_| Error::new(ErrorKind::Unsupported, 0))?;
            c.encrypt_in_place_detached(nonce, aad, buf).map_err(|_| Error::new(ErrorKind::Unsupported, 0))?
        };
        Ok(tag_to_array(&tag))
    }

    fn aead_open(
        &self,
        key: KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 12],
    ) -> Result<()> {
        let k = self.resolve(key)?;
        let nonce = &aes_gcm::Nonce::<U12>::from(*nonce);
        let tag = &aes_gcm::Tag::<U12>::from(*tag);
        let ok = if suite == SecuritySuite::Suite2 {
            if k.len() != 32 {
                return Err(Error::new(ErrorKind::Unsupported, 0));
            }
            let c = Aes256Gcm96::new_from_slice(k).map_err(|_| Error::new(ErrorKind::Unsupported, 0))?;
            c.decrypt_in_place_detached(nonce, aad, buf, tag).is_ok()
        } else {
            if k.len() != 16 {
                return Err(Error::new(ErrorKind::Unsupported, 0));
            }
            let c = Aes128Gcm96::new_from_slice(k).map_err(|_| Error::new(ErrorKind::Unsupported, 0))?;
            c.decrypt_in_place_detached(nonce, aad, buf, tag).is_ok()
        };
        if ok { Ok(()) } else { Err(Error::new(ErrorKind::BadTag, 0)) }
    }

    fn key_wrap(&self, kek: KeyRef<'_>, key: &[u8], out: &mut [u8]) -> Result<usize> {
        let k = self.resolve(kek)?;
        let kek: [u8; 16] = k.try_into().map_err(|_| Error::new(ErrorKind::Unsupported, 0))?;
        let n = key.len() + 8;
        if out.len() < n {
            return Err(Error::new(ErrorKind::BufferTooSmall { needed: n - out.len() }, 0));
        }
        aes_kw::KekAes128::from(kek)
            .wrap(key, &mut out[..n])
            .map_err(|_| Error::new(ErrorKind::InvalidLength, 0))?;
        Ok(n)
    }

    fn key_unwrap(&self, kek: KeyRef<'_>, wrapped: &[u8], out: &mut [u8]) -> Result<usize> {
        let k = self.resolve(kek)?;
        let kek: [u8; 16] = k.try_into().map_err(|_| Error::new(ErrorKind::Unsupported, 0))?;
        let n = wrapped.len().checked_sub(8).ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0))?;
        if out.len() < n {
            return Err(Error::new(ErrorKind::BufferTooSmall { needed: n - out.len() }, 0));
        }
        aes_kw::KekAes128::from(kek)
            .unwrap(wrapped, &mut out[..n])
            .map_err(|_| Error::new(ErrorKind::BadTag, 0))?;
        Ok(n)
    }

    fn gmac(
        &self,
        key: KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[&[u8]],
    ) -> Result<[u8; 12]> {
        let k = self.resolve(key)?;
        if k.len() != suite.key_len() {
            return Err(Error::new(ErrorKind::Unsupported, 0));
        }
        // GMAC is GCM with an empty plaintext, so the tag is
        // `GHASH_H(A ‖ pad ‖ len(A) ‖ 0) ⊕ AES_K(IV ‖ 0x00000001)`. Running GHASH
        // directly is what lets the additional data arrive in pieces: the segments are
        // absorbed one after another with no buffer standing between them, so the
        // authenticated-only mode has no size limit beyond the APDU itself.
        let mut hash_subkey = [0u8; 16];
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(nonce);
        counter_block[15] = 1;
        encrypt_block(k, suite, &mut hash_subkey)?;
        encrypt_block(k, suite, &mut counter_block)?;

        let mut ghash = ghash::GHash::new(&hash_subkey.into());
        // Segment boundaries have nothing to do with block boundaries, so a partial
        // block is carried across them.
        let mut pending = [0u8; 16];
        let mut pending_len = 0usize;
        let mut total: u64 = 0;
        for segment in aad {
            total = total
                .checked_add(segment.len() as u64)
                .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0))?;
            let mut rest = *segment;
            while !rest.is_empty() {
                if pending_len == 0 && rest.len() >= 16 {
                    // Aligned and long enough: absorb whole blocks with no copy.
                    let whole = rest.len() / 16 * 16;
                    for block in rest[..whole].chunks_exact(16) {
                        let mut b = [0u8; 16];
                        b.copy_from_slice(block);
                        ghash.update(&[b.into()]);
                    }
                    rest = &rest[whole..];
                } else {
                    let take = rest.len().min(16 - pending_len);
                    pending[pending_len..pending_len + take].copy_from_slice(&rest[..take]);
                    pending_len += take;
                    rest = &rest[take..];
                    if pending_len == 16 {
                        ghash.update(&[pending.into()]);
                        pending_len = 0;
                    }
                }
            }
        }
        if pending_len > 0 {
            pending[pending_len..].fill(0);
            ghash.update(&[pending.into()]);
        }
        // The trailing length block: the bit length of the additional data, then the
        // bit length of the ciphertext, which for a GMAC is zero.
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&total.wrapping_mul(8).to_be_bytes());
        ghash.update(&[lengths.into()]);

        let s = ghash.finalize();
        let mut tag = [0u8; 12];
        for (i, t) in tag.iter_mut().enumerate() {
            *t = s[i] ^ counter_block[i];
        }
        Ok(tag)
    }

    fn random(&self, out: &mut [u8]) -> Result<()> {
        self.rng.fill(out)
    }

    fn authentication_key(&self) -> Option<&[u8]> {
        self.keys.get(KeyUsage::Authentication)
    }

    fn dedicated_key(&self) -> Option<&[u8]> {
        self.keys.get(KeyUsage::Dedicated)
    }

    fn set_dedicated_key(&mut self, key: super::keys::Key) -> Result<()> {
        self.keys.set_dedicated(key);
        Ok(())
    }

    fn clear_dedicated_key(&mut self) {
        self.keys.clear_dedicated();
    }
}

/// Encrypt one block in place with the suite's block cipher.
fn encrypt_block(key: &[u8], suite: SecuritySuite, block: &mut [u8; 16]) -> Result<()> {
    let bad = || Error::new(ErrorKind::Unsupported, 0);
    if suite == SecuritySuite::Suite2 {
        Aes256::new_from_slice(key).map_err(|_| bad())?.encrypt_block(block.into());
    } else {
        Aes128::new_from_slice(key).map_err(|_| bad())?.encrypt_block(block.into());
    }
    Ok(())
}

/// Where a provider gets randomness.
///
/// A separate trait so a provider can exist without one — a decode-only listener needs
/// no entropy — and so an embedded caller can wire in a hardware generator.
pub trait RandomSource {
    /// Fill `out` with random bytes.
    ///
    /// # Errors
    /// When no entropy is available. Returning predictable bytes is never acceptable.
    fn fill(&self, out: &mut [u8]) -> Result<()>;
}

impl RandomSource for () {
    fn fill(&self, _out: &mut [u8]) -> Result<()> {
        Err(Error::new(ErrorKind::Unsupported, 0))
    }
}

/// A fixed byte sequence, for tests that need a *reproducible* challenge.
///
/// Never use this for anything that faces a network: a predictable challenge lets a
/// replayed HLS response authenticate.
#[derive(Debug, Clone, Copy)]
pub struct FixedRandom(pub u8);

impl RandomSource for FixedRandom {
    fn fill(&self, out: &mut [u8]) -> Result<()> {
        out.fill(self.0);
        Ok(())
    }
}

impl KeyUsage {
    /// The key id used by `general-ciphering`'s identified-key form.
    #[must_use]
    pub const fn key_id(self) -> Option<u8> {
        match self {
            Self::GlobalUnicastEncryption => Some(0),
            Self::GlobalBroadcastEncryption => Some(1),
            Self::Authentication => Some(2),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use hex_literal::hex;

    /// NIST SP 800-38D test case 3 — AES-128-GCM with a 64-byte plaintext and no
    /// additional data, computed by a body that has never heard of DLMS. If this
    /// passes, the cipher underneath is right and everything else is framing.
    #[test]
    fn nist_gcm_test_case_3() {
        let key = hex!("feffe9928665731c6d6a8f9467308308");
        let mut buf = hex!(
            "d9313225f88406e5a55909c5aff5269a
             86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525
             b16aedf5aa0de657ba637b391aafd255"
        );
        let nonce = hex!("cafebabefacedbaddecaf888");
        let provider = RustCryptoProvider::new(KeyRing::default());
        let tag =
            provider.aead_seal(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &[], &mut buf).unwrap();
        assert_eq!(
            buf,
            hex!(
                "42831ec2217774244b7221b784d0d49c
                 e3aa212f2c02a4e035c17e2329aca12e
                 21d514b25466931c7d8f6a5aac84aa05
                 1ba30b396a0aac973d58e091473f5985"
            )
        );
        // The published tag is 4d5c2af327cd64a62cf35abd2ba6fab4; DLMS keeps its
        // leftmost 96 bits, which is what GCM's own truncation rule prescribes.
        assert_eq!(tag, hex!("4d5c2af327cd64a62cf35abd"));
    }

    /// NIST SP 800-38D test case 4 — the same key with additional authenticated data,
    /// which is the shape every DLMS APDU uses.
    #[test]
    fn nist_gcm_test_case_4_exercises_the_additional_data_path() {
        let key = hex!("feffe9928665731c6d6a8f9467308308");
        let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut buf = hex!(
            "d9313225f88406e5a55909c5aff5269a
             86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525
             b16aedf5aa0de657ba637b39"
        );
        let nonce = hex!("cafebabefacedbaddecaf888");
        let provider = RustCryptoProvider::new(KeyRing::default());
        let tag =
            provider.aead_seal(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(tag, hex!("5bc94fbc3221a5db94fae95a"));

        // And the same inputs with an empty plaintext are a GMAC, which is what
        // authentication-only protection and HLS mechanism 5 compute.
        let mut empty: [u8; 0] = [];
        let mac =
            provider.aead_seal(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &aad, &mut empty).unwrap();
        assert_eq!(mac, hex!("346434fd51d5cd0c5887ec63"));
        assert_eq!(
            provider.gmac(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &[&aad[..]]).unwrap(),
            mac,
            "gmac() must agree with sealing an empty buffer"
        );
    }

    /// The tag must depend only on the bytes, never on where the caller happened to cut
    /// them — that is the whole premise of taking segments.
    #[test]
    fn a_gmac_is_the_same_however_the_additional_data_is_split() {
        let key = hex!("feffe9928665731c6d6a8f9467308308");
        let nonce = hex!("cafebabefacedbaddecaf888");
        let provider = RustCryptoProvider::new(KeyRing::default());
        // Long enough to cross many block boundaries, and a prime length so no split
        // lands where another does.
        let data: Vec<u8> = (0..1021u32).map(|i| (i % 251) as u8).collect();

        let whole = provider.gmac(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &[&data]).unwrap();
        for cut in [0usize, 1, 15, 16, 17, 31, 33, 512, 1020, 1021] {
            let (a, b) = data.split_at(cut);
            let split = provider.gmac(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &[a, b]).unwrap();
            assert_eq!(split, whole, "a cut at {cut} changed the tag");
        }
        // Three segments, the shape authentication-only protection actually uses.
        let (a, rest) = data.split_at(1);
        let (b, c) = rest.split_at(16);
        assert_eq!(
            provider.gmac(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &[a, b, c]).unwrap(),
            whole
        );
        // And an empty segment must not disturb anything.
        assert_eq!(
            provider.gmac(KeyRef::Raw(&key), SecuritySuite::Suite0, &nonce, &[&[], &data, &[]]).unwrap(),
            whole
        );
    }

    /// The authenticated-only mode authenticates the whole APDU as additional data, so
    /// it must work at the sizes an APDU actually reaches.
    #[test]
    fn authentication_only_protection_has_no_size_ceiling() {
        use crate::security::{Protector, SecurityPolicy};
        let provider = RustCryptoProvider::new(KeyRing::new([0x11; 16], [0x22; 16]));
        let policy = SecurityPolicy {
            authenticated: true,
            encrypted: false,
            ..SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0)
        };
        let protector = Protector::new(provider, policy);
        let title = crate::security::SystemTitle::new(*b"MMM\0\0\0\0\x01");
        let auth_key = [0x22u8; 16];

        // 2 KiB is an ordinary negotiated PDU size; the old fixed 289-byte join refused
        // anything past roughly 256.
        let plain = vec![0xABu8; 2048];
        let mut out = vec![0u8; plain.len() + 12];
        let protected = protector.protect(&title, 1, &auth_key, &plain, &mut out).unwrap();
        assert_eq!(protected.len(), plain.len() + 12);

        let mut buf = protected.to_vec();
        let opened = protector
            .unprotect(policy.control(), &title, 1, &auth_key, &mut buf)
            .expect("what we protected must open");
        assert_eq!(opened, &plain[..]);
    }

    #[test]
    fn seal_and_open_are_inverses_and_a_flipped_bit_is_caught() {
        let provider = RustCryptoProvider::new(KeyRing::new([0x11; 16], [0x22; 16]));
        let nonce = [7u8; 12];
        let aad = [0x30u8, 0x22];
        let mut buf = *b"get-response";
        let tag = provider
            .aead_seal(
                KeyUsage::GlobalUnicastEncryption.into(),
                SecuritySuite::Suite0,
                &nonce,
                &aad,
                &mut buf,
            )
            .unwrap();
        assert_ne!(&buf[..], b"get-response");
        let mut copy = buf;
        provider
            .aead_open(
                KeyUsage::GlobalUnicastEncryption.into(),
                SecuritySuite::Suite0,
                &nonce,
                &aad,
                &mut copy,
                &tag,
            )
            .unwrap();
        assert_eq!(&copy[..], b"get-response");

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut copy = buf;
        assert_eq!(
            provider
                .aead_open(
                    KeyUsage::GlobalUnicastEncryption.into(),
                    SecuritySuite::Suite0,
                    &nonce,
                    &aad,
                    &mut copy,
                    &bad_tag
                )
                .unwrap_err()
                .kind,
            ErrorKind::BadTag
        );
    }

    #[test]
    fn changing_the_additional_data_invalidates_the_tag() {
        let provider = RustCryptoProvider::new(KeyRing::new([0x11; 16], [0x22; 16]));
        let nonce = [7u8; 12];
        let mut buf = *b"hello";
        let tag = provider
            .aead_seal(
                KeyUsage::GlobalUnicastEncryption.into(),
                SecuritySuite::Suite0,
                &nonce,
                &[0x30],
                &mut buf,
            )
            .unwrap();
        let mut copy = buf;
        assert!(
            provider
                .aead_open(
                    KeyUsage::GlobalUnicastEncryption.into(),
                    SecuritySuite::Suite0,
                    &nonce,
                    &[0x31],
                    &mut copy,
                    &tag
                )
                .is_err()
        );
    }

    /// RFC 3394 section 4.1: wrapping a 128-bit key with a 128-bit KEK.
    #[test]
    fn rfc3394_key_wrap() {
        let provider = RustCryptoProvider::new(KeyRing::default());
        let kek = hex!("000102030405060708090A0B0C0D0E0F");
        let key = hex!("00112233445566778899AABBCCDDEEFF");
        let mut out = [0u8; 24];
        let n = provider.key_wrap(KeyRef::Raw(&kek), &key, &mut out).unwrap();
        assert_eq!(n, 24);
        assert_eq!(out, hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"));
        let mut back = [0u8; 16];
        let n = provider.key_unwrap(KeyRef::Raw(&kek), &out, &mut back).unwrap();
        assert_eq!(n, 16);
        assert_eq!(back, key);
    }

    #[test]
    fn a_corrupted_wrapped_key_does_not_unwrap() {
        let provider = RustCryptoProvider::new(KeyRing::default());
        let kek = hex!("000102030405060708090A0B0C0D0E0F");
        let mut wrapped = hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        wrapped[3] ^= 0x80;
        let mut back = [0u8; 16];
        assert_eq!(
            provider.key_unwrap(KeyRef::Raw(&kek), &wrapped, &mut back).unwrap_err().kind,
            ErrorKind::BadTag
        );
    }

    #[test]
    fn a_provider_without_entropy_refuses_to_invent_it() {
        let provider = RustCryptoProvider::new(KeyRing::default());
        let mut challenge = [0u8; 16];
        assert_eq!(provider.random(&mut challenge).unwrap_err().kind, ErrorKind::Unsupported);
    }
}
