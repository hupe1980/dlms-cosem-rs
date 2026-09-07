//! The protection wrappers: ciphered services, general ciphering and general signing.
//!
//! These types carry protected APDUs on the wire. They do no cryptography — see
//! [`crate::security`] for that — so a translator, a fuzzer and a server can all handle
//! a protected APDU without a key.

use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

/// The security control byte that introduces every protected APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityControl(pub u8);

impl SecurityControl {
    /// A control byte for a suite, with the chosen protection, on the unicast key set.
    #[must_use]
    pub const fn new(suite: u8, authenticated: bool, encrypted: bool) -> Self {
        let mut v = suite & 0x0F;
        if authenticated {
            v |= 0x10;
        }
        if encrypted {
            v |= 0x20;
        }
        Self(v)
    }

    /// The same control byte with the broadcast-key bit set or cleared.
    ///
    /// The bit selects which key set opens the frame, so it is part of what a receiver
    /// *demands* rather than something it reads off the wire — see
    /// [`crate::security::SecurityPolicy::broadcast`].
    #[must_use]
    pub const fn with_broadcast(self, broadcast: bool) -> Self {
        Self(if broadcast { self.0 | 0x40 } else { self.0 & !0x40 })
    }

    /// The security suite id, 0–2.
    #[must_use]
    pub const fn suite(self) -> u8 {
        self.0 & 0x0F
    }

    /// True when an authentication tag is appended.
    #[must_use]
    pub const fn authenticated(self) -> bool {
        self.0 & 0x10 != 0
    }

    /// True when the payload is encrypted.
    #[must_use]
    pub const fn encrypted(self) -> bool {
        self.0 & 0x20 != 0
    }

    /// True when the broadcast key set is used instead of the unicast one.
    #[must_use]
    pub const fn broadcast_key(self) -> bool {
        self.0 & 0x40 != 0
    }

    /// True when the payload is compressed.
    ///
    /// This crate reports compression and never performs it: a frame that needs it
    /// fails by name rather than being decoded into nonsense.
    #[must_use]
    pub const fn compressed(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// True when no protection at all is applied.
    #[must_use]
    pub const fn is_plain(self) -> bool {
        !self.authenticated() && !self.encrypted()
    }
}

/// A protected service APDU: the body of a `glo-` or `ded-` tagged APDU.
///
/// The `payload` is what the cipher produced: for authenticated-and-encrypted it is the
/// ciphertext followed by the twelve-byte tag; for authenticated-only it is the
/// plaintext followed by the tag; for neither it is the plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipheredService<'a> {
    /// What protection was applied.
    pub security_control: SecurityControl,
    /// The sender's frame counter, which forms the second half of the nonce.
    pub invocation_counter: u32,
    /// The protected bytes.
    pub payload: &'a [u8],
}

impl Encode for CipheredService<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_length(5 + self.payload.len())?;
        w.write_u8(self.security_control.0)?;
        w.write_u32(self.invocation_counter)?;
        w.write_bytes(self.payload)
    }
}

impl<'a> Decode<'a> for CipheredService<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let body = r.length_prefixed()?;
        let mut br = Reader::with_base(body, r.offset() - body.len());
        Ok(Self {
            security_control: SecurityControl(br.u8()?),
            invocation_counter: br.u32()?,
            payload: br.take_rest(),
        })
    }
}

/// A protected APDU that names the system title it came from.
///
/// `general-glo-ciphering` and `general-ded-ciphering` differ only in which key the
/// receiver looks up, which is why they share this type and are told apart by the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralGloCiphering<'a> {
    /// The originator's system title — how a listener finds the key.
    pub system_title: &'a [u8],
    /// The protected service.
    pub ciphered: CipheredService<'a>,
}

impl Encode for GeneralGloCiphering<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_length_prefixed(self.system_title)?;
        self.ciphered.encode(w)
    }
}

impl<'a> Decode<'a> for GeneralGloCiphering<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { system_title: r.length_prefixed()?, ciphered: CipheredService::decode(r)? })
    }
}

/// Which key protected a `general-ciphering` APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInfo<'a> {
    /// A key both sides already hold, named by id.
    Identified {
        /// 0 for the global unicast key, 1 for the global broadcast key.
        key_id: u8,
    },
    /// A key delivered with the message, wrapped under a key-encrypting key.
    Wrapped {
        /// Which key-encrypting key unwraps it. `0` is the master key, and is the only
        /// value the standard defines — this is a *kek* id, not the id of the key being
        /// delivered, which the ASN.1 makes plain and which is easy to read the other
        /// way round.
        kek_id: u8,
        /// The wrapped key.
        ciphered_key: &'a [u8],
    },
    /// A key derived by agreement, with the parameters that derived it.
    Agreed {
        /// The key agreement parameters.
        parameters: &'a [u8],
        /// The data the agreement produced.
        ciphered_key: &'a [u8],
    },
}

impl Encode for KeyInfo<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Identified { key_id } => w.write_bytes(&[0, *key_id]),
            Self::Wrapped { kek_id, ciphered_key } => {
                w.write_bytes(&[1, *kek_id])?;
                w.write_length_prefixed(ciphered_key)
            }
            Self::Agreed { parameters, ciphered_key } => {
                w.write_u8(2)?;
                w.write_length_prefixed(parameters)?;
                w.write_length_prefixed(ciphered_key)
            }
        }
    }
}

impl<'a> Decode<'a> for KeyInfo<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(match r.u8()? {
            0 => Self::Identified { key_id: r.u8()? },
            1 => Self::Wrapped { kek_id: r.u8()?, ciphered_key: r.length_prefixed()? },
            2 => Self::Agreed { parameters: r.length_prefixed()?, ciphered_key: r.length_prefixed()? },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        })
    }
}

/// A protected APDU that carries everything a third party needs to check it.
///
/// Unlike `glo-`/`ded-` ciphering, `general-ciphering` names both ends, may carry the
/// key, and may travel end to end across intermediaries that cannot read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralCiphering<'a> {
    /// Correlates a request with its response across a third party.
    pub transaction_id: &'a [u8],
    /// Who protected it.
    pub originator_system_title: &'a [u8],
    /// Who may unprotect it.
    pub recipient_system_title: &'a [u8],
    /// When, as raw octets — empty when absent.
    pub date_time: &'a [u8],
    /// Anything else the profile puts here.
    pub other_information: &'a [u8],
    /// Which key, when the message says.
    pub key_info: Option<KeyInfo<'a>>,
    /// The protected service.
    pub ciphered: CipheredService<'a>,
}

impl Encode for GeneralCiphering<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_length_prefixed(self.transaction_id)?;
        w.write_length_prefixed(self.originator_system_title)?;
        w.write_length_prefixed(self.recipient_system_title)?;
        w.write_length_prefixed(self.date_time)?;
        w.write_length_prefixed(self.other_information)?;
        match &self.key_info {
            None => w.write_u8(0)?,
            Some(k) => {
                w.write_u8(1)?;
                k.encode(w)?;
            }
        }
        self.ciphered.encode(w)
    }
}

impl<'a> Decode<'a> for GeneralCiphering<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            transaction_id: r.length_prefixed()?,
            originator_system_title: r.length_prefixed()?,
            recipient_system_title: r.length_prefixed()?,
            date_time: r.length_prefixed()?,
            other_information: r.length_prefixed()?,
            key_info: if r.u8()? == 0 { None } else { Some(KeyInfo::decode(r)?) },
            ciphered: CipheredService::decode(r)?,
        })
    }
}

/// A signed APDU: proof of origin that survives an intermediary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralSigning<'a> {
    /// Correlates a request with its response.
    pub transaction_id: &'a [u8],
    /// Who signed.
    pub originator_system_title: &'a [u8],
    /// Who it is for.
    pub recipient_system_title: &'a [u8],
    /// When, as raw octets — empty when absent.
    pub date_time: &'a [u8],
    /// Anything else the profile puts here.
    pub other_information: &'a [u8],
    /// The signed APDU, itself possibly ciphered.
    pub content: &'a [u8],
    /// The signature over everything before it.
    pub signature: &'a [u8],
}

impl Encode for GeneralSigning<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_length_prefixed(self.transaction_id)?;
        w.write_length_prefixed(self.originator_system_title)?;
        w.write_length_prefixed(self.recipient_system_title)?;
        w.write_length_prefixed(self.date_time)?;
        w.write_length_prefixed(self.other_information)?;
        w.write_length_prefixed(self.content)?;
        w.write_length_prefixed(self.signature)
    }
}

impl<'a> Decode<'a> for GeneralSigning<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            transaction_id: r.length_prefixed()?,
            originator_system_title: r.length_prefixed()?,
            recipient_system_title: r.length_prefixed()?,
            date_time: r.length_prefixed()?,
            other_information: r.length_prefixed()?,
            content: r.length_prefixed()?,
            signature: r.length_prefixed()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn security_control_bits() {
        let sc = SecurityControl::new(1, true, true);
        assert_eq!(sc.suite(), 1);
        assert!(sc.authenticated() && sc.encrypted());
        assert!(!sc.broadcast_key() && !sc.compressed());
        assert_eq!(sc.0, 0x31);
        assert!(SecurityControl(0x00).is_plain());
        assert!(SecurityControl(0x80).compressed());
        assert!(SecurityControl(0x40).broadcast_key());
    }

    #[test]
    fn a_ciphered_service_round_trips() {
        let c = CipheredService {
            security_control: SecurityControl::new(0, true, true),
            invocation_counter: 0x0000_0001,
            payload: &[0xAA, 0xBB, 0xCC],
        };
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        c.encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x08, 0x30, 0, 0, 0, 1, 0xAA, 0xBB, 0xCC]);
        assert_eq!(CipheredService::from_bytes(w.as_slice()).unwrap(), c);
    }

    #[test]
    fn general_glo_ciphering_names_the_originator() {
        let g = GeneralGloCiphering {
            system_title: b"MMM\x00\x00\xbcaN",
            ciphered: CipheredService {
                security_control: SecurityControl::new(0, true, true),
                invocation_counter: 5,
                payload: &[0x01],
            },
        };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        g.encode(&mut w).unwrap();
        assert_eq!(w.as_slice()[0], 8, "system title is length-prefixed");
        assert_eq!(GeneralGloCiphering::from_bytes(w.as_slice()).unwrap(), g);
    }

    #[test]
    fn key_info_variants_round_trip() {
        for k in [
            KeyInfo::Identified { key_id: 0 },
            KeyInfo::Wrapped { kek_id: 0, ciphered_key: &[1, 2, 3] },
            KeyInfo::Agreed { parameters: &[9], ciphered_key: &[8, 7] },
        ] {
            let mut buf = [0u8; 32];
            let mut w = SliceWriter::new(&mut buf);
            k.encode(&mut w).unwrap();
            assert_eq!(KeyInfo::from_bytes(w.as_slice()).unwrap(), k);
        }
    }
}
