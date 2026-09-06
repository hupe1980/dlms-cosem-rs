//! ACSE — establishing and releasing an application association.
//!
//! The AARQ/AARE exchange decides four things at once: which application context (so,
//! whether the association is ciphered and whether it uses logical or short names),
//! which authentication mechanism, what each side's system title is, and — inside the
//! user-information field, in A-XDR — what services and PDU sizes both sides accept.
//!
//! Get any one of those wrong and the association still opens, then fails later in a
//! way that looks like a different bug. So each is a typed field here, and an unknown
//! value is preserved rather than defaulted.

use crate::ber::{Tlv, iter_tlv, read_tlv, write_constructed, write_tlv};
use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, Writer};

/// The object identifier prefix all DLMS context and mechanism names share:
/// `2.16.756.5.8` — joint-iso-itu-t(2) country(16) ch(756) dlms-ua(5).
const OID_PREFIX: [u8; 5] = [0x60, 0x85, 0x74, 0x05, 0x08];

/// Which naming and protection the association uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationContext {
    /// Logical-name referencing, no ciphering.
    LogicalName,
    /// Short-name referencing, no ciphering.
    ShortName,
    /// Logical-name referencing with ciphering.
    LogicalNameCiphered,
    /// Short-name referencing with ciphering.
    ShortNameCiphered,
    /// A context this crate does not know, kept so the refusal can name it.
    Other(u8),
}

impl ApplicationContext {
    /// The final arc of the object identifier.
    #[must_use]
    pub const fn arc(self) -> u8 {
        match self {
            Self::LogicalName => 1,
            Self::ShortName => 2,
            Self::LogicalNameCiphered => 3,
            Self::ShortNameCiphered => 4,
            Self::Other(v) => v,
        }
    }

    /// From the final arc.
    #[must_use]
    pub const fn from_arc(v: u8) -> Self {
        match v {
            1 => Self::LogicalName,
            2 => Self::ShortName,
            3 => Self::LogicalNameCiphered,
            4 => Self::ShortNameCiphered,
            other => Self::Other(other),
        }
    }

    /// True when the association protects its APDUs.
    #[must_use]
    pub const fn is_ciphered(self) -> bool {
        matches!(self, Self::LogicalNameCiphered | Self::ShortNameCiphered)
    }

    /// True when objects are addressed by logical name.
    #[must_use]
    pub const fn is_logical_name(self) -> bool {
        matches!(self, Self::LogicalName | Self::LogicalNameCiphered)
    }

    /// The same context with ciphering switched on or off.
    #[must_use]
    pub const fn with_ciphering(self, ciphered: bool) -> Self {
        match (self.is_logical_name(), ciphered) {
            (true, false) => Self::LogicalName,
            (true, true) => Self::LogicalNameCiphered,
            (false, false) => Self::ShortName,
            (false, true) => Self::ShortNameCiphered,
        }
    }
}

/// How the client proves who it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    /// No authentication. The public client.
    None,
    /// Low level security: the password is sent in the AARQ.
    Low,
    /// High level security, manufacturer-specific. Not implemented by this crate.
    HighManufacturer,
    /// High level security using MD5. Obsolete.
    HighMd5,
    /// High level security using SHA-1. Obsolete.
    HighSha1,
    /// High level security using GMAC — the mechanism in general use.
    HighGmac,
    /// High level security using SHA-256.
    HighSha256,
    /// High level security using ECDSA.
    HighEcdsa,
    /// A mechanism this crate does not know.
    Other(u8),
}

impl AuthMechanism {
    /// The final arc of the object identifier.
    #[must_use]
    pub const fn arc(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Low => 1,
            Self::HighManufacturer => 2,
            Self::HighMd5 => 3,
            Self::HighSha1 => 4,
            Self::HighGmac => 5,
            Self::HighSha256 => 6,
            Self::HighEcdsa => 7,
            Self::Other(v) => v,
        }
    }

    /// From the final arc.
    #[must_use]
    pub const fn from_arc(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Low,
            2 => Self::HighManufacturer,
            3 => Self::HighMd5,
            4 => Self::HighSha1,
            5 => Self::HighGmac,
            6 => Self::HighSha256,
            7 => Self::HighEcdsa,
            other => Self::Other(other),
        }
    }

    /// True when the mechanism needs the two extra passes that exchange challenges.
    #[must_use]
    pub const fn is_high_level(self) -> bool {
        !matches!(self, Self::None | Self::Low)
    }
}

/// Whether the server accepted the association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationResult {
    /// Accepted.
    Accepted,
    /// Refused, and asking again will not help.
    RejectedPermanent,
    /// Refused for now.
    RejectedTransient,
    /// A value this crate does not know.
    Other(u8),
}

impl AssociationResult {
    /// From the wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Accepted,
            1 => Self::RejectedPermanent,
            2 => Self::RejectedTransient,
            other => Self::Other(other),
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::RejectedPermanent => 1,
            Self::RejectedTransient => 2,
            Self::Other(v) => v,
        }
    }
}

/// Why the server answered as it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Diagnostic {
    /// Attributed to the peer application.
    User(UserDiagnostic),
    /// Attributed to the association-control service itself.
    Provider(u8),
}

/// The `acse-service-user` diagnostics that matter in DLMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserDiagnostic {
    /// No diagnostic; the association was accepted.
    Null,
    /// No reason given.
    NoReasonGiven,
    /// The proposed application context is not supported — usually a client asking for
    /// ciphering from a meter that has none, or short names from a logical-name meter.
    ApplicationContextNameNotSupported,
    /// The mechanism name is not one the server knows.
    AuthenticationMechanismNameNotRecognised,
    /// The server requires a mechanism name and none was offered.
    AuthenticationMechanismNameRequired,
    /// The credentials were wrong.
    AuthenticationFailure,
    /// The server requires authentication for this association.
    AuthenticationRequired,
    /// A value this crate does not name.
    Other(u8),
}

impl UserDiagnostic {
    /// From the wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::NoReasonGiven,
            2 => Self::ApplicationContextNameNotSupported,
            11 => Self::AuthenticationMechanismNameNotRecognised,
            12 => Self::AuthenticationMechanismNameRequired,
            13 => Self::AuthenticationFailure,
            14 => Self::AuthenticationRequired,
            other => Self::Other(other),
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::NoReasonGiven => 1,
            Self::ApplicationContextNameNotSupported => 2,
            Self::AuthenticationMechanismNameNotRecognised => 11,
            Self::AuthenticationMechanismNameRequired => 12,
            Self::AuthenticationFailure => 13,
            Self::AuthenticationRequired => 14,
            Self::Other(v) => v,
        }
    }
}

/// Why an association is being released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseReason {
    /// The client is finished.
    Normal,
    /// The client wants the association released urgently.
    Urgent,
    /// The client is not saying.
    UserDefined,
    /// A value this crate does not know.
    Other(u8),
}

impl ReleaseReason {
    /// From the wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Normal,
            1 => Self::Urgent,
            30 => Self::UserDefined,
            other => Self::Other(other),
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Urgent => 1,
            Self::UserDefined => 30,
            Self::Other(v) => v,
        }
    }
}

/// The client's association request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Aarq<'a> {
    /// Which naming and protection.
    pub application_context: Option<ApplicationContext>,
    /// The server's system title, when the client names it.
    pub called_ap_title: Option<&'a [u8]>,
    /// The client's system title. Required for GMAC and for any ciphered context,
    /// because it is half of every nonce the client will use.
    pub calling_ap_title: Option<&'a [u8]>,
    /// A qualifier some profiles use to select a key set.
    pub calling_ae_qualifier: Option<&'a [u8]>,
    /// The ACSE requirements bit string; `0x0780` means "authentication used".
    pub sender_acse_requirements: bool,
    /// Which authentication mechanism.
    pub mechanism_name: Option<AuthMechanism>,
    /// The password for low level security, or the client's challenge for high level.
    pub calling_authentication_value: Option<&'a [u8]>,
    /// The xDLMS InitiateRequest, ciphered when the context says so.
    pub user_information: Option<&'a [u8]>,
}

impl Encode for Aarq<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        write_constructed(w, 0x60, |w| {
            if let Some(ctx) = self.application_context {
                write_constructed(w, 0xA1, |w| write_tlv(w, 0x06, &oid(1, ctx.arc())))?;
            }
            if let Some(t) = self.called_ap_title {
                write_constructed(w, 0xA2, |w| write_tlv(w, 0x04, t))?;
            }
            if let Some(t) = self.calling_ap_title {
                write_constructed(w, 0xA6, |w| write_tlv(w, 0x04, t))?;
            }
            if let Some(q) = self.calling_ae_qualifier {
                write_constructed(w, 0xA7, |w| write_tlv(w, 0x04, q))?;
            }
            if self.sender_acse_requirements {
                write_tlv(w, 0x8A, &[0x07, 0x80])?;
            }
            if let Some(m) = self.mechanism_name {
                write_tlv(w, 0x8B, &oid(2, m.arc()))?;
            }
            if let Some(v) = self.calling_authentication_value {
                write_constructed(w, 0xAC, |w| write_tlv(w, 0x80, v))?;
            }
            if let Some(u) = self.user_information {
                write_constructed(w, 0xBE, |w| write_tlv(w, 0x04, u))?;
            }
            Ok(())
        })
    }
}

impl<'a> Decode<'a> for Aarq<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let outer = read_tlv(r)?;
        if outer.tag != 0x60 {
            return Err(Error::new(ErrorKind::InvalidTag(outer.tag), outer.offset));
        }
        let mut out = Self::default();
        for tlv in iter_tlv(outer.value, outer.offset) {
            let tlv = tlv?;
            match tlv.context_number() {
                Some(1) => out.application_context = Some(ApplicationContext::from_arc(oid_arc(&tlv)?)),
                Some(2) => out.called_ap_title = Some(inner_octets(&tlv, 0x04)?),
                Some(6) => out.calling_ap_title = Some(inner_octets(&tlv, 0x04)?),
                Some(7) => out.calling_ae_qualifier = Some(inner_octets(&tlv, 0x04)?),
                Some(10) => out.sender_acse_requirements = authentication_bit(tlv.value),
                Some(11) => out.mechanism_name = Some(AuthMechanism::from_arc(implicit_oid_arc(&tlv)?)),
                Some(12) => out.calling_authentication_value = Some(inner_octets(&tlv, 0x80)?),
                Some(30) => out.user_information = Some(inner_octets(&tlv, 0x04)?),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The server's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aare<'a> {
    /// Which naming and protection the server agrees to.
    pub application_context: Option<ApplicationContext>,
    /// Accepted or refused.
    pub result: AssociationResult,
    /// Why.
    pub diagnostic: Diagnostic,
    /// The server's system title. Required for a ciphered association, because it is
    /// half of every nonce the server will use.
    pub responding_ap_title: Option<&'a [u8]>,
    /// The ACSE requirements bit string.
    pub responder_acse_requirements: bool,
    /// Which authentication mechanism the server will use.
    pub mechanism_name: Option<AuthMechanism>,
    /// The server's challenge for high level security.
    pub responding_authentication_value: Option<&'a [u8]>,
    /// The xDLMS InitiateResponse, or a ConfirmedServiceError when the association was
    /// refused for an xDLMS reason.
    pub user_information: Option<&'a [u8]>,
}

impl Default for Aare<'_> {
    fn default() -> Self {
        Self {
            application_context: None,
            result: AssociationResult::Accepted,
            diagnostic: Diagnostic::User(UserDiagnostic::Null),
            responding_ap_title: None,
            responder_acse_requirements: false,
            mechanism_name: None,
            responding_authentication_value: None,
            user_information: None,
        }
    }
}

impl Aare<'_> {
    /// True when the server accepted.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self.result, AssociationResult::Accepted)
    }
}

impl Encode for Aare<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        write_constructed(w, 0x61, |w| {
            if let Some(ctx) = self.application_context {
                write_constructed(w, 0xA1, |w| write_tlv(w, 0x06, &oid(1, ctx.arc())))?;
            }
            write_constructed(w, 0xA2, |w| write_tlv(w, 0x02, &[self.result.as_u8()]))?;
            write_constructed(w, 0xA3, |w| match self.diagnostic {
                Diagnostic::User(d) => write_constructed(w, 0xA1, |w| write_tlv(w, 0x02, &[d.as_u8()])),
                Diagnostic::Provider(d) => write_constructed(w, 0xA2, |w| write_tlv(w, 0x02, &[d])),
            })?;
            if let Some(t) = self.responding_ap_title {
                write_constructed(w, 0xA4, |w| write_tlv(w, 0x04, t))?;
            }
            if self.responder_acse_requirements {
                write_tlv(w, 0x88, &[0x07, 0x80])?;
            }
            if let Some(m) = self.mechanism_name {
                write_tlv(w, 0x89, &oid(2, m.arc()))?;
            }
            if let Some(v) = self.responding_authentication_value {
                write_constructed(w, 0xAA, |w| write_tlv(w, 0x80, v))?;
            }
            if let Some(u) = self.user_information {
                write_constructed(w, 0xBE, |w| write_tlv(w, 0x04, u))?;
            }
            Ok(())
        })
    }
}

impl<'a> Decode<'a> for Aare<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let outer = read_tlv(r)?;
        if outer.tag != 0x61 {
            return Err(Error::new(ErrorKind::InvalidTag(outer.tag), outer.offset));
        }
        let mut out = Self::default();
        for tlv in iter_tlv(outer.value, outer.offset) {
            let tlv = tlv?;
            match tlv.context_number() {
                Some(1) => out.application_context = Some(ApplicationContext::from_arc(oid_arc(&tlv)?)),
                Some(2) => {
                    let inner = read_tlv(&mut tlv.reader())?;
                    out.result = AssociationResult::from_u8(inner.as_u8()?);
                }
                Some(3) => {
                    let inner = read_tlv(&mut tlv.reader())?;
                    let value = read_tlv(&mut inner.reader())?.as_u8()?;
                    out.diagnostic = match inner.context_number() {
                        Some(1) => Diagnostic::User(UserDiagnostic::from_u8(value)),
                        _ => Diagnostic::Provider(value),
                    };
                }
                Some(4) => out.responding_ap_title = Some(inner_octets(&tlv, 0x04)?),
                Some(8) => out.responder_acse_requirements = authentication_bit(tlv.value),
                Some(9) => out.mechanism_name = Some(AuthMechanism::from_arc(implicit_oid_arc(&tlv)?)),
                Some(10) => out.responding_authentication_value = Some(inner_octets(&tlv, 0x80)?),
                Some(30) => out.user_information = Some(inner_octets(&tlv, 0x04)?),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The client asks to release the association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rlrq<'a> {
    /// Why, when given.
    pub reason: Option<ReleaseReason>,
    /// A ciphered InitiateRequest, when the profile requires the release to be
    /// protected too.
    pub user_information: Option<&'a [u8]>,
}

/// The server confirms the release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rlre<'a> {
    /// Why, when given.
    pub reason: Option<ReleaseReason>,
    /// A ciphered InitiateResponse, when the profile requires it.
    pub user_information: Option<&'a [u8]>,
}

macro_rules! release_codec {
    ($ty:ident, $tag:literal) => {
        impl Encode for $ty<'_> {
            fn encode(&self, w: &mut dyn Writer) -> Result<()> {
                write_constructed(w, $tag, |w| {
                    if let Some(reason) = self.reason {
                        write_tlv(w, 0x80, &[reason.as_u8()])?;
                    }
                    if let Some(u) = self.user_information {
                        write_constructed(w, 0xBE, |w| write_tlv(w, 0x04, u))?;
                    }
                    Ok(())
                })
            }
        }

        impl<'a> Decode<'a> for $ty<'a> {
            fn decode(r: &mut Reader<'a>) -> Result<Self> {
                let outer = read_tlv(r)?;
                if outer.tag != $tag {
                    return Err(Error::new(ErrorKind::InvalidTag(outer.tag), outer.offset));
                }
                let mut out = Self::default();
                for tlv in iter_tlv(outer.value, outer.offset) {
                    let tlv = tlv?;
                    match tlv.context_number() {
                        Some(0) => out.reason = Some(ReleaseReason::from_u8(tlv.as_u8()?)),
                        Some(30) => out.user_information = Some(inner_octets(&tlv, 0x04)?),
                        _ => {}
                    }
                }
                Ok(out)
            }
        }
    };
}

release_codec!(Rlrq, 0x62);
release_codec!(Rlre, 0x63);

/// `2.16.756.5.8.<branch>.<arc>` as BER contents.
fn oid(branch: u8, arc: u8) -> [u8; 7] {
    let mut out = [0u8; 7];
    out[..5].copy_from_slice(&OID_PREFIX);
    out[5] = branch;
    out[6] = arc;
    out
}

/// The final arc of an object identifier inside an explicitly tagged container.
fn oid_arc(tlv: &Tlv<'_>) -> Result<u8> {
    let inner = read_tlv(&mut tlv.reader())?;
    if inner.tag != 0x06 {
        return Err(Error::new(ErrorKind::InvalidTag(inner.tag), inner.offset));
    }
    check_oid_prefix(inner.value, inner.offset)
}

/// The final arc of an implicitly tagged object identifier.
fn implicit_oid_arc(tlv: &Tlv<'_>) -> Result<u8> {
    check_oid_prefix(tlv.value, tlv.offset)
}

fn check_oid_prefix(value: &[u8], offset: usize) -> Result<u8> {
    if value.len() != 7 || value[..5] != OID_PREFIX {
        return Err(Error::new(ErrorKind::InvalidValue, offset));
    }
    Ok(value[6])
}

/// The contents of a single TLV of tag `expected` inside `tlv`.
fn inner_octets<'a>(tlv: &Tlv<'a>, expected: u8) -> Result<&'a [u8]> {
    if !tlv.is_constructed() {
        // An implicit octet string: the contents are the value itself.
        return Ok(tlv.value);
    }
    let inner = read_tlv(&mut tlv.reader())?;
    if inner.tag != expected {
        return Err(Error::new(ErrorKind::InvalidTag(inner.tag), inner.offset));
    }
    Ok(inner.value)
}

/// The `authentication` bit of an ACSE-requirements BIT STRING.
///
/// A BER bit string is `[unused-bit-count, content…]`, and bit 0 — `authentication` — is
/// the *most significant* bit of the first content byte. Reading the last byte instead
/// happens to work for the one-byte form every stack sends (`07 80`) and silently
/// reports "no authentication" for any longer one.
fn authentication_bit(value: &[u8]) -> bool {
    value.get(1).is_some_and(|b| *b & 0x80 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn the_context_and_mechanism_oids_are_the_dlms_ua_arcs() {
        assert_eq!(oid(1, 1), [0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]);
        assert_eq!(oid(2, 5), [0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x05]);
    }

    #[test]
    fn a_low_level_security_aarq_round_trips() {
        let aarq = Aarq {
            application_context: Some(ApplicationContext::LogicalName),
            calling_ap_title: None,
            sender_acse_requirements: true,
            mechanism_name: Some(AuthMechanism::Low),
            calling_authentication_value: Some(b"12345678"),
            user_information: Some(&[
                0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0,
            ]),
            ..Default::default()
        };
        let mut buf = [0u8; 128];
        let mut w = SliceWriter::new(&mut buf);
        aarq.encode(&mut w).unwrap();
        let bytes = w.as_slice();
        assert_eq!(bytes[0], 0x60, "AARQ is [APPLICATION 0]");
        assert_eq!(bytes[1] as usize, bytes.len() - 2, "length covers the rest");
        let back = Aarq::from_bytes(bytes).unwrap();
        assert_eq!(back, aarq);
    }

    #[test]
    fn a_ciphered_hls_aarq_carries_both_system_title_and_challenge() {
        let title = [0x4Du8, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E];
        let challenge = [0xAAu8; 16];
        let aarq = Aarq {
            application_context: Some(ApplicationContext::LogicalNameCiphered),
            calling_ap_title: Some(&title),
            sender_acse_requirements: true,
            mechanism_name: Some(AuthMechanism::HighGmac),
            calling_authentication_value: Some(&challenge),
            user_information: Some(&[0x21, 0x30, 0x00, 0x00, 0x00, 0x01, 0xFF]),
            ..Default::default()
        };
        let mut buf = [0u8; 128];
        let mut w = SliceWriter::new(&mut buf);
        aarq.encode(&mut w).unwrap();
        let back = Aarq::from_bytes(w.as_slice()).unwrap();
        assert_eq!(back.calling_ap_title, Some(&title[..]));
        assert_eq!(back.calling_authentication_value, Some(&challenge[..]));
        assert_eq!(back.mechanism_name, Some(AuthMechanism::HighGmac));
        assert!(back.application_context.unwrap().is_ciphered());
    }

    #[test]
    fn an_accepted_aare_round_trips() {
        let aare = Aare {
            application_context: Some(ApplicationContext::LogicalName),
            result: AssociationResult::Accepted,
            diagnostic: Diagnostic::User(UserDiagnostic::Null),
            user_information: Some(&[
                0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0x00, 0x00, 0x07,
            ]),
            ..Default::default()
        };
        let mut buf = [0u8; 128];
        let mut w = SliceWriter::new(&mut buf);
        aare.encode(&mut w).unwrap();
        assert_eq!(w.as_slice()[0], 0x61);
        let back = Aare::from_bytes(w.as_slice()).unwrap();
        assert_eq!(back, aare);
        assert!(back.is_accepted());
    }

    #[test]
    fn a_refusal_keeps_its_diagnostic() {
        let aare = Aare {
            result: AssociationResult::RejectedPermanent,
            diagnostic: Diagnostic::User(UserDiagnostic::AuthenticationFailure),
            ..Default::default()
        };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        aare.encode(&mut w).unwrap();
        let back = Aare::from_bytes(w.as_slice()).unwrap();
        assert!(!back.is_accepted());
        assert_eq!(back.diagnostic, Diagnostic::User(UserDiagnostic::AuthenticationFailure));
    }

    #[test]
    fn a_provider_diagnostic_is_not_mistaken_for_a_user_one() {
        let aare = Aare {
            result: AssociationResult::RejectedTransient,
            diagnostic: Diagnostic::Provider(1),
            ..Default::default()
        };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        aare.encode(&mut w).unwrap();
        assert_eq!(Aare::from_bytes(w.as_slice()).unwrap().diagnostic, Diagnostic::Provider(1));
    }

    #[test]
    fn release_round_trips() {
        let rlrq = Rlrq { reason: Some(ReleaseReason::Normal), user_information: None };
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        rlrq.encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x62, 0x03, 0x80, 0x01, 0x00]);
        assert_eq!(Rlrq::from_bytes(w.as_slice()).unwrap(), rlrq);

        let rlre = Rlre { reason: Some(ReleaseReason::Normal), user_information: None };
        let mut w = SliceWriter::new(&mut buf);
        rlre.encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x63, 0x03, 0x80, 0x01, 0x00]);
    }

    /// The bit string is `[unused-bits, content…]` and `authentication` is the top bit
    /// of the *first* content byte. Every stack sends the one-byte form, so reading the
    /// last byte works until somebody sends a longer one — and then authentication
    /// silently reads as absent.
    #[test]
    fn the_authentication_bit_is_read_from_the_first_content_byte() {
        // The one-byte form everyone sends.
        let tlv = read_tlv(&mut Reader::new(&[0x8A, 0x02, 0x07, 0x80])).unwrap();
        assert!(authentication_bit(tlv.value));
        // A two-byte content with the same bit set. `.last()` would see 0x00 here.
        let tlv = read_tlv(&mut Reader::new(&[0x8A, 0x03, 0x00, 0x80, 0x00])).unwrap();
        assert!(authentication_bit(tlv.value), "a longer bit string must not lose the bit");
        // And genuinely absent.
        let tlv = read_tlv(&mut Reader::new(&[0x8A, 0x02, 0x07, 0x00])).unwrap();
        assert!(!authentication_bit(tlv.value));
        // A bit string with no content byte at all says nothing.
        let tlv = read_tlv(&mut Reader::new(&[0x8A, 0x01, 0x00])).unwrap();
        assert!(!authentication_bit(tlv.value));
    }

    #[test]
    fn an_unknown_context_arc_is_kept_not_defaulted() {
        let aarq = Aarq { application_context: Some(ApplicationContext::Other(9)), ..Default::default() };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        aarq.encode(&mut w).unwrap();
        assert_eq!(
            Aarq::from_bytes(w.as_slice()).unwrap().application_context,
            Some(ApplicationContext::Other(9))
        );
    }
}
