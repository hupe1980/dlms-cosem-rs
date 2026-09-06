//! The APDU tag byte.

/// Every APDU tag the DLMS/COSEM application layer defines.
///
/// The ciphered families are regular: a `glo-` tag is its plain tag plus `0x20` for the
/// short-name services and sits in `0xC8..=0xCF` for the logical-name ones, and a `ded-`
/// tag adds `0x40` / sits in `0xD0..=0xD7`. [`ApduTag::unprotect`] and
/// [`ApduTag::protected_as`] exploit that instead of a lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum ApduTag {
    InitiateRequest = 0x01,
    ReadRequest = 0x05,
    WriteRequest = 0x06,
    InitiateResponse = 0x08,
    ReadResponse = 0x0C,
    WriteResponse = 0x0D,
    ConfirmedServiceError = 0x0E,
    DataNotification = 0x0F,
    UnconfirmedWriteRequest = 0x16,
    InformationReportRequest = 0x18,

    GloInitiateRequest = 0x21,
    GloReadRequest = 0x25,
    GloWriteRequest = 0x26,
    GloInitiateResponse = 0x28,
    GloReadResponse = 0x2C,
    GloWriteResponse = 0x2D,
    GloConfirmedServiceError = 0x2E,
    GloUnconfirmedWriteRequest = 0x36,
    GloInformationReport = 0x38,

    DedInitiateRequest = 0x41,
    DedReadRequest = 0x45,
    DedWriteRequest = 0x46,
    DedInitiateResponse = 0x48,
    DedReadResponse = 0x4C,
    DedWriteResponse = 0x4D,
    DedConfirmedServiceError = 0x4E,
    DedUnconfirmedWriteRequest = 0x56,
    DedInformationReport = 0x58,

    Aarq = 0x60,
    Aare = 0x61,
    ReleaseRequest = 0x62,
    ReleaseResponse = 0x63,

    GetRequest = 0xC0,
    SetRequest = 0xC1,
    EventNotificationRequest = 0xC2,
    ActionRequest = 0xC3,
    GetResponse = 0xC4,
    SetResponse = 0xC5,
    ActionResponse = 0xC7,

    GloGetRequest = 0xC8,
    GloSetRequest = 0xC9,
    GloEventNotification = 0xCA,
    GloActionRequest = 0xCB,
    GloGetResponse = 0xCC,
    GloSetResponse = 0xCD,
    GloActionResponse = 0xCF,

    DedGetRequest = 0xD0,
    DedSetRequest = 0xD1,
    DedEventNotification = 0xD2,
    DedActionRequest = 0xD3,
    DedGetResponse = 0xD4,
    DedSetResponse = 0xD5,
    DedActionResponse = 0xD7,

    ExceptionResponse = 0xD8,
    AccessRequest = 0xD9,
    AccessResponse = 0xDA,
    GeneralGloCiphering = 0xDB,
    GeneralDedCiphering = 0xDC,
    GeneralCiphering = 0xDD,
    GeneralSigning = 0xDF,
    GeneralBlockTransfer = 0xE0,

    GatewayRequest = 0xE6,
    GatewayResponse = 0xE7,

    PingRequest = 0x19,
    PingResponse = 0x1A,
    RegisterRequest = 0x1C,
    DiscoverRequest = 0x1D,
    DiscoverReport = 0x1E,
    RepeatCallRequest = 0x1F,
}

/// How an APDU is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// No protection: the service tag itself.
    None,
    /// Protected with the global key set (`glo-`).
    Global,
    /// Protected with the dedicated key of this association (`ded-`).
    Dedicated,
}

impl ApduTag {
    /// Classify a tag byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::InitiateRequest,
            0x05 => Self::ReadRequest,
            0x06 => Self::WriteRequest,
            0x08 => Self::InitiateResponse,
            0x0C => Self::ReadResponse,
            0x0D => Self::WriteResponse,
            0x0E => Self::ConfirmedServiceError,
            0x0F => Self::DataNotification,
            0x16 => Self::UnconfirmedWriteRequest,
            0x18 => Self::InformationReportRequest,
            0x19 => Self::PingRequest,
            0x1A => Self::PingResponse,
            0x1C => Self::RegisterRequest,
            0x1D => Self::DiscoverRequest,
            0x1E => Self::DiscoverReport,
            0x1F => Self::RepeatCallRequest,
            0x21 => Self::GloInitiateRequest,
            0x25 => Self::GloReadRequest,
            0x26 => Self::GloWriteRequest,
            0x28 => Self::GloInitiateResponse,
            0x2C => Self::GloReadResponse,
            0x2D => Self::GloWriteResponse,
            0x2E => Self::GloConfirmedServiceError,
            0x36 => Self::GloUnconfirmedWriteRequest,
            0x38 => Self::GloInformationReport,
            0x41 => Self::DedInitiateRequest,
            0x45 => Self::DedReadRequest,
            0x46 => Self::DedWriteRequest,
            0x48 => Self::DedInitiateResponse,
            0x4C => Self::DedReadResponse,
            0x4D => Self::DedWriteResponse,
            0x4E => Self::DedConfirmedServiceError,
            0x56 => Self::DedUnconfirmedWriteRequest,
            0x58 => Self::DedInformationReport,
            0x60 => Self::Aarq,
            0x61 => Self::Aare,
            0x62 => Self::ReleaseRequest,
            0x63 => Self::ReleaseResponse,
            0xC0 => Self::GetRequest,
            0xC1 => Self::SetRequest,
            0xC2 => Self::EventNotificationRequest,
            0xC3 => Self::ActionRequest,
            0xC4 => Self::GetResponse,
            0xC5 => Self::SetResponse,
            0xC7 => Self::ActionResponse,
            0xC8 => Self::GloGetRequest,
            0xC9 => Self::GloSetRequest,
            0xCA => Self::GloEventNotification,
            0xCB => Self::GloActionRequest,
            0xCC => Self::GloGetResponse,
            0xCD => Self::GloSetResponse,
            0xCF => Self::GloActionResponse,
            0xD0 => Self::DedGetRequest,
            0xD1 => Self::DedSetRequest,
            0xD2 => Self::DedEventNotification,
            0xD3 => Self::DedActionRequest,
            0xD4 => Self::DedGetResponse,
            0xD5 => Self::DedSetResponse,
            0xD7 => Self::DedActionResponse,
            0xD8 => Self::ExceptionResponse,
            0xD9 => Self::AccessRequest,
            0xDA => Self::AccessResponse,
            0xDB => Self::GeneralGloCiphering,
            0xDC => Self::GeneralDedCiphering,
            0xDD => Self::GeneralCiphering,
            0xDF => Self::GeneralSigning,
            0xE0 => Self::GeneralBlockTransfer,
            0xE6 => Self::GatewayRequest,
            0xE7 => Self::GatewayResponse,
            _ => return None,
        })
    }

    /// The tag byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// How this tag is protected, and the plain service underneath it.
    ///
    /// Returns `None` for a tag that is not a ciphered service — `general-ciphering`
    /// included, because that one wraps a whole APDU rather than renaming a service.
    #[must_use]
    pub const fn unprotect(self) -> Option<(Protection, Self)> {
        let v = self as u8;
        let (protection, plain) = match v {
            0x21 | 0x25 | 0x26 | 0x28 | 0x2C | 0x2D | 0x2E | 0x36 | 0x38 => (Protection::Global, v - 0x20),
            0x41 | 0x45 | 0x46 | 0x48 | 0x4C | 0x4D | 0x4E | 0x56 | 0x58 => (Protection::Dedicated, v - 0x40),
            0xC8..=0xCF => (Protection::Global, v - 0x08),
            0xD0..=0xD7 => (Protection::Dedicated, v - 0x10),
            _ => return None,
        };
        match Self::from_u8(plain) {
            Some(p) => Some((protection, p)),
            None => None,
        }
    }

    /// The ciphered tag for this plain service under `protection`.
    #[must_use]
    pub const fn protected_as(self, protection: Protection) -> Option<Self> {
        let v = self as u8;
        let out = match (protection, v) {
            (Protection::None, _) => v,
            (Protection::Global, 0x01 | 0x05 | 0x06 | 0x08 | 0x0C | 0x0D | 0x0E | 0x16 | 0x18) => v + 0x20,
            (Protection::Dedicated, 0x01 | 0x05 | 0x06 | 0x08 | 0x0C | 0x0D | 0x0E | 0x16 | 0x18) => v + 0x40,
            (Protection::Global, 0xC0..=0xC7) => v + 0x08,
            (Protection::Dedicated, 0xC0..=0xC7) => v + 0x10,
            _ => return None,
        };
        Self::from_u8(out)
    }

    /// True when this tag carries a service that expects a response.
    #[must_use]
    pub const fn is_request(self) -> bool {
        matches!(
            self,
            Self::GetRequest
                | Self::SetRequest
                | Self::ActionRequest
                | Self::AccessRequest
                | Self::ReadRequest
                | Self::WriteRequest
                | Self::Aarq
                | Self::ReleaseRequest
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ciphered_families_are_arithmetic() {
        assert_eq!(ApduTag::GetRequest.protected_as(Protection::Global), Some(ApduTag::GloGetRequest));
        assert_eq!(ApduTag::GetRequest.protected_as(Protection::Dedicated), Some(ApduTag::DedGetRequest));
        assert_eq!(
            ApduTag::GloActionResponse.unprotect(),
            Some((Protection::Global, ApduTag::ActionResponse))
        );
        assert_eq!(
            ApduTag::DedInitiateRequest.unprotect(),
            Some((Protection::Dedicated, ApduTag::InitiateRequest))
        );
    }

    #[test]
    fn every_glo_and_ded_tag_round_trips_through_its_plain_form() {
        for v in 0u8..=255 {
            let Some(tag) = ApduTag::from_u8(v) else { continue };
            let Some((protection, plain)) = tag.unprotect() else { continue };
            assert_eq!(plain.protected_as(protection), Some(tag), "tag {v:#04x} does not round-trip");
        }
    }

    /// The two tables are inverses of each other, in both directions. The asymmetry
    /// this catches is real: `glo-unconfirmedWriteRequest` ([54] in the ASN.1) was
    /// missing while its `ded-` sibling ([86]) was present, so an
    /// `unconfirmed-write-request` could be protected with the dedicated key and not
    /// with the global one.
    #[test]
    fn every_plain_tag_with_a_ciphered_form_round_trips_back() {
        for v in 0u8..=255 {
            let Some(plain) = ApduTag::from_u8(v) else { continue };
            for protection in [Protection::Global, Protection::Dedicated] {
                let Some(ciphered) = plain.protected_as(protection) else { continue };
                assert_eq!(
                    ciphered.unprotect(),
                    Some((protection, plain)),
                    "{plain:?} under {protection:?} became {ciphered:?}, which does not unprotect back"
                );
            }
        }
    }

    /// Both key sets protect the same set of services. A tag that only one of them can
    /// carry is a table typo, not a rule of the standard.
    #[test]
    fn the_global_and_dedicated_families_cover_the_same_services() {
        for v in 0u8..=255 {
            let Some(plain) = ApduTag::from_u8(v) else { continue };
            assert_eq!(
                plain.protected_as(Protection::Global).is_some(),
                plain.protected_as(Protection::Dedicated).is_some(),
                "{plain:?} can be protected with one key set and not the other"
            );
        }
    }

    #[test]
    fn general_ciphering_is_not_a_renamed_service() {
        assert_eq!(ApduTag::GeneralCiphering.unprotect(), None);
        assert_eq!(ApduTag::GeneralGloCiphering.unprotect(), None);
        assert_eq!(ApduTag::GeneralSigning.unprotect(), None);
    }

    #[test]
    fn tags_round_trip_through_bytes() {
        for v in 0u8..=255 {
            if let Some(t) = ApduTag::from_u8(v) {
                assert_eq!(t.as_u8(), v);
            }
        }
    }
}
