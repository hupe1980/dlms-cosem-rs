//! The APDU: one enum over everything the application layer can send.

use crate::acse::{Aare, Aarq, Rlre, Rlrq};
use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

use super::access::{AccessRequest, AccessResponse};
use super::error::{ConfirmedServiceError, ExceptionResponse};
use super::gbt::GeneralBlockTransfer;
use super::initiate::{InitiateRequest, InitiateResponse};
use super::notify::{DataNotification, EventNotification};
use super::protection::{CipheredService, GeneralCiphering, GeneralGloCiphering, GeneralSigning};
use super::service::{ActionRequest, ActionResponse, GetRequest, GetResponse, SetRequest, SetResponse};
#[cfg(feature = "sn")]
use super::sn::{
    InformationReportRequest, ReadRequest, ReadResponse, UnconfirmedWriteRequest, WriteRequest, WriteResponse,
};
use super::tag::{ApduTag, Protection};

/// Anything the application layer can send.
///
/// Decoding never fails on an APDU merely because it is protected: a ciphered service
/// decodes into [`Apdu::Ciphered`] with its security header intact, so a translator, a
/// fuzzer or a router can handle it without a key. [`crate::security`] turns one back
/// into a plain `Apdu`.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Apdu<'a> {
    Aarq(Aarq<'a>),
    Aare(Aare<'a>),
    Rlrq(Rlrq<'a>),
    Rlre(Rlre<'a>),

    InitiateRequest(InitiateRequest<'a>),
    InitiateResponse(InitiateResponse),

    GetRequest(GetRequest<'a>),
    GetResponse(GetResponse<'a>),
    SetRequest(SetRequest<'a>),
    SetResponse(SetResponse<'a>),
    ActionRequest(ActionRequest<'a>),
    ActionResponse(ActionResponse<'a>),
    AccessRequest(AccessRequest<'a>),
    AccessResponse(AccessResponse<'a>),

    DataNotification(DataNotification<'a>),
    EventNotification(EventNotification<'a>),

    /// The short-name services, behind the `sn` feature.
    ///
    /// Legacy addressing: an attribute is a sixteen-bit number rather than a class,
    /// a logical name and an index. Still what an installed base of pre-logical-name
    /// meters speaks.
    #[cfg(feature = "sn")]
    ReadRequest(ReadRequest<'a>),
    #[cfg(feature = "sn")]
    #[allow(missing_docs)]
    ReadResponse(ReadResponse<'a>),
    #[cfg(feature = "sn")]
    #[allow(missing_docs)]
    WriteRequest(WriteRequest<'a>),
    #[cfg(feature = "sn")]
    #[allow(missing_docs)]
    WriteResponse(WriteResponse<'a>),
    #[cfg(feature = "sn")]
    #[allow(missing_docs)]
    UnconfirmedWriteRequest(UnconfirmedWriteRequest<'a>),
    #[cfg(feature = "sn")]
    #[allow(missing_docs)]
    InformationReportRequest(InformationReportRequest<'a>),

    ExceptionResponse(ExceptionResponse),
    ConfirmedServiceError(ConfirmedServiceError),
    GeneralBlockTransfer(GeneralBlockTransfer<'a>),

    /// A `glo-` or `ded-` protected service, still protected.
    Ciphered {
        /// Which protection was applied.
        protection: Protection,
        /// Which service is inside.
        service: ApduTag,
        /// The security header and payload.
        body: CipheredService<'a>,
    },
    /// A `general-glo-ciphering` or `general-ded-ciphering` APDU, still protected.
    GeneralCiphered {
        /// Which protection was applied.
        protection: Protection,
        /// The originator and the protected service.
        body: GeneralGloCiphering<'a>,
    },
    GeneralCiphering(GeneralCiphering<'a>),
    GeneralSigning(GeneralSigning<'a>),

    /// An APDU addressed through a gateway, with the network and device it is for.
    Gateway {
        /// True for a response.
        response: bool,
        /// Which network behind the gateway.
        network_id: u8,
        /// Which device on it.
        physical_device_address: &'a [u8],
        /// The APDU to forward.
        payload: &'a [u8],
    },
}

impl Apdu<'_> {
    /// The tag this APDU encodes with.
    #[must_use]
    pub const fn tag(&self) -> ApduTag {
        match self {
            Self::Aarq(_) => ApduTag::Aarq,
            Self::Aare(_) => ApduTag::Aare,
            Self::Rlrq(_) => ApduTag::ReleaseRequest,
            Self::Rlre(_) => ApduTag::ReleaseResponse,
            Self::InitiateRequest(_) => ApduTag::InitiateRequest,
            Self::InitiateResponse(_) => ApduTag::InitiateResponse,
            Self::GetRequest(_) => ApduTag::GetRequest,
            Self::GetResponse(_) => ApduTag::GetResponse,
            Self::SetRequest(_) => ApduTag::SetRequest,
            Self::SetResponse(_) => ApduTag::SetResponse,
            Self::ActionRequest(_) => ApduTag::ActionRequest,
            Self::ActionResponse(_) => ApduTag::ActionResponse,
            Self::AccessRequest(_) => ApduTag::AccessRequest,
            Self::AccessResponse(_) => ApduTag::AccessResponse,
            Self::DataNotification(_) => ApduTag::DataNotification,
            Self::EventNotification(_) => ApduTag::EventNotificationRequest,
            #[cfg(feature = "sn")]
            Self::ReadRequest(_) => ApduTag::ReadRequest,
            #[cfg(feature = "sn")]
            Self::ReadResponse(_) => ApduTag::ReadResponse,
            #[cfg(feature = "sn")]
            Self::WriteRequest(_) => ApduTag::WriteRequest,
            #[cfg(feature = "sn")]
            Self::WriteResponse(_) => ApduTag::WriteResponse,
            #[cfg(feature = "sn")]
            Self::UnconfirmedWriteRequest(_) => ApduTag::UnconfirmedWriteRequest,
            #[cfg(feature = "sn")]
            Self::InformationReportRequest(_) => ApduTag::InformationReportRequest,
            Self::ExceptionResponse(_) => ApduTag::ExceptionResponse,
            Self::ConfirmedServiceError(_) => ApduTag::ConfirmedServiceError,
            Self::GeneralBlockTransfer(_) => ApduTag::GeneralBlockTransfer,
            // A `Ciphered` whose service has no form under this protection cannot be
            // encoded at all, and [`Encode`] refuses it. Reporting the plain service
            // here keeps this method total without inventing a tag that names a
            // different service — which is what reporting `exception-response` did.
            Self::Ciphered { protection, service, .. } => match service.protected_as(*protection) {
                Some(t) => t,
                None => *service,
            },
            Self::GeneralCiphered { protection, .. } => match protection {
                Protection::Dedicated => ApduTag::GeneralDedCiphering,
                _ => ApduTag::GeneralGloCiphering,
            },
            Self::GeneralCiphering(_) => ApduTag::GeneralCiphering,
            Self::GeneralSigning(_) => ApduTag::GeneralSigning,
            Self::Gateway { response: true, .. } => ApduTag::GatewayResponse,
            Self::Gateway { response: false, .. } => ApduTag::GatewayRequest,
        }
    }

    /// True when this APDU is protected and must be unprotected before it means
    /// anything.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        matches!(
            self,
            Self::Ciphered { .. }
                | Self::GeneralCiphered { .. }
                | Self::GeneralCiphering(_)
                | Self::GeneralSigning(_)
        )
    }
}

impl Encode for Apdu<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        // The ACSE APDUs carry their own BER tag; everything else is tag then body.
        match self {
            Self::Aarq(v) => return v.encode(w),
            Self::Aare(v) => return v.encode(w),
            Self::Rlrq(v) => return v.encode(w),
            Self::Rlre(v) => return v.encode(w),
            // A ciphered service whose plain tag has no form under the requested
            // protection is refused rather than written under some other tag. There is
            // no `unreachable!()` anywhere on this path: every arm below returns a
            // `Result`, so nothing reachable from the network can abort the process.
            Self::Ciphered { protection, service, .. } if service.protected_as(*protection).is_none() => {
                return Err(crate::codec::Error::new(ErrorKind::InvalidValue, w.written()));
            }
            _ => {}
        }
        w.write_u8(self.tag().as_u8())?;
        match self {
            // Handled above; kept as an arm so the match stays exhaustive and adding a
            // variant is a compile error rather than a silent fall-through.
            Self::Aarq(_) | Self::Aare(_) | Self::Rlrq(_) | Self::Rlre(_) => {
                Err(crate::codec::Error::new(ErrorKind::InvalidValue, w.written()))
            }
            Self::InitiateRequest(v) => v.encode(w),
            Self::InitiateResponse(v) => v.encode(w),
            Self::GetRequest(v) => v.encode(w),
            Self::GetResponse(v) => v.encode(w),
            Self::SetRequest(v) => v.encode(w),
            Self::SetResponse(v) => v.encode(w),
            Self::ActionRequest(v) => v.encode(w),
            Self::ActionResponse(v) => v.encode(w),
            Self::AccessRequest(v) => v.encode(w),
            Self::AccessResponse(v) => v.encode(w),
            Self::DataNotification(v) => v.encode(w),
            Self::EventNotification(v) => v.encode(w),
            #[cfg(feature = "sn")]
            Self::ReadRequest(v) => v.encode(w),
            #[cfg(feature = "sn")]
            Self::ReadResponse(v) => v.encode(w),
            #[cfg(feature = "sn")]
            Self::WriteRequest(v) => v.encode(w),
            #[cfg(feature = "sn")]
            Self::WriteResponse(v) => v.encode(w),
            #[cfg(feature = "sn")]
            Self::UnconfirmedWriteRequest(v) => v.encode(w),
            #[cfg(feature = "sn")]
            Self::InformationReportRequest(v) => v.encode(w),
            Self::ExceptionResponse(v) => v.encode(w),
            Self::ConfirmedServiceError(v) => v.encode(w),
            Self::GeneralBlockTransfer(v) => v.encode(w),
            Self::Ciphered { body, .. } => body.encode(w),
            Self::GeneralCiphered { body, .. } => body.encode(w),
            Self::GeneralCiphering(v) => v.encode(w),
            Self::GeneralSigning(v) => v.encode(w),
            Self::Gateway { network_id, physical_device_address, payload, .. } => {
                w.write_u8(*network_id)?;
                w.write_length_prefixed(physical_device_address)?;
                w.write_bytes(payload)
            }
        }
    }
}

impl<'a> Decode<'a> for Apdu<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let tag_byte = r.peek_u8()?;
        let tag = ApduTag::from_u8(tag_byte).ok_or_else(|| r.err(ErrorKind::InvalidTag(tag_byte)))?;
        // ACSE APDUs are BER and re-read their own tag.
        match tag {
            ApduTag::Aarq => return Ok(Self::Aarq(Aarq::decode(r)?)),
            ApduTag::Aare => return Ok(Self::Aare(Aare::decode(r)?)),
            ApduTag::ReleaseRequest => return Ok(Self::Rlrq(Rlrq::decode(r)?)),
            ApduTag::ReleaseResponse => return Ok(Self::Rlre(Rlre::decode(r)?)),
            _ => {}
        }
        r.skip(1)?;
        if let Some((protection, service)) = tag.unprotect() {
            return Ok(Self::Ciphered { protection, service, body: CipheredService::decode(r)? });
        }
        Ok(match tag {
            ApduTag::InitiateRequest => Self::InitiateRequest(InitiateRequest::decode(r)?),
            ApduTag::InitiateResponse => Self::InitiateResponse(InitiateResponse::decode(r)?),
            ApduTag::GetRequest => Self::GetRequest(GetRequest::decode(r)?),
            ApduTag::GetResponse => Self::GetResponse(GetResponse::decode(r)?),
            ApduTag::SetRequest => Self::SetRequest(SetRequest::decode(r)?),
            ApduTag::SetResponse => Self::SetResponse(SetResponse::decode(r)?),
            ApduTag::ActionRequest => Self::ActionRequest(ActionRequest::decode(r)?),
            ApduTag::ActionResponse => Self::ActionResponse(ActionResponse::decode(r)?),
            ApduTag::AccessRequest => Self::AccessRequest(AccessRequest::decode(r)?),
            ApduTag::AccessResponse => Self::AccessResponse(AccessResponse::decode(r)?),
            ApduTag::DataNotification => Self::DataNotification(DataNotification::decode(r)?),
            ApduTag::EventNotificationRequest => Self::EventNotification(EventNotification::decode(r)?),
            #[cfg(feature = "sn")]
            ApduTag::ReadRequest => Self::ReadRequest(ReadRequest::decode(r)?),
            #[cfg(feature = "sn")]
            ApduTag::ReadResponse => Self::ReadResponse(ReadResponse::decode(r)?),
            #[cfg(feature = "sn")]
            ApduTag::WriteRequest => Self::WriteRequest(WriteRequest::decode(r)?),
            #[cfg(feature = "sn")]
            ApduTag::WriteResponse => Self::WriteResponse(WriteResponse::decode(r)?),
            #[cfg(feature = "sn")]
            ApduTag::UnconfirmedWriteRequest => {
                Self::UnconfirmedWriteRequest(UnconfirmedWriteRequest::decode(r)?)
            }
            #[cfg(feature = "sn")]
            ApduTag::InformationReportRequest => {
                Self::InformationReportRequest(InformationReportRequest::decode(r)?)
            }
            ApduTag::ExceptionResponse => Self::ExceptionResponse(ExceptionResponse::decode(r)?),
            ApduTag::ConfirmedServiceError => Self::ConfirmedServiceError(ConfirmedServiceError::decode(r)?),
            ApduTag::GeneralBlockTransfer => Self::GeneralBlockTransfer(GeneralBlockTransfer::decode(r)?),
            ApduTag::GeneralGloCiphering => Self::GeneralCiphered {
                protection: Protection::Global,
                body: GeneralGloCiphering::decode(r)?,
            },
            ApduTag::GeneralDedCiphering => Self::GeneralCiphered {
                protection: Protection::Dedicated,
                body: GeneralGloCiphering::decode(r)?,
            },
            ApduTag::GeneralCiphering => Self::GeneralCiphering(GeneralCiphering::decode(r)?),
            ApduTag::GeneralSigning => Self::GeneralSigning(GeneralSigning::decode(r)?),
            ApduTag::GatewayRequest | ApduTag::GatewayResponse => Self::Gateway {
                response: tag == ApduTag::GatewayResponse,
                network_id: r.u8()?,
                physical_device_address: r.length_prefixed()?,
                payload: r.take_rest(),
            },
            _ => return Err(r.err_back(ErrorKind::InvalidTag(tag_byte), 1)),
        })
    }
}
