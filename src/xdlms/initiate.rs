//! The xDLMS association negotiation, carried inside the ACSE user information.

use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

use super::conformance::Conformance;
use super::descriptor::{decode_optional, encode_optional};

/// The DLMS version this crate speaks. Every deployed meter uses 6.
pub const DLMS_VERSION: u8 = 6;

/// The variable-access-specification name a logical-name association reports.
pub const VAA_NAME_LN: u16 = 0x0007;

/// Wrapper making an octet string encode length-prefixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Octets<'a>(&'a [u8]);

impl Encode for Octets<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_length_prefixed(self.0)
    }
}

impl<'a> Decode<'a> for Octets<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self(r.length_prefixed()?))
    }
}

/// What the client proposes when the association is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitiateRequest<'a> {
    /// A key for this association only, carried encrypted inside the ciphered
    /// InitiateRequest. Present only in a ciphered application context.
    pub dedicated_key: Option<&'a [u8]>,
    /// Whether the client wants responses. Absent means yes.
    pub response_allowed: Option<bool>,
    /// A quality-of-service value; nothing in the field uses it.
    pub proposed_quality_of_service: Option<i8>,
    /// The DLMS version, [`DLMS_VERSION`] in practice.
    pub proposed_dlms_version: u8,
    /// The services the client can perform.
    pub proposed_conformance: Conformance,
    /// The largest APDU the client will accept.
    pub client_max_receive_pdu_size: u16,
}

impl Default for InitiateRequest<'_> {
    fn default() -> Self {
        Self {
            dedicated_key: None,
            response_allowed: None,
            proposed_quality_of_service: None,
            proposed_dlms_version: DLMS_VERSION,
            proposed_conformance: Conformance::CLIENT_DEFAULT,
            client_max_receive_pdu_size: 1024,
        }
    }
}

impl Encode for InitiateRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        encode_optional(w, self.dedicated_key.map(Octets).as_ref())?;
        match self.response_allowed {
            None => w.write_u8(0)?,
            Some(v) => {
                w.write_u8(1)?;
                w.write_u8(u8::from(v))?;
            }
        }
        match self.proposed_quality_of_service {
            None => w.write_u8(0)?,
            Some(v) => {
                w.write_u8(1)?;
                w.write_u8(v as u8)?;
            }
        }
        w.write_u8(self.proposed_dlms_version)?;
        self.proposed_conformance.encode_tagged(w)?;
        w.write_u16(self.client_max_receive_pdu_size)
    }
}

impl<'a> Decode<'a> for InitiateRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let dedicated_key = decode_optional::<Octets<'a>>(r)?.map(|o| o.0);
        let response_allowed = if r.u8()? == 0 { None } else { Some(r.u8()? != 0) };
        let proposed_quality_of_service = if r.u8()? == 0 { None } else { Some(r.i8()?) };
        Ok(Self {
            dedicated_key,
            response_allowed,
            proposed_quality_of_service,
            proposed_dlms_version: r.u8()?,
            proposed_conformance: Conformance::decode_tagged(r)?,
            client_max_receive_pdu_size: r.u16()?,
        })
    }
}

/// What the server agrees to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitiateResponse {
    /// A quality-of-service value; nothing in the field uses it.
    pub negotiated_quality_of_service: Option<i8>,
    /// The DLMS version both sides will use.
    pub negotiated_dlms_version: u8,
    /// The services both sides can perform — the intersection.
    pub negotiated_conformance: Conformance,
    /// The largest APDU the server will accept. Every buffer this crate sizes for the
    /// association comes from here.
    pub server_max_receive_pdu_size: u16,
    /// [`VAA_NAME_LN`] for a logical-name association.
    pub vaa_name: u16,
}

impl Default for InitiateResponse {
    fn default() -> Self {
        Self {
            negotiated_quality_of_service: None,
            negotiated_dlms_version: DLMS_VERSION,
            negotiated_conformance: Conformance::empty(),
            server_max_receive_pdu_size: 1024,
            vaa_name: VAA_NAME_LN,
        }
    }
}

impl Encode for InitiateResponse {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self.negotiated_quality_of_service {
            None => w.write_u8(0)?,
            Some(v) => {
                w.write_u8(1)?;
                w.write_u8(v as u8)?;
            }
        }
        w.write_u8(self.negotiated_dlms_version)?;
        self.negotiated_conformance.encode_tagged(w)?;
        w.write_u16(self.server_max_receive_pdu_size)?;
        w.write_u16(self.vaa_name)
    }
}

impl<'a> Decode<'a> for InitiateResponse {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let negotiated_quality_of_service = if r.u8()? == 0 { None } else { Some(r.i8()?) };
        Ok(Self {
            negotiated_quality_of_service,
            negotiated_dlms_version: r.u8()?,
            negotiated_conformance: Conformance::decode_tagged(r)?,
            server_max_receive_pdu_size: r.u16()?,
            vaa_name: r.u16()?,
        })
    }
}

impl InitiateResponse {
    /// Fail unless the negotiated version is one this crate speaks.
    pub fn check_version(&self) -> Result<()> {
        if self.negotiated_dlms_version == DLMS_VERSION {
            Ok(())
        } else {
            Err(crate::codec::Error::new(ErrorKind::Unsupported, 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn an_initiate_request_encodes_the_shape_the_standard_prints() {
        let req = InitiateRequest {
            proposed_conformance: Conformance::from_bytes([0x00, 0x7E, 0x1F]),
            client_max_receive_pdu_size: 0xFFFF,
            ..Default::default()
        };
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(
            w.as_slice(),
            [
                0x00, // no dedicated key
                0x00, // response-allowed absent (defaults to true)
                0x00, // no proposed quality of service
                0x06, // DLMS version 6
                0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, // conformance
                0xFF, 0xFF, // max receive PDU size
            ]
        );
        assert_eq!(InitiateRequest::from_bytes(w.as_slice()).unwrap(), req);
    }

    #[test]
    fn a_dedicated_key_is_carried_length_prefixed() {
        let key = [0u8; 16];
        let req = InitiateRequest { dedicated_key: Some(&key), ..Default::default() };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(w.as_slice()[0], 0x01);
        assert_eq!(w.as_slice()[1], 16);
        assert_eq!(InitiateRequest::from_bytes(w.as_slice()).unwrap().dedicated_key, Some(&key[..]));
    }

    #[test]
    fn an_initiate_response_round_trips() {
        let resp = InitiateResponse {
            negotiated_conformance: Conformance::from_bytes([0x00, 0x7E, 0x1F]),
            server_max_receive_pdu_size: 512,
            ..Default::default()
        };
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        resp.encode(&mut w).unwrap();
        assert_eq!(
            w.as_slice(),
            [0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x02, 0x00, 0x00, 0x07]
        );
        assert_eq!(InitiateResponse::from_bytes(w.as_slice()).unwrap(), resp);
        assert!(resp.check_version().is_ok());
    }
}
