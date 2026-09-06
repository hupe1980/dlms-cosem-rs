//! The ACCESS service: several operations in one exchange.
//!
//! ACCESS batches GET, SET and ACTION into a single request and a single response. It
//! is the service a battery-powered meter on a low-power network uses, because the cost
//! there is round trips rather than bytes, and it is what the Green Book's LPWAN
//! examples are built on.

use crate::axdr::Data;
use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

use super::descriptor::{
    AttributeDescriptor, AttributeDescriptorWithSelection, LongInvokeId, MethodDescriptor, decode_optional,
    encode_optional,
};
use super::notify::OptionalDateTime;
use super::result::{ActionResult, DataAccessResult, List};

/// The most operations one ACCESS request may batch.
///
/// A bound rather than a buffer: a server's outcome list is two bytes an entry, so this
/// decides a 128-byte array instead of one sized by the PDU. It also decides how much
/// work a single request can demand, which is worth deciding rather than inheriting from
/// whatever the PDU size happens to be. Sixty-four operations in one exchange is already
/// far beyond what a companion profile's use cases ask for.
pub const MAX_ACCESS_ITEMS: usize = 64;

/// One operation inside an ACCESS request.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AccessRequestSpecification<'a> {
    /// Read an attribute.
    Get(AttributeDescriptor),
    /// Write an attribute; the value is in the data list.
    Set(AttributeDescriptor),
    /// Invoke a method; the parameter is in the data list.
    Action(MethodDescriptor),
    /// Read part of an attribute.
    GetWithSelection(AttributeDescriptorWithSelection<'a>),
    /// Write part of an attribute.
    SetWithSelection(AttributeDescriptorWithSelection<'a>),
}

impl Encode for AccessRequestSpecification<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Get(d) => {
                w.write_u8(1)?;
                d.encode(w)
            }
            Self::Set(d) => {
                w.write_u8(2)?;
                d.encode(w)
            }
            Self::Action(d) => {
                w.write_u8(3)?;
                d.encode(w)
            }
            Self::GetWithSelection(d) => {
                w.write_u8(4)?;
                d.encode(w)
            }
            Self::SetWithSelection(d) => {
                w.write_u8(5)?;
                d.encode(w)
            }
        }
    }
}

impl<'a> Decode<'a> for AccessRequestSpecification<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(match r.u8()? {
            1 => Self::Get(AttributeDescriptor::decode(r)?),
            2 => Self::Set(AttributeDescriptor::decode(r)?),
            3 => Self::Action(MethodDescriptor::decode(r)?),
            4 => Self::GetWithSelection(AttributeDescriptorWithSelection::decode(r)?),
            5 => Self::SetWithSelection(AttributeDescriptorWithSelection::decode(r)?),
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        })
    }
}

/// The outcome of one operation inside an ACCESS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessResponseSpecification {
    /// Result of a read.
    Get(DataAccessResult),
    /// Result of a write.
    Set(DataAccessResult),
    /// Result of a method invocation.
    Action(ActionResult),
}

impl Encode for AccessResponseSpecification {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Get(v) => w.write_bytes(&[1, v.as_u8()]),
            Self::Set(v) => w.write_bytes(&[2, v.as_u8()]),
            Self::Action(v) => w.write_bytes(&[3, v.as_u8()]),
        }
    }

    fn encoded_len(&self) -> usize {
        2
    }
}

impl<'a> Decode<'a> for AccessResponseSpecification {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(match r.u8()? {
            1 => Self::Get(DataAccessResult::from_u8(r.u8()?)),
            2 => Self::Set(DataAccessResult::from_u8(r.u8()?)),
            3 => Self::Action(ActionResult::from_u8(r.u8()?)),
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        })
    }
}

/// Several operations in one request.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccessRequest<'a> {
    /// Identifies the exchange.
    pub long_invoke_id: LongInvokeId,
    /// When the client sent it, if it said.
    pub date_time: OptionalDateTime,
    /// What to do, in order.
    pub specification: List<'a, AccessRequestSpecification<'a>>,
    /// The values the SET and ACTION entries consume, in the same order.
    pub data: List<'a, Data<'a>>,
}

impl Encode for AccessRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u32(self.long_invoke_id.0)?;
        self.date_time.encode(w)?;
        self.specification.encode(w)?;
        self.data.encode(w)
    }
}

impl<'a> Decode<'a> for AccessRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            long_invoke_id: LongInvokeId(r.u32()?),
            date_time: OptionalDateTime::decode(r)?,
            specification: List::decode(r)?,
            data: List::decode(r)?,
        })
    }
}

/// The answer to an [`AccessRequest`].
///
/// The response echoes the request's specification list before its own results, so a
/// client that lost track of what it asked can still line the answers up.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccessResponse<'a> {
    /// Echoes the request.
    pub long_invoke_id: LongInvokeId,
    /// When the server answered, if it said.
    pub date_time: OptionalDateTime,
    /// The request's specification list, echoed.
    ///
    /// `OPTIONAL` in the ASN.1 — the only optional field in either ACCESS body — so it
    /// is preceded by a usage flag on the wire. A codec that writes the list
    /// unconditionally emits a response every other stack reads one byte out of step.
    pub request_specification: Option<List<'a, AccessRequestSpecification<'a>>>,
    /// The values the GET and ACTION entries produced.
    pub data: List<'a, Data<'a>>,
    /// One outcome per operation, in order.
    pub response_specification: List<'a, AccessResponseSpecification>,
}

impl Encode for AccessResponse<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u32(self.long_invoke_id.0)?;
        self.date_time.encode(w)?;
        encode_optional(w, self.request_specification.as_ref())?;
        self.data.encode(w)?;
        self.response_specification.encode(w)
    }
}

impl<'a> Decode<'a> for AccessResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            long_invoke_id: LongInvokeId(r.u32()?),
            date_time: OptionalDateTime::decode(r)?,
            request_specification: decode_optional(r)?,
            data: List::decode(r)?,
            response_specification: List::decode(r)?,
        })
    }
}
