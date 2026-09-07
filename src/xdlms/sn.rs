//! Short-name referencing: the Read, Write and report services.
//!
//! Logical-name referencing names an attribute by `(class_id, logical name, index)` —
//! sixteen bytes. Short-name referencing names the same attribute by a **sixteen-bit
//! number**. An installed base of meters built before logical names became universal
//! speaks it, and nothing else.
//!
//! [`ReadRequest`], [`WriteRequest`], [`UnconfirmedWriteRequest`] and
//! [`InformationReportRequest`] are the four services. All are lists, and all address
//! their targets through [`VariableAccess`].
//!
//! There is no ACTION service: a method is invoked by *writing* its short name, with the
//! value as the parameter. [`crate::cosem::ShortName`] turns a base name into a short
//! name and back.

use crate::axdr::Data;
use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

use super::result::{DataAccessResult, List};

/// A sixteen-bit short name.
///
/// The Blue Book calls this an `ObjectName`. The low three bits of a *named-variable*
/// short name are zero, and `0xFA00` is the base name of the current association object
/// in every short-name logical device.
pub type ObjectName = u16;

/// The base name of the current association object in a short-name logical device.
pub const CURRENT_ASSOCIATION_SN: ObjectName = 0xFA00;

/// How far apart consecutive attributes of one object sit.
///
/// Confirmed twice: attribute *n* of an object based at `x` is `x + (n − 1) × 8`.
pub const ATTRIBUTE_STRIDE: u16 = 8;

/// What a Read, Write or report entry addresses.
///
/// The `detailed-access` choice `[3]` is defined in the ASN.1 and explicitly not used in
/// DLMS/COSEM, so it is not here: decoding a tag no conformant peer sends buys nothing
/// and widens a parser that faces the network.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VariableAccess<'a> {
    /// An attribute or a method, by short name.
    VariableName(ObjectName),
    /// An attribute with a selective-access descriptor, or a method with its parameter —
    /// short-name referencing has one shape for both.
    Parameterized {
        /// Which attribute or method.
        name: ObjectName,
        /// Which selector, or which method invocation the profile defines.
        selector: u8,
        /// The selector's parameter.
        parameter: Data<'a>,
    },
    /// Ask for the next block of a long read.
    BlockNumber(u16),
    /// One block of a long write going up.
    ReadDataBlock {
        /// True when no further block follows.
        last_block: bool,
        /// This block's number.
        block_number: u16,
        /// The fragment.
        raw_data: &'a [u8],
    },
    /// Acknowledge a block of a long write.
    WriteDataBlock {
        /// True when no further block follows.
        last_block: bool,
        /// The block being acknowledged.
        block_number: u16,
    },
}

impl VariableAccess<'_> {
    /// The short name this entry addresses, for the two forms that name one.
    #[must_use]
    pub const fn name(&self) -> Option<ObjectName> {
        match self {
            Self::VariableName(n) | Self::Parameterized { name: n, .. } => Some(*n),
            _ => None,
        }
    }
}

impl Encode for VariableAccess<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::VariableName(name) => {
                w.write_u8(2)?;
                w.write_u16(*name)
            }
            Self::Parameterized { name, selector, parameter } => {
                w.write_u8(4)?;
                w.write_u16(*name)?;
                w.write_u8(*selector)?;
                parameter.encode(w)
            }
            Self::BlockNumber(n) => {
                w.write_u8(5)?;
                w.write_u16(*n)
            }
            Self::ReadDataBlock { last_block, block_number, raw_data } => {
                w.write_u8(6)?;
                w.write_u8(u8::from(*last_block))?;
                w.write_u16(*block_number)?;
                w.write_length_prefixed(raw_data)
            }
            Self::WriteDataBlock { last_block, block_number } => {
                w.write_u8(7)?;
                w.write_u8(u8::from(*last_block))?;
                w.write_u16(*block_number)
            }
        }
    }
}

impl<'a> Decode<'a> for VariableAccess<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(match r.u8()? {
            2 => Self::VariableName(r.u16()?),
            4 => Self::Parameterized { name: r.u16()?, selector: r.u8()?, parameter: Data::decode(r)? },
            5 => Self::BlockNumber(r.u16()?),
            6 => Self::ReadDataBlock {
                last_block: r.u8()? != 0,
                block_number: r.u16()?,
                raw_data: r.length_prefixed()?,
            },
            7 => Self::WriteDataBlock { last_block: r.u8()? != 0, block_number: r.u16()? },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        })
    }
}

/// Read one or more attributes by short name.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadRequest<'a> {
    /// What to read, in order. The answers come back in the same order.
    pub specification: List<'a, VariableAccess<'a>>,
}

impl Encode for ReadRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        self.specification.encode(w)
    }
}

impl<'a> Decode<'a> for ReadRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { specification: List::decode(r)? })
    }
}

/// One answer inside a [`ReadResponse`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReadResult<'a> {
    /// The value.
    Data(Data<'a>),
    /// Why there is none.
    Error(DataAccessResult),
    /// One fragment of a value too large for the negotiated PDU size. Ask for the next
    /// with [`VariableAccess::BlockNumber`].
    Block {
        /// True when no further block follows.
        last_block: bool,
        /// This block's number.
        block_number: u16,
        /// The fragment.
        raw_data: &'a [u8],
    },
    /// The server has accepted a block of a long *write* and names it.
    BlockNumber(u16),
}

impl Encode for ReadResult<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Data(d) => {
                w.write_u8(0)?;
                d.encode(w)
            }
            Self::Error(e) => {
                w.write_u8(1)?;
                w.write_u8(e.as_u8())
            }
            Self::Block { last_block, block_number, raw_data } => {
                w.write_u8(2)?;
                w.write_u8(u8::from(*last_block))?;
                w.write_u16(*block_number)?;
                w.write_length_prefixed(raw_data)
            }
            Self::BlockNumber(n) => {
                w.write_u8(3)?;
                w.write_u16(*n)
            }
        }
    }
}

impl<'a> Decode<'a> for ReadResult<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(match r.u8()? {
            0 => Self::Data(Data::decode(r)?),
            1 => Self::Error(DataAccessResult::from_u8(r.u8()?)),
            2 => Self::Block {
                last_block: r.u8()? != 0,
                block_number: r.u16()?,
                raw_data: r.length_prefixed()?,
            },
            3 => Self::BlockNumber(r.u16()?),
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        })
    }
}

/// The answer to a [`ReadRequest`]: one result per entry, in order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadResponse<'a> {
    /// One per entry of the request.
    pub results: List<'a, ReadResult<'a>>,
}

impl Encode for ReadResponse<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        self.results.encode(w)
    }
}

impl<'a> Decode<'a> for ReadResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { results: List::decode(r)? })
    }
}

/// Write one or more attributes by short name.
///
/// The two lists are **positional**: value *i* is written to entry *i*. A request whose
/// lists are different lengths names writes whose values cannot be found, and is refused
/// rather than paired up as far as it goes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteRequest<'a> {
    /// What to write to, in order.
    pub specification: List<'a, VariableAccess<'a>>,
    /// The values, in the same order.
    pub values: List<'a, Data<'a>>,
}

impl Encode for WriteRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        self.specification.encode(w)?;
        self.values.encode(w)
    }
}

impl<'a> Decode<'a> for WriteRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { specification: List::decode(r)?, values: List::decode(r)? })
    }
}

/// One outcome inside a [`WriteResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteResult {
    /// The write succeeded.
    Success,
    /// Why it did not.
    Error(DataAccessResult),
    /// A block of a long write was accepted, and this is its number.
    BlockNumber(u16),
}

impl Encode for WriteResult {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Success => w.write_u8(0),
            Self::Error(e) => {
                w.write_u8(1)?;
                w.write_u8(e.as_u8())
            }
            Self::BlockNumber(n) => {
                w.write_u8(2)?;
                w.write_u16(*n)
            }
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Success => 1,
            Self::Error(_) => 2,
            Self::BlockNumber(_) => 3,
        }
    }
}

impl<'a> Decode<'a> for WriteResult {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(match r.u8()? {
            0 => Self::Success,
            1 => Self::Error(DataAccessResult::from_u8(r.u8()?)),
            2 => Self::BlockNumber(r.u16()?),
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        })
    }
}

/// The answer to a [`WriteRequest`]: one outcome per entry, in order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteResponse<'a> {
    /// One per entry of the request.
    pub results: List<'a, WriteResult>,
}

impl Encode for WriteResponse<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        self.results.encode(w)
    }
}

impl<'a> Decode<'a> for WriteResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { results: List::decode(r)? })
    }
}

/// A write the server does not answer.
///
/// The same body as [`WriteRequest`] under a tag of its own. Worth having as a distinct
/// type rather than a flag: a caller that sends one must not then wait for a reply, and
/// a type that cannot produce a response is how that is said.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnconfirmedWriteRequest<'a> {
    /// What to write to, in order.
    pub specification: List<'a, VariableAccess<'a>>,
    /// The values, in the same order.
    pub values: List<'a, Data<'a>>,
}

impl Encode for UnconfirmedWriteRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        self.specification.encode(w)?;
        self.values.encode(w)
    }
}

impl<'a> Decode<'a> for UnconfirmedWriteRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { specification: List::decode(r)?, values: List::decode(r)? })
    }
}

/// The short-name push: values a server sends unasked.
///
/// The sibling of `DataNotification`, from the era before logical names. `current_time`
/// is an `OPTIONAL GeneralizedTime`, so A-XDR puts a usage flag in front of it; the time
/// itself is carried as the octets the peer sent, because the encoding of a
/// `GeneralizedTime` inside A-XDR is not stated in material this project can read and a
/// timestamp decoded under a guessed grammar is a reading dated wrongly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InformationReportRequest<'a> {
    /// When, as the peer sent it, or `None` when it did not say.
    pub current_time: Option<&'a [u8]>,
    /// What the values are, in order.
    pub specification: List<'a, VariableAccess<'a>>,
    /// The values, in the same order.
    pub values: List<'a, Data<'a>>,
}

impl Encode for InformationReportRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self.current_time {
            None => w.write_u8(0)?,
            Some(t) => {
                w.write_u8(1)?;
                w.write_length_prefixed(t)?;
            }
        }
        self.specification.encode(w)?;
        self.values.encode(w)
    }
}

impl<'a> Decode<'a> for InformationReportRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let current_time = if r.u8()? == 0 { None } else { Some(r.length_prefixed()?) };
        Ok(Self { current_time, specification: List::decode(r)?, values: List::decode(r)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    fn round_trip<'a, T: Encode + Decode<'a> + PartialEq + core::fmt::Debug>(v: &T, buf: &'a mut [u8]) {
        let n = {
            let mut w = SliceWriter::new(buf);
            v.encode(&mut w).unwrap();
            w.written()
        };
        assert_eq!(v.encoded_len(), n, "encoded_len must agree with encode");
        let decoded = T::from_bytes(buf.get(..n).unwrap()).unwrap();
        assert_eq!(&decoded, v);
    }

    #[test]
    fn every_variable_access_form_round_trips() {
        let forms = [
            VariableAccess::VariableName(0xFA00),
            VariableAccess::Parameterized { name: 0x0028, selector: 1, parameter: Data::LongUnsigned(7) },
            VariableAccess::BlockNumber(3),
            VariableAccess::ReadDataBlock { last_block: false, block_number: 2, raw_data: &[1, 2, 3] },
            VariableAccess::WriteDataBlock { last_block: true, block_number: 9 },
        ];
        for form in forms {
            let mut buf = [0u8; 32];
            round_trip(&form, &mut buf);
        }
    }

    /// The one encoding worth pinning by hand: `variable-name` is choice 2 and a
    /// big-endian sixteen-bit number, which is the whole point of short names.
    #[test]
    fn a_variable_name_is_three_bytes() {
        let mut buf = [0u8; 8];
        let mut w = SliceWriter::new(&mut buf);
        VariableAccess::VariableName(0xFA00).encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x02, 0xFA, 0x00]);
    }

    #[test]
    fn every_read_result_form_round_trips() {
        for form in [
            ReadResult::Data(Data::DoubleLongUnsigned(1234)),
            ReadResult::Error(DataAccessResult::ObjectUndefined),
            ReadResult::Block { last_block: true, block_number: 1, raw_data: &[0xAA] },
            ReadResult::BlockNumber(4),
        ] {
            let mut buf = [0u8; 32];
            round_trip(&form, &mut buf);
        }
    }

    #[test]
    fn every_write_result_form_round_trips() {
        for form in [
            WriteResult::Success,
            WriteResult::Error(DataAccessResult::ReadWriteDenied),
            WriteResult::BlockNumber(2),
        ] {
            let mut buf = [0u8; 8];
            round_trip(&form, &mut buf);
        }
    }

    #[test]
    fn a_report_without_a_time_still_says_so() {
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        InformationReportRequest {
            current_time: None,
            specification: List::from_raw(0, &[]),
            values: List::from_raw(0, &[]),
        }
        .encode(&mut w)
        .unwrap();
        assert_eq!(w.as_slice(), [0x00, 0x00, 0x00], "usage flag, then two empty lists");
    }
}
