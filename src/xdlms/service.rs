//! GET, SET and ACTION — the confirmed services of logical-name referencing.

use crate::axdr::Data;
use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

use super::descriptor::{
    AttributeDescriptor, AttributeDescriptorWithSelection, InvokeId, MethodDescriptor, SelectiveAccess,
    decode_optional, encode_optional,
};
use super::result::{ActionResult, DataAccessResult, DataBlockG, DataBlockSA, GetDataResult, List};

impl Encode for DataAccessResult {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.as_u8())
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

impl<'a> Decode<'a> for DataAccessResult {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self::from_u8(r.u8()?))
    }
}

impl Encode for ActionResult {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.as_u8())
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

impl<'a> Decode<'a> for ActionResult {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self::from_u8(r.u8()?))
    }
}

/// Read an attribute.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetRequest<'a> {
    /// One attribute.
    Normal {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which attribute.
        descriptor: AttributeDescriptor,
        /// Which part of it.
        access: Option<SelectiveAccess<'a>>,
    },
    /// The next block of a long response.
    Next {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// The block just received, which the server continues after.
        block_number: u32,
    },
    /// Several attributes in one request.
    WithList {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which attributes.
        list: List<'a, AttributeDescriptorWithSelection<'a>>,
    },
}

impl Encode for GetRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Normal { invoke_id, descriptor, access } => {
                w.write_u8(1)?;
                w.write_u8(invoke_id.0)?;
                descriptor.encode(w)?;
                encode_optional(w, access.as_ref())
            }
            Self::Next { invoke_id, block_number } => {
                w.write_u8(2)?;
                w.write_u8(invoke_id.0)?;
                w.write_u32(*block_number)
            }
            Self::WithList { invoke_id, list } => {
                w.write_u8(3)?;
                w.write_u8(invoke_id.0)?;
                list.encode(w)
            }
        }
    }
}

impl<'a> Decode<'a> for GetRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let choice = r.u8()?;
        let invoke_id = InvokeId(r.u8()?);
        Ok(match choice {
            1 => Self::Normal {
                invoke_id,
                descriptor: AttributeDescriptor::decode(r)?,
                access: decode_optional(r)?,
            },
            2 => Self::Next { invoke_id, block_number: r.u32()? },
            3 => Self::WithList { invoke_id, list: List::decode(r)? },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 2)),
        })
    }
}

/// The answer to a [`GetRequest`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetResponse<'a> {
    /// One value.
    Normal {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// The value, or why there is none.
        result: GetDataResult<'a>,
    },
    /// One block of a value too long for a single APDU.
    WithDataBlock {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// The block.
        block: DataBlockG<'a>,
    },
    /// Several values.
    WithList {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// One result per requested attribute, in order.
        results: List<'a, GetDataResult<'a>>,
    },
}

impl Encode for GetResponse<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Normal { invoke_id, result } => {
                w.write_u8(1)?;
                w.write_u8(invoke_id.0)?;
                result.encode(w)
            }
            Self::WithDataBlock { invoke_id, block } => {
                w.write_u8(2)?;
                w.write_u8(invoke_id.0)?;
                block.encode(w)
            }
            Self::WithList { invoke_id, results } => {
                w.write_u8(3)?;
                w.write_u8(invoke_id.0)?;
                results.encode(w)
            }
        }
    }
}

impl<'a> Decode<'a> for GetResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let choice = r.u8()?;
        let invoke_id = InvokeId(r.u8()?);
        Ok(match choice {
            1 => Self::Normal { invoke_id, result: GetDataResult::decode(r)? },
            2 => Self::WithDataBlock { invoke_id, block: DataBlockG::decode(r)? },
            3 => Self::WithList { invoke_id, results: List::decode(r)? },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 2)),
        })
    }
}

/// Write an attribute.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SetRequest<'a> {
    /// One attribute, one value.
    Normal {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which attribute.
        descriptor: AttributeDescriptor,
        /// Which part of it.
        access: Option<SelectiveAccess<'a>>,
        /// The new value.
        value: Data<'a>,
    },
    /// The first block of a value too long for one APDU.
    WithFirstDataBlock {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which attribute.
        descriptor: AttributeDescriptor,
        /// Which part of it.
        access: Option<SelectiveAccess<'a>>,
        /// The first block.
        block: DataBlockSA<'a>,
    },
    /// A further block.
    WithDataBlock {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// The block.
        block: DataBlockSA<'a>,
    },
    /// Several attributes, several values.
    WithList {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which attributes.
        descriptors: List<'a, AttributeDescriptorWithSelection<'a>>,
        /// The new values, in the same order.
        values: List<'a, Data<'a>>,
    },
    /// Several attributes whose values start in this block.
    WithListAndFirstDataBlock {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which attributes.
        descriptors: List<'a, AttributeDescriptorWithSelection<'a>>,
        /// The first block of the concatenated values.
        block: DataBlockSA<'a>,
    },
}

impl Encode for SetRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Normal { invoke_id, descriptor, access, value } => {
                w.write_u8(1)?;
                w.write_u8(invoke_id.0)?;
                descriptor.encode(w)?;
                encode_optional(w, access.as_ref())?;
                value.encode(w)
            }
            Self::WithFirstDataBlock { invoke_id, descriptor, access, block } => {
                w.write_u8(2)?;
                w.write_u8(invoke_id.0)?;
                descriptor.encode(w)?;
                encode_optional(w, access.as_ref())?;
                block.encode(w)
            }
            Self::WithDataBlock { invoke_id, block } => {
                w.write_u8(3)?;
                w.write_u8(invoke_id.0)?;
                block.encode(w)
            }
            Self::WithList { invoke_id, descriptors, values } => {
                w.write_u8(4)?;
                w.write_u8(invoke_id.0)?;
                descriptors.encode(w)?;
                values.encode(w)
            }
            Self::WithListAndFirstDataBlock { invoke_id, descriptors, block } => {
                w.write_u8(5)?;
                w.write_u8(invoke_id.0)?;
                descriptors.encode(w)?;
                block.encode(w)
            }
        }
    }
}

impl<'a> Decode<'a> for SetRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let choice = r.u8()?;
        let invoke_id = InvokeId(r.u8()?);
        Ok(match choice {
            1 => Self::Normal {
                invoke_id,
                descriptor: AttributeDescriptor::decode(r)?,
                access: decode_optional(r)?,
                value: Data::decode(r)?,
            },
            2 => Self::WithFirstDataBlock {
                invoke_id,
                descriptor: AttributeDescriptor::decode(r)?,
                access: decode_optional(r)?,
                block: DataBlockSA::decode(r)?,
            },
            3 => Self::WithDataBlock { invoke_id, block: DataBlockSA::decode(r)? },
            4 => Self::WithList { invoke_id, descriptors: List::decode(r)?, values: List::decode(r)? },
            5 => Self::WithListAndFirstDataBlock {
                invoke_id,
                descriptors: List::decode(r)?,
                block: DataBlockSA::decode(r)?,
            },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 2)),
        })
    }
}

/// The answer to a [`SetRequest`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SetResponse<'a> {
    /// One result.
    Normal {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// Whether the write took effect.
        result: DataAccessResult,
    },
    /// A block was accepted; send the next one.
    DataBlock {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// The block just accepted.
        block_number: u32,
    },
    /// The last block was accepted, and here is the outcome.
    LastDataBlock {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// Whether the write took effect.
        result: DataAccessResult,
        /// The last block number.
        block_number: u32,
    },
    /// The last block of a list write.
    LastDataBlockWithList {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// One result per attribute.
        results: List<'a, DataAccessResult>,
        /// The last block number.
        block_number: u32,
    },
    /// A list write with no blocking.
    WithList {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// One result per attribute.
        results: List<'a, DataAccessResult>,
    },
}

impl Encode for SetResponse<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Normal { invoke_id, result } => {
                w.write_u8(1)?;
                w.write_u8(invoke_id.0)?;
                w.write_u8(result.as_u8())
            }
            Self::DataBlock { invoke_id, block_number } => {
                w.write_u8(2)?;
                w.write_u8(invoke_id.0)?;
                w.write_u32(*block_number)
            }
            Self::LastDataBlock { invoke_id, result, block_number } => {
                w.write_u8(3)?;
                w.write_u8(invoke_id.0)?;
                w.write_u8(result.as_u8())?;
                w.write_u32(*block_number)
            }
            Self::LastDataBlockWithList { invoke_id, results, block_number } => {
                w.write_u8(4)?;
                w.write_u8(invoke_id.0)?;
                results.encode(w)?;
                w.write_u32(*block_number)
            }
            Self::WithList { invoke_id, results } => {
                w.write_u8(5)?;
                w.write_u8(invoke_id.0)?;
                results.encode(w)
            }
        }
    }
}

impl<'a> Decode<'a> for SetResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let choice = r.u8()?;
        let invoke_id = InvokeId(r.u8()?);
        Ok(match choice {
            1 => Self::Normal { invoke_id, result: DataAccessResult::from_u8(r.u8()?) },
            2 => Self::DataBlock { invoke_id, block_number: r.u32()? },
            3 => Self::LastDataBlock {
                invoke_id,
                result: DataAccessResult::from_u8(r.u8()?),
                block_number: r.u32()?,
            },
            4 => Self::LastDataBlockWithList { invoke_id, results: List::decode(r)?, block_number: r.u32()? },
            5 => Self::WithList { invoke_id, results: List::decode(r)? },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 2)),
        })
    }
}

/// A method result with its optional return value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ActionResponseWithOptionalData<'a> {
    /// Whether the method ran.
    pub result: ActionResult,
    /// What it returned, if anything.
    pub return_parameters: Option<GetDataResult<'a>>,
}

impl Encode for ActionResponseWithOptionalData<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.result.as_u8())?;
        encode_optional(w, self.return_parameters.as_ref())
    }
}

impl<'a> Decode<'a> for ActionResponseWithOptionalData<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { result: ActionResult::from_u8(r.u8()?), return_parameters: decode_optional(r)? })
    }
}

/// Invoke a method.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActionRequest<'a> {
    /// One method.
    Normal {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which method.
        descriptor: MethodDescriptor,
        /// Its parameter, if it takes one.
        parameters: Option<Data<'a>>,
    },
    /// Ask for the next block of a long return value.
    NextPblock {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// The block just received.
        block_number: u32,
    },
    /// Several methods.
    WithList {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which methods.
        descriptors: List<'a, MethodDescriptor>,
        /// Their parameters, in the same order.
        parameters: List<'a, Data<'a>>,
    },
    /// One method whose parameter starts in this block.
    WithFirstPblock {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which method.
        descriptor: MethodDescriptor,
        /// The first block of the parameter.
        block: DataBlockSA<'a>,
    },
    /// Several methods whose parameters start in this block.
    WithListAndFirstPblock {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// Which methods.
        descriptors: List<'a, MethodDescriptor>,
        /// The first block of the concatenated parameters.
        block: DataBlockSA<'a>,
    },
    /// A further parameter block.
    WithPblock {
        /// Correlates the response.
        invoke_id: InvokeId,
        /// The block.
        block: DataBlockSA<'a>,
    },
}

impl Encode for ActionRequest<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Normal { invoke_id, descriptor, parameters } => {
                w.write_u8(1)?;
                w.write_u8(invoke_id.0)?;
                descriptor.encode(w)?;
                encode_optional(w, parameters.as_ref())
            }
            Self::NextPblock { invoke_id, block_number } => {
                w.write_u8(2)?;
                w.write_u8(invoke_id.0)?;
                w.write_u32(*block_number)
            }
            Self::WithList { invoke_id, descriptors, parameters } => {
                w.write_u8(3)?;
                w.write_u8(invoke_id.0)?;
                descriptors.encode(w)?;
                parameters.encode(w)
            }
            Self::WithFirstPblock { invoke_id, descriptor, block } => {
                w.write_u8(4)?;
                w.write_u8(invoke_id.0)?;
                descriptor.encode(w)?;
                block.encode(w)
            }
            Self::WithListAndFirstPblock { invoke_id, descriptors, block } => {
                w.write_u8(5)?;
                w.write_u8(invoke_id.0)?;
                descriptors.encode(w)?;
                block.encode(w)
            }
            Self::WithPblock { invoke_id, block } => {
                w.write_u8(6)?;
                w.write_u8(invoke_id.0)?;
                block.encode(w)
            }
        }
    }
}

impl<'a> Decode<'a> for ActionRequest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let choice = r.u8()?;
        let invoke_id = InvokeId(r.u8()?);
        Ok(match choice {
            1 => Self::Normal {
                invoke_id,
                descriptor: MethodDescriptor::decode(r)?,
                parameters: decode_optional(r)?,
            },
            2 => Self::NextPblock { invoke_id, block_number: r.u32()? },
            3 => Self::WithList { invoke_id, descriptors: List::decode(r)?, parameters: List::decode(r)? },
            4 => Self::WithFirstPblock {
                invoke_id,
                descriptor: MethodDescriptor::decode(r)?,
                block: DataBlockSA::decode(r)?,
            },
            5 => Self::WithListAndFirstPblock {
                invoke_id,
                descriptors: List::decode(r)?,
                block: DataBlockSA::decode(r)?,
            },
            6 => Self::WithPblock { invoke_id, block: DataBlockSA::decode(r)? },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 2)),
        })
    }
}

/// The answer to an [`ActionRequest`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActionResponse<'a> {
    /// One result.
    Normal {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// The outcome and any return value.
        response: ActionResponseWithOptionalData<'a>,
    },
    /// One block of a long return value.
    WithPblock {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// The block.
        block: DataBlockSA<'a>,
    },
    /// Several results.
    WithList {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// One per method, in order.
        responses: List<'a, ActionResponseWithOptionalData<'a>>,
    },
    /// The next block was requested and here it is.
    NextPblock {
        /// Echoes the request.
        invoke_id: InvokeId,
        /// The block just sent.
        block_number: u32,
    },
}

impl Encode for ActionResponse<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Normal { invoke_id, response } => {
                w.write_u8(1)?;
                w.write_u8(invoke_id.0)?;
                response.encode(w)
            }
            Self::WithPblock { invoke_id, block } => {
                w.write_u8(2)?;
                w.write_u8(invoke_id.0)?;
                block.encode(w)
            }
            Self::WithList { invoke_id, responses } => {
                w.write_u8(3)?;
                w.write_u8(invoke_id.0)?;
                responses.encode(w)
            }
            Self::NextPblock { invoke_id, block_number } => {
                w.write_u8(4)?;
                w.write_u8(invoke_id.0)?;
                w.write_u32(*block_number)
            }
        }
    }
}

impl<'a> Decode<'a> for ActionResponse<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let choice = r.u8()?;
        let invoke_id = InvokeId(r.u8()?);
        Ok(match choice {
            1 => Self::Normal { invoke_id, response: ActionResponseWithOptionalData::decode(r)? },
            2 => Self::WithPblock { invoke_id, block: DataBlockSA::decode(r)? },
            3 => Self::WithList { invoke_id, responses: List::decode(r)? },
            4 => Self::NextPblock { invoke_id, block_number: r.u32()? },
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 2)),
        })
    }
}
