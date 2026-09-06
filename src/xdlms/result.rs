//! Service results and data blocks.

use crate::axdr::Data;
use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

macro_rules! result_enum {
    ($(#[$m:meta])* $name:ident { $($code:literal $variant:ident $doc:literal,)* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum $name {
            $(
                #[doc = $doc]
                $variant,
            )*
            /// A code this crate does not name. Preserved rather than rejected: a server
            /// may report something a later edition defines, and turning that into a
            /// parse error would lose the only diagnostic the caller has.
            Other(u8),
        }

        impl $name {
            /// From the wire byte.
            #[must_use]
            pub const fn from_u8(v: u8) -> Self {
                match v {
                    $($code => Self::$variant,)*
                    other => Self::Other(other),
                }
            }

            /// The wire byte.
            #[must_use]
            pub const fn as_u8(self) -> u8 {
                match self {
                    $(Self::$variant => $code,)*
                    Self::Other(v) => v,
                }
            }

            /// True only for success.
            #[must_use]
            pub const fn is_success(self) -> bool {
                matches!(self, Self::Success)
            }

            /// The result as a `core::result::Result`, so `?` works on it.
            ///
            /// # Errors
            /// Returns `self` when it is not [`Self::Success`].
            pub const fn ok(self) -> core::result::Result<(), Self> {
                if self.is_success() { Ok(()) } else { Err(self) }
            }
        }
    };
}

result_enum! {
    /// Why a GET or SET did not return a value.
    DataAccessResult {
        0 Success "The attribute was read or written.",
        1 HardwareFault "The meter's hardware could not serve the request.",
        2 TemporaryFailure "Try again later.",
        3 ReadWriteDenied "The association's access rights forbid this.",
        4 ObjectUndefined "No object with that logical name and class.",
        9 ObjectClassInconsistent "The class id does not match the object with that name.",
        11 ObjectUnavailable "The object exists but is not accessible now.",
        12 TypeUnmatched "The value's type is not the attribute's type.",
        13 ScopeOfAccessViolated "Outside the range this association may address.",
        14 DataBlockUnavailable "The requested block is gone.",
        15 LongGetAborted "The block transfer was abandoned.",
        16 NoLongGetInProgress "There is no block transfer to continue.",
        17 LongSetAborted "The block transfer was abandoned.",
        18 NoLongSetInProgress "There is no block transfer to continue.",
        19 DataBlockNumberInvalid "The block number is not the expected one.",
        250 OtherReason "Unspecified.",
    }
}

result_enum! {
    /// Why a method invocation did not succeed.
    ActionResult {
        0 Success "The method ran.",
        1 HardwareFault "The meter's hardware could not serve the request.",
        2 TemporaryFailure "Try again later.",
        3 ReadWriteDenied "The association's access rights forbid this.",
        4 ObjectUndefined "No object with that logical name and class.",
        9 ObjectClassInconsistent "The class id does not match the object with that name.",
        11 ObjectUnavailable "The object exists but is not accessible now.",
        12 TypeUnmatched "The parameter's type is not the method's type.",
        13 ScopeOfAccessViolated "Outside the range this association may address.",
        14 DataBlockUnavailable "The requested block is gone.",
        15 LongActionAborted "The block transfer was abandoned.",
        16 NoLongActionInProgress "There is no block transfer to continue.",
        250 OtherReason "Unspecified.",
    }
}

/// A value, or the reason there is none.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetDataResult<'a> {
    /// The value.
    Data(Data<'a>),
    /// Why there is none.
    Error(DataAccessResult),
}

impl<'a> GetDataResult<'a> {
    /// The value, turning an error result into an `Err`.
    ///
    /// # Errors
    /// Returns the [`DataAccessResult`] when the server refused.
    pub const fn value(self) -> core::result::Result<Data<'a>, DataAccessResult> {
        match self {
            Self::Data(d) => Ok(d),
            Self::Error(e) => Err(e),
        }
    }
}

impl Encode for GetDataResult<'_> {
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
        }
    }
}

impl<'a> Decode<'a> for GetDataResult<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        match r.u8()? {
            0 => Ok(Self::Data(Data::decode(r)?)),
            1 => Ok(Self::Error(DataAccessResult::from_u8(r.u8()?))),
            other => Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        }
    }
}

/// A block of a long GET response.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataBlockG<'a> {
    /// True when this is the last block.
    pub last_block: bool,
    /// The block number, counting from one.
    pub block_number: u32,
    /// The block's payload, or why there is none.
    pub result: core::result::Result<&'a [u8], DataAccessResult>,
}

impl Encode for DataBlockG<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(u8::from(self.last_block))?;
        w.write_u32(self.block_number)?;
        match self.result {
            Ok(raw) => {
                w.write_u8(0)?;
                w.write_length_prefixed(raw)
            }
            Err(e) => {
                w.write_u8(1)?;
                w.write_u8(e.as_u8())
            }
        }
    }
}

impl<'a> Decode<'a> for DataBlockG<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let last_block = r.u8()? != 0;
        let block_number = r.u32()?;
        let result = match r.u8()? {
            0 => Ok(r.length_prefixed()?),
            1 => Err(DataAccessResult::from_u8(r.u8()?)),
            other => return Err(r.err_back(ErrorKind::InvalidTag(other), 1)),
        };
        Ok(Self { last_block, block_number, result })
    }
}

/// A block of a long SET request or an ACTION parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBlockSA<'a> {
    /// True when this is the last block.
    pub last_block: bool,
    /// The block number, counting from one.
    pub block_number: u32,
    /// The block's payload.
    pub raw_data: &'a [u8],
}

impl Encode for DataBlockSA<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(u8::from(self.last_block))?;
        w.write_u32(self.block_number)?;
        w.write_length_prefixed(self.raw_data)
    }
}

impl<'a> Decode<'a> for DataBlockSA<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { last_block: r.u8()? != 0, block_number: r.u32()?, raw_data: r.length_prefixed()? })
    }
}

/// A sequence of values with an A-XDR count in front, kept borrowed.
///
/// The elements are validated when the list is decoded and re-parsed when iterated,
/// which is the same trade [`crate::axdr::Seq`] makes and for the same reason.
#[derive(Debug, Clone, Copy)]
pub struct List<'a, T> {
    count: usize,
    raw: &'a [u8],
    /// Where these bytes started in the frame. Diagnostic only — it is what makes an
    /// error inside an element point at the right byte of the whole APDU.
    base: usize,
    _marker: core::marker::PhantomData<fn() -> T>,
}

/// Two lists are equal when they hold the same elements.
///
/// Written by hand for the same reason [`crate::axdr::Seq`]'s is: `base` says where the
/// bytes came from, not what they say, and deriving over it made an otherwise identical
/// `get-response-with-list` compare unequal to itself after a round trip.
impl<T> PartialEq for List<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count && self.raw == other.raw
    }
}

impl<T> Eq for List<'_, T> {}

impl<'a, T: Decode<'a>> List<'a, T> {
    /// How many elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The encoded elements.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Iterate the elements.
    pub fn iter(&self) -> impl Iterator<Item = Result<T>> + 'a {
        let mut r = Reader::with_base(self.raw, self.base);
        let mut left = self.count;
        core::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            left -= 1;
            Some(T::decode(&mut r))
        })
    }

    /// Build a list from elements already encoded elsewhere.
    #[must_use]
    pub const fn from_raw(count: usize, raw: &'a [u8]) -> Self {
        Self { count, raw, base: 0, _marker: core::marker::PhantomData }
    }
}

impl<'a, T: Decode<'a>> Decode<'a> for List<'a, T> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let count = r.length()?;
        let base = r.offset();
        let mut probe = Reader::with_base(r.rest(), base);
        for _ in 0..count {
            T::decode(&mut probe)?;
        }
        let raw = r.take(probe.offset() - base)?;
        Ok(Self { count, raw, base, _marker: core::marker::PhantomData })
    }
}

impl<T> Encode for List<'_, T> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_length(self.count)?;
        w.write_bytes(self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn results_round_trip_including_unnamed_codes() {
        for v in 0u8..=255 {
            assert_eq!(DataAccessResult::from_u8(v).as_u8(), v);
            assert_eq!(ActionResult::from_u8(v).as_u8(), v);
        }
        assert_eq!(DataAccessResult::from_u8(200), DataAccessResult::Other(200));
    }

    #[test]
    fn only_zero_is_success() {
        assert!(DataAccessResult::Success.is_success());
        assert!(!DataAccessResult::ReadWriteDenied.is_success());
        assert!(DataAccessResult::Success.ok().is_ok());
        assert_eq!(DataAccessResult::ObjectUndefined.ok().unwrap_err(), DataAccessResult::ObjectUndefined);
    }

    #[test]
    fn get_data_result_discriminates_a_value_from_a_refusal() {
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        GetDataResult::Error(DataAccessResult::ReadWriteDenied).encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [1, 3]);
        let decoded = GetDataResult::from_bytes(&[1, 3]).unwrap();
        assert_eq!(decoded, GetDataResult::Error(DataAccessResult::ReadWriteDenied));
        assert!(decoded.value().is_err());
    }

    #[test]
    fn a_data_block_carries_its_number_and_last_flag() {
        let b = DataBlockG { last_block: false, block_number: 2, result: Ok(&[0xAA, 0xBB]) };
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        b.encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0, 0, 0, 0, 2, 0, 2, 0xAA, 0xBB]);
        assert_eq!(DataBlockG::from_bytes(w.as_slice()).unwrap(), b);
    }

    #[test]
    fn a_list_validates_every_element_before_it_is_iterated() {
        // Two attribute descriptors, count-prefixed.
        let raw = [
            2u8, //
            0x00, 0x03, 1, 0, 1, 8, 0, 255, 2, 0, //
            0x00, 0x08, 0, 0, 1, 0, 0, 255, 2, 0,
        ];
        let list: List<'_, super::super::AttributeDescriptorWithSelection<'_>> =
            List::from_bytes(&raw).unwrap();
        assert_eq!(list.len(), 2);
        let items: alloc::vec::Vec<_> = list.iter().map(|d| d.unwrap().descriptor.class_id).collect();
        assert_eq!(items, [3, 8]);
    }

    #[test]
    fn a_list_whose_elements_do_not_parse_fails_at_decode() {
        let raw = [2u8, 0x00, 0x03, 1, 0, 1, 8, 0, 255, 2, 0];
        let e = List::<'_, super::super::AttributeDescriptorWithSelection<'_>>::from_bytes(&raw).unwrap_err();
        assert!(e.is_truncated());
    }
}
