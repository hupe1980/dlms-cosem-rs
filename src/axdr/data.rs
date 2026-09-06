//! The A-XDR `Data` type.

use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, Writer};

use super::{CompactArray, Date, DateTime, Time};

/// The deepest nesting a decoder will follow before refusing.
///
/// Structures nest legitimately — a profile buffer is an array of structures, and a
/// capture-object entry is a structure inside it — but nothing in the Blue Book nests
/// anywhere near this deep, and unbounded recursion on attacker-controlled input is how
/// a decoder is turned into a stack overflow.
pub const MAX_DEPTH: u8 = 16;

/// The tag byte that introduces a value.
///
/// Every variant is a tag the Blue Book defines. An unknown tag is refused rather than
/// skipped: without a length, an unknown value cannot be stepped over safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum DataTag {
    NullData = 0,
    Array = 1,
    Structure = 2,
    Boolean = 3,
    BitString = 4,
    DoubleLong = 5,
    DoubleLongUnsigned = 6,
    OctetString = 9,
    VisibleString = 10,
    Utf8String = 12,
    Bcd = 13,
    Integer = 15,
    Long = 16,
    Unsigned = 17,
    LongUnsigned = 18,
    CompactArray = 19,
    Long64 = 20,
    Long64Unsigned = 21,
    Enum = 22,
    Float32 = 23,
    Float64 = 24,
    DateTime = 25,
    Date = 26,
    Time = 27,
    DeltaInteger = 28,
    DeltaLong = 29,
    DeltaDoubleLong = 30,
    DeltaUnsigned = 31,
    DeltaLongUnsigned = 32,
    DeltaDoubleLongUnsigned = 33,
    DontCare = 255,
}

impl DataTag {
    /// Classify a tag byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::NullData,
            1 => Self::Array,
            2 => Self::Structure,
            3 => Self::Boolean,
            4 => Self::BitString,
            5 => Self::DoubleLong,
            6 => Self::DoubleLongUnsigned,
            9 => Self::OctetString,
            10 => Self::VisibleString,
            12 => Self::Utf8String,
            13 => Self::Bcd,
            15 => Self::Integer,
            16 => Self::Long,
            17 => Self::Unsigned,
            18 => Self::LongUnsigned,
            19 => Self::CompactArray,
            20 => Self::Long64,
            21 => Self::Long64Unsigned,
            22 => Self::Enum,
            23 => Self::Float32,
            24 => Self::Float64,
            25 => Self::DateTime,
            26 => Self::Date,
            27 => Self::Time,
            28 => Self::DeltaInteger,
            29 => Self::DeltaLong,
            30 => Self::DeltaDoubleLong,
            31 => Self::DeltaUnsigned,
            32 => Self::DeltaLongUnsigned,
            33 => Self::DeltaDoubleLongUnsigned,
            255 => Self::DontCare,
            _ => return None,
        })
    }

    /// The tag byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The fixed encoded length of the value body, for tags that have one.
    ///
    /// `None` for the variable-length tags: strings, arrays, structures, bit strings and
    /// compact arrays.
    #[must_use]
    pub const fn fixed_len(self) -> Option<usize> {
        Some(match self {
            Self::NullData | Self::DontCare => 0,
            Self::Boolean
            | Self::Bcd
            | Self::Integer
            | Self::Unsigned
            | Self::Enum
            | Self::DeltaInteger
            | Self::DeltaUnsigned => 1,
            Self::Long | Self::LongUnsigned | Self::DeltaLong | Self::DeltaLongUnsigned => 2,
            Self::DoubleLong
            | Self::DoubleLongUnsigned
            | Self::Float32
            | Self::DeltaDoubleLong
            | Self::DeltaDoubleLongUnsigned => 4,
            Self::Time => 4,
            Self::Date => 5,
            Self::Long64 | Self::Long64Unsigned | Self::Float64 => 8,
            Self::DateTime => 12,
            _ => return None,
        })
    }

    /// True for one of the six delta types added in Green Book edition 10.
    #[must_use]
    pub const fn is_delta(self) -> bool {
        matches!(
            self,
            Self::DeltaInteger
                | Self::DeltaLong
                | Self::DeltaDoubleLong
                | Self::DeltaUnsigned
                | Self::DeltaLongUnsigned
                | Self::DeltaDoubleLongUnsigned
        )
    }
}

/// A bit string: a bit count and the bytes holding it, most significant bit first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitStr<'a> {
    bits: usize,
    bytes: &'a [u8],
}

impl<'a> BitStr<'a> {
    /// A bit string over `bytes`, of which the first `bits` are significant.
    pub fn new(bits: usize, bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != bits.div_ceil(8) {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        }
        Ok(Self { bits, bytes })
    }

    /// The number of significant bits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bits
    }

    /// True when there are no bits.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// The backing bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Bit `i`, counting from the most significant bit of the first byte — which is how
    /// the Blue Book numbers them, and the opposite of the usual little-endian habit.
    #[must_use]
    pub fn bit(&self, i: usize) -> bool {
        if i >= self.bits {
            return false;
        }
        self.bytes[i / 8] & (0x80 >> (i % 8)) != 0
    }

    /// The bits as a big-endian integer, most significant bit first.
    ///
    /// The conformance block and the version-3 access-right masks are bit strings that
    /// are used as integers; this is the conversion, and it saturates rather than
    /// wrapping for a longer string than `u32` can hold.
    #[must_use]
    pub fn to_u32(&self) -> u32 {
        let mut v = 0u32;
        for i in 0..self.bits.min(32) {
            v = (v << 1) | u32::from(self.bit(i));
        }
        v
    }
}

/// A borrowed array or structure: an element count and the bytes they live in.
///
/// Elements are validated when the sequence is decoded — every one is walked to find
/// where the sequence ends — and re-parsed when iterated. That is one extra pass over
/// the bytes in exchange for never allocating and never holding an index table.
#[derive(Debug, Clone, Copy)]
pub struct Seq<'a> {
    count: usize,
    raw: &'a [u8],
    /// Where these bytes started in the frame they were decoded from. Diagnostic only:
    /// it is what makes an error inside the sequence point at the right byte.
    base: usize,
    /// How deep this sequence sits, so its children inherit the remaining budget.
    depth: u8,
}

/// Two sequences are equal when they hold the same elements.
///
/// Written by hand rather than derived, because `base` and `depth` describe *where the
/// bytes came from* and not what they say. The derived version made an array decoded at
/// offset 3 unequal to the identical array decoded at offset 0 — so comparing two APDUs,
/// deduplicating readings, or asserting a round trip all reported differences that were
/// not there.
impl PartialEq for Seq<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count && self.raw == other.raw
    }
}

impl Eq for Seq<'_> {}

impl<'a> Seq<'a> {
    /// The number of elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// True when there are no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The encoded elements, tags included.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Iterate the elements.
    #[must_use]
    pub fn iter(&self) -> SeqIter<'a> {
        SeqIter { reader: Reader::with_base(self.raw, self.base), left: self.count, depth: self.depth }
    }

    /// The element at `index`, decoded by walking from the start.
    ///
    /// `O(index)`. For a structure of a handful of fields — which is what the Blue Book
    /// defines — that is cheaper than any index this could have built instead.
    pub fn get(&self, index: usize) -> Result<Data<'a>> {
        self.iter().nth(index).ok_or_else(|| Error::new(ErrorKind::InvalidLength, self.base))?
    }
}

impl<'a> IntoIterator for &Seq<'a> {
    type Item = Result<Data<'a>>;
    type IntoIter = SeqIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over the elements of a [`Seq`].
#[derive(Debug, Clone)]
pub struct SeqIter<'a> {
    reader: Reader<'a>,
    left: usize,
    depth: u8,
}

impl<'a> Iterator for SeqIter<'a> {
    type Item = Result<Data<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        Some(Data::decode_at(&mut self.reader, self.depth))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for SeqIter<'_> {}

/// A value, borrowed from the buffer it was decoded out of.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub enum Data<'a> {
    /// No value. In a profile buffer with null-data compression it also means
    /// "unchanged from the previous row".
    Null,
    Array(Seq<'a>),
    Structure(Seq<'a>),
    Boolean(bool),
    BitString(BitStr<'a>),
    DoubleLong(i32),
    DoubleLongUnsigned(u32),
    OctetString(&'a [u8]),
    /// An ISO 646 string. Not validated as UTF-8 — meters put arbitrary bytes here.
    VisibleString(&'a [u8]),
    /// Bytes tagged as UTF-8. Validated on access through [`Data::as_str`], not on decode.
    Utf8String(&'a [u8]),
    Bcd(i8),
    Integer(i8),
    Long(i16),
    Unsigned(u8),
    LongUnsigned(u16),
    CompactArray(CompactArray<'a>),
    Long64(i64),
    Long64Unsigned(u64),
    Enum(u8),
    Float32(f32),
    Float64(f64),
    DateTime(DateTime),
    Date(Date),
    Time(Time),
    DeltaInteger(i8),
    DeltaLong(i16),
    DeltaDoubleLong(i32),
    DeltaUnsigned(u8),
    DeltaLongUnsigned(u16),
    DeltaDoubleLongUnsigned(u32),
    /// A wildcard used in access descriptors to mean "any".
    DontCare,
}

impl<'a> Data<'a> {
    /// The tag this value encodes with.
    #[must_use]
    pub const fn tag(&self) -> DataTag {
        match self {
            Self::Null => DataTag::NullData,
            Self::Array(_) => DataTag::Array,
            Self::Structure(_) => DataTag::Structure,
            Self::Boolean(_) => DataTag::Boolean,
            Self::BitString(_) => DataTag::BitString,
            Self::DoubleLong(_) => DataTag::DoubleLong,
            Self::DoubleLongUnsigned(_) => DataTag::DoubleLongUnsigned,
            Self::OctetString(_) => DataTag::OctetString,
            Self::VisibleString(_) => DataTag::VisibleString,
            Self::Utf8String(_) => DataTag::Utf8String,
            Self::Bcd(_) => DataTag::Bcd,
            Self::Integer(_) => DataTag::Integer,
            Self::Long(_) => DataTag::Long,
            Self::Unsigned(_) => DataTag::Unsigned,
            Self::LongUnsigned(_) => DataTag::LongUnsigned,
            Self::CompactArray(_) => DataTag::CompactArray,
            Self::Long64(_) => DataTag::Long64,
            Self::Long64Unsigned(_) => DataTag::Long64Unsigned,
            Self::Enum(_) => DataTag::Enum,
            Self::Float32(_) => DataTag::Float32,
            Self::Float64(_) => DataTag::Float64,
            Self::DateTime(_) => DataTag::DateTime,
            Self::Date(_) => DataTag::Date,
            Self::Time(_) => DataTag::Time,
            Self::DeltaInteger(_) => DataTag::DeltaInteger,
            Self::DeltaLong(_) => DataTag::DeltaLong,
            Self::DeltaDoubleLong(_) => DataTag::DeltaDoubleLong,
            Self::DeltaUnsigned(_) => DataTag::DeltaUnsigned,
            Self::DeltaLongUnsigned(_) => DataTag::DeltaLongUnsigned,
            Self::DeltaDoubleLongUnsigned(_) => DataTag::DeltaDoubleLongUnsigned,
            Self::DontCare => DataTag::DontCare,
        }
    }

    /// Decode one value with the depth budget already spent by enclosing sequences.
    fn decode_at(r: &mut Reader<'a>, depth: u8) -> Result<Self> {
        if depth >= MAX_DEPTH {
            return Err(r.err(ErrorKind::DepthExceeded));
        }
        let tag_byte = r.u8()?;
        let tag = DataTag::from_u8(tag_byte).ok_or_else(|| r.err_back(ErrorKind::InvalidTag(tag_byte), 1))?;
        Ok(match tag {
            DataTag::NullData => Self::Null,
            DataTag::DontCare => Self::DontCare,
            DataTag::Array | DataTag::Structure => {
                let count = r.length()?;
                let start = r.offset();
                let before = r.rest();
                let mut probe = Reader::with_base(before, start);
                for _ in 0..count {
                    Self::skip(&mut probe, depth + 1)?;
                }
                let used = probe.offset() - start;
                let raw = r.take(used)?;
                let seq = Seq { count, raw, base: start, depth: depth + 1 };
                if tag == DataTag::Array { Self::Array(seq) } else { Self::Structure(seq) }
            }
            DataTag::Boolean => Self::Boolean(r.u8()? != 0),
            DataTag::BitString => {
                let bits = r.length()?;
                let bytes = r.take(bits.div_ceil(8))?;
                Self::BitString(BitStr { bits, bytes })
            }
            DataTag::DoubleLong => Self::DoubleLong(r.i32()?),
            DataTag::DoubleLongUnsigned => Self::DoubleLongUnsigned(r.u32()?),
            DataTag::OctetString => Self::OctetString(r.length_prefixed()?),
            DataTag::VisibleString => Self::VisibleString(r.length_prefixed()?),
            DataTag::Utf8String => Self::Utf8String(r.length_prefixed()?),
            DataTag::Bcd => Self::Bcd(r.i8()?),
            DataTag::Integer => Self::Integer(r.i8()?),
            DataTag::Long => Self::Long(r.i16()?),
            DataTag::Unsigned => Self::Unsigned(r.u8()?),
            DataTag::LongUnsigned => Self::LongUnsigned(r.u16()?),
            DataTag::CompactArray => Self::CompactArray(CompactArray::decode_body(r, depth + 1)?),
            DataTag::Long64 => Self::Long64(r.i64()?),
            DataTag::Long64Unsigned => Self::Long64Unsigned(r.u64()?),
            DataTag::Enum => Self::Enum(r.u8()?),
            DataTag::Float32 => Self::Float32(f32::from_bits(r.u32()?)),
            DataTag::Float64 => Self::Float64(f64::from_bits(r.u64()?)),
            DataTag::DateTime => Self::DateTime(DateTime::from_bytes(r.array()?)),
            DataTag::Date => Self::Date(Date::from_bytes(r.array()?)),
            DataTag::Time => Self::Time(Time::from_bytes(r.array()?)),
            DataTag::DeltaInteger => Self::DeltaInteger(r.i8()?),
            DataTag::DeltaLong => Self::DeltaLong(r.i16()?),
            DataTag::DeltaDoubleLong => Self::DeltaDoubleLong(r.i32()?),
            DataTag::DeltaUnsigned => Self::DeltaUnsigned(r.u8()?),
            DataTag::DeltaLongUnsigned => Self::DeltaLongUnsigned(r.u16()?),
            DataTag::DeltaDoubleLongUnsigned => Self::DeltaDoubleLongUnsigned(r.u32()?),
        })
    }

    /// Walk one value without building it, to find where it ends.
    fn skip(r: &mut Reader<'a>, depth: u8) -> Result<()> {
        if depth >= MAX_DEPTH {
            return Err(r.err(ErrorKind::DepthExceeded));
        }
        let tag_byte = r.u8()?;
        let tag = DataTag::from_u8(tag_byte).ok_or_else(|| r.err_back(ErrorKind::InvalidTag(tag_byte), 1))?;
        if let Some(n) = tag.fixed_len() {
            return r.skip(n);
        }
        match tag {
            DataTag::Array | DataTag::Structure => {
                let count = r.length()?;
                for _ in 0..count {
                    Self::skip(r, depth + 1)?;
                }
                Ok(())
            }
            DataTag::BitString => {
                let bits = r.length()?;
                r.skip(bits.div_ceil(8))
            }
            DataTag::OctetString | DataTag::VisibleString | DataTag::Utf8String => {
                let n = r.length()?;
                r.skip(n)
            }
            DataTag::CompactArray => CompactArray::skip_body(r, depth + 1),
            _ => Err(r.err(ErrorKind::InvalidTag(tag_byte))),
        }
    }

    /// The value as an integer, for any of the signed or unsigned integer tags.
    ///
    /// Returns `None` for a value that is not an integer, and for a `u64` that does not
    /// fit in an `i128`'s positive range — which cannot happen, and is written as a
    /// conversion rather than a cast so that it stays impossible.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        Some(match *self {
            Self::Integer(v) | Self::DeltaInteger(v) => i64::from(v),
            Self::Long(v) | Self::DeltaLong(v) => i64::from(v),
            Self::DoubleLong(v) | Self::DeltaDoubleLong(v) => i64::from(v),
            Self::Long64(v) => v,
            Self::Unsigned(v) | Self::DeltaUnsigned(v) => i64::from(v),
            Self::LongUnsigned(v) | Self::DeltaLongUnsigned(v) => i64::from(v),
            Self::DoubleLongUnsigned(v) | Self::DeltaDoubleLongUnsigned(v) => i64::from(v),
            Self::Long64Unsigned(v) => i64::try_from(v).ok()?,
            Self::Enum(v) => i64::from(v),
            _ => return None,
        })
    }

    /// The value as an unsigned integer, when it is one and is not negative.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::Long64Unsigned(v) => Some(v),
            _ => u64::try_from(self.as_i64()?).ok(),
        }
    }

    /// The decimal value of a binary-coded-decimal byte.
    ///
    /// `bcd` is *not* an integer, and this is deliberately not part of
    /// [`Data::as_i64`]: the byte `0x25` is the number twenty-five, and reading it as an
    /// integer gives thirty-seven. Both are plausible-looking meter readings, which is
    /// what makes the confusion expensive — so a caller has to say which one it means.
    ///
    /// `None` when either nibble is not a decimal digit.
    #[must_use]
    pub const fn as_bcd(&self) -> Option<u8> {
        let Self::Bcd(v) = *self else {
            return None;
        };
        let b = v as u8;
        let (high, low) = (b >> 4, b & 0x0F);
        if high > 9 || low > 9 {
            return None;
        }
        Some(high * 10 + low)
    }

    /// The value as a `bool`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match *self {
            Self::Boolean(v) => Some(v),
            _ => None,
        }
    }

    /// The bytes of an octet string or either string type.
    #[must_use]
    pub const fn as_bytes(&self) -> Option<&'a [u8]> {
        match *self {
            Self::OctetString(b) | Self::VisibleString(b) | Self::Utf8String(b) => Some(b),
            _ => None,
        }
    }

    /// A string value, validated as UTF-8 here rather than at decode time.
    #[must_use]
    pub fn as_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.as_bytes()?).ok()
    }

    /// The elements of an array or structure.
    #[must_use]
    pub const fn as_seq(&self) -> Option<Seq<'a>> {
        match *self {
            Self::Array(s) | Self::Structure(s) => Some(s),
            _ => None,
        }
    }

    /// The elements of a structure, refusing an array.
    ///
    /// A structure is a record with a fixed shape and an array is a repetition; a
    /// decoder that accepts either where the specification says one is how a field gets
    /// read out of the wrong position.
    #[must_use]
    pub const fn as_structure(&self) -> Option<Seq<'a>> {
        match *self {
            Self::Structure(s) => Some(s),
            _ => None,
        }
    }

    /// The elements of an array, refusing a structure.
    #[must_use]
    pub const fn as_array(&self) -> Option<Seq<'a>> {
        match *self {
            Self::Array(s) => Some(s),
            _ => None,
        }
    }

    /// Field `index` of a structure.
    pub fn field(&self, index: usize) -> Result<Data<'a>> {
        self.as_structure().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?.get(index)
    }

    /// A six-byte octet string read as a logical name.
    #[must_use]
    pub fn as_obis(&self) -> Option<crate::obis::Obis> {
        let b: [u8; 6] = self.as_bytes()?.try_into().ok()?;
        Some(crate::obis::Obis(b))
    }

    /// True for one of the six delta types.
    #[must_use]
    pub const fn is_delta(&self) -> bool {
        self.tag().is_delta()
    }
}

impl Encode for Data<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.tag().as_u8())?;
        match self {
            Self::Null | Self::DontCare => Ok(()),
            Self::Array(s) | Self::Structure(s) => {
                w.write_length(s.len())?;
                w.write_bytes(s.as_bytes())
            }
            Self::Boolean(v) => w.write_u8(u8::from(*v)),
            Self::BitString(b) => {
                w.write_length(b.len())?;
                w.write_bytes(b.as_bytes())
            }
            Self::DoubleLong(v) => w.write_u32(*v as u32),
            Self::DoubleLongUnsigned(v) => w.write_u32(*v),
            Self::OctetString(b) | Self::VisibleString(b) | Self::Utf8String(b) => w.write_length_prefixed(b),
            Self::Bcd(v) | Self::Integer(v) | Self::DeltaInteger(v) => w.write_u8(*v as u8),
            Self::Long(v) | Self::DeltaLong(v) => w.write_u16(*v as u16),
            Self::Unsigned(v) | Self::Enum(v) | Self::DeltaUnsigned(v) => w.write_u8(*v),
            Self::LongUnsigned(v) | Self::DeltaLongUnsigned(v) => w.write_u16(*v),
            Self::CompactArray(c) => c.encode_body(w),
            Self::Long64(v) => w.write_u64(*v as u64),
            Self::Long64Unsigned(v) => w.write_u64(*v),
            Self::Float32(v) => w.write_u32(v.to_bits()),
            Self::Float64(v) => w.write_u64(v.to_bits()),
            Self::DateTime(v) => w.write_bytes(&v.to_bytes()),
            Self::Date(v) => w.write_bytes(&v.to_bytes()),
            Self::Time(v) => w.write_bytes(&v.to_bytes()),
            Self::DeltaDoubleLong(v) => w.write_u32(*v as u32),
            Self::DeltaDoubleLongUnsigned(v) => w.write_u32(*v),
        }
    }
}

impl<'a> Decode<'a> for Data<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Self::decode_at(r, 0)
    }
}

impl<'a> Data<'a> {
    /// Decode a value that borrows `bytes`, requiring all of them to be used.
    ///
    /// The same as [`Decode::from_bytes`], named so it can be called where the lifetime
    /// of the buffer, rather than of a reader, is what matters.
    pub fn from_bytes_in(bytes: &'a [u8]) -> Result<Self> {
        <Self as Decode<'a>>::from_bytes(bytes)
    }
}

/// An owned `Data` tree.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum DataBuf {
    Null,
    Array(alloc::vec::Vec<DataBuf>),
    Structure(alloc::vec::Vec<DataBuf>),
    Boolean(bool),
    BitString {
        /// Significant bits.
        bits: usize,
        /// Backing bytes.
        bytes: alloc::vec::Vec<u8>,
    },
    DoubleLong(i32),
    DoubleLongUnsigned(u32),
    OctetString(alloc::vec::Vec<u8>),
    VisibleString(alloc::vec::Vec<u8>),
    Utf8String(alloc::vec::Vec<u8>),
    Bcd(i8),
    Integer(i8),
    Long(i16),
    Unsigned(u8),
    LongUnsigned(u16),
    Long64(i64),
    Long64Unsigned(u64),
    Enum(u8),
    Float32(f32),
    Float64(f64),
    DateTime(DateTime),
    Date(Date),
    Time(Time),
    DeltaInteger(i8),
    DeltaLong(i16),
    DeltaDoubleLong(i32),
    DeltaUnsigned(u8),
    DeltaLongUnsigned(u16),
    DeltaDoubleLongUnsigned(u32),
    DontCare,
}

#[cfg(feature = "alloc")]
impl DataBuf {
    /// Copy a borrowed value into an owned one.
    ///
    /// A compact array is expanded into an array of its rows, because the compact
    /// encoding is a transfer syntax rather than a distinct type.
    pub fn from_data(d: &Data<'_>) -> Result<Self> {
        use alloc::vec::Vec;
        Ok(match *d {
            Data::Null => Self::Null,
            Data::DontCare => Self::DontCare,
            Data::Array(s) => {
                Self::Array(s.iter().map(|e| Self::from_data(&e?)).collect::<Result<Vec<_>>>()?)
            }
            Data::Structure(s) => {
                Self::Structure(s.iter().map(|e| Self::from_data(&e?)).collect::<Result<Vec<_>>>()?)
            }
            Data::Boolean(v) => Self::Boolean(v),
            Data::BitString(b) => Self::BitString { bits: b.len(), bytes: b.as_bytes().to_vec() },
            Data::DoubleLong(v) => Self::DoubleLong(v),
            Data::DoubleLongUnsigned(v) => Self::DoubleLongUnsigned(v),
            Data::OctetString(b) => Self::OctetString(b.to_vec()),
            Data::VisibleString(b) => Self::VisibleString(b.to_vec()),
            Data::Utf8String(b) => Self::Utf8String(b.to_vec()),
            Data::Bcd(v) => Self::Bcd(v),
            Data::Integer(v) => Self::Integer(v),
            Data::Long(v) => Self::Long(v),
            Data::Unsigned(v) => Self::Unsigned(v),
            Data::LongUnsigned(v) => Self::LongUnsigned(v),
            Data::CompactArray(c) => Self::Array(c.to_rows()?),
            Data::Long64(v) => Self::Long64(v),
            Data::Long64Unsigned(v) => Self::Long64Unsigned(v),
            Data::Enum(v) => Self::Enum(v),
            Data::Float32(v) => Self::Float32(v),
            Data::Float64(v) => Self::Float64(v),
            Data::DateTime(v) => Self::DateTime(v),
            Data::Date(v) => Self::Date(v),
            Data::Time(v) => Self::Time(v),
            Data::DeltaInteger(v) => Self::DeltaInteger(v),
            Data::DeltaLong(v) => Self::DeltaLong(v),
            Data::DeltaDoubleLong(v) => Self::DeltaDoubleLong(v),
            Data::DeltaUnsigned(v) => Self::DeltaUnsigned(v),
            Data::DeltaLongUnsigned(v) => Self::DeltaLongUnsigned(v),
            Data::DeltaDoubleLongUnsigned(v) => Self::DeltaDoubleLongUnsigned(v),
        })
    }

    /// Decode an owned value from bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::from_data(&Data::from_bytes(bytes)?)
    }
}

#[cfg(feature = "alloc")]
impl Encode for DataBuf {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        let tag = match self {
            Self::Null => 0,
            Self::Array(_) => 1,
            Self::Structure(_) => 2,
            Self::Boolean(_) => 3,
            Self::BitString { .. } => 4,
            Self::DoubleLong(_) => 5,
            Self::DoubleLongUnsigned(_) => 6,
            Self::OctetString(_) => 9,
            Self::VisibleString(_) => 10,
            Self::Utf8String(_) => 12,
            Self::Bcd(_) => 13,
            Self::Integer(_) => 15,
            Self::Long(_) => 16,
            Self::Unsigned(_) => 17,
            Self::LongUnsigned(_) => 18,
            Self::Long64(_) => 20,
            Self::Long64Unsigned(_) => 21,
            Self::Enum(_) => 22,
            Self::Float32(_) => 23,
            Self::Float64(_) => 24,
            Self::DateTime(_) => 25,
            Self::Date(_) => 26,
            Self::Time(_) => 27,
            Self::DeltaInteger(_) => 28,
            Self::DeltaLong(_) => 29,
            Self::DeltaDoubleLong(_) => 30,
            Self::DeltaUnsigned(_) => 31,
            Self::DeltaLongUnsigned(_) => 32,
            Self::DeltaDoubleLongUnsigned(_) => 33,
            Self::DontCare => 255,
        };
        w.write_u8(tag)?;
        match self {
            Self::Null | Self::DontCare => Ok(()),
            Self::Array(v) | Self::Structure(v) => {
                w.write_length(v.len())?;
                for e in v {
                    e.encode(w)?;
                }
                Ok(())
            }
            Self::Boolean(v) => w.write_u8(u8::from(*v)),
            Self::BitString { bits, bytes } => {
                w.write_length(*bits)?;
                w.write_bytes(bytes)
            }
            Self::DoubleLong(v) => w.write_u32(*v as u32),
            Self::DoubleLongUnsigned(v) => w.write_u32(*v),
            Self::OctetString(b) | Self::VisibleString(b) | Self::Utf8String(b) => w.write_length_prefixed(b),
            Self::Bcd(v) | Self::Integer(v) | Self::DeltaInteger(v) => w.write_u8(*v as u8),
            Self::Long(v) | Self::DeltaLong(v) => w.write_u16(*v as u16),
            Self::Unsigned(v) | Self::Enum(v) | Self::DeltaUnsigned(v) => w.write_u8(*v),
            Self::LongUnsigned(v) | Self::DeltaLongUnsigned(v) => w.write_u16(*v),
            Self::Long64(v) => w.write_u64(*v as u64),
            Self::Long64Unsigned(v) => w.write_u64(*v),
            Self::Float32(v) => w.write_u32(v.to_bits()),
            Self::Float64(v) => w.write_u64(v.to_bits()),
            Self::DateTime(v) => w.write_bytes(&v.to_bytes()),
            Self::Date(v) => w.write_bytes(&v.to_bytes()),
            Self::Time(v) => w.write_bytes(&v.to_bytes()),
            Self::DeltaDoubleLong(v) => w.write_u32(*v as u32),
            Self::DeltaDoubleLongUnsigned(v) => w.write_u32(*v),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Equality is about the elements, not about where the bytes were found.
    ///
    /// The derived implementation compared the diagnostic offset and the nesting depth,
    /// so the same array decoded at two positions was unequal to itself — which is a
    /// wrong answer for anything that compares two decoded APDUs, and it is silent.
    #[test]
    fn two_identical_sequences_are_equal_wherever_they_were_decoded() {
        use super::*;
        let bare = [0x01u8, 0x02, 0x11, 0x07, 0x11, 0x09];
        // The same array, nested inside a structure, so it decodes at a different offset
        // and a deeper level.
        let nested = [0x02u8, 0x01, 0x01, 0x02, 0x11, 0x07, 0x11, 0x09];

        let a = Data::from_bytes(&bare).unwrap();
        let outer = Data::from_bytes(&nested).unwrap();
        let b = outer.as_structure().unwrap().get(0).unwrap();

        assert_eq!(a, b, "the same array is the same array wherever it was found");
        assert_eq!(a.as_array().unwrap(), b.as_array().unwrap());
    }

    use super::*;

    /// `bcd` looks like an integer on the wire and is not one.
    #[test]
    fn a_bcd_byte_is_not_the_integer_it_looks_like() {
        let d = Data::Bcd(0x25);
        assert_eq!(d.as_bcd(), Some(25), "0x25 reads as twenty-five");
        assert_eq!(
            d.as_i64(),
            None,
            "and must not quietly answer thirty-seven to a caller asking for an integer"
        );
        // A nibble above nine is not a decimal digit.
        assert_eq!(Data::Bcd(0x1A).as_bcd(), None);
        assert_eq!(Data::Bcd(0xA1u8 as i8).as_bcd(), None);
        assert_eq!(Data::Bcd(0x99u8 as i8).as_bcd(), Some(99));
        // And nothing else answers to it.
        assert_eq!(Data::Unsigned(0x25).as_bcd(), None);
        assert_eq!(Data::Unsigned(0x25).as_i64(), Some(37));
    }

    #[test]
    fn a_bit_string_is_numbered_from_its_most_significant_bit() {
        let bytes = [0b1010_0000u8];
        let b = BitStr::new(3, &bytes).unwrap();
        assert!(b.bit(0));
        assert!(!b.bit(1));
        assert!(b.bit(2));
        assert!(!b.bit(3), "past the end is false, not a panic");
        assert_eq!(b.to_u32(), 0b101);
    }
}
