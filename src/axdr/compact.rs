//! Compact arrays — the same values, with the type written once.
//!
//! A compact array (tag 19) carries a *type description* followed by the raw contents
//! of every element, with no per-value tags. It is how a profile buffer of ten thousand
//! rows is transferred without repeating the same twelve tag bytes ten thousand times,
//! and it is the encoding most often got wrong, because the description is itself a
//! recursive structure and the contents cannot be walked without it.

use crate::codec::{Error, ErrorKind, Reader, Result, Writer};

use super::data::{BitStr, Data, DataTag, MAX_DEPTH};
use super::{Date, DateTime, Time};

/// The shape of every element of a compact array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDesc<'a> {
    /// A single value of this type.
    Scalar(DataTag),
    /// A fixed-length repetition of one type.
    Array {
        /// How many elements.
        len: u16,
        /// The element's own description.
        elem: &'a [u8],
    },
    /// A record of differently-typed fields.
    Structure {
        /// How many fields.
        count: usize,
        /// The fields' descriptions, concatenated.
        fields: &'a [u8],
    },
}

impl<'a> TypeDesc<'a> {
    /// Parse one type description.
    ///
    /// A description is itself a recursive structure, so it carries the same depth
    /// budget as the values it describes. Without one, `structure { structure { ... } }`
    /// repeated once per input byte is a stack overflow, and the description is read
    /// straight off the wire before anything has been authenticated.
    pub fn parse(r: &mut Reader<'a>) -> Result<Self> {
        Self::parse_at(r, 0)
    }

    fn parse_at(r: &mut Reader<'a>, depth: u8) -> Result<Self> {
        if depth >= MAX_DEPTH {
            return Err(r.err(ErrorKind::DepthExceeded));
        }
        let tag_byte = r.u8()?;
        let tag = DataTag::from_u8(tag_byte).ok_or_else(|| r.err_back(ErrorKind::InvalidTag(tag_byte), 1))?;
        match tag {
            DataTag::Array => {
                let len = r.u16()?;
                let start = r.offset();
                let mut probe = Reader::with_base(r.rest(), start);
                Self::skip_at(&mut probe, depth + 1)?;
                let elem = r.take(probe.offset() - start)?;
                Ok(Self::Array { len, elem })
            }
            DataTag::Structure => {
                let count = r.length()?;
                let start = r.offset();
                let mut probe = Reader::with_base(r.rest(), start);
                for _ in 0..count {
                    Self::skip_at(&mut probe, depth + 1)?;
                }
                let fields = r.take(probe.offset() - start)?;
                Ok(Self::Structure { count, fields })
            }
            DataTag::CompactArray => Err(r.err_back(ErrorKind::InvalidTag(tag_byte), 1)),
            other => Ok(Self::Scalar(other)),
        }
    }

    /// Walk one type description without building it.
    pub fn skip(r: &mut Reader<'a>) -> Result<()> {
        Self::skip_at(r, 0)
    }

    fn skip_at(r: &mut Reader<'a>, depth: u8) -> Result<()> {
        Self::parse_at(r, depth).map(|_| ())
    }

    /// The number of leaf values one element of this shape expands to.
    ///
    /// The count is checked at every step: a description may nest arrays of 65 535
    /// elements, and the product of a few of those overflows a `usize` long before it
    /// describes anything a meter could send.
    pub fn leaf_count(&self) -> Result<usize> {
        self.leaf_count_at(0)
    }

    fn leaf_count_at(&self, depth: u8) -> Result<usize> {
        if depth >= MAX_DEPTH {
            return Err(Error::new(ErrorKind::DepthExceeded, 0));
        }
        let overflow = || Error::new(ErrorKind::InvalidLength, 0);
        Ok(match *self {
            Self::Scalar(_) => 1,
            Self::Array { len, elem } => {
                let inner = Self::parse_at(&mut Reader::new(elem), depth + 1)?;
                usize::from(len).checked_mul(inner.leaf_count_at(depth + 1)?).ok_or_else(overflow)?
            }
            Self::Structure { count, fields } => {
                let mut r = Reader::new(fields);
                let mut n = 0usize;
                for _ in 0..count {
                    let field = Self::parse_at(&mut r, depth + 1)?;
                    n = n.checked_add(field.leaf_count_at(depth + 1)?).ok_or_else(overflow)?;
                }
                n
            }
        })
    }
}

/// One value out of a compact array, with where it sat.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompactLeaf<'a> {
    /// The index of the top-level element this leaf belongs to.
    pub row: usize,
    /// The index of this leaf within its element, counting flattened leaves.
    pub column: usize,
    /// The value.
    pub value: Data<'a>,
}

/// A borrowed compact array: a type description and the raw contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactArray<'a> {
    desc: &'a [u8],
    contents: &'a [u8],
    /// Where the description sits in the frame, for error offsets.
    desc_base: usize,
    /// Where the contents sit in the frame. Kept apart from `desc_base` so an error in
    /// the contents does not report a position inside the description.
    contents_base: usize,
    depth: u8,
}

impl<'a> CompactArray<'a> {
    /// The raw type description.
    #[must_use]
    pub const fn description_bytes(&self) -> &'a [u8] {
        self.desc
    }

    /// The raw contents.
    #[must_use]
    pub const fn contents(&self) -> &'a [u8] {
        self.contents
    }

    /// The parsed type description.
    pub fn description(&self) -> Result<TypeDesc<'a>> {
        TypeDesc::parse_at(&mut Reader::with_base(self.desc, self.desc_base), self.depth)
    }

    /// How many leaf values one row expands to.
    pub fn row_len(&self) -> Result<usize> {
        self.description()?.leaf_count()
    }

    /// Visit every leaf value in order.
    ///
    /// The visitor form is what a `no_std` build can offer without allocating an index:
    /// the contents are walked once, and each leaf is handed over as it is decoded.
    pub fn for_each_leaf(&self, mut f: impl FnMut(CompactLeaf<'a>) -> Result<()>) -> Result<()> {
        let desc = self.description()?;
        let mut contents = Reader::with_base(self.contents, self.contents_base);
        let mut row = 0usize;
        while !contents.is_empty() {
            let before = contents.offset();
            let mut column = 0usize;
            walk(&mut contents, &desc, self.depth, &mut |value| {
                let leaf = CompactLeaf { row, column, value };
                column += 1;
                f(leaf)
            })?;
            ensure_progress(&contents, before)?;
            row += 1;
        }
        Ok(())
    }

    /// How many rows the contents hold.
    ///
    /// Requires walking the contents, because a row containing a string has no fixed
    /// length. `O(n)` and allocation-free.
    pub fn row_count(&self) -> Result<usize> {
        let desc = self.description()?;
        let mut contents = Reader::with_base(self.contents, self.contents_base);
        let mut rows = 0;
        while !contents.is_empty() {
            let before = contents.offset();
            walk(&mut contents, &desc, self.depth, &mut |_| Ok(()))?;
            ensure_progress(&contents, before)?;
            rows += 1;
        }
        Ok(rows)
    }

    pub(super) fn decode_body(r: &mut Reader<'a>, depth: u8) -> Result<Self> {
        if depth >= MAX_DEPTH {
            return Err(r.err(ErrorKind::DepthExceeded));
        }
        let desc_base = r.offset();
        let mut probe = Reader::with_base(r.rest(), desc_base);
        TypeDesc::skip_at(&mut probe, depth)?;
        let desc = r.take(probe.offset() - desc_base)?;
        let len = r.length()?;
        let contents_base = r.offset();
        let contents = r.take(len)?;
        Ok(Self { desc, contents, desc_base, contents_base, depth })
    }

    pub(super) fn skip_body(r: &mut Reader<'a>, depth: u8) -> Result<()> {
        Self::decode_body(r, depth).map(|_| ())
    }

    pub(super) fn encode_body(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_bytes(self.desc)?;
        w.write_length_prefixed(self.contents)
    }

    /// Expand into owned rows, preserving the nesting the description describes.
    #[cfg(feature = "alloc")]
    pub fn to_rows(&self) -> Result<alloc::vec::Vec<super::DataBuf>> {
        let desc = self.description()?;
        let mut contents = Reader::with_base(self.contents, self.contents_base);
        let mut out = alloc::vec::Vec::new();
        while !contents.is_empty() {
            let before = contents.offset();
            out.push(build(&mut contents, &desc, self.depth)?);
            ensure_progress(&contents, before)?;
        }
        Ok(out)
    }
}

/// Refuse a description that consumes no bytes per row.
///
/// `null-data`, `dont-care`, an array of zero elements and a structure of no fields all
/// decode without reading anything. A row of those against a non-empty contents field
/// would be decoded forever — and, in [`CompactArray::to_rows`], allocated forever. The
/// contents cannot be divided into rows at all in that case, so it is a malformed value
/// rather than a very large one.
fn ensure_progress(contents: &Reader<'_>, before: usize) -> Result<()> {
    if contents.offset() == before {
        return Err(contents.err(ErrorKind::InvalidValue));
    }
    Ok(())
}

/// Decode one leaf value that carries no tag of its own.
fn leaf<'a>(r: &mut Reader<'a>, tag: DataTag) -> Result<Data<'a>> {
    Ok(match tag {
        DataTag::NullData => Data::Null,
        DataTag::DontCare => Data::DontCare,
        DataTag::Boolean => Data::Boolean(r.u8()? != 0),
        DataTag::BitString => {
            let bits = r.length()?;
            let bytes = r.take(bits.div_ceil(8))?;
            Data::BitString(BitStr::new(bits, bytes).map_err(|_| r.err(ErrorKind::InvalidLength))?)
        }
        DataTag::DoubleLong => Data::DoubleLong(r.i32()?),
        DataTag::DoubleLongUnsigned => Data::DoubleLongUnsigned(r.u32()?),
        DataTag::OctetString => Data::OctetString(r.length_prefixed()?),
        DataTag::VisibleString => Data::VisibleString(r.length_prefixed()?),
        DataTag::Utf8String => Data::Utf8String(r.length_prefixed()?),
        DataTag::Bcd => Data::Bcd(r.i8()?),
        DataTag::Integer => Data::Integer(r.i8()?),
        DataTag::Long => Data::Long(r.i16()?),
        DataTag::Unsigned => Data::Unsigned(r.u8()?),
        DataTag::LongUnsigned => Data::LongUnsigned(r.u16()?),
        DataTag::Long64 => Data::Long64(r.i64()?),
        DataTag::Long64Unsigned => Data::Long64Unsigned(r.u64()?),
        DataTag::Enum => Data::Enum(r.u8()?),
        DataTag::Float32 => Data::Float32(f32::from_bits(r.u32()?)),
        DataTag::Float64 => Data::Float64(f64::from_bits(r.u64()?)),
        DataTag::DateTime => Data::DateTime(DateTime::from_bytes(r.array()?)),
        DataTag::Date => Data::Date(Date::from_bytes(r.array()?)),
        DataTag::Time => Data::Time(Time::from_bytes(r.array()?)),
        DataTag::DeltaInteger => Data::DeltaInteger(r.i8()?),
        DataTag::DeltaLong => Data::DeltaLong(r.i16()?),
        DataTag::DeltaDoubleLong => Data::DeltaDoubleLong(r.i32()?),
        DataTag::DeltaUnsigned => Data::DeltaUnsigned(r.u8()?),
        DataTag::DeltaLongUnsigned => Data::DeltaLongUnsigned(r.u16()?),
        DataTag::DeltaDoubleLongUnsigned => Data::DeltaDoubleLongUnsigned(r.u32()?),
        DataTag::Array | DataTag::Structure | DataTag::CompactArray => {
            return Err(r.err(ErrorKind::InvalidTag(tag.as_u8())));
        }
    })
}

fn walk<'a>(
    contents: &mut Reader<'a>,
    desc: &TypeDesc<'_>,
    depth: u8,
    f: &mut dyn FnMut(Data<'a>) -> Result<()>,
) -> Result<()> {
    if depth >= MAX_DEPTH {
        return Err(contents.err(ErrorKind::DepthExceeded));
    }
    match *desc {
        TypeDesc::Scalar(tag) => f(leaf(contents, tag)?),
        TypeDesc::Array { len, elem } => {
            let inner = TypeDesc::parse(&mut Reader::new(elem))?;
            for _ in 0..len {
                walk(contents, &inner, depth + 1, f)?;
            }
            Ok(())
        }
        TypeDesc::Structure { count, fields } => {
            let mut dr = Reader::new(fields);
            for _ in 0..count {
                let inner = TypeDesc::parse(&mut dr)?;
                walk(contents, &inner, depth + 1, f)?;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "alloc")]
fn build(contents: &mut Reader<'_>, desc: &TypeDesc<'_>, depth: u8) -> Result<super::DataBuf> {
    use super::DataBuf;
    if depth >= MAX_DEPTH {
        return Err(contents.err(ErrorKind::DepthExceeded));
    }
    Ok(match *desc {
        TypeDesc::Scalar(tag) => DataBuf::from_data(&leaf(contents, tag)?)?,
        TypeDesc::Array { len, elem } => {
            let inner = TypeDesc::parse(&mut Reader::new(elem))?;
            let mut v = alloc::vec::Vec::with_capacity(usize::from(len));
            for _ in 0..len {
                v.push(build(contents, &inner, depth + 1)?);
            }
            DataBuf::Array(v)
        }
        TypeDesc::Structure { count, fields } => {
            let mut dr = Reader::new(fields);
            let mut v = alloc::vec::Vec::with_capacity(count);
            for _ in 0..count {
                let inner = TypeDesc::parse(&mut dr)?;
                v.push(build(contents, &inner, depth + 1)?);
            }
            DataBuf::Structure(v)
        }
    })
}

impl<'a> CompactArray<'a> {
    /// Build a compact array from an already-encoded description and contents.
    ///
    /// The two must agree; [`CompactArray::row_count`] is the cheap way to check.
    pub fn from_parts(desc: &'a [u8], contents: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(desc);
        TypeDesc::skip(&mut r)?;
        if !r.is_empty() {
            return Err(Error::new(ErrorKind::InvalidLength, r.offset()));
        }
        Ok(Self { desc, contents, desc_base: 0, contents_base: 0, depth: 0 })
    }
}
