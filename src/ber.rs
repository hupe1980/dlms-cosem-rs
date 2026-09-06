//! Just enough BER for ACSE.
//!
//! The association-control APDUs — AARQ, AARE, RLRQ, RLRE — are BER, while everything
//! inside them is A-XDR. Only what those four need is here: single-byte identifiers,
//! definite lengths, object identifiers and the constructed context tags. Indefinite
//! lengths and multi-byte tags are refused: nothing in DLMS uses them, and accepting
//! them widens a parser that faces the network before any key has been checked.

use crate::codec::{Error, ErrorKind, Reader, Result, Writer};

/// A tag, a length and the bytes in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier octet.
    pub tag: u8,
    /// The contents.
    pub value: &'a [u8],
    /// Where the contents start, for error offsets.
    pub offset: usize,
}

impl<'a> Tlv<'a> {
    /// True when the identifier says the contents are themselves TLVs.
    #[must_use]
    pub const fn is_constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// The context-specific tag number, for an identifier in the context class.
    #[must_use]
    pub const fn context_number(&self) -> Option<u8> {
        if self.tag & 0xC0 == 0x80 { Some(self.tag & 0x1F) } else { None }
    }

    /// A reader over the contents, reporting offsets in the enclosing buffer.
    #[must_use]
    pub fn reader(&self) -> Reader<'a> {
        Reader::with_base(self.value, self.offset)
    }

    /// The contents as a single unsigned byte.
    pub fn as_u8(&self) -> Result<u8> {
        match self.value {
            [v] => Ok(*v),
            _ => Err(Error::new(ErrorKind::InvalidLength, self.offset)),
        }
    }
}

/// Read one TLV.
pub fn read_tlv<'a>(r: &mut Reader<'a>) -> Result<Tlv<'a>> {
    let tag = r.u8()?;
    if tag & 0x1F == 0x1F {
        return Err(r.err_back(ErrorKind::InvalidTag(tag), 1));
    }
    let first = r.u8()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            // 0x80 is the indefinite form; more than four length bytes cannot describe
            // anything this crate will hold.
            return Err(r.err_back(ErrorKind::InvalidLength, 1));
        }
        let bytes = r.take(n)?;
        let mut v = 0usize;
        for b in bytes {
            v = v
                .checked_shl(8)
                .and_then(|v| v.checked_add(usize::from(*b)))
                .ok_or_else(|| r.err_back(ErrorKind::InvalidLength, n))?;
        }
        v
    };
    let offset = r.offset();
    Ok(Tlv { tag, value: r.take(len)?, offset })
}

/// Iterate the TLVs in a buffer until it is exhausted.
pub fn iter_tlv(bytes: &[u8], base: usize) -> impl Iterator<Item = Result<Tlv<'_>>> {
    let mut r = Reader::with_base(bytes, base);
    core::iter::from_fn(move || if r.is_empty() { None } else { Some(read_tlv(&mut r)) })
}

/// Write a tag, a length and the contents.
pub fn write_tlv(w: &mut dyn Writer, tag: u8, value: &[u8]) -> Result<()> {
    w.write_u8(tag)?;
    write_len(w, value.len())?;
    w.write_bytes(value)
}

/// Write a BER definite length in the shortest form.
pub fn write_len(w: &mut dyn Writer, len: usize) -> Result<()> {
    if len < 0x80 {
        return w.write_u8(len as u8);
    }
    let be = (len as u64).to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(7);
    let n = 8 - first;
    if n > 4 {
        return Err(Error::new(ErrorKind::InvalidLength, w.written()));
    }
    w.write_u8(0x80 | n as u8)?;
    w.write_bytes(&be[first..])
}

/// Write a constructed TLV whose contents are produced by `f`.
///
/// The body is measured before it is written, so the length goes out in its shortest
/// form with nothing to move afterwards. `f` therefore runs twice and must be
/// deterministic — which every encoder here is, being a pure function of its input.
pub fn write_constructed(
    w: &mut dyn Writer,
    tag: u8,
    f: impl Fn(&mut dyn Writer) -> Result<()>,
) -> Result<()> {
    let mut counter = crate::codec::CountingWriter::default();
    f(&mut counter)?;
    let len = counter.count();
    w.write_u8(tag)?;
    write_len(w, len)?;
    let before = w.written();
    f(w)?;
    debug_assert_eq!(w.written() - before, len, "encoder must be deterministic");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn short_and_long_forms() {
        let mut buf = [0u8; 300];
        let mut w = SliceWriter::new(&mut buf);
        write_tlv(&mut w, 0x04, &[1, 2, 3]).unwrap();
        assert_eq!(w.as_slice(), [0x04, 0x03, 1, 2, 3]);

        let body = [0xAAu8; 200];
        let mut w = SliceWriter::new(&mut buf);
        write_tlv(&mut w, 0x04, &body).unwrap();
        assert_eq!(&w.as_slice()[..3], [0x04, 0x81, 200]);
        let tlv = read_tlv(&mut Reader::new(w.as_slice())).unwrap();
        assert_eq!(tlv.value.len(), 200);
    }

    #[test]
    fn indefinite_length_is_refused() {
        assert_eq!(
            read_tlv(&mut Reader::new(&[0x30, 0x80, 0x00, 0x00])).unwrap_err().kind,
            ErrorKind::InvalidLength
        );
    }

    #[test]
    fn multi_byte_tags_are_refused() {
        assert!(matches!(
            read_tlv(&mut Reader::new(&[0x1F, 0x81, 0x01, 0x00])).unwrap_err().kind,
            ErrorKind::InvalidTag(0x1F)
        ));
    }

    #[test]
    fn context_tags_are_recognised() {
        let tlv = read_tlv(&mut Reader::new(&[0xA1, 0x02, 0x06, 0x00])).unwrap();
        assert_eq!(tlv.context_number(), Some(1));
        assert!(tlv.is_constructed());
        let tlv = read_tlv(&mut Reader::new(&[0x8A, 0x02, 0x07, 0x80])).unwrap();
        assert_eq!(tlv.context_number(), Some(10));
        assert!(!tlv.is_constructed());
    }

    #[test]
    fn constructed_writing_back_patches_the_length() {
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        write_constructed(&mut w, 0x60, |w| {
            write_tlv(w, 0x80, &[1])?;
            write_tlv(w, 0x81, &[2, 3])
        })
        .unwrap();
        assert_eq!(w.as_slice(), [0x60, 0x07, 0x80, 0x01, 0x01, 0x81, 0x02, 0x02, 0x03]);
    }

    #[test]
    fn a_truncated_value_is_truncated_not_invalid() {
        let e = read_tlv(&mut Reader::new(&[0x04, 0x05, 1, 2])).unwrap_err();
        assert!(e.is_truncated());
    }
}
