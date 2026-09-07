//! The cursor codec: a reader, a writer, and an error that always knows *where*.
//!
//! Every decoder in this crate is a function over a [`Reader`] and every encoder a
//! function over a [`Writer`]. There is no parser-combinator dependency: DLMS encodings
//! are length-prefixed and tag-dispatched, and a hand-written cursor keeps the byte
//! offset of a failure exact, which is what a protocol translator prints and what a
//! fuzz finding is triaged from.
//!
//! Neither side can panic. Every read is bounds-checked, every arithmetic operation on
//! a length is checked, and the only way out of a decoder is a [`Result`].

use core::fmt;

/// What went wrong.
///
/// The variants distinguish the cases a caller can act on — a truncated frame may
/// complete on the next read, an unknown tag never will.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input ended inside a value. `needed` is how many more bytes this particular
    /// read wanted, which is a lower bound on what the whole value needs.
    Truncated {
        /// Bytes the failing read still wanted.
        needed: usize,
    },
    /// A tag that is not defined at this position.
    InvalidTag(u8),
    /// A value outside the set the specification defines for this field.
    InvalidValue,
    /// A well-formed value of the wrong type for the position it appeared in.
    ///
    /// Distinct from [`ErrorKind::InvalidValue`] because the caller can act on it
    /// differently: the bytes decoded, the field is simply not what this position needs —
    /// a delta whose width disagrees with the column it continues, say. Coercing instead
    /// would hand back a number nobody sent.
    TypeMismatch,
    /// A length prefix that cannot be represented, or that exceeds the remaining input.
    InvalidLength,
    /// Nesting deeper than the configured limit. Guards recursion on hostile input.
    DepthExceeded,
    /// A value that would take more work to expand than any real one needs.
    ///
    /// The sibling of [`ErrorKind::DepthExceeded`]: depth bounds how far a decoder
    /// recurses, this bounds how *wide* it goes. A compact array's type description
    /// multiplies — `array 7425 of array 285 of array 257` is fourteen bytes describing
    /// half a billion values — so the cost of walking one must be bounded before it is
    /// walked, not discovered while walking it.
    WorkExceeded,
    /// The output buffer is full.
    BufferTooSmall {
        /// Bytes the failing write still wanted.
        needed: usize,
    },
    /// A frame check sequence, header check sequence or CRC did not match.
    BadChecksum,
    /// An authentication tag did not verify, or a signature did not verify.
    BadTag,
    /// An invocation counter that has already been accepted, or is too old to prove
    /// anything about.
    ///
    /// Distinct from [`ErrorKind::BadTag`] because the two are different events. A bad
    /// tag is a forgery or the wrong key; a replay is a message that really was sent
    /// under the real key, and is most often a retransmission or a peer that restarted
    /// from a stale counter. The standard has a service error for exactly this —
    /// `invocation-counter-error`, which carries the value the receiver expects next — and
    /// a server cannot send it without being able to tell the two apart.
    Replay,
    /// The peer's message is well formed but not allowed in this state.
    UnexpectedMessage,
    /// A field is longer than this build can represent without `alloc`.
    Unsupported,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed } => write!(f, "truncated, needed {needed} more byte(s)"),
            Self::InvalidTag(t) => write!(f, "invalid tag {t:#04x}"),
            Self::InvalidValue => f.write_str("invalid value"),
            Self::TypeMismatch => f.write_str("value is not of the type this position requires"),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::DepthExceeded => f.write_str("nesting too deep"),
            Self::WorkExceeded => f.write_str("a value that would take unbounded work to expand"),
            Self::BufferTooSmall { needed } => write!(f, "buffer too small, needed {needed}"),
            Self::BadChecksum => f.write_str("checksum mismatch"),
            Self::BadTag => f.write_str("authentication tag mismatch"),
            Self::Replay => f.write_str("invocation counter already accepted, or too old"),
            Self::UnexpectedMessage => f.write_str("message not allowed in this state"),
            Self::Unsupported => f.write_str("not supported in this build"),
        }
    }
}

/// An error and the byte offset it happened at.
///
/// The offset is into the buffer the failing [`Reader`] or [`Writer`] was given, so a
/// translator can print `byte 47: invalid tag 0x1b` without threading positions through
/// the call stack by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// What went wrong.
    pub kind: ErrorKind,
    /// Where, as an offset from the start of the buffer.
    pub offset: usize,
}

impl Error {
    /// Construct an error at `offset`.
    #[must_use]
    pub const fn new(kind: ErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// True when more input might complete this value.
    ///
    /// A stream transport uses this to decide between "wait for more bytes" and
    /// "this frame is broken, resynchronise".
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self.kind, ErrorKind::Truncated { .. })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "byte {}: {}", self.offset, self.kind)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The crate's result type.
pub type Result<T> = core::result::Result<T, Error>;

/// A bounds-checked cursor over borrowed input.
///
/// Every method that fails leaves the position untouched, so a caller that hits
/// [`ErrorKind::Truncated`] can retry the same read after more bytes arrive.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`, with offsets reported from its start.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, base: 0 }
    }

    /// A reader over `buf` whose reported offsets are shifted by `base`.
    ///
    /// Used when a sub-decoder is handed a slice out of a larger frame and its errors
    /// should still point at the position in that frame.
    #[must_use]
    pub const fn with_base(buf: &'a [u8], base: usize) -> Self {
        Self { buf, pos: 0, base }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// True when every byte has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The current offset, including the base.
    ///
    /// Saturating rather than wrapping: this is a byte position for a diagnostic, and
    /// the sum cannot overflow for any buffer that exists. Writing it as a plain `+`
    /// still emitted an overflow check, and because [`Reader::err`] calls this, that
    /// single addition put a panic path in every decoder in the crate.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.base.saturating_add(self.pos)
    }

    /// The bytes not yet consumed, without consuming them.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// How many bytes this reader has taken, ignoring the base.
    ///
    /// This is what a *probe* reader is for: make one over `rest()`, run a sub-decoder,
    /// ask how much it used. A list finds its end that way, and so does a compact array's
    /// type description.
    ///
    /// Written `probe.offset() - base` instead, that is a subtraction the optimiser
    /// cannot discharge — it cannot see that a reader's offset never goes below its own
    /// base — so it emits an overflow check in *every monomorphisation* of every such
    /// decoder. Asking the reader needs no arithmetic at all.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.pos
    }

    /// An error at the current position.
    #[must_use]
    pub const fn err(&self, kind: ErrorKind) -> Error {
        Error::new(kind, self.offset())
    }

    /// An error at `offset` bytes before the current position.
    #[must_use]
    pub const fn err_back(&self, kind: ErrorKind, back: usize) -> Error {
        Error::new(kind, self.offset().saturating_sub(back))
    }

    /// Fail unless at least `n` bytes remain.
    pub fn ensure(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(self.err(ErrorKind::Truncated { needed: n - self.remaining() }));
        }
        Ok(())
    }

    /// Take exactly `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.ensure(n)?;
        // `ensure` has established that this fits, but the slice is taken with `get` so
        // the bound is discharged by the type rather than left to the optimiser to
        // rediscover. This is the primitive every decoder in the crate reads through,
        // so a bounds check that survives here is a panic path in all of them.
        let end = self.pos.checked_add(n).ok_or_else(|| self.err(ErrorKind::InvalidLength))?;
        let out = self.buf.get(self.pos..end).ok_or_else(|| self.err(ErrorKind::InvalidLength))?;
        self.pos = end;
        Ok(out)
    }

    /// Take the remaining bytes.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let out = self.rest();
        self.pos = self.buf.len();
        out
    }

    /// Take exactly `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or_else(|| self.err(ErrorKind::Truncated { needed: 1 }))?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    /// One byte, without consuming it.
    pub fn peek_u8(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or_else(|| self.err(ErrorKind::Truncated { needed: 1 }))
    }

    /// A big-endian `u16`. DLMS is big-endian throughout.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// A big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// A big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A big-endian `i8`, `i16`, `i32`, `i64` — sign is the only difference.
    pub fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
    }

    /// A big-endian `i16`.
    pub fn i16(&mut self) -> Result<i16> {
        Ok(self.u16()? as i16)
    }

    /// A big-endian `i32`.
    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    /// A big-endian `i64`.
    pub fn i64(&mut self) -> Result<i64> {
        Ok(self.u64()? as i64)
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// An A-XDR length: a short form below `0x80`, else `0x80 | n` and `n` big-endian
    /// bytes. `n` above four, and the indefinite form `0x80`, are refused — DLMS uses
    /// neither and accepting them widens the attack surface for nothing.
    pub fn length(&mut self) -> Result<usize> {
        let first = self.u8()?;
        if first < 0x80 {
            return Ok(usize::from(first));
        }
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(self.err_back(ErrorKind::InvalidLength, 1));
        }
        let bytes = self.take(n)?;
        let mut v: u64 = 0;
        for b in bytes {
            v = (v << 8) | u64::from(*b);
        }
        usize::try_from(v).map_err(|_| self.err_back(ErrorKind::InvalidLength, n))
    }

    /// A length followed by that many bytes.
    pub fn length_prefixed(&mut self) -> Result<&'a [u8]> {
        let n = self.length()?;
        self.take(n)
    }

    /// Run `f` over the next `n` bytes in a reader of their own, and require it to
    /// consume all of them.
    ///
    /// This is how a nested structure is decoded without letting the inner decoder read
    /// past its own field — the single most common way a protocol parser is made to
    /// read out of bounds elsewhere in the frame.
    pub fn nested<T>(&mut self, n: usize, f: impl FnOnce(&mut Reader<'a>) -> Result<T>) -> Result<T> {
        let base = self.offset();
        let bytes = self.take(n)?;
        let mut inner = Reader::with_base(bytes, base);
        let out = f(&mut inner)?;
        if !inner.is_empty() {
            return Err(inner.err(ErrorKind::InvalidLength));
        }
        Ok(out)
    }
}

/// A sink for encoded bytes.
///
/// Implemented for a caller-owned slice ([`SliceWriter`]), for `alloc::vec::Vec<u8>` and
/// for `heapless::Vec`, so the same encoder serves a microcontroller with a static
/// buffer and a head-end that grows one.
pub trait Writer {
    /// Append `bytes`.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;

    /// How many bytes have been written so far, for error offsets and for sizing a
    /// length prefix against a [`CountingWriter`].
    fn written(&self) -> usize;

    /// Append one byte.
    fn write_u8(&mut self, b: u8) -> Result<()> {
        self.write_bytes(&[b])
    }

    /// Append a big-endian `u16`.
    fn write_u16(&mut self, v: u16) -> Result<()> {
        self.write_bytes(&v.to_be_bytes())
    }

    /// Append a big-endian `u32`.
    fn write_u32(&mut self, v: u32) -> Result<()> {
        self.write_bytes(&v.to_be_bytes())
    }

    /// Append a big-endian `u64`.
    fn write_u64(&mut self, v: u64) -> Result<()> {
        self.write_bytes(&v.to_be_bytes())
    }

    /// Append an A-XDR length.
    fn write_length(&mut self, len: usize) -> Result<()> {
        if len < 0x80 {
            return self.write_u8(len as u8);
        }
        let be = (len as u64).to_be_bytes();
        let first = be.iter().position(|b| *b != 0).unwrap_or(7);
        let n = 8 - first;
        if n > 4 {
            return Err(Error::new(ErrorKind::InvalidLength, self.written()));
        }
        self.write_u8(0x80 | n as u8)?;
        self.write_bytes(&be[first..])
    }

    /// Append a length followed by `bytes`.
    fn write_length_prefixed(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_length(bytes.len())?;
        self.write_bytes(bytes)
    }
}

/// A [`Writer`] over a caller-owned slice. Never allocates.
#[derive(Debug)]
pub struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceWriter<'a> {
    /// A writer that fills `buf` from the start.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The bytes written so far.
    #[must_use]
    pub fn finish(self) -> &'a mut [u8] {
        let n = self.pos.min(self.buf.len());
        &mut self.buf[..n]
    }

    /// The bytes written so far, borrowed.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.buf.get(..self.pos).unwrap_or(self.buf)
    }

    /// Discard everything written after `at`.
    ///
    /// For an encoder that starts a value and then learns it cannot finish it — a store
    /// that writes half an attribute and then reports a hardware fault, say. Without
    /// this, the half-written bytes stay in the buffer in front of the error that
    /// replaces them, and the result is a response whose length agrees with nothing.
    ///
    /// Only ever shrinks: `at` beyond what has been written is refused rather than
    /// treated as an extension into whatever the buffer happened to contain.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidLength`] when `at` is past the current position.
    pub fn truncate(&mut self, at: usize) -> Result<()> {
        if at > self.pos {
            return Err(Error::new(ErrorKind::InvalidLength, self.pos));
        }
        self.pos = at;
        Ok(())
    }
}

impl Writer for SliceWriter<'_> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.pos.saturating_add(bytes.len());
        let Some(slot) = self.buf.get_mut(self.pos..end) else {
            let needed = end.saturating_sub(self.buf.len());
            return Err(Error::new(ErrorKind::BufferTooSmall { needed }, self.pos));
        };
        slot.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn written(&self) -> usize {
        self.pos
    }
}

#[cfg(feature = "alloc")]
impl Writer for alloc::vec::Vec<u8> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }

    fn written(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> Writer for heapless::Vec<u8, N> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes).map_err(|()| {
            Error::new(ErrorKind::BufferTooSmall { needed: bytes.len() - (N - self.len()) }, self.len())
        })
    }

    fn written(&self) -> usize {
        self.len()
    }
}

/// Something that can be written to a [`Writer`].
pub trait Encode {
    /// Append the encoding of `self`.
    fn encode(&self, w: &mut dyn Writer) -> Result<()>;

    /// The number of bytes [`Encode::encode`] will write.
    ///
    /// Implementations must agree with `encode`. The default counts what `encode`
    /// writes, so it agrees by construction; an override that does not is a buffer
    /// sized wrongly, and `tests/robustness.rs` checks the two against each other for
    /// everything it decodes.
    fn encoded_len(&self) -> usize {
        let mut c = CountingWriter::default();
        let _ = self.encode(&mut c);
        c.written()
    }
}

/// Something that can be read from a [`Reader`].
pub trait Decode<'a>: Sized {
    /// Consume one value.
    fn decode(r: &mut Reader<'a>) -> Result<Self>;

    /// Consume one value from `bytes`, requiring all of them to be used.
    fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        if !r.is_empty() {
            return Err(r.err(ErrorKind::InvalidLength));
        }
        Ok(v)
    }
}

/// A [`Writer`] that counts instead of storing. Backs [`Encode::encoded_len`].
#[derive(Debug, Default, Clone, Copy)]
pub struct CountingWriter {
    n: usize,
}

impl CountingWriter {
    /// The count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.n
    }
}

impl Writer for CountingWriter {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        // Saturating: this counter measures a length nobody has room to reach, and a
        // plain `+=` here is an overflow check in every `encoded_len` in the crate.
        self.n = self.n.saturating_add(bytes.len());
        Ok(())
    }

    fn written(&self) -> usize {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_lengths_round_trip() {
        for len in [0usize, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x1_0000, 0x00ff_ffff] {
            let mut buf = [0u8; 8];
            let mut w = SliceWriter::new(&mut buf);
            w.write_length(len).unwrap();
            let n = w.written();
            let mut r = Reader::new(&buf[..n]);
            assert_eq!(r.length().unwrap(), len, "length {len}");
            assert!(r.is_empty());
        }
    }

    #[test]
    fn length_form_is_the_shortest_one() {
        let mut buf = [0u8; 8];
        let mut w = SliceWriter::new(&mut buf);
        w.write_length(0x7f).unwrap();
        assert_eq!(w.as_slice(), [0x7f]);
        let mut w = SliceWriter::new(&mut buf);
        w.write_length(0x80).unwrap();
        assert_eq!(w.as_slice(), [0x81, 0x80]);
        let mut w = SliceWriter::new(&mut buf);
        w.write_length(0x1234).unwrap();
        assert_eq!(w.as_slice(), [0x82, 0x12, 0x34]);
    }

    #[test]
    fn indefinite_and_oversized_lengths_are_refused() {
        assert_eq!(Reader::new(&[0x80]).length().unwrap_err().kind, ErrorKind::InvalidLength);
        assert_eq!(Reader::new(&[0x85, 1, 2, 3, 4, 5]).length().unwrap_err().kind, ErrorKind::InvalidLength);
    }

    #[test]
    fn truncation_reports_what_it_needed_and_where() {
        let mut r = Reader::new(&[0x01, 0x02]);
        r.u8().unwrap();
        let e = r.u32().unwrap_err();
        assert_eq!(e.kind, ErrorKind::Truncated { needed: 3 });
        assert_eq!(e.offset, 1);
        assert!(e.is_truncated());
    }

    #[test]
    fn a_failed_read_does_not_move_the_cursor() {
        let mut r = Reader::new(&[0xaa]);
        assert!(r.u16().is_err());
        assert_eq!(r.offset(), 0);
        assert_eq!(r.u8().unwrap(), 0xaa);
    }

    #[test]
    fn nested_readers_report_offsets_in_the_outer_frame() {
        let frame = [0xff, 0xff, 0x00, 0x1b];
        let mut r = Reader::new(&frame);
        r.skip(2).unwrap();
        let e = r
            .nested(2, |inner| -> Result<()> {
                inner.u8()?;
                Err(inner.err(ErrorKind::InvalidTag(0x1b)))
            })
            .unwrap_err();
        assert_eq!(e.offset, 3, "offset is into the outer frame, not the slice");
    }

    #[test]
    fn nested_refuses_a_decoder_that_leaves_bytes() {
        let mut r = Reader::new(&[1, 2, 3, 4]);
        let e = r.nested(4, |inner| inner.u8()).unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidLength);
    }

    #[test]
    fn slice_writer_reports_the_shortfall() {
        let mut buf = [0u8; 2];
        let mut w = SliceWriter::new(&mut buf);
        let e = w.write_bytes(&[1, 2, 3, 4]).unwrap_err();
        assert_eq!(e.kind, ErrorKind::BufferTooSmall { needed: 2 });
    }

    #[test]
    fn truncating_discards_only_what_came_after() {
        let mut buf = [0u8; 16];
        let mut w = SliceWriter::new(&mut buf);
        w.write_bytes(&[1, 2, 3]).unwrap();
        let mark = w.written();
        w.write_bytes(&[9, 9, 9, 9]).unwrap();
        w.truncate(mark).unwrap();
        assert_eq!(w.as_slice(), [1, 2, 3]);
        // And writing continues from there, over what was discarded.
        w.write_bytes(&[4]).unwrap();
        assert_eq!(w.as_slice(), [1, 2, 3, 4]);
    }

    #[test]
    fn truncating_forward_is_refused_rather_than_extending() {
        // Otherwise it would hand back whatever the caller's buffer happened to hold.
        let mut buf = [0xAAu8; 16];
        let mut w = SliceWriter::new(&mut buf);
        w.write_bytes(&[1, 2]).unwrap();
        assert_eq!(w.truncate(5).unwrap_err().kind, ErrorKind::InvalidLength);
        assert_eq!(w.as_slice(), [1, 2], "and leaves the position where it was");
        assert!(w.truncate(0).is_ok());
        assert!(w.as_slice().is_empty());
    }

    #[test]
    fn counting_writer_agrees_with_a_real_one() {
        let mut buf = [0u8; 16];
        let mut w = SliceWriter::new(&mut buf);
        w.write_length_prefixed(&[1, 2, 3]).unwrap();
        let mut c = CountingWriter::default();
        c.write_length_prefixed(&[1, 2, 3]).unwrap();
        assert_eq!(c.count(), w.written());
    }
}
