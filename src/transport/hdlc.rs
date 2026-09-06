//! HDLC — the data link layer of the three-layer connection-oriented profile.
//!
//! This is what an optical probe, an RS-485 bus and a great many GPRS meters speak.
//! Frame format type 3: an eleven-bit length, addresses of one, two or four bytes, a
//! header check sequence when there is an information field, and a frame check sequence
//! over everything.
//!
//! The decoder is built to resynchronise. A serial link delivers noise, half frames and
//! echoes of what was just transmitted, so [`Framer`] scans for a flag, validates, and
//! on failure discards to the next flag rather than giving up on the link.

use crate::codec::{Encode, Error, ErrorKind, Reader, Result, Writer};

/// The flag byte that opens and closes every frame.
pub const FLAG: u8 = 0x7E;

/// The LLC header a client sends before an APDU.
pub const LLC_REQUEST: [u8; 3] = [0xE6, 0xE6, 0x00];
/// The LLC header a server sends before an APDU.
pub const LLC_RESPONSE: [u8; 3] = [0xE6, 0xE7, 0x00];

/// The frame check sequence: CRC-16/X-25, as PPP and HDLC define it.
///
/// Reflected polynomial `0x8408` (that is, `x^16 + x^12 + x^5 + 1`), initial value
/// `0xFFFF`, final complement, transmitted least significant byte first.
#[must_use]
pub fn fcs16(data: &[u8]) -> u16 {
    let mut fcs: u16 = 0xFFFF;
    for b in data {
        fcs ^= u16::from(*b);
        for _ in 0..8 {
            fcs = if fcs & 1 != 0 { (fcs >> 1) ^ 0x8408 } else { fcs >> 1 };
        }
    }
    !fcs
}

/// An HDLC address: one, two or four bytes, each byte carrying seven bits and the last
/// one marked by its low bit.
///
/// The upper half is the logical device and the lower half the physical device, which
/// is how one physical meter hosts several logical ones on the same link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address {
    /// One byte: a client SAP, or a server whose logical and physical device are one.
    Single(u8),
    /// Two bytes: an upper and a lower address of seven bits each.
    Double {
        /// Logical device.
        upper: u8,
        /// Physical device.
        lower: u8,
    },
    /// Four bytes: an upper and a lower address of fourteen bits each.
    Quad {
        /// Logical device.
        upper: u16,
        /// Physical device.
        lower: u16,
    },
}

impl Address {
    /// The management logical device, address 1.
    pub const MANAGEMENT_LOGICAL_DEVICE: Self = Self::Single(1);

    /// A client SAP. 0x10 is the public client, 0x20 a meter reader, 0x30 management.
    #[must_use]
    pub const fn client(sap: u8) -> Self {
        Self::Single(sap)
    }

    /// A server address with a logical and a physical device.
    ///
    /// The four-byte form is chosen when either half needs more than seven bits, which
    /// is what a physical address like 0x3FFF ("any") requires.
    #[must_use]
    pub const fn server(logical: u16, physical: u16) -> Self {
        if logical <= 0x7F && physical <= 0x7F {
            Self::Double { upper: logical as u8, lower: physical as u8 }
        } else {
            Self::Quad { upper: logical, lower: physical }
        }
    }

    /// How many bytes this address occupies.
    #[must_use]
    pub const fn len(self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Double { .. } => 2,
            Self::Quad { .. } => 4,
        }
    }

    /// Always false; an address has at least one byte. Present because clippy asks for
    /// it next to `len`.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }

    fn encode(self, w: &mut dyn Writer) -> Result<()> {
        match self {
            Self::Single(v) => w.write_u8((v << 1) | 1),
            Self::Double { upper, lower } => w.write_bytes(&[upper << 1, (lower << 1) | 1]),
            Self::Quad { upper, lower } => w.write_bytes(&[
                ((upper >> 7) as u8) << 1,
                ((upper & 0x7F) as u8) << 1,
                ((lower >> 7) as u8) << 1,
                (((lower & 0x7F) as u8) << 1) | 1,
            ]),
        }
    }

    /// Read an address, stopping at the byte whose low bit is set.
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mut parts = [0u8; 4];
        let mut n = 0;
        loop {
            if n == 4 {
                return Err(r.err(ErrorKind::InvalidValue));
            }
            let b = r.u8()?;
            parts[n] = b >> 1;
            n += 1;
            if b & 1 != 0 {
                break;
            }
        }
        Ok(match n {
            1 => Self::Single(parts[0]),
            2 => Self::Double { upper: parts[0], lower: parts[1] },
            4 => Self::Quad {
                upper: (u16::from(parts[0]) << 7) | u16::from(parts[1]),
                lower: (u16::from(parts[2]) << 7) | u16::from(parts[3]),
            },
            // Three bytes is not a defined address length.
            _ => return Err(r.err(ErrorKind::InvalidValue)),
        })
    }
}

/// The control field: which kind of frame, and its sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Information frame, carrying an APDU fragment.
    I {
        /// Send sequence number, 0–7.
        ns: u8,
        /// Receive sequence number, 0–7.
        nr: u8,
        /// Poll or final bit.
        pf: bool,
    },
    /// Receive ready: acknowledges up to `nr` and invites the next frame.
    Rr {
        /// Receive sequence number.
        nr: u8,
        /// Poll or final bit.
        pf: bool,
    },
    /// Receive not ready: acknowledges, but asks the peer to pause.
    Rnr {
        /// Receive sequence number.
        nr: u8,
        /// Poll or final bit.
        pf: bool,
    },
    /// Set normal response mode: opens the link and negotiates parameters.
    Snrm,
    /// Unnumbered acknowledge: the answer to SNRM or DISC.
    Ua,
    /// Disconnect.
    Disc,
    /// Disconnected mode: the peer is not connected.
    Dm,
    /// Frame reject.
    Frmr,
    /// Unnumbered information, used by the discovery services.
    Ui,
}

impl Control {
    /// The control byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::I { ns, nr, pf } => ((nr & 7) << 5) | ((pf as u8) << 4) | ((ns & 7) << 1),
            Self::Rr { nr, pf } => ((nr & 7) << 5) | ((pf as u8) << 4) | 0x01,
            Self::Rnr { nr, pf } => ((nr & 7) << 5) | ((pf as u8) << 4) | 0x05,
            Self::Snrm => 0x93,
            Self::Ua => 0x73,
            Self::Disc => 0x53,
            Self::Dm => 0x1F,
            Self::Frmr => 0x97,
            Self::Ui => 0x13,
        }
    }

    /// Classify a control byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        if v & 1 == 0 {
            return Self::I { ns: (v >> 1) & 7, nr: (v >> 5) & 7, pf: v & 0x10 != 0 };
        }
        // Unnumbered frames are identified with the poll/final bit masked out.
        match v & !0x10 {
            0x83 => Self::Snrm,
            0x63 => Self::Ua,
            0x43 => Self::Disc,
            0x0F => Self::Dm,
            0x87 => Self::Frmr,
            0x03 => Self::Ui,
            _ => match v & 0x0F {
                0x01 => Self::Rr { nr: (v >> 5) & 7, pf: v & 0x10 != 0 },
                0x05 => Self::Rnr { nr: (v >> 5) & 7, pf: v & 0x10 != 0 },
                _ => Self::Frmr,
            },
        }
    }

    /// True when this frame carries no information field.
    #[must_use]
    pub const fn is_supervisory(self) -> bool {
        matches!(self, Self::Rr { .. } | Self::Rnr { .. })
    }
}

/// A decoded HDLC frame, borrowing its information field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// True when the APDU continues in the next frame.
    pub segmented: bool,
    /// Who the frame is for.
    pub destination: Address,
    /// Who sent it.
    pub source: Address,
    /// Which kind of frame.
    pub control: Control,
    /// The information field, empty for a supervisory or bare unnumbered frame.
    pub information: &'a [u8],
}

impl Frame<'_> {
    /// A frame with no information field.
    #[must_use]
    pub const fn control_only(destination: Address, source: Address, control: Control) -> Self {
        Self { segmented: false, destination, source, control, information: &[] }
    }

    /// The total encoded length, flags included.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let body = 2 + self.destination.len() + self.source.len() + 1;
        let info = if self.information.is_empty() { 0 } else { 2 + self.information.len() };
        1 + body + info + 2 + 1
    }
}

impl Encode for Frame<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        let header_len = 2 + self.destination.len() + self.source.len() + 1;
        let hcs_len = usize::from(!self.information.is_empty()) * 2;
        // The length in the format field spans everything between the flags.
        let frame_len = header_len + hcs_len + self.information.len() + 2;
        if frame_len > 0x7FF {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        }

        let mut header = [0u8; 12];
        let mut hw = crate::codec::SliceWriter::new(&mut header);
        let format = 0xA000 | (u16::from(self.segmented) << 11) | (frame_len as u16);
        hw.write_u16(format)?;
        self.destination.encode(&mut hw)?;
        self.source.encode(&mut hw)?;
        hw.write_u8(self.control.as_u8())?;
        let header_bytes_len = hw.written();
        let header = &header[..header_bytes_len];

        w.write_u8(FLAG)?;
        w.write_bytes(header)?;
        if !self.information.is_empty() {
            w.write_bytes(&fcs16(header).to_le_bytes())?;
            w.write_bytes(self.information)?;
        }
        // The frame check sequence covers the header, the HCS and the information.
        let mut fcs = 0xFFFFu16;
        fcs = crc_update(fcs, header);
        if !self.information.is_empty() {
            fcs = crc_update(fcs, &fcs16(header).to_le_bytes());
            fcs = crc_update(fcs, self.information);
        }
        w.write_bytes(&(!fcs).to_le_bytes())?;
        w.write_u8(FLAG)
    }
}

fn crc_update(mut fcs: u16, data: &[u8]) -> u16 {
    for b in data {
        fcs ^= u16::from(*b);
        for _ in 0..8 {
            fcs = if fcs & 1 != 0 { (fcs >> 1) ^ 0x8408 } else { fcs >> 1 };
        }
    }
    fcs
}

/// The shortest HDLC frame that can exist: the two format bytes, a one-byte destination,
/// a one-byte source, the control byte and the frame check sequence. Anything shorter
/// describes a frame with nowhere to put its own checksum.
const MIN_FRAME_LEN: usize = 2 + 1 + 1 + 1 + 2;

/// Decode one frame from `bytes`, which must start at the opening flag.
///
/// # Errors
/// [`ErrorKind::BadChecksum`] when the header or frame check sequence does not match,
/// [`ErrorKind::Truncated`] when the frame is not all there yet.
pub fn decode_frame(bytes: &[u8]) -> Result<(Frame<'_>, usize)> {
    let mut r = Reader::new(bytes);
    if r.u8()? != FLAG {
        return Err(r.err_back(ErrorKind::InvalidValue, 1));
    }
    let format = r.u16()?;
    if format & 0xF000 != 0xA000 {
        return Err(r.err_back(ErrorKind::InvalidValue, 2));
    }
    let segmented = format & 0x0800 != 0;
    let frame_len = usize::from(format & 0x07FF);
    if frame_len < MIN_FRAME_LEN {
        return Err(r.err_back(ErrorKind::InvalidLength, 2));
    }
    // The whole frame is the opening flag, `frame_len` bytes, and the closing flag.
    let total = 1 + frame_len + 1;
    if bytes.len() < total {
        return Err(Error::new(ErrorKind::Truncated { needed: total - bytes.len() }, bytes.len()));
    }
    if bytes[total - 1] != FLAG {
        return Err(Error::new(ErrorKind::InvalidValue, total - 1));
    }

    // Everything from here on is read out of the frame itself, never out of whatever
    // else the caller happened to have buffered behind it. The addresses are
    // variable-length and attacker-controlled, so a header that claims more bytes than
    // the frame holds must fail as a short read rather than reach past the closing flag.
    let frame = &bytes[..total];
    let mut r = Reader::new(frame);
    r.skip(3)?;
    let destination = Address::decode(&mut r)?;
    let source = Address::decode(&mut r)?;
    let control = Control::from_u8(r.u8()?);
    let header_end = r.offset();

    // The frame check sequence occupies the last two bytes before the closing flag.
    let fcs_at = total - 3;
    // A header that runs into or past the frame check sequence describes a frame that
    // cannot exist: there is nowhere for the checksum to be.
    if header_end > fcs_at {
        return Err(Error::new(ErrorKind::InvalidLength, header_end));
    }
    let header = &frame[1..header_end];
    let fcs = u16::from_le_bytes([frame[fcs_at], frame[fcs_at + 1]]);
    if fcs != fcs16(&frame[1..fcs_at]) {
        return Err(Error::new(ErrorKind::BadChecksum, fcs_at));
    }

    let information = if header_end == fcs_at {
        &[][..]
    } else {
        // An information field needs its own two-byte header check sequence in front of
        // it, so there must be room for both.
        if header_end + 2 > fcs_at {
            return Err(Error::new(ErrorKind::InvalidLength, header_end));
        }
        let hcs = u16::from_le_bytes([frame[header_end], frame[header_end + 1]]);
        if hcs != fcs16(header) {
            return Err(Error::new(ErrorKind::BadChecksum, header_end));
        }
        &frame[header_end + 2..fcs_at]
    };

    Ok((Frame { segmented, destination, source, control, information }, total))
}

/// What a [`Framer`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found<'a> {
    /// A complete, checksum-valid frame.
    Frame {
        /// The frame.
        frame: Frame<'a>,
        /// How many bytes of the input it used, including anything discarded before it.
        consumed: usize,
    },
    /// No complete frame yet.
    Incomplete {
        /// How many leading bytes are certainly not part of any frame and may be
        /// dropped.
        ///
        /// This is what keeps a receive buffer bounded on a noisy link: without it, a
        /// caller that keeps everything until a frame arrives grows without limit while
        /// a broken transmitter chatters.
        discard: usize,
    },
}

/// A resynchronising frame finder over a byte stream.
///
/// Feed it whatever arrives. It returns complete, checksum-valid frames and discards
/// everything else — line noise, the echo of the frame just sent on a half-duplex bus,
/// a partial frame from before the link came up.
///
/// The scan does not stop at the first flag that *might* begin a frame. A noise byte
/// that happens to look like a length field would otherwise make the finder wait
/// forever for a frame that was never sent, while the real frame sat in the buffer
/// behind it. So every flag position is tried, a complete frame wins over an incomplete
/// candidate, and only when nothing completes does the finder report how much it is
/// still waiting on.
#[derive(Debug, Default, Clone, Copy)]
pub struct Framer {
    discarded: usize,
}

impl Framer {
    /// A new finder.
    #[must_use]
    pub const fn new() -> Self {
        Self { discarded: 0 }
    }

    /// How many bytes have been thrown away. A rising count is the symptom of a
    /// mis-wired or noisy link, and is worth reporting.
    #[must_use]
    pub const fn discarded(&self) -> usize {
        self.discarded
    }

    /// Find the next frame in `buf`.
    ///
    /// # Errors
    /// Never, currently: a malformed candidate is discarded rather than reported, which
    /// is what a link layer facing noise has to do. The signature keeps the `Result` so
    /// a future policy — refusing after too many discards, say — does not break callers.
    pub fn next_frame<'b>(&mut self, buf: &'b [u8]) -> Result<Found<'b>> {
        let mut first_incomplete: Option<usize> = None;
        let mut start = 0usize;

        while start < buf.len() {
            let Some(rel) = buf[start..].iter().position(|b| *b == FLAG) else {
                break;
            };
            let from = start + rel;
            match decode_frame(&buf[from..]) {
                Ok((frame, used)) => {
                    self.discarded += from;
                    return Ok(Found::Frame { frame, consumed: from + used });
                }
                Err(e) => {
                    if e.is_truncated() && first_incomplete.is_none() {
                        first_incomplete = Some(from);
                    }
                    // This flag did not begin a frame. It may have been the *closing*
                    // flag of one, so the search resumes after it.
                    start = from + 1;
                }
            }
        }

        // Everything before the earliest candidate that might still complete is noise.
        let discard = first_incomplete.unwrap_or(buf.len());
        self.discarded += discard;
        Ok(Found::Incomplete { discard })
    }
}

/// Splits one LLC service data unit across as many information frames as it takes.
///
/// The information field is 128 bytes until SNRM negotiates otherwise, so an APDU of any
/// substance needs several frames: every one but the last sets the segmentation bit, and
/// the receiver concatenates the information fields.
///
/// Not the same mechanism as application-layer block transfer, and they compose. Block
/// transfer cuts a **value** into APDUs the PDU size can hold; this cuts each **APDU**
/// into frames the information field can hold. A meter with a 1024-byte PDU size on a
/// 128-byte link uses both at once.
///
/// The unit split is the whole LSDU — LLC header and APDU — because that is what the
/// link layer carries, so the header rides in the first segment only.
///
/// ```
/// use dlms_cosem_rs::transport::hdlc::{Address, Segmenter, LLC_REQUEST};
///
/// let apdu = [0xC0u8; 300];
/// let mut lsdu = [0u8; 3 + 300];
/// lsdu[..3].copy_from_slice(&LLC_REQUEST);
/// lsdu[3..].copy_from_slice(&apdu);
///
/// let mut segmenter = Segmenter::new(&lsdu, 128)?;
/// let mut frame = [0u8; 256];
/// let mut frames = 0;
/// while let Some(n) = segmenter.next_frame(
///     Address::server(1, 17), Address::client(0x10), 0, 0, &mut frame)?
/// {
///     assert!(n <= 128 + 16, "each frame fits the link");
///     frames += 1;
/// }
/// assert_eq!(frames, 3, "303 bytes at 128 per frame");
/// # Ok::<(), dlms_cosem_rs::Error>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Segmenter<'a> {
    lsdu: &'a [u8],
    sent: usize,
    max_info: usize,
}

impl<'a> Segmenter<'a> {
    /// Split `lsdu` into information fields of at most `max_info` bytes.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidLength`] when `max_info` is zero, which would never finish.
    pub fn new(lsdu: &'a [u8], max_info: u16) -> Result<Self> {
        if max_info == 0 {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        }
        Ok(Self { lsdu, sent: 0, max_info: usize::from(max_info) })
    }

    /// True when every segment has been produced.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.sent >= self.lsdu.len()
    }

    /// How many bytes are still to go out.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.lsdu.len().saturating_sub(self.sent)
    }

    /// Encode the next frame into `out`, or `None` when there are none left.
    ///
    /// `ns` and `nr` are the link's sequence numbers; the caller owns flow control and
    /// advances them, because a station that is also acknowledging the peer's frames
    /// knows things this type does not.
    ///
    /// # Errors
    /// When `out` is too small for the frame.
    pub fn next_frame(
        &mut self,
        destination: Address,
        source: Address,
        ns: u8,
        nr: u8,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        if self.is_done() {
            return Ok(None);
        }
        let end = self.sent.saturating_add(self.max_info).min(self.lsdu.len());
        let information = self.lsdu.get(self.sent..end).ok_or(Error::new(ErrorKind::InvalidLength, 0))?;
        let segmented = end < self.lsdu.len();
        let frame = Frame {
            segmented,
            destination,
            source,
            // The poll/final bit closes the transmission, so it belongs on the last
            // segment: a station that sets it on every one invites the peer to answer
            // in the middle of an APDU.
            control: Control::I { ns, nr, pf: !segmented },
            information,
        };
        let mut w = crate::codec::SliceWriter::new(out);
        frame.encode(&mut w)?;
        self.sent = end;
        Ok(Some(w.written()))
    }
}

/// Reassembles an LLC service data unit from segmented information frames.
///
/// The buffer is the caller's, as everywhere else: the largest APDU a link must carry
/// is a property of the deployment, and a reassembler that allocated one would be the
/// crate deciding it.
///
/// Frames are required to arrive with consecutive send-sequence numbers. That is not
/// bookkeeping — a lost or duplicated segment concatenated in the wrong place produces
/// a byte string that often still decodes, into an APDU that is simply wrong.
#[derive(Debug)]
pub struct Reassembler<'a> {
    buf: &'a mut [u8],
    len: usize,
    /// The send-sequence number the next segment must carry, once one has arrived.
    expect_ns: Option<u8>,
    complete: bool,
}

impl<'a> Reassembler<'a> {
    /// A reassembler filling `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0, expect_ns: None, complete: false }
    }

    /// Feed one frame. Returns true when a complete LSDU is available.
    ///
    /// Frames that carry no information — supervisory and unnumbered ones — are ignored
    /// rather than refused, so a caller can hand over everything the framer finds.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] when a segment arrives out of sequence;
    /// [`ErrorKind::BufferTooSmall`] when the reassembled unit does not fit.
    pub fn push(&mut self, frame: &Frame<'_>) -> Result<bool> {
        let Control::I { ns, .. } = frame.control else {
            return Ok(false);
        };
        if self.complete {
            // The previous unit was never taken; starting a new one over the top of it
            // would silently discard it.
            self.reset();
        }
        if let Some(expected) = self.expect_ns {
            if ns != expected {
                return Err(Error::new(ErrorKind::UnexpectedMessage, self.len));
            }
        }
        let end = self.len.saturating_add(frame.information.len());
        let capacity = self.buf.len();
        let at = self.len;
        let slot = self
            .buf
            .get_mut(at..end)
            .ok_or(Error::new(ErrorKind::BufferTooSmall { needed: end.saturating_sub(capacity) }, at))?;
        slot.copy_from_slice(frame.information);
        self.len = end;
        self.expect_ns = Some((ns + 1) % 8);
        self.complete = !frame.segmented;
        Ok(self.complete)
    }

    /// The reassembled unit — the LLC header and the APDU behind it.
    ///
    /// Empty until [`Reassembler::push`] has returned true.
    #[must_use]
    pub fn lsdu(&self) -> &[u8] {
        if self.complete { self.buf.get(..self.len).unwrap_or(&[]) } else { &[] }
    }

    /// How many bytes have been gathered, complete or not.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True before any information has been gathered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Discard everything, ready for the next unit.
    pub const fn reset(&mut self) {
        self.len = 0;
        self.expect_ns = None;
        self.complete = false;
    }
}

/// Which end of the link a [`Connection`] is.
///
/// HDLC as DLMS uses it is not symmetric: the client is the *primary* station and the
/// only one that may open the link or poll, and the server answers. A connection that did
/// not know which it was would let a meter send an SNRM, which no meter does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The primary station: opens the link, polls, and sets the poll bit.
    Client,
    /// The secondary station: answers, and sets the final bit.
    Server,
}

/// Where the link is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// No link. An information frame here is refused.
    Disconnected,
    /// An SNRM has gone out and the UA has not come back.
    Connecting,
    /// Normal response mode: information frames may flow.
    Connected,
    /// A DISC has gone out.
    Disconnecting,
}

/// What a received frame means for the caller.
///
/// Every variant is something to *do*, which is the point: a caller loops on frames and
/// branches on this, and there is nothing else it has to know about HDLC's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Nothing to do; keep reading.
    Idle,
    /// The link came up. [`Connection::parameters`] are what both ends agreed.
    Connected,
    /// The link went down, because the peer asked or refused.
    Disconnected,
    /// A complete service data unit is in the reassembler.
    Lsdu,
    /// Answer with what [`Connection::acknowledge`] builds — a UA confirming the peer's
    /// SNRM or DISC.
    AcknowledgeRequired,
    /// The peer has stopped short of a complete unit and is waiting to be asked for the
    /// rest: send what [`Connection::poll`] builds.
    PollRequired,
}

/// One HDLC link, with its sequence numbers.
///
/// [`Framer`], [`Segmenter`] and [`Reassembler`] are the pieces; this is the machine that
/// drives them, and it exists because the pieces alone leave the caller holding the two
/// things that are easy to get wrong: **the SNRM/UA handshake**, whose answer carries the
/// parameters every later frame is sized by, and **the send and receive sequence
/// numbers**, which are modulo eight, advance on different events for each role, and
/// produce a link that half works when they drift.
///
/// What it deliberately does **not** do is recover from loss. Retransmission needs a
/// timer, and there is no clock in this crate ([`crate::transport`]); a frame out of
/// sequence is reported by name so the caller can reset the link, rather than being
/// silently accepted into the wrong place in a service data unit. Naming that limit is
/// worth more than a retry loop that cannot time out.
///
/// ```
/// use dlms_cosem_rs::transport::hdlc::{Address, Connection, Event, Parameters, Role};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client_addr = Address::client(0x10);
/// let server_addr = Address::server(1, 17);
/// let mut client = Connection::new(Role::Client, client_addr, server_addr, Parameters::default());
/// let mut server = Connection::new(Role::Server, server_addr, client_addr, Parameters::default());
///
/// let mut buf = [0u8; 128];
/// let mut storage = [0u8; 512];
/// let mut into = dlms_cosem_rs::transport::hdlc::Reassembler::new(&mut storage);
///
/// // The client opens the link and the server confirms it.
/// let n = client.connect(&mut buf)?;
/// let (frame, _) = dlms_cosem_rs::transport::hdlc::decode_frame(&buf[..n])?;
/// assert_eq!(server.handle(&frame, &mut into)?, Event::AcknowledgeRequired);
///
/// let mut reply = [0u8; 128];
/// let n = server.acknowledge(&mut reply)?;
/// let (frame, _) = dlms_cosem_rs::transport::hdlc::decode_frame(&reply[..n])?;
/// assert_eq!(client.handle(&frame, &mut into)?, Event::Connected);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Connection {
    role: Role,
    local: Address,
    peer: Address,
    state: LinkState,
    /// The sequence number the next information frame this station sends will carry.
    ns: u8,
    /// The sequence number this station next expects from the peer.
    nr: u8,
    proposed: Parameters,
    negotiated: Parameters,
    /// What the pending [`Connection::acknowledge`] is answering.
    acknowledging: Option<Control>,
}

impl Connection {
    /// A link between `local` and `peer`, proposing `proposed` when it opens.
    ///
    /// Until SNRM and UA have been exchanged the link runs on
    /// [`Parameters::default`] — 128-byte information fields and a window of one — which
    /// is what the standard says a station must assume, and what an optical probe often
    /// stays on.
    #[must_use]
    pub const fn new(role: Role, local: Address, peer: Address, proposed: Parameters) -> Self {
        Self {
            role,
            local,
            peer,
            state: LinkState::Disconnected,
            ns: 0,
            nr: 0,
            proposed,
            negotiated: Parameters::DEFAULT,
            acknowledging: None,
        }
    }

    /// Where the link is.
    #[must_use]
    pub const fn state(&self) -> LinkState {
        self.state
    }

    /// What both ends agreed, or the defaults before they have.
    #[must_use]
    pub const fn parameters(&self) -> Parameters {
        self.negotiated
    }

    /// True when information frames may flow.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(self.state, LinkState::Connected)
    }

    /// Build the SNRM that opens the link.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] on a server, which never opens a link, or when
    /// one is already open; [`ErrorKind::BufferTooSmall`] when `out` is too small.
    pub fn connect(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.role != Role::Client || self.state == LinkState::Connected {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        let mut info = [0u8; 32];
        let mut iw = crate::codec::SliceWriter::new(&mut info);
        self.proposed.encode(&mut iw)?;
        let n = iw.written();
        let frame = Frame {
            segmented: false,
            destination: self.peer,
            source: self.local,
            control: Control::Snrm,
            information: info.get(..n).unwrap_or(&[]),
        };
        let mut w = crate::codec::SliceWriter::new(out);
        frame.encode(&mut w)?;
        self.state = LinkState::Connecting;
        Ok(w.written())
    }

    /// Build the DISC that closes the link.
    ///
    /// # Errors
    /// When `out` is too small.
    pub fn disconnect(&mut self, out: &mut [u8]) -> Result<usize> {
        let frame = Frame::control_only(self.peer, self.local, Control::Disc);
        let mut w = crate::codec::SliceWriter::new(out);
        frame.encode(&mut w)?;
        self.state = LinkState::Disconnecting;
        Ok(w.written())
    }

    /// Build the UA that [`Event::AcknowledgeRequired`] asked for.
    ///
    /// Answering an SNRM it carries the negotiated parameters, which is how the peer
    /// learns what it may actually send; answering a DISC it carries nothing.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] when nothing is waiting to be acknowledged.
    pub fn acknowledge(&mut self, out: &mut [u8]) -> Result<usize> {
        let pending = self.acknowledging.take().ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        let mut info = [0u8; 32];
        let mut n = 0;
        if pending == Control::Snrm {
            let mut iw = crate::codec::SliceWriter::new(&mut info);
            self.negotiated.encode(&mut iw)?;
            n = iw.written();
        }
        let frame = Frame {
            segmented: false,
            destination: self.peer,
            source: self.local,
            control: Control::Ua,
            information: info.get(..n).unwrap_or(&[]),
        };
        let mut w = crate::codec::SliceWriter::new(out);
        frame.encode(&mut w)?;
        Ok(w.written())
    }

    /// Build the receive-ready frame that [`Event::PollRequired`] asked for.
    ///
    /// It carries this station's receive sequence number, which is what tells the peer
    /// where to continue, and the poll bit, which is what gives it permission to.
    ///
    /// # Errors
    /// When `out` is too small.
    pub fn poll(&mut self, out: &mut [u8]) -> Result<usize> {
        let frame = Frame::control_only(self.peer, self.local, Control::Rr { nr: self.nr, pf: true });
        let mut w = crate::codec::SliceWriter::new(out);
        frame.encode(&mut w)?;
        Ok(w.written())
    }

    /// Split a service data unit — the LLC header and the APDU behind it — into frames
    /// this link can carry.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] when the link is not open.
    pub fn segmenter<'d>(&self, lsdu: &'d [u8]) -> Result<Segmenter<'d>> {
        if self.state != LinkState::Connected {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        Segmenter::new(lsdu, self.negotiated.max_info_tx)
    }

    /// Emit the next frame of a unit, advancing the send sequence number.
    ///
    /// This is the reason the segmenter is driven through the connection rather than
    /// used directly: `ns` advances once per information frame, modulo eight, and a
    /// caller keeping it by hand is a caller whose link works until the ninth frame.
    ///
    /// # Errors
    /// When the link is not open, or `out` is too small.
    pub fn next_frame(&mut self, segmenter: &mut Segmenter<'_>, out: &mut [u8]) -> Result<Option<usize>> {
        if self.state != LinkState::Connected {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        let n = segmenter.next_frame(self.peer, self.local, self.ns, self.nr, out)?;
        if n.is_some() {
            self.ns = (self.ns + 1) % 8;
        }
        Ok(n)
    }

    /// Take one received frame and say what it means.
    ///
    /// Frames carrying information are pushed into `into`; supervisory and unnumbered
    /// frames are handled here.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] for a frame that is not addressed to this
    /// station, or whose send sequence number is neither the expected one nor a repeat
    /// of the last accepted one — recovering from *that* needs a timer this crate does
    /// not have, so it is named rather than guessed at.
    pub fn handle(&mut self, frame: &Frame<'_>, into: &mut Reassembler<'_>) -> Result<Event> {
        // A frame for somebody else on a shared bus is not this link's business. RS-485
        // segments carry several meters, and accepting one addressed elsewhere mixes two
        // conversations into one reassembly buffer.
        if frame.destination != self.local {
            return Ok(Event::Idle);
        }
        match frame.control {
            Control::Snrm => {
                if self.role != Role::Server {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
                let peer = Parameters::decode(frame.information)?;
                self.negotiated = self.proposed.negotiate(peer);
                self.reset_sequence();
                self.state = LinkState::Connected;
                self.acknowledging = Some(Control::Snrm);
                into.reset();
                Ok(Event::AcknowledgeRequired)
            }
            Control::Ua => {
                if self.state == LinkState::Connecting {
                    // The UA carries the parameters the peer actually agreed to, and
                    // every later frame is sized by them.
                    let peer = Parameters::decode(frame.information)?;
                    self.negotiated = self.proposed.negotiate(peer);
                    self.reset_sequence();
                    self.state = LinkState::Connected;
                    into.reset();
                    return Ok(Event::Connected);
                }
                // Otherwise it answers our DISC.
                self.state = LinkState::Disconnected;
                Ok(Event::Disconnected)
            }
            Control::Disc => {
                self.state = LinkState::Disconnected;
                self.acknowledging = Some(Control::Disc);
                Ok(Event::AcknowledgeRequired)
            }
            // The peer is not connected, or rejected the frame. Either way the link is
            // not usable and pretending otherwise wastes a round trip per frame.
            Control::Dm | Control::Frmr => {
                self.state = LinkState::Disconnected;
                Ok(Event::Disconnected)
            }
            Control::I { ns, .. } => {
                if self.state != LinkState::Connected {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
                // A repeat of the frame just accepted is a retransmission of something
                // already held: ignoring it is right, and concatenating it again is the
                // bug that produces an APDU with a duplicated middle.
                if ns == (self.nr + 7) % 8 {
                    return Ok(Event::Idle);
                }
                if ns != self.nr {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
                self.nr = (self.nr + 1) % 8;
                if into.push(frame)? {
                    return Ok(Event::Lsdu);
                }
                // The unit is not finished. If the peer has given up the line — the
                // poll/final bit closes a transmission — it is waiting to be asked for
                // the rest.
                let handed_over = match frame.control {
                    Control::I { pf, .. } => pf,
                    _ => false,
                };
                Ok(if handed_over { Event::PollRequired } else { Event::Idle })
            }
            Control::Rr { .. } | Control::Rnr { .. } | Control::Ui => Ok(Event::Idle),
        }
    }

    /// Forget the link, ready for a new one on the same wire.
    pub const fn reset(&mut self) {
        self.state = LinkState::Disconnected;
        self.negotiated = Parameters::DEFAULT;
        self.acknowledging = None;
        self.reset_sequence();
    }

    /// SNRM and UA reset both counters at both ends. A station that carried them over
    /// answers the first frame of a new link with the sequence number of the last frame
    /// of the old one.
    const fn reset_sequence(&mut self) {
        self.ns = 0;
        self.nr = 0;
    }
}

/// The link parameters SNRM proposes and UA confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    /// The largest information field this side will send.
    pub max_info_tx: u16,
    /// The largest information field this side will accept.
    pub max_info_rx: u16,
    /// How many frames this side will send before an acknowledgement.
    pub window_tx: u32,
    /// How many frames this side will accept before acknowledging.
    pub window_rx: u32,
}

impl Default for Parameters {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Parameters {
    /// The values a station must assume when the peer negotiates nothing: 128-byte
    /// information fields and a window of one.
    ///
    /// Not a guess and not a minimum — it is what the standard says both ends run on
    /// until SNRM and UA say otherwise, and what a great many optical probes never leave.
    pub const DEFAULT: Self = Self { max_info_tx: 128, max_info_rx: 128, window_tx: 1, window_rx: 1 };

    /// Encode as the SNRM/UA information field.
    pub fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        let mut body = [0u8; 32];
        let mut bw = crate::codec::SliceWriter::new(&mut body);
        write_param(&mut bw, 5, u32::from(self.max_info_tx))?;
        write_param(&mut bw, 6, u32::from(self.max_info_rx))?;
        write_param(&mut bw, 7, self.window_tx)?;
        write_param(&mut bw, 8, self.window_rx)?;
        let n = bw.written();
        w.write_bytes(&[0x81, 0x80, n as u8])?;
        w.write_bytes(&body[..n])
    }

    /// Decode an SNRM/UA information field, keeping the default for anything absent.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut out = Self::default();
        if bytes.is_empty() {
            return Ok(out);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x81 || r.u8()? != 0x80 {
            return Err(r.err_back(ErrorKind::InvalidValue, 2));
        }
        let len = usize::from(r.u8()?);
        let mut inner = Reader::with_base(r.take(len)?, 3);
        while !inner.is_empty() {
            let id = inner.u8()?;
            let vlen = usize::from(inner.u8()?);
            let raw = inner.take(vlen)?;
            let mut v: u32 = 0;
            for b in raw {
                v = (v << 8) | u32::from(*b);
            }
            match id {
                5 => out.max_info_tx = u16::try_from(v).unwrap_or(u16::MAX),
                6 => out.max_info_rx = u16::try_from(v).unwrap_or(u16::MAX),
                7 => out.window_tx = v,
                8 => out.window_rx = v,
                _ => {}
            }
        }
        Ok(out)
    }

    /// What both sides can do: each side's send limit capped by the other's receive
    /// limit.
    #[must_use]
    pub const fn negotiate(self, peer: Self) -> Self {
        Self {
            max_info_tx: if self.max_info_tx < peer.max_info_rx {
                self.max_info_tx
            } else {
                peer.max_info_rx
            },
            max_info_rx: if self.max_info_rx < peer.max_info_tx {
                self.max_info_rx
            } else {
                peer.max_info_tx
            },
            window_tx: if self.window_tx < peer.window_rx { self.window_tx } else { peer.window_rx },
            window_rx: if self.window_rx < peer.window_tx { self.window_rx } else { peer.window_tx },
        }
    }
}

fn write_param(w: &mut dyn Writer, id: u8, value: u32) -> Result<()> {
    let be = value.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(3);
    let n = 4 - first;
    w.write_bytes(&[id, n as u8])?;
    w.write_bytes(&be[first..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    /// The X-25 / PPP check value for "123456789", which is what every published FCS-16
    /// description uses as its own test.
    #[test]
    fn fcs16_matches_the_published_check_value() {
        assert_eq!(fcs16(b"123456789"), 0x906E);
    }

    #[test]
    fn addresses_round_trip_in_every_width() {
        for a in [
            Address::Single(0x10),
            Address::Double { upper: 1, lower: 0x11 },
            Address::Quad { upper: 1, lower: 0x3FFF },
        ] {
            let mut buf = [0u8; 8];
            let mut w = SliceWriter::new(&mut buf);
            a.encode(&mut w).unwrap();
            let n = w.written();
            assert_eq!(n, a.len());
            assert_eq!(buf[n - 1] & 1, 1, "the last byte marks the end");
            assert_eq!(Address::decode(&mut Reader::new(&buf[..n])).unwrap(), a);
        }
    }

    #[test]
    fn a_client_address_is_the_sap_shifted_and_marked() {
        let mut buf = [0u8; 4];
        let mut w = SliceWriter::new(&mut buf);
        Address::client(0x10).encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x21]);
    }

    #[test]
    fn a_wide_physical_address_forces_the_four_byte_form() {
        assert_eq!(Address::server(1, 0x3FFF).len(), 4);
        assert_eq!(Address::server(1, 17).len(), 2);
    }

    #[test]
    fn control_bytes_round_trip() {
        for c in [
            Control::Snrm,
            Control::Ua,
            Control::Disc,
            Control::Dm,
            Control::Ui,
            Control::I { ns: 3, nr: 5, pf: true },
            Control::Rr { nr: 2, pf: false },
            Control::Rnr { nr: 7, pf: true },
        ] {
            assert_eq!(Control::from_u8(c.as_u8()), c, "{c:?} -> {:#04x}", c.as_u8());
        }
        assert_eq!(Control::Snrm.as_u8(), 0x93);
        assert_eq!(Control::Ua.as_u8(), 0x73);
        assert_eq!(Control::Disc.as_u8(), 0x53);
    }

    #[test]
    fn a_frame_with_information_carries_both_check_sequences() {
        let frame = Frame {
            segmented: false,
            destination: Address::server(1, 17),
            source: Address::client(0x10),
            control: Control::I { ns: 0, nr: 0, pf: true },
            information: &[0xE6, 0xE6, 0x00, 0xC0, 0x01, 0x81],
        };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        frame.encode(&mut w).unwrap();
        let bytes = w.as_slice();
        assert_eq!(bytes[0], FLAG);
        assert_eq!(*bytes.last().unwrap(), FLAG);
        assert_eq!(bytes.len(), frame.encoded_len());
        let (back, used) = decode_frame(bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(back, frame);
    }

    #[test]
    fn a_supervisory_frame_has_no_header_check_sequence() {
        let frame = Frame::control_only(
            Address::server(1, 17),
            Address::client(0x10),
            Control::Rr { nr: 1, pf: true },
        );
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        frame.encode(&mut w).unwrap();
        let (back, _) = decode_frame(w.as_slice()).unwrap();
        assert_eq!(back, frame);
        assert!(back.information.is_empty());
    }

    #[test]
    fn a_flipped_bit_is_caught_by_the_frame_check_sequence() {
        let frame = Frame {
            segmented: false,
            destination: Address::client(0x10),
            source: Address::server(1, 17),
            control: Control::I { ns: 0, nr: 1, pf: true },
            information: &[1, 2, 3, 4],
        };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        frame.encode(&mut w).unwrap();
        let n = w.written();
        for i in 1..n - 1 {
            let mut corrupt = buf;
            corrupt[i] ^= 0x01;
            if corrupt[i] == FLAG || buf[i] == FLAG {
                continue;
            }
            assert!(decode_frame(&corrupt[..n]).is_err(), "a flipped bit at {i} was not caught");
        }
    }

    #[test]
    fn the_framer_resynchronises_past_noise() {
        let frame = Frame {
            segmented: false,
            destination: Address::client(0x10),
            source: Address::server(1, 17),
            control: Control::Ua,
            information: &[0x81, 0x80, 0x06, 0x05, 0x01, 0x80, 0x06, 0x01, 0x80],
        };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        frame.encode(&mut w).unwrap();
        let good = w.as_slice().to_vec();

        let mut stream = alloc::vec::Vec::new();
        stream.extend_from_slice(&[0xAA, 0x7E, 0x55, 0x00]); // noise, including a flag
        stream.extend_from_slice(&good);

        let mut framer = Framer::new();
        let Found::Frame { frame: back, consumed } = framer.next_frame(&stream).unwrap() else {
            panic!("the frame behind the noise was not found");
        };
        assert_eq!(back, frame);
        assert_eq!(consumed, stream.len());
        assert!(framer.discarded() >= 4, "the noise was counted");
    }

    #[test]
    fn the_framer_waits_rather_than_failing_on_a_partial_frame() {
        let frame = Frame::control_only(Address::client(0x10), Address::server(1, 17), Control::Ua);
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        frame.encode(&mut w).unwrap();
        let n = w.written();
        let mut framer = Framer::new();
        for split in 1..n {
            assert!(
                matches!(framer.next_frame(&buf[..split]).unwrap(), Found::Incomplete { discard: 0 }),
                "a frame cut at {split} must be waited for, not rejected or discarded"
            );
        }
        assert!(matches!(framer.next_frame(&buf[..n]).unwrap(), Found::Frame { .. }));
    }

    /// Split, frame, find, reassemble — and get the same bytes back.
    #[test]
    fn a_long_apdu_survives_segmentation_and_reassembly() {
        let lsdu: alloc::vec::Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for max_info in [1u16, 2, 31, 32, 33, 128, 999, 1000, 1001] {
            let mut stream = alloc::vec::Vec::new();
            let mut segmenter = Segmenter::new(&lsdu, max_info).unwrap();
            let mut ns = 0u8;
            let mut frames = 0;
            let mut buf = [0u8; 1100];
            while let Some(n) =
                segmenter.next_frame(Address::server(1, 17), Address::client(0x10), ns, 0, &mut buf).unwrap()
            {
                stream.extend_from_slice(&buf[..n]);
                ns = (ns + 1) % 8;
                frames += 1;
            }
            let expected_frames = lsdu.len().div_ceil(usize::from(max_info));
            assert_eq!(frames, expected_frames, "at {max_info} bytes a frame");

            let mut storage = [0u8; 1100];
            let mut assembled = Reassembler::new(&mut storage);
            let mut framer = Framer::new();
            let mut offset = 0;
            let mut done = false;
            while let Ok(Found::Frame { frame, consumed }) = framer.next_frame(&stream[offset..]) {
                assert!(
                    frame.information.len() <= usize::from(max_info),
                    "a segment overran the negotiated information field"
                );
                done = assembled.push(&frame).unwrap();
                offset += consumed;
                if done {
                    break;
                }
            }
            assert!(done, "the last segment must clear the segmentation bit");
            assert_eq!(assembled.lsdu(), &lsdu[..], "at {max_info} bytes a frame");
        }
    }

    /// The poll/final bit closes a transmission, so it goes on the last segment only.
    /// Setting it on every one invites the peer to answer in the middle of an APDU.
    #[test]
    fn only_the_last_segment_is_final() {
        let lsdu = [0xAAu8; 300];
        let mut segmenter = Segmenter::new(&lsdu, 128).unwrap();
        let mut buf = [0u8; 256];
        let mut flags = alloc::vec::Vec::new();
        while let Some(n) =
            segmenter.next_frame(Address::server(1, 17), Address::client(0x10), 0, 0, &mut buf).unwrap()
        {
            let (frame, _) = decode_frame(&buf[..n]).unwrap();
            let Control::I { pf, .. } = frame.control else { panic!("not an information frame") };
            flags.push((frame.segmented, pf));
        }
        assert_eq!(flags, [(true, false), (true, false), (false, true)]);
    }

    #[test]
    fn a_segment_out_of_sequence_is_refused_rather_than_concatenated() {
        let mut storage = [0u8; 64];
        let mut assembled = Reassembler::new(&mut storage);
        let seg = |ns, segmented, info| Frame {
            segmented,
            destination: Address::client(0x10),
            source: Address::server(1, 17),
            control: Control::I { ns, nr: 0, pf: !segmented },
            information: info,
        };
        assert!(!assembled.push(&seg(0, true, &[1, 2])).unwrap());
        // A repeat of the frame just taken, and a gap, are both refused.
        assert_eq!(assembled.push(&seg(0, true, &[1, 2])).unwrap_err().kind, ErrorKind::UnexpectedMessage);
        assert_eq!(assembled.push(&seg(3, true, &[9])).unwrap_err().kind, ErrorKind::UnexpectedMessage);
        assert!(assembled.push(&seg(1, false, &[3])).unwrap());
        assert_eq!(assembled.lsdu(), [1, 2, 3]);
    }

    #[test]
    fn the_sequence_number_wraps_at_eight() {
        let mut storage = [0u8; 64];
        let mut assembled = Reassembler::new(&mut storage);
        for ns in 0..8u8 {
            let last = ns == 7;
            let frame = Frame {
                segmented: !last,
                destination: Address::client(0x10),
                source: Address::server(1, 17),
                control: Control::I { ns, nr: 0, pf: last },
                information: &[ns],
            };
            assert_eq!(assembled.push(&frame).unwrap(), last);
        }
        assert_eq!(assembled.lsdu(), [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn frames_that_carry_nothing_are_ignored_not_refused() {
        // A caller should be able to hand over everything the framer finds.
        let mut storage = [0u8; 32];
        let mut assembled = Reassembler::new(&mut storage);
        let rr = Frame::control_only(
            Address::client(0x10),
            Address::server(1, 17),
            Control::Rr { nr: 1, pf: true },
        );
        assert!(!assembled.push(&rr).unwrap());
        assert!(assembled.is_empty());
    }

    #[test]
    fn a_unit_too_large_for_the_buffer_is_refused_before_it_overruns() {
        let mut storage = [0u8; 4];
        let mut assembled = Reassembler::new(&mut storage);
        let frame = Frame {
            segmented: true,
            destination: Address::client(0x10),
            source: Address::server(1, 17),
            control: Control::I { ns: 0, nr: 0, pf: false },
            information: &[0; 8],
        };
        assert!(matches!(assembled.push(&frame).unwrap_err().kind, ErrorKind::BufferTooSmall { .. }));
    }

    #[test]
    fn an_information_field_of_zero_would_never_finish() {
        assert_eq!(Segmenter::new(&[1, 2, 3], 0).unwrap_err().kind, ErrorKind::InvalidLength);
    }

    /// A whole link, both ends in one process: open it, carry a unit that needs several
    /// frames, and close it — with neither side keeping a sequence number by hand.
    #[test]
    fn a_link_opens_carries_a_long_unit_and_closes() {
        let client_addr = Address::client(0x10);
        let server_addr = Address::server(1, 17);
        let proposed = Parameters { max_info_tx: 64, max_info_rx: 64, window_tx: 1, window_rx: 1 };
        let mut client = Connection::new(Role::Client, client_addr, server_addr, proposed);
        let mut server = Connection::new(Role::Server, server_addr, client_addr, Parameters::default());

        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        let mut client_storage = [0u8; 1024];
        let mut server_storage = [0u8; 1024];
        let mut to_server = Reassembler::new(&mut server_storage);
        let mut to_client = Reassembler::new(&mut client_storage);

        // SNRM / UA.
        let n = client.connect(&mut a).unwrap();
        let (f, _) = decode_frame(&a[..n]).unwrap();
        assert_eq!(server.handle(&f, &mut to_server).unwrap(), Event::AcknowledgeRequired);
        let m = server.acknowledge(&mut b).unwrap();
        let (f, _) = decode_frame(&b[..m]).unwrap();
        assert_eq!(client.handle(&f, &mut to_client).unwrap(), Event::Connected);
        assert!(client.is_connected() && server.is_connected());
        // Each side sends at most what the other will receive.
        assert_eq!(client.parameters().max_info_tx, 64);
        assert_eq!(server.parameters().max_info_tx, 64, "capped by what the client proposed to receive");

        // A unit several frames long, from client to server.
        let lsdu: alloc::vec::Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let mut segmenter = client.segmenter(&lsdu).unwrap();
        let mut sequence_numbers = alloc::vec::Vec::new();
        let mut event = Event::Idle;
        while let Some(n) = client.next_frame(&mut segmenter, &mut a).unwrap() {
            let (f, _) = decode_frame(&a[..n]).unwrap();
            let Control::I { ns, .. } = f.control else { panic!("an information frame") };
            sequence_numbers.push(ns);
            event = server.handle(&f, &mut to_server).unwrap();
        }
        assert_eq!(sequence_numbers, [0, 1, 2, 3], "the connection counted, not the caller");
        assert_eq!(event, Event::Lsdu);
        assert_eq!(to_server.lsdu(), &lsdu[..]);

        // And back, with the roles reversed.
        let reply: alloc::vec::Vec<u8> = (0..150u32).map(|i| (i % 97) as u8).collect();
        let mut segmenter = server.segmenter(&reply).unwrap();
        let mut event = Event::Idle;
        while let Some(m) = server.next_frame(&mut segmenter, &mut b).unwrap() {
            let (f, _) = decode_frame(&b[..m]).unwrap();
            event = client.handle(&f, &mut to_client).unwrap();
        }
        assert_eq!(event, Event::Lsdu);
        assert_eq!(to_client.lsdu(), &reply[..]);

        // DISC / UA.
        let n = client.disconnect(&mut a).unwrap();
        let (f, _) = decode_frame(&a[..n]).unwrap();
        assert_eq!(server.handle(&f, &mut to_server).unwrap(), Event::AcknowledgeRequired);
        let m = server.acknowledge(&mut b).unwrap();
        let (f, _) = decode_frame(&b[..m]).unwrap();
        assert_eq!(client.handle(&f, &mut to_client).unwrap(), Event::Disconnected);
        assert!(!client.is_connected() && !server.is_connected());
    }

    /// The counters are modulo eight, so a link that carries more than eight frames is
    /// where a hand-kept sequence number goes wrong — and it goes wrong by *working*
    /// for the first eight.
    #[test]
    fn the_sequence_numbers_wrap_at_eight_and_keep_working() {
        let client_addr = Address::client(0x10);
        let server_addr = Address::server(1, 17);
        let mut client = Connection::new(Role::Client, client_addr, server_addr, Parameters::default());
        let mut server = Connection::new(Role::Server, server_addr, client_addr, Parameters::default());
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        let mut storage = [0u8; 4096];
        let mut into = Reassembler::new(&mut storage);
        let mut scratch = [0u8; 64];
        let mut ignored = Reassembler::new(&mut scratch);

        let n = client.connect(&mut a).unwrap();
        let (f, _) = decode_frame(&a[..n]).unwrap();
        server.handle(&f, &mut into).unwrap();
        let m = server.acknowledge(&mut b).unwrap();
        let (f, _) = decode_frame(&b[..m]).unwrap();
        client.handle(&f, &mut ignored).unwrap();

        // Twenty frames' worth: two and a half turns of the modulo-eight counter.
        let lsdu = [0xABu8; 20 * 128];
        let mut segmenter = client.segmenter(&lsdu).unwrap();
        let mut seen = alloc::vec::Vec::new();
        let mut event = Event::Idle;
        while let Some(n) = client.next_frame(&mut segmenter, &mut a).unwrap() {
            let (f, _) = decode_frame(&a[..n]).unwrap();
            let Control::I { ns, .. } = f.control else { panic!() };
            seen.push(ns);
            event = server.handle(&f, &mut into).unwrap();
        }
        assert_eq!(seen.len(), 20);
        assert_eq!(&seen[..10], &[0, 1, 2, 3, 4, 5, 6, 7, 0, 1], "and it wrapped");
        assert_eq!(event, Event::Lsdu);
        assert_eq!(into.lsdu().len(), lsdu.len());
    }

    /// A frame addressed to another station on the same bus belongs to another
    /// conversation. Accepting it mixes two of them into one reassembly buffer.
    #[test]
    fn a_frame_for_another_station_is_ignored_rather_than_reassembled() {
        let mut server = Connection::new(
            Role::Server,
            Address::server(1, 17),
            Address::client(0x10),
            Parameters::default(),
        );
        let mut storage = [0u8; 64];
        let mut into = Reassembler::new(&mut storage);
        let elsewhere = Frame {
            segmented: false,
            destination: Address::server(1, 99),
            source: Address::client(0x10),
            control: Control::I { ns: 0, nr: 0, pf: true },
            information: &[1, 2, 3],
        };
        assert_eq!(server.handle(&elsewhere, &mut into).unwrap(), Event::Idle);
        assert!(into.is_empty(), "nothing of another station's conversation was kept");
    }

    /// A retransmission of the frame just accepted is ignored; a gap is named. Recovering
    /// from the gap needs a timer, which is the caller's, so the link says so rather than
    /// concatenating the fragment into the wrong place.
    #[test]
    fn a_repeat_is_ignored_and_a_gap_is_named() {
        let client_addr = Address::client(0x10);
        let server_addr = Address::server(1, 17);
        let mut client = Connection::new(Role::Client, client_addr, server_addr, Parameters::default());
        let mut server = Connection::new(Role::Server, server_addr, client_addr, Parameters::default());
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        let mut storage = [0u8; 256];
        let mut into = Reassembler::new(&mut storage);
        let mut scratch = [0u8; 64];
        let mut ignored = Reassembler::new(&mut scratch);

        let n = client.connect(&mut a).unwrap();
        let (f, _) = decode_frame(&a[..n]).unwrap();
        server.handle(&f, &mut into).unwrap();
        let m = server.acknowledge(&mut b).unwrap();
        let (f, _) = decode_frame(&b[..m]).unwrap();
        client.handle(&f, &mut ignored).unwrap();

        let lsdu = [0xAAu8; 200];
        let mut segmenter = client.segmenter(&lsdu).unwrap();
        let n = client.next_frame(&mut segmenter, &mut a).unwrap().unwrap();
        let (first, _) = decode_frame(&a[..n]).unwrap();
        assert_eq!(server.handle(&first, &mut into).unwrap(), Event::Idle);
        let held = into.len();
        // The same frame again.
        assert_eq!(server.handle(&first, &mut into).unwrap(), Event::Idle);
        assert_eq!(into.len(), held, "a retransmission must not be concatenated twice");

        // And a frame from two places further on.
        let jumped = Frame {
            segmented: true,
            destination: server_addr,
            source: client_addr,
            control: Control::I { ns: 5, nr: 0, pf: false },
            information: &[9, 9],
        };
        assert_eq!(server.handle(&jumped, &mut into).unwrap_err().kind, ErrorKind::UnexpectedMessage);
    }

    /// A server never opens a link, and nothing may flow before one is open.
    #[test]
    fn the_roles_are_not_interchangeable() {
        let mut server = Connection::new(
            Role::Server,
            Address::server(1, 17),
            Address::client(0x10),
            Parameters::default(),
        );
        let mut out = [0u8; 64];
        assert_eq!(server.connect(&mut out).unwrap_err().kind, ErrorKind::UnexpectedMessage);
        assert_eq!(server.segmenter(&[1, 2, 3]).unwrap_err().kind, ErrorKind::UnexpectedMessage);
        assert_eq!(server.acknowledge(&mut out).unwrap_err().kind, ErrorKind::UnexpectedMessage);
    }

    #[test]
    fn snrm_parameters_round_trip_and_negotiate_downwards() {
        let p = Parameters { max_info_tx: 512, max_info_rx: 1024, window_tx: 3, window_rx: 5 };
        let mut buf = [0u8; 64];
        let mut w = SliceWriter::new(&mut buf);
        p.encode(&mut w).unwrap();
        assert_eq!(Parameters::decode(w.as_slice()).unwrap(), p);

        let peer = Parameters { max_info_tx: 256, max_info_rx: 128, window_tx: 1, window_rx: 1 };
        let n = p.negotiate(peer);
        assert_eq!(n.max_info_tx, 128, "capped by what the peer will receive");
        assert_eq!(n.max_info_rx, 256);
        assert_eq!(n.window_tx, 1);
    }

    #[test]
    fn an_empty_information_field_means_the_defaults() {
        assert_eq!(Parameters::decode(&[]).unwrap(), Parameters::default());
    }

    #[test]
    fn a_false_candidate_does_not_hide_the_frame_behind_it() {
        // A noise byte that looks like the start of a long frame, then a real one. A
        // finder that stopped at the first plausible flag would wait for a frame that
        // was never sent while the real one sat behind it.
        let frame = Frame::control_only(Address::client(0x10), Address::server(1, 17), Control::Ua);
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        frame.encode(&mut w).unwrap();
        let good = w.as_slice();

        let mut stream = alloc::vec::Vec::new();
        stream.extend_from_slice(&[0x7E, 0xA0, 0x7E]); // claims a 126-byte frame
        stream.extend_from_slice(good);

        let mut framer = Framer::new();
        let Found::Frame { frame: back, consumed } = framer.next_frame(&stream).unwrap() else {
            panic!("the real frame was not found behind a false candidate");
        };
        assert_eq!(back, frame);
        assert_eq!(consumed, stream.len());
    }

    #[test]
    fn a_buffer_of_pure_noise_is_entirely_discardable() {
        let mut framer = Framer::new();
        let noise = [0xAAu8, 0xBB, 0xCC, 0xDD];
        assert_eq!(
            framer.next_frame(&noise).unwrap(),
            Found::Incomplete { discard: 4 },
            "with no flag at all, every byte can go"
        );
        assert_eq!(framer.discarded(), 4);
    }

    #[test]
    fn noise_before_a_partial_frame_is_discardable_and_the_partial_is_kept() {
        let frame = Frame::control_only(Address::client(0x10), Address::server(1, 17), Control::Ua);
        let mut buf = [0u8; 32];
        let mut w = SliceWriter::new(&mut buf);
        frame.encode(&mut w).unwrap();
        let n = w.written();

        let mut stream = alloc::vec::Vec::new();
        stream.extend_from_slice(&[0x11, 0x22, 0x33]);
        stream.extend_from_slice(&buf[..n - 2]); // cut short

        let mut framer = Framer::new();
        assert_eq!(
            framer.next_frame(&stream).unwrap(),
            Found::Incomplete { discard: 3 },
            "the leading noise goes, the partial frame stays"
        );
    }
}
