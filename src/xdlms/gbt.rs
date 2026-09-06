//! General block transfer.
//!
//! GBT moves an APDU that does not fit the negotiated maximum size, in either
//! direction, independently of which service it carries. The procedure was rewritten in
//! Green Book edition 9 with an explicit window, a streaming sub-procedure and a retry
//! sub-procedure; this is that version.
//!
//! The block control byte packs three things: the last-block flag, the streaming flag,
//! and a six-bit window size. A window of zero is not "no window" — it is the value a
//! sender uses when it is not streaming, and treating it as a window of one is how a
//! streaming peer ends up waiting forever for an acknowledgement that is not coming.

use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, SliceWriter, Writer};

/// The block control byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockControl(pub u8);

impl BlockControl {
    /// A control byte.
    #[must_use]
    pub const fn new(last_block: bool, streaming: bool, window: u8) -> Self {
        let mut v = window & 0x3F;
        if last_block {
            v |= 0x80;
        }
        if streaming {
            v |= 0x40;
        }
        Self(v)
    }

    /// True when no further block follows.
    #[must_use]
    pub const fn last_block(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// True when the sender is streaming: it will send a whole window without waiting.
    #[must_use]
    pub const fn streaming(self) -> bool {
        self.0 & 0x40 != 0
    }

    /// How many blocks the sender will send before it expects an acknowledgement.
    #[must_use]
    pub const fn window(self) -> u8 {
        self.0 & 0x3F
    }
}

/// One block of a general block transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralBlockTransfer<'a> {
    /// Last-block flag, streaming flag and window size.
    pub control: BlockControl,
    /// This block's number, counting from one.
    pub block_number: u16,
    /// The highest block number the sender has received from the peer.
    pub block_number_ack: u16,
    /// The fragment of the carried APDU.
    pub block_data: &'a [u8],
}

impl GeneralBlockTransfer<'_> {
    /// An acknowledgement carrying no data, used to open the next window.
    #[must_use]
    pub const fn ack(block_number_ack: u16, window: u8) -> Self {
        Self {
            control: BlockControl::new(false, false, window),
            block_number: 0,
            block_number_ack,
            block_data: &[],
        }
    }
}

impl Encode for GeneralBlockTransfer<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.control.0)?;
        w.write_u16(self.block_number)?;
        w.write_u16(self.block_number_ack)?;
        w.write_length_prefixed(self.block_data)
    }
}

impl<'a> Decode<'a> for GeneralBlockTransfer<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            control: BlockControl(r.u8()?),
            block_number: r.u16()?,
            block_number_ack: r.u16()?,
            block_data: r.length_prefixed()?,
        })
    }
}

/// The largest window a sender will use, which is what the six-bit field can carry.
pub const GBT_WINDOW_MAX: u8 = 0x3F;

/// Splits an APDU into general block transfer blocks, and takes acknowledgements back.
///
/// GBT is the *other* segmentation mechanism, and it is not a substitute for the
/// service-specific one: block transfer cuts a **value** into APDUs, GBT cuts an
/// **APDU** into blocks, and it does so for any service — including the ones that have
/// no blocked form of their own, which is the whole reason it exists.
///
/// Two sub-procedures, both from the text rewritten in Green Book edition 9:
///
/// * **Streaming.** The sender may put `window` blocks on the wire before it waits for
///   an acknowledgement. A window of zero is not "no window": it is the value a sender
///   uses when it is *not* streaming, and treating it as one is how a streaming peer
///   ends up waiting forever for an acknowledgement nobody owes it.
/// * **Retry.** An acknowledgement names the highest block the peer received **in
///   order**. One lower than the last block sent is not an error — it is the receiver
///   saying where the run broke, and the sender rewinds to just after it. That is why
///   [`GbtSender::acknowledge`] moves the cursor *backwards* rather than refusing.
///
/// The bytes stay the caller's, as everywhere else here.
///
/// ```
/// use dlms_cosem_rs::codec::Decode;
/// use dlms_cosem_rs::xdlms::{GbtAction, GbtReceiver, GbtSender, GeneralBlockTransfer};
///
/// let apdu = [0xC4u8; 300];                   // a get-response, too big for the link
/// let mut sender = GbtSender::new(&apdu, 100, 4, true)?;
/// let mut storage = [0u8; 512];
/// let mut receiver = GbtReceiver::new(&mut storage);
///
/// let mut frame = [0u8; 256];
/// while !sender.is_done() {
///     while let Some(n) = sender.next_block(&mut frame)? {
///         let block = GeneralBlockTransfer::from_bytes(&frame[..n])?;
///         if receiver.push(&block)? != GbtAction::Await {
///             sender.acknowledge(receiver.acknowledged())?;
///         }
///     }
/// }
/// assert_eq!(receiver.apdu(), &apdu[..]);
/// # Ok::<(), dlms_cosem_rs::Error>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct GbtSender<'a> {
    apdu: &'a [u8],
    /// The number of the last block emitted. Blocks count from one.
    block: u16,
    /// The highest block the peer has acknowledged.
    acked: u16,
    /// How many bytes each block but the last carries.
    ///
    /// Non-zero by construction rather than by a check the optimiser cannot see: a
    /// `div_ceil` by a plain `usize` leaves a divide-by-zero panic path in the object
    /// code, and this crate's headline property is that there are none.
    fragment: core::num::NonZeroUsize,
    window: u8,
    streaming: bool,
}

impl<'a> GbtSender<'a> {
    /// Split `apdu` into blocks of at most `fragment` bytes.
    ///
    /// `window` is how many blocks may be outstanding when `streaming`; it is clamped to
    /// [`GBT_WINDOW_MAX`] and forced to one when not streaming, which is what a
    /// non-streaming sender means.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidLength`] when `fragment` is zero, which would never finish,
    /// or when the APDU needs more blocks than a sixteen-bit number can name.
    pub fn new(apdu: &'a [u8], fragment: usize, window: u8, streaming: bool) -> Result<Self> {
        let Some(fragment) = core::num::NonZeroUsize::new(fragment) else {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        };
        let blocks = apdu.len().div_ceil(fragment.get()).max(1);
        if u16::try_from(blocks).is_err() {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        }
        let window = if streaming { window.clamp(1, GBT_WINDOW_MAX) } else { 1 };
        Ok(Self { apdu, block: 0, acked: 0, fragment, window, streaming })
    }

    /// How many blocks the whole APDU takes.
    #[must_use]
    pub const fn blocks(&self) -> u16 {
        let n = self.apdu.len().div_ceil(self.fragment.get());
        // An empty APDU is still one block: it has to be sent for the peer to learn
        // that it is the last one.
        if n == 0 { 1 } else { n as u16 }
    }

    /// True when every block has been sent *and* acknowledged.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.acked >= self.blocks()
    }

    /// The number of the last block emitted; zero before the first.
    #[must_use]
    pub const fn block(&self) -> u16 {
        self.block
    }

    /// Emit the next block, or `None` when the window is full and an acknowledgement is
    /// owed first.
    ///
    /// # Errors
    /// When `out` is too small for the block.
    pub fn next_block(&mut self, out: &mut [u8]) -> Result<Option<usize>> {
        let total = self.blocks();
        if self.block >= total {
            return Ok(None);
        }
        // Outstanding = emitted but not yet acknowledged. A non-streaming sender has a
        // window of one, so it emits a block and then waits, which is the same rule.
        if self.block.saturating_sub(self.acked) >= u16::from(self.window) {
            return Ok(None);
        }

        let number = self.block.saturating_add(1);
        let start = usize::from(self.block).saturating_mul(self.fragment.get());
        let end = start.saturating_add(self.fragment.get()).min(self.apdu.len());
        let last = number == total;
        let frame = GeneralBlockTransfer {
            control: BlockControl::new(last, self.streaming, self.window),
            block_number: number,
            // A sender that is not also receiving has nothing of the peer's to
            // acknowledge; a caller driving both directions sets this from its receiver.
            block_number_ack: 0,
            block_data: self.apdu.get(start..end).unwrap_or(&[]),
        };
        let mut w = SliceWriter::new(out);
        frame.encode(&mut w)?;
        self.block = number;
        Ok(Some(w.written()))
    }

    /// Take the peer's acknowledgement.
    ///
    /// One lower than the last block sent rewinds the sender to just after it: that is
    /// the retry sub-procedure, and it is the whole reason an acknowledgement carries a
    /// number rather than being a bare "go on".
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] when the peer acknowledges a block that was
    /// never sent, which no honest receiver does.
    pub fn acknowledge(&mut self, block_number_ack: u16) -> Result<()> {
        if block_number_ack > self.block {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        self.acked = block_number_ack;
        // Rewind: everything after the acknowledged block is sent again.
        self.block = block_number_ack;
        Ok(())
    }
}

/// What a [`GbtReceiver`] wants done after a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbtAction {
    /// The sender is streaming and its window is not full. Keep reading.
    Await,
    /// Send an acknowledgement carrying [`GbtReceiver::acknowledged`].
    Acknowledge,
    /// The APDU is complete; [`GbtReceiver::apdu`] has it. Acknowledge as well.
    Complete,
}

/// Reassembles an APDU from general block transfer blocks.
///
/// The buffer is the caller's: the largest APDU a link must carry is a property of the
/// deployment, and a receiver that allocated one would be this crate deciding it.
///
/// Out-of-order and duplicate blocks are handled rather than refused, because that is
/// what the retry sub-procedure is made of. A block ahead of the run is **not** stored:
/// acknowledging the last one received in order is precisely how the receiver tells the
/// sender where to resume, and storing the future block as well would leave a hole that
/// nothing fills.
#[derive(Debug)]
pub struct GbtReceiver<'a> {
    buf: &'a mut [u8],
    len: usize,
    /// The highest block received in order. Blocks count from one.
    received: u16,
    /// How many in-order blocks have arrived since the last acknowledgement.
    since_ack: u8,
    complete: bool,
}

impl<'a> GbtReceiver<'a> {
    /// A receiver filling `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0, received: 0, since_ack: 0, complete: false }
    }

    /// Take one block.
    ///
    /// # Errors
    /// [`ErrorKind::BufferTooSmall`] when the APDU does not fit.
    pub fn push(&mut self, block: &GeneralBlockTransfer<'_>) -> Result<GbtAction> {
        if self.complete {
            // The previous APDU was never taken; starting a new one over the top of it
            // would silently discard it.
            self.reset();
        }
        let expected = self.received.saturating_add(1);
        if block.block_number != expected {
            // Either a duplicate the sender resent, or one from beyond the gap. Both
            // answers are the same: say where the run actually reaches and let the
            // sender rewind to it.
            self.since_ack = 0;
            return Ok(GbtAction::Acknowledge);
        }

        let end = self.len.saturating_add(block.block_data.len());
        let capacity = self.buf.len();
        let at = self.len;
        let slot = self.buf.get_mut(at..end).ok_or_else(|| {
            Error::new(ErrorKind::BufferTooSmall { needed: end.saturating_sub(capacity) }, at)
        })?;
        slot.copy_from_slice(block.block_data);
        self.len = end;
        self.received = block.block_number;
        self.since_ack = self.since_ack.saturating_add(1);

        if block.control.last_block() {
            self.complete = true;
            self.since_ack = 0;
            return Ok(GbtAction::Complete);
        }
        // A window of zero on a non-streaming sender means one block at a time.
        let window = if block.control.streaming() { block.control.window().max(1) } else { 1 };
        if self.since_ack >= window {
            self.since_ack = 0;
            return Ok(GbtAction::Acknowledge);
        }
        Ok(GbtAction::Await)
    }

    /// The block number to acknowledge: the highest received in order.
    #[must_use]
    pub const fn acknowledged(&self) -> u16 {
        self.received
    }

    /// Encode the acknowledgement this receiver owes.
    ///
    /// # Errors
    /// When `out` is too small.
    pub fn acknowledgement(&self, window: u8, out: &mut [u8]) -> Result<usize> {
        let mut w = SliceWriter::new(out);
        GeneralBlockTransfer::ack(self.received, window).encode(&mut w)?;
        Ok(w.written())
    }

    /// The reassembled APDU. Empty until [`GbtReceiver::push`] has returned
    /// [`GbtAction::Complete`].
    #[must_use]
    pub fn apdu(&self) -> &[u8] {
        if self.complete { self.buf.get(..self.len).unwrap_or(&[]) } else { &[] }
    }

    /// How many bytes have been gathered, complete or not.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True before any block has been taken.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Discard everything, ready for the next APDU.
    pub const fn reset(&mut self) {
        self.len = 0;
        self.received = 0;
        self.since_ack = 0;
        self.complete = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_bits_are_independent() {
        let c = BlockControl::new(true, false, 7);
        assert!(c.last_block());
        assert!(!c.streaming());
        assert_eq!(c.window(), 7);
        assert_eq!(c.0, 0x87);

        let c = BlockControl::new(false, true, 0);
        assert!(!c.last_block());
        assert!(c.streaming());
        assert_eq!(c.window(), 0, "a window of zero is a value, not an absence");
        assert_eq!(c.0, 0x40);
    }

    #[test]
    fn a_block_round_trips() {
        let b = GeneralBlockTransfer {
            control: BlockControl::new(false, true, 4),
            block_number: 1,
            block_number_ack: 0,
            block_data: &[0xC4, 0x01, 0x81],
        };
        let mut buf = [0u8; 32];
        let mut w = crate::codec::SliceWriter::new(&mut buf);
        b.encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x44, 0x00, 0x01, 0x00, 0x00, 0x03, 0xC4, 0x01, 0x81]);
        assert_eq!(GeneralBlockTransfer::from_bytes(w.as_slice()).unwrap(), b);
    }

    /// Drive a whole APDU across, one block at a time, with no streaming.
    #[test]
    fn an_apdu_crosses_block_by_block_and_comes_back_identical() {
        let apdu: alloc::vec::Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for fragment in [1usize, 7, 128, 999, 1000, 1001] {
            let mut sender = GbtSender::new(&apdu, fragment, 1, false).unwrap();
            let mut storage = [0u8; 1100];
            let mut receiver = GbtReceiver::new(&mut storage);
            let mut frame = [0u8; 1100];
            let mut blocks = 0;
            while !sender.is_done() {
                let Some(n) = sender.next_block(&mut frame).unwrap() else {
                    panic!("a non-streaming sender must always have a block to send");
                };
                blocks += 1;
                let block = GeneralBlockTransfer::from_bytes(&frame[..n]).unwrap();
                let action = receiver.push(&block).unwrap();
                assert_ne!(action, GbtAction::Await, "a window of one acknowledges every block");
                sender.acknowledge(receiver.acknowledged()).unwrap();
            }
            assert_eq!(blocks, sender.blocks(), "at {fragment} bytes a block");
            assert_eq!(receiver.apdu(), &apdu[..], "at {fragment} bytes a block");
        }
    }

    /// Streaming: the sender puts a whole window on the wire before it waits.
    #[test]
    fn a_streaming_sender_fills_its_window_before_waiting() {
        let apdu = [0xAAu8; 500];
        let mut sender = GbtSender::new(&apdu, 50, 4, true).unwrap();
        let mut frame = [0u8; 128];
        // Four blocks go out with nothing coming back.
        for _ in 0..4 {
            assert!(sender.next_block(&mut frame).unwrap().is_some());
        }
        assert!(
            sender.next_block(&mut frame).unwrap().is_none(),
            "the fifth block waits for an acknowledgement"
        );
        sender.acknowledge(2).unwrap();
        // Two are now clear, so two more may go — and they are blocks 3 and 4 again,
        // because acknowledging 2 rewound the sender.
        let n = sender.next_block(&mut frame).unwrap().unwrap();
        assert_eq!(GeneralBlockTransfer::from_bytes(&frame[..n]).unwrap().block_number, 3);
    }

    /// The exit criterion for GBT: a dropped block is recovered by resuming after the
    /// last one that arrived, not by restarting the transfer.
    #[test]
    fn a_dropped_block_is_recovered_by_retry_rather_than_by_starting_again() {
        let apdu: alloc::vec::Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let mut sender = GbtSender::new(&apdu, 100, 6, true).unwrap();
        let mut storage = [0u8; 700];
        let mut receiver = GbtReceiver::new(&mut storage);
        let mut frame = [0u8; 256];

        let mut emitted = 0usize;
        let mut dropped_once = false;
        while !sender.is_done() {
            let Some(n) = sender.next_block(&mut frame).unwrap() else {
                sender.acknowledge(receiver.acknowledged()).unwrap();
                continue;
            };
            emitted += 1;
            let block = GeneralBlockTransfer::from_bytes(&frame[..n]).unwrap();
            // Lose block 3 exactly once. Everything after it arrives, and must not be
            // stored out of order.
            if block.block_number == 3 && !dropped_once {
                dropped_once = true;
                continue;
            }
            if receiver.push(&block).unwrap() != GbtAction::Await {
                sender.acknowledge(receiver.acknowledged()).unwrap();
            }
        }
        assert!(dropped_once);
        assert_eq!(receiver.apdu(), &apdu[..], "the APDU is whole and in order");
        assert!(emitted > 6, "the lost block and the ones after it were sent again");
        assert!(emitted < 6 * 3, "and the transfer did not restart from the beginning");
    }

    /// A receiver never stores a block from beyond a gap: acknowledging where the run
    /// really reaches is what makes the sender come back for the missing one, and
    /// keeping the future block as well would leave a hole nothing fills.
    #[test]
    fn a_block_from_beyond_a_gap_is_not_stored() {
        let mut storage = [0u8; 64];
        let mut receiver = GbtReceiver::new(&mut storage);
        let block = |n, last, data| GeneralBlockTransfer {
            control: BlockControl::new(last, false, 1),
            block_number: n,
            block_number_ack: 0,
            block_data: data,
        };
        assert_eq!(receiver.push(&block(1, false, &[1, 2])).unwrap(), GbtAction::Acknowledge);
        // Block 2 is lost; block 3 arrives.
        assert_eq!(receiver.push(&block(3, false, &[9, 9])).unwrap(), GbtAction::Acknowledge);
        assert_eq!(receiver.acknowledged(), 1, "the run still only reaches block one");
        assert_eq!(receiver.len(), 2, "and nothing from beyond the gap was kept");
        // A duplicate of what is already held changes nothing either.
        assert_eq!(receiver.push(&block(1, false, &[1, 2])).unwrap(), GbtAction::Acknowledge);
        assert_eq!(receiver.len(), 2);
        // The retry closes the gap.
        assert_eq!(receiver.push(&block(2, false, &[3, 4])).unwrap(), GbtAction::Acknowledge);
        assert_eq!(receiver.push(&block(3, true, &[5, 6])).unwrap(), GbtAction::Complete);
        assert_eq!(receiver.apdu(), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn an_acknowledgement_of_a_block_never_sent_is_refused() {
        let apdu = [0u8; 100];
        let mut sender = GbtSender::new(&apdu, 50, 1, false).unwrap();
        let mut frame = [0u8; 128];
        sender.next_block(&mut frame).unwrap();
        assert_eq!(sender.acknowledge(7).unwrap_err().kind, ErrorKind::UnexpectedMessage);
    }

    #[test]
    fn a_fragment_of_zero_would_never_finish() {
        assert_eq!(GbtSender::new(&[1, 2, 3], 0, 1, false).unwrap_err().kind, ErrorKind::InvalidLength);
    }
}
