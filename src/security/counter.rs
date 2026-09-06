//! Invocation counters and replay rejection.
//!
//! The counter is the second half of every nonce. Reusing one with the same key repeats
//! a GCM nonce, and repeating a GCM nonce does not merely leak a plaintext — it leaks
//! the authentication subkey, after which anyone can forge messages. So the rules here
//! are strict on purpose:
//!
//! * a sender never reuses a value, and refuses to encrypt rather than wrapping;
//! * a receiver accepts each value **at most once**;
//! * a receiver that tolerates reordering still accepts each value at most once.
//!
//! That last rule is the one that is easy to get wrong. A receiver that remembers only
//! the highest counter it has seen and then accepts anything within `n` of it has not
//! built a replay window — it has built a hole `n` wide that the same frame can be
//! replayed through as often as an attacker likes. A real window remembers *which* of
//! the recent values have arrived, which is what [`ReplayWindow`] does.

use crate::codec::{Error, ErrorKind, Result};

/// A sending counter.
///
/// The value is *the last one used*, so the first call to [`InvocationCounter::next`]
/// after `new(v)` yields `v + 1`.
///
/// # Surviving a restart
///
/// A counter that restarts from zero against a key that has not changed reuses every
/// nonce it used before. Nothing in this crate can detect that, because the peer has no
/// way to tell a restarted meter from a replayed one — it will simply reject the
/// traffic, and the key is burnt either way. The value must therefore outlive the
/// process: read [`InvocationCounter::get`] and persist it, and hand the stored value
/// back through the session or server configuration on the way up.
///
/// A device that cannot persist on every message should persist in blocks — store
/// `n + 1000`, use up to that, store again — so a crash costs a thousand unused values
/// rather than a reused one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InvocationCounter(u32);

impl InvocationCounter {
    /// A counter whose last used value was `v`. The next value sent will be `v + 1`.
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    /// The last value used. This is the value to persist.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Take the next value.
    ///
    /// # Errors
    /// [`ErrorKind::Unsupported`] when the counter has reached `u32::MAX`. There is no
    /// safe next value: the association must be re-keyed.
    #[allow(
        clippy::should_implement_trait,
        reason = "a counter is not an iterator; `next` is the domain's word"
    )]
    pub fn next(&mut self) -> Result<u32> {
        let next = self.0.checked_add(1).ok_or(Error::new(ErrorKind::Unsupported, 0))?;
        self.0 = next;
        Ok(next)
    }
}

/// How many invocation counters a [`ReplayWindow`] remembers: the highest accepted,
/// plus the `REPLAY_WINDOW_MAX - 1` values below it.
///
/// The bitmap is a `u64`, so the largest usable reorder *width* is one less than this —
/// [`ReplayWindow::new`] clamps to that. A width equal to the slot count would name a
/// value the bitmap has no bit for, and the check would then reject what the constructor
/// said it would accept.
pub const REPLAY_WINDOW_MAX: u32 = 64;

/// The largest reorder width [`ReplayWindow::new`] will honour.
pub const REPLAY_WIDTH_MAX: u32 = REPLAY_WINDOW_MAX - 1;

/// Accepts each invocation counter from one peer at most once.
///
/// The window is the standard one — the shape IPsec (RFC 4303 appendix A) and DTLS use:
/// the highest counter seen, plus a bitmap of which of the `width` values below it have
/// already arrived. A counter above the highest advances the window; one inside it is
/// accepted only if its bit is clear; one below it, or already seen, is a replay.
///
/// The default width is **zero**, which accepts only strictly increasing counters. That
/// is right for HDLC, TCP and anything else that delivers in order. Widen it only for a
/// transport that genuinely reorders — UDP, a store-and-forward gateway, LoRaWAN — and
/// know that the width is how far out of order a frame may arrive, not how much replay
/// is tolerated: none is, at any width.
///
/// ```
/// use dlms_cosem_rs::security::ReplayWindow;
///
/// let mut w = ReplayWindow::new(4);
/// assert!(w.accept(10).is_ok());
/// assert!(w.accept(12).is_ok());
/// assert!(w.accept(11).is_ok(), "arrived late, but never seen before");
/// assert!(w.accept(11).is_err(), "the same frame again is a replay");
/// assert!(w.accept(3).is_err(), "too old to prove anything about");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplayWindow {
    /// The highest counter accepted, if any has been.
    highest: Option<u32>,
    /// Bit `i` records that `highest - i` has been accepted. Bit 0 is `highest` itself.
    seen: u64,
    /// How far below `highest` to accept at all.
    width: u32,
}

impl ReplayWindow {
    /// A window accepting only strictly increasing counters.
    #[must_use]
    pub const fn strict() -> Self {
        Self { highest: None, seen: 0, width: 0 }
    }

    /// A window that tolerates arrival up to `width` values out of order.
    ///
    /// `width` is clamped to [`REPLAY_WIDTH_MAX`], which is the widest the bitmap can
    /// actually answer for. Clamping to the slot count instead would leave the
    /// constructor promising a width the check refuses.
    #[must_use]
    pub const fn new(width: u32) -> Self {
        Self {
            highest: None,
            seen: 0,
            width: if width > REPLAY_WIDTH_MAX { REPLAY_WIDTH_MAX } else { width },
        }
    }

    /// The reorder width in force, after clamping.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Resume a window whose peer's highest accepted counter is known.
    ///
    /// Everything at or below `highest` is treated as already seen, which is the safe
    /// reading of a value restored from storage: it is a lower bound on what arrived.
    #[must_use]
    pub const fn resumed(highest: u32, width: u32) -> Self {
        let mut w = Self::new(width);
        w.highest = Some(highest);
        w.seen = u64::MAX;
        w
    }

    /// The highest counter accepted so far. This is the value to persist.
    #[must_use]
    pub const fn highest(&self) -> Option<u32> {
        self.highest
    }

    /// Whether `received` would be accepted, without recording it.
    ///
    /// This is the cheap check to run *before* verifying a tag, so a flood of obvious
    /// replays costs no cryptography. It must never be the only check: an attacker who
    /// could advance the window with a counter that later fails to verify would lock
    /// the real peer out, so nothing is recorded until [`ReplayWindow::accept`] is
    /// called on a message whose tag has already verified.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when the counter has been seen or is too old.
    pub fn check(&self, received: u32) -> Result<()> {
        let replay = || Error::new(ErrorKind::BadTag, 0);
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if received > highest {
            return Ok(());
        }
        let back = highest - received;
        if back > self.width || back >= REPLAY_WINDOW_MAX {
            return Err(replay());
        }
        if self.seen & (1u64 << back) != 0 {
            return Err(replay());
        }
        Ok(())
    }

    /// Record `received` as accepted, having verified the message it came with.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when the counter has been seen or is too old.
    pub fn accept(&mut self, received: u32) -> Result<()> {
        self.check(received)?;
        match self.highest {
            None => {
                self.highest = Some(received);
                self.seen = 1;
            }
            Some(highest) if received > highest => {
                let advance = received - highest;
                // Shifting a `u64` by 64 or more is undefined in C and a panic in Rust;
                // an advance that large simply empties the window.
                self.seen = if advance >= REPLAY_WINDOW_MAX { 0 } else { self.seen << advance };
                self.seen |= 1;
                self.highest = Some(received);
            }
            Some(highest) => {
                let back = highest - received;
                self.seen |= 1u64 << back;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_value_sent_is_one_past_the_stored_one() {
        let mut c = InvocationCounter::new(0);
        assert_eq!(c.next().unwrap(), 1);
        assert_eq!(c.next().unwrap(), 2);
        assert_eq!(c.get(), 2);
    }

    #[test]
    fn exhaustion_refuses_rather_than_wrapping() {
        let mut c = InvocationCounter::new(u32::MAX);
        assert_eq!(c.next().unwrap_err().kind, ErrorKind::Unsupported);
        assert_eq!(c.get(), u32::MAX, "and does not move");
    }

    #[test]
    fn a_strict_window_accepts_only_what_is_higher() {
        let mut w = ReplayWindow::strict();
        assert!(w.accept(5).is_ok(), "the first message has nothing to beat");
        assert!(w.accept(6).is_ok());
        assert_eq!(w.accept(6).unwrap_err().kind, ErrorKind::BadTag, "equal is a replay");
        assert_eq!(w.accept(5).unwrap_err().kind, ErrorKind::BadTag, "lower is a replay");
        assert!(w.accept(7).is_ok());
        assert_eq!(w.highest(), Some(7));
    }

    /// The property the old "accept anything within n" check did not have.
    #[test]
    fn a_widened_window_still_accepts_each_value_exactly_once() {
        let mut w = ReplayWindow::new(16);
        assert!(w.accept(100).is_ok());
        // Everything below arrives late, in a scrambled order, and each is taken once.
        for v in [99u32, 95, 88, 97, 90] {
            assert!(w.accept(v).is_ok(), "{v} has not been seen");
            assert_eq!(w.accept(v).unwrap_err().kind, ErrorKind::BadTag, "{v} twice is a replay");
        }
        // And replaying the value that opened the window is still a replay.
        assert_eq!(w.accept(100).unwrap_err().kind, ErrorKind::BadTag);
    }

    #[test]
    fn a_value_older_than_the_window_is_refused_however_wide_it_is() {
        let mut w = ReplayWindow::new(REPLAY_WINDOW_MAX * 4);
        assert!(w.accept(1000).is_ok());
        assert_eq!(w.accept(1000 - REPLAY_WINDOW_MAX).unwrap_err().kind, ErrorKind::BadTag);
        assert!(w.accept(1000 - REPLAY_WINDOW_MAX + 1).is_ok(), "the oldest value still inside");
    }

    #[test]
    fn a_large_jump_forward_empties_the_window_rather_than_shifting_out_of_range() {
        let mut w = ReplayWindow::new(32);
        assert!(w.accept(1).is_ok());
        assert!(w.accept(u32::MAX).is_ok(), "a jump of four billion must not panic");
        assert_eq!(w.highest(), Some(u32::MAX));
        assert_eq!(w.accept(u32::MAX).unwrap_err().kind, ErrorKind::BadTag);
        assert_eq!(w.accept(1).unwrap_err().kind, ErrorKind::BadTag, "long since out of the window");
    }

    #[test]
    fn checking_does_not_record() {
        // The ordering that keeps a forged counter from locking out the real peer.
        let mut w = ReplayWindow::strict();
        assert!(w.accept(10).is_ok());
        assert!(w.check(11).is_ok());
        assert!(w.check(11).is_ok(), "checking twice is still fine: nothing was recorded");
        assert_eq!(w.highest(), Some(10), "a check must not advance the window");
        assert!(w.accept(11).is_ok());
    }

    /// Every width the constructor accepts is a width the check honours. The bug this
    /// pins: clamping to the slot count let `new(64)` promise a reorder depth of 64
    /// while `check` refused anything 64 back, so the widest window silently behaved
    /// like the next one down.
    #[test]
    fn the_widest_window_accepts_exactly_as_far_back_as_it_claims() {
        let w = ReplayWindow::new(u32::MAX);
        assert_eq!(w.width(), REPLAY_WIDTH_MAX);
        for width in [0u32, 1, 7, REPLAY_WIDTH_MAX] {
            let mut w = ReplayWindow::new(width);
            assert!(w.accept(10_000).is_ok());
            if width > 0 {
                // `10_000` itself is spent, so the furthest value still open is exactly
                // `width` below it.
                assert!(w.accept(10_000 - width).is_ok(), "width {width} refuses its own furthest value");
            }
            assert_eq!(
                w.accept(10_000 - width - 1).unwrap_err().kind,
                ErrorKind::BadTag,
                "width {width} accepts one past its own bound"
            );
        }
    }

    #[test]
    fn a_resumed_window_does_not_reaccept_what_was_stored() {
        let mut w = ReplayWindow::resumed(500, 8);
        assert_eq!(w.accept(500).unwrap_err().kind, ErrorKind::BadTag);
        assert_eq!(w.accept(495).unwrap_err().kind, ErrorKind::BadTag);
        assert!(w.accept(501).is_ok());
    }
}
