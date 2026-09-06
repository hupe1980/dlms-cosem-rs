//! Sending a push: the other half of the notification story.
//!
//! A meter's customer interface emits a `DataNotification` on its own initiative — no
//! association, no request, nothing to correlate. [`crate::client::NotificationListener`]
//! reads one; this builds one, and the two are tested against each other.
//!
//! It is a separate object from [`super::Server`] for the same reason the listener is
//! separate from a session: **a push is not part of an association**. It is sent when the
//! push setup's communication window opens, to a destination the push setup names,
//! possibly while no client is connected at all. Folding it into the association engine
//! would tie a meter's ability to report to a client's willingness to ask.
//!
//! The protection is the interesting part. A `DataNotification` has no `glo-` tag, so a
//! ciphered push travels inside `general-glo-ciphering`, which carries the meter's system
//! title in the clear — that is how a listener with keys for a hundred meters knows which
//! one to try. The counter that goes with it is this device's own, and it must outlive
//! the process ([`crate::security::InvocationCounter`]).

use crate::axdr::{Data, DateTime};
use crate::codec::{Encode, Error, ErrorKind, Result, SliceWriter, Writer};
use crate::security::wrap::{Outgoing, protect_apdu};
use crate::security::{CryptoProvider, InvocationCounter, Protector, SecurityPolicy, SystemTitle};
use crate::xdlms::{Apdu, DataNotification, LongInvokeId, OptionalDateTime};

/// Builds pushed notifications.
///
/// `N` is the scratch the plain notification is built in before it is protected, and so
/// bounds the body a single push may carry.
#[derive(Debug)]
pub struct PushSender<P, const N: usize = 512> {
    protector: Protector<P>,
    system_title: SystemTitle,
    invocation_counter: InvocationCounter,
    long_invoke_id: u32,
    scratch: [u8; N],
}

impl<P: CryptoProvider, const N: usize> PushSender<P, N> {
    /// A sender identifying itself as `system_title` and protecting under `policy`.
    ///
    /// `invocation_counter` is the last value this device sent under. Zero is right
    /// exactly once per key: a meter that restarts from zero against an unchanged key
    /// repeats every nonce it has ever used, and a repeated GCM nonce leaks the
    /// authentication subkey rather than a single reading. Persist
    /// [`PushSender::invocation_counter`] and hand it back here.
    pub fn new(
        provider: P,
        system_title: SystemTitle,
        policy: SecurityPolicy,
        invocation_counter: u32,
    ) -> Self {
        Self {
            // A push is never dedicated: there is no association to have negotiated a
            // key for, so the global key set is the only one both ends can hold.
            protector: Protector::new(provider, policy.global()),
            system_title,
            invocation_counter: InvocationCounter::new(invocation_counter),
            long_invoke_id: 0,
            scratch: [0; N],
        }
    }

    /// The counter this sender last sent under. **Persist this.**
    #[must_use]
    pub const fn invocation_counter(&self) -> u32 {
        self.invocation_counter.get()
    }

    /// What this sender identifies itself as. A listener finds the key by it.
    #[must_use]
    pub const fn system_title(&self) -> SystemTitle {
        self.system_title
    }

    /// Build one notification.
    ///
    /// `body` is what the push object list produced — for a push setup naming several
    /// objects, a structure with one field per object, in the order the setup lists them.
    /// `captured_at` is when the values were taken, which is not the same as when the
    /// frame is sent and is the field a receiver actually timestamps the reading with.
    ///
    /// # Errors
    /// When a buffer is too small, when the provider cannot find a key, or when the
    /// invocation counter has been exhausted — at which point the key must be changed
    /// rather than the counter wrapped.
    pub fn notify(
        &mut self,
        captured_at: Option<DateTime>,
        body: &Data<'_>,
        out: &mut [u8],
    ) -> Result<usize> {
        let long_invoke_id = self.next_long_invoke_id();
        let notification =
            DataNotification { long_invoke_id, date_time: OptionalDateTime(captured_at), body: *body };
        let mut w = SliceWriter::new(&mut self.scratch);
        Apdu::DataNotification(notification).encode(&mut w)?;
        let plain_len = w.written();

        if self.protector.policy().is_none() {
            let mut w = SliceWriter::new(out);
            w.write_bytes(self.scratch.get(..plain_len).unwrap_or(&[]))?;
            return Ok(w.written());
        }

        let ctx = Outgoing {
            system_title: self.system_title,
            invocation_counter: self.invocation_counter.next()?,
            auth_key: self.protector.auth_key(),
            policy: self.protector.policy(),
            // A `DataNotification` has no ciphered tag of its own, so the general wrapper
            // is not an option here — it is the only form a protected push has, and the
            // one that carries the system title a listener needs to find the key.
            general_allowed: true,
        };
        let mut body_buf = [0u8; N];
        let plain = self.scratch.get(..plain_len).unwrap_or(&[]);
        protect_apdu(&self.protector, &ctx, plain, &mut body_buf, out)
    }

    /// The long invoke id counts pushes so a confirmed one can be matched to its
    /// acknowledgement, and so a receiver can tell a repeat from a new reading.
    fn next_long_invoke_id(&mut self) -> LongInvokeId {
        self.long_invoke_id = self.long_invoke_id.wrapping_add(1) & 0x00FF_FFFF;
        LongInvokeId::new(self.long_invoke_id)
    }
}

/// The push destination and method a `PushSetup` object holds.
///
/// Where the notification goes is a *configuration* question and not a protocol one, so
/// this is data the caller reads out of its own object model and acts on. The crate does
/// not open the connection: that is I/O, and there is none here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushDestination<'a> {
    /// A TCP or UDP endpoint, as the `destination` attribute spells it — for example
    /// `192.168.0.1:7259`.
    Wrapper(&'a str),
    /// An HDLC or M-Bus destination, as the profile defines it.
    Local(&'a str),
    /// Anything else the companion profile names.
    Other(&'a str),
}

impl<'a> PushDestination<'a> {
    /// The destination as the meter's `send_destination_and_method` spells it.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::Wrapper(s) | Self::Local(s) | Self::Other(s) => s,
        }
    }
}

/// Refuse a body a push cannot carry.
///
/// Not used internally — the encoder's own buffer bound catches an oversized body — but
/// exposed because a scheduler wants to know *before* it opens a connection whether the
/// push it is about to build will fit.
///
/// # Errors
/// [`ErrorKind::BufferTooSmall`] when the encoded body exceeds `max_pdu_size`.
pub fn check_body_fits(body: &Data<'_>, max_pdu_size: u16) -> Result<()> {
    // The tag, the four-byte long invoke id, the date-time octet string at its longest,
    // and the general-ciphering wrapper at its worst.
    const OVERHEAD: usize = 1 + 4 + 13 + (1 + 9 + 5 + 1 + 4 + 12);
    let needed = body.encoded_len().saturating_add(OVERHEAD);
    if needed > usize::from(max_pdu_size) {
        return Err(Error::new(ErrorKind::BufferTooSmall { needed: needed - usize::from(max_pdu_size) }, 0));
    }
    Ok(())
}
