//! Putting protection on an APDU and taking it off again.
//!
//! Both engines do exactly this and they must do it identically, so it is written once.
//! The client and the server differ in whose system title is whose and in what they do
//! afterwards; the wrapping itself does not differ at all, and when it was written twice
//! the two copies drifted — one of them protected the `InitiateRequest` with the
//! dedicated key it was carrying, which is a key the peer cannot have yet.
//!
//! Three forms exist and the choice between them is not a preference:
//!
//! * **`glo-`/`ded-`** — the ordinary form. Available only for the services that have a
//!   ciphered tag: GET, SET, ACTION, the notifications, and the short-name services.
//! * **`general-glo-ciphering`/`general-ded-ciphering`** — wraps *any* APDU and carries
//!   the sender's system title in the clear. This is the only way to protect an
//!   `access-request`, an `access-response` or an `exception-response`, none of which
//!   has a ciphered tag of its own. It costs the `general-protection` conformance bit.
//! * **plain** — for the APDUs that precede the association, and for the ones a peer may
//!   legitimately send unprotected.

use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, SliceWriter, Writer};
use crate::xdlms::{ApduTag, CipheredService, GeneralGloCiphering, Protection};

use super::CryptoProvider;
use super::counter::ReplayWindow;
use super::keys::SystemTitle;
use super::protect::{Protector, SecurityPolicy};

/// Everything the wrapper needs about the message going out.
pub(crate) struct Outgoing<'a> {
    /// This end's system title — the first eight bytes of every nonce it sends under.
    pub system_title: SystemTitle,
    /// The counter for this message. Already taken from the sender's counter.
    pub invocation_counter: u32,
    /// The authentication key, which is authenticated data rather than a cipher key.
    /// `None` when the ring holds none — which is only ever right for an unprotected
    /// association, and is refused the moment protection is actually applied.
    pub auth_key: Option<&'a [u8]>,
    /// The protection to apply. Global for the Initiate exchange even in a dedicated
    /// association, because the dedicated key travels inside it.
    pub policy: SecurityPolicy,
    /// Whether `general-glo-ciphering` may be used for a service that has no ciphered
    /// tag. False when the peer did not agree to `general-protection`, in which case
    /// such a service simply cannot be protected and is refused rather than sent bare.
    pub general_allowed: bool,
}

/// Wrap `plain` — a complete plain APDU, its own tag included — into `out`.
///
/// Returns how many bytes of `out` the protected APDU occupies.
pub(crate) fn protect_apdu<P: CryptoProvider>(
    protector: &Protector<P>,
    out_ctx: &Outgoing<'_>,
    plain: &[u8],
    body: &mut [u8],
    out: &mut [u8],
) -> Result<usize> {
    let mut w = SliceWriter::new(out);
    if out_ctx.policy.is_none() {
        w.write_bytes(plain)?;
        return Ok(w.written());
    }

    let plain_tag = plain
        .first()
        .copied()
        .and_then(ApduTag::from_u8)
        .ok_or_else(|| Error::new(ErrorKind::InvalidTag(plain.first().copied().unwrap_or(0)), 0))?;
    let protection = if out_ctx.policy.dedicated { Protection::Dedicated } else { Protection::Global };

    let payload = protector.protect_as(
        out_ctx.policy,
        &out_ctx.system_title,
        out_ctx.invocation_counter,
        out_ctx.auth_key.ok_or_else(|| Error::new(ErrorKind::Unsupported, 0))?,
        plain,
        body,
    )?;
    let ciphered = CipheredService {
        security_control: out_ctx.policy.control(),
        invocation_counter: out_ctx.invocation_counter,
        payload,
    };

    if let Some(tag) = plain_tag.protected_as(protection) {
        w.write_u8(tag.as_u8())?;
        ciphered.encode(&mut w)?;
    } else {
        // No ciphered tag for this service. `general-glo-ciphering` is the general
        // wrapper the standard provides for exactly that, and it is the only way an
        // ACCESS exchange or an exception response is protected at all.
        if !out_ctx.general_allowed {
            return Err(Error::new(ErrorKind::Unsupported, 0));
        }
        let tag = match protection {
            Protection::Dedicated => ApduTag::GeneralDedCiphering,
            _ => ApduTag::GeneralGloCiphering,
        };
        w.write_u8(tag.as_u8())?;
        GeneralGloCiphering { system_title: out_ctx.system_title.as_bytes(), ciphered }.encode(&mut w)?;
    }
    Ok(w.written())
}

/// Everything the wrapper needs about the message coming in.
pub(crate) struct Incoming<'a> {
    /// The peer's system title, once it is known. A `general-*-ciphering` APDU carries
    /// one; it must be the peer's, or the frame is somebody else's.
    pub peer: Option<SystemTitle>,
    /// The authentication key. `None` when the ring holds none.
    pub auth_key: Option<&'a [u8]>,
    /// The protection in force for service APDUs.
    pub policy: SecurityPolicy,
    /// Which tags this end accepts with no protection at all. Everything else in a
    /// protected association must arrive protected.
    pub plain_allowed: &'a [ApduTag],
}

/// Take protection off `apdu` into `buf`, returning the plain APDU.
///
/// The invocation counter is checked against `replay` **before** any cryptography and
/// recorded **after** the tag verifies. That order is the whole control: the other one
/// lets a single forged frame with a high counter lock the real peer out permanently.
pub(crate) fn unprotect_apdu<'b, P: CryptoProvider>(
    protector: &Protector<P>,
    ctx: &Incoming<'_>,
    replay: &mut ReplayWindow,
    apdu: &[u8],
    buf: &'b mut [u8],
) -> Result<&'b [u8]> {
    let tag_byte = apdu.first().copied().unwrap_or(0);
    let tag = ApduTag::from_u8(tag_byte).ok_or_else(|| Error::new(ErrorKind::InvalidTag(tag_byte), 0))?;

    let mut r = Reader::new(apdu);
    r.skip(1)?;

    // Which of the three forms is this, and what does it say about itself?
    let (policy, expect_tag, ciphered) = match tag {
        ApduTag::GeneralGloCiphering | ApduTag::GeneralDedCiphering => {
            let g = GeneralGloCiphering::decode(&mut r)?;
            // The title travels in the clear and is not authenticated, so it is a hint
            // about which key to try, never a statement of identity. Requiring it to be
            // the peer's keeps a frame addressed elsewhere from being opened here; the
            // tag is what actually proves who sent it.
            if let Some(peer) = ctx.peer {
                if g.system_title != peer.as_bytes() {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
            }
            let dedicated = tag == ApduTag::GeneralDedCiphering;
            (ctx.policy.with_dedicated(dedicated), None, g.ciphered)
        }
        _ => {
            let Some((protection, plain_tag)) = tag.unprotect() else {
                // Unprotected. The policy still gets a say: an association that demands
                // protection accepts a bare APDU only where one is unavoidable.
                if !ctx.policy.is_none() && !ctx.plain_allowed.contains(&tag) {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
                let n = apdu.len();
                buf.get_mut(..n)
                    .ok_or_else(|| Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))?
                    .copy_from_slice(apdu);
                return buf.get(..n).ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0));
            };
            let dedicated = protection == Protection::Dedicated;
            (ctx.policy.with_dedicated(dedicated), Some(plain_tag), CipheredService::decode(&mut r)?)
        }
    };

    let peer = ctx.peer.ok_or_else(|| Error::new(ErrorKind::UnexpectedMessage, 0))?;
    replay.check(ciphered.invocation_counter)?;

    // The deciphered plaintext is the *whole* plain APDU, its own tag included — the
    // `glo-`/`ded-` tag outside names the same service, and a decoder that prepends it
    // again reads the tag as the service's first field.
    let n = ciphered.payload.len();
    let body = buf.get_mut(..n).ok_or_else(|| Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))?;
    body.copy_from_slice(ciphered.payload);
    let plain_len = protector
        .unprotect_as(
            policy,
            ciphered.security_control,
            &peer,
            ciphered.invocation_counter,
            ctx.auth_key.ok_or_else(|| Error::new(ErrorKind::Unsupported, 0))?,
            body,
        )?
        .len();

    // The tag has verified: the counter is spent, and this exact APDU can never be
    // replayed into this association again.
    replay.accept(ciphered.invocation_counter)?;

    // For the `glo-`/`ded-` forms the outer tag and the inner one must name the same
    // service. They are authenticated together, so a mismatch is a bug rather than an
    // attack — but it is exactly the bug that silently reads the wrong service.
    if let Some(expected) = expect_tag {
        if buf.first() != Some(&expected.as_u8()) {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
    }
    buf.get(..plain_len).ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0))
}
