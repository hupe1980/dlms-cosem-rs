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

use crate::codec::{Decode, Error, ErrorKind, Reader, Result, SliceWriter, Writer};
use crate::xdlms::{ApduTag, CipheredService, GeneralCiphering, GeneralGloCiphering, KeyInfo, Protection};

use super::counter::ReplayWindow;
use super::keys::SystemTitle;
use super::protect::{Protector, SecurityPolicy};
use super::{CryptoProvider, SecuritySuite};

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

/// The longest fixed part a protected APDU puts in front of its payload: the APDU tag,
/// a length-prefixed eight-byte system title for the general forms, the ciphered
/// content's own length prefix at its longest, the security control byte and the
/// invocation counter.
const HEADER_MAX: usize = 1 + (1 + 8) + 5 + 1 + 4;

/// Wrap `plain` — a complete plain APDU, its own tag included — into `out`.
///
/// Returns how many bytes of `out` the protected APDU occupies.
///
/// The cipher runs **in place, inside `out`**, behind the header rather than into a
/// scratch buffer of its own. That is worth the small amount of arithmetic it costs:
/// the scratch would have to be as large as the largest APDU the peer negotiated, so
/// every caller of this function carried an `N`-sized buffer live across the call — one
/// on the client, one on the push sender, and one on the server on top of the three it
/// already holds. The payload's length is known before a byte of it is written —
/// the plaintext plus a tag when there is one — so the header can be laid down first.
pub(crate) fn protect_apdu<P: CryptoProvider>(
    protector: &Protector<P>,
    out_ctx: &Outgoing<'_>,
    plain: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    if out_ctx.policy.is_none() {
        let mut w = SliceWriter::new(out);
        w.write_bytes(plain)?;
        return Ok(w.written());
    }

    let plain_tag = plain
        .first()
        .copied()
        .and_then(ApduTag::from_u8)
        .ok_or_else(|| Error::new(ErrorKind::InvalidTag(plain.first().copied().unwrap_or(0)), 0))?;
    let protection = if out_ctx.policy.dedicated() { Protection::Dedicated } else { Protection::Global };
    let auth_key = out_ctx.auth_key.ok_or_else(|| Error::new(ErrorKind::Unsupported, 0))?;

    // What the cipher will produce, counted rather than measured afterwards.
    let payload_len = plain
        .len()
        .checked_add(if out_ctx.policy.authenticated { SecuritySuite::TAG_LEN } else { 0 })
        .ok_or_else(|| Error::new(ErrorKind::InvalidLength, 0))?;
    let control = out_ctx.policy.control();

    let mut header = [0u8; HEADER_MAX];
    let mut hw = SliceWriter::new(&mut header);
    if let Some(tag) = plain_tag.protected_as(protection) {
        hw.write_u8(tag.as_u8())?;
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
        hw.write_u8(tag.as_u8())?;
        hw.write_length_prefixed(out_ctx.system_title.as_bytes())?;
    }
    // The `ciphered-content` octet string: its length, then the security header the
    // payload follows. Written by hand rather than through `CipheredService` because
    // the payload does not exist yet — it is about to be produced in place behind this.
    hw.write_length(5usize.saturating_add(payload_len))?;
    hw.write_u8(control.0)?;
    hw.write_u32(out_ctx.invocation_counter)?;
    let header_len = hw.written();

    let head = out
        .get_mut(..header_len)
        .ok_or_else(|| Error::new(ErrorKind::BufferTooSmall { needed: header_len }, 0))?;
    head.copy_from_slice(header.get(..header_len).unwrap_or(&[]));
    let body = out
        .get_mut(header_len..)
        .ok_or_else(|| Error::new(ErrorKind::BufferTooSmall { needed: header_len }, 0))?;
    let written = protector
        .protect_as(out_ctx.policy, &out_ctx.system_title, out_ctx.invocation_counter, auth_key, plain, body)?
        .len();
    // The header was sized from `payload_len`; if the cipher disagreed the length prefix
    // would be a lie, and a length prefix that disagrees with its own body is the defect
    // that decodes into plausible nonsense at the far end.
    debug_assert_eq!(written, payload_len);
    if written != payload_len {
        return Err(Error::new(ErrorKind::InvalidLength, header_len));
    }
    Ok(header_len.saturating_add(written))
}

/// Everything the wrapper needs about the message coming in.
pub(crate) struct Incoming<'a> {
    /// This end's own system title, when it has one. `general-ciphering` names its
    /// recipient, and a frame addressed to somebody else is not this end's to open.
    pub local: Option<SystemTitle>,
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
            if dedicated != ctx.policy.dedicated() {
                return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
            }
            (ctx.policy, None, g.ciphered)
        }
        // `general-ciphering` names both ends and carries its own key information. Its
        // *content* is protected exactly as `general-glo-ciphering`'s is — the same
        // nonce, the same additional data — so the identified-key form is openable with
        // nothing this crate lacks, and it is the form a peer uses when it wants to name
        // the recipient. The wrapped and agreed forms deliver a key with the message and
        // need suite 1's or suite 2's asymmetric half; they are refused by name.
        ApduTag::GeneralCiphering => {
            let g = GeneralCiphering::decode(&mut r)?;
            // Every field of this header travels in the clear and outside the tag, so
            // each is a hint rather than a statement. The two identities are still
            // *checked*, because opening a frame addressed elsewhere is work this end
            // should not do and a plaintext this end should not hold — the GCM tag is
            // what proves who sent it.
            if let Some(peer) = ctx.peer {
                if g.originator_system_title != peer.as_bytes() {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
            }
            if let Some(local) = ctx.local {
                // Empty means "not stated", which the standard allows; anything else
                // must be us.
                if !g.recipient_system_title.is_empty() && g.recipient_system_title != local.as_bytes() {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
            }
            // Which key opens it is this end's decision, as everywhere else (D50). An
            // absent key-info means the association's own key set; an identified key
            // must *name* that same key set rather than choose a different one.
            match g.key_info {
                None => {}
                Some(KeyInfo::Identified { key_id }) if Some(key_id) == ctx.policy.key_usage().key_id() => {}
                Some(KeyInfo::Identified { .. }) => {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
                // A key delivered with the message, wrapped under a key-encrypting key
                // or derived by agreement. Both are suite 1 and 2 work.
                Some(KeyInfo::Wrapped { .. } | KeyInfo::Agreed { .. }) => {
                    return Err(Error::new(ErrorKind::Unsupported, 0));
                }
            }
            // There is no `general-ded-ciphering` equivalent here: the key is named by
            // key-info, so an association on the dedicated key set cannot be addressed
            // this way and a frame that tries is refused rather than opened globally.
            if ctx.policy.dedicated() {
                return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
            }
            (ctx.policy, None, g.ciphered)
        }
        // An ECDSA signature over the APDU, which needs suite 1's or suite 2's
        // asymmetric half. Named here rather than left to fall through to the
        // unprotected branch, where the answer would be `UnexpectedMessage` and a caller
        // could not tell "this peer speaks a wrapper we do not" from "this peer
        // downgraded to plaintext".
        ApduTag::GeneralSigning => {
            return Err(Error::new(ErrorKind::Unsupported, 0));
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
            // The `glo-`/`ded-` tag names a key set, and after the handshake both ends
            // have agreed which one that is. A frame naming the other one is refused for
            // the same reason a frame naming the broadcast key set is: which key opens a
            // message is not the sender's to choose (D50). It also catches the honest
            // version of the same fault — one end switching to the dedicated key and the
            // other not — at the first message rather than as a tag failure with nothing
            // to point at.
            let dedicated = protection == Protection::Dedicated;
            if dedicated != ctx.policy.dedicated() {
                return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
            }
            (ctx.policy, Some(plain_tag), CipheredService::decode(&mut r)?)
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
