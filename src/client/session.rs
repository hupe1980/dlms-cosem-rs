//! The client session.

use crate::acse::{
    Aare, Aarq, ApplicationContext, AssociationResult, AuthMechanism, Diagnostic, Referencing, ReleaseReason,
    Rlrq,
};
use crate::axdr::Data;
use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, SliceWriter, Writer};
use crate::cosem::InterfaceClass;
use crate::obis::Obis;
use crate::security::wrap::{Incoming, Outgoing, protect_apdu, unprotect_apdu};
use crate::security::{
    CryptoProvider, InvocationCounter, Protector, ReplayWindow, SecurityPolicy, SystemTitle,
};
use crate::xdlms::{
    AccessRequestSpecification, ActionRequest, Apdu, ApduTag, AttributeDescriptor,
    AttributeDescriptorWithSelection, Conformance, DataAccessResult, DataBlockSA, ExceptionResponse,
    GetDataResult, GetRequest, GetResponse, InitiateRequest, InitiateResponse, InvokeId, List, LongInvokeId,
    MethodDescriptor, Protection, SelectiveAccess, SetRequest, SetResponse,
};

/// The APDUs a client accepts from a server with no protection on them, even in a
/// ciphered association.
///
/// The ACSE ones precede the association and cannot be protected as APDUs — their
/// user-information is protected instead. `exception-response` is here because it has no
/// ciphered tag of its own: a server that has not negotiated `general-protection` has no
/// way to protect one, and refusing it means a ciphered client turns every server
/// refusal into a decode error and never learns what the meter actually said. It carries
/// no data and changes no state on this side; it is a diagnostic, and it is treated as
/// an unauthenticated one.
const PLAIN_FROM_SERVER: &[ApduTag] = &[ApduTag::Aare, ApduTag::ReleaseResponse, ApduTag::ExceptionResponse];

/// What the AARE's user information may be when the association is not ciphered.
const PLAIN_INITIATE: &[ApduTag] = &[ApduTag::InitiateResponse, ApduTag::ConfirmedServiceError];

/// What the session is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No association.
    Idle,
    /// An AARQ has gone out and the AARE has not come back.
    Associating,
    /// High level security: the challenges have been exchanged and the client's reply
    /// to the server's challenge is outstanding.
    AuthenticatingHls,
    /// Ready for services.
    Associated,
    /// A release request has gone out.
    Releasing,
    /// The association is over. The server refused, or it was released.
    Closed,
}

/// What the client must do next in the association handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationStep {
    /// The association is open.
    Established,
    /// High level security requires a reply to the server's challenge; call
    /// [`ClientSession::hls_reply_request`].
    HlsReplyRequired,
    /// The server refused, with its reason.
    Rejected {
        /// Accepted, permanently rejected or transiently rejected.
        result: AssociationResult,
        /// Why.
        diagnostic: Diagnostic,
    },
    /// The server answered the AARQ with an exception rather than an AARE, so the
    /// association was never attempted.
    ///
    /// The case worth acting on is `invocation-counter-error`: it carries the counter
    /// the server expects next, and a client whose stored value went stale — a restart
    /// from a backup, most often — can move to it with
    /// [`ClientSession::set_invocation_counter`] and associate again. The exception is
    /// unprotected and anyone can forge one, so the value is *reported* rather than
    /// applied: moving a counter is the caller's decision because moving it backwards
    /// burns the key.
    Exception(ExceptionResponse),
}

/// What a response carried.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Response<'a> {
    /// A value.
    Data(Data<'a>),
    /// One result per attribute of a [`ClientSession::get_request_with_list`], in the
    /// order they were asked for. Each is a value or the reason there is none.
    DataList(List<'a, GetDataResult<'a>>),
    /// The server refused the request.
    DataError(DataAccessResult),
    /// One block of a value; ask for the next with
    /// [`ClientSession::get_next_block_request`].
    Block {
        /// True when no further block follows.
        last: bool,
        /// This block's number.
        number: u32,
        /// The fragment.
        data: &'a [u8],
    },
    /// One result per attribute of a [`ClientSession::set_request_with_list`], in the
    /// order they were asked for.
    ResultList(List<'a, DataAccessResult>),
    /// One outcome per method of a [`ClientSession::action_request_with_list`], in the
    /// order they were asked for.
    ActionResults(List<'a, crate::xdlms::ActionResponseWithOptionalData<'a>>),
    /// The server took a block of a long SET or ACTION parameter and wants the next;
    /// send it with [`ClientSession::next_block_request`].
    BlockAccepted {
        /// The block the server acknowledged.
        number: u32,
    },
    /// The answers to an [`ClientSession::access_request`], one per item in the order
    /// they were asked for.
    Access {
        /// One value per item — `null-data` where the item produced none.
        data: List<'a, Data<'a>>,
        /// One outcome per item.
        results: List<'a, crate::xdlms::AccessResponseSpecification>,
    },
    /// One answer per entry of a [`ClientSession::read_request`], in order.
    #[cfg(feature = "sn")]
    ReadResults(List<'a, crate::xdlms::ReadResult<'a>>),
    /// One outcome per entry of a [`ClientSession::write_request`], in order.
    #[cfg(feature = "sn")]
    WriteResults(List<'a, crate::xdlms::WriteResult>),
    /// A write or an invocation succeeded.
    Ok,
    /// A method returned a value.
    ActionResult {
        /// Whether the method ran.
        result: crate::xdlms::ActionResult,
        /// What it returned, if anything.
        value: Option<Data<'a>>,
    },
    /// The server refused the APDU itself.
    Exception(ExceptionResponse),
    /// The server released the association.
    Released,
}

/// How the client identifies itself and what it demands.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The client service access point: 0x10 public, 0x20 reader, 0x30 management.
    pub client_sap: u8,
    /// The client's system title. Required for GMAC authentication and for any
    /// ciphered association, because it is half of every nonce the client sends under.
    pub system_title: Option<SystemTitle>,
    /// Which authentication mechanism to propose.
    pub mechanism: AuthMechanism,
    /// The low-level-security password, or the high-level-security shared secret.
    pub password: Option<crate::security::Secret>,
    /// What protection to apply.
    ///
    /// Set `dedicated` to propose a dedicated-key association; the key itself comes from
    /// the provider, and an association is refused rather than opened if the provider
    /// has none.
    pub security: SecurityPolicy,
    /// The largest APDU the client will accept.
    pub max_pdu_size: u16,
    /// What the client proposes it can do.
    pub conformance: Conformance,
    /// How objects are addressed.
    pub referencing: Referencing,
    /// How long a challenge to send. The Blue Book allows eight to sixty-four bytes;
    /// shorter is weaker and there is no reason to go below sixteen.
    pub challenge_len: usize,
    /// The last invocation counter this client used before it started.
    ///
    /// Zero is right only for a client that has never sent under these keys. Restarting
    /// from zero against an unchanged key reuses every nonce it used before, and a
    /// repeated GCM nonce leaks the authentication subkey. Persist
    /// [`ClientSession::invocation_counter`] and restore it here.
    pub invocation_counter: u32,
    /// How far out of order the server's invocation counters may arrive.
    ///
    /// Zero — strictly increasing — is right for HDLC and TCP.
    pub replay_window: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client_sap: 0x10,
            system_title: None,
            mechanism: AuthMechanism::None,
            password: None,
            security: SecurityPolicy::NONE,
            max_pdu_size: 1024,
            conformance: Conformance::CLIENT_DEFAULT,
            referencing: Referencing::LogicalName,
            challenge_len: 16,
            invocation_counter: 0,
            replay_window: 0,
        }
    }
}

/// A client association.
///
/// `N` is the scratch buffer the session uses to build an APDU before protecting it.
/// It must be at least as large as the largest APDU the client sends; 1024 covers
/// every request that is not a block transfer.
#[derive(Debug)]
pub struct ClientSession<P, const N: usize = 1024> {
    config: ClientConfig,
    protector: Protector<P>,
    state: SessionState,
    invoke_id: u8,
    /// The invoke id of the request whose response has not arrived yet.
    ///
    /// A `get-request-next` continues an outstanding request and must carry *its* invoke
    /// id: a fresh one names a different invocation, and a server that checks will
    /// refuse it while a server that does not will answer a block of the wrong thing.
    outstanding: Option<InvokeId>,
    invocation_counter: InvocationCounter,
    /// Which of the server's invocation counters have already been spent.
    peer_replay: ReplayWindow,
    negotiated: Option<InitiateResponse>,
    server_system_title: Option<SystemTitle>,
    client_challenge: [u8; 64],
    client_challenge_len: usize,
    server_challenge: [u8; 64],
    server_challenge_len: usize,
    scratch: [u8; N],
}

impl<P: CryptoProvider, const N: usize> ClientSession<P, N> {
    /// A session that will use `provider` for cryptography.
    pub fn new(config: ClientConfig, provider: P) -> Self {
        // Before the association is open there is no dedicated key at either end, so the
        // protector starts on the global key set and is switched over in
        // `handle_associate_response`.
        let policy = config.security.global();
        let invocation_counter = InvocationCounter::new(config.invocation_counter);
        let peer_replay = ReplayWindow::new(config.replay_window);
        Self {
            config,
            protector: Protector::new(provider, policy),
            state: SessionState::Idle,
            invoke_id: 0,
            outstanding: None,
            invocation_counter,
            peer_replay,
            negotiated: None,
            server_system_title: None,
            client_challenge: [0; 64],
            client_challenge_len: 0,
            server_challenge: [0; 64],
            server_challenge_len: 0,
            scratch: [0; N],
        }
    }

    /// What the session is doing.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// What both sides agreed to, once the association is open.
    #[must_use]
    pub const fn negotiated(&self) -> Option<&InitiateResponse> {
        self.negotiated.as_ref()
    }

    /// The server's system title, learned from the AARE.
    #[must_use]
    pub const fn server_system_title(&self) -> Option<SystemTitle> {
        self.server_system_title
    }

    /// The invocation counter the client last sent under.
    ///
    /// Persist this. Restoring a lower value after a restart reuses a nonce; see
    /// [`ClientConfig::invocation_counter`].
    #[must_use]
    pub const fn invocation_counter(&self) -> u32 {
        self.invocation_counter.get()
    }

    /// Start the invocation counter from a known value, after reading the meter's
    /// record of it or restoring one from storage.
    ///
    /// Only ever move it *forward*. There is no check here, because a client that has
    /// just read a higher value out of the meter's own counter object is doing the
    /// right thing and a client that sets it backwards is burning the key either way.
    pub const fn set_invocation_counter(&mut self, value: u32) {
        self.invocation_counter = InvocationCounter::new(value);
    }

    /// The highest invocation counter accepted from the server, if any.
    #[must_use]
    pub const fn peer_invocation_counter(&self) -> Option<u32> {
        self.peer_replay.highest()
    }

    /// The largest payload a block of a long SET or ACTION parameter may carry.
    ///
    /// Deliberately conservative: every header field is counted at its longest, and
    /// protection at its worst case. A few wasted bytes per block cost one extra block
    /// on a very long transfer; a block one byte too large is a request the server drops.
    fn max_fragment(&self) -> Result<core::num::NonZeroUsize> {
        self.max_fragment_less(0)
    }

    /// The same, with `extra` bytes of header this transfer carries beyond the fixed
    /// part — the encoded selective-access descriptor of a blocked SET, which rides in
    /// the first block and is as long as the selector makes it.
    ///
    /// Every block is sized as though it carried the descriptor, not just the first.
    /// That wastes a few bytes per block on a long transfer; sizing only the first block
    /// down would make the later ones a different size for no gain, and getting *that*
    /// arithmetic wrong produces a request the server drops with nothing to point at.
    fn max_fragment_less(&self, extra: usize) -> Result<core::num::NonZeroUsize> {
        // The block header at its longest: APDU tag, request choice, invoke id, the
        // attribute or method descriptor, the selective-access usage flag, the last-block
        // flag, the four-byte block number, and a length prefix in its longest form.
        const HEADER_MAX: usize = 1 + 1 + 1 + 9 + 1 + 1 + 4 + 5;
        // The `glo-` tag, the ciphered service's length prefix at its longest, the
        // security control byte, the invocation counter and the GCM tag.
        const PROTECTION_MAX: usize = 1 + 5 + 1 + 4 + 12;
        let overhead = if self.config.security.is_none() { 0 } else { PROTECTION_MAX };
        let ceiling =
            self.negotiated.as_ref().map_or(self.config.max_pdu_size, |n| n.server_max_receive_pdu_size);
        let fragment = usize::from(ceiling)
            .saturating_sub(HEADER_MAX)
            .saturating_sub(overhead)
            .saturating_sub(extra)
            .min(N);
        // A negotiated PDU size that leaves no room for a payload cannot carry a blocked
        // transfer at all, and a transfer of zero-length blocks would never finish.
        core::num::NonZeroUsize::new(fragment).ok_or(Error::new(ErrorKind::InvalidLength, 0))
    }

    fn next_long_invoke_id(&mut self) -> LongInvokeId {
        self.invoke_id = self.invoke_id.wrapping_add(1) & 0x0F;
        // ACSE's short invoke id is not in play for an ACCESS exchange, so nothing is
        // outstanding under one: leaving a stale id here would have a later block
        // request continue an invocation that is over.
        self.outstanding = None;
        LongInvokeId::new(u32::from(self.invoke_id)).confirmed()
    }

    fn next_invoke_id(&mut self) -> InvokeId {
        self.invoke_id = self.invoke_id.wrapping_add(1) & 0x0F;
        let id = InvokeId::confirmed(self.invoke_id);
        self.outstanding = Some(id);
        id
    }

    fn application_context(&self) -> ApplicationContext {
        ApplicationContext::for_referencing(self.config.referencing, !self.config.security.is_none())
    }

    /// Build the AARQ that opens the association.
    ///
    /// # Errors
    /// When the buffer is too small, when high level security is configured without a
    /// system title, or when a challenge is needed and the provider has no entropy.
    pub fn associate_request(&mut self, out: &mut [u8]) -> Result<usize> {
        // Proposing short-name referencing from a build that left the `sn` feature out
        // would open an association with no services in it. Refusing here says so before
        // a byte goes out, rather than after a handshake that appeared to work.
        #[cfg(not(feature = "sn"))]
        if self.config.referencing == Referencing::ShortName {
            return Err(Error::new(ErrorKind::Unsupported, 0));
        }
        let ciphered = !self.config.security.is_none();
        if (ciphered || self.config.mechanism == AuthMechanism::HighGmac)
            && self.config.system_title.is_none()
        {
            // Without a system title the client cannot form a nonce, so every frame it
            // sent would share one — which is worse than not connecting.
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }

        let mut initiate = InitiateRequest {
            proposed_dlms_version: crate::xdlms::DLMS_VERSION,
            proposed_conformance: self.config.conformance,
            client_max_receive_pdu_size: self.config.max_pdu_size,
            ..Default::default()
        };
        // The dedicated key travels inside the ciphered InitiateRequest, so it is only
        // ever offered in a ciphered context — sending one in the clear would publish it.
        if ciphered && self.config.security.dedicated() {
            initiate.dedicated_key =
                Some(self.protector.provider().dedicated_key().ok_or(Error::new(ErrorKind::Unsupported, 0))?);
        }

        // The InitiateRequest is protected on its own, inside the user information.
        let mut plain = [0u8; 64];
        let mut pw = SliceWriter::new(&mut plain);
        pw.write_u8(ApduTag::InitiateRequest.as_u8())?;
        initiate.encode(&mut pw)?;
        let plain_len = pw.written();

        let mut user_info = [0u8; 160];
        let user_info = if ciphered {
            let ic = self.next_counter()?;
            let title = self.config.system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
            let mut body = [0u8; 128];
            // Always the *global* key set, whatever the association will use afterwards:
            // the dedicated key is delivered inside this very message, so the peer
            // cannot yet hold it. Protecting the InitiateRequest with it produces a
            // frame nobody can open.
            let payload = self.protector.protect_as(
                self.config.security.global(),
                &title,
                ic,
                self.auth_key()?,
                &plain[..plain_len],
                &mut body,
            )?;
            let mut w = SliceWriter::new(&mut user_info);
            let tag = ApduTag::InitiateRequest
                .protected_as(Protection::Global)
                .ok_or(Error::new(ErrorKind::Unsupported, 0))?;
            w.write_u8(tag.as_u8())?;
            crate::xdlms::CipheredService {
                security_control: self.config.security.control(),
                invocation_counter: ic,
                payload,
            }
            .encode(&mut w)?;
            let n = w.written();
            &user_info[..n]
        } else {
            &plain[..plain_len]
        };

        let challenge = if self.config.mechanism.is_high_level() {
            let len = self.config.challenge_len.clamp(8, 64);
            self.protector.provider().random(&mut self.client_challenge[..len])?;
            self.client_challenge_len = len;
            Some(&self.client_challenge[..len])
        } else {
            self.config.password.as_ref().map(crate::security::Secret::expose)
        };

        let aarq = Aarq {
            application_context: Some(self.application_context()),
            called_ap_title: None,
            calling_ap_title: self.config.system_title.as_ref().map(|t| &t.0[..]),
            calling_ae_qualifier: None,
            sender_acse_requirements: self.config.mechanism != AuthMechanism::None,
            mechanism_name: (self.config.mechanism != AuthMechanism::None).then_some(self.config.mechanism),
            calling_authentication_value: challenge,
            user_information: Some(user_info),
        };
        let mut w = SliceWriter::new(out);
        aarq.encode(&mut w)?;
        self.state = SessionState::Associating;
        Ok(w.written())
    }

    /// Consume the AARE and say what happens next.
    ///
    /// # Errors
    /// When the APDU is not an AARE, when the negotiated version is not one this crate
    /// speaks, or when the server's InitiateResponse cannot be unprotected.
    pub fn handle_associate_response(&mut self, apdu: &[u8]) -> Result<AssociationStep> {
        // A server that cannot even get as far as an AARE answers with an exception.
        // Decoding it as a malformed AARE would turn the one message that says how to
        // recover into `invalid tag 0xd8`.
        if apdu.first().copied() == Some(ApduTag::ExceptionResponse.as_u8()) {
            self.state = SessionState::Closed;
            return Ok(AssociationStep::Exception(ExceptionResponse::from_bytes(
                apdu.get(1..).unwrap_or(&[]),
            )?));
        }
        let aare = Aare::from_bytes(apdu)?;
        if let Some(title) = aare.responding_ap_title {
            self.server_system_title = Some(SystemTitle::from_slice(title)?);
        }
        if !aare.is_accepted() {
            self.state = SessionState::Closed;
            return Ok(AssociationStep::Rejected { result: aare.result, diagnostic: aare.diagnostic });
        }

        // An accepted association must be the one that was asked for. The context says
        // whether the association is ciphered and how objects are named, and the
        // mechanism says how the client proves who it is; a server that answers "yes"
        // to a *different* pair has not agreed to anything the client proposed. The
        // ACSE fields are not protected, so this is not by itself an authentication —
        // it is the check that stops the handshake continuing under the wrong
        // assumptions, which is where a downgrade would otherwise be laundered into a
        // session that never notices.
        let proposed = self.application_context();
        if aare.application_context.is_some_and(|got| got != proposed) {
            self.state = SessionState::Closed;
            return Ok(AssociationStep::Rejected {
                result: AssociationResult::RejectedPermanent,
                diagnostic: Diagnostic::User(crate::acse::UserDiagnostic::ApplicationContextNameNotSupported),
            });
        }
        if aare.mechanism_name.is_some_and(|got| got != self.config.mechanism) {
            self.state = SessionState::Closed;
            return Ok(AssociationStep::Rejected {
                result: AssociationResult::RejectedPermanent,
                diagnostic: Diagnostic::User(
                    crate::acse::UserDiagnostic::AuthenticationMechanismNameNotRecognised,
                ),
            });
        }
        // A server that names no mechanism has not accepted the one that was proposed.
        if self.config.mechanism != AuthMechanism::None && aare.mechanism_name.is_none() {
            self.state = SessionState::Closed;
            return Ok(AssociationStep::Rejected {
                result: AssociationResult::RejectedPermanent,
                diagnostic: Diagnostic::User(crate::acse::UserDiagnostic::AuthenticationRequired),
            });
        }

        if let Some(user_info) = aare.user_information {
            let mut buf = [0u8; 256];
            // The InitiateResponse is protected globally for the same reason the request
            // is, so it is unprotected under the global policy rather than the
            // association's.
            let plain = self.unprotect_initiate(user_info, &mut buf)?;
            let mut r = Reader::new(plain);
            let tag = r.u8()?;
            match ApduTag::from_u8(tag) {
                Some(ApduTag::InitiateResponse) => {
                    let resp = InitiateResponse::decode(&mut r)?;
                    resp.check_version()?;
                    self.negotiated = Some(resp);
                }
                Some(ApduTag::ConfirmedServiceError) => {
                    self.state = SessionState::Closed;
                    return Ok(AssociationStep::Rejected {
                        result: AssociationResult::RejectedPermanent,
                        diagnostic: aare.diagnostic,
                    });
                }
                _ => return Err(Error::new(ErrorKind::UnexpectedMessage, 0)),
            }
        }

        // From here on the association's own protection applies, which is the dedicated
        // key set when one was delivered in the InitiateRequest.
        if self.config.security.dedicated() {
            self.protector.set_dedicated(true);
        }

        if self.config.mechanism.is_high_level() {
            let challenge =
                aare.responding_authentication_value.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
            if challenge.len() > 64 {
                return Err(Error::new(ErrorKind::InvalidLength, 0));
            }
            self.server_challenge[..challenge.len()].copy_from_slice(challenge);
            self.server_challenge_len = challenge.len();
            self.state = SessionState::AuthenticatingHls;
            return Ok(AssociationStep::HlsReplyRequired);
        }

        self.state = SessionState::Associated;
        Ok(AssociationStep::Established)
    }

    /// Build the `reply_to_HLS_authentication` request that answers the server's
    /// challenge.
    ///
    /// # Errors
    /// When the mechanism is not one this crate implements, or the session is not at
    /// this step.
    pub fn hls_reply_request(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.state != SessionState::AuthenticatingHls {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        if self.config.mechanism != AuthMechanism::HighGmac {
            // Mechanisms 3, 4, 6 and 7 are named by the standard but their exact
            // constructions are not in the material this crate was built from, and a
            // guessed construction authenticates nothing.
            return Err(Error::new(ErrorKind::Unsupported, 0));
        }
        let title = self.config.system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        let ic = self.next_counter()?;
        let mut reply = [0u8; 17];
        self.protector.hls_gmac_response(
            &title,
            ic,
            self.auth_key()?,
            &self.server_challenge[..self.server_challenge_len],
            &mut reply,
        )?;

        let descriptor = MethodDescriptor::new(15, Obis::new(0, 0, 40, 0, 0, 255), 1);
        let request = ActionRequest::Normal {
            invoke_id: self.next_invoke_id(),
            descriptor,
            parameters: Some(Data::OctetString(&reply)),
        };
        self.send(&Apdu::ActionRequest(request), out)
    }

    /// Consume the server's answer to the HLS reply.
    ///
    /// # Errors
    /// [`ErrorKind::BadTag`] when the server's proof does not match the challenge the
    /// client sent — which means the server does not hold the key, and the association
    /// must not be used.
    pub fn handle_hls_reply_response(&mut self, apdu: &[u8]) -> Result<AssociationStep> {
        let mut buf = [0u8; 512];
        let plain = self.unprotect_into(apdu, &mut buf)?;
        let apdu = Apdu::from_bytes(plain)?;
        let Apdu::ActionResponse(crate::xdlms::ActionResponse::Normal { response, .. }) = apdu else {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        };
        if !response.result.is_success() {
            self.state = SessionState::Closed;
            return Ok(AssociationStep::Rejected {
                result: AssociationResult::RejectedPermanent,
                diagnostic: Diagnostic::User(crate::acse::UserDiagnostic::AuthenticationFailure),
            });
        }
        let proof = response
            .return_parameters
            .and_then(|p| p.value().ok())
            .and_then(|d| d.as_bytes())
            .ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        let peer = self.server_system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        self.protector.verify_hls_gmac(
            &peer,
            self.auth_key()?,
            &self.client_challenge[..self.client_challenge_len],
            proof,
        )?;
        self.state = SessionState::Associated;
        Ok(AssociationStep::Established)
    }

    /// Build a GET request for one attribute.
    ///
    /// # Errors
    /// When the association is not open, when the server did not agree to GET, or when
    /// the buffer is too small.
    pub fn get_request(
        &mut self,
        descriptor: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_associated()?;
        self.require_conformance(Conformance::GET)?;
        if access.is_some() {
            self.require_conformance(Conformance::SELECTIVE_ACCESS)?;
        }
        let request = GetRequest::Normal { invoke_id: self.next_invoke_id(), descriptor, access };
        self.send(&Apdu::GetRequest(request), out)
    }

    /// Build a GET request for an attribute of a typed class.
    ///
    /// # Errors
    /// As [`ClientSession::get_request`].
    pub fn get<C: InterfaceClass>(
        &mut self,
        logical_name: Obis,
        attribute: i8,
        out: &mut [u8],
    ) -> Result<usize> {
        self.get_request(AttributeDescriptor::new(C::CLASS_ID, logical_name, attribute), None, out)
    }

    /// Build a GET request for several attributes at once.
    ///
    /// One round trip instead of one per attribute. On a GPRS or LPWAN link the round
    /// trip dominates everything else, so reading thirty registers one at a time is not
    /// thirty times the bytes — it is thirty times the latency, which is the difference
    /// between a meter read taking a second and taking a minute.
    ///
    /// Each item gets its own result: a list where one attribute is unreadable comes
    /// back with a value for the others and a [`DataAccessResult`] in that one's place,
    /// so a single denied object does not lose the whole read.
    ///
    /// # Errors
    /// When the association is not open, when the server did not agree to
    /// [`Conformance::GET`] or [`Conformance::MULTIPLE_REFERENCES`], when the list is
    /// empty, or when a buffer is too small.
    pub fn get_request_with_list(
        &mut self,
        items: &[AttributeDescriptorWithSelection<'_>],
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_associated()?;
        self.require_conformance(Conformance::GET)?;
        self.require_conformance(Conformance::MULTIPLE_REFERENCES)?;
        if items.is_empty() {
            // An empty list is a request for nothing that still costs a round trip.
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }
        if items.iter().any(|i| i.access.is_some()) {
            self.require_conformance(Conformance::SELECTIVE_ACCESS)?;
        }

        // The elements are encoded into a local buffer and handed over as raw bytes,
        // because `List` is a borrowed view: it never owns what it describes.
        let mut encoded = [0u8; N];
        let mut lw = SliceWriter::new(&mut encoded);
        for item in items {
            item.encode(&mut lw)?;
        }
        let n = lw.written();
        let request = GetRequest::WithList {
            invoke_id: self.next_invoke_id(),
            list: List::from_raw(items.len(), &encoded[..n]),
        };
        self.send(&Apdu::GetRequest(request), out)
    }

    /// Build the request for the next block of a long response.
    ///
    /// `block_number` acknowledges the block just received; the server answers with the
    /// one after it. The request carries the invoke id of the read it is continuing, not
    /// a fresh one — a `get-request-next` is part of an invocation already in flight,
    /// and giving it a new id asks the server about something it has never been asked.
    ///
    /// # Errors
    /// When the association is not open, when no request is outstanding to continue, or
    /// when the buffer is too small.
    pub fn get_next_block_request(&mut self, block_number: u32, out: &mut [u8]) -> Result<usize> {
        self.require_associated()?;
        let invoke_id = self.outstanding.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        let request = GetRequest::Next { invoke_id, block_number };
        self.send(&Apdu::GetRequest(request), out)
    }

    /// Build a SET request.
    ///
    /// # Errors
    /// When the association is not open, when the server did not agree to SET, or when
    /// the buffer is too small.
    pub fn set_request(
        &mut self,
        descriptor: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
        value: Data<'_>,
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_associated()?;
        self.require_conformance(Conformance::SET)?;
        if access.is_some() {
            self.require_conformance(Conformance::SELECTIVE_ACCESS)?;
        }
        let request = SetRequest::Normal { invoke_id: self.next_invoke_id(), descriptor, access, value };
        self.send(&Apdu::SetRequest(request), out)
    }

    /// Write several attributes in one exchange, one result each.
    ///
    /// The values are positional: value *i* is written to attribute *i*. A server
    /// answers with one [`DataAccessResult`] per item, so a single refused write does
    /// not lose the batch.
    ///
    /// # Errors
    /// When the association is not open, when the server did not agree to
    /// [`Conformance::SET`] or [`Conformance::MULTIPLE_REFERENCES`], when the two lists
    /// are different lengths, or when a buffer is too small.
    pub fn set_request_with_list(
        &mut self,
        items: &[AttributeDescriptorWithSelection<'_>],
        values: &[Data<'_>],
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_associated()?;
        self.require_conformance(Conformance::SET)?;
        self.require_conformance(Conformance::MULTIPLE_REFERENCES)?;
        if items.is_empty() || items.len() != values.len() {
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }
        if items.iter().any(|i| i.access.is_some()) {
            self.require_conformance(Conformance::SELECTIVE_ACCESS)?;
        }

        // Both lists are encoded into one buffer, back to back, because `List` is a
        // borrowed view that never owns what it describes.
        let mut encoded = [0u8; N];
        let mut lw = SliceWriter::new(&mut encoded);
        for item in items {
            item.encode(&mut lw)?;
        }
        let descriptors_end = lw.written();
        for value in values {
            value.encode(&mut lw)?;
        }
        let end = lw.written();
        let request = SetRequest::WithList {
            invoke_id: self.next_invoke_id(),
            descriptors: List::from_raw(items.len(), encoded.get(..descriptors_end).unwrap_or(&[])),
            values: List::from_raw(values.len(), encoded.get(descriptors_end..end).unwrap_or(&[])),
        };
        self.send(&Apdu::SetRequest(request), out)
    }

    /// Invoke several methods in one exchange, one result each.
    ///
    /// The parameters are positional: parameter *i* goes to method *i*, and a method that
    /// takes none gets `null-data` in its slot. The answer is a
    /// [`Response::ActionResults`] with one outcome per method, so a method that refuses
    /// does not lose the batch — which matters more here than for a read, because a batch
    /// that opened a breaker and then failed would otherwise report only the failure.
    ///
    /// # Errors
    /// When the association is not open, when the server did not agree to
    /// [`Conformance::ACTION`] or [`Conformance::MULTIPLE_REFERENCES`], when the two
    /// lists are different lengths, or when a buffer is too small.
    pub fn action_request_with_list(
        &mut self,
        descriptors: &[MethodDescriptor],
        parameters: &[Option<Data<'_>>],
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_associated()?;
        self.require_conformance(Conformance::ACTION)?;
        self.require_conformance(Conformance::MULTIPLE_REFERENCES)?;
        if descriptors.is_empty()
            || descriptors.len() != parameters.len()
            || descriptors.len() > crate::xdlms::MAX_ACCESS_ITEMS
        {
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }

        let mut encoded = [0u8; N];
        let mut lw = SliceWriter::new(&mut encoded);
        for d in descriptors {
            d.encode(&mut lw)?;
        }
        let descriptors_end = lw.written();
        for p in parameters {
            p.unwrap_or(Data::Null).encode(&mut lw)?;
        }
        let end = lw.written();
        let request = ActionRequest::WithList {
            invoke_id: self.next_invoke_id(),
            descriptors: List::from_raw(descriptors.len(), encoded.get(..descriptors_end).unwrap_or(&[])),
            parameters: List::from_raw(parameters.len(), encoded.get(descriptors_end..end).unwrap_or(&[])),
        };
        self.send(&Apdu::ActionRequest(request), out)
    }

    /// Begin writing several attributes whose values together exceed the PDU size.
    ///
    /// `values` is the **encoded** `value-list` — a count prefix and one `Data` per
    /// attribute, which is exactly what [`ClientSession::encode_value_list`] produces —
    /// and it stays the caller's, as every other long value does.
    ///
    /// # Errors
    /// When the association is not open, or the server did not agree to
    /// [`Conformance::MULTIPLE_REFERENCES`] and
    /// [`Conformance::BLOCK_TRANSFER_WITH_SET_OR_WRITE`].
    pub fn set_transfer_with_list<'v>(
        &mut self,
        items: &'v [AttributeDescriptorWithSelection<'v>],
        values: &'v [u8],
        scratch: &'v mut [u8],
    ) -> Result<BlockSender<'v>> {
        self.require_associated()?;
        self.require_conformance(Conformance::SET)?;
        self.require_conformance(Conformance::MULTIPLE_REFERENCES)?;
        self.require_conformance(Conformance::BLOCK_TRANSFER_WITH_SET_OR_WRITE)?;
        if items.is_empty() || items.len() > crate::xdlms::MAX_ACCESS_ITEMS {
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }
        // The descriptor list rides in the first block, so it counts against the
        // fragment size the same way a single write's selector does.
        let mut lw = SliceWriter::new(scratch);
        for item in items {
            item.encode(&mut lw)?;
        }
        let n = lw.written();
        let list = List::from_raw(items.len(), lw.finish().get(..n).unwrap_or(&[]));
        let extra = list.encoded_len();
        Ok(BlockSender {
            target: BlockTarget::AttributeList(list),
            bytes: values,
            sent: 0,
            block: 0,
            fragment: self.max_fragment_less(extra)?,
        })
    }

    /// Encode a `value-list` for [`ClientSession::set_transfer_with_list`].
    ///
    /// A free function on the session rather than a method on a list type, because what
    /// it produces is the *field* — count prefix included — and that is the thing the
    /// blocks carry.
    ///
    /// # Errors
    /// When `out` is too small.
    pub fn encode_value_list(values: &[Data<'_>], out: &mut [u8]) -> Result<usize> {
        let mut w = SliceWriter::new(out);
        w.write_length(values.len())?;
        for v in values {
            v.encode(&mut w)?;
        }
        Ok(w.written())
    }

    /// Begin writing a value larger than the negotiated PDU size.
    ///
    /// `value` is the **encoded** attribute value, and it stays the caller's: how large
    /// a value a deployment writes is not a decision for this crate, and a session that
    /// buffered it would put a ceiling on it that nothing in the standard has. Drive the
    /// transfer with [`ClientSession::next_block_request`] until it reports done.
    ///
    /// # Errors
    /// When the association is not open, or the server did not agree to
    /// [`Conformance::BLOCK_TRANSFER_WITH_SET_OR_WRITE`].
    pub fn set_transfer<'v>(
        &mut self,
        descriptor: AttributeDescriptor,
        access: Option<SelectiveAccess<'v>>,
        value: &'v [u8],
    ) -> Result<BlockSender<'v>> {
        self.require_associated()?;
        self.require_conformance(Conformance::SET)?;
        self.require_conformance(Conformance::BLOCK_TRANSFER_WITH_SET_OR_WRITE)?;
        let extra = access.map_or(0, |a| a.encoded_len());
        Ok(BlockSender {
            target: BlockTarget::Attribute { descriptor, access },
            bytes: value,
            sent: 0,
            block: 0,
            fragment: self.max_fragment_less(extra)?,
        })
    }

    /// Begin invoking a method whose parameter is larger than the negotiated PDU size.
    ///
    /// # Errors
    /// When the association is not open, or the server did not agree to
    /// [`Conformance::BLOCK_TRANSFER_WITH_ACTION`].
    pub fn action_transfer<'v>(
        &mut self,
        descriptor: MethodDescriptor,
        parameters: &'v [u8],
    ) -> Result<BlockSender<'v>> {
        self.require_associated()?;
        self.require_conformance(Conformance::ACTION)?;
        self.require_conformance(Conformance::BLOCK_TRANSFER_WITH_ACTION)?;
        Ok(BlockSender {
            target: BlockTarget::Method(descriptor),
            bytes: parameters,
            sent: 0,
            block: 0,
            fragment: self.max_fragment()?,
        })
    }

    /// Emit the next block of a transfer started with [`ClientSession::set_transfer`] or
    /// [`ClientSession::action_transfer`].
    ///
    /// Every block of one transfer carries the same invoke id: a fresh one names a
    /// different invocation, and a server that checks refuses it while one that does not
    /// writes the fragment into something else.
    ///
    /// # Errors
    /// When the transfer is already finished, or the buffer is too small.
    pub fn next_block_request(&mut self, sender: &mut BlockSender<'_>, out: &mut [u8]) -> Result<usize> {
        self.require_associated()?;
        if sender.is_done() {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        let first = sender.block == 0;
        let invoke_id = if first {
            self.next_invoke_id()
        } else {
            self.outstanding.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?
        };
        let end = sender.sent.saturating_add(sender.fragment.get()).min(sender.bytes.len());
        let raw_data = sender.bytes.get(sender.sent..end).unwrap_or(&[]);
        let last_block = end == sender.bytes.len();
        let block_number = sender.block.saturating_add(1);
        let block = DataBlockSA { last_block, block_number, raw_data };

        let apdu = match (first, sender.target) {
            (true, BlockTarget::Attribute { descriptor, access }) => {
                Apdu::SetRequest(SetRequest::WithFirstDataBlock { invoke_id, descriptor, access, block })
            }
            (false, BlockTarget::Attribute { .. }) => {
                Apdu::SetRequest(SetRequest::WithDataBlock { invoke_id, block })
            }
            (true, BlockTarget::Method(descriptor)) => {
                Apdu::ActionRequest(ActionRequest::WithFirstPblock { invoke_id, descriptor, block })
            }
            (false, BlockTarget::Method(_)) => {
                Apdu::ActionRequest(ActionRequest::WithPblock { invoke_id, block })
            }
            (true, BlockTarget::AttributeList(descriptors)) => {
                Apdu::SetRequest(SetRequest::WithListAndFirstDataBlock { invoke_id, descriptors, block })
            }
            (false, BlockTarget::AttributeList(_)) => {
                Apdu::SetRequest(SetRequest::WithDataBlock { invoke_id, block })
            }
        };
        let n = self.send(&apdu, out)?;
        sender.sent = end;
        sender.block = block_number;
        Ok(n)
    }

    /// Ask for the next block of a long ACTION *result*.
    ///
    /// The counterpart of [`ClientSession::get_next_block_request`] for a method that
    /// returns more than one APDU can carry.
    ///
    /// # Errors
    /// When the association is not open, or no invocation is outstanding.
    pub fn action_next_block_request(&mut self, block_number: u32, out: &mut [u8]) -> Result<usize> {
        self.require_associated()?;
        let invoke_id = self.outstanding.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        let request = ActionRequest::NextPblock { invoke_id, block_number };
        self.send(&Apdu::ActionRequest(request), out)
    }

    /// Read, write and invoke in one exchange — the ACCESS service.
    ///
    /// This is what a battery-powered device on a low-power network uses: the cost there
    /// is round trips, not bytes, and ACCESS is the only service that mixes the three
    /// operations into one. It has no ciphered tag of its own, so in a protected
    /// association it travels inside `general-glo-ciphering` and needs
    /// [`Conformance::GENERAL_PROTECTION`] as well as [`Conformance::ACCESS`].
    ///
    /// The answer comes back as [`Response::Access`], positionally: entry *i* of the
    /// result list is the outcome of item *i*, and entry *i* of the data list is what it
    /// produced — `null-data` for a write, and for a read that failed.
    ///
    /// # Errors
    /// When the association is not open, when the server did not agree to
    /// [`Conformance::ACCESS`], when `items` is empty, or when a buffer is too small.
    pub fn access_request(&mut self, items: &[AccessItem<'_>], out: &mut [u8]) -> Result<usize> {
        self.require_associated()?;
        self.require_conformance(Conformance::ACCESS)?;
        if items.is_empty() || items.len() > crate::xdlms::MAX_ACCESS_ITEMS {
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }

        let mut encoded = [0u8; N];
        let mut lw = SliceWriter::new(&mut encoded);
        for item in items {
            item.specification().encode(&mut lw)?;
        }
        let spec_end = lw.written();
        // One data entry per specification entry, in order. A GET contributes
        // `null-data`, which is what keeps the three lists aligned by position.
        for item in items {
            match item {
                AccessItem::Get { .. } => Data::Null.encode(&mut lw)?,
                AccessItem::Set { value, .. } => value.encode(&mut lw)?,
                AccessItem::Action { parameters, .. } => {
                    parameters.unwrap_or(Data::Null).encode(&mut lw)?;
                }
            }
        }
        let end = lw.written();

        let request = crate::xdlms::AccessRequest {
            long_invoke_id: self.next_long_invoke_id(),
            date_time: crate::xdlms::OptionalDateTime(None),
            specification: List::from_raw(items.len(), encoded.get(..spec_end).unwrap_or(&[])),
            data: List::from_raw(items.len(), encoded.get(spec_end..end).unwrap_or(&[])),
        };
        self.send(&Apdu::AccessRequest(request), out)
    }

    /// Read attributes by **short name** — the legacy addressing mode.
    ///
    /// One entry per thing to read, answered by a [`Response::ReadResults`] with one
    /// result in the same position. A short name is an object's base name plus an
    /// offset; [`crate::cosem::ShortName`] computes one, and the base names come from
    /// the meter's own `Association SN` object list.
    ///
    /// Short-name referencing is a property of the *association*, not of a request:
    /// set [`ClientConfig::referencing`] to [`Referencing::ShortName`] so the AARQ
    /// proposes the short-name application context. A meter that answered a
    /// logical-name association with short names would be answering a different
    /// question, so this refuses to send one into the wrong context.
    ///
    /// # Errors
    /// When the association is not open or is not a short-name one, when the server did
    /// not agree to [`Conformance::READ`], when the list is empty, or when a buffer is
    /// too small.
    #[cfg(feature = "sn")]
    pub fn read_request(
        &mut self,
        items: &[crate::xdlms::VariableAccess<'_>],
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_associated()?;
        self.require_short_name()?;
        self.require_conformance(Conformance::READ)?;
        if items.is_empty() {
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }
        let mut encoded = [0u8; N];
        let mut lw = SliceWriter::new(&mut encoded);
        for item in items {
            item.encode(&mut lw)?;
        }
        let n = lw.written();
        let request = crate::xdlms::ReadRequest {
            specification: List::from_raw(items.len(), encoded.get(..n).unwrap_or(&[])),
        };
        // The short-name services carry no invoke id at all, so nothing is outstanding
        // under one: leaving a stale id here would let a later block request continue an
        // invocation that is over.
        self.outstanding = None;
        self.send(&Apdu::ReadRequest(request), out)
    }

    /// Ask for the next block of a long short-name read.
    ///
    /// `block_number` acknowledges the block just received. Unlike the logical-name
    /// services this is an ordinary read entry rather than a form of its own, which is
    /// why it takes the same path.
    ///
    /// # Errors
    /// As [`ClientSession::read_request`].
    #[cfg(feature = "sn")]
    pub fn read_next_block_request(&mut self, block_number: u16, out: &mut [u8]) -> Result<usize> {
        self.read_request(&[crate::xdlms::VariableAccess::BlockNumber(block_number)], out)
    }

    /// Write attributes by **short name**.
    ///
    /// The two lists are positional: value *i* goes to entry *i*. The answer is a
    /// [`Response::WriteResults`] with one outcome per entry, so a single refused write
    /// does not lose the batch.
    ///
    /// # Errors
    /// When the association is not open or is not a short-name one, when the server did
    /// not agree to [`Conformance::WRITE`], when the two lists are different lengths, or
    /// when a buffer is too small.
    #[cfg(feature = "sn")]
    pub fn write_request(
        &mut self,
        items: &[crate::xdlms::VariableAccess<'_>],
        values: &[Data<'_>],
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_short_name_write(items, values)?;
        // Both lists go into one local buffer, back to back, because `List` is a
        // borrowed view that never owns what it describes — and a local rather than a
        // field of the session, so building the APDU afterwards does not conflict with
        // it.
        let mut encoded = [0u8; N];
        let mut lw = SliceWriter::new(&mut encoded);
        for item in items {
            item.encode(&mut lw)?;
        }
        let spec_end = lw.written();
        for value in values {
            value.encode(&mut lw)?;
        }
        let end = lw.written();
        let request = crate::xdlms::WriteRequest {
            specification: List::from_raw(items.len(), encoded.get(..spec_end).unwrap_or(&[])),
            values: List::from_raw(values.len(), encoded.get(spec_end..end).unwrap_or(&[])),
        };
        self.outstanding = None;
        self.send(&Apdu::WriteRequest(request), out)
    }

    /// The same write, with no answer expected.
    ///
    /// `unconfirmed-write` is a distinct service rather than a flag on the confirmed one,
    /// and this is a distinct method for the same reason: a caller that sends one must
    /// not then wait for a reply. It costs [`Conformance::UNCONFIRMED_WRITE`] rather than
    /// [`Conformance::WRITE`].
    ///
    /// # Errors
    /// As [`ClientSession::write_request`].
    #[cfg(feature = "sn")]
    pub fn unconfirmed_write_request(
        &mut self,
        items: &[crate::xdlms::VariableAccess<'_>],
        values: &[Data<'_>],
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_short_name_write(items, values)?;
        self.require_conformance(Conformance::UNCONFIRMED_WRITE)?;
        let mut encoded = [0u8; N];
        let mut lw = SliceWriter::new(&mut encoded);
        for item in items {
            item.encode(&mut lw)?;
        }
        let spec_end = lw.written();
        for value in values {
            value.encode(&mut lw)?;
        }
        let end = lw.written();
        let request = crate::xdlms::UnconfirmedWriteRequest {
            specification: List::from_raw(items.len(), encoded.get(..spec_end).unwrap_or(&[])),
            values: List::from_raw(values.len(), encoded.get(spec_end..end).unwrap_or(&[])),
        };
        self.outstanding = None;
        self.send(&Apdu::UnconfirmedWriteRequest(request), out)
    }

    /// The checks both short-name writes share.
    #[cfg(feature = "sn")]
    fn require_short_name_write(
        &self,
        items: &[crate::xdlms::VariableAccess<'_>],
        values: &[Data<'_>],
    ) -> Result<()> {
        self.require_associated()?;
        self.require_short_name()?;
        self.require_conformance(Conformance::WRITE)?;
        if items.is_empty() || items.len() != values.len() {
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }
        Ok(())
    }

    /// Build an ACTION request.
    ///
    /// # Errors
    /// When the association is not open, when the server did not agree to ACTION, or
    /// when the buffer is too small.
    pub fn action_request(
        &mut self,
        descriptor: MethodDescriptor,
        parameters: Option<Data<'_>>,
        out: &mut [u8],
    ) -> Result<usize> {
        self.require_associated()?;
        self.require_conformance(Conformance::ACTION)?;
        let request = ActionRequest::Normal { invoke_id: self.next_invoke_id(), descriptor, parameters };
        self.send(&Apdu::ActionRequest(request), out)
    }

    /// Build the request that releases the association.
    ///
    /// # Errors
    /// When the buffer is too small.
    pub fn release_request(&mut self, out: &mut [u8]) -> Result<usize> {
        let rlrq = Rlrq { reason: Some(ReleaseReason::Normal), user_information: None };
        let mut w = SliceWriter::new(out);
        rlrq.encode(&mut w)?;
        self.state = SessionState::Releasing;
        Ok(w.written())
    }

    /// Consume a response APDU.
    ///
    /// `buf` receives the unprotected APDU, and the returned [`Response`] borrows from
    /// it. That is why it is a parameter: the caller decides where a decrypted APDU
    /// lives, and it lives no longer than the caller lets it.
    ///
    /// # Errors
    /// When the APDU is malformed, protected more weakly than the policy demands, or
    /// not a response at all.
    pub fn handle_response<'b>(&mut self, apdu: &[u8], buf: &'b mut [u8]) -> Result<Response<'b>> {
        let plain = self.unprotect_into(apdu, buf)?;
        let decoded = Apdu::from_bytes(plain)?;
        // An answer must be to the question that was asked. On a shared link — an
        // RS-485 bus, a concentrator multiplexing several meters — a response with
        // somebody else's invoke id is a reading attributed to the wrong request, and
        // nothing downstream can tell.
        if let Some(outstanding) = self.outstanding {
            if let Some(got) = response_invoke_id(&decoded) {
                if got.id() != outstanding.id() {
                    return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
                }
            }
        }
        Ok(match decoded {
            Apdu::GetResponse(GetResponse::Normal { result, .. }) => match result.value() {
                Ok(d) => Response::Data(d),
                Err(e) => Response::DataError(e),
            },
            Apdu::GetResponse(GetResponse::WithList { results, .. }) => Response::DataList(results),
            Apdu::GetResponse(GetResponse::WithDataBlock { block, .. }) => match block.result {
                Ok(data) => Response::Block { last: block.last_block, number: block.block_number, data },
                Err(e) => Response::DataError(e),
            },
            Apdu::SetResponse(
                SetResponse::Normal { result, .. } | SetResponse::LastDataBlock { result, .. },
            ) => {
                if result.is_success() {
                    Response::Ok
                } else {
                    Response::DataError(result)
                }
            }
            Apdu::SetResponse(SetResponse::DataBlock { block_number, .. }) => {
                Response::BlockAccepted { number: block_number }
            }
            Apdu::SetResponse(
                SetResponse::WithList { results, .. } | SetResponse::LastDataBlockWithList { results, .. },
            ) => Response::ResultList(results),
            Apdu::ActionResponse(crate::xdlms::ActionResponse::Normal { response, .. }) => {
                Response::ActionResult {
                    result: response.result,
                    value: response.return_parameters.and_then(|p| p.value().ok()),
                }
            }
            Apdu::ActionResponse(crate::xdlms::ActionResponse::NextPblock { block_number, .. }) => {
                Response::BlockAccepted { number: block_number }
            }
            Apdu::ActionResponse(crate::xdlms::ActionResponse::WithList { responses, .. }) => {
                Response::ActionResults(responses)
            }
            Apdu::ActionResponse(crate::xdlms::ActionResponse::WithPblock { block, .. }) => {
                Response::Block { last: block.last_block, number: block.block_number, data: block.raw_data }
            }
            Apdu::AccessResponse(r) => Response::Access { data: r.data, results: r.response_specification },
            #[cfg(feature = "sn")]
            Apdu::ReadResponse(r) => Response::ReadResults(r.results),
            #[cfg(feature = "sn")]
            Apdu::WriteResponse(r) => Response::WriteResults(r.results),
            Apdu::ExceptionResponse(e) => Response::Exception(e),
            Apdu::Rlre(_) => {
                self.state = SessionState::Closed;
                Response::Released
            }
            _ => return Err(Error::new(ErrorKind::UnexpectedMessage, 0)),
        })
    }

    /// Encode an APDU, protecting it when the policy says so.
    fn send(&mut self, apdu: &Apdu<'_>, out: &mut [u8]) -> Result<usize> {
        let mut w = SliceWriter::new(&mut self.scratch);
        apdu.encode(&mut w)?;
        let plain_len = w.written();
        self.send_plain(plain_len, out)
    }

    /// Protect and emit whatever the first `plain_len` bytes of the scratch buffer hold.
    fn send_plain(&mut self, plain_len: usize, out: &mut [u8]) -> Result<usize> {
        if self.config.security.is_none() {
            let mut w = SliceWriter::new(out);
            w.write_bytes(self.scratch.get(..plain_len).unwrap_or(&[]))?;
            return Ok(w.written());
        }
        let ctx = Outgoing {
            system_title: self.config.system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?,
            invocation_counter: self.invocation_counter.next()?,
            auth_key: self.protector.auth_key(),
            policy: self.protector.policy(),
            general_allowed: self.general_protection_agreed(),
        };
        let plain = self.scratch.get(..plain_len).unwrap_or(&[]);
        protect_apdu(&self.protector, &ctx, plain, out)
    }

    /// Remove protection from the AARE's user information, which is protected with the
    /// global key set even when the association will use a dedicated one.
    fn unprotect_initiate<'b>(&mut self, apdu: &[u8], buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let ctx = Incoming {
            local: self.config.system_title,
            peer: self.server_system_title,
            auth_key: self.protector.auth_key(),
            policy: self.config.security.global(),
            plain_allowed: PLAIN_INITIATE,
        };
        unprotect_apdu(&self.protector, &ctx, &mut self.peer_replay, apdu, buf)
    }

    /// Remove protection from an incoming APDU, if it has any.
    fn unprotect_into<'b>(&mut self, apdu: &[u8], buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let ctx = Incoming {
            local: self.config.system_title,
            peer: self.server_system_title,
            auth_key: self.protector.auth_key(),
            policy: self.protector.policy(),
            plain_allowed: PLAIN_FROM_SERVER,
        };
        unprotect_apdu(&self.protector, &ctx, &mut self.peer_replay, apdu, buf)
    }

    fn auth_key(&self) -> Result<&[u8]> {
        self.protector.auth_key().ok_or(Error::new(ErrorKind::Unsupported, 0))
    }

    fn next_counter(&mut self) -> Result<u32> {
        self.invocation_counter.next()
    }

    /// Refuse a short-name service in an association that named objects the other way.
    ///
    /// The referencing mode is chosen once, in the application context the AARQ
    /// proposes; a `read-request` sent into a logical-name association asks a question
    /// the peer has not agreed to answer, and a peer that answered anyway would be
    /// answering a different one.
    #[cfg(feature = "sn")]
    fn require_short_name(&self) -> Result<()> {
        if self.config.referencing == Referencing::ShortName {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::UnexpectedMessage, 0))
        }
    }

    fn require_associated(&self) -> Result<()> {
        if self.state == SessionState::Associated {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::UnexpectedMessage, 0))
        }
    }

    /// Whether `general-glo-ciphering` may be used, which the peer has to have agreed
    /// to: it is the `general-protection` bit of the conformance block and nothing else.
    fn general_protection_agreed(&self) -> bool {
        self.negotiated
            .as_ref()
            .is_some_and(|n| n.negotiated_conformance.contains(Conformance::GENERAL_PROTECTION))
    }

    fn require_conformance(&self, required: Conformance) -> Result<()> {
        match &self.negotiated {
            Some(n) => n.negotiated_conformance.require(required),
            None => Ok(()),
        }
    }
}

/// Gathers the fragments of a blocked response into one value.
///
/// A response too large for the negotiated PDU size arrives as a run of
/// `get-response-with-datablock` APDUs, each carrying a slice of the encoded value.
/// Only the concatenation is decodable: a fragment boundary falls wherever the server's
/// buffer ran out, which is very often in the middle of a length prefix.
///
/// The buffer is the caller's: how large a load profile may be is a property of the
/// deployment, not a decision for this crate.
///
/// ```
/// use dlms_cosem_rs::client::BlockCollector;
///
/// let mut storage = [0u8; 64];
/// let mut blocks = BlockCollector::new(&mut storage);
/// blocks.push(1, &[0x02, 0x02, 0x11])?;   // a structure of two, first field…
/// blocks.push(2, &[0x07, 0x11, 0x09])?;   // …split mid-value
/// let value = blocks.value()?;
/// assert_eq!(value.as_structure().unwrap().len(), 2);
/// # Ok::<(), dlms_cosem_rs::Error>(())
/// ```
#[derive(Debug)]
pub struct BlockCollector<'a> {
    buf: &'a mut [u8],
    len: usize,
    last_block: u32,
}

impl<'a> BlockCollector<'a> {
    /// A collector filling `buf`.
    ///
    /// `buf` must be large enough for the whole encoded value; the largest attribute a
    /// meter will return is a profile buffer, and its size is a property of the meter
    /// rather than of the protocol.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0, last_block: 0 }
    }

    /// Append one block.
    ///
    /// Block numbers must arrive consecutively from one. That check is not bookkeeping:
    /// a duplicated or reordered fragment concatenated in the wrong place produces a
    /// byte string that very often still *decodes*, into a value that is simply wrong —
    /// a meter reading no error ever attaches to.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] when `block_number` is not the one expected;
    /// [`ErrorKind::BufferTooSmall`] when the value does not fit.
    pub fn push(&mut self, block_number: u32, data: &[u8]) -> Result<()> {
        if block_number != self.last_block.saturating_add(1) {
            return Err(Error::new(ErrorKind::UnexpectedMessage, self.len));
        }
        let end = self.len.checked_add(data.len()).ok_or(Error::new(ErrorKind::InvalidLength, self.len))?;
        let capacity = self.buf.len();
        let at = self.len;
        let slot = self
            .buf
            .get_mut(at..end)
            .ok_or(Error::new(ErrorKind::BufferTooSmall { needed: end.saturating_sub(capacity) }, at))?;
        slot.copy_from_slice(data);
        self.len = end;
        self.last_block = block_number;
        Ok(())
    }

    /// The number of the last block accepted; zero before the first.
    ///
    /// This is what [`ClientSession::get_next_block_request`] acknowledges.
    #[must_use]
    pub const fn last_block(&self) -> u32 {
        self.last_block
    }

    /// How many bytes have been gathered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True before any block has been pushed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes gathered so far.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Decode what has been gathered.
    ///
    /// # Errors
    /// Whatever decoding the value returns — including [`ErrorKind::Truncated`] if this
    /// is called before the last block has arrived.
    pub fn value(&self) -> Result<Data<'_>> {
        Data::from_bytes_in(self.bytes())
    }

    /// Decode what has been gathered as the result list of a `get-request-with-list`.
    ///
    /// A blocked response carries the encoded body of whichever response form it is, so
    /// the fragments of a list read reassemble into a list rather than into a value.
    /// Calling the wrong one of this and [`BlockCollector::value`] is a decode error,
    /// not a wrong answer.
    ///
    /// # Errors
    /// Whatever decoding the list returns.
    pub fn results(&self) -> Result<List<'_, GetDataResult<'_>>> {
        List::from_bytes(self.bytes())
    }

    /// Forget everything, ready for another read into the same buffer.
    pub const fn reset(&mut self) {
        self.len = 0;
        self.last_block = 0;
    }
}

/// The invoke id a confirmed response echoes, for the services that carry one.
///
/// `None` for the APDUs that have no invoke id at all — the ACSE ones, the exception
/// response, and ACCESS, which uses a long invoke id of its own.
const fn response_invoke_id(apdu: &Apdu<'_>) -> Option<InvokeId> {
    Some(match apdu {
        Apdu::GetResponse(
            GetResponse::Normal { invoke_id, .. }
            | GetResponse::WithDataBlock { invoke_id, .. }
            | GetResponse::WithList { invoke_id, .. },
        ) => *invoke_id,
        Apdu::SetResponse(
            SetResponse::Normal { invoke_id, .. }
            | SetResponse::DataBlock { invoke_id, .. }
            | SetResponse::LastDataBlock { invoke_id, .. }
            | SetResponse::LastDataBlockWithList { invoke_id, .. }
            | SetResponse::WithList { invoke_id, .. },
        ) => *invoke_id,
        Apdu::ActionResponse(
            crate::xdlms::ActionResponse::Normal { invoke_id, .. }
            | crate::xdlms::ActionResponse::WithPblock { invoke_id, .. }
            | crate::xdlms::ActionResponse::WithList { invoke_id, .. }
            | crate::xdlms::ActionResponse::NextPblock { invoke_id, .. },
        ) => *invoke_id,
        _ => return None,
    })
}

/// Which service a [`BlockSender`] is feeding.
#[derive(Debug, Clone, Copy, PartialEq)]
enum BlockTarget<'a> {
    /// A SET: the first block carries the attribute descriptor and any selector.
    Attribute { descriptor: AttributeDescriptor, access: Option<SelectiveAccess<'a>> },
    /// An ACTION: the first block carries the method descriptor.
    Method(MethodDescriptor),
    /// A batched SET: the first block carries the whole attribute list.
    AttributeList(List<'a, AttributeDescriptorWithSelection<'a>>),
}

/// A value going out block by block, because it is larger than one APDU can carry.
///
/// The mirror of [`BlockCollector`]: that one gathers a long *response*, this one emits a
/// long *request*. The bytes stay the caller's in both directions, for the same reason —
/// how large a value a deployment writes is a property of the deployment, and a session
/// that buffered it would put a ceiling on it that nothing in the standard has.
///
/// Every block of one transfer carries the same invoke id, which the session keeps.
#[derive(Debug, Clone, Copy)]
pub struct BlockSender<'a> {
    target: BlockTarget<'a>,
    bytes: &'a [u8],
    sent: usize,
    block: u32,
    /// Non-zero by construction: a `div_ceil` by a plain `usize` leaves a
    /// divide-by-zero panic path in the object code, and a fragment of zero would in
    /// any case never finish.
    fragment: core::num::NonZeroUsize,
}

impl BlockSender<'_> {
    /// True when every block has gone out.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.block > 0 && self.sent >= self.bytes.len()
    }

    /// How many bytes are still to go.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.sent)
    }

    /// The number of the last block emitted; zero before the first.
    #[must_use]
    pub const fn block(&self) -> u32 {
        self.block
    }

    /// How many blocks this transfer will take in total.
    #[must_use]
    pub const fn blocks(&self) -> usize {
        // An empty value is still one block: it has to be sent for the server to learn
        // that it is the last one.
        let n = self.bytes.len().div_ceil(self.fragment.get());
        if n == 0 { 1 } else { n }
    }
}

/// One operation inside an [`ClientSession::access_request`].
///
/// ACCESS is the only service that mixes reads, writes and invocations into a single
/// exchange, which is what makes it the right one for a link where a round trip costs
/// more than a kilobyte.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AccessItem<'a> {
    /// Read an attribute.
    Get {
        /// Which attribute.
        descriptor: AttributeDescriptor,
        /// Which part of it.
        access: Option<SelectiveAccess<'a>>,
    },
    /// Write an attribute.
    Set {
        /// Which attribute.
        descriptor: AttributeDescriptor,
        /// Which part of it.
        access: Option<SelectiveAccess<'a>>,
        /// The new value.
        value: Data<'a>,
    },
    /// Invoke a method.
    Action {
        /// Which method.
        descriptor: MethodDescriptor,
        /// Its parameter, if it takes one.
        parameters: Option<Data<'a>>,
    },
}

impl<'a> AccessItem<'a> {
    fn specification(&self) -> AccessRequestSpecification<'a> {
        match *self {
            Self::Get { descriptor, access: None } => AccessRequestSpecification::Get(descriptor),
            Self::Get { descriptor, access: Some(access) } => {
                AccessRequestSpecification::GetWithSelection(AttributeDescriptorWithSelection {
                    descriptor,
                    access: Some(access),
                })
            }
            Self::Set { descriptor, access: None, .. } => AccessRequestSpecification::Set(descriptor),
            Self::Set { descriptor, access: Some(access), .. } => {
                AccessRequestSpecification::SetWithSelection(AttributeDescriptorWithSelection {
                    descriptor,
                    access: Some(access),
                })
            }
            Self::Action { descriptor, .. } => AccessRequestSpecification::Action(descriptor),
        }
    }
}
