//! The server: a sans-I/O meter.
//!
//! The same engine runs inside firmware and behind `dlms-cli sim`. Objects are behind
//! the [`ObjectStore`] trait, so a meter backs an attribute with a flash cell and a
//! simulator backs it with whatever it likes; associations, authentication, access
//! control and protection are in the framework, not in each object.

mod push;
mod store;

pub use push::{PushDestination, PushSender, check_body_fits};
pub use store::{AuditEvent, ObjectStore, StoreResult};

use crate::acse::{
    Aare, Aarq, ApplicationContext, AssociationResult, AuthMechanism, Diagnostic, Rlre, Rlrq, UserDiagnostic,
};
use crate::axdr::Data;
use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, SliceWriter, Writer};
use crate::cosem::AttributeAccess;
use crate::obis::Obis;
use crate::security::wrap::{Incoming, Outgoing, protect_apdu, unprotect_apdu};
use crate::security::{
    CryptoProvider, InvocationCounter, Protector, ReplayWindow, SecurityPolicy, SystemTitle,
};
use crate::xdlms::{
    AccessRequest, AccessRequestSpecification, AccessResponse, AccessResponseSpecification, ActionRequest,
    ActionResponse, ActionResponseWithOptionalData, ActionResult, Apdu, ApduTag, AttributeDescriptor,
    Conformance, DataAccessResult, DataBlockG, DataBlockSA, ExceptionResponse, GetDataResult, GetRequest,
    GetResponse, InitiateRequest, InitiateResponse, InvokeId, List, MAX_ACCESS_ITEMS, MethodDescriptor,
    Protection, SelectiveAccess, ServiceError, SetRequest, SetResponse, StateError,
};

/// The APDUs a server accepts from a client with no protection on them, even in a
/// ciphered association: the two that precede or end the association, whose protection
/// lives in their user-information field rather than around the APDU.
const PLAIN_FROM_CLIENT: &[ApduTag] = &[ApduTag::Aarq, ApduTag::ReleaseRequest];

/// What the AARQ's user information may be when the association is not ciphered.
const PLAIN_INITIATE: &[ApduTag] = &[ApduTag::InitiateRequest];

/// What a `get-response-with-datablock` costs around its fragment, worst case.
///
/// APDU tag, response choice, invoke id, last-block flag, four-byte block number,
/// result choice, and a length prefix in its longest form.
const BLOCK_HEADER_MAX: usize = 1 + 1 + 1 + 1 + 4 + 1 + 5;

/// What protection costs around a plaintext APDU, worst case.
///
/// The `glo-` tag, the ciphered service's length prefix in its longest form, the
/// security control byte, the invocation counter, and the truncated GCM tag.
const PROTECTION_MAX: usize = 1 + 5 + 1 + 4 + 12;

/// What a `get-response-normal` costs around its value.
const NORMAL_HEADER_MAX: usize = 1 + 1 + 1 + 1;

/// What an `action-response-normal` costs around its return value: the tag, the response
/// choice, the invoke id, the action result, and the optional-data usage flag and choice.
const ACTION_HEADER_MAX: usize = 1 + 1 + 1 + 1 + 1 + 1;

/// A transfer in flight: bytes going out block by block, or a value arriving that way.
///
/// Only one can be in flight at a time — the standard's block transfer is a single
/// outstanding invocation per association — so this is one state rather than four
/// optional fields that could disagree with each other. It is small and `Copy`: the
/// bytes live in the server's `response` buffer and only the bookkeeping is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transfer {
    /// Nothing in flight.
    Idle,
    /// A response too large for one APDU, waiting for the client to ask for the rest.
    Sending {
        /// The invoke id every block of this transfer carries.
        invoke_id: InvokeId,
        /// Which service is being answered, which decides the APDU each block goes in.
        service: Outbound,
        /// How many bytes there are in total.
        len: usize,
        /// How many have gone out.
        sent: usize,
        /// The number of the last block sent. Blocks count from one.
        block: u32,
    },
    /// A SET whose value is arriving block by block.
    ///
    /// The value accumulates in the response buffer *after* whatever had to survive from
    /// the first block to the last and has nowhere else to live — the selective-access
    /// descriptor of a single write, or the attribute list of a batched one. `header_end`
    /// is where the value starts, and zero means there was nothing to keep.
    ReceivingSet {
        /// The invoke id every block carries.
        invoke_id: InvokeId,
        /// Which attribute is being written, for a single write.
        descriptor: crate::xdlms::AttributeDescriptor,
        /// True when the header holds an attribute *list* rather than one descriptor's
        /// selector — the two are reassembled the same way and completed differently.
        list: bool,
        /// Where the value starts in the response buffer.
        header_end: usize,
        /// How many bytes of the value have arrived.
        len: usize,
        /// The number of the last block accepted.
        block: u32,
    },
    /// An ACTION whose parameter is arriving block by block.
    ReceivingAction {
        /// The invoke id every block carries.
        invoke_id: InvokeId,
        /// Which method is being invoked.
        descriptor: crate::xdlms::MethodDescriptor,
        /// How many bytes of the parameter have arrived.
        len: usize,
        /// The number of the last block accepted.
        block: u32,
    },
}

/// Which service a [`Transfer::Sending`] is answering.
///
/// GET and ACTION segment their results differently — `get-response-with-datablock`
/// carries a `DataBlock-G` whose payload is a choice, `action-response-with-pblock`
/// carries a bare `DataBlock-SA` — so the block form cannot be inferred from the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outbound {
    /// `get-response-with-datablock`.
    Get,
    /// `action-response-with-pblock`.
    Action,
}

/// What the server is.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The server's system title. Required for a ciphered association and for GMAC.
    pub system_title: Option<SystemTitle>,
    /// Which authentication the server requires.
    pub mechanism: AuthMechanism,
    /// The low-level-security password, or the high-level-security shared secret.
    pub password: Option<crate::security::Secret>,
    /// What protection the server applies and demands.
    pub security: SecurityPolicy,
    /// The largest APDU the server will accept.
    pub max_pdu_size: u16,
    /// What the server can do.
    pub conformance: Conformance,
    /// How long a challenge to send.
    pub challenge_len: usize,
    /// The last invocation counter this server used before it started.
    ///
    /// Zero is right only for a device that has never sent under these keys. A server
    /// that restarts from zero against an unchanged key reuses every nonce it used
    /// before, and repeating a GCM nonce leaks the authentication subkey — after which
    /// anyone can forge messages under that key. Persist
    /// [`Server::invocation_counter`] and restore it here.
    pub invocation_counter: u32,
    /// How far out of order a client's invocation counters may arrive.
    ///
    /// Zero — strictly increasing — is right for HDLC and TCP. See [`ReplayWindow`].
    pub replay_window: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            system_title: None,
            mechanism: AuthMechanism::None,
            password: None,
            security: SecurityPolicy::NONE,
            max_pdu_size: 1024,
            conformance: Conformance::SERVER_DEFAULT,
            challenge_len: 16,
            invocation_counter: 0,
            replay_window: 0,
        }
    }
}

/// Where the association is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// No association.
    Idle,
    /// The AARE has gone out and the client's reply to the challenge is outstanding.
    AwaitingHlsReply,
    /// Serving requests.
    Associated,
    /// Released.
    Closed,
}

/// A DLMS server over one link, serving one logical device.
///
/// A meter hosting several logical devices runs **one `Server` per device**; the caller
/// routes by the service access point its transport hands it — the wrapper header's
/// destination, or the HDLC destination address. This type never sees a transport, so
/// the SAP is not its to dispatch on.
///
/// `N` sizes the working buffers and bounds **the largest attribute the store can
/// produce** — not the largest APDU it can send:
///
/// * `max_pdu_size` and the client's own limit bound one *message*. A value larger than
///   that is delivered over block transfer, however many blocks it takes.
/// * `N` bounds the *value*, because a response is built whole before it is cut into
///   blocks. A meter whose load profile encodes to eight kilobytes needs `N` of at
///   least that, whatever PDU size it negotiates.
///
/// A store that overruns `N` gets a write error from its `Writer` and reports whatever
/// [`DataAccessResult`] it chooses; nothing is truncated silently.
#[derive(Debug)]
pub struct Server<S, P, const N: usize = 1024> {
    config: ServerConfig,
    store: S,
    protector: Protector<P>,
    state: ServerState,
    client_system_title: Option<SystemTitle>,
    client_challenge: [u8; 64],
    client_challenge_len: usize,
    server_challenge: [u8; 64],
    server_challenge_len: usize,
    invocation_counter: InvocationCounter,
    /// Which of the client's invocation counters have already been spent.
    peer_replay: ReplayWindow,
    negotiated: Conformance,
    ciphered_association: bool,
    /// The largest APDU the client said it can receive, once it has said so.
    client_max_pdu_size: u16,
    /// The block transfer in flight, if any.
    transfer: Transfer,
    /// Where a blocked transfer's bytes live between blocks, in either direction.
    response: [u8; N],
    scratch: [u8; N],
}

impl<S: ObjectStore, P: CryptoProvider, const N: usize> Server<S, P, N> {
    /// A server over `store`, using `provider` for cryptography.
    pub fn new(config: ServerConfig, store: S, provider: P) -> Self {
        // Before the association is open there is no dedicated key, so the protector
        // starts on the global key set. A client that delivers one in its
        // InitiateRequest switches it over for the rest of the association.
        let policy = config.security.global();
        let invocation_counter = InvocationCounter::new(config.invocation_counter);
        let peer_replay = ReplayWindow::new(config.replay_window);
        let client_max_pdu_size = config.max_pdu_size;
        Self {
            config,
            store,
            protector: Protector::new(provider, policy),
            state: ServerState::Idle,
            client_system_title: None,
            client_challenge: [0; 64],
            client_challenge_len: 0,
            server_challenge: [0; 64],
            server_challenge_len: 0,
            invocation_counter,
            peer_replay,
            negotiated: Conformance::empty(),
            ciphered_association: false,
            client_max_pdu_size,
            transfer: Transfer::Idle,
            response: [0; N],
            scratch: [0; N],
        }
    }

    /// The last invocation counter this server sent under.
    ///
    /// Persist this. Restoring a lower value after a restart reuses a nonce; see
    /// [`ServerConfig::invocation_counter`].
    #[must_use]
    pub const fn invocation_counter(&self) -> u32 {
        self.invocation_counter.get()
    }

    /// The highest invocation counter accepted from the client, if any.
    #[must_use]
    pub const fn peer_invocation_counter(&self) -> Option<u32> {
        self.peer_replay.highest()
    }

    /// The largest APDU the client said it can receive.
    #[must_use]
    pub const fn client_max_pdu_size(&self) -> u16 {
        self.client_max_pdu_size
    }

    /// Forget the association, ready for a new client on the same link.
    ///
    /// A `Server` holds one association at a time. Releasing clears it, but a client
    /// that simply drops the connection never sends an RLRQ — and a sans-I/O engine
    /// cannot see a closed socket, so nothing else can notice. A caller that reuses a
    /// `Server` across connections must call this, or the next client inherits the
    /// previous one's dedicated key, negotiated conformance and challenge.
    ///
    /// What is deliberately **not** reset is the invocation counter: it must never go
    /// backwards, because a repeated GCM nonce is a key-recovery event and the key is
    /// the same key. The peer's replay window is cleared, because it belongs to the
    /// peer's counter and the next client is a different peer.
    pub fn reset(&mut self) {
        self.state = ServerState::Idle;
        self.client_system_title = None;
        self.client_challenge = [0; 64];
        self.client_challenge_len = 0;
        self.server_challenge = [0; 64];
        self.server_challenge_len = 0;
        self.negotiated = Conformance::empty();
        self.ciphered_association = false;
        self.client_max_pdu_size = self.config.max_pdu_size;
        self.peer_replay = ReplayWindow::new(self.config.replay_window);
        self.protector.provider_mut().clear_dedicated_key();
        self.protector.set_dedicated(false);
        self.transfer = Transfer::Idle;
        self.scratch = [0; N];
        self.store.audit(AuditEvent::Released);
    }

    /// True while a value is being delivered or received block by block.
    #[must_use]
    pub const fn is_block_transfer_in_progress(&self) -> bool {
        !matches!(self.transfer, Transfer::Idle)
    }

    /// Where the association is.
    #[must_use]
    pub const fn state(&self) -> ServerState {
        self.state
    }

    /// The objects.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// The objects, mutably.
    pub const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Handle one APDU and produce the reply.
    ///
    /// Returns how many bytes of `out` the reply uses, or zero when there is nothing to
    /// say.
    ///
    /// # Errors
    /// Only for a malformed APDU or an output buffer too small. A *refused* request is
    /// not an error: it is an exception response, and the caller sends it.
    pub fn handle(&mut self, apdu: &[u8], out: &mut [u8]) -> Result<usize> {
        // The server told the client how much it would accept; a client that ignores
        // that is refused here rather than part-way through a decode.
        if apdu.len() > usize::from(self.config.max_pdu_size) {
            // The standard has a code for exactly this, and it tells the client what to
            // do about it — shrink and try again — where a generic refusal does not.
            return self.exception(StateError::ServiceNotAllowed, ServiceError::PduTooLong, out);
        }
        let tag_byte = apdu.first().copied().unwrap_or(0);
        let Some(tag) = ApduTag::from_u8(tag_byte) else {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        };

        match tag {
            ApduTag::Aarq => return self.handle_aarq(apdu, out),
            ApduTag::ReleaseRequest => return self.handle_release(apdu, out),
            _ => {}
        }

        if self.state != ServerState::Associated && self.state != ServerState::AwaitingHlsReply {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }

        // Unprotect into a scratch that is not the one used for building the reply.
        let mut plain_buf = [0u8; N];
        // Anything that goes wrong removing protection is a `deciphering-error`, which
        // is the code the standard has for it. Returning a transport-level `Err` instead
        // makes the caller invent an answer, and the two cases it invented for — a
        // plaintext APDU arriving in a ciphered association, and a replayed counter —
        // are the two a client most needs told about by name.
        let plain = match self.unprotect_into(apdu, &mut plain_buf) {
            Ok(p) => p,
            Err(e) => {
                let service = if matches!(e.kind, ErrorKind::BufferTooSmall { .. }) {
                    ServiceError::PduTooLong
                } else {
                    ServiceError::DecipheringError
                };
                return self.exception(StateError::ServiceNotAllowed, service, out);
            }
        };
        let Ok(decoded) = Apdu::from_bytes(plain) else {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        };

        match decoded {
            Apdu::GetRequest(req) => self.handle_get(req, out),
            Apdu::SetRequest(req) => self.handle_set(req, out),
            Apdu::ActionRequest(req) => self.handle_action(req, out),
            Apdu::AccessRequest(req) => self.handle_access(&req, out),
            _ => self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the association handshake decides seven things and splitting it hides the order they are decided in"
    )]
    fn handle_aarq(&mut self, apdu: &[u8], out: &mut [u8]) -> Result<usize> {
        let aarq = Aarq::from_bytes(apdu)?;
        let context = aarq.application_context.unwrap_or(ApplicationContext::LogicalName);
        self.ciphered_association = context.is_ciphered();

        if !context.is_logical_name() {
            return self.refuse(
                AssociationResult::RejectedPermanent,
                UserDiagnostic::ApplicationContextNameNotSupported,
                out,
            );
        }
        if self.ciphered_association == self.config.security.is_none() {
            return self.refuse(
                AssociationResult::RejectedPermanent,
                UserDiagnostic::ApplicationContextNameNotSupported,
                out,
            );
        }

        let mechanism = aarq.mechanism_name.unwrap_or(AuthMechanism::None);
        if mechanism != self.config.mechanism {
            let diagnostic = if self.config.mechanism == AuthMechanism::None {
                UserDiagnostic::AuthenticationMechanismNameNotRecognised
            } else {
                UserDiagnostic::AuthenticationMechanismNameRequired
            };
            return self.refuse(AssociationResult::RejectedPermanent, diagnostic, out);
        }

        if let Some(title) = aarq.calling_ap_title {
            self.client_system_title = Some(SystemTitle::from_slice(title)?);
        }

        // Low level security is decided here and now; high level security needs two
        // more passes and is only *started* here.
        if mechanism == AuthMechanism::Low {
            let expected = self.config.password.as_ref().map_or(&[][..], |p| p.expose());
            let given = aarq.calling_authentication_value.unwrap_or(&[]);
            if !crate::security::constant_time_eq(expected, given) {
                return self.refuse(
                    AssociationResult::RejectedPermanent,
                    UserDiagnostic::AuthenticationFailure,
                    out,
                );
            }
        }

        // Negotiate against what the client proposed.
        let mut proposed = Conformance::empty();
        let mut client_max = self.config.max_pdu_size;
        if let Some(user_info) = aarq.user_information {
            let mut buf = [0u8; 256];
            let plain = self.unprotect_initiate(user_info, &mut buf)?;
            let mut r = Reader::new(plain);
            let tag = r.u8()?;
            if ApduTag::from_u8(tag) == Some(ApduTag::InitiateRequest) {
                let init = InitiateRequest::decode(&mut r)?;
                proposed = init.proposed_conformance;
                client_max = init.client_max_receive_pdu_size;
                if let Some(dedicated) = init.dedicated_key {
                    // A dedicated key is not a preference the server configured — it is
                    // the client's decision, taken in this message. Both ends must
                    // switch or nothing after it decrypts, so the protector follows the
                    // key rather than the configuration. A provider that cannot hold one
                    // says so, and the association stays on the global key set.
                    let key = crate::security::Key::from_slice(dedicated)?;
                    if self.protector.provider_mut().set_dedicated_key(key).is_ok() {
                        self.protector.set_dedicated(true);
                    }
                }
            }
        }
        self.negotiated = self.config.conformance.negotiate(proposed);
        // What the client says it can receive bounds every reply this association will
        // send. Parsing it and then ignoring it is how a server ends up transmitting a
        // response the client has already stopped reading.
        self.client_max_pdu_size = if client_max == 0 { self.config.max_pdu_size } else { client_max };

        let mut challenge_len: Option<usize> = None;
        if mechanism.is_high_level() {
            if mechanism != AuthMechanism::HighGmac {
                return self.refuse(
                    AssociationResult::RejectedPermanent,
                    UserDiagnostic::AuthenticationMechanismNameNotRecognised,
                    out,
                );
            }
            let given =
                aarq.calling_authentication_value.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
            if given.len() > 64 {
                return Err(Error::new(ErrorKind::InvalidLength, 0));
            }
            self.client_challenge[..given.len()].copy_from_slice(given);
            self.client_challenge_len = given.len();
            let len = self.config.challenge_len.clamp(8, 64);
            self.protector.provider().random(&mut self.server_challenge[..len])?;
            self.server_challenge_len = len;
            challenge_len = Some(len);
            self.state = ServerState::AwaitingHlsReply;
        } else {
            self.state = ServerState::Associated;
        }

        let response = InitiateResponse {
            negotiated_conformance: self.negotiated,
            server_max_receive_pdu_size: self.config.max_pdu_size,
            ..Default::default()
        };
        let mut plain = [0u8; 64];
        let mut pw = SliceWriter::new(&mut plain);
        pw.write_u8(ApduTag::InitiateResponse.as_u8())?;
        response.encode(&mut pw)?;
        let plain_len = pw.written();

        let mut user_info_buf = [0u8; 160];
        let user_info: &[u8] = if self.ciphered_association {
            let title = self.config.system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
            let ic = self.next_counter()?;
            let mut body = [0u8; 128];
            let auth_key = self.auth_key()?;
            let payload = self.protector.protect_as(
                self.config.security.global(),
                &title,
                ic,
                auth_key,
                &plain[..plain_len],
                &mut body,
            )?;
            let mut w = SliceWriter::new(&mut user_info_buf);
            let tag = ApduTag::InitiateResponse
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
            &user_info_buf[..n]
        } else {
            &plain[..plain_len]
        };

        let challenge = challenge_len.map(|len| &self.server_challenge[..len]);
        let aare = Aare {
            application_context: Some(context),
            result: AssociationResult::Accepted,
            diagnostic: Diagnostic::User(UserDiagnostic::Null),
            responding_ap_title: self.config.system_title.as_ref().map(|t| &t.0[..]),
            responder_acse_requirements: mechanism != AuthMechanism::None,
            mechanism_name: (mechanism != AuthMechanism::None).then_some(mechanism),
            responding_authentication_value: challenge,
            user_information: Some(user_info),
        };
        self.store.audit(AuditEvent::Associated { mechanism, ciphered: self.ciphered_association });
        let mut w = SliceWriter::new(out);
        aare.encode(&mut w)?;
        Ok(w.written())
    }

    fn handle_release(&mut self, apdu: &[u8], out: &mut [u8]) -> Result<usize> {
        let rlrq = Rlrq::from_bytes(apdu)?;
        self.state = ServerState::Closed;
        self.protector.provider_mut().clear_dedicated_key();
        self.protector.set_dedicated(false);
        self.store.audit(AuditEvent::Released);
        let rlre = Rlre { reason: rlrq.reason, user_information: None };
        let mut w = SliceWriter::new(out);
        rlre.encode(&mut w)?;
        Ok(w.written())
    }

    fn handle_get(&mut self, req: GetRequest<'_>, out: &mut [u8]) -> Result<usize> {
        if self.state != ServerState::Associated {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }
        if self.negotiated.require(Conformance::GET).is_err() {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        }

        let (invoke_id, descriptor, access) = match req {
            GetRequest::Normal { invoke_id, descriptor, access } => (invoke_id, descriptor, access),
            GetRequest::Next { invoke_id, block_number } => {
                return self.handle_get_next(invoke_id, block_number, out);
            }
            GetRequest::WithList { invoke_id, list } => {
                return self.handle_get_with_list(invoke_id, &list, out);
            }
        };

        // A new request abandons whatever was half-delivered. The client asked for
        // something else; continuing to hold the old transfer would mean a later
        // `get-request-next` silently returned a block of it.
        self.transfer = Transfer::Idle;

        let rights =
            self.store.attribute_access(descriptor.class_id, descriptor.instance_id, descriptor.attribute_id);
        if !rights.can_read() {
            self.audit_read(&descriptor, DataAccessResult::ReadWriteDenied);
            return self.get_error(invoke_id, DataAccessResult::ReadWriteDenied, out);
        }

        // The value is written straight into the response buffer, so a large attribute
        // never exists twice.
        let mut value = [0u8; N];
        let mut vw = SliceWriter::new(&mut value);
        match self.store.get_attribute(
            descriptor.class_id,
            descriptor.instance_id,
            descriptor.attribute_id,
            access,
            &mut vw,
        ) {
            Ok(()) => self.audit_read(&descriptor, DataAccessResult::Success),
            Err(e) => {
                self.audit_read(&descriptor, e);
                return self.get_error(invoke_id, e, out);
            }
        }
        let n = vw.written();
        if n == 0 {
            // Success with no value written: the store's contract, broken. A
            // `get-response-normal` with a choice byte and nothing behind it is
            // malformed, which is worse than a refusal because the client cannot even
            // say which read failed.
            self.audit_read(&descriptor, DataAccessResult::OtherReason);
            return self.get_error(invoke_id, DataAccessResult::OtherReason, out);
        }

        if n + NORMAL_HEADER_MAX + self.protection_overhead() <= usize::from(self.client_max_pdu_size) {
            let data = Data::from_bytes_in(&value[..n])?;
            let response = GetResponse::Normal { invoke_id, result: GetDataResult::Data(data) };
            return self.send(&Apdu::GetResponse(response), out);
        }

        // Too large for one APDU. The client must have agreed to block transfer;
        // otherwise there is no way to deliver this and saying so beats truncating.
        if self.negotiated.require(Conformance::BLOCK_TRANSFER_WITH_GET_OR_READ).is_err() {
            // The value exists and the client may read it; there is simply no way to
            // deliver it under what was negotiated.
            return self.get_error(invoke_id, DataAccessResult::DataBlockUnavailable, out);
        }
        self.response
            .get_mut(..n)
            .ok_or(Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))?
            .copy_from_slice(value.get(..n).unwrap_or(&[]));
        self.transfer = Transfer::Sending { invoke_id, service: Outbound::Get, len: n, sent: 0, block: 0 };
        self.send_next_block(out)
    }

    /// Read several attributes in one exchange.
    ///
    /// Each item gets its own result, so one unreadable object does not lose the whole
    /// read — which is the reason a head-end uses this service rather than issuing the
    /// reads one at a time.
    fn handle_get_with_list(
        &mut self,
        invoke_id: InvokeId,
        list: &crate::xdlms::List<'_, crate::xdlms::AttributeDescriptorWithSelection<'_>>,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.negotiated.require(Conformance::MULTIPLE_REFERENCES).is_err() {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        }
        self.transfer = Transfer::Idle;

        // Every result is encoded into one buffer as it is produced, so a list of large
        // attributes never exists twice.
        let mut results = [0u8; N];
        let mut rw = SliceWriter::new(&mut results);
        let mut count = 0usize;
        for item in list.iter() {
            let item = item?;
            let d = item.descriptor;
            let rights = self.store.attribute_access(d.class_id, d.instance_id, d.attribute_id);
            let outcome = if rights.can_read() {
                // `get-data-result` is a choice: 0 and the value, or 1 and the reason.
                // The tag goes down first and the store writes straight after it.
                rw.write_u8(0)?;
                let before = rw.written();
                match self.store.get_attribute(
                    d.class_id,
                    d.instance_id,
                    d.attribute_id,
                    item.access,
                    &mut rw,
                ) {
                    // A store that reports success and writes nothing has broken its
                    // contract, and the response it would produce is *malformed* rather
                    // than wrong — a choice byte with no value behind it, which the
                    // client cannot decode and cannot attribute. Reporting it as this
                    // item's failure keeps the rest of the list readable.
                    Ok(()) if rw.written() == before => {
                        rw.truncate(before.saturating_sub(1))?;
                        rw.write_u8(1)?;
                        rw.write_u8(DataAccessResult::OtherReason.as_u8())?;
                        DataAccessResult::OtherReason
                    }
                    Ok(()) => DataAccessResult::Success,
                    Err(e) => {
                        // Rewind over the choice byte and whatever the store managed to
                        // write, and put the failure there instead.
                        rw.truncate(before.saturating_sub(1))?;
                        rw.write_u8(1)?;
                        rw.write_u8(e.as_u8())?;
                        e
                    }
                }
            } else {
                rw.write_u8(1)?;
                rw.write_u8(DataAccessResult::ReadWriteDenied.as_u8())?;
                DataAccessResult::ReadWriteDenied
            };
            self.audit_read(&d, outcome);
            count += 1;
        }
        let n = rw.written();

        // The count prefix belongs to the list, so it is part of what gets blocked.
        let mut body = [0u8; N];
        let mut bw = SliceWriter::new(&mut body);
        bw.write_length(count)?;
        bw.write_bytes(&results[..n])?;
        let body_len = bw.written();

        if body_len + NORMAL_HEADER_MAX + self.protection_overhead() <= usize::from(self.client_max_pdu_size)
        {
            let response = GetResponse::WithList {
                invoke_id,
                results: crate::xdlms::List::from_raw(count, &results[..n]),
            };
            return self.send(&Apdu::GetResponse(response), out);
        }

        if self.negotiated.require(Conformance::BLOCK_TRANSFER_WITH_GET_OR_READ).is_err() {
            return self.get_error(invoke_id, DataAccessResult::DataBlockUnavailable, out);
        }
        // A blocked response carries the encoded body of whichever response form it is,
        // so what goes into the blocks here is the list, count prefix included.
        self.response
            .get_mut(..body_len)
            .ok_or(Error::new(ErrorKind::BufferTooSmall { needed: body_len }, 0))?
            .copy_from_slice(body.get(..body_len).unwrap_or(&[]));
        self.transfer =
            Transfer::Sending { invoke_id, service: Outbound::Get, len: body_len, sent: 0, block: 0 };
        self.send_next_block(out)
    }

    /// The client acknowledges a block and asks for the next.
    fn handle_get_next(&mut self, invoke_id: InvokeId, acked: u32, out: &mut [u8]) -> Result<usize> {
        let Transfer::Sending { invoke_id: id, service: Outbound::Get, block, .. } = self.transfer else {
            // Nothing is being transferred. The standard has a code for exactly this,
            // and it is worth using: a client that gets `no-long-get-in-progress` knows
            // its transfer was dropped, where a generic exception tells it nothing.
            return self.get_error(invoke_id, DataAccessResult::NoLongGetInProgress, out);
        };
        // The acknowledgement must name the block actually last sent, under the invoke
        // id the transfer was started with. Anything else is a client that has lost
        // track, and answering it would deliver the wrong fragment as though it were
        // the right one.
        if invoke_id != id || acked != block {
            self.transfer = Transfer::Idle;
            return self.get_error(invoke_id, DataAccessResult::DataBlockNumberInvalid, out);
        }
        self.send_next_block(out)
    }

    /// The client acknowledges a block of a long ACTION result and asks for the next.
    fn handle_action_next(&mut self, invoke_id: InvokeId, acked: u32, out: &mut [u8]) -> Result<usize> {
        let Transfer::Sending { invoke_id: id, service: Outbound::Action, block, .. } = self.transfer else {
            return self.action_error(invoke_id, ActionResult::NoLongActionInProgress, out);
        };
        if invoke_id != id || acked != block {
            self.transfer = Transfer::Idle;
            return self.action_error(invoke_id, ActionResult::DataBlockUnavailable, out);
        }
        self.send_next_block(out)
    }

    /// Emit the next fragment of whatever is being sent block by block.
    fn send_next_block(&mut self, out: &mut [u8]) -> Result<usize> {
        let Transfer::Sending { invoke_id, service, len, sent, block } = self.transfer else {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        };
        let max = self.max_fragment();
        if max == 0 {
            // The negotiated PDU size leaves no room for a payload at all.
            self.transfer = Transfer::Idle;
            return match service {
                Outbound::Get => self.get_error(invoke_id, DataAccessResult::LongGetAborted, out),
                Outbound::Action => self.action_error(invoke_id, ActionResult::LongActionAborted, out),
            };
        }
        let end = sent.saturating_add(max).min(len);
        let take = end.saturating_sub(sent);

        // The fragment is copied out of the response buffer rather than borrowed from
        // it, because building the reply needs `&mut self` and the buffer is part of
        // `self`. One copy of at most one fragment; the response itself does not move.
        let mut fragment = [0u8; N];
        let src = self.response.get(sent..end).unwrap_or(&[]);
        fragment
            .get_mut(..take)
            .ok_or(Error::new(ErrorKind::BufferTooSmall { needed: take }, 0))?
            .copy_from_slice(src);
        let payload = fragment.get(..take).unwrap_or(&[]);

        let last_block = end == len;
        let number = block.saturating_add(1);
        let n = match service {
            Outbound::Get => {
                let response = GetResponse::WithDataBlock {
                    invoke_id,
                    block: DataBlockG { last_block, block_number: number, result: Ok(payload) },
                };
                self.send(&Apdu::GetResponse(response), out)?
            }
            Outbound::Action => {
                let response = ActionResponse::WithPblock {
                    invoke_id,
                    block: DataBlockSA { last_block, block_number: number, raw_data: payload },
                };
                self.send(&Apdu::ActionResponse(response), out)?
            }
        };

        self.transfer = if last_block {
            Transfer::Idle
        } else {
            Transfer::Sending { invoke_id, service, len, sent: end, block: number }
        };
        Ok(n)
    }

    /// Start delivering `len` bytes already sitting in the response buffer, or send them
    /// whole if they fit.
    ///
    /// The caller has put the encoded body in `self.response`; this decides between one
    /// APDU and a run of them, which is a decision about the *negotiated PDU size* and
    /// nothing else.
    fn deliver_blocked(
        &mut self,
        invoke_id: InvokeId,
        service: Outbound,
        len: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        let required = match service {
            Outbound::Get => Conformance::BLOCK_TRANSFER_WITH_GET_OR_READ,
            Outbound::Action => Conformance::BLOCK_TRANSFER_WITH_ACTION,
        };
        if self.negotiated.require(required).is_err() {
            // The value exists and the client may read it; there is simply no way to
            // deliver it under what was negotiated.
            self.transfer = Transfer::Idle;
            return match service {
                Outbound::Get => self.get_error(invoke_id, DataAccessResult::DataBlockUnavailable, out),
                Outbound::Action => self.action_error(invoke_id, ActionResult::DataBlockUnavailable, out),
            };
        }
        self.transfer = Transfer::Sending { invoke_id, service, len, sent: 0, block: 0 };
        self.send_next_block(out)
    }

    fn audit_read(&mut self, descriptor: &crate::xdlms::AttributeDescriptor, outcome: DataAccessResult) {
        self.store.audit(AuditEvent::AttributeRead {
            class_id: descriptor.class_id,
            logical_name: descriptor.instance_id,
            attribute_id: descriptor.attribute_id,
            outcome,
        });
    }

    /// What protection adds to an APDU under the current policy.
    const fn protection_overhead(&self) -> usize {
        if self.config.security.is_none() { 0 } else { PROTECTION_MAX }
    }

    /// The largest fragment a `get-response-with-datablock` can carry to this client.
    ///
    /// Deliberately conservative: every header field is counted at its longest. A few
    /// wasted bytes per block cost a block on a very long transfer; a fragment computed
    /// one byte too large is a reply the client cannot receive, discovered in the field.
    /// `check_fits` catches the second case regardless.
    fn max_fragment(&self) -> usize {
        usize::from(self.client_max_pdu_size)
            .saturating_sub(BLOCK_HEADER_MAX)
            .saturating_sub(self.protection_overhead())
            .min(N)
    }

    fn get_error(&mut self, invoke_id: InvokeId, e: DataAccessResult, out: &mut [u8]) -> Result<usize> {
        let response = GetResponse::Normal { invoke_id, result: GetDataResult::Error(e) };
        self.send(&Apdu::GetResponse(response), out)
    }

    fn action_error(&mut self, invoke_id: InvokeId, e: ActionResult, out: &mut [u8]) -> Result<usize> {
        let response = ActionResponse::Normal {
            invoke_id,
            response: ActionResponseWithOptionalData { result: e, return_parameters: None },
        };
        self.send(&Apdu::ActionResponse(response), out)
    }

    fn handle_set(&mut self, req: SetRequest<'_>, out: &mut [u8]) -> Result<usize> {
        if self.state != ServerState::Associated {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }
        if self.negotiated.require(Conformance::SET).is_err() {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        }
        match req {
            SetRequest::Normal { invoke_id, descriptor, access, value } => {
                self.transfer = Transfer::Idle;
                let result = Self::write_one(&mut self.store, descriptor, access, value);
                self.send(&Apdu::SetResponse(SetResponse::Normal { invoke_id, result }), out)
            }
            SetRequest::WithFirstDataBlock { invoke_id, descriptor, access, block } => {
                self.begin_blocked_set(invoke_id, descriptor, access, &block, out)
            }
            SetRequest::WithDataBlock { invoke_id, block } => {
                self.continue_blocked_set(invoke_id, &block, out)
            }
            SetRequest::WithList { invoke_id, descriptors, values } => {
                self.handle_set_with_list(invoke_id, &descriptors, &values, out)
            }
            SetRequest::WithListAndFirstDataBlock { invoke_id, descriptors, block } => {
                self.begin_blocked_list_set(invoke_id, &descriptors, &block, out)
            }
        }
    }

    /// Perform one write, enforcing access rights and recording the outcome.
    ///
    /// Takes the store rather than the whole server, because the value being written may
    /// be borrowed out of the server's own reassembly buffer — a blocked SET is exactly
    /// that case — and `&mut self` would conflict with it. Naming the field keeps the
    /// two borrows disjoint instead of forcing a copy of the value.
    fn write_one(
        store: &mut S,
        descriptor: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
        value: Data<'_>,
    ) -> DataAccessResult {
        let rights =
            store.attribute_access(descriptor.class_id, descriptor.instance_id, descriptor.attribute_id);
        let result = if rights.can_write() {
            match store.set_attribute(
                descriptor.class_id,
                descriptor.instance_id,
                descriptor.attribute_id,
                access,
                value,
            ) {
                Ok(()) => DataAccessResult::Success,
                Err(e) => e,
            }
        } else {
            DataAccessResult::ReadWriteDenied
        };
        store.audit(AuditEvent::AttributeWritten {
            class_id: descriptor.class_id,
            logical_name: descriptor.instance_id,
            attribute_id: descriptor.attribute_id,
            outcome: result,
        });
        result
    }

    /// Write several attributes in one exchange, one result each.
    fn handle_set_with_list(
        &mut self,
        invoke_id: InvokeId,
        descriptors: &List<'_, crate::xdlms::AttributeDescriptorWithSelection<'_>>,
        values: &List<'_, Data<'_>>,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.negotiated.require(Conformance::MULTIPLE_REFERENCES).is_err() {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        }
        // One value per descriptor. A request where the two lists disagree names a write
        // nobody can carry out: pairing what is there and guessing at the rest is how a
        // meter ends up writing one attribute's value into another.
        if descriptors.len() != values.len() {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }
        self.transfer = Transfer::Idle;

        let mut results = [0u8; N];
        let mut rw = SliceWriter::new(&mut results);
        let mut count = 0usize;
        for (item, value) in descriptors.iter().zip(values.iter()) {
            let item = item?;
            let value = value?;
            let result = Self::write_one(&mut self.store, item.descriptor, item.access, value);
            rw.write_u8(result.as_u8())?;
            count += 1;
        }
        let n = rw.written();
        let response = SetResponse::WithList {
            invoke_id,
            results: List::from_raw(count, results.get(..n).unwrap_or(&[])),
        };
        self.send(&Apdu::SetResponse(response), out)
    }

    /// The first block of a value too large for one APDU.
    fn begin_blocked_set(
        &mut self,
        invoke_id: InvokeId,
        descriptor: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
        block: &DataBlockSA<'_>,
        out: &mut [u8],
    ) -> Result<usize> {
        self.transfer = Transfer::Idle;
        if self.negotiated.require(Conformance::BLOCK_TRANSFER_WITH_SET_OR_WRITE).is_err() {
            return self.set_error(invoke_id, DataAccessResult::DataBlockUnavailable, out);
        }
        // Rights are checked now rather than when the last block lands: a client with no
        // write access should not be able to make the server hold a buffer for it.
        let rights =
            self.store.attribute_access(descriptor.class_id, descriptor.instance_id, descriptor.attribute_id);
        if !rights.can_write() {
            self.store.audit(AuditEvent::AttributeWritten {
                class_id: descriptor.class_id,
                logical_name: descriptor.instance_id,
                attribute_id: descriptor.attribute_id,
                outcome: DataAccessResult::ReadWriteDenied,
            });
            return self.set_last_block(
                invoke_id,
                DataAccessResult::ReadWriteDenied,
                block.block_number,
                out,
            );
        }

        // The selective-access descriptor has to survive from here to the last block, so
        // it is re-encoded at the front of the buffer the value accumulates in. Nothing
        // else in the server outlives a single `handle` call.
        let access_end = match access {
            None => 0,
            Some(sa) => {
                let mut w = SliceWriter::new(&mut self.response);
                sa.encode(&mut w)?;
                w.written()
            }
        };
        self.transfer = Transfer::ReceivingSet {
            invoke_id,
            descriptor,
            list: false,
            header_end: access_end,
            len: 0,
            block: 0,
        };
        self.continue_blocked_set(invoke_id, block, out)
    }

    /// The first block of a *batched* write whose values are too large for one APDU.
    ///
    /// The attribute list arrives with the first block and is needed at the last, so it
    /// is re-encoded at the front of the same buffer the values accumulate in — the same
    /// trick a single write uses for its selector, and for the same reason: nothing else
    /// in the server outlives one `handle` call.
    ///
    /// What the blocks carry is the encoded `value-list` field, count prefix included —
    /// a blocked request carries the body of whichever request form it is, which is the
    /// rule the blocked *response* already follows.
    fn begin_blocked_list_set(
        &mut self,
        invoke_id: InvokeId,
        descriptors: &List<'_, crate::xdlms::AttributeDescriptorWithSelection<'_>>,
        block: &DataBlockSA<'_>,
        out: &mut [u8],
    ) -> Result<usize> {
        self.transfer = Transfer::Idle;
        if self.negotiated.require(Conformance::MULTIPLE_REFERENCES).is_err()
            || self.negotiated.require(Conformance::BLOCK_TRANSFER_WITH_SET_OR_WRITE).is_err()
        {
            return self.set_error(invoke_id, DataAccessResult::DataBlockUnavailable, out);
        }
        if descriptors.len() > MAX_ACCESS_ITEMS {
            return self.set_error(invoke_id, DataAccessResult::OtherReason, out);
        }
        let header_end = {
            let mut w = SliceWriter::new(&mut self.response);
            descriptors.encode(&mut w)?;
            w.written()
        };
        self.transfer = Transfer::ReceivingSet {
            invoke_id,
            // Unused for a list write; the descriptors are in the buffer.
            descriptor: AttributeDescriptor::new(0, Obis::new(0, 0, 0, 0, 0, 0), 0),
            list: true,
            header_end,
            len: 0,
            block: 0,
        };
        self.continue_blocked_set(invoke_id, block, out)
    }

    /// A further block of a long SET — and the first one too, which is the same work.
    fn continue_blocked_set(
        &mut self,
        invoke_id: InvokeId,
        block: &DataBlockSA<'_>,
        out: &mut [u8],
    ) -> Result<usize> {
        let Transfer::ReceivingSet { invoke_id: id, descriptor, list, header_end, len, block: last } =
            self.transfer
        else {
            return self.set_error(invoke_id, DataAccessResult::NoLongSetInProgress, out);
        };
        // Blocks must arrive in order under the invoke id the transfer opened with. A
        // fragment concatenated in the wrong place usually still decodes, into a value
        // that is simply wrong — and this one is a *write*.
        if invoke_id != id || block.block_number != last.saturating_add(1) {
            self.transfer = Transfer::Idle;
            return self.set_error(invoke_id, DataAccessResult::DataBlockNumberInvalid, out);
        }

        let at = header_end.saturating_add(len);
        let end = at.saturating_add(block.raw_data.len());
        let Some(slot) = self.response.get_mut(at..end) else {
            self.transfer = Transfer::Idle;
            return self.set_error(invoke_id, DataAccessResult::LongSetAborted, out);
        };
        slot.copy_from_slice(block.raw_data);
        let len = len.saturating_add(block.raw_data.len());

        if !block.last_block {
            self.transfer = Transfer::ReceivingSet {
                invoke_id,
                descriptor,
                list,
                header_end,
                len,
                block: block.block_number,
            };
            let response = SetResponse::DataBlock { invoke_id, block_number: block.block_number };
            return self.send(&Apdu::SetResponse(response), out);
        }

        self.transfer = Transfer::Idle;
        // Decoding happens once, over the concatenation: a fragment boundary falls
        // wherever the client's buffer ran out, which is very often inside a length
        // prefix, so no fragment is decodable on its own.
        if list {
            return self.finish_blocked_list_set(invoke_id, header_end, len, block.block_number, out);
        }
        // The stored descriptor is re-decoded rather than kept as a borrowed value,
        // because it was encoded into the same buffer the value accumulated in.
        let selective = if header_end == 0 {
            None
        } else {
            Some(SelectiveAccess::from_bytes(self.response.get(..header_end).unwrap_or(&[]))?)
        };
        let result = {
            let bytes = self.response.get(header_end..header_end.saturating_add(len)).unwrap_or(&[]);
            let value = Data::from_bytes_in(bytes)?;
            Self::write_one(&mut self.store, descriptor, selective, value)
        };
        self.set_last_block(invoke_id, result, block.block_number, out)
    }

    /// The last block of a batched write: pair the stored attribute list with the
    /// reassembled value list and answer with one result per attribute.
    fn finish_blocked_list_set(
        &mut self,
        invoke_id: InvokeId,
        header_end: usize,
        len: usize,
        block_number: u32,
        out: &mut [u8],
    ) -> Result<usize> {
        let mut results = [0u8; MAX_ACCESS_ITEMS];
        let mut rw = SliceWriter::new(&mut results);
        let count = {
            let header = self.response.get(..header_end).unwrap_or(&[]);
            let values_bytes = self.response.get(header_end..header_end.saturating_add(len)).unwrap_or(&[]);
            let descriptors: List<'_, crate::xdlms::AttributeDescriptorWithSelection<'_>> =
                List::from_bytes(header)?;
            let values: List<'_, Data<'_>> = List::from_bytes(values_bytes)?;
            if descriptors.len() != values.len() {
                // The two lists were sent by the same client in the same invocation, so
                // this is not an attack — it is a request that names writes whose values
                // cannot be found, and pairing what is there would write the wrong value
                // to the wrong object.
                self.transfer = Transfer::Idle;
                return self.set_error(invoke_id, DataAccessResult::TypeUnmatched, out);
            }
            let mut count = 0usize;
            for (item, value) in descriptors.iter().zip(values.iter()) {
                let item = item?;
                let value = value?;
                let result = Self::write_one(&mut self.store, item.descriptor, item.access, value);
                rw.write_u8(result.as_u8())?;
                count += 1;
            }
            count
        };
        let n = rw.written();
        let response = SetResponse::LastDataBlockWithList {
            invoke_id,
            results: List::from_raw(count, results.get(..n).unwrap_or(&[])),
            block_number,
        };
        self.send(&Apdu::SetResponse(response), out)
    }

    fn set_error(&mut self, invoke_id: InvokeId, e: DataAccessResult, out: &mut [u8]) -> Result<usize> {
        self.send(&Apdu::SetResponse(SetResponse::Normal { invoke_id, result: e }), out)
    }

    fn set_last_block(
        &mut self,
        invoke_id: InvokeId,
        result: DataAccessResult,
        block_number: u32,
        out: &mut [u8],
    ) -> Result<usize> {
        let response = SetResponse::LastDataBlock { invoke_id, result, block_number };
        self.send(&Apdu::SetResponse(response), out)
    }

    fn handle_action(&mut self, req: ActionRequest<'_>, out: &mut [u8]) -> Result<usize> {
        // The one method that is legal before the association is open: the reply to the
        // server's high-level-security challenge.
        if self.state == ServerState::AwaitingHlsReply {
            let ActionRequest::Normal { invoke_id, descriptor, parameters } = req else {
                return self.exception(
                    StateError::ServiceNotAllowed,
                    ServiceError::OperationNotPossible,
                    out,
                );
            };
            return self.handle_hls_reply(invoke_id, descriptor, parameters, out);
        }
        if self.state != ServerState::Associated {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }
        if self.negotiated.require(Conformance::ACTION).is_err() {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        }

        match req {
            ActionRequest::Normal { invoke_id, descriptor, parameters } => {
                self.transfer = Transfer::Idle;
                self.invoke_and_answer(invoke_id, descriptor, parameters, out)
            }
            ActionRequest::NextPblock { invoke_id, block_number } => {
                self.handle_action_next(invoke_id, block_number, out)
            }
            ActionRequest::WithFirstPblock { invoke_id, descriptor, block } => {
                self.transfer = Transfer::Idle;
                if self.negotiated.require(Conformance::BLOCK_TRANSFER_WITH_ACTION).is_err() {
                    return self.action_error(invoke_id, ActionResult::DataBlockUnavailable, out);
                }
                self.transfer = Transfer::ReceivingAction { invoke_id, descriptor, len: 0, block: 0 };
                self.continue_blocked_action(invoke_id, &block, out)
            }
            ActionRequest::WithPblock { invoke_id, block } => {
                self.continue_blocked_action(invoke_id, &block, out)
            }
            ActionRequest::WithList { invoke_id, descriptors, parameters } => {
                self.handle_action_with_list(invoke_id, &descriptors, &parameters, out)
            }
            // A batch of methods whose *parameters* are themselves too large for one
            // APDU. Nothing in the field does this, and it would need the method list
            // held across blocks alongside a parameter list whose division between the
            // methods is not stated anywhere this project can read. Saying so beats
            // invoking the first method of a batch and guessing at the rest.
            ActionRequest::WithListAndFirstPblock { .. } => {
                self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out)
            }
        }
    }

    /// Invoke several methods in one exchange, one result each.
    ///
    /// Like the batched read and the batched write, the point is per-item isolation: a
    /// method that refuses occupies its own slot and the others still run. That matters
    /// more here than for a read — a batch that opened a breaker and then failed would
    /// otherwise report only the failure.
    fn handle_action_with_list(
        &mut self,
        invoke_id: InvokeId,
        descriptors: &List<'_, MethodDescriptor>,
        parameters: &List<'_, Data<'_>>,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.negotiated.require(Conformance::MULTIPLE_REFERENCES).is_err() {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        }
        // One parameter entry per method, `null-data` for a method that takes none —
        // the same positional rule the ACCESS service uses, and for the same reason.
        if descriptors.len() != parameters.len() || descriptors.len() > MAX_ACCESS_ITEMS {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }
        self.transfer = Transfer::Idle;

        let mut responses = [0u8; N];
        let mut rw = SliceWriter::new(&mut responses);
        let mut count = 0usize;
        for (descriptor, parameter) in descriptors.iter().zip(parameters.iter()) {
            let descriptor = descriptor?;
            let parameter = parameter?;
            let parameter = (!matches!(parameter, Data::Null)).then_some(parameter);

            // `action-response-with-optional-data` is the result byte, an optional-usage
            // flag, and — when there is a return value — a `get-data-result` choice. The
            // store writes straight after the choice byte so a large return value never
            // exists twice.
            let before = rw.written();
            rw.write_u8(ActionResult::Success.as_u8())?;
            rw.write_u8(1)?;
            rw.write_u8(0)?;
            let value_at = rw.written();
            let outcome = Self::run_method(&mut self.store, descriptor, parameter, &mut rw);
            match outcome {
                // A method that reports a return value and writes none would leave a
                // `get-data-result` choice with nothing behind it: malformed rather than
                // wrong, and unattributable at the other end.
                Ok(true) if rw.written() == value_at => {
                    rw.truncate(before)?;
                    rw.write_u8(ActionResult::OtherReason.as_u8())?;
                    rw.write_u8(0)?;
                }
                Ok(true) => {}
                Ok(false) => {
                    // Success with nothing returned: rewind over the optional fields.
                    rw.truncate(before)?;
                    rw.write_u8(ActionResult::Success.as_u8())?;
                    rw.write_u8(0)?;
                }
                Err(e) => {
                    rw.truncate(before)?;
                    rw.write_u8(e.as_u8())?;
                    rw.write_u8(0)?;
                }
            }
            count += 1;
        }
        let n = rw.written();
        let response = ActionResponse::WithList {
            invoke_id,
            responses: List::from_raw(count, responses.get(..n).unwrap_or(&[])),
        };
        self.send(&Apdu::ActionResponse(response), out)
    }

    /// A further block of a long ACTION parameter.
    fn continue_blocked_action(
        &mut self,
        invoke_id: InvokeId,
        block: &DataBlockSA<'_>,
        out: &mut [u8],
    ) -> Result<usize> {
        let Transfer::ReceivingAction { invoke_id: id, descriptor, len, block: last } = self.transfer else {
            return self.action_error(invoke_id, ActionResult::NoLongActionInProgress, out);
        };
        if invoke_id != id || block.block_number != last.saturating_add(1) {
            self.transfer = Transfer::Idle;
            return self.action_error(invoke_id, ActionResult::DataBlockUnavailable, out);
        }

        let end = len.saturating_add(block.raw_data.len());
        let Some(slot) = self.response.get_mut(len..end) else {
            self.transfer = Transfer::Idle;
            return self.action_error(invoke_id, ActionResult::LongActionAborted, out);
        };
        slot.copy_from_slice(block.raw_data);

        if !block.last_block {
            self.transfer =
                Transfer::ReceivingAction { invoke_id, descriptor, len: end, block: block.block_number };
            // The acknowledgement of a parameter block is `action-response-next-pblock`
            // carrying the number just received; there is no separate ack form.
            let response = ActionResponse::NextPblock { invoke_id, block_number: block.block_number };
            return self.send(&Apdu::ActionResponse(response), out);
        }

        self.transfer = Transfer::Idle;
        // The parameter borrows the reassembly buffer and building the reply needs the
        // rest of the server, so the invocation happens in a scope of its own: the
        // borrow ends with it and nothing is copied.
        let mut value = [0u8; N];
        let mut vw = SliceWriter::new(&mut value);
        let outcome = {
            let bytes = self.response.get(..end).unwrap_or(&[]);
            let parameters = Data::from_bytes_in(bytes)?;
            Self::run_method(&mut self.store, descriptor, Some(parameters), &mut vw)
        };
        let n = vw.written();
        self.answer_method(invoke_id, outcome, value.get(..n).unwrap_or(&[]), out)
    }

    /// Invoke a method, then deliver whatever it returned — in one APDU or in blocks.
    fn invoke_and_answer(
        &mut self,
        invoke_id: InvokeId,
        descriptor: MethodDescriptor,
        parameters: Option<Data<'_>>,
        out: &mut [u8],
    ) -> Result<usize> {
        let mut value = [0u8; N];
        let mut vw = SliceWriter::new(&mut value);
        let outcome = Self::run_method(&mut self.store, descriptor, parameters, &mut vw);
        let n = vw.written();
        self.answer_method(invoke_id, outcome, value.get(..n).unwrap_or(&[]), out)
    }

    /// Check the rights, invoke, and record — the half that touches only the store, so a
    /// parameter borrowed out of the reassembly buffer does not conflict with it.
    fn run_method(
        store: &mut S,
        descriptor: MethodDescriptor,
        parameters: Option<Data<'_>>,
        w: &mut SliceWriter<'_>,
    ) -> core::result::Result<bool, ActionResult> {
        let rights = store.method_access(descriptor.class_id, descriptor.instance_id, descriptor.method_id);
        let outcome = if rights.can_invoke() {
            store.invoke_method(
                descriptor.class_id,
                descriptor.instance_id,
                descriptor.method_id,
                parameters,
                w,
            )
        } else {
            Err(ActionResult::ReadWriteDenied)
        };
        store.audit(AuditEvent::MethodInvoked {
            class_id: descriptor.class_id,
            logical_name: descriptor.instance_id,
            method_id: descriptor.method_id,
            outcome: outcome.as_ref().err().copied().unwrap_or(ActionResult::Success),
        });
        outcome
    }

    /// Turn a method's outcome into a reply, segmenting a long return value.
    fn answer_method(
        &mut self,
        invoke_id: InvokeId,
        outcome: core::result::Result<bool, ActionResult>,
        value: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let returned = match outcome {
            Ok(returned) => returned,
            Err(e) => return self.action_error(invoke_id, e, out),
        };
        if !returned {
            let response = ActionResponse::Normal {
                invoke_id,
                response: ActionResponseWithOptionalData {
                    result: ActionResult::Success,
                    return_parameters: None,
                },
            };
            return self.send(&Apdu::ActionResponse(response), out);
        }
        if value.is_empty() {
            // The store said it returned something and wrote nothing. That is its bug,
            // and the honest answer is a refusal this method can name rather than a
            // transport error the caller has to invent a reply for.
            return self.action_error(invoke_id, ActionResult::OtherReason, out);
        }

        // A return value large enough to need segmenting is rare but real — an image
        // block read back, a certificate exported — and a method that silently could not
        // answer would be worse than one that says so.
        let n = value.len();
        if n + ACTION_HEADER_MAX + self.protection_overhead() <= usize::from(self.client_max_pdu_size) {
            let response = ActionResponse::Normal {
                invoke_id,
                response: ActionResponseWithOptionalData {
                    result: ActionResult::Success,
                    return_parameters: Some(GetDataResult::Data(Data::from_bytes_in(value)?)),
                },
            };
            return self.send(&Apdu::ActionResponse(response), out);
        }
        self.response
            .get_mut(..n)
            .ok_or(Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))?
            .copy_from_slice(value);
        self.deliver_blocked(invoke_id, Outbound::Action, n, out)
    }

    /// The ACCESS service: reads, writes and method invocations in one exchange.
    ///
    /// This is the service a battery-powered meter on a low-power network uses, because
    /// the cost there is round trips rather than bytes. It has no ciphered tag of its
    /// own, so in a protected association it can only travel inside
    /// `general-glo-ciphering` — which is what the `general-protection` conformance bit
    /// is for, and why this service and that bit are refused together.
    ///
    /// The request's data list runs **one element per specification entry**, in order: a
    /// SET or ACTION entry consumes its value from that position, and a GET entry has
    /// `null-data` there. The response is built the same way, so the three lists line up
    /// by position and a client never has to count which entries produced data. This
    /// positional rule is the convention the second sources use; the clause that states
    /// it is outside the excerpts this crate was built from.
    fn handle_access(&mut self, req: &AccessRequest<'_>, out: &mut [u8]) -> Result<usize> {
        if self.state != ServerState::Associated {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }
        if self.negotiated.require(Conformance::ACCESS).is_err() {
            return self.exception(StateError::ServiceUnknown, ServiceError::ServiceNotSupported, out);
        }
        // One data entry per specification entry — that is the whole alignment rule, and
        // a request where the two lists disagree names operations whose values cannot be
        // found. Pairing what is there and guessing at the rest is how a meter writes one
        // attribute's value into another.
        if req.specification.len() != req.data.len() {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        }
        if req.specification.len() > MAX_ACCESS_ITEMS {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::PduTooLong, out);
        }
        self.transfer = Transfer::Idle;

        // Two lists are produced side by side: the values, and one outcome per entry.
        // They interleave on neither side, so they are built separately — the values into
        // an `N`-sized buffer because a read can produce anything, the outcomes into a
        // small one because they are two bytes each and the count is bounded above.
        let mut data = [0u8; N];
        let mut dw = SliceWriter::new(&mut data);
        let mut results = [0u8; MAX_ACCESS_ITEMS * 2];
        let mut rw = SliceWriter::new(&mut results);
        let mut count = 0usize;

        for (spec, value) in req.specification.iter().zip(req.data.iter()) {
            let spec = spec?;
            let value = value?;
            let outcome = match spec {
                AccessRequestSpecification::Get(d) | AccessRequestSpecification::Set(d) => self.access_one(
                    d,
                    None,
                    value,
                    matches!(spec, AccessRequestSpecification::Get(_)),
                    &mut dw,
                ),
                AccessRequestSpecification::GetWithSelection(d) => {
                    self.access_one(d.descriptor, d.access, value, true, &mut dw)
                }
                AccessRequestSpecification::SetWithSelection(d) => {
                    self.access_one(d.descriptor, d.access, value, false, &mut dw)
                }
                AccessRequestSpecification::Action(d) => {
                    // A method's parameter is the data-list entry at its position, and
                    // `null-data` there means the method takes none.
                    let parameters = (!matches!(value, Data::Null)).then_some(value);
                    let before = dw.written();
                    let outcome = Self::run_method(&mut self.store, d, parameters, &mut dw);
                    match outcome {
                        Ok(true) => AccessResponseSpecification::Action(ActionResult::Success),
                        Ok(false) => {
                            // Nothing returned, but the lists stay aligned by position.
                            Data::Null.encode(&mut dw)?;
                            AccessResponseSpecification::Action(ActionResult::Success)
                        }
                        Err(e) => {
                            dw.truncate(before)?;
                            Data::Null.encode(&mut dw)?;
                            AccessResponseSpecification::Action(e)
                        }
                    }
                }
            };
            outcome.encode(&mut rw)?;
            count += 1;
        }

        let dn = dw.written();
        let rn = rw.written();
        let response = AccessResponse {
            long_invoke_id: req.long_invoke_id,
            // The response's date-time is the *server's*, and this crate has no clock —
            // echoing the client's back would be a timestamp attributed to the wrong
            // party. The field is an octet string that may be empty, so absent is
            // sayable and is the honest answer.
            date_time: crate::xdlms::OptionalDateTime(None),
            // Echoing the request's specification list back is optional and costs a copy
            // of it; the response is already positional, so it buys nothing.
            request_specification: None,
            data: List::from_raw(count, data.get(..dn).unwrap_or(&[])),
            response_specification: List::from_raw(count, results.get(..rn).unwrap_or(&[])),
        };
        self.send(&Apdu::AccessResponse(response), out)
    }

    /// One read or write inside an ACCESS request, appending its value to the data list.
    fn access_one(
        &mut self,
        descriptor: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
        value: Data<'_>,
        is_get: bool,
        dw: &mut SliceWriter<'_>,
    ) -> AccessResponseSpecification {
        if !is_get {
            let result = Self::write_one(&mut self.store, descriptor, access, value);
            // A write produces no value, and the lists are positional.
            if Data::Null.encode(dw).is_err() {
                return AccessResponseSpecification::Set(DataAccessResult::OtherReason);
            }
            return AccessResponseSpecification::Set(result);
        }

        let rights =
            self.store.attribute_access(descriptor.class_id, descriptor.instance_id, descriptor.attribute_id);
        let before = dw.written();
        let outcome = if rights.can_read() {
            match self.store.get_attribute(
                descriptor.class_id,
                descriptor.instance_id,
                descriptor.attribute_id,
                access,
                dw,
            ) {
                // Success with nothing written leaves a hole in a positional list, which
                // shifts every value after it onto the wrong operation.
                Ok(()) if dw.written() == before => DataAccessResult::OtherReason,
                Ok(()) => DataAccessResult::Success,
                Err(e) => e,
            }
        } else {
            DataAccessResult::ReadWriteDenied
        };
        if outcome != DataAccessResult::Success {
            // Roll back whatever the store managed to write and keep the position.
            if dw.truncate(before).is_err() || Data::Null.encode(dw).is_err() {
                return AccessResponseSpecification::Get(DataAccessResult::OtherReason);
            }
        }
        self.audit_read(&descriptor, outcome);
        AccessResponseSpecification::Get(outcome)
    }

    fn handle_hls_reply(
        &mut self,
        invoke_id: InvokeId,
        descriptor: crate::xdlms::MethodDescriptor,
        parameters: Option<Data<'_>>,
        out: &mut [u8],
    ) -> Result<usize> {
        let is_reply = descriptor.class_id == 15 && descriptor.method_id == 1;
        let proof = parameters.and_then(|p| p.as_bytes());
        let Some((true, Some(proof))) = Some((is_reply, proof)) else {
            return self.exception(StateError::ServiceNotAllowed, ServiceError::OperationNotPossible, out);
        };
        let peer = self.client_system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        let auth_key = self.auth_key()?;
        let verified = self
            .protector
            .verify_hls_gmac(&peer, auth_key, &self.server_challenge[..self.server_challenge_len], proof)
            .is_ok();
        if !verified {
            self.state = ServerState::Closed;
            let response = ActionResponse::Normal {
                invoke_id,
                response: ActionResponseWithOptionalData {
                    result: ActionResult::ReadWriteDenied,
                    return_parameters: None,
                },
            };
            return self.send(&Apdu::ActionResponse(response), out);
        }

        let title = self.config.system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?;
        let ic = self.next_counter()?;
        let mut reply = [0u8; 17];
        let auth_key = self.auth_key()?;
        self.protector.hls_gmac_response(
            &title,
            ic,
            auth_key,
            &self.client_challenge[..self.client_challenge_len],
            &mut reply,
        )?;
        self.state = ServerState::Associated;
        let response = ActionResponse::Normal {
            invoke_id,
            response: ActionResponseWithOptionalData {
                result: ActionResult::Success,
                return_parameters: Some(GetDataResult::Data(Data::OctetString(&reply))),
            },
        };
        self.send(&Apdu::ActionResponse(response), out)
    }

    fn refuse(
        &mut self,
        result: AssociationResult,
        diagnostic: UserDiagnostic,
        out: &mut [u8],
    ) -> Result<usize> {
        self.state = ServerState::Closed;
        self.store.audit(AuditEvent::AssociationRefused { diagnostic });
        // The refusal names the context the *client* asked for, not the one the server
        // would have preferred. A client checks that the answer is about what it
        // proposed, and one that reads "logical name, plain" in response to a request
        // for a ciphered association cannot tell a refusal from a downgrade attempt.
        let context = if self.ciphered_association {
            ApplicationContext::LogicalNameCiphered
        } else {
            ApplicationContext::LogicalName
        };
        let aare = Aare {
            application_context: Some(context),
            result,
            diagnostic: Diagnostic::User(diagnostic),
            responding_ap_title: self.config.system_title.as_ref().map(|t| &t.0[..]),
            ..Default::default()
        };
        let mut w = SliceWriter::new(out);
        aare.encode(&mut w)?;
        Ok(w.written())
    }

    /// Refuse an APDU outright, protecting the refusal when the association can.
    ///
    /// `exception-response` has no ciphered tag, so protecting one means
    /// `general-glo-ciphering` and therefore the `general-protection` conformance bit.
    /// When it was negotiated the refusal is authenticated like every other reply, and a
    /// client can tell the server's diagnostic from one an on-path attacker injected;
    /// when it was not, there is no way to protect it and it goes out bare, which is what
    /// the client is prepared to accept for exactly this reason.
    ///
    /// Protecting it spends an invocation counter, so a peer that floods malformed APDUs
    /// consumes counter space. That is true of any protected reply and is bounded by the
    /// same 2³² ceiling; refusing to answer at all would be the larger problem.
    fn exception(
        &mut self,
        state_error: StateError,
        service_error: ServiceError,
        out: &mut [u8],
    ) -> Result<usize> {
        let apdu = Apdu::ExceptionResponse(ExceptionResponse {
            state_error,
            service_error,
            expected_invocation_counter: None,
        });
        if self.config.security.is_none() || !self.negotiated.contains(Conformance::GENERAL_PROTECTION) {
            let mut w = SliceWriter::new(out);
            apdu.encode(&mut w)?;
            return Ok(w.written());
        }
        self.send(&apdu, out)
    }

    fn send(&mut self, apdu: &Apdu<'_>, out: &mut [u8]) -> Result<usize> {
        let mut w = SliceWriter::new(&mut self.scratch);
        apdu.encode(&mut w)?;
        let plain_len = w.written();

        if self.config.security.is_none() {
            self.check_fits(plain_len)?;
            let mut w = SliceWriter::new(out);
            w.write_bytes(self.scratch.get(..plain_len).unwrap_or(&[]))?;
            return Ok(w.written());
        }

        let ctx = Outgoing {
            system_title: self.config.system_title.ok_or(Error::new(ErrorKind::UnexpectedMessage, 0))?,
            invocation_counter: self.invocation_counter.next()?,
            auth_key: self.protector.auth_key(),
            policy: self.protector.policy(),
            general_allowed: self.negotiated.contains(Conformance::GENERAL_PROTECTION),
        };
        let mut body = [0u8; N];
        let plain = self.scratch.get(..plain_len).unwrap_or(&[]);
        let n = protect_apdu(&self.protector, &ctx, plain, &mut body, out)?;
        self.check_fits(n)?;
        Ok(n)
    }

    /// Refuse to emit a reply the client has said it cannot receive.
    ///
    /// A GET whose value is too large is segmented long before it reaches here, so this
    /// is the backstop rather than the mechanism: it catches a fragment size computed
    /// wrongly, and a response of a kind that has no segmentation (a SET result that
    /// overflows). Erring is the honest answer in both cases — the alternative is
    /// transmitting something the peer will drop.
    fn check_fits(&self, len: usize) -> Result<()> {
        if len > usize::from(self.client_max_pdu_size) {
            return Err(Error::new(
                ErrorKind::BufferTooSmall { needed: len - usize::from(self.client_max_pdu_size) },
                0,
            ));
        }
        Ok(())
    }

    fn unprotect_into<'b>(&mut self, apdu: &[u8], buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let ctx = Incoming {
            peer: self.client_system_title,
            auth_key: self.protector.auth_key(),
            policy: self.protector.policy(),
            plain_allowed: PLAIN_FROM_CLIENT,
        };
        unprotect_apdu(&self.protector, &ctx, &mut self.peer_replay, apdu, buf)
    }

    /// Remove protection from the AARQ's user information, which is protected with the
    /// global key set even when the association will go on to use a dedicated one — the
    /// dedicated key is what this very message delivers.
    fn unprotect_initiate<'b>(&mut self, apdu: &[u8], buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let ctx = Incoming {
            peer: self.client_system_title,
            auth_key: self.protector.auth_key(),
            policy: self.config.security.global(),
            plain_allowed: PLAIN_INITIATE,
        };
        unprotect_apdu(&self.protector, &ctx, &mut self.peer_replay, apdu, buf)
    }

    fn auth_key(&self) -> Result<&[u8]> {
        self.protector.auth_key().ok_or(Error::new(ErrorKind::Unsupported, 0))
    }

    fn next_counter(&mut self) -> Result<u32> {
        self.invocation_counter.next()
    }
}

/// The default access a store gives when it does not say otherwise.
pub const DEFAULT_ACCESS: AttributeAccess = AttributeAccess::READ;

/// The logical name of the current association object, which every server hosts.
pub const CURRENT_ASSOCIATION: Obis = Obis::new(0, 0, 40, 0, 0, 255);
