//! A whole association, client against server, in one process.
//!
//! Every one of these runs the real state machines over the real codec: the bytes that
//! cross between them are the bytes that would cross a wire. What they cannot prove is
//! agreement with somebody else's implementation — that is what the interoperability
//! job is for, and it is not this.

mod support;

use dlms_cosem_rs::acse::{AssociationResult, AuthMechanism, Diagnostic, UserDiagnostic};
use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::client::{
    AccessItem, AssociationStep, BlockCollector, ClientConfig, ClientSession, Response, SessionState,
};
use dlms_cosem_rs::codec::{Decode, ErrorKind};
use dlms_cosem_rs::codec::{Encode, Writer};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{
    FixedRandom, Key, KeyRing, RustCryptoProvider, Secret, SecurityPolicy, SecuritySuite, SystemTitle,
};
use dlms_cosem_rs::server::{Server, ServerConfig, ServerState};
use dlms_cosem_rs::xdlms::{
    AccessResponseSpecification, AttributeDescriptor, AttributeDescriptorWithSelection, DataAccessResult,
    GetDataResult, MethodDescriptor,
};
use support::{BREAKER, BROKEN, CLOCK, ENERGY, IMAGE, LOAD_PROFILE, PROFILE_ROWS, SECRET_LOG, TestMeter};

const GUEK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] =
    [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
const DEDICATED: [u8; 16] =
    [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF];
/// Suite 2 is AES-GCM-256, so its keys are twice as long. A ring that could only hold
/// 128-bit keys made the suite unreachable however completely the provider implemented it.
const GUEK_256: [u8; 32] = [0x5A; 32];
const GAK_256: [u8; 32] = [0xA5; 32];
const CLIENT_TITLE: SystemTitle = SystemTitle::new([0x43, 0x4C, 0x49, 0x00, 0x00, 0x00, 0x00, 0x01]);
const SERVER_TITLE: SystemTitle = SystemTitle::new([0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E]);

type Client = ClientSession<RustCryptoProvider<FixedRandom>>;
type Meter = Server<TestMeter, RustCryptoProvider<FixedRandom>>;
/// A server whose buffers are large enough to hold a whole load profile. `N` bounds the
/// largest attribute a server can produce, independently of the PDU size it delivers it
/// in — see [`Server`]'s documentation.
type BigMeter = Server<TestMeter, RustCryptoProvider<FixedRandom>, 4096>;

/// A pair with no protection and no authentication — the public client.
fn plain_pair() -> (Client, Meter) {
    let client = ClientSession::new(
        ClientConfig { client_sap: 0x10, ..Default::default() },
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig::default(),
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );
    (client, server)
}

/// A pair using low level security with a password.
fn lls_pair(client_password: &[u8], server_password: &[u8]) -> (Client, Meter) {
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x20,
            mechanism: AuthMechanism::Low,
            password: Some(Secret::new(client_password).unwrap()),
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig {
            mechanism: AuthMechanism::Low,
            password: Some(Secret::new(server_password).unwrap()),
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );
    (client, server)
}

/// A pair with an authenticated and encrypted association under high level security.
fn ciphered_pair() -> (Client, Meter) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xB2)),
    );
    (client, server)
}

/// The same, for a client that identifies itself as somebody else.
fn ciphered_pair_titled(title: SystemTitle) -> (Client, Meter) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            system_title: Some(title),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xB2)),
    );
    (client, server)
}

/// A ciphered pair that negotiates a **dedicated** key: the client delivers one inside
/// the ciphered InitiateRequest and both ends switch to `ded-` tags afterwards.
fn dedicated_pair() -> (Client, Meter) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0).with_dedicated(true);
    let mut client_keys = KeyRing::new(GUEK, GAK);
    client_keys.set_dedicated(Key::new(DEDICATED));
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(client_keys, FixedRandom(0xA1)),
    );
    // The server configures nothing about the dedicated key: it learns it from the
    // client, which is the only way it can, and switches on its own.
    let server = Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xB2)),
    );
    (client, server)
}

/// A suite-2 pair: AES-GCM-256 keys throughout.
fn suite2_pair() -> (Client, Meter) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite2);
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::new_256(GUEK_256, GAK_256), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new_256(GUEK_256, GAK_256), FixedRandom(0xB2)),
    );
    (client, server)
}

/// A plain pair with a small negotiated PDU size, so an ordinary attribute fits and a
/// load profile cannot.
fn small_pdu_pair() -> (Client, BigMeter) {
    let client = ClientSession::new(
        ClientConfig { client_sap: 0x10, max_pdu_size: 256, ..Default::default() },
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig { max_pdu_size: 256, ..Default::default() },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );
    (client, server)
}

/// A ciphered HLS pair with a small PDU size, so protection overhead has to be counted
/// into the fragment size rather than assumed away.
fn small_pdu_ciphered_pair() -> (Client, BigMeter) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            max_pdu_size: 128,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            max_pdu_size: 128,
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xB2)),
    );
    (client, server)
}

/// Run the whole handshake, however many passes it takes.
fn associate<const N: usize>(
    client: &mut Client,
    server: &mut Server<TestMeter, RustCryptoProvider<FixedRandom>, N>,
) -> AssociationStep {
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.associate_request(&mut c).expect("build AARQ");
    let m = server.handle(&c[..n], &mut s).expect("server handles AARQ");
    let mut step = client.handle_associate_response(&s[..m]).expect("client handles AARE");
    if step == AssociationStep::HlsReplyRequired {
        let n = client.hls_reply_request(&mut c).expect("build HLS reply");
        let m = server.handle(&c[..n], &mut s).expect("server handles HLS reply");
        step = client.handle_hls_reply_response(&s[..m]).expect("client handles HLS result");
    }
    step
}

#[test]
fn a_plain_association_opens_and_reads_a_register() {
    let (mut client, mut server) = plain_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    assert_eq!(client.state(), SessionState::Associated);
    assert_eq!(server.state(), ServerState::Associated);

    let negotiated = client.negotiated().expect("the server answered with an InitiateResponse");
    assert!(negotiated.negotiated_conformance.contains(dlms_cosem_rs::xdlms::Conformance::GET));

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("expected a value, got {other:?}"),
    }
}

#[test]
fn a_ciphered_hls_association_reads_writes_and_invokes() {
    let (mut client, mut server) = ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    assert_eq!(client.server_system_title(), Some(SERVER_TITLE));

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    // Read.
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    assert_ne!(c[0], 0xC0, "a ciphered association must not send a bare get-request");
    assert_eq!(c[0], 0xC8, "it sends glo-get-request");
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(s[0], 0xCC, "and the server answers with glo-get-response");
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("expected a value, got {other:?}"),
    }

    // Write the clock.
    let new_time = dlms_cosem_rs::axdr::DateTime::from_civil(2026, 12, 24, 18, 30, 0, 60);
    let n = client
        .set_request(AttributeDescriptor::new(8, CLOCK, 2), None, Data::DateTime(new_time), &mut c)
        .unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(client.handle_response(&s[..m], &mut plain).unwrap(), Response::Ok);
    assert_eq!(server.store().time, new_time);

    // Open the breaker.
    let n = client.action_request(MethodDescriptor::new(70, BREAKER, 1), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ActionResult { result, .. } => assert!(result.is_success()),
        other => panic!("expected an action result, got {other:?}"),
    }
    assert!(!server.store().breaker_closed);
    assert_eq!(server.store().breaker_operations, 1);
}

#[test]
fn each_protected_apdu_uses_a_fresh_invocation_counter() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let mut counters = alloc_vec();
    for _ in 0..4 {
        let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
        // The counter sits after the tag, the length and the security control byte.
        counters.push(u32::from_be_bytes([c[3], c[4], c[5], c[6]]));
        let m = server.handle(&c[..n], &mut s).unwrap();
        client.handle_response(&s[..m], &mut plain).unwrap();
    }
    for w in counters.windows(2) {
        assert!(w[1] > w[0], "counters must strictly increase: {counters:?}");
    }
}

#[test]
fn a_modified_protected_request_does_not_verify() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    // Flip a bit inside the ciphertext.
    c[n - 1] ^= 0x01;
    let m = server.handle(&c[..n], &mut s).unwrap();
    // The refusal is protected like every other reply — this association negotiated the
    // general wrapper — so it is read through the client rather than off the wire.
    let mut plain = [0u8; 512];
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::DecipheringError);
        }
        other => panic!("expected a deciphering error, got {other:?}"),
    }
}

/// The one that matters for a breaker.
///
/// A recorded ciphered request is a *valid* APDU: it verifies, because it really was
/// sent under the real key. Nothing but the invocation counter distinguishes it from
/// the original, so a server that does not track counters will happily open the breaker
/// again every time somebody replays the frame.
#[test]
fn a_replayed_request_is_refused_by_the_server() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];

    // A real, correctly protected request that the server accepts.
    let mut plain = [0u8; 512];
    let n = client.action_request(MethodDescriptor::new(70, BREAKER, 1), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ActionResult { result, .. } => assert!(result.is_success()),
        other => panic!("the genuine request must be served, got {other:?}"),
    }
    assert_eq!(server.store().breaker_operations, 1);

    // The identical bytes, sent again. The frame verifies perfectly — it really was sent
    // under the real key — so only the invocation counter tells the copy from the
    // original, and the refusal must say so *by name*: a client told "deciphering error"
    // learns nothing it can act on and retries the same frame, while one told
    // "invocation-counter-error" is handed the value to resynchronise to.
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::InvocationCounterError);
            assert_eq!(
                e.expected_invocation_counter,
                server.peer_invocation_counter().map(|c| c + 1),
                "and carries the counter the server will accept next"
            );
        }
        other => panic!("a replayed request must be refused, got {other:?}"),
    }
    assert_eq!(server.store().breaker_operations, 1, "the breaker must not have moved twice");
}

/// And the other direction: a recorded response replayed at the client.
#[test]
fn a_replayed_response_is_refused_by_the_client() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert!(client.handle_response(&s[..m], &mut plain).is_ok());

    // The same response bytes again — a stale reading dressed as a fresh one.
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap_err().kind,
        ErrorKind::Replay,
        "a replayed response must not be reported as a current value"
    );
}

/// A ciphered client must not continue into an association the server answered as
/// something else.
#[test]
fn a_downgraded_aare_is_refused() {
    use dlms_cosem_rs::acse::{Aare, ApplicationContext};
    use dlms_cosem_rs::codec::{Encode, SliceWriter, Writer};

    let (mut client, _server) = ciphered_pair();
    let mut c = [0u8; 512];
    client.associate_request(&mut c).unwrap();

    // The server says yes — to a plain, unauthenticated association instead.
    let aare = Aare {
        application_context: Some(ApplicationContext::LogicalName),
        result: AssociationResult::Accepted,
        diagnostic: Diagnostic::User(UserDiagnostic::Null),
        responding_ap_title: Some(SERVER_TITLE.as_bytes()),
        ..Default::default()
    };
    let mut s = [0u8; 512];
    let mut w = SliceWriter::new(&mut s);
    aare.encode(&mut w).unwrap();
    let m = w.written();

    match client.handle_associate_response(&s[..m]).unwrap() {
        AssociationStep::Rejected { diagnostic, .. } => assert_eq!(
            diagnostic,
            Diagnostic::User(UserDiagnostic::ApplicationContextNameNotSupported),
            "the client asked for a ciphered context and must not accept a plain one"
        ),
        other => panic!("a downgraded context must be refused, got {other:?}"),
    }
    assert_eq!(client.state(), SessionState::Closed);
}

/// The same, for the authentication mechanism.
#[test]
fn an_aare_that_drops_the_authentication_mechanism_is_refused() {
    use dlms_cosem_rs::acse::{Aare, ApplicationContext};
    use dlms_cosem_rs::codec::{Encode, SliceWriter, Writer};

    let (mut client, _server) = ciphered_pair();
    let mut c = [0u8; 512];
    client.associate_request(&mut c).unwrap();

    let aare = Aare {
        application_context: Some(ApplicationContext::LogicalNameCiphered),
        result: AssociationResult::Accepted,
        diagnostic: Diagnostic::User(UserDiagnostic::Null),
        responding_ap_title: Some(SERVER_TITLE.as_bytes()),
        // No mechanism name at all: high level security silently skipped.
        ..Default::default()
    };
    let mut s = [0u8; 512];
    let mut w = SliceWriter::new(&mut s);
    aare.encode(&mut w).unwrap();
    let m = w.written();

    match client.handle_associate_response(&s[..m]).unwrap() {
        AssociationStep::Rejected { diagnostic, .. } => {
            assert_eq!(diagnostic, Diagnostic::User(UserDiagnostic::AuthenticationRequired));
        }
        other => panic!("a dropped mechanism must be refused, got {other:?}"),
    }
}

#[test]
fn low_level_security_accepts_the_right_password() {
    let (mut client, mut server) = lls_pair(b"12345678", b"12345678");
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
}

#[test]
fn low_level_security_refuses_the_wrong_password() {
    let (mut client, mut server) = lls_pair(b"12345678", b"87654321");
    match associate(&mut client, &mut server) {
        AssociationStep::Rejected { result, diagnostic } => {
            assert_eq!(result, AssociationResult::RejectedPermanent);
            assert_eq!(diagnostic, Diagnostic::User(UserDiagnostic::AuthenticationFailure));
        }
        other => panic!("a wrong password must not associate: {other:?}"),
    }
    assert_eq!(client.state(), SessionState::Closed);
}

#[test]
fn high_level_security_refuses_a_peer_with_the_wrong_key() {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let mut wrong_gak = GAK;
    wrong_gak[0] ^= 0xFF;
    let mut client: Client = ClientSession::new(
        ClientConfig {
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    );
    let mut server: Meter = Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, wrong_gak), FixedRandom(0xB2)),
    );

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.associate_request(&mut c).unwrap();
    // The server cannot even open the ciphered InitiateRequest with the wrong key.
    let handled = server.handle(&c[..n], &mut s);
    assert!(
        handled.is_err() || {
            let m = handled.unwrap();
            client.handle_associate_response(&s[..m]).is_err()
                || !matches!(
                    {
                        let n2 = client.hls_reply_request(&mut c);
                        n2.and_then(|n2| server.handle(&c[..n2], &mut s))
                            .and_then(|m2| client.handle_hls_reply_response(&s[..m2]))
                    },
                    Ok(AssociationStep::Established)
                )
        },
        "a peer with the wrong key must not end up associated"
    );
}

#[test]
fn access_rights_are_enforced_before_the_store_is_asked() {
    let (mut client, mut server) = plain_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let n = client.get_request(AttributeDescriptor::new(7, SECRET_LOG, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::ReadWriteDenied),
        "the framework refuses before the store sees the request"
    );

    // And a write to a read-only attribute is refused the same way.
    let n = client
        .set_request(AttributeDescriptor::new(3, ENERGY, 2), None, Data::DoubleLongUnsigned(0), &mut c)
        .unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::ReadWriteDenied)
    );
    assert_eq!(server.store().energy_wh, 12_345_678, "and nothing changed");
}

#[test]
fn an_unknown_object_is_reported_not_crashed() {
    let (mut client, mut server) = plain_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client
        .get_request(AttributeDescriptor::new(3, Obis::new(1, 0, 99, 99, 99, 255), 2), None, &mut c)
        .unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::ObjectUndefined)
    );
}

#[test]
fn a_service_before_association_is_refused() {
    let (mut client, mut server) = plain_pair();
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    // The client refuses to build one at all.
    assert_eq!(
        client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap_err().kind,
        ErrorKind::UnexpectedMessage
    );
    // And a server that receives one anyway answers with an exception rather than
    // serving it.
    let raw = [0xC0u8, 0x01, 0x81, 0x00, 0x03, 1, 0, 1, 8, 0, 255, 2, 0];
    let m = server.handle(&raw, &mut s).unwrap();
    match dlms_cosem_rs::Apdu::from_bytes(&s[..m]).unwrap() {
        dlms_cosem_rs::Apdu::ExceptionResponse(e) => {
            assert_eq!(e.state_error, dlms_cosem_rs::xdlms::StateError::ServiceNotAllowed);
        }
        other => panic!("expected an exception, got {other:?}"),
    }
}

#[test]
fn a_release_closes_both_ends() {
    let (mut client, mut server) = plain_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.release_request(&mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(client.handle_response(&s[..m], &mut plain).unwrap(), Response::Released);
    assert_eq!(client.state(), SessionState::Closed);
    assert_eq!(server.state(), ServerState::Closed);
}

/// A client that demands ciphering, against a server that offers none.
fn ciphered_pair_with_plain_server() -> (Client, Meter) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let client: Client = ClientSession::new(
        ClientConfig { system_title: Some(CLIENT_TITLE), security: policy, ..Default::default() },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    );
    let server: Meter = Server::new(
        ServerConfig { system_title: Some(SERVER_TITLE), ..Default::default() },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );
    (client, server)
}

#[test]
fn a_ciphered_client_will_not_associate_with_a_plain_server() {
    let (mut client, mut server) = ciphered_pair_with_plain_server();
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.associate_request(&mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_associate_response(&s[..m]).unwrap() {
        AssociationStep::Rejected { diagnostic, .. } => {
            assert_eq!(diagnostic, Diagnostic::User(UserDiagnostic::ApplicationContextNameNotSupported))
        }
        other => panic!("a ciphering mismatch must be refused: {other:?}"),
    }
}

#[test]
fn a_ciphered_association_refuses_an_unprotected_response() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut plain = [0u8; 512];
    // A bare get-response, as an attacker who cannot encrypt would have to send.
    let raw = [0xC4u8, 0x01, 0x81, 0x00, 0x06, 0x00, 0xBC, 0x61, 0x4E];
    assert_eq!(
        client.handle_response(&raw, &mut plain).unwrap_err().kind,
        ErrorKind::UnexpectedMessage,
        "downgrade to plaintext must be refused"
    );
    let _ = &mut server;
}

fn alloc_vec() -> Vec<u32> {
    Vec::new()
}

/// A client that drops the connection without releasing leaves the server holding its
/// dedicated key, its negotiated conformance and its challenge. Nothing in a sans-I/O
/// engine can see a closed socket, so the caller has to say so — and the thing it says
/// must not also roll the invocation counter back.
#[test]
fn resetting_a_server_forgets_the_association_but_not_the_counter() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    client.handle_response(&s[..m], &mut plain).unwrap();

    let counter_before = server.invocation_counter();
    assert!(counter_before > 0);
    let peer_counter_before = server.peer_invocation_counter().expect("the client has spent counters");

    server.reset();

    assert_eq!(server.state(), ServerState::Idle);
    assert_eq!(
        server.invocation_counter(),
        counter_before,
        "the counter must never go backwards: the key has not changed"
    );
    assert_eq!(
        server.peer_invocation_counter(),
        Some(peer_counter_before),
        "and neither does the peer's window: the same client reconnecting must not be \
         able to replay what it sent before the gap"
    );

    // A service without a fresh association is refused.
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert!(matches!(
        dlms_cosem_rs::Apdu::from_bytes(&s[..m]).unwrap(),
        dlms_cosem_rs::Apdu::ExceptionResponse(_)
    ));

    // And a fresh association from *another* peer works, continuing the server's own
    // counter rather than restarting it. Another peer's title is what starts a new
    // window; the counters of one client say nothing about another's, and this one
    // starts from zero.
    let (mut second, _) = ciphered_pair_titled(SystemTitle::new(*b"CLI\0\0\0\0\x02"));
    assert_eq!(associate(&mut second, &mut server), AssociationStep::Established);
    assert!(server.invocation_counter() > counter_before);
    assert_eq!(server.replay_owner(), Some(SystemTitle::new(*b"CLI\0\0\0\0\x02")));
}

/// The window is the only thing standing between a recorded frame and a second
/// execution, and a dropped connection is exactly the gap an attacker arranges: an AARQ
/// is unauthenticated, so anyone on the path can make the association restart.
///
/// So a peer that comes back keeps its window. What starts a fresh one is a *different*
/// system title, because a different sender's counters say nothing about this one's.
#[test]
fn a_reconnecting_client_cannot_replay_what_it_sent_before_the_gap() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    // A breaker operation, recorded off the wire.
    let n =
        client.action_request(MethodDescriptor::new(70, BREAKER, 1), Some(Data::Integer(0)), &mut c).unwrap();
    let recorded = c[..n].to_vec();
    let m = server.handle(&c[..n], &mut s).unwrap();
    client.handle_response(&s[..m], &mut plain).unwrap();
    let operations = server.store().breaker_operations;

    // The connection drops and the same client reconnects, restoring the counter it
    // persisted — which is what a client that does not want to burn its key must do.
    server.reset();
    let (mut again, _) = ciphered_pair();
    again.set_invocation_counter(client.invocation_counter());
    assert_eq!(associate(&mut again, &mut server), AssociationStep::Established);

    // The recording goes back on the wire. It really was sent under the real key, so the
    // tag verifies — only the counter says it has been seen.
    let m = server.handle(&recorded, &mut s).unwrap();
    let apdu = dlms_cosem_rs::Apdu::from_bytes(&s[..m]).unwrap();
    match apdu {
        dlms_cosem_rs::Apdu::ExceptionResponse(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::InvocationCounterError);
        }
        other => panic!("a replay across a reconnection must be refused by name: {other:?}"),
    }
    assert_eq!(server.store().breaker_operations, operations, "and must not move the breaker again");
}

/// A client that restarts from a stale counter is the commonest cause of a replay, and
/// it fails at the *first* protected message there is — the InitiateRequest inside the
/// AARQ. Before this, that produced a transport error with nothing on the wire: the
/// client saw a dropped connection and retried the same stale value for ever.
#[test]
fn a_stale_counter_is_answered_with_the_value_to_move_to() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    client.handle_response(&s[..m], &mut plain).unwrap();
    server.reset();

    // The same client restarts from a backup and its counter has gone backwards.
    let (mut restarted, _) = ciphered_pair();
    let n = restarted.associate_request(&mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).expect("a refusal is a response, not an error");
    let expected = match restarted.handle_associate_response(&s[..m]).unwrap() {
        AssociationStep::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::InvocationCounterError);
            e.expected_invocation_counter.expect("and it says what to move to")
        }
        other => panic!("a stale counter must be named, not dropped: {other:?}"),
    };

    // Moving to it deliberately — never automatically — restores the association.
    let (mut recovered, _) = ciphered_pair();
    recovered.set_invocation_counter(expected.saturating_sub(1));
    assert_eq!(associate(&mut recovered, &mut server), AssociationStep::Established);
}

/// The broadcast bit inside a received security header chooses *which key* verifies the
/// frame. A receiver that took it from the sender would let anyone holding the fleet's
/// broadcast key speak to any meter as the head-end, with a tag that verifies — so the
/// bit is compared against what this end demands, before a key is touched.
#[test]
fn a_frame_claiming_the_broadcast_key_set_is_refused_on_a_unicast_association() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];

    let spent_before = server.peer_invocation_counter();
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    // A `glo-get-request` is tag, length, security control, counter, payload. Flip the
    // broadcast bit in the control byte where it travels in the clear.
    let control = 2;
    assert_eq!(c[0], 0xC8, "a ciphered GET request");
    assert_eq!(c[control] & 0x40, 0, "and it is unicast to start with");
    c[control] |= 0x40;

    let m = server.handle(&c[..n], &mut s).unwrap();
    let mut plain = [0u8; 512];
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::DecipheringError);
        }
        other => panic!("a key-set downgrade must be refused: {other:?}"),
    }
    assert_eq!(
        server.peer_invocation_counter(),
        spent_before,
        "and the counter it carried is not spent, so the real request can still be sent"
    );
}

/// `general-signing` is decoded as a type and cannot be opened: it needs suite 1's or
/// suite 2's asymmetric half. That has to be sayable, because a caller cannot otherwise
/// tell a wrapper this crate does not implement from a peer that dropped protection.
#[test]
fn a_protection_wrapper_this_crate_cannot_open_is_named_rather_than_read_as_plaintext() {
    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut plain = [0u8; 512];
    let _ = &mut server;

    // Seven zero bytes decode as a signing header of seven empty fields.
    let frame = [0xDFu8, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        client.handle_response(&frame, &mut plain).unwrap_err().kind,
        ErrorKind::Unsupported,
        "general-signing must be refused by name, not as a downgrade"
    );
}

/// Rewrap the ciphered content of `apdu` — a `glo-`/`ded-` or `general-glo-` frame — as a
/// `general-ciphering` APDU. The content is protected identically in all of them (same
/// nonce, same additional data), so the tag stays valid and only the header changes.
fn as_general_ciphering(
    apdu: &[u8],
    originator: SystemTitle,
    recipient: &[u8],
    key_info: Option<dlms_cosem_rs::xdlms::KeyInfo<'_>>,
    out: &mut [u8],
) -> usize {
    use dlms_cosem_rs::codec::{Decode, Encode, SliceWriter};
    use dlms_cosem_rs::xdlms::{Apdu, GeneralCiphering};

    let ciphered = match Apdu::from_bytes(apdu).unwrap() {
        Apdu::Ciphered { body, .. } => body,
        Apdu::GeneralCiphered { body: g, .. } => g.ciphered,
        other => panic!("not a protected APDU: {other:?}"),
    };
    let g = GeneralCiphering {
        transaction_id: &[],
        originator_system_title: originator.as_bytes(),
        recipient_system_title: recipient,
        date_time: &[],
        other_information: &[],
        key_info,
        ciphered,
    };
    let mut w = SliceWriter::new(out);
    w.write_u8(0xDD).unwrap();
    g.encode(&mut w).unwrap();
    w.written()
}

/// `general-ciphering` names both ends and carries its own key information. Its content
/// is protected exactly as `general-glo-ciphering`'s is, so the identified-key form needs
/// nothing this crate lacks — and it is the form a peer uses when it wants to name the
/// recipient. Opening one is what lets this crate talk to a stack that prefers it.
#[test]
fn a_general_ciphering_frame_in_its_identified_key_form_is_opened() {
    use dlms_cosem_rs::xdlms::KeyInfo;

    let (mut client, mut server) = ciphered_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut wrapped = [0u8; 512];

    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();

    // The same answer, re-headed as `general-ciphering` naming both ends.
    let k = as_general_ciphering(
        &s[..m],
        SERVER_TITLE,
        CLIENT_TITLE.as_bytes(),
        Some(KeyInfo::Identified { key_id: 0 }),
        &mut wrapped,
    );
    match client.handle_response(&wrapped[..k], &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("the reading must come through: {other:?}"),
    }
}

/// Every field of a `general-ciphering` header travels in the clear and outside the tag,
/// so each is a hint — but the ones that decide *whether this end should open the frame
/// at all* are still checked, and the one that decides *which key* is this end's.
#[test]
fn a_general_ciphering_frame_is_refused_when_its_header_says_it_is_not_ours() {
    use dlms_cosem_rs::xdlms::KeyInfo;

    let mut wrapped = [0u8; 512];
    let mut plain = [0u8; 512];

    // Each case gets its own pair, because a refused frame must not spend a counter that
    // a later case then depends on.
    /// One way a `general-ciphering` header can be somebody else's, and the refusal it
    /// must produce.
    struct Case<'a> {
        what: &'a str,
        originator: SystemTitle,
        recipient: &'a [u8],
        key_info: Option<KeyInfo<'a>>,
        expected: ErrorKind,
    }

    let cases = [
        Case {
            what: "addressed to another client",
            originator: SERVER_TITLE,
            recipient: b"OTHER\0\0\0",
            key_info: None,
            expected: ErrorKind::UnexpectedMessage,
        },
        Case {
            what: "claiming to come from another meter",
            originator: SystemTitle::new(*b"XXX\0\0\0\0\x09"),
            recipient: CLIENT_TITLE.as_bytes(),
            key_info: None,
            expected: ErrorKind::UnexpectedMessage,
        },
        Case {
            what: "naming the broadcast key set",
            originator: SERVER_TITLE,
            recipient: CLIENT_TITLE.as_bytes(),
            key_info: Some(KeyInfo::Identified { key_id: 1 }),
            expected: ErrorKind::UnexpectedMessage,
        },
        Case {
            what: "delivering a wrapped key",
            originator: SERVER_TITLE,
            recipient: CLIENT_TITLE.as_bytes(),
            key_info: Some(KeyInfo::Wrapped { kek_id: 0, ciphered_key: &[0u8; 24] }),
            expected: ErrorKind::Unsupported,
        },
    ];

    for Case { what, originator, recipient, key_info, expected } in cases {
        let (mut client, mut server) = ciphered_pair();
        associate(&mut client, &mut server);
        let mut c = [0u8; 512];
        let mut s = [0u8; 512];
        let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
        let m = server.handle(&c[..n], &mut s).unwrap();
        let k = as_general_ciphering(&s[..m], originator, recipient, key_info, &mut wrapped);
        assert_eq!(
            client.handle_response(&wrapped[..k], &mut plain).unwrap_err().kind,
            expected,
            "a frame {what} must be refused"
        );
    }
}

/// A dedicated association agreed to use the key it negotiated. A `glo-` tagged service
/// APDU names the *other* key set, and which key opens a message is not the sender's to
/// choose — the same rule as the broadcast bit, applied where the tag carries it.
///
/// It also catches the honest version of the same fault, which is the expensive one: one
/// end switching to the dedicated key and the other not. Before this, that showed up as a
/// tag failure on every message with nothing to point at.
#[test]
fn a_dedicated_association_refuses_a_frame_on_the_global_key_set() {
    let (mut client, mut server) = dedicated_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];

    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    assert_eq!(c[0], 0xD0, "a dedicated association sends ded-get-request");
    // Rewrite the tag as its global sibling. The body is unchanged, so this is exactly
    // the frame a peer that had not switched would send.
    c[0] = 0xC8;

    let m = server.handle(&c[..n], &mut s).unwrap();
    let mut plain = [0u8; 512];
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::DecipheringError);
        }
        other => panic!("a key-set mismatch must be refused: {other:?}"),
    }
}

/// A provider that will not hold a dedicated key.
///
/// The default `CryptoProvider` behaviour, which a secure element backed by fixed slots
/// would have — and which used to leave the association half-switched.
#[derive(Debug)]
struct NoDedicatedKey(RustCryptoProvider<FixedRandom>);

impl dlms_cosem_rs::security::CryptoProvider for NoDedicatedKey {
    fn aead_seal(
        &self,
        key: dlms_cosem_rs::security::KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> dlms_cosem_rs::Result<[u8; 12]> {
        self.0.aead_seal(key, suite, nonce, aad, buf)
    }
    fn aead_open(
        &self,
        key: dlms_cosem_rs::security::KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 12],
    ) -> dlms_cosem_rs::Result<()> {
        self.0.aead_open(key, suite, nonce, aad, buf, tag)
    }
    fn gmac(
        &self,
        key: dlms_cosem_rs::security::KeyRef<'_>,
        suite: SecuritySuite,
        nonce: &[u8; 12],
        aad: &[&[u8]],
    ) -> dlms_cosem_rs::Result<[u8; 12]> {
        self.0.gmac(key, suite, nonce, aad)
    }
    fn random(&self, out: &mut [u8]) -> dlms_cosem_rs::Result<()> {
        self.0.random(out)
    }
    fn authentication_key(&self) -> Option<&[u8]> {
        self.0.authentication_key()
    }
    // `set_dedicated_key` is left at its default, which refuses.
}

/// A server whose provider cannot hold the dedicated key the client delivered **refuses
/// the association**. Carrying on with the global key set reads like graceful degradation
/// and is not: the client has already switched to `ded-` tags, so nothing afterwards
/// decrypts — and a client that asked for a key of its own and silently got the
/// long-lived one had a security expectation quietly dropped.
#[test]
fn a_server_that_cannot_hold_a_dedicated_key_refuses_rather_than_half_switching() {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0).with_dedicated(true);
    let mut client_keys = KeyRing::new(GUEK, GAK);
    client_keys.set_dedicated(Key::new(DEDICATED));
    let mut client: Client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            system_title: Some(CLIENT_TITLE),
            security: policy,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(client_keys, FixedRandom(0xA1)),
    );
    let mut server = Server::<_, _, 1024>::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            security: SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
            ..Default::default()
        },
        TestMeter::default(),
        NoDedicatedKey(RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xB2))),
    );

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.associate_request(&mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_associate_response(&s[..m]).unwrap() {
        AssociationStep::Rejected { result, .. } => {
            assert_eq!(result, dlms_cosem_rs::acse::AssociationResult::RejectedPermanent);
        }
        other => panic!("the association cannot be served and must be refused: {other:?}"),
    }
}

/// Reading a load profile: the operation DLMS exists for, and the one that never fits.
///
/// The encoded buffer here is several kilobytes against a negotiated PDU size of a few
/// hundred bytes, so it can only arrive as a run of `get-response-with-datablock`. Until
/// the server could segment, this read simply failed.
#[test]
fn a_load_profile_larger_than_the_pdu_size_is_read_over_block_transfer() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut storage = [0u8; 8192];
    let mut blocks = BlockCollector::new(&mut storage);

    let mut n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut c).unwrap();
    let mut rounds = 0;
    loop {
        rounds += 1;
        assert!(rounds < 200, "the transfer should converge");
        let m = server.handle(&c[..n], &mut s).unwrap();
        match client.handle_response(&s[..m], &mut plain).unwrap() {
            Response::Block { last, number, data } => {
                blocks.push(number, data).expect("blocks arrive in order");
                if last {
                    break;
                }
                n = client.get_next_block_request(number, &mut c).unwrap();
            }
            other => panic!("expected a block, got {other:?}"),
        }
    }

    assert!(rounds >= 5, "a profile this size must take several blocks, took {rounds}");
    assert!(!server.is_block_transfer_in_progress(), "the server let go after the last block");

    // The concatenation decodes, and every row is the one the meter holds.
    let value = blocks.value().expect("the reassembled value decodes");
    let rows = value.as_array().expect("a profile buffer is an array");
    assert_eq!(rows.len(), PROFILE_ROWS);
    for (i, row) in rows.iter().enumerate() {
        let row = row.unwrap();
        assert_eq!(row.field(0).unwrap().as_u64(), Some(1_000_000 + i as u64));
        assert_eq!(row.field(1).unwrap().as_u64(), Some((i * 7 % 1000) as u64));
    }
}

/// A fragment boundary falls wherever the server's buffer ran out — very often inside a
/// length prefix or a multi-byte integer. Any single block on its own is therefore not
/// a decodable value, and treating one as though it were is how a partial read becomes
/// a plausible wrong number.
#[test]
fn a_single_block_is_not_a_value_on_its_own() {
    let (mut client, mut server) = small_pdu_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let Response::Block { last, data, .. } = client.handle_response(&s[..m], &mut plain).unwrap() else {
        panic!("expected a block")
    };
    assert!(!last);
    // The array header claims 120 rows and the block holds a handful of them.
    assert!(dlms_cosem_rs::axdr::Data::from_bytes_in(data).is_err());
}

/// The collector refuses a fragment that is not the next one. A duplicated or reordered
/// block concatenated in the wrong place usually still decodes — into a wrong reading
/// that no error is ever attached to.
#[test]
fn the_collector_refuses_a_block_out_of_order() {
    let mut storage = [0u8; 64];
    let mut blocks = BlockCollector::new(&mut storage);
    assert!(blocks.push(1, &[0x11, 0x07]).is_ok());
    assert_eq!(blocks.last_block(), 1);
    assert_eq!(blocks.push(1, &[0x11, 0x07]).unwrap_err().kind, ErrorKind::UnexpectedMessage, "a repeat");
    assert_eq!(blocks.push(3, &[0x11, 0x07]).unwrap_err().kind, ErrorKind::UnexpectedMessage, "a gap");
    assert!(blocks.push(2, &[0x00]).is_ok());
    assert_eq!(blocks.len(), 3);

    // And it refuses to overrun the buffer it was given.
    let mut small = [0u8; 4];
    let mut tight = BlockCollector::new(&mut small);
    assert!(tight.push(1, &[0; 4]).is_ok());
    assert!(matches!(tight.push(2, &[0; 4]).unwrap_err().kind, ErrorKind::BufferTooSmall { .. }));
}

/// A `get-request-next` that acknowledges a block the server did not just send is a
/// client that has lost track. Answering it would hand over the wrong fragment.
#[test]
fn a_stray_or_mismatched_block_acknowledgement_is_refused() {
    let (mut client, mut server) = small_pdu_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];

    // A client with nothing outstanding cannot even build the request: there is no
    // invocation for a `next` to continue.
    assert_eq!(client.get_next_block_request(1, &mut c).unwrap_err().kind, ErrorKind::UnexpectedMessage);

    // A server that receives one anyway — from a peer that is not this client — refuses.
    let stray = [0xC0u8, 0x02, 0x81, 0x00, 0x00, 0x00, 0x01];
    let m = server.handle(&stray, &mut s).unwrap();
    let mut plain = [0u8; 512];
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::NoLongGetInProgress),
        "the standard names this case; a generic refusal would tell the client nothing"
    );

    // Start a real transfer, then acknowledge the wrong block.
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut c).unwrap();
    server.handle(&c[..n], &mut s).unwrap();
    assert!(server.is_block_transfer_in_progress());
    let n = client.get_next_block_request(7, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::DataBlockNumberInvalid)
    );
    assert!(!server.is_block_transfer_in_progress(), "and the transfer is abandoned");
}

/// A new read while a transfer is half-delivered abandons the old one, rather than
/// letting a later `next` return a block of something the client is no longer asking for.
#[test]
fn a_new_read_abandons_a_half_delivered_one() {
    let (mut client, mut server) = small_pdu_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut c).unwrap();
    server.handle(&c[..n], &mut s).unwrap();
    assert!(server.is_block_transfer_in_progress());

    // A small read now: it fits in one APDU and ends the transfer.
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("expected the small value, got {other:?}"),
    }
    assert!(!server.is_block_transfer_in_progress());
}

/// The same read, ciphered, at a PDU size where the protection overhead is a sixth of
/// the budget. A fragment sized without counting the `glo-` tag, the length prefix, the
/// security control byte, the invocation counter and the GCM tag produces a reply the
/// client cannot receive — and it does so only at the boundary, so it is the kind of
/// arithmetic that passes every small test and fails in the field.
#[test]
fn a_load_profile_is_read_over_ciphered_block_transfer() {
    let (mut client, mut server) = small_pdu_ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut storage = [0u8; 8192];
    let mut blocks = BlockCollector::new(&mut storage);

    let mut n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut c).unwrap();
    let mut rounds = 0;
    loop {
        rounds += 1;
        assert!(rounds < 400, "the transfer should converge");
        let m = server.handle(&c[..n], &mut s).unwrap();
        assert!(m <= 128, "every reply must fit the negotiated PDU size, this one was {m}");
        assert_ne!(s[0], 0xC4, "and must be protected: a bare get-response leaked");
        match client.handle_response(&s[..m], &mut plain).unwrap() {
            Response::Block { last, number, data } => {
                blocks.push(number, data).unwrap();
                if last {
                    break;
                }
                n = client.get_next_block_request(number, &mut c).unwrap();
            }
            other => panic!("expected a block, got {other:?}"),
        }
    }

    assert!(rounds > 10, "a 128-byte budget must take many blocks, took {rounds}");
    let value = blocks.value().expect("the reassembled value decodes");
    assert_eq!(value.as_array().unwrap().len(), PROFILE_ROWS);

    // Every block was a protected APDU of its own, so every one spent a counter and
    // none of them can be replayed.
    assert_eq!(server.peer_invocation_counter(), Some(client.invocation_counter()));
}

/// The audit trail: what the server was asked to do, and what came of it.
///
/// The refusals are the half that matters. Access control is the framework's job, so a
/// store only ever sees the calls it was asked to service — it never learns that
/// somebody tried to read the object it is not allowed to expose, or tried to open the
/// breaker without the rights to. Recording only successes would leave exactly the
/// events an incident review is looking for out of the record.
#[test]
fn the_audit_trail_records_refusals_as_well_as_successes() {
    use dlms_cosem_rs::server::AuditEvent;

    let (mut client, mut server) = lls_pair(b"12345678", b"12345678");
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    // A read that works, a read that is denied, a method that runs.
    for (class, obis, attr) in [(3u16, ENERGY, 2i8), (1, SECRET_LOG, 2)] {
        let n = client.get_request(AttributeDescriptor::new(class, obis, attr), None, &mut c).unwrap();
        let m = server.handle(&c[..n], &mut s).unwrap();
        client.handle_response(&s[..m], &mut plain).unwrap();
    }
    let n = client.action_request(MethodDescriptor::new(70, BREAKER, 1), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    client.handle_response(&s[..m], &mut plain).unwrap();

    // And one the association may not invoke at all.
    let n = client.action_request(MethodDescriptor::new(15, CLOCK, 1), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    client.handle_response(&s[..m], &mut plain).unwrap();

    let trail = &server.store().trail;
    assert_eq!(
        trail.first(),
        Some(&AuditEvent::Associated { mechanism: AuthMechanism::Low, ciphered: false }),
        "the association itself is the first thing on the record"
    );
    assert!(trail.contains(&AuditEvent::AttributeRead {
        class_id: 3,
        logical_name: ENERGY,
        attribute_id: 2,
        outcome: DataAccessResult::Success,
    }));
    assert!(
        trail.contains(&AuditEvent::AttributeRead {
            class_id: 1,
            logical_name: SECRET_LOG,
            attribute_id: 2,
            outcome: DataAccessResult::ReadWriteDenied,
        }),
        "the attempt on the object nobody may read is on the record, with its refusal — \
         and note the store is never asked for it, so this event can only come from the \
         framework"
    );
    assert!(trail.contains(&AuditEvent::MethodInvoked {
        class_id: 70,
        logical_name: BREAKER,
        method_id: 1,
        outcome: dlms_cosem_rs::xdlms::ActionResult::Success,
    }));
    assert!(
        trail.contains(&AuditEvent::MethodInvoked {
            class_id: 15,
            logical_name: CLOCK,
            method_id: 1,
            outcome: dlms_cosem_rs::xdlms::ActionResult::ReadWriteDenied,
        }),
        "a method the association may not invoke is recorded as denied, not omitted"
    );

    // Releasing closes the record.
    let n = client.release_request(&mut c).unwrap();
    server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(server.store().trail.last(), Some(&AuditEvent::Released));
}

/// A refused association is recorded too, with the diagnostic the client was given.
#[test]
fn a_refused_association_is_on_the_record() {
    use dlms_cosem_rs::server::AuditEvent;

    let (mut client, mut server) = lls_pair(b"wrong-one", b"12345678");
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.associate_request(&mut c).unwrap();
    server.handle(&c[..n], &mut s).unwrap();

    assert_eq!(
        server.store().trail.as_slice(),
        [AuditEvent::AssociationRefused { diagnostic: UserDiagnostic::AuthenticationFailure }],
        "a failed authentication is exactly what a trail is for"
    );
}

/// Reading many attributes in one exchange.
///
/// On a GPRS or LPWAN link the round trip dominates everything else, so thirty reads one
/// at a time is not thirty times the bytes — it is thirty times the latency.
#[test]
fn several_attributes_are_read_in_one_exchange() {
    let (mut client, mut server) = plain_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let items = [
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None },
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(8, CLOCK, 2), access: None },
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(3, ENERGY, 1), access: None },
    ];
    let n = client.get_request_with_list(&items, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let Response::DataList(results) = client.handle_response(&s[..m], &mut plain).unwrap() else {
        panic!("expected a list of results")
    };
    assert_eq!(results.len(), 3, "one result per attribute asked for, in order");

    let got: Vec<GetDataResult<'_>> = results.iter().map(Result::unwrap).collect();
    assert_eq!(got[0].value().unwrap().as_u64(), Some(12_345_678));
    assert!(matches!(got[1].value().unwrap(), dlms_cosem_rs::axdr::Data::DateTime(_)));
    assert_eq!(got[2].value().unwrap().as_obis(), Some(ENERGY), "attribute 1 is the logical name");
}

/// The reason to use the service rather than issuing the reads separately: one
/// unreadable object costs its own slot, not the whole read.
#[test]
fn one_denied_attribute_does_not_lose_the_rest_of_the_list() {
    let (mut client, mut server) = plain_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let items = [
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None },
        // Nobody may read this one.
        AttributeDescriptorWithSelection {
            descriptor: AttributeDescriptor::new(1, SECRET_LOG, 2),
            access: None,
        },
        // And this object does not exist at all.
        AttributeDescriptorWithSelection {
            descriptor: AttributeDescriptor::new(3, Obis::new(1, 0, 3, 8, 0, 255), 2),
            access: None,
        },
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(8, CLOCK, 2), access: None },
    ];
    let n = client.get_request_with_list(&items, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let Response::DataList(results) = client.handle_response(&s[..m], &mut plain).unwrap() else {
        panic!("expected a list of results")
    };
    let got: Vec<GetDataResult<'_>> = results.iter().map(Result::unwrap).collect();
    assert_eq!(got.len(), 4);
    assert_eq!(got[0].value().unwrap().as_u64(), Some(12_345_678), "the first still arrives");
    assert_eq!(got[1].value().unwrap_err(), DataAccessResult::ReadWriteDenied);
    assert_eq!(got[2].value().unwrap_err(), DataAccessResult::ObjectUndefined);
    assert!(
        got[3].value().is_ok(),
        "and the reads after the failures are unaffected — which is the whole point"
    );

    // Every attempt, refusals included, is on the audit record.
    assert_eq!(
        server
            .store()
            .trail
            .iter()
            .filter(|e| matches!(e, dlms_cosem_rs::server::AuditEvent::AttributeRead { .. }))
            .count(),
        4
    );
}

/// A list whose results do not fit one APDU is blocked like any other response — and
/// what the blocks carry is the encoded *list*, not a value.
#[test]
fn a_list_response_too_large_for_one_apdu_is_blocked() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut storage = [0u8; 8192];
    let mut blocks = BlockCollector::new(&mut storage);

    // Two load profiles in one request: far past a 256-byte PDU.
    let items = [
        AttributeDescriptorWithSelection {
            descriptor: AttributeDescriptor::new(7, LOAD_PROFILE, 2),
            access: None,
        },
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None },
    ];
    let mut n = client.get_request_with_list(&items, &mut c).unwrap();
    loop {
        let m = server.handle(&c[..n], &mut s).unwrap();
        match client.handle_response(&s[..m], &mut plain).unwrap() {
            Response::Block { last, number, data } => {
                blocks.push(number, data).unwrap();
                if last {
                    break;
                }
                n = client.get_next_block_request(number, &mut c).unwrap();
            }
            other => panic!("expected a block, got {other:?}"),
        }
    }

    // Reassembled, it is a list — decoding it as a single value would be wrong.
    let results = blocks.results().expect("the blocks reassemble into a result list");
    assert_eq!(results.len(), 2);
    let got: Vec<GetDataResult<'_>> = results.iter().map(Result::unwrap).collect();
    assert_eq!(got[0].value().unwrap().as_array().unwrap().len(), PROFILE_ROWS);
    assert_eq!(got[1].value().unwrap().as_u64(), Some(12_345_678));
}

/// An empty list is a round trip that asks for nothing.
#[test]
fn an_empty_list_is_refused_before_it_costs_a_round_trip() {
    let (mut client, mut server) = plain_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    assert_eq!(client.get_request_with_list(&[], &mut c).unwrap_err().kind, ErrorKind::InvalidValue);
}

/// Selective access, end to end.
///
/// The descriptor is built by the client, encoded into the request, carried across, and
/// handed to the store — and until this test, every one of those steps was plumbed and
/// none of them was proven. A meter that received the descriptor and ignored it would
/// answer a day's read with a year of data, and nothing in the exchange would say so.
#[test]
fn selective_access_reaches_the_store_and_narrows_the_read() {
    use dlms_cosem_rs::cosem::EntryDescriptor;

    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut params = [0u8; 64];

    // Entries 3 to 7 inclusive — five rows, which now fits one APDU where the whole
    // profile needed five blocks.
    let access = EntryDescriptor::entries(3, 7).to_selective_access(&mut params).unwrap();
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), Some(access), &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let Response::Data(value) = client.handle_response(&s[..m], &mut plain).unwrap() else {
        panic!("a narrowed read fits in one response")
    };

    let rows = value.as_array().expect("an array of rows");
    assert_eq!(rows.len(), 5, "entries 3..=7 is five rows, not the whole {PROFILE_ROWS}");
    let first = rows.get(0).unwrap();
    assert_eq!(first.field(0).unwrap().as_u64(), Some(1_000_002), "entry 3 counting from one is index 2");
    let last = rows.get(4).unwrap();
    assert_eq!(last.field(0).unwrap().as_u64(), Some(1_000_006));
}

/// "To the end" is written as zero, and a meter that read it as an index would return
/// nothing at all.
#[test]
fn an_open_ended_entry_range_runs_to_the_end_of_the_buffer() {
    use dlms_cosem_rs::cosem::EntryDescriptor;

    let (mut client, mut server) = small_pdu_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut params = [0u8; 64];
    let mut storage = [0u8; 8192];
    let mut blocks = BlockCollector::new(&mut storage);

    let access =
        EntryDescriptor::entries(PROFILE_ROWS as u32 - 2, 0).to_selective_access(&mut params).unwrap();
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), Some(access), &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Data(value) => assert_eq!(value.as_array().unwrap().len(), 3),
        Response::Block { number, data, .. } => {
            blocks.push(number, data).unwrap();
            panic!("three rows should not need blocking");
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// A selector the meter does not offer is refused by name, not answered with everything.
#[test]
fn an_unsupported_selector_is_refused_rather_than_ignored() {
    let (mut client, mut server) = small_pdu_pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut params = [0u8; 96];

    // Selector 1 — a range by clock — which this meter's profile does not implement.
    let from = dlms_cosem_rs::axdr::DateTime::from_civil(2026, 9, 1, 0, 0, 0, 120);
    let to = dlms_cosem_rs::axdr::DateTime::from_civil(2026, 9, 2, 0, 0, 0, 120);
    let access =
        dlms_cosem_rs::cosem::RangeDescriptor::by_clock(from, to).to_selective_access(&mut params).unwrap();
    assert_eq!(access.selector, 1);

    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), Some(access), &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::ScopeOfAccessViolated),
        "a meter that cannot honour the selector must say so, not answer the whole buffer"
    );
}

/// A dedicated key is delivered inside the ciphered InitiateRequest and governs every
/// APDU after it. The two ends cannot be configured into agreement — only the client
/// knows there is one — so the server has to follow the key it was handed.
///
/// What this pins is the ordering the design gets wrong most easily: the InitiateRequest
/// itself is protected **globally**, because it is what carries the key. A client that
/// protected it with the dedicated key would send a message the server has no way to
/// open, and the failure would look like a wrong global key.
#[test]
fn a_dedicated_key_is_delivered_in_the_initiate_and_governs_everything_after_it() {
    let (mut client, mut server) = dedicated_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    // `ded-get-request` is 0xD0; a global association would have sent 0xC8.
    assert_eq!(c[0], 0xD0, "the request must be tagged with the dedicated family");
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(s[0], 0xD4, "and so must the response");
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("expected a value, got {other:?}"),
    }

    // The key must not outlive the association that negotiated it.
    server.reset();
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert!(m > 0, "a server with no association answers with an exception, not silence");
}

/// Suite 2 ciphers with AES-GCM-256. Everything above the cipher is identical, which is
/// the point: the suite travels in the security control byte and the key length follows
/// from it.
#[test]
fn a_suite_two_association_reads_a_register() {
    let (mut client, mut server) = suite2_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    // The security control byte names suite 2 in its low nibble.
    let dlms_cosem_rs::Apdu::Ciphered { body, .. } =
        dlms_cosem_rs::Apdu::from_bytes(&s[..m]).expect("the response is a ciphered service")
    else {
        panic!("expected a ciphered response")
    };
    assert_eq!(body.security_control.suite(), 2, "the response announces suite 2");
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("expected a value, got {other:?}"),
    }
}

/// An `exception-response` has no `glo-` tag of its own, so a ciphered server can only
/// send one plain or wrapped in `general-glo-ciphering`. A client that refused both
/// turned every server refusal into a decode error and never learned what the meter
/// actually said — which is the one message a client most needs to read.
#[test]
fn a_ciphered_client_can_read_the_servers_refusal() {
    let (mut client, mut server) = ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    // The server forgets the association; the client does not know yet.
    server.reset();

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).expect("a refusal is a response, not an error");
    match client.handle_response(&s[..m], &mut plain).expect("and the client can read it") {
        Response::Exception(e) => {
            assert_eq!(e.state_error, dlms_cosem_rs::xdlms::StateError::ServiceNotAllowed);
        }
        other => panic!("expected an exception response, got {other:?}"),
    }
}

/// Encode an octet string of `n` bytes as A-XDR, which is what a blocked SET carries.
fn blob(n: usize) -> Vec<u8> {
    let payload: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let mut out = vec![0u8; n + 8];
    let mut w = dlms_cosem_rs::codec::SliceWriter::new(&mut out);
    Data::OctetString(&payload).encode(&mut w).unwrap();
    let used = w.written();
    out.truncate(used);
    out
}

/// A value larger than the negotiated PDU size is written over block transfer, and the
/// meter has the whole of it afterwards.
///
/// This is the direction a stack most often leaves out. Reading a load profile needs
/// blocks for the response; writing an activity calendar, a firmware image or a set of
/// tariff scripts needs them for the *request*, and a client that has only the first
/// half works right up until somebody configures a meter.
#[test]
fn a_value_larger_than_the_pdu_size_is_written_over_block_transfer() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let value = blob(1500);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let mut sender = client.set_transfer(AttributeDescriptor::new(18, IMAGE, 2), None, &value).unwrap();
    assert!(sender.blocks() > 1, "the point of the test is that this takes several blocks");
    let mut blocks = 0;
    loop {
        let n = client.next_block_request(&mut sender, &mut c).unwrap();
        assert!(n <= 256, "a block must fit the negotiated PDU size");
        let m = server.handle(&c[..n], &mut s).unwrap();
        blocks += 1;
        match client.handle_response(&s[..m], &mut plain).unwrap() {
            Response::BlockAccepted { number } => assert_eq!(number as usize, blocks),
            Response::Ok => break,
            other => panic!("unexpected response at block {blocks}: {other:?}"),
        }
    }
    assert_eq!(blocks, sender.blocks(), "every block was acknowledged");
    assert!(sender.is_done());

    // And the meter has exactly what was sent.
    let n = client.get_request(AttributeDescriptor::new(18, IMAGE, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let mut collector_buf = [0u8; 2048];
    let mut collected = BlockCollector::new(&mut collector_buf);
    let mut response = client.handle_response(&s[..m], &mut plain).unwrap();
    loop {
        match response {
            Response::Block { last, number, data } => {
                collected.push(number, data).unwrap();
                if last {
                    break;
                }
                let n = client.get_next_block_request(number, &mut c).unwrap();
                let m = server.handle(&c[..n], &mut s).unwrap();
                response = client.handle_response(&s[..m], &mut plain).unwrap();
            }
            Response::Data(d) => {
                assert_eq!(d.as_bytes().unwrap().len(), 1500);
                return;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
    assert_eq!(collected.value().unwrap().as_bytes().unwrap().len(), 1500);
}

/// A method parameter too large for one APDU goes out in blocks, and a return value too
/// large for one comes back in blocks — in the same invocation.
#[test]
fn a_long_action_parameter_and_a_long_action_result_both_segment() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let value = blob(1200);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let mut sender = client.action_transfer(MethodDescriptor::new(18, IMAGE, 1), &value).unwrap();
    assert!(sender.blocks() > 1);

    // Push the parameter up.
    let mut response;
    loop {
        let n = client.next_block_request(&mut sender, &mut c).unwrap();
        let m = server.handle(&c[..n], &mut s).unwrap();
        response = client.handle_response(&s[..m], &mut plain).unwrap();
        if sender.is_done() {
            break;
        }
        match response {
            Response::BlockAccepted { .. } => {}
            other => panic!("expected an acknowledgement, got {other:?}"),
        }
    }

    // Pull the result back.
    let mut collector_buf = [0u8; 2048];
    let mut collected = BlockCollector::new(&mut collector_buf);
    loop {
        match response {
            Response::Block { last, number, data } => {
                collected.push(number, data).unwrap();
                if last {
                    break;
                }
                let n = client.action_next_block_request(number, &mut c).unwrap();
                let m = server.handle(&c[..n], &mut s).unwrap();
                response = client.handle_response(&s[..m], &mut plain).unwrap();
            }
            other => panic!("expected a block of the result, got {other:?}"),
        }
    }
    assert_eq!(collected.value().unwrap().as_bytes().unwrap().len(), 1200);
}

/// A batched write answers per item, so one refusal does not lose the rest.
#[test]
fn a_batched_write_answers_one_result_per_attribute() {
    let (mut client, mut server) = plain_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let items = [
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(8, CLOCK, 2), access: None },
        // Not writable: the register is read-only.
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None },
    ];
    let new_time = dlms_cosem_rs::axdr::DateTime::from_civil(2027, 1, 2, 3, 4, 5, 60);
    let values = [Data::DateTime(new_time), Data::DoubleLongUnsigned(1)];

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.set_request_with_list(&items, &values, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ResultList(results) => {
            let got: Vec<_> = results.iter().map(|r| r.unwrap()).collect();
            assert_eq!(got, [DataAccessResult::Success, DataAccessResult::ReadWriteDenied]);
        }
        other => panic!("expected one result per attribute, got {other:?}"),
    }
    assert_eq!(server.store().time, new_time, "the writable one took effect");
    assert_eq!(server.store().energy_wh, 12_345_678, "and the refused one did not");
}

/// The ACCESS service mixes a read, a write and an invocation into one exchange, and
/// answers them positionally.
#[test]
fn one_access_exchange_reads_writes_and_invokes() {
    let (mut client, mut server) = plain_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let new_time = dlms_cosem_rs::axdr::DateTime::from_civil(2027, 3, 4, 5, 6, 7, 60);
    let items = [
        AccessItem::Get { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None },
        AccessItem::Set {
            descriptor: AttributeDescriptor::new(8, CLOCK, 2),
            access: None,
            value: Data::DateTime(new_time),
        },
        AccessItem::Action { descriptor: MethodDescriptor::new(70, BREAKER, 1), parameters: None },
        // And one the association may not touch, to prove a refusal costs its own slot.
        AccessItem::Get { descriptor: AttributeDescriptor::new(1, SECRET_LOG, 2), access: None },
    ];

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.access_request(&items, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Access { data, results } => {
            let values: Vec<_> = data.iter().map(|d| d.unwrap()).collect();
            let outcomes: Vec<_> = results.iter().map(|r| r.unwrap()).collect();
            assert_eq!(values.len(), 4, "one data slot per item, whatever it produced");
            assert_eq!(outcomes.len(), 4);
            assert_eq!(values[0].as_u64(), Some(12_345_678));
            assert_eq!(
                outcomes,
                [
                    AccessResponseSpecification::Get(DataAccessResult::Success),
                    AccessResponseSpecification::Set(DataAccessResult::Success),
                    AccessResponseSpecification::Action(dlms_cosem_rs::xdlms::ActionResult::Success),
                    AccessResponseSpecification::Get(DataAccessResult::ReadWriteDenied),
                ]
            );
            assert!(matches!(values[3], Data::Null), "a refused read still occupies its slot");
        }
        other => panic!("expected an ACCESS response, got {other:?}"),
    }
    assert_eq!(server.store().time, new_time);
    assert!(!server.store().breaker_closed, "the breaker was opened by the same exchange");
}

/// An ACCESS exchange inside a ciphered association.
///
/// `access-request` and `access-response` have no `glo-` tag of their own, so the only
/// way to protect them is `general-glo-ciphering` — the general wrapper that carries the
/// sender's system title and takes any APDU. That is what the `general-protection`
/// conformance bit is for, and a stack that never implements the wrapper cannot use
/// ACCESS on a ciphered link at all, however completely it decodes the service.
#[test]
fn a_ciphered_access_exchange_travels_inside_general_glo_ciphering() {
    let (mut client, mut server) = ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let items = [AccessItem::Get { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None }];
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.access_request(&items, &mut c).unwrap();
    assert_eq!(c[0], 0xDB, "general-glo-ciphering, because access-request has no glo- tag");
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(s[0], 0xDB, "and so does the answer");

    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Access { data, results } => {
            assert_eq!(data.iter().next().unwrap().unwrap().as_u64(), Some(12_345_678));
            assert_eq!(
                results.iter().next().unwrap().unwrap(),
                AccessResponseSpecification::Get(DataAccessResult::Success)
            );
        }
        other => panic!("expected an ACCESS response, got {other:?}"),
    }
}

/// The system title in a `general-glo-ciphering` header travels in the clear and is not
/// authenticated, so it is a hint about which key to try and never a statement of
/// identity. A frame naming somebody else is refused before a key is touched.
#[test]
fn a_general_ciphering_frame_from_another_system_title_is_refused() {
    let (mut client, mut server) = ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let items = [AccessItem::Get { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None }];
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.access_request(&items, &mut c).unwrap();
    // Rewrite the originator's title. The tag would fail too, but this must be caught
    // first — before a key is looked up, let alone used.
    c[3] ^= 0xFF;
    let m = server.handle(&c[..n], &mut s).unwrap();
    let mut plain = [0u8; 512];
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::DecipheringError);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// An answer must be to the question that was asked.
///
/// On a shared link — an RS-485 bus, a concentrator multiplexing several meters — a
/// response carrying somebody else's invoke id is a reading attributed to the wrong
/// request, and nothing downstream can tell. The check is cheap and the failure it
/// prevents is silent.
#[test]
fn a_response_under_the_wrong_invoke_id_is_refused() {
    let (mut client, mut server) = plain_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    // Byte 2 of a get-response is the invoke-id-and-priority. Move it to another
    // invocation, leaving everything else exactly as the server built it.
    assert_eq!(s[0], 0xC4);
    s[2] ^= 0x01;
    assert_eq!(client.handle_response(&s[..m], &mut plain).unwrap_err().kind, ErrorKind::UnexpectedMessage);
}

/// A client that ignores the PDU size the server announced is told so by name, not with
/// a generic refusal it cannot act on.
#[test]
fn an_oversized_request_is_refused_as_pdu_too_long() {
    let (_, mut server) = plain_pair();
    let mut s = [0u8; 512];
    let oversized = vec![0xC0u8; 2048];
    let m = server.handle(&oversized, &mut s).unwrap();
    let dlms_cosem_rs::Apdu::ExceptionResponse(e) = dlms_cosem_rs::Apdu::from_bytes(&s[..m]).unwrap() else {
        panic!("expected an exception response")
    };
    assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::PduTooLong);
}

/// A refusal names the context the client asked for. A client that proposed a ciphered
/// association and reads "logical name, plain" in the answer cannot tell a refusal from
/// a downgrade attempt.
#[test]
fn a_refusal_answers_in_the_context_that_was_proposed() {
    let (mut client, mut server) = ciphered_pair_with_plain_server();
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let n = client.associate_request(&mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let aare = dlms_cosem_rs::acse::Aare::from_bytes(&s[..m]).unwrap();
    assert!(!aare.is_accepted());
    assert_eq!(
        aare.application_context,
        Some(dlms_cosem_rs::acse::ApplicationContext::LogicalNameCiphered),
        "the refusal is about the association the client asked for"
    );
}

/// A blocked SET carries its selective-access descriptor in the **first** block and needs
/// it at the **last**, so it has to survive in between. A server that dropped it would
/// hand the store a write with no selector — which for a profile or an array manager is
/// a write that lands somewhere else and says nothing about it.
#[test]
fn a_selective_access_descriptor_survives_a_blocked_write() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let value = blob(900);
    let mut params = [0u8; 64];
    let selector =
        dlms_cosem_rs::cosem::EntryDescriptor::entries(3, 7).to_selective_access(&mut params).unwrap();

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut sender =
        client.set_transfer(AttributeDescriptor::new(18, IMAGE, 2), Some(selector), &value).unwrap();
    assert!(sender.blocks() > 1);
    loop {
        let n = client.next_block_request(&mut sender, &mut c).unwrap();
        let m = server.handle(&c[..n], &mut s).unwrap();
        match client.handle_response(&s[..m], &mut plain).unwrap() {
            Response::BlockAccepted { .. } => {}
            Response::Ok => break,
            other => panic!("unexpected response: {other:?}"),
        }
    }
    assert_eq!(
        server.store().last_write_selector,
        Some(2),
        "the selector reached the store with the last block, not just the first"
    );
    assert_eq!(server.store().image.len(), 900);
}

/// A write the association may not make is refused at the first block, not after the
/// server has buffered a kilobyte for it. A client with no rights should not be able to
/// make a meter hold memory on its behalf.
#[test]
fn a_blocked_write_to_a_read_only_attribute_is_refused_before_it_is_buffered() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let value = blob(900);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    // The register is read-only in this meter.
    let mut sender = client.set_transfer(AttributeDescriptor::new(3, ENERGY, 2), None, &value).unwrap();
    let n = client.next_block_request(&mut sender, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::ReadWriteDenied)
    );
    assert!(!server.is_block_transfer_in_progress(), "and nothing is being held for it");
}

/// A block out of order is refused rather than concatenated. A fragment written into the
/// wrong place usually still decodes — into a value that is simply wrong, and this one is
/// a *write*.
#[test]
fn a_blocked_write_with_a_gap_is_refused_rather_than_concatenated() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let value = blob(900);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut sender = client.set_transfer(AttributeDescriptor::new(18, IMAGE, 2), None, &value).unwrap();

    // First block, accepted.
    let n = client.next_block_request(&mut sender, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert!(matches!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::BlockAccepted { number: 1 }
    ));

    // Second block, built and then renumbered to three: the byte after the last-block
    // flag is the top of the four-byte block number, so the low byte is the one to move.
    let n = client.next_block_request(&mut sender, &mut c).unwrap();
    // set-request-with-datablock: tag, choice 3, invoke id, last-block flag, then the
    // four-byte block number — so byte 7 is its least significant byte.
    assert_eq!((c[0], c[1]), (0xC1, 0x03));
    assert_eq!(c[7], 2, "this is the second block before it is tampered with");
    c[7] = 3;
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::DataBlockNumberInvalid)
    );
    assert!(!server.is_block_transfer_in_progress(), "and the transfer is abandoned");
    assert!(server.store().image.is_empty(), "nothing was written");
}

/// When the association *did* negotiate `general-protection`, the server's refusal is
/// protected like everything else rather than sent bare.
///
/// `exception-response` has no ciphered tag, so the only way to protect one is the
/// general wrapper. Both halves of that matter: a server that could protect it and did
/// not would leak the shape of its refusals, and a client that could not read the
/// protected form would be back to guessing.
#[test]
fn a_refusal_is_protected_when_the_association_can_protect_it() {
    let (mut client, mut server) = ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    assert!(
        client
            .negotiated()
            .unwrap()
            .negotiated_conformance
            .contains(dlms_cosem_rs::xdlms::Conformance::GENERAL_PROTECTION),
        "both defaults offer the general wrapper"
    );

    // A request longer than the server said it would accept. It never reaches a decoder.
    let mut s = [0u8; 4096];
    let mut plain = [0u8; 512];
    let oversized = vec![0xC8u8; 2048];
    let m = server.handle(&oversized, &mut s).unwrap();
    assert_eq!(s[0], 0xDB, "the refusal is wrapped in general-glo-ciphering");

    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::PduTooLong);
        }
        other => panic!("expected a protected exception response, got {other:?}"),
    }
}

/// A batch of methods answers per item, so one refusal does not lose the rest.
///
/// That matters more for ACTION than for a read: a batch that opened a breaker and then
/// hit a method it may not invoke would otherwise report only the failure, and nothing
/// would say the breaker had moved.
#[test]
fn a_batch_of_methods_answers_one_outcome_per_method() {
    let (mut client, mut server) = plain_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let descriptors = [
        MethodDescriptor::new(70, BREAKER, 1), // open the breaker: allowed
        MethodDescriptor::new(3, ENERGY, 1),   // reset the register: allowed, returns a value
        MethodDescriptor::new(8, CLOCK, 1),    // not an invocable method on this meter
    ];
    let parameters = [None, None, None];

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.action_request_with_list(&descriptors, &parameters, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ActionResults(results) => {
            let got: Vec<_> = results.iter().map(|r| r.unwrap()).collect();
            assert_eq!(got.len(), 3);
            assert!(got[0].result.is_success());
            assert!(got[0].return_parameters.is_none(), "opening a breaker returns nothing");
            assert!(got[1].result.is_success());
            assert_eq!(
                got[1].return_parameters.unwrap().value().unwrap().as_u64(),
                Some(0),
                "the reset returned the new register value"
            );
            assert_eq!(got[2].result, dlms_cosem_rs::xdlms::ActionResult::ReadWriteDenied);
        }
        other => panic!("expected one outcome per method, got {other:?}"),
    }
    assert!(!server.store().breaker_closed, "the breaker moved even though a later method failed");
    assert_eq!(server.store().energy_wh, 0);
}

/// A batched write whose values together exceed the PDU size.
///
/// The attribute list rides in the first block and is needed at the last, and what the
/// blocks carry is the encoded `value-list` field — count prefix included — which is the
/// same rule a blocked *response* follows.
#[test]
fn a_batched_write_larger_than_the_pdu_size_completes_over_block_transfer() {
    let (mut client, mut server) = small_pdu_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let new_time = dlms_cosem_rs::axdr::DateTime::from_civil(2027, 5, 6, 7, 8, 9, 60);
    let big: Vec<u8> = (0..900).map(|i| (i % 251) as u8).collect();
    let items = [
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(8, CLOCK, 2), access: None },
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(18, IMAGE, 2), access: None },
    ];
    let values = [Data::DateTime(new_time), Data::OctetString(&big)];

    let mut encoded = vec![0u8; 2048];
    let n =
        ClientSession::<RustCryptoProvider<FixedRandom>>::encode_value_list(&values, &mut encoded).unwrap();
    encoded.truncate(n);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let mut list_scratch = [0u8; 256];
    let mut sender = client.set_transfer_with_list(&items, &encoded, &mut list_scratch).unwrap();
    assert!(sender.blocks() > 1);

    loop {
        let n = client.next_block_request(&mut sender, &mut c).unwrap();
        assert!(n <= 256, "a block must fit the negotiated PDU size");
        let m = server.handle(&c[..n], &mut s).unwrap();
        match client.handle_response(&s[..m], &mut plain).unwrap() {
            Response::BlockAccepted { .. } => {}
            Response::ResultList(results) => {
                let got: Vec<_> = results.iter().map(|r| r.unwrap()).collect();
                assert_eq!(got, [DataAccessResult::Success, DataAccessResult::Success]);
                break;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
    assert_eq!(server.store().time, new_time);
    assert_eq!(server.store().image, big, "and the large value arrived whole");
}

/// A store that reports success and writes nothing is answered with a refusal, not with a
/// malformed response.
///
/// Every real store has this bug once — a branch that returns `Ok` before it encodes. The
/// response it would otherwise produce is a `get-data-result` choice byte with no value
/// behind it: not a wrong reading but an *undecodable* one, which at the far end is a
/// parse error the client cannot attribute to any particular read. Naming it as that
/// item's failure keeps the exchange readable and points at the object.
#[test]
fn a_store_that_reports_success_without_writing_is_refused_rather_than_malformed() {
    let (mut client, mut server) = plain_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    // A single read.
    let n = client.get_request(AttributeDescriptor::new(1, BROKEN, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut plain).unwrap(),
        Response::DataError(DataAccessResult::OtherReason)
    );

    // A batched read: the broken object costs its own slot and the good one still reads.
    let items = [
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(1, BROKEN, 2), access: None },
        AttributeDescriptorWithSelection { descriptor: AttributeDescriptor::new(3, ENERGY, 2), access: None },
    ];
    let n = client.get_request_with_list(&items, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::DataList(results) => {
            let got: Vec<_> = results.iter().map(|r| r.unwrap()).collect();
            assert_eq!(got[0], GetDataResult::Error(DataAccessResult::OtherReason));
            assert_eq!(got[1].value().unwrap().as_u64(), Some(12_345_678));
        }
        other => panic!("expected a list, got {other:?}"),
    }

    // A method that claims a return value and writes none.
    let n = client.action_request(MethodDescriptor::new(1, BROKEN, 1), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ActionResult { result, value } => {
            assert_eq!(result, dlms_cosem_rs::xdlms::ActionResult::OtherReason);
            assert!(value.is_none());
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And the same method inside a batch, where a malformed entry would shift every
    // result after it onto the wrong method.
    let descriptors = [MethodDescriptor::new(1, BROKEN, 1), MethodDescriptor::new(70, BREAKER, 1)];
    let n = client.action_request_with_list(&descriptors, &[None, None], &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ActionResults(results) => {
            let got: Vec<_> = results.iter().map(|r| r.unwrap()).collect();
            assert_eq!(got[0].result, dlms_cosem_rs::xdlms::ActionResult::OtherReason);
            assert!(got[1].result.is_success(), "and the method after it still ran");
        }
        other => panic!("expected one outcome per method, got {other:?}"),
    }
    assert!(!server.store().breaker_closed);
}

/// A device whose counter went backwards can recover, and the exchange tells it how.
///
/// This is the whole point of `invocation-counter-error` carrying a value. A meter that
/// restarted from stale storage — or a head-end that lost its own record — sends a
/// counter the peer has already seen. Told only "deciphering error" it retries the same
/// frame forever and needs a site visit; told the value expected next it can move its
/// counter forward **deliberately** and carry on.
///
/// Deliberately is the operative word: the crate never resynchronises on its own, because
/// an exception response is unprotected and anyone can forge one. Moving a counter is the
/// caller's decision, and moving it *backwards* is what burns a key.
#[test]
fn a_client_whose_counter_went_backwards_can_resynchronise_from_the_refusal() {
    let (mut client, mut server) = ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    // A few genuine reads, so the server's window has moved on.
    for _ in 0..3 {
        let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
        let m = server.handle(&c[..n], &mut s).unwrap();
        assert!(matches!(client.handle_response(&s[..m], &mut plain).unwrap(), Response::Data(_)));
    }

    // Now the client restarts from a stale value — the failure mode the API is shaped to
    // make visible, here forced on purpose.
    client.set_invocation_counter(1);
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();

    let expected = match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Exception(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::InvocationCounterError);
            e.expected_invocation_counter.expect("the refusal names the value to move to")
        }
        other => panic!("expected a counter error, got {other:?}"),
    };

    // Acting on it is the caller's choice, and one call.
    client.set_invocation_counter(expected);
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::Data(v) => assert_eq!(v.as_u64(), Some(12_345_678)),
        other => panic!("the association must be usable again, got {other:?}"),
    }
}
