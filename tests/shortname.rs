//! A whole short-name association, client against server, in one process.
//!
//! Short-name referencing is the addressing mode a pre-logical-name meter speaks: an
//! attribute is a sixteen-bit number rather than a class, an OBIS code and an index. The
//! *services* differ — `read` and `write` instead of GET, SET and ACTION — but nothing
//! below them does, and these tests exist to hold that line: the same store, the same
//! access control, the same audit trail, the same protection.

#![cfg(feature = "sn")]

mod support;

use dlms_cosem_rs::acse::{AuthMechanism, Referencing};
use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::client::{AssociationStep, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::codec::{Decode, ErrorKind};
use dlms_cosem_rs::cosem::{ShortName, ShortNameTarget};
use dlms_cosem_rs::security::{
    FixedRandom, KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle,
};
use dlms_cosem_rs::server::{AuditEvent, Server, ServerConfig};
use dlms_cosem_rs::xdlms::{Conformance, DataAccessResult, ReadResult, VariableAccess, WriteResult};
use support::{ENERGY, SHORT_NAMES, TestMeter};

const GUEK: [u8; 16] = [0x11; 16];
const GAK: [u8; 16] = [0x22; 16];
const CLIENT_TITLE: SystemTitle = SystemTitle::new(*b"CLI\0\0\0\0\x01");
const SERVER_TITLE: SystemTitle = SystemTitle::new(*b"MMM\0\0\0\0\x02");

type Client = ClientSession<RustCryptoProvider<FixedRandom>, 1024>;
type Meter = Server<TestMeter, RustCryptoProvider<FixedRandom>, 4096>;

/// What a short-name client and meter both have to be told: the referencing mode, and a
/// conformance block naming the services that mode actually has.
fn conformance() -> Conformance {
    Conformance::READ
        | Conformance::WRITE
        | Conformance::UNCONFIRMED_WRITE
        | Conformance::BLOCK_TRANSFER_WITH_GET_OR_READ
        | Conformance::MULTIPLE_REFERENCES
}

fn pair() -> (Client, Meter) {
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            referencing: Referencing::ShortName,
            conformance: conformance(),
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig {
            referencing: Referencing::ShortName,
            conformance: conformance(),
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );
    (client, server)
}

/// The same pair with an authenticated and encrypted association, because short-name
/// referencing is orthogonal to protection and a stack that only ciphered its modern
/// half would be a stack nobody could use on the meters that need SN.
fn ciphered_pair() -> (Client, Meter) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let client = ClientSession::new(
        ClientConfig {
            client_sap: 0x30,
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            referencing: Referencing::ShortName,
            conformance: conformance() | Conformance::GENERAL_PROTECTION,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    );
    let server = Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            referencing: Referencing::ShortName,
            conformance: conformance() | Conformance::GENERAL_PROTECTION,
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xB2)),
    );
    (client, server)
}

fn associate(client: &mut Client, server: &mut Meter) -> AssociationStep {
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

/// The short name of `ENERGY`'s `value` attribute, computed the way a client would after
/// reading the meter's object list.
fn energy_value() -> u16 {
    SHORT_NAMES[0].attribute(2).expect("Register has three attributes")
}

#[test]
fn a_short_name_association_opens_and_reads_a_register() {
    let (mut client, mut server) = pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    // The negotiated vaa-name is what tells a client which mode it got.
    assert_eq!(
        client.negotiated().unwrap().vaa_name,
        dlms_cosem_rs::xdlms::CURRENT_ASSOCIATION_SN,
        "a short-name association reports the association object's base name"
    );

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.read_request(&[VariableAccess::VariableName(energy_value())], &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ReadResults(results) => {
            let mut it = results.iter();
            match it.next().unwrap().unwrap() {
                ReadResult::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
                other => panic!("expected the reading: {other:?}"),
            }
            assert!(it.next().is_none(), "one entry, one result");
        }
        other => panic!("expected read results: {other:?}"),
    }
}

/// The point of `read` taking a list: one round trip, one result per entry, in order —
/// and a refused entry occupies its own slot rather than losing the batch. Exactly the
/// property the logical-name `with-list` forms have, which is not an accident: it is the
/// same dispatch underneath.
#[test]
fn several_entries_are_answered_positionally_and_a_refusal_keeps_its_slot() {
    let (mut client, mut server) = pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 1024];

    let items = [
        VariableAccess::VariableName(energy_value()),
        // The object nobody may read.
        VariableAccess::VariableName(SHORT_NAMES[4].attribute(2).unwrap()),
        // A name that belongs to no object at all.
        VariableAccess::VariableName(0x9000),
        // The clock, which does exist.
        VariableAccess::VariableName(SHORT_NAMES[1].attribute(2).unwrap()),
    ];
    let n = client.read_request(&items, &mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let Response::ReadResults(results) = client.handle_response(&s[..m], &mut plain).unwrap() else {
        panic!("expected read results");
    };
    let answers: Vec<ReadResult<'_>> = results.iter().map(Result::unwrap).collect();
    assert_eq!(answers.len(), 4, "one answer per entry, whatever happened to each");
    assert!(matches!(answers[0], ReadResult::Data(_)));
    assert_eq!(answers[1], ReadResult::Error(DataAccessResult::ReadWriteDenied));
    assert_eq!(answers[2], ReadResult::Error(DataAccessResult::ObjectUndefined));
    assert!(matches!(answers[3], ReadResult::Data(Data::DateTime(_))));
}

/// Access rights are the framework's, and a short-name request goes through the same
/// gate as a logical-name one: the store is never asked for an object this association
/// may not touch, and the refusal reaches the audit trail all the same.
#[test]
fn access_control_and_the_audit_trail_are_the_same_gate_for_both_modes() {
    let (mut client, mut server) = pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let n = client
        .read_request(&[VariableAccess::VariableName(SHORT_NAMES[4].attribute(2).unwrap())], &mut c)
        .unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let _ = client.handle_response(&s[..m], &mut plain).unwrap();

    let denied =
        server.store().trail.iter().any(|e| {
            matches!(e, AuditEvent::AttributeRead { outcome: DataAccessResult::ReadWriteDenied, .. })
        });
    assert!(denied, "a refusal a short-name client caused must reach the audit trail");
}

#[test]
fn a_short_name_write_lands_and_a_forbidden_one_is_refused() {
    let (mut client, mut server) = pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];

    let clock_time = SHORT_NAMES[1].attribute(2).unwrap();
    let new_time = dlms_cosem_rs::axdr::DateTime::from_civil(2031, 3, 4, 5, 6, 7, 60);
    let n = client
        .write_request(
            &[VariableAccess::VariableName(clock_time), VariableAccess::VariableName(energy_value())],
            &[Data::DateTime(new_time), Data::DoubleLongUnsigned(1)],
            &mut c,
        )
        .unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let Response::WriteResults(results) = client.handle_response(&s[..m], &mut plain).unwrap() else {
        panic!("expected write results");
    };
    let answers: Vec<WriteResult> = results.iter().map(Result::unwrap).collect();
    assert_eq!(answers[0], WriteResult::Success);
    assert_eq!(
        answers[1],
        WriteResult::Error(DataAccessResult::ReadWriteDenied),
        "the register is read-only, and one refused write must not lose the other"
    );
    assert_eq!(server.store().time, new_time);
}

/// An unconfirmed write is a different service, not a flag: the server produces **no
/// reply at all**, and a caller that waited for one would wait for ever.
#[test]
fn an_unconfirmed_write_produces_no_reply() {
    let (mut client, mut server) = pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];

    let clock_time = SHORT_NAMES[1].attribute(2).unwrap();
    let new_time = dlms_cosem_rs::axdr::DateTime::from_civil(2032, 1, 1, 0, 0, 0, 0);
    let n = client
        .unconfirmed_write_request(
            &[VariableAccess::VariableName(clock_time)],
            &[Data::DateTime(new_time)],
            &mut c,
        )
        .unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(m, 0, "an unconfirmed write is unconfirmed");
    assert_eq!(server.store().time, new_time, "and it still happened");
}

/// Short-name referencing spells ACTION as a *write to a method's short name*. The
/// breaker is the object where getting that wrong matters.
#[test]
fn writing_a_methods_short_name_invokes_it() {
    let (mut client, mut server) = pair();
    associate(&mut client, &mut server);
    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    assert!(server.store().breaker_closed);

    let disconnect = SHORT_NAMES[2].method(1).expect("the breaker's first method");
    let n = client
        .write_request(&[VariableAccess::VariableName(disconnect)], &[Data::Integer(0)], &mut c)
        .unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let Response::WriteResults(results) = client.handle_response(&s[..m], &mut plain).unwrap() else {
        panic!("expected write results");
    };
    assert_eq!(results.iter().next().unwrap().unwrap(), WriteResult::Success);
    assert!(!server.store().breaker_closed, "the breaker moved");
    assert_eq!(server.store().breaker_operations, 1);
}

/// A load profile is the only thing anybody reads, and it never fits. Short-name block
/// transfer is a `data-block-result` inside the read response, continued by a
/// `block-number-access` entry rather than by a service of its own.
#[test]
fn a_profile_larger_than_the_pdu_size_is_read_over_short_name_block_transfer() {
    let (mut client, mut server) = pair();
    // A small PDU size on both sides, so the profile has to be blocked.
    client.set_invocation_counter(0);
    associate(&mut client, &mut server);

    let mut c = [0u8; 2048];
    let mut s = [0u8; 2048];
    let mut plain = [0u8; 2048];
    let mut storage = [0u8; 8192];
    let mut gathered = 0usize;

    let profile = SHORT_NAMES[3].attribute(2).unwrap();
    let mut n = client.read_request(&[VariableAccess::VariableName(profile)], &mut c).unwrap();
    let mut blocks = 0;
    loop {
        blocks += 1;
        assert!(blocks < 200, "the transfer must converge");
        let m = server.handle(&c[..n], &mut s).unwrap();
        let Response::ReadResults(results) = client.handle_response(&s[..m], &mut plain).unwrap() else {
            panic!("expected read results");
        };
        match results.iter().next().unwrap().unwrap() {
            ReadResult::Block { last_block, block_number, raw_data } => {
                storage[gathered..gathered + raw_data.len()].copy_from_slice(raw_data);
                gathered += raw_data.len();
                if last_block {
                    break;
                }
                n = client.read_next_block_request(block_number, &mut c).unwrap();
            }
            // A profile that fits in one PDU would come back whole, which would mean the
            // test is not testing what it says.
            other => panic!("the profile must not fit in one APDU: {other:?}"),
        }
    }
    assert!(blocks > 1, "more than one block, or the test proves nothing");

    let value = Data::from_bytes_in(&storage[..gathered]).expect("the concatenation decodes");
    assert_eq!(value.as_array().unwrap().len(), support::PROFILE_ROWS, "and it is the whole profile");
}

/// The referencing mode is a property of the *association*, agreed once in the
/// application context. A short-name service sent into a logical-name association asks a
/// question the peer never agreed to answer.
#[test]
fn the_referencing_mode_is_agreed_once_and_then_binding() {
    // A client that proposes short names to a logical-name meter is refused outright.
    let mut client = ClientSession::<_, 1024>::new(
        ClientConfig {
            referencing: Referencing::ShortName,
            conformance: conformance(),
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
    );
    let mut server: Meter = Server::new(
        ServerConfig { referencing: Referencing::LogicalName, ..Default::default() },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );
    assert!(
        matches!(associate(&mut client, &mut server), AssociationStep::Rejected { .. }),
        "a meter that names objects the other way must refuse"
    );

    // And a logical-name client cannot reach for a short-name service.
    let (mut ln_client, _) = {
        let c = ClientSession::<_, 1024>::new(
            ClientConfig::default(),
            RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
        );
        (c, ())
    };
    let mut out = [0u8; 128];
    assert_eq!(
        ln_client.read_request(&[VariableAccess::VariableName(0x0028)], &mut out).unwrap_err().kind,
        ErrorKind::UnexpectedMessage,
    );
}

/// Protection is orthogonal to addressing: the same ciphering, the same replay window,
/// the same high-level-security handshake, over `read` instead of GET.
#[test]
fn a_ciphered_short_name_association_reads_a_register() {
    let (mut client, mut server) = ciphered_pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);

    let mut c = [0u8; 512];
    let mut s = [0u8; 512];
    let mut plain = [0u8; 512];
    let n = client.read_request(&[VariableAccess::VariableName(energy_value())], &mut c).unwrap();
    assert_eq!(c[0], 0x25, "a ciphered read request is glo-readRequest");

    let m = server.handle(&c[..n], &mut s).unwrap();
    assert_eq!(s[0], 0x2C, "and the answer is glo-readResponse");
    match client.handle_response(&s[..m], &mut plain).unwrap() {
        Response::ReadResults(results) => match results.iter().next().unwrap().unwrap() {
            ReadResult::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
            other => panic!("expected the reading: {other:?}"),
        },
        other => panic!("expected read results: {other:?}"),
    }

    // The replay control is the same control.
    let replayed = c[..n].to_vec();
    let m = server.handle(&replayed, &mut s).unwrap();
    match dlms_cosem_rs::Apdu::from_bytes(&s[..m]).unwrap() {
        dlms_cosem_rs::Apdu::ExceptionResponse(e) => {
            assert_eq!(e.service_error, dlms_cosem_rs::xdlms::ServiceError::InvocationCounterError);
        }
        other => panic!("a replay must be refused by name: {other:?}"),
    }
}

/// The mapping is the store's, and the framework only does arithmetic it can justify.
#[test]
fn a_name_between_two_objects_belongs_to_neither() {
    let table = SHORT_NAMES;
    // Between the register's last attribute (0x0038) and its method block (0x0050).
    assert_eq!(dlms_cosem_rs::cosem::sn::resolve(table, 0x0040), None);
    // Past the clock's nine attributes.
    assert_eq!(dlms_cosem_rs::cosem::sn::resolve(table, 0x0148), None);
    // The clock's methods are not addressable, because this meter did not say where they
    // start — which is the answer that keeps a guess off the wire.
    assert_eq!(table[1].method(1), None);

    // And an object that does resolve, resolves to the right thing.
    assert_eq!(
        dlms_cosem_rs::cosem::sn::resolve(table, 0x0128),
        Some(ShortNameTarget::Attribute { class_id: 8, logical_name: support::CLOCK, attribute_id: 6 })
    );
}

/// A build that left the feature out must not be able to *configure* a mode it cannot
/// serve — an association that opens and then answers `service-not-supported` to
/// everything is worse than one that was refused. The mirror of that check, in a build
/// that does have the feature, is that the configuration is honoured.
#[test]
fn a_mode_this_build_can_serve_is_the_one_it_accepts() {
    let (mut client, mut server) = pair();
    assert_eq!(associate(&mut client, &mut server), AssociationStep::Established);
    assert_eq!(server.state(), dlms_cosem_rs::server::ServerState::Associated);
}

/// A `ShortName` built by hand agrees with the arithmetic the meter's own table uses.
#[test]
fn the_client_side_arithmetic_matches_the_servers_table() {
    let energy = ShortName::new(0x0028, 3, ENERGY, 3).with_methods(0x28, 1);
    assert_eq!(energy, SHORT_NAMES[0]);
    assert_eq!(energy.attribute(1), Some(0x0028));
    assert_eq!(energy.attribute(2), Some(0x0030));
    assert_eq!(energy.method(1), Some(0x0050));
}
