//! Is every encoder the inverse of its decoder?
//!
//! `tests/robustness.rs` starts from bytes and asks whether a decoder survives them. That
//! can only reach the variants a decoder produces, so it is blind to the opposite defect:
//! **a variant that encodes and never decodes back**, or decodes back as something else.
//! A missing arm, a field written and not read, an `OPTIONAL` whose usage flag is
//! forgotten — none of them can be seen from the byte side, because no byte string the
//! harness generates will ever exercise the arm that is not there.
//!
//! So this test starts from *values*. Every variant of every service is constructed
//! explicitly rather than sampled, because sampling a variant space misses the one
//! nobody thought of; the payloads inside them are seeded-random, because that is where
//! sampling helps.
//!
//! Two properties per value, and the second is the one that matters:
//!
//! 1. `decode(encode(v)) == v` — the value survives.
//! 2. `encode(decode(encode(v))) == encode(v)` — and so do the *bytes*. A codec can pass
//!    the first and fail this one by normalising something, which on the wire means two
//!    stacks that agree about a value and disagree about its encoding.
//!
//! This is deliberately not `proptest`: the generator is seeded and hand-written, like
//! the one in `robustness.rs`, so a failure reproduces from the seed alone and the
//! `no_std` core gains no dependency.

use dlms_cosem_rs::acse::{
    Aare, Aarq, ApplicationContext, AssociationResult, AuthMechanism, Diagnostic, ReleaseReason, Rlre, Rlrq,
    UserDiagnostic,
};
use dlms_cosem_rs::axdr::{ClockStatus, Data, DateTime};
use dlms_cosem_rs::codec::{Decode, Encode, SliceWriter, Writer};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::transport::hdlc::{Address, Control, Frame, decode_frame};
use dlms_cosem_rs::xdlms::{
    AccessRequest, AccessRequestSpecification, AccessResponse, AccessResponseSpecification, ActionRequest,
    ActionResponse, ActionResponseWithOptionalData, ActionResult, Apdu, AttributeDescriptor,
    AttributeDescriptorWithSelection, BlockControl, Conformance, DataAccessResult, DataBlockG, DataBlockSA,
    ExceptionResponse, GeneralBlockTransfer, GetDataResult, GetRequest, GetResponse, InitiateRequest,
    InitiateResponse, InvokeId, List, LongInvokeId, MethodDescriptor, OptionalDateTime, SelectiveAccess,
    ServiceError, SetRequest, SetResponse, StateError,
};

/// The same seeded generator `robustness.rs` uses: enough randomness to shake a codec,
/// small enough that a failure reproduces from the seed.
struct Rng(u64);

impl Rng {
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        ((x.wrapping_mul(0x2545_F491_4F6C_DD1D)) >> 32) as u32
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { self.next_u32() as usize % n }
    }

    fn byte(&mut self) -> u8 {
        self.next_u32() as u8
    }
}

/// Encode into a fresh buffer, returning the bytes.
fn encoded<E: Encode>(value: &E) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    let mut w = SliceWriter::new(&mut buf);
    value.encode(&mut w).expect("encoding into 8 KiB must succeed");
    let n = w.written();
    // `encoded_len` must agree with what `encode` actually wrote, or every buffer sized
    // from it is sized wrongly.
    assert_eq!(value.encoded_len(), n, "encoded_len disagrees with encode");
    buf.truncate(n);
    buf
}

/// Both round-trip properties, for one value.
fn round_trips<'a, T>(value: &T, what: &str) -> Vec<u8>
where
    T: Encode + Decode<'a> + PartialEq + core::fmt::Debug + 'a,
{
    let bytes = encoded(value);
    // The decoded value borrows `bytes`, so it is compared inside this scope and the
    // bytes are returned for the caller to keep.
    let leaked: &'a [u8] = Box::leak(bytes.clone().into_boxed_slice());
    let back = T::from_bytes(leaked).unwrap_or_else(|e| panic!("{what} did not decode back: {e}"));
    assert_eq!(&back, value, "{what} decoded to a different value");
    assert_eq!(encoded(&back), bytes, "{what} re-encoded to different bytes");
    bytes
}

/// A generated `Data` tree, at most `depth` deep.
fn data(rng: &mut Rng, depth: usize, arena: &mut Vec<Vec<u8>>) -> Data<'static> {
    // Leaves only at the bottom, so the tree terminates.
    let choice = if depth == 0 { rng.below(18) } else { rng.below(20) };
    match choice {
        0 => Data::Null,
        1 => Data::Boolean(rng.byte() & 1 == 1),
        2 => Data::DoubleLong(rng.next_u32() as i32),
        3 => Data::DoubleLongUnsigned(rng.next_u32()),
        4 => Data::Integer(rng.byte() as i8),
        5 => Data::Unsigned(rng.byte()),
        6 => Data::Long(rng.next_u32() as i16),
        7 => Data::LongUnsigned(rng.next_u32() as u16),
        8 => Data::Long64((u64::from(rng.next_u32()) << 32 | u64::from(rng.next_u32())) as i64),
        9 => Data::Long64Unsigned(u64::from(rng.next_u32()) << 32 | u64::from(rng.next_u32())),
        10 => Data::Enum(rng.byte()),
        11 => Data::Bcd(rng.byte() as i8),
        12 => Data::Float32(f32::from_bits(rng.next_u32())),
        13 => Data::Float64(f64::from_bits(u64::from(rng.next_u32()) << 32 | u64::from(rng.next_u32()))),
        14 => Data::DateTime(datetime(rng)),
        15 => Data::DontCare,
        16 => {
            let n = rng.below(12);
            let bytes: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            arena.push(bytes);
            let slice: &'static [u8] = Box::leak(arena.last().unwrap().clone().into_boxed_slice());
            Data::OctetString(slice)
        }
        17 => {
            // A visible string has to be text a decoder will hand back unchanged.
            let n = rng.below(8);
            let bytes: Vec<u8> = (0..n).map(|_| b'a' + (rng.byte() % 26)).collect();
            let slice: &'static [u8] = Box::leak(bytes.into_boxed_slice());
            Data::VisibleString(slice)
        }
        18 | 19 => {
            // An array or a structure: build the children's bytes, then wrap them.
            let count = rng.below(4);
            let mut body = Vec::new();
            body.push(if choice == 18 { 0x01 } else { 0x02 });
            body.push(count as u8);
            for _ in 0..count {
                let child = data(rng, depth - 1, arena);
                body.extend_from_slice(&encoded(&child));
            }
            let slice: &'static [u8] = Box::leak(body.into_boxed_slice());
            Data::from_bytes(slice).expect("a tree this generator built must decode")
        }
        _ => Data::Null,
    }
}

/// A date-time with plausible fields, wildcards included — the wildcards are the half a
/// codec is most likely to normalise away.
fn datetime(rng: &mut Rng) -> DateTime {
    let mut dt = DateTime::from_civil(
        2000 + rng.below(80) as u16,
        1 + rng.below(12) as u8,
        1 + rng.below(28) as u8,
        rng.below(24) as u8,
        rng.below(60) as u8,
        rng.below(60) as u8,
        (rng.below(48) as i16 - 24) * 30,
    );
    match rng.below(4) {
        0 => dt.year = 0xFFFF,
        1 => dt.month = 0xFE,
        2 => dt.hundredths = 0xFF,
        _ => {}
    }
    dt.status = ClockStatus(rng.byte());
    dt
}

fn obis(rng: &mut Rng) -> Obis {
    Obis::new(rng.byte(), rng.byte(), rng.byte(), rng.byte(), rng.byte(), rng.byte())
}

fn attribute(rng: &mut Rng) -> AttributeDescriptor {
    AttributeDescriptor::new(rng.next_u32() as u16, obis(rng), rng.byte() as i8)
}

fn method(rng: &mut Rng) -> MethodDescriptor {
    MethodDescriptor::new(rng.next_u32() as u16, obis(rng), rng.byte() as i8)
}

fn invoke(rng: &mut Rng) -> InvokeId {
    InvokeId(rng.byte())
}

#[test]
fn every_generated_data_value_survives_a_round_trip() {
    let mut rng = Rng(0x0DA7_A0DA_7A0D_A7A0);
    let mut arena = Vec::new();
    for _ in 0..4000 {
        let value = data(&mut rng, 3, &mut arena);
        let bytes = encoded(&value);
        let leaked: &'static [u8] = Box::leak(bytes.clone().into_boxed_slice());
        let back = Data::from_bytes(leaked).expect("a value this crate encoded must decode");
        assert_eq!(encoded(&back), bytes, "re-encoding produced different bytes for {value:?}");
    }
}

/// Every wildcard and every deviation, because those are the fields a permissive codec
/// normalises — and a normalised wildcard is a reading on a definite day that nobody
/// reported.
#[test]
fn a_date_time_is_returned_exactly_as_it_arrived() {
    let mut rng = Rng(0xD47E_7113_D47E_7113);
    for _ in 0..2000 {
        let dt = datetime(&mut rng);
        assert_eq!(DateTime::from_bytes(dt.to_bytes()), dt);
    }
    // And the two values that are not points in time survive as themselves.
    assert_eq!(DateTime::from_bytes(DateTime::WILDCARD.to_bytes()), DateTime::WILDCARD);
}

/// Every choice of every logical-name service, constructed by hand.
///
/// Enumerated rather than sampled: a variant space is exactly what sampling misses, and
/// the defect this guards against is an arm that is not there at all.
#[test]
fn every_service_variant_round_trips() {
    let mut rng = Rng(0x5E12_1CE5_5E12_1CE5);
    let mut arena = Vec::new();

    // Two selective-access descriptors: present and absent, because an `OPTIONAL` field
    // is a usage flag and a codec can lose it in only one of the two directions.
    let sa_params = data(&mut rng, 1, &mut arena);
    let sa = SelectiveAccess { selector: 2, parameters: sa_params };

    let d = attribute(&mut rng);
    let m = method(&mut rng);
    let value = data(&mut rng, 2, &mut arena);
    let raw: &'static [u8] = Box::leak(vec![0xAB; 37].into_boxed_slice());

    // The `with-list` forms need pre-encoded element bytes, since `List` is a view.
    let items = [
        AttributeDescriptorWithSelection { descriptor: d, access: None },
        AttributeDescriptorWithSelection { descriptor: attribute(&mut rng), access: Some(sa) },
    ];
    let mut list_bytes = Vec::new();
    for item in &items {
        list_bytes.extend_from_slice(&encoded(item));
    }
    let list_bytes: &'static [u8] = Box::leak(list_bytes.into_boxed_slice());
    let attr_list = List::from_raw(items.len(), list_bytes);

    let values = [data(&mut rng, 1, &mut arena), data(&mut rng, 1, &mut arena)];
    let mut value_bytes = Vec::new();
    for v in &values {
        value_bytes.extend_from_slice(&encoded(v));
    }
    let value_bytes: &'static [u8] = Box::leak(value_bytes.into_boxed_slice());
    let value_list = List::from_raw(values.len(), value_bytes);

    let mut method_bytes = Vec::new();
    let methods = [m, method(&mut rng)];
    for x in &methods {
        method_bytes.extend_from_slice(&encoded(x));
    }
    let method_bytes: &'static [u8] = Box::leak(method_bytes.into_boxed_slice());
    let method_list = List::from_raw(methods.len(), method_bytes);

    let results = [GetDataResult::Data(values[0]), GetDataResult::Error(DataAccessResult::ObjectUndefined)];
    let mut result_bytes = Vec::new();
    for r in &results {
        result_bytes.extend_from_slice(&encoded(r));
    }
    let result_bytes: &'static [u8] = Box::leak(result_bytes.into_boxed_slice());
    let result_list = List::from_raw(results.len(), result_bytes);

    let dar_bytes: &'static [u8] = Box::leak(vec![0u8, 3].into_boxed_slice());
    let dar_list: List<'static, DataAccessResult> = List::from_raw(2, dar_bytes);

    let block_g = DataBlockG { last_block: false, block_number: 9, result: Ok(raw) };
    let block_g_err =
        DataBlockG { last_block: true, block_number: 3, result: Err(DataAccessResult::HardwareFault) };
    let block_sa = DataBlockSA { last_block: true, block_number: 4, raw_data: raw };

    let id = invoke(&mut rng);

    // GET.
    for r in [
        GetRequest::Normal { invoke_id: id, descriptor: d, access: None },
        GetRequest::Normal { invoke_id: id, descriptor: d, access: Some(sa) },
        GetRequest::Next { invoke_id: id, block_number: 0x0102_0304 },
        GetRequest::WithList { invoke_id: id, list: attr_list },
    ] {
        round_trips(&r, "get-request");
    }
    for r in [
        GetResponse::Normal { invoke_id: id, result: GetDataResult::Data(value) },
        GetResponse::Normal {
            invoke_id: id,
            result: GetDataResult::Error(DataAccessResult::ReadWriteDenied),
        },
        GetResponse::WithDataBlock { invoke_id: id, block: block_g },
        GetResponse::WithDataBlock { invoke_id: id, block: block_g_err },
        GetResponse::WithList { invoke_id: id, results: result_list },
    ] {
        round_trips(&r, "get-response");
    }

    // SET — all five request forms and all five response forms.
    for r in [
        SetRequest::Normal { invoke_id: id, descriptor: d, access: None, value },
        SetRequest::Normal { invoke_id: id, descriptor: d, access: Some(sa), value },
        SetRequest::WithFirstDataBlock { invoke_id: id, descriptor: d, access: None, block: block_sa },
        SetRequest::WithFirstDataBlock { invoke_id: id, descriptor: d, access: Some(sa), block: block_sa },
        SetRequest::WithDataBlock { invoke_id: id, block: block_sa },
        SetRequest::WithList { invoke_id: id, descriptors: attr_list, values: value_list },
        SetRequest::WithListAndFirstDataBlock { invoke_id: id, descriptors: attr_list, block: block_sa },
    ] {
        round_trips(&r, "set-request");
    }
    for r in [
        SetResponse::Normal { invoke_id: id, result: DataAccessResult::Success },
        SetResponse::DataBlock { invoke_id: id, block_number: 7 },
        SetResponse::LastDataBlock {
            invoke_id: id,
            result: DataAccessResult::TypeUnmatched,
            block_number: 7,
        },
        SetResponse::LastDataBlockWithList { invoke_id: id, results: dar_list, block_number: 7 },
        SetResponse::WithList { invoke_id: id, results: dar_list },
    ] {
        round_trips(&r, "set-response");
    }

    // ACTION — all six request forms and all four response forms.
    for r in [
        ActionRequest::Normal { invoke_id: id, descriptor: m, parameters: None },
        ActionRequest::Normal { invoke_id: id, descriptor: m, parameters: Some(value) },
        ActionRequest::NextPblock { invoke_id: id, block_number: 11 },
        ActionRequest::WithList { invoke_id: id, descriptors: method_list, parameters: value_list },
        ActionRequest::WithFirstPblock { invoke_id: id, descriptor: m, block: block_sa },
        ActionRequest::WithListAndFirstPblock { invoke_id: id, descriptors: method_list, block: block_sa },
        ActionRequest::WithPblock { invoke_id: id, block: block_sa },
    ] {
        round_trips(&r, "action-request");
    }

    let responses = [
        ActionResponseWithOptionalData { result: ActionResult::Success, return_parameters: None },
        ActionResponseWithOptionalData {
            result: ActionResult::Success,
            return_parameters: Some(GetDataResult::Data(values[0])),
        },
    ];
    let mut response_bytes = Vec::new();
    for r in &responses {
        response_bytes.extend_from_slice(&encoded(r));
    }
    let response_bytes: &'static [u8] = Box::leak(response_bytes.into_boxed_slice());
    let response_list = List::from_raw(responses.len(), response_bytes);

    for r in [
        ActionResponse::Normal { invoke_id: id, response: responses[0] },
        ActionResponse::Normal { invoke_id: id, response: responses[1] },
        ActionResponse::WithPblock { invoke_id: id, block: block_sa },
        ActionResponse::WithList { invoke_id: id, responses: response_list },
        ActionResponse::NextPblock { invoke_id: id, block_number: 2 },
    ] {
        round_trips(&r, "action-response");
    }
}

/// ACCESS, whose response body carries the only `OPTIONAL` field in either body.
///
/// Both states of that flag are constructed on purpose. A codec that wrote the list
/// unconditionally passes every test that only ever sets it — and produces a response
/// every other stack reads one byte out of step.
#[test]
fn the_access_bodies_round_trip_with_the_optional_field_both_ways() {
    let mut rng = Rng(0xACCE_5500_ACCE_5500);
    let mut arena = Vec::new();

    let specs = [
        AccessRequestSpecification::Get(attribute(&mut rng)),
        AccessRequestSpecification::Set(attribute(&mut rng)),
        AccessRequestSpecification::Action(method(&mut rng)),
        AccessRequestSpecification::GetWithSelection(AttributeDescriptorWithSelection {
            descriptor: attribute(&mut rng),
            access: Some(SelectiveAccess { selector: 1, parameters: data(&mut rng, 1, &mut arena) }),
        }),
        AccessRequestSpecification::SetWithSelection(AttributeDescriptorWithSelection {
            descriptor: attribute(&mut rng),
            access: None,
        }),
    ];
    let mut spec_bytes = Vec::new();
    for s in &specs {
        spec_bytes.extend_from_slice(&encoded(s));
    }
    let spec_bytes: &'static [u8] = Box::leak(spec_bytes.into_boxed_slice());
    let spec_list = List::from_raw(specs.len(), spec_bytes);

    let values: Vec<Data<'static>> = (0..specs.len()).map(|_| data(&mut rng, 1, &mut arena)).collect();
    let mut value_bytes = Vec::new();
    for v in &values {
        value_bytes.extend_from_slice(&encoded(v));
    }
    let value_bytes: &'static [u8] = Box::leak(value_bytes.into_boxed_slice());
    let value_list = List::from_raw(values.len(), value_bytes);

    let outcomes = [
        AccessResponseSpecification::Get(DataAccessResult::Success),
        AccessResponseSpecification::Set(DataAccessResult::ReadWriteDenied),
        AccessResponseSpecification::Action(ActionResult::Success),
        AccessResponseSpecification::Get(DataAccessResult::ObjectUndefined),
        AccessResponseSpecification::Set(DataAccessResult::Success),
    ];
    let mut outcome_bytes = Vec::new();
    for o in &outcomes {
        outcome_bytes.extend_from_slice(&encoded(o));
    }
    let outcome_bytes: &'static [u8] = Box::leak(outcome_bytes.into_boxed_slice());
    let outcome_list = List::from_raw(outcomes.len(), outcome_bytes);

    let when = OptionalDateTime(Some(datetime(&mut rng)));
    for date_time in [when, OptionalDateTime(None)] {
        round_trips(
            &AccessRequest {
                long_invoke_id: LongInvokeId::new(0x0012_3456).confirmed(),
                date_time,
                specification: spec_list,
                data: value_list,
            },
            "access-request",
        );
        // The response's specification list is OPTIONAL: both states, on purpose.
        for request_specification in [Some(spec_list), None] {
            round_trips(
                &AccessResponse {
                    long_invoke_id: LongInvokeId::new(7),
                    date_time,
                    request_specification,
                    data: value_list,
                    response_specification: outcome_list,
                },
                "access-response",
            );
        }
    }
}

/// The ACSE APDUs, whose fields are BER and whose optional ones are context tags rather
/// than usage flags — a different way to lose a field, and worth its own pass.
#[test]
fn the_association_apdus_round_trip() {
    let title: &'static [u8] = b"CLI\x00\x00\x00\x00\x01";
    let challenge: &'static [u8] = &[0xAA; 16];
    let user_info: &'static [u8] = &[0x01, 0x00, 0x00, 0x00, 0x06];

    for context in [
        ApplicationContext::LogicalName,
        ApplicationContext::ShortName,
        ApplicationContext::LogicalNameCiphered,
        ApplicationContext::ShortNameCiphered,
        ApplicationContext::Other(9),
    ] {
        for mechanism in
            [None, Some(AuthMechanism::Low), Some(AuthMechanism::HighGmac), Some(AuthMechanism::Other(9))]
        {
            round_trips(
                &Aarq {
                    application_context: Some(context),
                    called_ap_title: None,
                    calling_ap_title: Some(title),
                    calling_ae_qualifier: None,
                    sender_acse_requirements: mechanism.is_some(),
                    mechanism_name: mechanism,
                    calling_authentication_value: mechanism.map(|_| challenge),
                    user_information: Some(user_info),
                },
                "aarq",
            );
        }
    }

    for result in [
        AssociationResult::Accepted,
        AssociationResult::RejectedPermanent,
        AssociationResult::RejectedTransient,
        AssociationResult::Other(7),
    ] {
        for diagnostic in [
            Diagnostic::User(UserDiagnostic::Null),
            Diagnostic::User(UserDiagnostic::AuthenticationFailure),
            Diagnostic::User(UserDiagnostic::Other(99)),
            Diagnostic::Provider(1),
        ] {
            round_trips(
                &Aare {
                    application_context: Some(ApplicationContext::LogicalNameCiphered),
                    result,
                    diagnostic,
                    responding_ap_title: Some(title),
                    responder_acse_requirements: true,
                    mechanism_name: Some(AuthMechanism::HighGmac),
                    responding_authentication_value: Some(challenge),
                    user_information: Some(user_info),
                },
                "aare",
            );
        }
    }

    for reason in [
        None,
        Some(ReleaseReason::Normal),
        Some(ReleaseReason::Urgent),
        Some(ReleaseReason::UserDefined),
        Some(ReleaseReason::Other(5)),
    ] {
        round_trips(&Rlrq { reason, user_information: None }, "rlrq");
        round_trips(&Rlre { reason, user_information: Some(user_info) }, "rlre");
    }
}

/// The negotiation payloads, including the conformance block — whose bit order is
/// reversed on the wire, which is the classic place for a round trip to pass while the
/// bytes are wrong.
#[test]
fn the_initiate_payloads_and_every_conformance_bit_round_trip() {
    let key: &'static [u8] = &[0x11; 16];
    for dedicated_key in [None, Some(key)] {
        for response_allowed in [None, Some(true), Some(false)] {
            for qos in [None, Some(-3i8)] {
                round_trips(
                    &InitiateRequest {
                        dedicated_key,
                        response_allowed,
                        proposed_quality_of_service: qos,
                        proposed_dlms_version: 6,
                        proposed_conformance: Conformance::CLIENT_DEFAULT,
                        client_max_receive_pdu_size: 0x1234,
                    },
                    "initiate-request",
                );
            }
        }
    }
    for qos in [None, Some(1i8)] {
        round_trips(
            &InitiateResponse {
                negotiated_quality_of_service: qos,
                negotiated_dlms_version: 6,
                negotiated_conformance: Conformance::SERVER_DEFAULT,
                server_max_receive_pdu_size: 512,
                vaa_name: 7,
            },
            "initiate-response",
        );
    }
    // Every single bit, on its own, through the byte form and back.
    for n in 0..24 {
        let c = Conformance::from_bits_truncate(1 << n);
        assert_eq!(Conformance::from_bytes(c.to_bytes()), c, "conformance bit {n}");
    }
}

/// The exception response, whose trailing counter is present for exactly one service
/// error and absent for every other — a field whose presence depends on an earlier one.
#[test]
fn the_exception_response_round_trips_with_and_without_its_counter() {
    for state_error in [StateError::ServiceNotAllowed, StateError::ServiceUnknown, StateError::Other(9)] {
        for service_error in [
            ServiceError::OperationNotPossible,
            ServiceError::ServiceNotSupported,
            ServiceError::OtherReason,
            ServiceError::PduTooLong,
            ServiceError::DecipheringError,
            ServiceError::Other(9),
        ] {
            round_trips(
                &ExceptionResponse { state_error, service_error, expected_invocation_counter: None },
                "exception-response",
            );
        }
        round_trips(
            &ExceptionResponse {
                state_error,
                service_error: ServiceError::InvocationCounterError,
                expected_invocation_counter: Some(0xDEAD_BEEF),
            },
            "exception-response with a counter",
        );
    }
}

/// General block transfer blocks, across every combination of the control byte's three
/// fields — including a window of zero, which is a value and not an absence.
#[test]
fn every_block_control_combination_round_trips() {
    let payload: &'static [u8] = &[0xC4; 23];
    for last in [false, true] {
        for streaming in [false, true] {
            for window in [0u8, 1, 7, 0x3F] {
                round_trips(
                    &GeneralBlockTransfer {
                        control: BlockControl::new(last, streaming, window),
                        block_number: 0x0102,
                        block_number_ack: 0x0304,
                        block_data: payload,
                    },
                    "general-block-transfer",
                );
            }
        }
    }
}

/// HDLC frames, at every address width and every control type.
///
/// Not a `Decode` implementation, so it gets its own pass: the frame carries two
/// checksums and an eleven-bit length, and every one of them is computed from the others.
#[test]
fn every_hdlc_frame_shape_round_trips() {
    let addresses = [
        Address::Single(0x10),
        Address::Double { upper: 1, lower: 0x11 },
        Address::Quad { upper: 0x3FFF, lower: 0x3FFF },
    ];
    let controls = [
        Control::Snrm,
        Control::Ua,
        Control::Disc,
        Control::Dm,
        Control::Frmr,
        Control::Ui,
        Control::I { ns: 5, nr: 3, pf: true },
        Control::I { ns: 0, nr: 0, pf: false },
        Control::Rr { nr: 7, pf: true },
        Control::Rnr { nr: 2, pf: false },
    ];
    let mut rng = Rng(0x4D1C_4D1C_4D1C_4D1C);
    let mut buf = [0u8; 2048];

    for destination in addresses {
        for source in addresses {
            for control in controls {
                for info_len in [0usize, 1, 17, 128] {
                    // Only information frames carry an information field, and only they
                    // get a header check sequence — which is the asymmetry a codec loses.
                    let carries_info =
                        matches!(control, Control::I { .. } | Control::Ui | Control::Snrm) || info_len == 0;
                    if !carries_info {
                        continue;
                    }
                    let information: Vec<u8> = (0..info_len).map(|_| rng.byte()).collect();
                    let frame = Frame {
                        segmented: info_len > 0 && rng.byte() & 1 == 1,
                        destination,
                        source,
                        control,
                        information: &information,
                    };
                    let mut w = SliceWriter::new(&mut buf);
                    frame.encode(&mut w).expect("a frame this size must encode");
                    let n = w.written();
                    assert_eq!(n, frame.encoded_len(), "encoded_len disagrees with encode");
                    let (back, used) = decode_frame(&buf[..n]).expect("it must decode back");
                    assert_eq!(used, n);
                    assert_eq!(back, frame, "a frame changed across a round trip");
                }
            }
        }
    }
}

/// And the whole `Apdu` enum, through the one decoder a peer actually uses.
///
/// The service tests above go through each service's own codec; this one goes through
/// `Apdu`, which is what dispatches on the tag byte. A service whose tag is missing from
/// that dispatch passes every test above and is unreachable on the wire.
#[test]
fn every_apdu_tag_reaches_its_service_through_the_top_level_decoder() {
    let mut rng = Rng(0xAB0D_AB0D_AB0D_AB0D);
    let mut arena = Vec::new();
    let value = data(&mut rng, 2, &mut arena);
    let id = InvokeId::confirmed(3);
    let raw: &'static [u8] = &[0x01, 0x02, 0x03];

    let apdus = [
        Apdu::GetRequest(GetRequest::Normal { invoke_id: id, descriptor: attribute(&mut rng), access: None }),
        Apdu::GetResponse(GetResponse::Normal { invoke_id: id, result: GetDataResult::Data(value) }),
        Apdu::SetRequest(SetRequest::Normal {
            invoke_id: id,
            descriptor: attribute(&mut rng),
            access: None,
            value,
        }),
        Apdu::SetResponse(SetResponse::Normal { invoke_id: id, result: DataAccessResult::Success }),
        Apdu::ActionRequest(ActionRequest::Normal {
            invoke_id: id,
            descriptor: method(&mut rng),
            parameters: Some(value),
        }),
        Apdu::ActionResponse(ActionResponse::Normal {
            invoke_id: id,
            response: ActionResponseWithOptionalData {
                result: ActionResult::Success,
                return_parameters: None,
            },
        }),
        Apdu::DataNotification(dlms_cosem_rs::xdlms::DataNotification {
            long_invoke_id: LongInvokeId::new(1),
            date_time: OptionalDateTime(None),
            body: value,
        }),
        Apdu::ExceptionResponse(ExceptionResponse {
            state_error: StateError::ServiceUnknown,
            service_error: ServiceError::ServiceNotSupported,
            expected_invocation_counter: None,
        }),
        Apdu::GeneralBlockTransfer(GeneralBlockTransfer {
            control: BlockControl::new(true, false, 0),
            block_number: 1,
            block_number_ack: 0,
            block_data: raw,
        }),
        Apdu::Gateway { response: false, network_id: 3, physical_device_address: raw, payload: raw },
    ];

    for apdu in apdus {
        let bytes = encoded(&apdu);
        let leaked: &'static [u8] = Box::leak(bytes.clone().into_boxed_slice());
        let back = Apdu::from_bytes(leaked)
            .unwrap_or_else(|e| panic!("{:?} did not decode through Apdu: {e}", apdu.tag()));
        assert_eq!(back.tag(), apdu.tag(), "the tag changed across a round trip");
        assert_eq!(encoded(&back), bytes, "{:?} re-encoded to different bytes", apdu.tag());
    }
}
