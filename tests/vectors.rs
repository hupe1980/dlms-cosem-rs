//! Golden vectors: bytes somebody else wrote down.
//!
//! Every other test in this repository checks the crate against itself — an encoder
//! against its own decoder, a client against its own server. That catches a great deal
//! and is structurally blind to one thing: a misreading of the standard that both halves
//! share. The only cure is a byte string produced by someone who has never seen this
//! code.
//!
//! The vectors here come from Petr Matoušek, *Description and analysis of IEC 104
//! Protocol* / *Analysis of DLMS Protocol*, technical report FIT-TR-2017-13, Brno
//! University of Technology, 2017 — a public academic analysis that works several xDLMS
//! APDUs out byte by byte, with a field-by-field commentary. It is an independent
//! reading of the same specification, which is exactly what makes it useful.
//!
//! An encoding is a fact rather than an expression: what is reproduced below is the
//! hexadecimal, and the field values the report states for it. Where the report's prose
//! and its bytes disagree, the bytes win and the disagreement is noted.

use dlms_cosem_rs::codec::{Decode, Encode, SliceWriter, Writer};
use dlms_cosem_rs::xdlms::{ApduTag, Conformance, InitiateRequest, InitiateResponse, VAA_NAME_LN};
use hex_literal::hex;

/// Encode `apdu` behind its tag and compare with what the report printed.
fn assert_encodes_to(tag: ApduTag, apdu: &dyn Encode, expected: &[u8]) {
    let mut buf = [0u8; 64];
    let mut w = SliceWriter::new(&mut buf);
    w.write_u8(tag.as_u8()).unwrap();
    apdu.encode(&mut w).unwrap();
    assert_eq!(w.as_slice(), expected, "encoding disagrees with the published bytes");
    assert_eq!(
        1 + apdu.encoded_len(),
        expected.len(),
        "encoded_len disagrees with what encode actually wrote"
    );
}

/// FIT-TR-2017-13, Example 1 — `xDLMS-Initiate.request`, logical-name referencing.
///
/// No ciphering, no quality of service, DLMS version 6, conformance `00 7E 1F`, and a
/// client PDU size of 1200.
///
/// The report annotates the third byte as "the response-allowed (00=FALSE, FF=TRUE)".
/// That gloss is wrong and its own bytes are right: `response-allowed` is
/// `BOOLEAN DEFAULT TRUE`, so A-XDR encodes it as an optional field, and `00` is the
/// *absence* flag — meaning the default, TRUE. Reading `00` as the boolean `false`
/// would make this APDU say the exact opposite of what the report's prose says it says.
/// This crate models it as `Option<bool>`, where `None` is that absence.
#[test]
fn initiate_request_logical_name() {
    let expected = hex!("01 00 00 00 06 5F 1F 04 00 00 7E 1F 04 B0");

    let request = InitiateRequest {
        dedicated_key: None,
        response_allowed: None,
        proposed_quality_of_service: None,
        proposed_dlms_version: 6,
        proposed_conformance: Conformance::from_bytes([0x00, 0x7E, 0x1F]),
        client_max_receive_pdu_size: 1200,
    };
    assert_encodes_to(ApduTag::InitiateRequest, &request, &expected);

    let mut r = dlms_cosem_rs::codec::Reader::new(&expected);
    assert_eq!(r.u8().unwrap(), ApduTag::InitiateRequest.as_u8());
    let back = InitiateRequest::decode(&mut r).unwrap();
    assert_eq!(back, request);
    assert!(r.is_empty(), "the vector is exactly one APDU, with nothing left over");

    // The conformance block names services, not just bits.
    let c = back.proposed_conformance;
    for service in [
        Conformance::GET,
        Conformance::SET,
        Conformance::ACTION,
        Conformance::SELECTIVE_ACCESS,
        Conformance::BLOCK_TRANSFER_WITH_GET_OR_READ,
    ] {
        assert!(c.contains(service), "a logical-name client offers {service:?}");
    }
    assert!(!c.contains(Conformance::READ), "and does not offer the short-name services");
    assert!(!c.contains(Conformance::WRITE));
}

/// The same request with the short-name conformance block, `1C 03 02`.
///
/// This crate does not implement short-name referencing, but the conformance block is
/// the same 24 bits either way and must decode to the services the report names.
#[test]
fn initiate_request_short_name() {
    let expected = hex!("01 00 00 00 06 5F 1F 04 00 1C 03 02 04 B0");

    let request = InitiateRequest {
        dedicated_key: None,
        response_allowed: None,
        proposed_quality_of_service: None,
        proposed_dlms_version: 6,
        proposed_conformance: Conformance::from_bytes([0x1C, 0x03, 0x02]),
        client_max_receive_pdu_size: 1200,
    };
    assert_encodes_to(ApduTag::InitiateRequest, &request, &expected);

    let c = request.proposed_conformance;
    assert!(c.contains(Conformance::READ), "a short-name client offers read");
    assert!(c.contains(Conformance::WRITE));
    assert!(!c.contains(Conformance::GET), "and not the logical-name services");
    assert!(!c.contains(Conformance::SET));
}

/// FIT-TR-2017-13, Example 3 — `xDLMS-Initiate.response`, logical-name referencing.
///
/// No quality of service, version 6, conformance `00 50 1F`, a server PDU size of 500,
/// and the VAA name `0007` that every logical-name association reports.
#[test]
fn initiate_response_logical_name() {
    let expected = hex!("08 00 06 5F 1F 04 00 00 50 1F 01 F4 00 07");

    let response = InitiateResponse {
        negotiated_quality_of_service: None,
        negotiated_dlms_version: 6,
        negotiated_conformance: Conformance::from_bytes([0x00, 0x50, 0x1F]),
        server_max_receive_pdu_size: 500,
        vaa_name: VAA_NAME_LN,
    };
    assert_encodes_to(ApduTag::InitiateResponse, &response, &expected);

    let mut r = dlms_cosem_rs::codec::Reader::new(&expected);
    assert_eq!(r.u8().unwrap(), ApduTag::InitiateResponse.as_u8());
    let back = InitiateResponse::decode(&mut r).unwrap();
    assert_eq!(back, response);
    assert!(r.is_empty());
    assert_eq!(back.vaa_name, 0x0007);
    back.check_version().expect("version 6 is the one this crate speaks");

    // The server has agreed to less than the client proposed: this is the intersection
    // a real negotiation produces, not a copy of the request.
    let proposed = Conformance::from_bytes([0x00, 0x7E, 0x1F]);
    assert_eq!(
        proposed.negotiate(back.negotiated_conformance),
        back.negotiated_conformance,
        "the response must already be a subset of what was proposed"
    );
    assert!(back.negotiated_conformance.contains(Conformance::GET));
}

/// The same response with the short-name conformance block and the short-name VAA name.
#[test]
fn initiate_response_short_name() {
    let expected = hex!("08 00 06 5F 1F 04 00 1C 03 20 01 F4 FA 00");

    let response = InitiateResponse {
        negotiated_quality_of_service: None,
        negotiated_dlms_version: 6,
        negotiated_conformance: Conformance::from_bytes([0x1C, 0x03, 0x20]),
        server_max_receive_pdu_size: 500,
        vaa_name: 0xFA00,
    };
    assert_encodes_to(ApduTag::InitiateResponse, &response, &expected);
    assert_eq!(InitiateResponse::from_bytes(&expected[1..]).unwrap(), response);
}

/// FIT-TR-2017-13, Example 2 — a legacy `InitiateRequest`, refused at its conformance tag.
///
/// `01 00 00 01 04 01 5E 03 00 10 C3 00 86`: no dedicated key, no response-allowed,
/// quality of service **present** with value 4, DLMS version 1, and a 16-bit
/// conformance block under application tag 30.
///
/// Everything up to the conformance block is the same grammar version 6 uses, so this
/// vector proves the optional-field decoding is right — the parser has to get four
/// presence flags and a signed byte correct before it can reach the tag it refuses. The
/// report's own commentary is misaligned here, annotating the third `00` as the quality
/// of service when the byte in that position is `01`; the bytes are self-consistent and
/// are what is asserted.
#[test]
fn a_legacy_initiate_request_is_refused_at_its_conformance_tag() {
    let legacy = hex!("01 00 00 01 04 01 5E 03 00 10 C3 00 86");
    let err = InitiateRequest::from_bytes(&legacy[1..]).unwrap_err();
    assert_eq!(
        err.offset, 5,
        "the refusal must land on the conformance tag, after the optional fields parsed: {err}"
    );
}

/// FIT-TR-2017-13, Example 4 — the *legacy* DLMS form, and the one case where this
/// crate refuses rather than agrees.
///
/// `08 01 04 01 5E 03 00 1C 00 00 86 00 37` carries its conformance under application
/// tag 30 (`5E`) as a 16-bit bit string, which is DLMS rather than xDLMS. Version 6
/// moved it to tag 31 (`5F 1F`) and 24 bits, and that is the only form this crate
/// encodes or decodes ([`Conformance::encode_tagged`]).
///
/// The vector is kept because "we refuse this, deliberately, and here is the byte that
/// makes us refuse it" is worth as much as a vector we reproduce — and because a
/// decoder that silently accepted the shorter block would read every field after it
/// from the wrong offset.
#[test]
fn the_legacy_sixteen_bit_conformance_block_is_refused_not_misread() {
    let legacy = hex!("08 01 04 01 5E 03 00 1C 00 00 86 00 37");
    let err = InitiateResponse::from_bytes(&legacy[1..]).unwrap_err();
    // It fails at the conformance tag, not somewhere further along having mis-parsed it.
    assert_eq!(err.offset, 3, "the refusal must land on the tag itself: {err}");
}
