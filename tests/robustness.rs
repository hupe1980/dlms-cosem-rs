//! What arbitrary bytes do to the decoders.
//!
//! `cargo fuzz` is the real instrument and lives in `fuzz/`, but it needs a nightly
//! toolchain and time. This is the part that runs on stable, in CI, on every commit: a
//! deterministic mutation harness over seeds taken from the rest of the test suite.
//!
//! What it asserts is narrow and absolute. Every decoder must either return a value or
//! return an error. It must never panic, never loop forever, and never return a value
//! that points outside the input it was given. Nothing here checks that the *meaning*
//! is right — that is what the vector and association tests are for.

use dlms_cosem_rs::acse::{Aare, Aarq, Rlre, Rlrq};
use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::codec::Decode;
use dlms_cosem_rs::transport::{hdlc, wrapper};
use dlms_cosem_rs::xdlms::Apdu;

/// A deterministic generator. A fuzzer needs entropy; a regression test needs the same
/// bytes every time, and this gives both by being seeded.
struct Rng(u64);

impl Rng {
    fn next_u32(&mut self) -> u32 {
        // xorshift64*, which is enough randomness to shake a parser and small enough
        // that a failing case can be reproduced from the seed alone.
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
}

/// Every decoder this crate exposes, as a uniform "bytes in, did it survive" closure.
type Decoder = (&'static str, fn(&[u8]));

fn decoders() -> Vec<Decoder> {
    vec![
        ("data", |b| {
            if let Ok(d) = Data::from_bytes(b) {
                // Walk it: a lazily-decoded sequence is not really decoded until it is
                // iterated, and that is where a length lie would land.
                walk(&d, 0);
            }
        }),
        ("apdu", |b| {
            if let Ok(a) = Apdu::from_bytes(b) {
                let _ = a.tag();
                let _ = a.is_protected();
            }
        }),
        ("aarq", |b| {
            let _ = Aarq::from_bytes(b);
        }),
        ("aare", |b| {
            let _ = Aare::from_bytes(b);
        }),
        ("rlrq", |b| {
            let _ = Rlrq::from_bytes(b);
        }),
        ("rlre", |b| {
            let _ = Rlre::from_bytes(b);
        }),
        ("hdlc", |b| {
            let mut framer = hdlc::Framer::new();
            match framer.next_frame(b) {
                Ok(hdlc::Found::Frame { frame, consumed }) => {
                    assert!(consumed <= b.len(), "a framer consumed more than it was given");
                    assert!(
                        frame.information.len() <= b.len(),
                        "an information field longer than the whole input"
                    );
                }
                Ok(hdlc::Found::Incomplete { discard }) => {
                    assert!(discard <= b.len(), "a framer discarded more than it was given");
                }
                Err(_) => {}
            }
        }),
        ("wrapper", |b| {
            let r = wrapper::StreamReassembler::new(2048);
            if let Ok(Some((pdu, used))) = r.next_pdu(b) {
                assert!(used <= b.len());
                assert_eq!(pdu.apdu.len(), usize::from(pdu.header.length));
            }
        }),
        ("hdlc_params", |b| {
            let _ = hdlc::Parameters::decode(b);
        }),
    ]
}

fn walk(d: &Data<'_>, depth: usize) {
    assert!(depth < 64, "recursion escaped the decoder's own depth bound");
    if let Some(seq) = d.as_seq() {
        for e in seq.iter() {
            match e {
                Ok(e) => walk(&e, depth + 1),
                Err(_) => break,
            }
        }
    }
    // A compact array is only validated far enough to find its end when it is decoded;
    // the contents are not divided into rows until somebody asks. Walking it here is
    // what puts the row splitter under the harness rather than only under `cargo fuzz`.
    if let Data::CompactArray(c) = d {
        let _ = c.row_count();
        let _ = c.row_len();
        let _ = c.for_each_leaf(|_| Ok(()));
    }
    let _ = d.as_i64();
    let _ = d.as_str();
    let _ = d.as_obis();
}

/// Seeds: well-formed messages the rest of the suite produces, which is what makes the
/// mutations land near a valid parse rather than being rejected at the first byte.
fn seeds() -> Vec<Vec<u8>> {
    vec![
        // A get-request.
        vec![0xC0, 0x01, 0x81, 0x00, 0x03, 1, 0, 1, 8, 0, 255, 2, 0],
        // A get-response carrying a structure.
        vec![0xC4, 0x01, 0x81, 0x00, 0x02, 0x02, 0x11, 0x07, 0x12, 0x00, 0x64],
        // An array of arrays.
        vec![0x01, 0x02, 0x01, 0x02, 0x11, 0x01, 0x11, 0x02, 0x01, 0x01, 0x09, 0x03, 1, 2, 3],
        // A compact array.
        vec![0x13, 0x02, 0x02, 0x11, 0x12, 0x09, 0x06, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00],
        // A date-time.
        vec![0x19, 0x07, 0xE9, 0x0C, 0x1F, 0xFF, 0x17, 0x3B, 0x3B, 0xFF, 0x00, 0x3C, 0x00],
        // An AARQ.
        vec![
            0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01, 0xBE, 0x10, 0x04,
            0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0,
        ],
        // An HDLC frame.
        vec![0x7E, 0xA0, 0x0A, 0x03, 0x21, 0x93, 0x0F, 0x01, 0x7E],
        // A wrapper PDU.
        vec![0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x03, 0xC0, 0x01, 0x81],
        // A general-glo-ciphering APDU.
        vec![
            0xDB, 0x08, 0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E, 0x11, 0x30, 0x00, 0x00, 0x00, 0x01,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ],
        // A compact array whose description is a zero-width type: a row of it consumes
        // nothing, so splitting the contents into rows has no fixed point.
        vec![0x13, 0x00, 0x01, 0xAA],
        // A compact array of a nested structure description.
        vec![0x13, 0x02, 0x02, 0x02, 0x01, 0x11, 0x12, 0x04, 0x01, 0x00, 0x02],
        // Deliberately hostile: a length prefix that claims far more than is present.
        vec![0x09, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
        // And a deeply nested structure, to press the depth bound.
        {
            let mut v = Vec::new();
            for _ in 0..200 {
                v.push(0x02);
                v.push(0x01);
            }
            v.push(0x00);
            v
        },
    ]
}

#[test]
fn no_decoder_panics_on_a_mutated_message() {
    let decoders = decoders();
    let seeds = seeds();
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let mut cases = 0usize;

    for round in 0..20_000 {
        let seed = &seeds[round % seeds.len()];
        let mut buf = seed.clone();
        // One to four mutations: a byte flip, a truncation, an insertion or a splice.
        for _ in 0..=rng.below(4) {
            if buf.is_empty() {
                buf.push(rng.next_u32() as u8);
                continue;
            }
            match rng.below(4) {
                0 => {
                    let at = rng.below(buf.len());
                    buf[at] ^= 1 << rng.below(8);
                }
                1 => {
                    let at = rng.below(buf.len());
                    buf.truncate(at);
                }
                2 => {
                    let at = rng.below(buf.len());
                    buf.insert(at, rng.next_u32() as u8);
                }
                _ => {
                    let other = &seeds[rng.below(seeds.len())];
                    let at = rng.below(buf.len());
                    let take = rng.below(other.len().max(1));
                    buf.truncate(at);
                    buf.extend_from_slice(&other[..take]);
                }
            }
        }
        for (_name, f) in &decoders {
            f(&buf);
            cases += 1;
        }
    }
    assert!(cases > 100_000, "the harness should have run a lot of cases, ran {cases}");
}

#[test]
fn no_decoder_panics_on_uniform_noise() {
    let decoders = decoders();
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..20_000 {
        let len = rng.below(96);
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(rng.next_u32() as u8);
        }
        for (_name, f) in &decoders {
            f(&buf);
        }
    }
}

#[test]
fn every_prefix_of_every_seed_is_survivable() {
    // Truncation is the single most common real-world malformation: a link drops, a
    // buffer is short, a frame is split. Every prefix of a valid message must be either
    // decoded or refused, never fatal.
    let decoders = decoders();
    for seed in seeds() {
        for len in 0..=seed.len() {
            for (_name, f) in &decoders {
                f(&seed[..len]);
            }
        }
    }
}

#[test]
fn nesting_is_bounded_rather_than_recursive() {
    // 100 000 nested structures: a decoder that recurses without a bound dies here.
    let mut deep = Vec::new();
    for _ in 0..100_000 {
        deep.push(0x02);
        deep.push(0x01);
    }
    deep.push(0x00);
    assert!(Data::from_bytes(&deep).is_err(), "a 100 000-deep value must be refused");
}

#[test]
fn a_length_that_lies_is_refused_not_believed() {
    // An octet string claiming four gigabytes inside a six-byte buffer.
    let claim = [0x09, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
    let err = Data::from_bytes(&claim).unwrap_err();
    assert!(err.is_truncated(), "expected truncation, got {err:?}");

    // A wrapper header claiming more than the reassembler will hold.
    let r = wrapper::StreamReassembler::new(256);
    assert!(r.next_pdu(&[0x00, 0x01, 0, 0x10, 0, 1, 0xFF, 0xFF]).is_err());

    // An HDLC frame whose length field exceeds what arrived.
    let mut framer = hdlc::Framer::new();
    assert!(matches!(
        framer.next_frame(&[0x7E, 0xA7, 0xFF, 0x03, 0x21, 0x93]).unwrap(),
        hdlc::Found::Incomplete { .. }
    ));
}

#[test]
fn a_zero_width_compact_array_row_is_refused_rather_than_split_forever() {
    // `null-data` as the element type: every row decodes without consuming a byte, so a
    // splitter that loops until the contents are exhausted never finishes, and the
    // owning variant allocates a row per iteration until the process dies. There is no
    // number of rows this value could mean, so it is malformed.
    for desc in [
        0x00u8, // null-data
        0xFF,   // dont-care
    ] {
        let bytes = [0x13, desc, 0x01, 0xAA];
        let d = Data::from_bytes(&bytes).expect("the description itself is well formed");
        let Data::CompactArray(c) = d else { panic!("expected a compact array") };
        assert!(c.row_count().is_err(), "description {desc:#04x} must be refused, not walked forever");
        assert!(c.for_each_leaf(|_| Ok(())).is_err());
        assert!(c.to_rows().is_err());
    }

    // An array of zero elements is zero-width for the same reason.
    let bytes = [0x13, 0x01, 0x00, 0x00, 0x11, 0x01, 0xAA];
    if let Ok(Data::CompactArray(c)) = Data::from_bytes(&bytes) {
        assert!(c.row_count().is_err());
    }
}

#[test]
fn a_compact_array_description_is_depth_bounded_like_everything_else() {
    // The type description is itself recursive and is read before anything is
    // authenticated. 20 000 nested structures is a stack overflow for a decoder that
    // walks it without a budget.
    let mut bytes = vec![0x13u8];
    for _ in 0..20_000 {
        bytes.push(0x02);
        bytes.push(0x01);
    }
    bytes.push(0x11);
    bytes.push(0x01);
    bytes.push(0xAA);
    assert!(Data::from_bytes(&bytes).is_err(), "a 20 000-deep type description must be refused");
}

#[test]
fn a_compact_array_row_width_cannot_overflow_a_usize() {
    // Nested arrays multiply: 65 535 of 65 535 of 65 535 … overflows long before it
    // describes anything a meter could send, and the product must be refused rather
    // than wrapped.
    let mut desc = Vec::new();
    for _ in 0..5 {
        desc.push(0x01); // array
        desc.push(0xFF); // of 65 535
        desc.push(0xFF);
    }
    desc.push(0x11); // of unsigned
    let mut bytes = vec![0x13u8];
    bytes.extend_from_slice(&desc);
    bytes.push(0x00); // empty contents
    if let Ok(Data::CompactArray(c)) = Data::from_bytes(&bytes) {
        assert!(c.row_len().is_err(), "an overflowing row width must be an error");
    }
}

#[test]
fn an_hdlc_header_cannot_reach_past_its_own_frame() {
    // The addresses are variable-length and attacker-controlled. A frame whose header
    // runs into the space the frame check sequence has to occupy describes something
    // that cannot exist, and reading it as though it could reaches past the frame.
    for frame_len in 5u16..24 {
        for pattern in 0u8..64 {
            let total = 1 + frame_len as usize + 1;
            let mut b = vec![0u8; total];
            b[0] = hdlc::FLAG;
            b[total - 1] = hdlc::FLAG;
            let format = 0xA000u16 | frame_len;
            b[1] = (format >> 8) as u8;
            b[2] = (format & 0xff) as u8;
            for (i, byte) in b.iter_mut().enumerate().take(total - 1).skip(3) {
                *byte = u8::from((pattern as usize + i) % 5 == 0);
            }
            let fcs_at = total - 3;
            let f = hdlc::fcs16(&b[1..fcs_at]);
            b[fcs_at] = (f & 0xff) as u8;
            b[fcs_at + 1] = (f >> 8) as u8;
            // Must return a frame or an error. Never reach past `total`.
            if let Ok((frame, used)) = hdlc::decode_frame(&b) {
                assert_eq!(used, total);
                assert!(frame.information.len() < total);
            }
        }
    }
}

/// The general block transfer procedure under a hostile sender.
///
/// A decoder test proves one block cannot crash the parser; this proves the *procedure*
/// cannot. Blocks arrive in any order, repeated, from beyond a gap, with any window and
/// any last-block flag, and the receiver must gather or refuse each one without aborting.
///
/// The invariant is the one the retry sub-procedure rests on: **a block is either
/// accepted whole or not at all.** When the receiver advances its run to a block's number
/// it stored exactly that block's payload; when it does not advance, it stored nothing.
/// A receiver that got this wrong would send a rewinding sender to the wrong byte, and
/// the reassembled APDU would be wrong rather than absent — the failure with no error
/// attached to it.
///
/// Note what the invariant is *not*: "acknowledging a block means the buffer grew". A
/// block may carry an empty payload, and then the run advances while the length does not.
/// The loose phrasing is false for a frame a peer is entitled to send.
#[test]
fn a_general_block_transfer_block_is_accepted_whole_or_not_at_all() {
    use dlms_cosem_rs::xdlms::{BlockControl, GbtAction, GbtReceiver, GeneralBlockTransfer};

    let mut rng = Rng(0x6B7_0F1E_2D3C_4B5A);
    let mut storage = [0u8; 512];
    let mut receiver = GbtReceiver::new(&mut storage);
    let payload = [0xAAu8; 64];

    for _ in 0..20_000 {
        let control = BlockControl(rng.next_u32() as u8);
        let block = GeneralBlockTransfer {
            control,
            block_number: (rng.below(8) + 1) as u16,
            block_number_ack: rng.below(8) as u16,
            // Zero-length payloads included on purpose: they are the case that made the
            // looser version of this assertion false.
            block_data: &payload[..rng.below(payload.len() + 1)],
        };
        let before_len = receiver.len();
        let before_ack = receiver.acknowledged();
        match receiver.push(&block) {
            Ok(action) => {
                if receiver.acknowledged() == block.block_number && receiver.acknowledged() != before_ack {
                    assert_eq!(
                        receiver.len(),
                        before_len + block.block_data.len(),
                        "block {} was accepted but stored the wrong number of bytes",
                        block.block_number
                    );
                } else {
                    assert_eq!(
                        receiver.len(),
                        before_len,
                        "block {} was not accepted and was stored anyway",
                        block.block_number
                    );
                }
                if action == GbtAction::Complete {
                    assert_eq!(receiver.apdu().len(), receiver.len());
                    receiver.reset();
                }
            }
            Err(_) => receiver.reset(),
        }
    }
}

/// The case `cargo fuzz` found: an in-order block with an **empty** payload.
///
/// It is a legitimate frame — the run advances, no bytes are stored — and it is kept here
/// as a regression because the fuzzer only reaches it on a nightly toolchain with time to
/// spend, while this runs on stable on every commit.
#[test]
fn a_block_with_an_empty_payload_advances_the_run_without_storing_anything() {
    use dlms_cosem_rs::codec::Decode;
    use dlms_cosem_rs::xdlms::{GbtAction, GbtReceiver, GeneralBlockTransfer};

    // control 0x00, block 1, ack 0, zero-length data.
    let block = GeneralBlockTransfer::from_bytes(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap();
    assert!(block.block_data.is_empty());

    let mut storage = [0u8; 64];
    let mut receiver = GbtReceiver::new(&mut storage);
    assert_eq!(receiver.push(&block).unwrap(), GbtAction::Acknowledge);
    assert_eq!(receiver.acknowledged(), 1, "the run reaches block one");
    assert_eq!(receiver.len(), 0, "and no bytes were stored, because none were sent");

    // The transfer continues from there exactly as if the empty block had carried data.
    // control 0x80 (last block), block 2, ack 0, two bytes of data.
    let two = GeneralBlockTransfer::from_bytes(&[0x80, 0x00, 0x02, 0x00, 0x00, 0x02, 0xAB, 0xCD]).unwrap();
    assert_eq!(receiver.push(&two).unwrap(), GbtAction::Complete);
    assert_eq!(receiver.apdu(), [0xAB, 0xCD]);
}
