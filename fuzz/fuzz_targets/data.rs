#![no_main]
//! The A-XDR decoder, including the lazy sequences.
//!
//! Decoding a sequence only validates it; the values are not built until they are
//! iterated, so a target that stops at `from_bytes` would never reach the code where a
//! length lie actually lands. This one walks everything.

use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::codec::Decode;
use libfuzzer_sys::fuzz_target;

fn walk(d: &Data<'_>, depth: usize) {
    assert!(depth < 64, "recursion escaped the decoder's depth bound");
    if let Some(seq) = d.as_seq() {
        for e in seq.iter() {
            match e {
                Ok(e) => walk(&e, depth + 1),
                Err(_) => break,
            }
        }
    }
    if let Data::CompactArray(c) = d {
        let _ = c.row_count();
        let _ = c.for_each_leaf(|_| Ok(()));
    }
    let _ = d.as_i64();
    let _ = d.as_str();
    let _ = d.as_obis();
}

fuzz_target!(|bytes: &[u8]| {
    if let Ok(d) = Data::from_bytes(bytes) {
        walk(&d, 0);
        // Whatever decoded must re-encode, and re-encoding must not overflow the
        // length the decoder measured.
        let mut out = alloc_buf(bytes.len() * 2 + 16);
        use dlms_cosem_rs::codec::{Encode, SliceWriter, Writer};
        let mut w = SliceWriter::new(&mut out);
        if d.encode(&mut w).is_ok() {
            assert_eq!(w.written(), d.encoded_len(), "encoded_len disagreed with encode");
        }
    }
});

fn alloc_buf(n: usize) -> Vec<u8> {
    vec![0u8; n.min(1 << 20)]
}
