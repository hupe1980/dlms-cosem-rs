#![no_main]
//! The frame finder and the reassembler, fed the kind of stream a noisy optical link
//! produces.
//!
//! Both face the network before anything has been authenticated: the framer decides
//! where a frame begins, and the reassembler concatenates information fields across
//! frames on the strength of one attacker-controlled bit.

use dlms_cosem_rs::transport::hdlc::{Found, Framer, Parameters, Reassembler, Segmenter};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let mut framer = Framer::new();
    let mut storage = [0u8; 2048];
    let mut assembled = Reassembler::new(&mut storage);
    let mut offset = 0usize;

    // Drive it as a caller would: keep going until it stops making progress.
    loop {
        match framer.next_frame(&bytes[offset..]) {
            Ok(Found::Frame { frame, consumed }) => {
                assert!(consumed > 0, "a frame that consumes nothing would loop forever");
                assert!(consumed <= bytes.len() - offset);
                let _ = Parameters::decode(frame.information);
                match assembled.push(&frame) {
                    Ok(true) => {
                        // A complete unit must be exactly what was accumulated, and must
                        // never exceed the buffer it was given.
                        assert!(assembled.lsdu().len() <= storage_len());
                        assembled.reset();
                    }
                    Ok(false) => {}
                    Err(_) => assembled.reset(),
                }
                offset += consumed;
            }
            Ok(Found::Incomplete { discard }) => {
                assert!(discard <= bytes.len() - offset);
                break;
            }
            Err(_) => break,
        }
    }

    // And the other direction: whatever these bytes are, splitting them at any width and
    // putting them back must give them back unchanged.
    if !bytes.is_empty() && bytes.len() <= 512 {
        let width = u16::from(bytes[0]).max(1);
        if let Ok(mut segmenter) = Segmenter::new(bytes, width) {
            let mut wire = Vec::new();
            let mut frame = [0u8; 1024];
            let mut ns = 0u8;
            let dest = dlms_cosem_rs::transport::hdlc::Address::server(1, 17);
            let src = dlms_cosem_rs::transport::hdlc::Address::client(0x10);
            while let Ok(Some(n)) = segmenter.next_frame(dest, src, ns, 0, &mut frame) {
                wire.extend_from_slice(&frame[..n]);
                ns = (ns + 1) % 8;
            }
            let mut back = [0u8; 512];
            let mut r = Reassembler::new(&mut back);
            let mut f = Framer::new();
            let mut at = 0usize;
            let mut done = false;
            while let Ok(Found::Frame { frame, consumed }) = f.next_frame(&wire[at..]) {
                at += consumed;
                if r.push(&frame).unwrap_or(false) {
                    done = true;
                    break;
                }
            }
            assert!(done, "our own segments must reassemble");
            assert_eq!(r.lsdu(), bytes, "and give back exactly what was split");
        }
    }
});

fn storage_len() -> usize {
    2048
}
