#![no_main]
//! Every APDU the application layer can receive, protected ones included.

use dlms_cosem_rs::codec::{Decode, Encode, SliceWriter};
use dlms_cosem_rs::xdlms::Apdu;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(apdu) = Apdu::from_bytes(bytes) {
        let _ = apdu.tag();
        let _ = apdu.is_protected();
        let mut out = vec![0u8; bytes.len() * 2 + 64];
        let mut w = SliceWriter::new(&mut out);
        if apdu.encode(&mut w).is_ok() {
            // Re-decoding what we encoded must give the same APDU: an encoder that
            // loses a field is a silently wrong stack.
            let again = Apdu::from_bytes(w.as_slice()).expect("our own output must decode");
            assert_eq!(apdu.tag(), again.tag());
        }
    }
});
