#![no_main]
//! Stream reassembly, which must never buffer more than it was told to.

use dlms_cosem_rs::transport::wrapper::StreamReassembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let r = StreamReassembler::new(1024);
    let mut offset = 0usize;
    while let Ok(Some((pdu, used))) = r.next_pdu(&bytes[offset..]) {
        assert!(used > 0);
        assert_eq!(pdu.apdu.len(), usize::from(pdu.header.length));
        assert!(pdu.apdu.len() <= 1024);
        offset += used;
    }
});
