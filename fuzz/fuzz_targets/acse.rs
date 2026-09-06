#![no_main]
//! The BER decoders, which face the network before any key has been checked.

use dlms_cosem_rs::acse::{Aare, Aarq, Rlre, Rlrq};
use dlms_cosem_rs::codec::Decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = Aarq::from_bytes(bytes);
    let _ = Aare::from_bytes(bytes);
    let _ = Rlrq::from_bytes(bytes);
    let _ = Rlre::from_bytes(bytes);
});
