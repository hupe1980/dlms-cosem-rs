#![no_main]
//! The general block transfer procedure, driven by an attacker.
//!
//! A decoder target proves one block cannot crash the parser. This proves the *procedure*
//! cannot: blocks arrive in any order, repeated, from beyond a gap, with any window and
//! any last-block flag, and the receiver must gather or refuse each without aborting and
//! without ever reading outside the buffer it was given.
//!
//! The invariant checked here is the one the retry sub-procedure rests on: what a
//! receiver acknowledges is the length of the run it has actually stored, so a sender
//! that rewinds to it resumes at the right byte. A receiver that acknowledged a block it
//! had not stored would leave a hole nothing fills, and the reassembled APDU would be
//! wrong rather than absent.

use dlms_cosem_rs::codec::Decode;
use dlms_cosem_rs::xdlms::{GbtAction, GbtReceiver, GeneralBlockTransfer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let mut storage = [0u8; 4096];
    let mut receiver = GbtReceiver::new(&mut storage);
    let mut acknowledged = 0u16;

    // Split the input into blocks on a marker byte, so one case is a whole transfer.
    for message in bytes.split(|b| *b == 0xFE) {
        if message.is_empty() {
            continue;
        }
        let Ok(block) = GeneralBlockTransfer::from_bytes(message) else { continue };
        let before = receiver.len();
        match receiver.push(&block) {
            Ok(action) => {
                let now = receiver.acknowledged();
                // The run only ever grows, except when a completed APDU is taken and the
                // next transfer starts over.
                if now > acknowledged {
                    assert!(
                        receiver.len() > before,
                        "a block was acknowledged without being stored: the sender would \
                         rewind to a byte that is not there"
                    );
                }
                acknowledged = now;
                if action == GbtAction::Complete {
                    assert_eq!(
                        receiver.apdu().len(),
                        receiver.len(),
                        "a completed APDU is exactly what was gathered"
                    );
                    receiver.reset();
                    acknowledged = 0;
                }
            }
            Err(_) => {
                // The only failure is a buffer too small, and it must leave the receiver
                // usable rather than half-written.
                receiver.reset();
                acknowledged = 0;
            }
        }
    }
});
