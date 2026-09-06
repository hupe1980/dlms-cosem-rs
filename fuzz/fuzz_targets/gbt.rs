#![no_main]
//! The general block transfer procedure, driven by an attacker.
//!
//! A decoder target proves one block cannot crash the parser. This proves the *procedure*
//! cannot: blocks arrive in any order, repeated, from beyond a gap, with any window and
//! any last-block flag, and the receiver must gather or refuse each without aborting and
//! without ever reading outside the buffer it was given.
//!
//! The invariant checked here is the one the retry sub-procedure rests on: **a block is
//! either accepted whole or not at all.** When the receiver advances its run to a block's
//! number it must have stored exactly that block's payload, and when it does not advance
//! it must have stored nothing — otherwise a sender that rewinds to the acknowledged
//! number resumes at the wrong byte, and the reassembled APDU is wrong rather than
//! absent.
//!
//! Note what that is *not*: "acknowledging a block means the buffer grew". A block may
//! legitimately carry an empty payload, and then the run advances while the length does
//! not. Stating the invariant the loose way makes it false for a frame a peer is entitled
//! to send — which is how this assertion first failed.

use dlms_cosem_rs::codec::Decode;
use dlms_cosem_rs::xdlms::{GbtAction, GbtReceiver, GeneralBlockTransfer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let mut storage = [0u8; 4096];
    let mut receiver = GbtReceiver::new(&mut storage);

    // Split the input into blocks on a marker byte, so one case is a whole transfer.
    for message in bytes.split(|b| *b == 0xFE) {
        if message.is_empty() {
            continue;
        }
        let Ok(block) = GeneralBlockTransfer::from_bytes(message) else { continue };
        let before = receiver.len();
        let before_ack = receiver.acknowledged();
        match receiver.push(&block) {
            Ok(action) => {
                if receiver.acknowledged() == block.block_number
                    && receiver.acknowledged() != before_ack
                {
                    // Accepted: exactly this block's payload, and nothing else.
                    assert_eq!(
                        receiver.len(),
                        before + block.block_data.len(),
                        "an accepted block stored the wrong number of bytes"
                    );
                } else {
                    // A duplicate, or one from beyond a gap. Storing it would leave a
                    // hole nothing fills.
                    assert_eq!(receiver.len(), before, "a block that was not accepted was stored anyway");
                }
                if action == GbtAction::Complete {
                    assert_eq!(
                        receiver.apdu().len(),
                        receiver.len(),
                        "a completed APDU is exactly what was gathered"
                    );
                    receiver.reset();
                }
            }
            Err(_) => {
                // The only failure is a buffer too small, and it must leave the receiver
                // usable rather than half-written.
                receiver.reset();
            }
        }
    }
});
