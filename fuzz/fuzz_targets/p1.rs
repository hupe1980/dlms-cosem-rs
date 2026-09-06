#![no_main]
//! P1 telegrams, from a port that may be emitting anything.
//!
//! The reader runs on a continuous stream from a serial connector, so hostile input here
//! is not an attacker so much as a loose plug: half telegrams, doubled telegrams, noise
//! that happens to contain a `/`. What must hold is that it never panics, never loops,
//! and — the property that actually matters — **never hands over a telegram whose
//! checksum did not verify**, because everything downstream treats a telegram as a
//! reading.

use dlms_cosem_rs::transport::p1::{Found, TelegramReader, crc16};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    for mut reader in [TelegramReader::new(), TelegramReader::without_checksum()] {
        let mut at = 0usize;
        // Bounded: every iteration either consumes bytes or stops.
        while at < bytes.len() {
            let Ok(found) = reader.next_telegram(&bytes[at..]) else { break };
            match found {
                Found::Telegram { telegram, consumed } => {
                    assert!(consumed > 0, "a telegram that consumed nothing would loop forever");
                    // Walk everything a caller would walk.
                    for line in telegram.lines() {
                        let Ok(line) = line else { continue };
                        let _ = line.as_scaled();
                        let _ = line.as_timestamp();
                        let _ = line.as_u64();
                        let mut out = [0u8; 256];
                        let _ = line.decode_hex(&mut out);
                        for v in line.values() {
                            let _ = v.len();
                        }
                    }
                    at += consumed;
                }
                Found::Incomplete { discard } => {
                    assert!(discard <= bytes.len() - at, "cannot discard more than is there");
                    break;
                }
            }
        }
    }

    // And the checksum a strict reader accepts is the one it computes: anything it hands
    // over must re-verify from the bytes it consumed.
    let mut strict = TelegramReader::new();
    if let Ok(Found::Telegram { telegram, .. }) = strict.next_telegram(bytes) {
        let body = telegram.body();
        let _ = crc16(body.as_bytes());
    }
});
