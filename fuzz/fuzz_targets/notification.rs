#![no_main]
//! The push listener, which is the one decoder an unauthenticated stranger can reach.
//!
//! A notification arrives with no association and nothing to correlate. The listener
//! must never accept one that is protected more weakly than it was told to require, and
//! must never accept the same invocation counter twice — and it must do both without
//! aborting on whatever bytes turn up.

use dlms_cosem_rs::client::{NotificationListener, SingleMeterKeys};
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use libfuzzer_sys::fuzz_target;

const GUEK: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] = [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
const METER: SystemTitle = SystemTitle::new([0x4C, 0x47, 0x5A, 0x00, 0x12, 0x34, 0x56, 0x78]);

fuzz_target!(|bytes: &[u8]| {
    let required = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let mut listener = NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(METER, KeyRing::new(GUEK, GAK)),
        required,
    );
    let mut buf = [0u8; 4096];

    // Whole frames, and the same frames split, so a session of many messages is one case.
    for message in bytes.split(|b| *b == 0xFE) {
        if message.is_empty() {
            continue;
        }
        if let Ok(n) = listener.handle(message, &mut buf) {
            // Anything that came back must have been protected as demanded: an accepted
            // notification is one the caller will act on.
            assert!(
                n.invocation_counter.is_some(),
                "an accepted notification under an authenticated policy must have been ciphered"
            );
            // And the very same bytes must never be accepted twice.
            assert!(
                listener.handle(message, &mut buf).is_err(),
                "a replayed notification was accepted a second time"
            );
        }
        let _ = listener.handle_from(METER, message, &mut buf);
    }
});
