```rust
let mut listener = NotificationListener::new(
    RustCryptoProvider::new(KeyRing::default()),
    SingleMeterKeys::new(meter_title, KeyRing::new(guek, gak)),
    // What the listener *requires*. A push is unsolicited, so nothing negotiated
    // this: the only statement about how a frame should have been protected is
    // this one.
    SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
);

let mut scratch = [0u8; 512];
if let Ok(push) = listener.handle(frame, &mut scratch) {
    for field in push.body.as_structure().into_iter().flat_map(|s| s.iter()) {
        println!("{:?}", field);
    }
}
```
