```rust
let mut session: ClientSession<_> = ClientSession::new(
    ClientConfig { client_sap: 0x10, ..Default::default() },
    RustCryptoProvider::new(KeyRing::default()),
);

let mut request = [0u8; 512];
let n = session.associate_request(&mut request)?;
// ... send request[..n] over HDLC, TCP, CoAP, whatever you have,
//     and feed the answer back:
session.handle_associate_response(&response)?;

let n = session.get_request(
    AttributeDescriptor::new(3, ACTIVE_ENERGY_IMPORT_TOTAL, 2),
    None,
    &mut request,
)?;

let mut scratch = [0u8; 512];
if let Response::Data(value) = session.handle_response(&answer, &mut scratch)? {
    println!("meter reads {:?} Wh", value.as_u64());
}
```
