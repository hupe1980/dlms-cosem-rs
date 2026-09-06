# dlms-cosem-rs

**DLMS/COSEM (IEC 62056) in one Rust crate: sans-I/O, `no_std`, client *and* server.**

[![crates.io](https://img.shields.io/crates/v/dlms-cosem-rs.svg)](https://crates.io/crates/dlms-cosem-rs)
[![docs.rs](https://img.shields.io/docsrs/dlms-cosem-rs)](https://docs.rs/dlms-cosem-rs)
[![license](https://img.shields.io/crates/l/dlms-cosem-rs.svg)](#license)

**[Documentation and guides →](https://hupe1980.github.io/dlms-cosem-rs/)**

The protocol a smart electricity, gas, water or heat meter speaks to the system that
reads it — the object model, the application layer and the transports — with no sockets,
no clock and no async runtime in the core. The same code drives a head-end under Tokio,
a WASM decoder in a browser, and a meter or gateway on a Cortex-M under Embassy.

```rust
use dlms_cosem_rs::client::{AssociationStep, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider};
use dlms_cosem_rs::xdlms::AttributeDescriptor;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut session: ClientSession<_> = ClientSession::new(
    ClientConfig { client_sap: 0x10, ..Default::default() },
    RustCryptoProvider::new(KeyRing::default()),
);

// Bytes out, bytes in: the session never touches a socket.
let mut request = [0u8; 512];
let n = session.associate_request(&mut request)?;
// ... send request[..n] over HDLC, TCP, CoAP, whatever you have,
//     and feed the answer back:
# let mut server = doctest_server();
# let mut response = [0u8; 512];
# let m = server.handle(&request[..n], &mut response)?;
assert_eq!(session.handle_associate_response(&response[..m])?, AssociationStep::Established);

// Class 3 is Register, attribute 2 is its value. `obis-names` gives the well-known
// codes names — `obis::names::ACTIVE_ENERGY_IMPORT_TOTAL` is this one.
let n = session.get_request(
    AttributeDescriptor::new(3, Obis::new(1, 0, 1, 8, 0, 255), 2),
    None,
    &mut request,
)?;
# let m = server.handle(&request[..n], &mut response)?;
let mut scratch = [0u8; 512];
if let Response::Data(value) = session.handle_response(&response[..m], &mut scratch)? {
    println!("meter reads {:?} Wh", value.as_u64());
}
# Ok(())
# }
#
# // A one-object meter, so the example above is a test rather than a sketch.
# use dlms_cosem_rs::axdr::Data;
# use dlms_cosem_rs::codec::{Encode, Writer};
# use dlms_cosem_rs::cosem::AttributeAccess;
# use dlms_cosem_rs::server::{ObjectStore, Server, ServerConfig, StoreResult};
# use dlms_cosem_rs::xdlms::{DataAccessResult, SelectiveAccess};
# struct OneRegister;
# impl ObjectStore for OneRegister {
#     fn get_attribute(&self, _c: u16, _n: Obis, _a: i8, _s: Option<SelectiveAccess<'_>>, w: &mut dyn Writer) -> StoreResult<()> {
#         Data::DoubleLongUnsigned(12_345_678).encode(w).map_err(|_| DataAccessResult::OtherReason)
#     }
#     fn attribute_access(&self, _c: u16, _n: Obis, _a: i8) -> AttributeAccess { AttributeAccess::READ }
# }
# fn doctest_server() -> Server<OneRegister, RustCryptoProvider> {
#     Server::new(ServerConfig::default(), OneRegister, RustCryptoProvider::new(KeyRing::default()))
# }
```

## What is here

| Layer | What it does |
|---|---|
| [`codec`] | A bounds-checked cursor. Every error carries the **byte offset** it happened at. |
| [`axdr`] | `Data` borrowed from the input — a load profile decodes without allocating. Compact arrays, delta types, COSEM date-times with their wildcards intact. |
| [`ber`], [`acse`] | AARQ / AARE / RLRQ / RLRE: application context, authentication mechanism, system titles, conformance. |
| [`xdlms`] | Every APDU tag. GET / SET / ACTION / ACCESS, block transfer, general block transfer with its streaming window and retry, push, exceptions, and the four protection wrappers. |
| [`security`] | `glo-`/`ded-`/general ciphering under suites 0–2 at both key widths, HLS-GMAC, invocation counters with a real replay window, AES key wrap — all behind a swappable [`security::CryptoProvider`], which is the one place keys live. |
| [`cosem`] | Interface classes as a registry, OBIS, access rights in both the legacy and version-3 shapes, profile selective access, and profile buffers with all three compressions undone. |
| [`transport`] | HDLC with a resynchronising frame finder, segmentation, and a link machine that drives SNRM/UA and the sequence numbers; the TCP/UDP wrapper with bounded reassembly; **P1** — DSMR and eMUCs telegrams, with exact decimals rather than floats. |
| [`client`], [`server`] | Sans-I/O state machines with block transfer in both directions, every batched service, ACCESS, and both halves of push — a listener that reads a notification and a sender that builds one. |

## Why another one

Every existing DLMS stack gives up at least two of these. This one is meant to give up
none:

- **Permissively licensed.** MIT or Apache-2.0. The reference implementation is GPL-2 or
  commercial; the nearest Rust one is GPL-3.
- **`no_std`, `alloc` optional.** The full codec, HDLC, the wrapper, **both** engines and
  suite 0 build for `thumbv7em-none-eabihf` with no allocator at all.
- **Sans-I/O.** A whole association — AARQ, HLS-GMAC challenge and response, a ciphered
  GET, release — runs as a unit test in microseconds, and the same engine is fuzzed as a
  state machine rather than as a parser.
- **Client *and* server, from one object model.** [`cosem`] does not depend on
  [`xdlms`]: the model says what a meter *is*, the application layer says how to ask it.
- **Memory-safe and panic-free from the network.** `#![forbid(unsafe_code)]` and the
  panic family denied is the easy half. The half that matters: a release build for
  `thumbv7em-none-eabihf` and `riscv32imac-unknown-none-elf` contains **no panic symbols
  at all**, measured on object code with LTO off so the library stands on its own. CI
  fails if one appears.
- **Replay is rejected, not documented.** Every ciphered APDU spends an invocation
  counter that is never accepted twice, on the client, on the server and in the push
  listener. A recorded "open the breaker" is refused the second time.
- **Keys where you want them, in one place.** [`security::CryptoProvider`] is a trait; the
  default keeps keys in zeroised memory and never prints them, and a secure element or HSM
  is another implementation. Neither engine keeps a copy: two homes for a key is one
  misconfiguration away from an association that opens and then fails its first tag.

## Decrypting a meter's push

The Austrian, Luxembourg and Dutch customer interfaces emit a ciphered
`DataNotification` with no association and nothing to correlate. That is a listener, not
a session:

```rust,no_run
use dlms_cosem_rs::client::{NotificationListener, SingleMeterKeys};
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};

let mut listener = NotificationListener::new(
    RustCryptoProvider::new(KeyRing::default()),
    SingleMeterKeys::new(
        SystemTitle::new(*b"LGZ\x00\x12\x34\x56\x78"),
        KeyRing::new(*b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", [0xD0; 16]),
    ),
    // What the listener *requires*. A push is unsolicited, so nothing negotiated this:
    // the only statement about how a frame should have been protected is this one.
    SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
);

let frame: &[u8] = &[];               // whatever arrived on the M-Bus or P1 port
let mut scratch = [0u8; 512];
if let Ok(push) = listener.handle(frame, &mut scratch) {
    for field in push.body.as_structure().into_iter().flat_map(|s| s.iter()) {
        println!("{:?}", field);
    }
}
```

The listener refuses a frame protected more weakly than it asked for, refuses one whose
tag does not verify, refuses an invocation counter it has already accepted, and refuses
a meter it has no key for — it never guesses. A frame that fails to verify spends
nothing, so a forged counter cannot lock the real meter out.

## Features

`default = ["std", "client", "server", "hdlc", "wrapper", "p1", "suite0", "obis-names"]`

| Feature | What it switches on |
|---|---|
| `client` / `server` | The two engines. A head-end needs no server; meter firmware needs no client. |
| `hdlc` / `wrapper` / `p1` | The transports that exist: the HDLC data link, the TCP/UDP wrapper, and the P1 customer interface. |
| `suite0` | The AES-GCM provider, which serves ciphering under suites 0, 1 and 2. Implies `crypto`. |
| `crypto` | Zeroised key storage and constant-time comparison, without a cipher. |
| `obis-names` | Names for the well-known OBIS codes. Pure tables. |
| `std` / `alloc` / `heapless` | Environment. `std` implies `alloc`. |

**Every feature here switches code that exists**, and CI builds each one alone. A flag
that gates nothing is worse than no flag: it tells you the crate does something it does
not, and it makes `--all-features` a weaker check than it looks. There is deliberately
no `suite1`/`suite2` flag — see Status.

Without `alloc` you still get the full codec over borrowed data, HDLC and the wrapper,
and both engines with caller-provided buffers.

## Status

**Pre-release.** The API is being made right rather than kept stable; the minor version is
the breaking one.

**Built and tested.** The codec, OBIS, A-XDR (compact arrays and delta types included), BER
and ACSE. Every APDU tag; GET, SET, ACTION and ACCESS with every batched `with-list` form;
push in both directions; general block transfer with its edition-9 streaming window and
retry. All three protection forms under suites 0, 1 and 2, with the dedicated key
negotiated rather than configured. Replay rejection on both engines and in the push
listener. Block transfer in *both* directions for all three services, HDLC segmentation,
and the two composing — which is what reading a load profile over an optical probe
actually needs. HDLC framing, segmentation and the link machine; the wrapper; P1.

**Refused rather than guessed.** High level security mechanisms 3, 4, 6 and 7 return
`Unsupported` by name: their exact constructions are in material this project does not
have, and a guessed construction authenticates nothing while looking like it does. The
asymmetric halves of suites 1 and 2 are not implemented, and there is deliberately no
feature flag suggesting otherwise.

**Not built.** Short-name referencing; the CoAP transport; confirmed push and push
*scheduling*; the gateway protocol, SMS, M-Bus and mode E; `tokio` and `embedded-io`
adapters. HDLC does not retransmit and push has no schedule, for the same structural
reason: both need a timer, and there is no clock in this crate.

The [status page](https://hupe1980.github.io/dlms-cosem-rs/docs/status/) has the full list,
and what each test is actually worth.

**Invocation counters must outlive the process.** Both engines start from
`invocation_counter` in their config and expose the value to persist. A device that
restarts from zero against an unchanged key reuses every nonce it used before, and a
repeated GCM nonce leaks the authentication subkey rather than a single plaintext. The
crate cannot detect this for you; it can only refuse to hide it.

**Interoperability has not been tested.** Almost every green test is this crate agreeing
with itself. The exceptions are the NIST and RFC cipher vectors, the published xDLMS
Initiate encodings and CRC-16's own check values — real independent evidence, but a narrow
slice of the protocol. Until it has been run against another implementation this crate
says "verified against the standard's own vectors", never "conformant".

## Standards

The DLMS User Association's Blue Book (edition 18) and Green Book (edition 12) are the
masters; IEC 62056-5-3, -6-1 and -6-2 (all edition 4.0, 2023) mirror them. Those
documents are copyrighted and are **not** redistributed here: this crate contains
encodings, tag values, class identifiers and OBIS codes, which are facts, and no
specification prose.

## Examples

Five, and all of them run.

```sh
cargo run --example association   # a whole ciphered association, no sockets at all
cargo run --example decode        # hex in, a decoded APDU out — a protocol translator
cargo run --example p1            # a DSMR telegram from the customer interface
```

`association` is the crate's central claim made runnable: both engines in one process,
four-pass high level security, a ciphered read, a breaker operation and a replay that is
refused — with the entire "transport" being one `copy_from_slice`.

The other two are a pair, over a real socket:

```sh
cargo run --example meter         # a meter simulator on 127.0.0.1:4059
cargo run --example read          # read it — or a real meter: `-- 10.0.0.5:4059`
cargo run --example meter -- --ciphered   # the same pair, protected
```

`meter` speaks the TCP wrapper, so **any** DLMS client can be pointed at it. That is
deliberate: the crate's largest gap is that almost every test is this code agreeing with
itself, and a simulator somebody else's stack can read is what closes it.

## Documentation

- **[Guides and reference](https://hupe1980.github.io/dlms-cosem-rs/)** — getting started,
  the cookbook, the security model, the transports, hosting a meter, and building for a
  microcontroller.
- **[API documentation](https://docs.rs/dlms-cosem-rs)** — generated from the same source.

## License

MIT OR Apache-2.0, at your option.
