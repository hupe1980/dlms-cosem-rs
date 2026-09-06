+++
title = "Getting started"
description = "Install dlms_cosem_rs, understand what sans-I/O means for your code, and read your first register from a smart meter over TCP."
weight = 10
+++

## What this crate is, and is not

`dlms_cosem_rs` implements **DLMS/COSEM** — IEC 62056, the protocol nearly every European
smart meter speaks. The DLMS User Association describes the standard in three steps, and
the crate follows the same three:

1. **Modelling.** A meter is a set of *logical devices* holding *objects*. An object is an
   instance of an *interface class* (a `class_id` and a `version`) named by a six-byte
   **OBIS** code like `1-0:1.8.0*255`. Attribute 1 is always that name.
2. **Messaging.** GET, SET, ACTION and ACCESS request and change those attributes;
   DataNotification pushes them unasked. A-XDR encodes the values, BER encodes the
   handshake.
3. **Transporting.** HDLC on an optical probe or RS-485, a thin wrapper over TCP or UDP,
   and — on the customer side — the P1 telegram.

It is a **library, not a stack**. No sockets, no clock, no async runtime, no cryptography
in the core: those belong to you. That is the point rather than an omission — the same
protocol logic drives a head-end under Tokio, a decoder compiled to WASM, and meter
firmware on a Cortex-M with no allocator.

## Install

```toml
[dependencies]
dlms_cosem_rs = "0.0"
```

The default feature set is `std`, `client`, `server`, `hdlc`, `wrapper`, `p1`, `suite0`
and `obis-names`. Take what you need:

| Feature | What it switches on |
|---|---|
| `client` / `server` | The two engines. A head-end needs no server; meter firmware needs no client. |
| `hdlc` / `wrapper` / `p1` | The transports: the HDLC data link, the TCP/UDP wrapper, the P1 customer interface. |
| `suite0` | The AES-GCM provider, which serves ciphering under suites 0, 1 and 2. Implies `crypto`. |
| `crypto` | Zeroised key storage and constant-time comparison, without a cipher. |
| `obis-names` | Names for the well-known OBIS codes. Pure tables; off saves the strings. |
| `std` / `alloc` / `heapless` | Environment. `std` implies `alloc`. |

**Every feature switches code that exists**, and CI builds each one on its own. A flag
that gates nothing is worse than no flag: it tells you the crate does something it does
not, and it makes `--all-features` a weaker check than it looks.

## What sans-I/O means for your code

There is no `connect`. A session *builds* an APDU into a buffer you own and *consumes* one
out of a buffer you own:

```rust,ignore
let n = session.associate_request(&mut request)?;      // bytes out
session.handle_associate_response(&reply)?;            // bytes in
```

Moving those bytes is yours: a `TcpStream`, a serial port, an `embedded-io` device, a
`Vec` in a test. Two consequences are worth knowing up front.

**Buffers are parameters, not fields.** `handle_response(apdu, buf)` takes the scratch
buffer to decrypt into, and the value it returns borrows that buffer. A buffer hidden
inside the session would make the borrow checker refuse a caller that wants to hold a
value across the next request, and would hide how long a decrypted plaintext lingers in
memory. Making it a parameter puts both facts in the signature.

**Randomness is injected; time is data.** A provider without an entropy source refuses to
produce a high-level-security challenge rather than returning something predictable. There
is no clock at all — a timestamp is a `DateTime` you supply, and nothing in the crate can
say “wake me in three seconds”.

## Read one register over TCP

```rust,ignore
use std::net::TcpStream;

use dlms_cosem_rs::client::{AssociationStep, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::obis::names::ACTIVE_ENERGY_IMPORT_TOTAL;
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider};
use dlms_cosem_rs::xdlms::AttributeDescriptor;

let mut sock = TcpStream::connect("10.0.0.5:4059")?;
let mut session: ClientSession<_> = ClientSession::new(
    ClientConfig { client_sap: 0x10, ..Default::default() },   // 0x10 = the public client
    RustCryptoProvider::new(KeyRing::default()),
);

let mut request = [0u8; 1024];

// Two passes with no authentication; four with high level security.
let n = session.associate_request(&mut request)?;
let aare = exchange(&mut sock, &request[..n])?;
assert_eq!(session.handle_associate_response(&aare)?, AssociationStep::Established);

let n = session.get_request(
    AttributeDescriptor::new(3, ACTIVE_ENERGY_IMPORT_TOTAL, 2),   // class 3, attribute 2
    None,                                                          // no selective access
    &mut request,
)?;
let answer = exchange(&mut sock, &request[..n])?;

let mut scratch = [0u8; 1024];
if let Response::Data(value) = session.handle_response(&answer, &mut scratch)? {
    println!("{:?} Wh", value.as_u64());
}
```

`AttributeDescriptor::new(3, …, 2)` says: interface class 3 (*Register*), this OBIS code,
attribute 2 (*value*). Attribute 3 of the same class is the `scaler_unit` pair that tells
you it is watt-hours and where the decimal point goes — the crate keeps that as an exact
integer and an exponent rather than a float, because 12 345 with a scaler of −3 is exactly
12.345 kWh and `12.345_f64` is not.

The full version of this recipe, with the wrapper framing and the stream reassembly
written out, is in the [cookbook](@/docs/cookbook.md).

## Run something first

Five examples ship with the source, and all of them run:

```sh
cargo run --example association   # a whole ciphered association, no sockets at all
cargo run --example decode        # hex in, a decoded APDU out — a protocol translator
cargo run --example p1            # a DSMR telegram from the customer interface
```

`association` is this page's argument made runnable: both engines in one process, four
passes of high level security, a ciphered read, a breaker operation, and a recorded frame
replayed and refused — with the whole transport being one `copy_from_slice`. Reading it
takes five minutes and answers most of what "sans-I/O" means in practice.

The other two are a pair over a real socket:

```sh
cargo run --example meter         # a meter simulator on 127.0.0.1:4059
cargo run --example read          # read it — or a real meter: `-- 10.0.0.5:4059`
```

`meter` speaks the TCP wrapper, so any DLMS client can be pointed at it, not only this
one.

## What to read next

- **[The cookbook](@/docs/cookbook.md)** — the things people actually do, each one a
  compiled example.
- **[Security](@/docs/security.md)** — if the meter needs a password or a key, start here.
  Invocation counters have one rule you must get right and the crate cannot get it for
  you.
- **[Services and segmentation](@/docs/services.md)** — why reading a load profile needs
  two different segmentation mechanisms at once.
- **[Status](@/docs/status.md)** — what is built, what is refused, and what is not proven.
