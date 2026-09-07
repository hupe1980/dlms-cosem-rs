# Cookbook

Short answers to the things people actually want to do. Every snippet here is compiled —
and, where it needs no socket, run — as part of the test suite, so a recipe that stops
working fails the build rather than quietly misleading somebody.

The recipes assume the **default features**. Two of them reach past that floor and say so:
the P1 reader needs `p1`, and the named OBIS constants need `obis-names`. Everything else
works with `client`, `server` and whichever transport you are using.

## Read one register over TCP

The session is sans-I/O: it hands you bytes and takes bytes back. A socket is yours.

```rust,no_run
use std::io::{Read, Write};
use std::net::TcpStream;

use dlms_cosem_rs::client::{AssociationStep, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::codec::Encode;
use dlms_cosem_rs::obis::names::ACTIVE_ENERGY_IMPORT_TOTAL;
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider};
use dlms_cosem_rs::transport::wrapper::{StreamReassembler, Wpdu};
use dlms_cosem_rs::xdlms::AttributeDescriptor;

const CLIENT_SAP: u16 = 0x0010;
const LOGICAL_DEVICE: u16 = 0x0001;

fn exchange(sock: &mut TcpStream, apdu: &[u8], scratch: &mut Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    Wpdu::new(CLIENT_SAP, LOGICAL_DEVICE, apdu).unwrap().encode(&mut out).unwrap();
    sock.write_all(&out)?;

    let reassembler = StreamReassembler::new(2048);
    let mut chunk = [0u8; 512];
    loop {
        if let Ok(Some((pdu, used))) = reassembler.next_pdu(scratch) {
            let answer = pdu.apdu.to_vec();
            scratch.drain(..used);
            return Ok(answer);
        }
        let n = sock.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        scratch.extend_from_slice(&chunk[..n]);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sock = TcpStream::connect("10.0.0.5:4059")?;
    let mut session: ClientSession<_> = ClientSession::new(
        ClientConfig { client_sap: 0x10, ..Default::default() },
        RustCryptoProvider::new(KeyRing::default()),
    );

    let mut request = [0u8; 1024];
    let mut held = Vec::new();

    let n = session.associate_request(&mut request)?;
    let aare = exchange(&mut sock, &request[..n], &mut held)?;
    assert_eq!(session.handle_associate_response(&aare)?, AssociationStep::Established);

    let n = session.get_request(
        AttributeDescriptor::new(3, ACTIVE_ENERGY_IMPORT_TOTAL, 2),
        None,
        &mut request,
    )?;
    let answer = exchange(&mut sock, &request[..n], &mut held)?;

    let mut scratch = [0u8; 1024];
    if let Response::Data(value) = session.handle_response(&answer, &mut scratch)? {
        println!("{:?} Wh", value.as_u64());
    }

    let n = session.release_request(&mut request)?;
    let _ = exchange(&mut sock, &request[..n], &mut held);
    Ok(())
}
```

## Open a ciphered association with high level security

The only difference is configuration. A ciphered association needs a system title —
without one the client cannot form a nonce, and it refuses rather than reusing one.

**The keys live in exactly one place: the provider.** There is no second copy in the
configuration to fall out of step with it, and a provider backed by a secure element
holds them somewhere the application core never sees.

```rust
use dlms_cosem_rs::acse::AuthMechanism;
use dlms_cosem_rs::client::{ClientConfig, ClientSession};
use dlms_cosem_rs::security::{
    KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle,
};

# fn main() {
# let guek = [0u8; 16];
# let gak = [0u8; 16];
# struct Os;
# impl dlms_cosem_rs::security::RandomSource for Os {
#     fn fill(&self, out: &mut [u8]) -> dlms_cosem_rs::codec::Result<()> { out.fill(1); Ok(()) }
# }
let session: ClientSession<_> = ClientSession::new(
    ClientConfig {
        client_sap: 0x30,                                   // management client
        system_title: Some(SystemTitle::new(*b"CLI\x00\x00\x00\x00\x01")),
        mechanism: AuthMechanism::HighGmac,
        security: SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
        ..Default::default()
    },
    // The provider holds the keys and needs entropy for the challenge. Wire in your
    // platform's generator; a provider without one refuses to invent it.
    RustCryptoProvider::with_rng(KeyRing::new(guek, gak), Os),
);
# let _ = session;
# }
```

**Suite 2** is the same code with longer keys: `KeyRing::new_256(guek, gak)` and
`SecuritySuite::Suite2`. Ciphering is AES-GCM in all three suites — 128-bit for suites 0
and 1, 256-bit for suite 2 — and the suite travels in the low nibble of every security
control byte. What suites 1 and 2 *add* is asymmetric (key agreement, signing,
certificates) and none of that is implemented; there is no feature flag suggesting
otherwise.

**A dedicated key** is negotiated rather than configured. Put one in the client's ring
and name it on the policy's key set:

```rust,ignore
let mut keys = KeyRing::new(guek, gak);
keys.set_dedicated(Key::new(dedicated));
// …
security: SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0).with_dedicated(true),
```

The client delivers it inside the ciphered `InitiateRequest` and both ends switch to the
`ded-` tags for everything afterwards. The server configures nothing: it learns the key
from the message and follows it, because only the client knows there is one. The
`InitiateRequest` itself is protected with the **global** key set — it is what carries
the dedicated key, so nothing can be protected with that key before it has been opened.

The handshake then takes four passes instead of two:

```text
client                                  server
  |  AARQ (context ciphered, CtoS)        |
  |-------------------------------------->|
  |         AARE (accepted, StoC)         |
  |<--------------------------------------|
  |  ACTION reply_to_HLS_authentication    |   f(StoC) = SC ‖ IC ‖ GMAC(AK, SC‖AK‖StoC)
  |-------------------------------------->|
  |         ACTION response f(CtoS)        |   verified before the association is used
  |<--------------------------------------|
```

`ClientSession::handle_associate_response` returns `AssociationStep::HlsReplyRequired`
when the third pass is needed, so a driver that loops on the step handles both cases
without knowing which mechanism was configured.

### When the association will not open because the counter is stale

The `InitiateRequest` is the first protected message a ciphered association sends, so a
client that restarted from a backup fails **there** rather than on its first read. The
server answers `invocation-counter-error` carrying the value it expects next, and the
client reads it as a step of its own:

```rust,ignore
match session.handle_associate_response(&aare)? {
    AssociationStep::Exception(e) => {
        if let Some(expected) = e.expected_invocation_counter {
            // A deliberate decision, made once, by you: an exception response is
            // unprotected and anyone can forge one, and moving a counter *backwards*
            // is what burns a key.
            session.set_invocation_counter(expected.saturating_sub(1));
        }
    }
    step => { /* … */ }
}
```

### Which key set opens a frame is yours to state

The security control byte carries a bit naming the broadcast key set, and on a received
frame that bit is the sender's claim. A broadcast key is shared with a whole fleet, so a
unicast exchange accepted under one lets any member of that fleet answer as the head-end,
with a tag that verifies. So the key set is part of the policy — `key_set`, defaulting to
the global unicast key — and a frame whose bit disagrees is refused before a key is
touched. A caller that genuinely wants the broadcast key set asks for it:

```rust,ignore
security: SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0).with_broadcast(true),
```

## Read a dozen registers in one round trip

Issuing the reads separately costs a round trip each, and on a GPRS or LPWAN link that
is the whole cost. `get-request-with-list` asks for all of them at once and answers with
one result per attribute, in order.

```rust,no_run
use dlms_cosem_rs::client::Response;
use dlms_cosem_rs::xdlms::{AttributeDescriptor, AttributeDescriptorWithSelection};
# use dlms_cosem_rs::client::{ClientConfig, ClientSession};
# use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider};
# use dlms_cosem_rs::obis::Obis;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut session: ClientSession<_> = ClientSession::new(
#     ClientConfig::default(), RustCryptoProvider::new(KeyRing::default()));
# let mut request = [0u8; 512];
# let mut scratch = [0u8; 512];
# fn exchange(_: &[u8]) -> Vec<u8> { Vec::new() }
let wanted = [
    AttributeDescriptor::new(3, Obis::new(1, 0, 1, 8, 0, 255), 2),   // import energy
    AttributeDescriptor::new(3, Obis::new(1, 0, 2, 8, 0, 255), 2),   // export energy
    AttributeDescriptor::new(8, Obis::new(0, 0, 1, 0, 0, 255), 2),   // the clock
];
let items: Vec<_> = wanted
    .iter()
    .map(|&descriptor| AttributeDescriptorWithSelection { descriptor, access: None })
    .collect();

let n = session.get_request_with_list(&items, &mut request)?;
let response = exchange(&request[..n]);
if let Response::DataList(results) = session.handle_response(&response, &mut scratch)? {
    for (descriptor, result) in wanted.iter().zip(results.iter()) {
        match result?.value() {
            Ok(value) => println!("{descriptor:?} = {value:?}"),
            // One unreadable object costs its own slot, not the whole read.
            Err(why) => println!("{descriptor:?} refused: {why:?}"),
        }
    }
}
# Ok(())
# }
```

A list response too large for one APDU is blocked like any other. What the blocks carry
is the encoded *list*, so reassemble it with `BlockCollector::results()` rather than
`value()` — calling the wrong one is a decode error, not a wrong answer.

## Read, write and invoke in one round trip

`get-request-with-list` batches reads. The **ACCESS** service batches all three, which is
what a battery-powered device on a low-power network wants: there the cost is round
trips, not bytes.

```rust,no_run
use dlms_cosem_rs::client::{AccessItem, Response};
use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::xdlms::{AttributeDescriptor, MethodDescriptor};
# use dlms_cosem_rs::client::{ClientConfig, ClientSession};
# use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider};
# use dlms_cosem_rs::obis::Obis;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut session: ClientSession<_> = ClientSession::new(
#     ClientConfig::default(), RustCryptoProvider::new(KeyRing::default()));
# let mut request = [0u8; 512];
# let mut scratch = [0u8; 512];
# fn exchange(_: &[u8]) -> Vec<u8> { Vec::new() }
let items = [
    AccessItem::Get {
        descriptor: AttributeDescriptor::new(3, Obis::new(1, 0, 1, 8, 0, 255), 2),
        access: None,
    },
    AccessItem::Action {
        descriptor: MethodDescriptor::new(70, Obis::new(0, 0, 96, 3, 10, 255), 2),
        parameters: Some(Data::Integer(0)),
    },
];

let n = session.access_request(&items, &mut request)?;
let answer = exchange(&request[..n]);
if let Response::Access { data, results } = session.handle_response(&answer, &mut scratch)? {
    // The three lists are positional: entry *i* of each belongs to item *i*. A write
    // and a failed read occupy their slot with `null-data` rather than being omitted,
    // so you never have to count which entries produced anything.
    for (value, outcome) in data.iter().zip(results.iter()) {
        println!("{:?} -> {:?}", outcome?, value?);
    }
}
# Ok(())
# }
```

ACCESS has no ciphered tag of its own, so on a protected link it travels inside
`general-glo-ciphering` and needs `Conformance::GENERAL_PROTECTION` as well as
`Conformance::ACCESS`. Both are in `CLIENT_DEFAULT`; a meter that offers neither gets a
`require` failure before anything goes on the wire.

## Ask for part of a profile instead of all of it

Selective access narrows a read at the meter, which is the difference between fetching a
day and fetching a year. Two selectors are defined: by a range of the sort value
(usually the clock), and by entry position.

```rust
use dlms_cosem_rs::cosem::{EntryDescriptor, RangeDescriptor};
use dlms_cosem_rs::axdr::DateTime;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// By position: entries 3 to 7 inclusive. Zero as the end means "to the end of the
// buffer" — it is not an index, and a meter that reads it as one returns nothing.
let mut params = [0u8; 64];
let by_entry = EntryDescriptor::entries(3, 7).to_selective_access(&mut params)?;
assert_eq!(by_entry.selector, 2);

// By clock: a day of a load profile.
let mut params = [0u8; 96];
let from = DateTime::from_civil(2026, 9, 1, 0, 0, 0, 120);
let to = DateTime::from_civil(2026, 9, 2, 0, 0, 0, 120);
let by_range = RangeDescriptor::by_clock(from, to).to_selective_access(&mut params)?;
assert_eq!(by_range.selector, 1);
# Ok(())
# }
```

Pass `Some(access)` to `get_request`. On the server side the descriptor arrives in
`ObjectStore::get_attribute` exactly as it was built — **and honouring it is the store's
job**. A store that accepts a selector and ignores it answers a day's request with a
year of data and nothing in the exchange says so, which is why the right answer to a
selector you do not implement is `ScopeOfAccessViolated` rather than the whole buffer.

## Read something larger than the PDU size

A profile buffer never fits in one APDU. The server cuts the encoded value into
`get-response-with-datablock` fragments and the client puts them back together. The
fragment boundaries fall wherever the server's budget ran out, which is usually in the
middle of a length prefix, so **no single block is a decodable value** — only the
concatenation is.

```rust,no_run
use dlms_cosem_rs::client::{BlockCollector, Response};
# use dlms_cosem_rs::client::{ClientConfig, ClientSession};
# use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider};
# use dlms_cosem_rs::xdlms::AttributeDescriptor;
# use dlms_cosem_rs::obis::Obis;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut session: ClientSession<_> = ClientSession::new(
#     ClientConfig::default(), RustCryptoProvider::new(KeyRing::default()));
# let descriptor = AttributeDescriptor::new(7, Obis::new(1, 0, 99, 1, 0, 255), 2);
# let mut request = [0u8; 512];
# let mut scratch = [0u8; 512];
# fn exchange(_: &[u8]) -> Vec<u8> { Vec::new() }
// One buffer for the whole value. Its size is a property of the meter, not of the
// protocol, so it is yours to choose.
let mut storage = [0u8; 8192];
let mut blocks = BlockCollector::new(&mut storage);

let mut n = session.get_request(descriptor, None, &mut request)?;
loop {
    let response = exchange(&request[..n]);
    match session.handle_response(&response, &mut scratch)? {
        Response::Block { last, number, data } => {
            blocks.push(number, data)?;         // refuses a duplicate or a gap
            if last { break; }
            n = session.get_next_block_request(number, &mut request)?;
        }
        Response::Data(_value) => break,        // it fitted after all
        other => return Err(format!("{other:?}").into()),
    }
}

let rows = blocks.value()?;
for row in rows.as_array().into_iter().flat_map(|a| a.iter()) {
    println!("{:?}", row?);
}
# Ok(())
# }
```

`push` insists that block numbers arrive consecutively from one. That is not
bookkeeping: a duplicated or reordered fragment concatenated in the wrong place usually
still *decodes*, into a reading that is simply wrong and that no error is ever attached
to.

On the server side there is nothing to do — segmentation is in the framework. What you
do have to choose is the `N` on `Server<Store, Provider, N>`, because it bounds the
largest value your store can produce. `N` and the PDU size are different limits: the PDU
size bounds one *message*, `N` bounds the whole *value* before it is cut up.

## Write something larger than the PDU size

The direction most stacks leave out. Reading a load profile needs blocks for the
*response*; writing an activity calendar, a set of tariff scripts or a firmware image
needs them for the *request*.

```rust,no_run
use dlms_cosem_rs::client::Response;
use dlms_cosem_rs::xdlms::AttributeDescriptor;
# use dlms_cosem_rs::client::{ClientConfig, ClientSession};
# use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider};
# use dlms_cosem_rs::obis::Obis;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut session: ClientSession<_> = ClientSession::new(
#     ClientConfig::default(), RustCryptoProvider::new(KeyRing::default()));
# let descriptor = AttributeDescriptor::new(18, Obis::new(0, 0, 44, 0, 0, 255), 2);
# let mut request = [0u8; 512];
# let mut scratch = [0u8; 512];
# let encoded_value: Vec<u8> = Vec::new();
# fn exchange(_: &[u8]) -> Vec<u8> { Vec::new() }
// The encoded value stays yours, as the collector's buffer does on the way back: how
// large a value a deployment writes is a property of the deployment.
let mut sender = session.set_transfer(descriptor, None, &encoded_value)?;
while !sender.is_done() {
    let n = session.next_block_request(&mut sender, &mut request)?;
    let answer = exchange(&request[..n]);
    match session.handle_response(&answer, &mut scratch)? {
        Response::BlockAccepted { .. } => {}          // send the next one
        Response::Ok => break,                        // the last block took effect
        other => return Err(format!("{other:?}").into()),
    }
}
# Ok(())
# }
```

`action_transfer` does the same for a method parameter. A method whose *return* value is
too large comes back as `Response::Block`, pulled with `action_next_block_request` and
reassembled with the same `BlockCollector`.

## Move a whole APDU with general block transfer

GBT is the *third* segmentation mechanism and the only service-independent one: it cuts
an **APDU** into blocks, whatever service the APDU carries — including the ones that have
no blocked form of their own.

```rust
use dlms_cosem_rs::codec::Decode;
use dlms_cosem_rs::xdlms::{GbtAction, GbtReceiver, GbtSender, GeneralBlockTransfer};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let apdu = [0xC4u8; 1000];
# fn send(_: &[u8]) {}
let mut sender = GbtSender::new(&apdu, 128, 4, true)?;   // 128-byte blocks, window of 4
let mut storage = [0u8; 2048];
let mut receiver = GbtReceiver::new(&mut storage);

let mut frame = [0u8; 256];
while !sender.is_done() {
    while let Some(n) = sender.next_block(&mut frame)? {
        send(&frame[..n]);
        // …the peer's side, here in the same process for the sake of the example:
        let block = GeneralBlockTransfer::from_bytes(&frame[..n])?;
        match receiver.push(&block)? {
            GbtAction::Await => {}                       // the window is not full yet
            _ => sender.acknowledge(receiver.acknowledged())?,
        }
    }
}
assert_eq!(receiver.apdu(), &apdu[..]);
# Ok(())
# }
```

An acknowledgement names the highest block the peer received **in order**, so one lower
than the last block sent is not an error — it is the receiver saying where the run broke,
and `acknowledge` rewinds the sender to just after it. That single rule is the whole
retry sub-procedure, and it is why a lost block costs the blocks after it rather than the
transfer.

## Three segmentations, and which one you need

They are different mechanisms at different layers, and they compose rather than
substitute:

| | Cuts up | Bounded by | Lives in |
|---|---|---|---|
| Block transfer | a *value* (GET, SET, ACTION) | the negotiated PDU size | `client` / `server` |
| General block transfer | an *APDU*, any service | the negotiated PDU size | `xdlms::Gbt*` |
| HDLC segmentation | an *APDU* | the negotiated information field | `transport::hdlc` |

A meter on an optical probe typically negotiates a 128-byte information field and a
1024-byte PDU size, so reading a load profile needs two of the three at once. A stack
with only one works right up until somebody reads a profile — which is the only thing
anybody reads.

## Decode a profile buffer, with its compression undone

Compression comes in two forms and both are undone here: a column that repeats the
previous row is sent as `null-data`, and a run of repeated columns at the *end* of a row
is sent by making the row shorter. The visitor sees every column of every row either
way. Handling that in the caller is how a load profile ends up with holes.

```rust
use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::codec::Decode;
use dlms_cosem_rs::cosem::ProfileBuffer;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Two columns; the second row repeats the first.
let encoded = [
    0x01, 0x02,
    0x02, 0x02, 0x11, 0x07, 0x12, 0x00, 0x64,
    0x02, 0x02, 0x00, 0x12, 0x00, 0xC8,
];
let value = Data::from_bytes(&encoded)?;
let buffer = ProfileBuffer::new(&value)?;

buffer.for_each_cell(2, |row, column, cell| {
    println!("row {row} column {column} = {:?}", cell.as_i64());
    Ok(())
})?;
// row 1 column 0 prints 7, carried forward, not None.
# Ok(())
# }
```

A `bcd` cell is the exception to `as_i64`: `0x25` is the number twenty-five, not
thirty-seven, so it has its own accessor, `Data::as_bcd`, and answers `None` to
`as_i64`. Both readings look like plausible meter values, which is what makes silently
picking one expensive.

## Host a meter

Implement `ObjectStore` and the framework does associations, authentication, access
control and protection. Note that `attribute_access` defaults to *nothing*: a store that
forgets it exposes nothing rather than everything.

```rust
use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::codec::{Encode, Writer};
use dlms_cosem_rs::cosem::AttributeAccess;
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::server::{ObjectStore, StoreResult};
use dlms_cosem_rs::xdlms::{DataAccessResult, SelectiveAccess};

struct Meter {
    energy_wh: u32,
}

impl ObjectStore for Meter {
    fn get_attribute(
        &self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        _selective_access: Option<SelectiveAccess<'_>>,
        w: &mut dyn Writer,
    ) -> StoreResult<()> {
        match (class_id, logical_name.as_bytes(), attribute_id) {
            (_, _, 1) => Data::OctetString(logical_name.as_bytes()).encode(w),
            (3, [1, 0, 1, 8, 0, 255], 2) => Data::DoubleLongUnsigned(self.energy_wh).encode(w),
            _ => return Err(DataAccessResult::ObjectUndefined),
        }
        .map_err(|_| DataAccessResult::OtherReason)
    }

    fn attribute_access(&self, _class_id: u16, _logical_name: Obis, _attribute_id: i8) -> AttributeAccess {
        AttributeAccess::READ
    }
}
# fn main() { let _ = Meter { energy_wh: 0 }; }
```

## Keep a record of what the meter was asked to do

`ObjectStore::audit` is called for every association attempt, every read and write and
every method invocation, with the outcome — **including the refusals**.

```rust
use dlms_cosem_rs::server::AuditEvent;
# use dlms_cosem_rs::server::{ObjectStore, StoreResult};
# use dlms_cosem_rs::obis::Obis;
# use dlms_cosem_rs::codec::Writer;
# use dlms_cosem_rs::xdlms::SelectiveAccess;
# struct Meter { log: Vec<AuditEvent> }
# impl ObjectStore for Meter {
#     fn get_attribute(&self, _c: u16, _n: Obis, _a: i8, _s: Option<SelectiveAccess<'_>>, _w: &mut dyn Writer) -> StoreResult<()> { Ok(()) }
fn audit(&mut self, event: AuditEvent) {
    // A breaker operation belongs in the same flash transaction as the operation.
    self.log.push(event);
}
# }
# fn main() {}
```

The refusals are the half worth having. Access control is the framework's job, so your
store is never *asked* for an object the association may not touch — without this hook
it would never learn that somebody tried. It is not a write-ahead log: the event is
recorded after the outcome is known, so if you need the record on disk before the relay
moves, do that inside `invoke_method`.

## Push a reading from the meter's side

The listener recipe above reads a notification. This builds one, and the two are tested
against each other, so neither can be quietly wrong on its own.

```rust,no_run
use dlms_cosem_rs::axdr::{Data, DateTime};
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use dlms_cosem_rs::server::PushSender;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let guek = [0u8; 16];
# let gak = [0u8; 16];
# fn restore_counter() -> u32 { 0 }
# fn persist_counter(_: u32) {}
# fn send_to(_: &[u8]) {}
# let captured_values = Data::DoubleLongUnsigned(0);
let mut sender: PushSender<_> = PushSender::new(
    RustCryptoProvider::new(KeyRing::new(guek, gak)),
    SystemTitle::new(*b"LGZ\x00\x12\x34\x56\x78"),
    SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
    // Not zero unless this device has never sent under this key. Restarting from zero
    // repeats every nonce it has ever used, and a repeated GCM nonce leaks the
    // authentication subkey rather than one reading.
    restore_counter(),
);

let mut frame = [0u8; 512];
let n = sender.notify(
    Some(DateTime::from_civil(2026, 9, 6, 8, 0, 0, 120)),   // when the values were taken
    &captured_values,                                       // what the push object list produced
    &mut frame,
)?;
send_to(&frame[..n]);
persist_counter(sender.invocation_counter());
# Ok(())
# }
```

A `DataNotification` has no `glo-` tag, so a protected push has exactly one form:
`general-glo-ciphering`, which carries the meter's system title in the clear. That is how
a listener holding keys for a hundred meters knows which key to try — and why the title is
a *hint*, never a statement of identity: the GCM tag is what proves who sent it.

Deciding *when* to push is not here. That needs the `PushSetup` communication window and a
clock, and there is no clock in this crate.
## Decrypt a meter's push

See the README. The short version: it is a `NotificationListener`, not a session, and it
is constructed with the protection it *requires*. A push is unsolicited — there is no
association, so nothing negotiated anything — which means the frame's own security
control byte is an attacker-controlled claim, not an agreement. Ask for
`SecurityPolicy::authenticated_encrypted(...)` and a frame that arrives with the
protection bits switched off is refused instead of decoded.

It also refuses a tag that does not verify, an invocation counter it has already
accepted, and a meter it has no key for. Counters are spent only *after* the tag
verifies, so a forged frame cannot advance the window and silence the real meter.

Persist `SingleMeterKeys::replay`'s `highest()` and restore it with
`ReplayWindow::resumed`, or a listener that restarts accepts every frame it has ever
seen a second time.

The same holds for a `Server`, and there it is easy to miss because the window survives
`Server::reset` on its own — but not a process restart. Persist `Server::replay_owner`
alongside `Server::peer_invocation_counter`, and restore both with
`Server::resume_replay_window`.

## Run an HDLC link without keeping the sequence numbers yourself

`Framer`, `Segmenter` and `Reassembler` are the pieces. `Connection` is the machine, and
it exists because the pieces leave you holding the two things that are actually hard: the
SNRM/UA handshake, whose answer carries the parameters every later frame is sized by, and
the send and receive sequence numbers — modulo eight, advancing on different events for
each role, and producing a link that works for exactly the first eight frames when they
drift.

```rust,no_run
use dlms_cosem_rs::transport::hdlc::{
    Address, Connection, Event, Found, Framer, Parameters, Reassembler, Role, LLC_REQUEST,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# fn send(_: &[u8]) {}
# fn arrived() -> Vec<u8> { Vec::new() }
# let apdu: &[u8] = &[];
let mut link = Connection::new(
    Role::Client,
    Address::client(0x10),
    Address::server(1, 17),
    Parameters { max_info_tx: 128, max_info_rx: 128, window_tx: 1, window_rx: 1 },
);

let mut out = [0u8; 512];
let mut storage = [0u8; 2048];
let mut assembled = Reassembler::new(&mut storage);
let mut framer = Framer::new();

// Open the link. The UA that answers carries what the meter actually agreed to.
let n = link.connect(&mut out)?;
send(&out[..n]);

// Then loop: find frames, hand each to the link, act on what it says.
let stream = arrived();
let mut at = 0;
while let Ok(Found::Frame { frame, consumed }) = framer.next_frame(&stream[at..]) {
    at += consumed;
    match link.handle(&frame, &mut assembled)? {
        Event::Connected => {
            // Now `link.parameters()` is real, and a unit can go out.
            let mut lsdu = vec![0u8; 3 + apdu.len()];
            lsdu[..3].copy_from_slice(&LLC_REQUEST);
            lsdu[3..].copy_from_slice(apdu);
            let mut segmenter = link.segmenter(&lsdu)?;
            while let Some(n) = link.next_frame(&mut segmenter, &mut out)? {
                send(&out[..n]);          // `ns` advanced; you did not touch it
            }
        }
        // The meter stopped short of a complete unit and is waiting to be asked.
        Event::PollRequired => {
            let n = link.poll(&mut out)?;
            send(&out[..n]);
        }
        Event::AcknowledgeRequired => {
            let n = link.acknowledge(&mut out)?;
            send(&out[..n]);
        }
        Event::Lsdu => println!("{} bytes of APDU", assembled.lsdu().len() - 3),
        Event::Disconnected => break,
        Event::Idle => {}
    }
}
# Ok(())
# }
```

**It does not retransmit**, and that is structural rather than unfinished: recovery needs
a timer and there is no clock in this crate. A frame out of sequence comes back as
`UnexpectedMessage` so you can reset the link. A retry loop that could not time out would
look like recovery without being it.

## Carry an APDU over HDLC without the link machine

The recipe above is the one to reach for. This is the layer underneath it, for a caller
that already has its own link state and wants only the segmentation: HDLC's information
field is 128 bytes until SNRM negotiates otherwise, so an APDU of any substance has to be
split and the receiver has to put it back.

```rust,no_run
use dlms_cosem_rs::transport::hdlc::{Address, Framer, Found, LLC_REQUEST, Reassembler, Segmenter};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let apdu: &[u8] = &[];
# let max_info_tx = 128u16;
# fn send(_: &[u8]) {}
# fn arrived() -> Vec<u8> { Vec::new() }
// The link carries the LLC header and the APDU behind it as one unit, so the header
// rides in the first segment only.
let mut lsdu = vec![0u8; 3 + apdu.len()];
lsdu[..3].copy_from_slice(&LLC_REQUEST);
lsdu[3..].copy_from_slice(apdu);

let mut segmenter = Segmenter::new(&lsdu, max_info_tx)?;
let mut frame = [0u8; 512];
let mut ns = 0u8;                                     // your link's send sequence
while let Some(n) = segmenter.next_frame(
    Address::server(1, 17), Address::client(0x10), ns, 0, &mut frame)?
{
    send(&frame[..n]);
    ns = (ns + 1) % 8;
}

// Receiving: hand the reassembler every frame the framer finds. It ignores the ones
// that carry nothing, so you do not have to filter.
let mut storage = [0u8; 2048];
let mut assembled = Reassembler::new(&mut storage);
let mut framer = Framer::new();
let stream = arrived();
let mut at = 0;
while let Ok(Found::Frame { frame, consumed }) = framer.next_frame(&stream[at..]) {
    at += consumed;
    if assembled.push(&frame)? {
        let lsdu = assembled.lsdu();
        let apdu = &lsdu[3..];                        // past the LLC header
        println!("{} bytes of APDU", apdu.len());
        break;
    }
}
# Ok(())
# }
```

**This is not the same thing as block transfer, and you usually need both.** Block
transfer cuts a *value* too large for the negotiated PDU size into several APDUs;
segmentation cuts each *APDU* into frames the information field can hold. A meter on an
optical probe with a 128-byte information field and a 1024-byte PDU size uses both at
once when you read a load profile — which is the only thing anyone reads.

`push` requires consecutive send-sequence numbers. A lost or duplicated segment
concatenated in the wrong place produces a byte string that often still decodes, into an
APDU that is simply wrong.

## Read a Dutch or Belgian meter's P1 port

The P1 socket on the front of the meter emits an ASCII telegram once a second. It is not
DLMS on the wire — it is the IEC 62056-21 data readout — but it is the same object model,
so the same `Obis`, `Unit` and `ScaledValue` read it.

```rust,no_run
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::transport::p1::{Found, TelegramReader};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# fn read_from_serial_port(_: &mut Vec<u8>) {}
let mut reader = TelegramReader::new();     // a checksum is required
let mut buffered = Vec::new();

loop {
    read_from_serial_port(&mut buffered);
    match reader.next_telegram(&buffered)? {
        Found::Telegram { telegram, consumed } => {
            // 123456.789 kWh is exactly 123 456 789 Wh. The SI prefix and the decimal
            // point both become the scaler; the mantissa stays an integer, because a
            // reading a billing system will subtract from next month's must not have
            // been through an f64.
            if let Some(line) = telegram.get(Obis::new(1, 0, 1, 8, 1, 255)) {
                let v = line.as_scaled().unwrap();
                println!("import, tariff 1: {} x 10^{} {}", v.value, v.scaler, v.unit);
            }
            // A gas reading carries two values: when, and how much.
            if let Some(gas) = telegram.get(Obis::new(0, 1, 24, 2, 1, 255)) {
                println!("gas at {:?}: {:?}", gas.as_timestamp(), gas.value(1));
            }
            buffered.drain(..consumed);
        }
        // The only bound that keeps a receive buffer from growing while a loose
        // connector chatters.
        Found::Incomplete { discard } => {
            buffered.drain(..discard);
        }
    }
}
# }
```

Three things that cost people an afternoon, and what this does about each:

- **The checksum covers `/` through `!` inclusive**, every CR and LF included. Trimming
  lines before checking produces a mismatch with no explanation.
- **A timestamp carries a daylight-saving flag, not a UTC offset.** `as_timestamp` marks
  the deviation *not specified* rather than inventing `+0100` — a fabricated offset cannot
  be taken back later.
- **DSMR 2.x and 3.x send no checksum.** `TelegramReader::without_checksum` reads them,
  and it is a separate constructor rather than a fallback, because losing the only
  integrity check the format has should be something a caller said out loud.

Luxembourg's P1 is a different thing on the same connector: an *encrypted DLMS
`DataNotification`*, which is the notification listener above and not this parser.

## Read an older meter that speaks short names

Turn on the `sn` feature. It is off by default: short-name referencing is a legacy
addressing mode, and proposing it to a modern meter proposes something it will refuse.

The mode belongs to the **association**, agreed once in the application context, so it is
configured rather than chosen per request:

```rust,ignore
use dlms_cosem_rs::acse::Referencing;
use dlms_cosem_rs::client::{ClientConfig, Response};
use dlms_cosem_rs::cosem::ShortName;
use dlms_cosem_rs::xdlms::VariableAccess;

let config = ClientConfig { referencing: Referencing::ShortName, ..Default::default() };
```

A short name is an object's **base name** plus an offset. Attribute *n* is
`base + (n − 1) × 8`, which `ShortName` computes; base names come from the meter's own
`Association SN` object list, so a client need not know them in advance. Where a class's
**methods** start is a per-class Blue Book constant, so you supply it — and a class whose
offset you do not know has no addressable methods, which beats invoking the wrong one:

```rust,ignore
// Register: three attributes at base 0x0028, and its class puts `reset` at x + 0x28.
let energy = ShortName::new(0x0028, 3, obis!("1-0:1.8.0*255"), 3).with_methods(0x28, 1);

let n = session.read_request(
    &[VariableAccess::VariableName(energy.attribute(2).unwrap())],
    &mut out,
)?;
if let Response::ReadResults(results) = session.handle_response(&answer, &mut scratch)? {
    for result in results.iter() { /* one per entry, in order */ }
}
```

Two things bite if you miss them. There is **no ACTION service** — a method is invoked by
*writing* its short name, with the value as the parameter. And `unconfirmed_write_request`
really is unconfirmed: the meter sends nothing back, so a caller that waits for a reply
waits for ever.

## Label an attribute you have never seen

The class registry answers for `CLASS_COUNT` classes — 102 today, of which 25 carry full
attribute and method tables and the rest carry a name, which is still enough for a
translator to say what an object is. The counts are constants rather than prose, so a
caller can print them and this paragraph cannot drift from the table.

```rust
use dlms_cosem_rs::cosem::{attribute_name, class_name, method_name};

# fn main() {
assert_eq!(class_name(7), Some("Profile generic"));
assert_eq!(attribute_name(7, 1, 2), Some("buffer"));
assert_eq!(method_name(70, 2, 1), Some("remote_disconnect"));

// A class with no attribute table still names itself, and attribute 1 is the logical
// name for every class there is.
assert_eq!(class_name(152), Some("CoAP setup"));
assert_eq!(attribute_name(152, 0, 1), Some("logical_name"));
assert_eq!(attribute_name(152, 0, 2), None);
# }
```

## Build for a microcontroller

```toml
[dependencies]
dlms-cosem-rs = { version = "0.1", default-features = false, features = [
    "client", "hdlc", "suite0",
] }
```

No `std`, no `alloc`. `Data` borrows the receive buffer, the session holds a fixed
scratch array whose size is a const generic, and every decoder returns a `Result` rather
than panicking.

That last claim is measured rather than asserted, and you can measure it yourself:

```sh
CARGO_PROFILE_RELEASE_LTO=false cargo build --release \
  --target thumbv7em-none-eabihf --no-default-features --features client,hdlc,wrapper,suite0
nm target/thumbv7em-none-eabihf/release/libdlms_cosem_rs.rlib | grep -E 'panicking|panic_fmt'
```

That prints nothing, and CI fails if it ever does. LTO is off because it is the only way
the scan means anything — and because it is the harder bar.

