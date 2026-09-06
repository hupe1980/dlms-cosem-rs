+++
title = "Transports"
description = "HDLC framing, segmentation and the link machine; the TCP/UDP wrapper with stream reassembly; and the P1 customer interface for DSMR and eMUCs telegrams."
weight = 50
+++

Each transport is sans-I/O in the same way the engines are: it turns bytes into APDUs and
APDUs into bytes. Opening a socket, driving a serial port and waiting on a timer are yours.

## HDLC

What an optical probe, an RS-485 bus and a great many GPRS meters speak. Frame format
type 3: a flag byte, an eleven-bit length, addresses of one, two or four bytes, a header
check sequence when there is an information field, and a frame check sequence over
everything.

### Finding a frame in noise

A serial link delivers noise, half frames, and the echo of what was just transmitted on a
half-duplex bus. `Framer` scans for a flag, validates, and on failure **discards to the
next flag** rather than giving up on the link.

It does not stop at the first flag that might begin a frame. One noise byte that happens to
look like a length field would otherwise make the finder wait forever for a frame nobody
sent, while the real frame sat in the buffer behind it. So every flag position is tried, a
complete frame beats an incomplete candidate, and only when nothing completes does the
finder report waiting — with **how much can be thrown away**:

```rust,ignore
match framer.next_frame(&buffer)? {
    Found::Frame { frame, consumed } => { /* … */ }
    Found::Incomplete { discard }    => { buffer.drain(..discard); }
}
```

That `discard` is not a nicety. Without it a receive buffer grows without bound while a
broken transmitter chatters, and on a microcontroller that is the bug that takes the device
down.

### The link machine

`Framer`, `Segmenter` and `Reassembler` are the pieces. `Connection` is the machine, and it
exists because the pieces leave you holding the two things that are actually hard:

- **the SNRM/UA handshake**, whose answer carries the parameters every later frame is sized
  by; and
- **the send and receive sequence numbers**, which are modulo eight, advance on different
  events for each role, and produce a link that works for exactly the first eight frames
  when they drift.

```rust,ignore
let mut link = Connection::new(Role::Client, client_addr, server_addr, proposed);
send(&out[..link.connect(&mut out)?]);          // SNRM

match link.handle(&frame, &mut assembled)? {
    Event::Connected           => { /* link.parameters() is now real */ }
    Event::Lsdu                => { /* a whole APDU is in `assembled` */ }
    Event::PollRequired        => { /* the peer is waiting to be asked for the rest */ }
    Event::AcknowledgeRequired => { /* answer with link.acknowledge() */ }
    Event::Disconnected        => break,
    Event::Idle                => {}
}
```

It takes a role because HDLC as DLMS uses it is not symmetric: the client is the primary
station and the only one that may open the link or poll.

**It does not retransmit**, and that is structural rather than unfinished. Recovery needs a
timer, and there is no clock in this crate. A frame out of sequence is reported by name so
you can reset the link; a retry loop that could not time out would look like recovery
without being it. A frame addressed to another station is ignored rather than reassembled —
an RS-485 segment carries several meters, and mixing two conversations into one buffer
produces an APDU nobody sent.

## The TCP/UDP wrapper

Eight bytes: version, source port, destination port, length. The ports are the client and
server service access points; 4059 is the IANA registration.

Over TCP the layer reassembles from a stream, because an APDU may arrive in three segments
and two APDUs may arrive in one. Over UDP one datagram is one wrapper PDU. Reassembly is
bounded by a limit you set at construction, which is the only thing standing between a
head-end and a peer that announces a very large length and then stops sending.

## P1 — the customer interface

The socket on the front of a Dutch or Belgian meter that the customer is entitled to read.
It is not DLMS on the wire — it is the ASCII data readout of IEC 62056-21 — but it *is* the
same object model, so the same `Obis`, `Unit` and `ScaledValue` read it and you need one
crate rather than two.

```text
/ISk5\2MT382-1000<CR><LF>
<CR><LF>
1-0:1.8.1(123456.789*kWh)<CR><LF>
…
!EF2F<CR><LF>
```

Three things about this format cost people an afternoon:

**The checksum covers `/` through `!` inclusive**, every CR and LF included. A parser that
trims lines before checking gets a mismatch it cannot explain. `TelegramReader`
resynchronises like the HDLC framer, because a reader that started mid-telegram is the
normal case on a port that has been running for hours.

**A value is not always a number.** An equipment identifier is a hex-encoded octet string,
a timestamp carries a daylight-saving flag, and an event log puts an OBIS code *inside* a
value — so the split is on parentheses rather than on punctuation, and values are handed
over as text and converted by name.

**A decimal is not a float.** `123456.789*kWh` is exactly 123 456 789 Wh: the SI prefix and
the decimal point both go into the scaler and the mantissa stays an integer. A reading a
billing system will subtract from next month's must not have been through an `f64` on the
way in.

```rust,ignore
if let Some(line) = telegram.get(Obis::new(1, 0, 1, 8, 1, 255)) {
    let v = line.as_scaled().unwrap();
    println!("{} × 10^{} {}", v.value, v.scaler, v.unit);   // 123456789 × 10^0 Wh
}
```

A timestamp's flag says which of the local zone's two offsets applied — it is *not* a UTC
offset — so `as_timestamp` marks the deviation **not specified** rather than inventing
`+0100`. A fabricated offset cannot be taken back later.

DSMR 2.x and 3.x meters send no checksum at all. `TelegramReader::without_checksum` reads
them, and it is a separate constructor rather than a fallback: losing the only integrity
check the format has should be something a caller said out loud.

**Luxembourg's P1 is a different thing on the same connector** — an *encrypted DLMS
`DataNotification`* — and is the [notification listener](@/docs/security.md), not this
parser.

## What is not here

CoAP, the gateway protocol, SMS, M-Bus and mode E. Each is either an IP network — in which
case the wrapper applies unchanged — or a MAC layer with a crate of its own. The line is
deliberate: no LoRaWAN, Wi-SUN, PLC or M-Bus radio stack lives here, and the crate meets
those links at the APDU or at a socket.
