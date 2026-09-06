+++
title = "Services and segmentation"
description = "GET, SET, ACTION and ACCESS in dlms_cosem_rs, the batched with-list forms, selective access, and the three segmentation mechanisms that compose rather than substitute."
weight = 40
+++

## The four services

Logical-name referencing has four, and the crate drives all of them in both roles.

| Service | Asks | Batched form |
|---|---|---|
| **GET** | read an attribute | `get-request-with-list` |
| **SET** | write one | `set-request-with-list` |
| **ACTION** | invoke a method | `action-request-with-list` |
| **ACCESS** | all three, mixed, in one exchange | — it *is* the batch |

A request names a class, an OBIS code and an attribute or method index. Nothing about the
service knows what the object *means*; that is the object model's job, and keeping the two
apart is what lets one set of tables serve a server that hosts objects and a client that
reads them.

### Why the batched forms exist

Not to save bytes. On a GPRS or LPWAN link the round trip dominates everything, so thirty
reads issued one at a time is thirty times the latency rather than thirty times the size.

The other half is **per-item isolation**: each item gets its own result, so a denied or
missing object occupies its own slot instead of losing the whole exchange. A head-end that
wanted only atomicity could issue the reads separately — the isolation is the reason the
service is worth having.

```rust,ignore
let n = session.get_request_with_list(&items, &mut request)?;
// …
if let Response::DataList(results) = session.handle_response(&answer, &mut scratch)? {
    for (descriptor, result) in wanted.iter().zip(results.iter()) {
        match result?.value() {
            Ok(value) => println!("{descriptor:?} = {value:?}"),
            Err(why)  => println!("{descriptor:?} refused: {why:?}"),   // its own slot
        }
    }
}
```

That matters most for ACTION. A batch that opened a breaker and then hit a method it may
not invoke would, without per-item results, report only the failure — and nothing would
say the breaker had moved.

### ACCESS

ACCESS is the one service that mixes reads, writes and invocations into a single request.
It is what a battery-powered device on a low-power network wants, and the Green Book's
LPWAN examples are built on it.

Its three lists are **positional**: entry *i* of each belongs to item *i*. A write and a
failed read occupy their slot with `null-data` rather than being omitted, so a caller never
has to count which entries produced anything.

ACCESS has **no ciphered tag of its own**. On a protected link it can only travel inside
`general-glo-ciphering`, so it needs the `general-protection` conformance bit as well as
`access`. Both are proposed by default.

## Selective access

A selector narrows a read *at the meter*, which is the difference between fetching a day
and fetching a year. Two are defined: by a range of the sort value (usually the clock), and
by entry position.

```rust,ignore
let mut params = [0u8; 96];
let access = RangeDescriptor::by_clock(from, to).to_selective_access(&mut params)?;
let n = session.get_request(descriptor, Some(access), &mut request)?;
```

The framework carries the descriptor end to end and hands it to the store intact. What it
cannot do is *apply* it — only the store knows what its buffer is sorted by. The failure
worth naming is a store that accepts a selector and ignores it: that answers a day's
request with a year of data and nothing in the exchange says so. The right response to a
selector a meter does not implement is a refusal, not the whole buffer.

## Three segmentations, and why they are not alternatives

This is the part stacks get wrong, and it is worth being precise. They are different
mechanisms at different layers, and they **compose**:

| | Cuts up | Bounded by |
|---|---|---|
| **Block transfer** | a *value* — GET, SET or ACTION | the negotiated PDU size |
| **General block transfer** | an *APDU*, whatever service it carries | the negotiated PDU size |
| **HDLC segmentation** | an *APDU* | the negotiated information field |

A meter on an optical probe typically negotiates a **128-byte information field** and a
**1024-byte PDU size**. Reading a load profile then needs two of the three at once: block
transfer to cut the value into APDUs the PDU size can hold, and HDLC segmentation to cut
each of those into frames the information field can hold. A stack with only one works right
up until somebody reads a profile — which is the only thing anybody reads.

### Block transfer, both directions

The outbound direction (a long GET response) is the one every stack implements. The
inbound one is the one they leave out, and it is not rare: reading a load profile needs
blocks for the *response*, but writing an activity calendar, a set of tariff scripts or a
firmware image needs them for the *request*.

| Service | Out of the server | Into the server |
|---|---|---|
| GET | `get-response-with-datablock` | — |
| SET | — | `set-request-with-first-datablock`, then `…-with-datablock` |
| ACTION | `action-response-with-pblock` | `action-request-with-first-pblock`, then `…-with-pblock` |

On the client, `BlockCollector` gathers a long response and `BlockSender` emits a long
request. **The bytes stay yours in both directions**, for the same reason: how large a
value a deployment moves is a property of the deployment, and a buffer allocated here would
be this crate deciding how large a load profile may be.

Two rules keep it honest. Block numbers must arrive consecutively from one — a duplicated
or reordered fragment concatenated in the wrong place usually still *decodes*, into a value
that is simply wrong and that carries no error. And every block of one transfer carries the
invoke id of the invocation it belongs to; a fresh id names a different invocation, and a
server that checks refuses it while one that does not writes the fragment into something
else.

### General block transfer

GBT is the service-independent one: it cuts an **APDU** into blocks whatever the APDU
carries. `GbtSender` and `GbtReceiver` are the whole edition-9 procedure.

**Streaming** — the sender puts a window of blocks on the wire before it waits. A window
of zero is not "no window": it is what a sender that is *not* streaming sends, and reading
it as one is how a streaming peer waits forever for an acknowledgement nobody owes it.

**Retry** — an acknowledgement names the highest block received *in order*, so one lower
than the last block sent is not an error. It is the receiver saying where the run broke,
and the sender rewinds to just after it. A lost block therefore costs the blocks after it
rather than the transfer.

The corollary is the invariant the whole mechanism rests on: **the receiver never stores a
block from beyond a gap.** Acknowledging the last in-order block is precisely what fetches
the missing one; keeping the future block as well would leave a hole nothing fills, and the
reassembled APDU would be wrong rather than absent.

Neither engine chooses GBT on its own — they segment with the service-specific mechanism,
which is what meters overwhelmingly use. A caller that needs GBT drives the two types
directly, over any transport.

## Profile buffers

A load profile is an array of structures whose columns are given by the meter's
`capture_objects`. Three compressions may be in play at once, and `ProfileBuffer` undoes
all three so the visitor sees every column of every row as an absolute value:

- a column repeating the previous row, sent as `null-data`;
- a run of repeated columns at the *end* of a row, sent by making the row shorter;
- a column sending a **delta** from the previous row rather than a value.

A caller that skipped the last of those gets no error. It gets *differences where readings
were meant*, which for a rising register looks like a meter that suddenly reads almost
nothing.

## What is not driven

`action-request-with-list-and-first-pblock` — a batch of methods whose parameters are
themselves too large for one APDU. It decodes; it is not driven, because how the parameter
bytes divide between the methods is not stated in the material this project has, and the
outcome of guessing is a meter running the right method on the wrong argument.

Short-name referencing (`Read` / `Write`, for an older installed base) is decoded but not
driven either.
