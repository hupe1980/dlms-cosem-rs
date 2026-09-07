+++
title = "Status and evidence"
description = "What dlms-cosem-rs implements, what it deliberately refuses rather than guesses, what the test suite actually proves — and the one gap that is still open."
weight = 80
+++

**Pre-release, and not yet published to crates.io.** The API is being made right rather
than kept stable; the minor version is the breaking one. Build it from the repository.

## Built and tested

- The codec, OBIS, A-XDR including compact arrays and the delta types, BER and ACSE.
- Every APDU tag. GET, SET, ACTION and ACCESS, every batched `with-list` form, push, and
  general block transfer — the framing **and** the edition-9 procedure with its streaming
  window and retry.
- **Short-name referencing**, behind the `sn` feature and off by default: Read, Write,
  UnconfirmedWrite and InformationReport, driven from both engines, with block transfer
  for a long read. It goes through the *same* object store, the same access control and
  the same audit trail as the logical-name services — the two modes differ in how a
  target is named, not in what a read is.
- **All three protection forms.** `glo-`/`ded-` for the services that have a ciphered tag,
  and `general-glo-`/`general-ded-ciphering` for the ones that do not — which is every
  ACCESS exchange and every exception response.
- **Suites 0, 1 and 2**, at both key widths, key wrap included: the key-encrypting key's
  own length picks AES-128 or AES-256, so suite 2's key transfer is reachable rather than
  merely implemented. The dedicated key negotiated end to end rather than configured.
- Replay rejection on both engines and in the push listener, with a sliding window of the
  shape IPsec and DTLS use — **per peer, and outliving the association**, so a client that
  reconnects cannot replay what it sent before the gap.
- **Which key set opens a frame is what the receiver demands**, never the bit the frame
  carries. A broadcast key is shared with a fleet; a unicast exchange accepted under one
  would let any member of that fleet answer as the head-end.
- **Block transfer in both directions** for all three services, and HDLC segmentation, and
  they compose — see [Services and segmentation](@/docs/services.md).
- HDLC (framing, segmentation and the link machine), the TCP/UDP wrapper, and P1.
- Both halves of push: a listener that reads a notification and a sender that builds one.
- Selective access carried end to end; profile buffers with all three compressions undone;
  an audit trail that records refusals.

## Refused rather than guessed

This list is short on purpose, and each entry is a decision rather than a shortfall.

**High level security mechanisms 3, 4, 6 and 7** (MD5, SHA-1, SHA-256, ECDSA) return
`Unsupported` by name. Their exact constructions are in material this project does not
have, and a guessed construction is worse than an unimplemented one: it authenticates
nothing while looking like it does. Mechanism 5 (GMAC) and low level security work.

**The asymmetric halves of suites 1 and 2** — key agreement, general ciphering, general
signing, certificates, attestation. Ciphering under all three suites works, because all
three cipher with AES-GCM. There is no feature flag offering the parts that do not exist: a
flag that gates nothing is a false statement in the place people look first.

`general-ciphering` and `general-signing` **decode** as types, so a translator can name one
and a fuzzer can walk one, and they are refused as `Unsupported` **by name** on the receive
path — deliberately not with the answer a plaintext downgrade gets, because those are
different events and a caller acts on them differently.

**Short-name method offsets.** A short name is an object's base name plus an offset.
Attribute *n* is `base + (n − 1) × 8`, which two sources state and this crate computes.
Where a class's *methods* start is a per-class constant from the Blue Book — `Register`
has three attributes and puts `reset` at `base + 0x28`, which is not a function of the
attribute count — so `ShortName` takes that offset as a **value**. The parties who need it
have it: a meter knows its own, and a client reads base names out of the meter's own
`Association SN` object list. A client that invoked the wrong method would be much worse
than one that could not invoke any.

**`action-request-with-list-and-first-pblock`** — a batch of methods whose parameters are
themselves too large for one APDU. How the parameter bytes divide between the methods is
not stated in the material this project has, and the outcome of guessing is a meter running
the right method on the wrong argument.

**V.44 compression** is decoded as a flag and never performed. A frame that needs it fails
by name.

## Not built

The CoAP transport; reliable (confirmed) push and push *scheduling*; SMS, M-Bus and mode E;
gateway *routing*, though the gateway PDU itself encodes and decodes; short-name **write**
block transfer; companion-profile content; `tokio` and `embedded-io` driver adapters; a
command-line tool.

**HDLC does not retransmit** and **push has no schedule** for the same structural reason:
both need a timer, and there is no clock in the crate. Both are named on their pages rather
than left to be discovered.

## What the tests actually prove

347 tests — and it is worth being precise about what they are worth. A claim about the wire
is worth what its evidence is worth, and there are three kinds here.

**Third-party bytes, the strongest thing on this list.** The `InitiateRequest` and
`InitiateResponse` encodings reproduce, byte for byte, the hexadecimal an independent
academic analysis derived from the specification. The cipher reproduces NIST SP 800-38D's
GCM and GMAC test cases and RFC 3394's key wrap at both key-encrypting widths. Both of the
crate's CRC-16s reproduce their own published check values — and a test asserts the two are
different functions, because two CRCs in one crate is exactly the situation where one gets
used for the other.

**Evidence about robustness.** Nine fuzz targets, including a *stateful* one that drives
the server with a whole hostile session and one that drives the block-transfer receiver
with blocks in any order. A seeded mutation harness runs the same questions on stable in CI
on every commit: 40 000 mutated and random inputs across thirteen decoders, every prefix of
every seed, 100 000-deep nesting refused rather than recursed. And the panic-symbol scan,
which is a measurement rather than an argument — see
[Embedded and no_std](@/docs/embedded.md).

**That scan has one blind spot, and it is worth naming.** It builds in release, where Rust
turns arithmetic overflow checks *off*, so it says nothing about overflow. What covers that
class is the fuzzers, which do enable the checks, plus a CI step that counts the remaining
overflow paths and refuses to let the number grow. The paths that remain are length
arithmetic bounded by buffers the compiler cannot see the bounds of, none of them known to
be reachable.

A round-trip suite starts from *values* rather than from bytes, enumerating every variant
of every service by hand. That direction matters: a byte-driven harness can only ever reach
what a decoder produces, so it is structurally blind to an arm that is not there, a
forgotten optional flag, or an equality that compares the wrong fields.

**And the weakest kind: this crate agreeing with itself.** A whole ciphered association
runs as one test in microseconds — plain, low level security, high level security with
GMAC, under a dedicated key, under suite 2, and in short-name referencing. A replayed
request does not move the breaker twice, and neither does one replayed across a
reconnection. A downgraded response is refused, and so is one naming the wrong key set. A
client whose counter has gone stale is told the value to move to. A 1500-byte value is
written over several blocks and read back byte for byte. All of that is real, and none of
it is independent.

> **Interoperability has not been tested.** A stack can be entirely self-consistent and
> speak to nothing — two implementations written together share a misreading invisibly, and
> that is precisely the class of defect a self round-trip cannot see. Until this has been
> run against an implementation that shares none of its code, it says “verified against the
> standard's own vectors”, never “conformant”.

That is the largest open gap, it is ahead of new features in priority, and stating it is
more useful than a claim that would later have to be withdrawn.

## Two conventions labelled as derived

Where the normative clause is not in the material this project can read, the reading is
implemented, said out loud, and re-checked later:

- **The ACCESS lists' positional alignment** — one data entry per specification entry, with
  `null-data` in the slot of anything that produced none.
- **The unsigned delta types' sign** — treated as unsigned increments, which is what their
  names say and what makes them worth having.
- **`InformationReport`'s timestamp** — an `OPTIONAL GeneralizedTime`, whose A-XDR encoding
  is not stated in material this project can read. It is handed over as the octets the peer
  sent rather than decoded under a guess, because a timestamp read wrongly is a reading
  dated wrongly and carries no error with it.

Both fail loudly where they can. An ACCESS response whose lists are different lengths is
refused rather than paired up, and a delta whose width disagrees with the value it follows
is a type mismatch rather than a silent widening.

## Standards

The DLMS User Association's Blue Book (edition 18) and Green Book (edition 12) are the
masters; IEC 62056-5-3, -6-1 and -6-2 (all edition 4.0, 2023) mirror them. Those documents
are copyrighted and are **not** redistributed here: this crate contains encodings, tag
values, class identifiers and OBIS codes, which are facts, and no specification prose.
