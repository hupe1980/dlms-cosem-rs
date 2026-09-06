+++
title = "Status and evidence"
description = "What dlms_cosem_rs implements, what it deliberately refuses rather than guesses, what the test suite actually proves — and the one gap that is still open."
weight = 80
+++

**Pre-release, and not yet published to crates.io.** The API is being made right rather
than kept stable; the minor version is the breaking one. Build it from the repository.

## Built and tested

- The codec, OBIS, A-XDR including compact arrays and the delta types, BER and ACSE.
- Every APDU tag. GET, SET, ACTION and ACCESS, every batched `with-list` form, push, and
  general block transfer — the framing **and** the edition-9 procedure with its streaming
  window and retry.
- **All three protection forms.** `glo-`/`ded-` for the services that have a ciphered tag,
  and `general-glo-`/`general-ded-ciphering` for the ones that do not — which is every
  ACCESS exchange and every exception response.
- **Suites 0, 1 and 2**, at both key widths. The dedicated key negotiated end to end rather
  than configured.
- Replay rejection on both engines and in the push listener, with a sliding window of the
  shape IPsec and DTLS use.
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

**The asymmetric halves of suites 1 and 2** — key agreement, general signing, certificates,
attestation. Ciphering under all three suites works, because all three cipher with AES-GCM.
There is no feature flag offering the parts that do not exist: a flag that gates nothing is
a false statement in the place people look first.

**`action-request-with-list-and-first-pblock`** — a batch of methods whose parameters are
themselves too large for one APDU. How the parameter bytes divide between the methods is
not stated in the material this project has, and the outcome of guessing is a meter running
the right method on the wrong argument.

**V.44 compression** is decoded as a flag and never performed. A frame that needs it fails
by name.

## Not built

Short-name referencing; the CoAP transport; reliable (confirmed) push and push
*scheduling*; the gateway protocol, SMS, M-Bus and mode E; companion-profile content;
`tokio` and `embedded-io` driver adapters; a command-line tool.

**HDLC does not retransmit** and **push has no schedule** for the same structural reason:
both need a timer, and there is no clock in the crate. Both are named on their pages rather
than left to be discovered.

## What the tests actually prove

303 tests — and it is worth being precise about what they are worth. A claim about the wire
is worth what its evidence is worth, and there are three kinds here.

**Third-party bytes, the strongest thing on this list.** The `InitiateRequest` and
`InitiateResponse` encodings reproduce, byte for byte, the hexadecimal an independent
academic analysis derived from the specification. The cipher reproduces NIST SP 800-38D's
GCM and GMAC test cases and RFC 3394's key wrap. Both of the crate's CRC-16s reproduce
their own published check values — and a test asserts the two are different functions,
because two CRCs in one crate is exactly the situation where one gets used for the other.

**Evidence about robustness.** Nine fuzz targets, including a *stateful* one that drives
the server with a whole hostile session and one that drives the block-transfer receiver
with blocks in any order. A seeded mutation harness runs the same questions on stable in CI
on every commit: 40 000 mutated and random inputs across nine decoders, every prefix of
every seed, 100 000-deep nesting refused rather than recursed. And the panic-symbol scan,
which is a measurement rather than an argument — see
[Embedded and no_std](@/docs/embedded.md).

A round-trip suite starts from *values* rather than from bytes, enumerating every variant
of every service by hand. That direction matters: a byte-driven harness can only ever reach
what a decoder produces, so it is structurally blind to an arm that is not there, a
forgotten optional flag, or an equality that compares the wrong fields. It found one of
each.

**And the weakest kind: this crate agreeing with itself.** A whole ciphered association
runs as one test in microseconds — plain, low level security, high level security with
GMAC, under a dedicated key, and under suite 2. A replayed request does not move the breaker
twice. A downgraded response is refused. A 1500-byte value is written over several blocks
and read back byte for byte. All of that is real, and none of it is independent.

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

Both fail loudly where they can. An ACCESS response whose lists are different lengths is
refused rather than paired up, and a delta whose width disagrees with the value it follows
is a type mismatch rather than a silent widening.

## Standards

The DLMS User Association's Blue Book (edition 18) and Green Book (edition 12) are the
masters; IEC 62056-5-3, -6-1 and -6-2 (all edition 4.0, 2023) mirror them. Those documents
are copyrighted and are **not** redistributed here: this crate contains encodings, tag
values, class identifiers and OBIS codes, which are facts, and no specification prose.
