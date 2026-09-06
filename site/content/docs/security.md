+++
title = "Security"
description = "DLMS security suites 0–2, the three protection forms, high level security, invocation counters and replay windows — and the one rule the crate cannot enforce for you."
weight = 30
+++

DLMS security is small: one AEAD, one MAC construction, one counter. Nearly everything
that goes wrong with it goes wrong in the bookkeeping around those, so this page is mostly
about the bookkeeping.

## The suites

| Suite | Ciphering | Adds |
|---|---|---|
| 0 | AES-GCM-128, AES-128 key wrap | — |
| 1 | AES-GCM-128 | ECDH / ECDSA on P-256 with SHA-256 |
| 2 | AES-GCM-256 | ECDH / ECDSA on P-384 with SHA-384 |

**Ciphering is AES-GCM in all three**, and the default provider does all three — a suite-2
association is an end-to-end test, not a sentence. What suites 1 and 2 *add* is asymmetric:
key agreement, signing, certificates. **None of that is implemented**, and there is
deliberately no feature flag suggesting otherwise. A received frame naming suite 1 or 2
decrypts correctly; a message that needs ECDSA to verify does not, and says so.

The nonce is twelve bytes: the sender's eight-byte **system title** followed by its
four-byte **invocation counter**. That single fact explains most of the rest of this page.

## Three ways an APDU is protected

Which one is used is not a preference — it follows from the service.

**`glo-` and `ded-`** rename the service tag: a `get-request` (`0xC0`) becomes a
`glo-get-request` (`0xC8`) or a `ded-get-request` (`0xD0`). Only the services that *have* a
ciphered tag can travel this way, and the deciphered plaintext is the whole plain APDU,
its own tag included — not a body to prepend the tag to.

**`general-glo-ciphering`** wraps *any* APDU and carries the sender's system title in the
clear. That is the only way to protect an `access-request`, an `access-response` or an
`exception-response`, none of which has a ciphered tag; it is also the form a pushed
`DataNotification` takes. It costs the `general-protection` conformance bit, so a stack
that never implements it cannot use ACCESS on a ciphered link at all.

The system title in that header is **unauthenticated**. It is a hint about which key to
try, never a statement of identity — a frame naming anyone but the peer is refused before a
key is touched, and the GCM tag is what actually proves who sent it.

**`general-ciphering` and `general-signing`** carry key information or an ECDSA signature
alongside the APDU. Both encode and decode; the asymmetric halves are not implemented.

## The dedicated key is negotiated, not configured

In a ciphered association the AARQ's user information is a `glo-InitiateRequest` whose
plaintext may carry a **dedicated key** for this association alone. If it does, both ends
use `ded-` tags for everything afterwards.

Two consequences worth stating plainly:

- **The Initiate exchange is protected globally, always** — including in an association
  that will use a dedicated key for everything else, because that message is what
  *delivers* the key. Protecting it with the dedicated key produces a frame the peer has
  no way to open, and the failure looks exactly like a wrong global key.
- **The server cannot be configured for it.** Only the client knows whether there is a
  dedicated key, so the server learns it from the InitiateRequest and switches to match.
  Both ends switch together or nothing after the handshake decrypts.

The key lives exactly as long as the association. A client that drops the connection never
sends a release, and a sans-I/O engine cannot see a closed socket — so a caller reusing a
`Server` across connections must call `Server::reset`, which clears the dedicated key, the
challenge, the negotiated conformance and the peer's replay window. What it deliberately
does **not** clear is the invocation counter: the association is gone but the key has not
changed, and a counter that went backwards would repeat a nonce.

## Authentication

| Mechanism | Status |
|---|---|
| 0 — none, 1 — low level security (a password) | implemented |
| 5 — high level security with GMAC | implemented |
| 2 — manufacturer-specific | never; it cannot be implemented generically |
| 3 MD5, 4 SHA-1, 6 SHA-256, 7 ECDSA | **refused by name** |

High level security exchanges challenges in the AARQ and AARE and completes with
`reply_to_HLS_authentication` in both directions: the client proves itself in pass three,
the server in pass four. Mechanism 5 authenticates with GMAC over the challenge.

The four refused mechanisms are named by the standard, but their exact constructions are
in material this project does not have. **A guessed construction is worse than an
unimplemented one**: it authenticates nothing while looking like it does. So they return
`Unsupported` by name, and a meter that requires one cannot be talked to — which is a
sentence somebody can act on.

The crate also checks the peer's *claim* about how it computed its reply. A response naming
a different suite, or setting the encryption, broadcast or compression bits, is not
answering the challenge that was sent; verifying under whatever it claimed would let the
peer choose the construction.

## Keys live in exactly one place

The `CryptoProvider` trait holds them. Neither engine keeps a copy, because two homes for
a key is one misconfiguration away from an association that opens and then fails its first
tag, with two plausible places to look and no way to tell which.

```rust,ignore
let session: ClientSession<_> = ClientSession::new(
    ClientConfig {
        system_title: Some(SystemTitle::new(*b"CLI\x00\x00\x00\x00\x01")),
        mechanism: AuthMechanism::HighGmac,
        security: SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
        ..Default::default()
    },
    RustCryptoProvider::with_rng(KeyRing::new(guek, gak), os_rng),
);
```

There is one exception, and it is inherent to DLMS rather than a compromise: the
additional authenticated data is `SC ‖ AK ‖ …`, so the **authentication key's bytes** go
into GCM in the clear. No arrangement of traits changes that, and a design that pretended
otherwise would have a secure-element provider authenticating the wrong bytes. Every other
key stays behind a `KeyRef` and never leaves the provider — which is what lets an ATECC608,
an SE050, a TPM or a head-end HSM be another implementation of the same trait.

## Invocation counters — the part you must get right

The counter is the second half of every nonce, which makes it two controls at once: it
keeps the sender from repeating a nonce, and it keeps the receiver from accepting the same
message twice.

**Sending.** The counter refuses to wrap. At `u32::MAX` the engine errors rather than
reusing a nonce; the association must be re-keyed.

**Receiving.** Each engine and the push listener holds a replay window per peer: the
highest counter accepted, plus a bitmap of which values below it have already arrived —
the shape IPsec and DTLS use. The default width is zero, which accepts only strictly
increasing counters and is right for HDLC and TCP. Widen it only for a transport that
genuinely reorders, and note what the width means: **how far out of order a frame may
arrive, not how much replay is tolerated.** None is, at any width. A check that merely
accepts anything within *n* of the highest seen is not a replay window but a hole *n* wide.

**Order matters as much as the check.** The counter is examined *before* any cryptography,
so a flood of replays is cheap, and recorded only *after* the tag verifies. The other order
hands an attacker a permanent denial of service: one forged frame with a counter near the
top of the range, and every genuine message afterwards looks like a replay.

### What the crate cannot do for you

> A counter that restarts from zero against a key that has not changed reuses every nonce
> it used before — and a repeated GCM nonce does not merely leak a plaintext. It leaks the
> authentication subkey, after which anyone can forge.

Nothing here can detect that. The peer cannot tell a restarted meter from a replayed one
and will simply reject the traffic, by which time the key is already burnt.

So **the value must outlive the process.** Read it after sending, persist it, and hand the
stored value back through the configuration on the way up:

```rust,ignore
ClientConfig { invocation_counter: restored_from_flash, ..Default::default() }
// … later …
persist(session.invocation_counter());
```

A device that cannot afford a write per message should reserve in blocks — store
`n + 1000`, use up to that, store again — so a crash costs a thousand unused values rather
than one reused one. The API is shaped to make this visible rather than to hide it: there
is no default that silently starts at zero without the field saying so.

## What is defended, and what is not

| Asset | Attack | What stops it |
|---|---|---|
| Keys | extraction from memory or a log | keys behind a reference; zeroised storage; `[REDACTED]` in every `Debug`; a secure-element provider |
| Meter data, breaker control | replay, reorder | a per-peer replay window on both engines and the listener; each counter accepted at most once, at any width |
| The same | downgrade to a weaker suite or to plaintext | unprotecting returns *what was found*; the session compares it with the negotiated policy and refuses a weaker frame |
| The same | tag forgery, tampering | GCM tags verified before parsing — decrypt-before-parse is the only path |
| A head-end process | parser crash, memory exhaustion | panic-free fuzzed decoders; the negotiated PDU size, the GBT window and the HDLC information field bound every buffer |
| Meter firmware | unauthorised ACTION | access rights enforced *before* the store is asked; a single-use challenge; an audit hook on every method |
| A reading | an answer to a different question | every response must carry the invoke id of the outstanding request |
| Association terms | context or mechanism downgrade | the client refuses an AARE accepting a different context or mechanism than it proposed, and a refusal is answered in the context that was *proposed* |
| Pushed data | a forged reading under the meter's identity | the listener enforces the protection **it** was configured to require, never the protection the frame claims |

Not defended here, and belonging to you: physical key provisioning, the security of the
transport below the wrapper (TLS on TCP is yours), and the policy deciding which suites a
fleet still accepts.
