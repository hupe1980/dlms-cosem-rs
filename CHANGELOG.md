# Changelog

Notable changes, newest first. The format follows [Keep a Changelog], and versions follow
[Semantic Versioning] — with the pre-1.0 rule that **the minor version is the breaking
one**.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [0.1.0] — unreleased

First release worth using. Everything below `0.1.0` was unpublished groundwork.

### Added

- **Codec** — bounds-checked cursor, `Encode`/`Decode`, every error carrying the byte
  offset it happened at.
- **A-XDR** — borrowed `Data<'a>`, compact arrays with a bounded work budget, the
  edition-10 delta types, COSEM date/time with wildcards, units and scaled values; owned
  `DataBuf` behind `alloc`.
- **ACSE** — AARQ/AARE/RLRQ/RLRE, application contexts, authentication mechanisms, the
  24-bit conformance block.
- **xDLMS** — every APDU tag; GET, SET, ACTION and ACCESS with every `with-list` form;
  block transfer in both directions; general block transfer with the edition-9 streaming
  window and retry sub-procedure; push; exceptions.
- **Short-name referencing** behind the `sn` feature (off by default) — Read, Write,
  UnconfirmedWrite and InformationReport, driven from both engines, dispatched through the
  same object store and access control as the logical-name services.
- **Security** — suites 0–2 at both key widths, `glo-`/`ded-`/`general-glo-` ciphering,
  `general-ciphering` in its identified-key form, AES key wrap under 128- and 256-bit
  key-encrypting keys, HLS-GMAC, invocation counters and a per-peer replay window, all
  behind a swappable `CryptoProvider`.
- **Object model** — 102 interface classes as a registry, OBIS, access rights in both
  shapes, profile selective access, profile buffers with all three compressions undone.
- **Engines** — sans-I/O `ClientSession` and `Server`, a `NotificationListener` and a
  `PushSender`.
- **Transports** — HDLC (framing, addressing, segmentation and a link machine), the
  TCP/UDP wrapper, and the P1 customer interface.

### Security

- The **key set** an incoming frame is opened under comes from this end's policy, never
  from the frame's own broadcast bit or `glo-`/`ded-` tag.
- The **replay window** belongs to a peer rather than to an association: it survives
  `Server::reset`, so a client that reconnects cannot replay what it sent before the gap.
- A **new AARQ** clears everything scoped to the previous association, so a second
  association cannot inherit its dedicated key.
- A server whose provider cannot hold a delivered **dedicated key** refuses the
  association instead of continuing on the global key set.
- A stale **invocation counter** is answered `invocation-counter-error` at the AARQ, where
  a ciphered association actually fails first, carrying the value to move to.

### Not built

The CoAP transport; reliable (confirmed) push and push scheduling; SMS, M-Bus, mode E and
gateway routing; the asymmetric halves of suites 1 and 2; HLS mechanisms 3, 4, 6 and 7;
`action-request-with-list-and-first-pblock`. Each is refused by name rather than guessed
at — see [the status page](https://hupe1980.github.io/dlms-cosem-rs/docs/status/).

**Interoperability has not been tested.** Almost every green test is this crate agreeing
with itself.

[0.1.0]: https://github.com/hupe1980/dlms-cosem-rs/releases/tag/v0.1.0
