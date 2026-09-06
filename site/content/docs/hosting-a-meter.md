+++
title = "Hosting a meter"
description = "Implement ObjectStore and let the framework handle associations, authentication, access control, protection and segmentation — with an audit trail that records refusals."
weight = 70
+++

The server is the half most stacks never grow, and it is the half that decides whether an
object model is any good: a model written for a client only has to *read* every class, one
written for a server has to *host* them.

Implement one trait. Associations, authentication, access control, protection, replay
rejection and segmentation are the framework's.

```rust,ignore
impl ObjectStore for Meter {
    fn get_attribute(
        &self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        selective_access: Option<SelectiveAccess<'_>>,
        w: &mut dyn Writer,
    ) -> StoreResult<()> {
        match (class_id, logical_name.as_bytes(), attribute_id) {
            (_, _, 1) => Data::OctetString(logical_name.as_bytes()).encode(w),
            (3, [1, 0, 1, 8, 0, 255], 2) => Data::DoubleLongUnsigned(self.energy_wh).encode(w),
            _ => return Err(DataAccessResult::ObjectUndefined),
        }
        .map_err(|_| DataAccessResult::OtherReason)
    }

    fn attribute_access(&self, _: u16, _: Obis, _: i8) -> AttributeAccess {
        AttributeAccess::READ
    }
}
```

Four things about that signature are deliberate.

**The store writes into the response buffer.** `get_attribute` takes an output sink rather
than returning a value. A profile buffer of ten thousand rows is the largest thing a meter
returns; a signature that returned it would make it exist twice, and in a build with no
allocator it could not exist even once.

**`attribute_access` has no useful default.** It defaults to *nothing*, so a store that
forgets to implement it exposes nothing rather than everything. The other default is the
one that ends up in a CVE.

**Access rights are consulted before the store is asked.** A store is never called for an
object the association may not touch, so it cannot leak a value it was not supposed to
expose by computing it first.

**`Ok` means something was written.** Returning `Ok(())` from `get_attribute` without
writing — or `Ok(true)` from `invoke_method` with no return value — is the bug every store
has once, a branch that returns before it encodes. The response it would produce is a
choice byte with nothing behind it: *undecodable* rather than merely wrong, and inside a
batched read it would shift every later answer onto the wrong attribute. The server checks
and answers with a refusal that names the object.

## The audit hook

`ObjectStore::audit` sees every association attempt, every read and write and every method
invocation — **with its outcome, refusals included**.

```rust,ignore
fn audit(&mut self, event: AuditEvent) {
    // A breaker operation belongs in the same flash transaction as the operation.
    self.log.push(event);
}
```

The refusals are the half worth having. Access control is the framework's, so your store is
never *asked* for an object the association may not touch — without this hook it would
never learn that somebody tried to open the breaker without the rights to, and that event
is the one an incident review wants.

It sits on `ObjectStore` rather than behind its own generic because a meter wants the
breaker operation and its record in one flash transaction. It is **not** a write-ahead log:
the event is recorded after the outcome is known, so if you need the record on disk before
the relay moves, do that inside `invoke_method`, which has the ordering guarantee.

## One association, one link

A `Server` hosts one association over one link. A meter with several logical devices runs
**one `Server` per device**, and the caller routes by the service access point its
transport hands it — the wrapper header's destination port, or the HDLC destination
address. The server never sees a transport, so the routing is not its to do.

A client that simply drops the connection never sends a release, and a sans-I/O engine
cannot see a closed socket. **A caller reusing a `Server` across connections must call
`Server::reset`**, or the next client inherits the previous one's dedicated key, negotiated
conformance and challenge.

## Refusals are responses, not errors

`Server::handle` returns `Err` only for a malformed APDU or an output buffer too small.
Everything a client can act on comes back as the exception response the standard defines
for it: a service in the wrong state, an APDU that would not decipher, one longer than the
negotiated size. A caller handed an `Err` has to invent an answer, and will invent a worse
one.

## Pushing

A push is not part of an association, so it is a separate object. `PushSender` builds a
notification; it goes out when the push setup's communication window opens, to a
destination the setup names, possibly while no client is connected at all.

```rust,ignore
let mut sender: PushSender<_> = PushSender::new(
    provider,
    SystemTitle::new(*b"LGZ\x00\x12\x34\x56\x78"),
    SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
    restore_counter(),          // never 0 against a key this device has used
);

let n = sender.notify(Some(captured_at), &values, &mut frame)?;
send_to(&frame[..n]);
persist_counter(sender.invocation_counter());
```

A `DataNotification` has no ciphered tag, so a protected push has exactly one form:
`general-glo-ciphering`, which carries the meter's system title in the clear — that is how
a listener holding keys for a hundred meters knows which to try.

Deciding *when* to push is not here. That needs the push setup's communication window and a
clock, and there is no clock in this crate.
