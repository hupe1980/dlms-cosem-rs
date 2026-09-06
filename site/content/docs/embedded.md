+++
title = "Embedded and no_std"
description = "Build dlms_cosem_rs for a Cortex-M or RISC-V microcontroller with no allocator, and check the panic-freedom claim yourself in one command."
weight = 60
+++

## Building without a standard library

```toml
[dependencies]
dlms_cosem_rs = { version = "0.0", default-features = false, features = [
    "client", "hdlc", "suite0",
] }
```

No `std`, no `alloc`. Without an allocator you still get:

- the full codec over borrowed `Data<'a>`, so a load profile decodes without copying;
- HDLC, the wrapper and P1;
- **both** engines, with caller-provided buffers;
- suite-0 protection and the notification listener.

`alloc` adds the owned `DataBuf` tree, `Vec` as an output sink, and expanding a compact
array into owned rows. `heapless` adds `heapless::Vec` as an output sink for a build with
no allocator at all.

`thumbv7em-none-eabihf`, `riscv32imac-unknown-none-elf` and `wasm32-unknown-unknown` are
built in CI, with and without `alloc`.

## Where the memory goes

Both engines are generic over a buffer size:

```rust,ignore
let server: Server<MyStore, MyProvider, 4096> = Server::new(config, store, provider);
```

That `N` and the negotiated PDU size are **different limits**, and confusing them is the
usual mistake:

- `max_pdu_size` bounds one *message*. A value larger than it is delivered over block
  transfer, however many blocks that takes.
- `N` bounds the whole *value*, because a response is built before it is cut up. A meter
  whose load profile encodes to eight kilobytes needs `N` of at least that, whatever PDU
  size it negotiates.

A store that overruns `N` gets a write error from its output sink and reports whatever
result it chooses. Nothing is truncated silently.

Reassembly buffers are always the caller's — `BlockCollector`, `BlockSender`,
`Reassembler`, `GbtReceiver` all take a slice. That is deliberate: reassembly is exactly
the allocation a firmware author has to size on purpose, and a type that allocated one
would be this crate deciding how large a load profile may be.

**One thing that is not yet measured**: a single `Server::handle` call can hold several
`N`-sized buffers live at once. At the default `N` of 1024 that is a few kilobytes of
stack. There is no size gate in CI yet, so the footprint goal on this page is an
aspiration and is labelled one.

## No panic reachable from the network

Everything in the crate faces the network before any key has been checked, so the ways a
decoder can abort the process are denied outright:

- `#![forbid(unsafe_code)]` — there is no `unsafe` anywhere in the crate;
- `panic!`, `unwrap`, `expect`, `todo` and `unimplemented` are denied in the library;
- every decoder returns a `Result` carrying the **byte offset** the failure happened at.

Lints are an argument, though. The claim is *measured*:

```sh
CARGO_PROFILE_RELEASE_LTO=false cargo build --release \
  --target thumbv7em-none-eabihf --no-default-features \
  --features client,server,hdlc,wrapper,p1,suite0

nm target/thumbv7em-none-eabihf/release/libdlms_cosem_rs*.rlib \
  | grep -E 'core[0-9]+panicking|panic_fmt'
```

That prints nothing, and CI fails if it ever does.

**Why LTO is switched off** matters. The release profile sets `lto = true`, which makes
rustc emit LLVM *bitcode* into the rlib rather than machine code — and bitcode still names
every panic path the optimiser has yet to discharge, so scanning it proves nothing either
way. Turning LTO off gets real object code, and it is also the harder bar: the library must
be panic-free on its own, without help from whole-program optimisation across the final
link.

The property is maintained by types rather than by review. Adding a `div_ceil` to the block
senders once put a divide-by-zero panic path into the object code, guarded by a check the
optimiser could not connect to the division; the fix was a `NonZeroUsize`, not a second
guard. `Reader`'s primitives are written in terms of `slice::get` rather than indexing
after a separate length check, for the same reason — and that one change discharged the
bound for every decoder in the crate at once.

## Randomness and time

**Randomness is injected.** A provider without an entropy source refuses to produce a high
level security challenge rather than returning something predictable:

```rust,ignore
impl RandomSource for MyHardwareRng {
    fn fill(&self, out: &mut [u8]) -> Result<()> { /* … */ }
}

let provider = RustCryptoProvider::with_rng(KeyRing::new(guek, gak), MyHardwareRng);
```

**Time is not injected, because nothing needs it.** There are no timers: a timestamp is a
`DateTime` you supply as data. The payoff is that a whole ciphered association runs as a
unit test in microseconds with time as a variable, and that a device without a wall clock
is not a special case.

The consequence is the one named on the [transports page](@/docs/transports.md): nothing in
the crate retransmits or times a peer out, because it has no way to. That is yours.

## Keys on a device

The default provider keeps keys in zeroised memory and never prints them. On a meter, a
provider backed by a secure element keeps them out of the application core entirely — that
is what `CryptoProvider` being a trait is for, and it is why binding cryptography into the
stack is a mistake two widely used C ports are still paying for.

And the rule that has no software answer: **persist the invocation counter.** A device that
restarts from zero against an unchanged key repeats every nonce it has used, and a repeated
GCM nonce leaks the authentication subkey. See [Security](@/docs/security.md).
