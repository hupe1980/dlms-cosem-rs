//! A whole ciphered association, client and server in one process, with no I/O at all.
//!
//! ```sh
//! cargo run --example association
//! ```
//!
//! This is the crate's central claim made runnable. Both engines are sans-I/O: they build
//! APDUs into buffers and consume APDUs out of buffers, and *moving the bytes* is the
//! caller's job. Here the caller is a `move_bytes` call that copies one slice to another,
//! which is why the whole exchange — four-pass high level security, a ciphered read, a
//! write, a breaker operation, a release — finishes in microseconds and needs no meter,
//! no socket and no network.
//!
//! The same two engines, unchanged, run over TCP in `examples/meter.rs` and
//! `examples/read.rs`.

use dlms_cosem_rs::acse::AuthMechanism;
use dlms_cosem_rs::axdr::{Data, DateTime};
use dlms_cosem_rs::client::{AssociationStep, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::codec::{Encode, Writer};
use dlms_cosem_rs::cosem::{AttributeAccess, MethodAccess};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use dlms_cosem_rs::server::{AuditEvent, ObjectStore, Server, ServerConfig, StoreResult};
use dlms_cosem_rs::xdlms::{
    ActionResult, AttributeDescriptor, DataAccessResult, MethodDescriptor, SelectiveAccess,
};

/// The global unicast encryption key and the authentication key. Both ends hold both;
/// in the field they arrive from the meter operator.
const GUEK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] =
    [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];

/// A system title is eight bytes and is *half of every nonce* this end sends under. Two
/// devices sharing a key must not share one.
const CLIENT_TITLE: SystemTitle = SystemTitle::new(*b"CLI\x00\x00\x00\x00\x01");
const METER_TITLE: SystemTitle = SystemTitle::new(*b"MMM\x00\x00\xbcaN");

const ENERGY: Obis = Obis::new(1, 0, 1, 8, 0, 255); // 1-0:1.8.0*255, import energy
const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255); // 0-0:1.0.0*255, the clock
const BREAKER: Obis = Obis::new(0, 0, 96, 3, 10, 255); // 0-0:96.3.10*255, disconnect control

/// A meter with three objects. Everything a real one adds is more of the same match arm;
/// nothing about associations, keys or framing appears here, because none of it is the
/// store's business.
struct Meter {
    energy_wh: u32,
    time: DateTime,
    breaker_closed: bool,
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
        match (class_id, logical_name, attribute_id) {
            // Attribute 1 is the logical name, for every class there is.
            (_, name, 1) => Data::OctetString(name.as_bytes()).encode(w),
            (3, ENERGY, 2) => Data::DoubleLongUnsigned(self.energy_wh).encode(w),
            (8, CLOCK, 2) => Data::DateTime(self.time).encode(w),
            (70, BREAKER, 2) => Data::Boolean(self.breaker_closed).encode(w),
            _ => return Err(DataAccessResult::ObjectUndefined),
        }
        .map_err(|_| DataAccessResult::OtherReason)
    }

    fn set_attribute(
        &mut self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        _selective_access: Option<SelectiveAccess<'_>>,
        value: Data<'_>,
    ) -> StoreResult<()> {
        match (class_id, logical_name, attribute_id, value) {
            (8, CLOCK, 2, Data::DateTime(dt)) => {
                self.time = dt;
                Ok(())
            }
            _ => Err(DataAccessResult::ReadWriteDenied),
        }
    }

    fn invoke_method(
        &mut self,
        class_id: u16,
        logical_name: Obis,
        method_id: i8,
        _parameters: Option<Data<'_>>,
        _w: &mut dyn Writer,
    ) -> Result<bool, ActionResult> {
        match (class_id, logical_name, method_id) {
            (70, BREAKER, 1) => {
                self.breaker_closed = false;
                Ok(false) // the method returns nothing
            }
            _ => Err(ActionResult::ObjectUndefined),
        }
    }

    /// The default is `empty()`, so a store that forgets this exposes nothing rather than
    /// everything. Rights are consulted *before* the store is asked.
    fn attribute_access(&self, _: u16, logical_name: Obis, attribute_id: i8) -> AttributeAccess {
        if logical_name == CLOCK && attribute_id == 2 {
            return AttributeAccess::READ | AttributeAccess::WRITE;
        }
        AttributeAccess::READ
    }

    fn method_access(&self, _: u16, logical_name: Obis, _: i8) -> MethodAccess {
        if logical_name == BREAKER { MethodAccess::ACCESS } else { MethodAccess::empty() }
    }

    /// Every association, read, write and invocation — **with its outcome, refusals
    /// included**. Access control is the framework's, so a store never learns any other
    /// way that somebody tried to open the breaker without the rights to.
    fn audit(&mut self, event: AuditEvent) {
        println!("      audit: {event:?}");
    }
}

/// The entire transport. In `examples/read.rs` this is a `TcpStream`.
fn move_bytes(from: &[u8], to: &mut [u8]) -> usize {
    to[..from.len()].copy_from_slice(from);
    from.len()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Authenticated and encrypted under suite 0, with high level security. Both ends hold
    // the keys in their provider and nowhere else.
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);

    let mut client: ClientSession<_> = ClientSession::new(
        ClientConfig {
            client_sap: 0x30, // the management client
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            // Zero is right exactly once per key. A real client restores this from
            // storage — see `client.invocation_counter()` at the end.
            invocation_counter: 0,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), Rng),
    );

    // `N` sizes the server's working buffers, and bounds the largest *value* a store can
    // produce — which is not the same limit as the PDU size, and is the one a load
    // profile runs into. 1024 is the default and is plenty for three small objects.
    let mut meter: Server<_, _> = Server::new(
        ServerConfig {
            system_title: Some(METER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy,
            ..Default::default()
        },
        Meter {
            energy_wh: 12_345_678,
            time: DateTime::from_civil(2026, 9, 6, 12, 0, 0, 120),
            breaker_closed: true,
        },
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), Rng),
    );

    let mut request = [0u8; 1024];
    let mut wire = [0u8; 1024];
    let mut response = [0u8; 1024];
    let mut plain = [0u8; 1024];

    // ---- 1. Associate. High level security takes four passes, not two. ----------
    println!("→ AARQ");
    let n = client.associate_request(&mut request)?;
    let n = move_bytes(&request[..n], &mut wire);
    let m = meter.handle(&wire[..n], &mut response)?;
    println!("← AARE  ({m} bytes)");

    match client.handle_associate_response(&response[..m])? {
        AssociationStep::HlsReplyRequired => {
            // Pass 3: the client proves it holds the key by answering the meter's
            // challenge. Pass 4 is the meter proving the same to the client — an
            // association that skipped it would authenticate only one direction.
            println!("→ ACTION reply_to_HLS_authentication");
            let n = client.hls_reply_request(&mut request)?;
            let n = move_bytes(&request[..n], &mut wire);
            let m = meter.handle(&wire[..n], &mut response)?;
            println!("← ACTION response, the meter's own proof");
            let step = client.handle_hls_reply_response(&response[..m])?;
            assert_eq!(step, AssociationStep::Established);
        }
        AssociationStep::Established => {}
        AssociationStep::Rejected { result, diagnostic } => {
            return Err(format!("refused: {result:?} / {diagnostic:?}").into());
        }
        AssociationStep::Exception(e) => {
            return Err(format!("the meter refused the AARQ outright: {e:?}").into());
        }
    }
    println!("  association open, ciphered, mutually authenticated\n");

    // ---- 2. Read a register. -----------------------------------------------------
    println!("→ GET 1-0:1.8.0*255 attribute 2");
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut request)?;
    // `0xC8` is glo-get-request: the plain tag 0xC0 protected with the global key set.
    println!("  on the wire: {:02X} … ({} bytes, ciphered)", request[0], n);
    let n = move_bytes(&request[..n], &mut wire);
    let m = meter.handle(&wire[..n], &mut response)?;
    match client.handle_response(&response[..m], &mut plain)? {
        Response::Data(v) => println!("← {:?} Wh\n", v.as_u64().unwrap_or_default()),
        other => println!("← {other:?}\n"),
    }

    // ---- 3. Write the clock. -----------------------------------------------------
    let new_time = DateTime::from_civil(2026, 9, 6, 13, 30, 0, 120);
    println!("→ SET 0-0:1.0.0*255 attribute 2");
    let n = client.set_request(
        AttributeDescriptor::new(8, CLOCK, 2),
        None,
        Data::DateTime(new_time),
        &mut request,
    )?;
    let n = move_bytes(&request[..n], &mut wire);
    let m = meter.handle(&wire[..n], &mut response)?;
    println!("← {:?}\n", client.handle_response(&response[..m], &mut plain)?);

    // ---- 4. Open the breaker, then replay the identical frame. --------------------
    println!("→ ACTION 0-0:96.3.10*255 method 1 (open the breaker)");
    let n = client.action_request(MethodDescriptor::new(70, BREAKER, 1), None, &mut request)?;
    let sent = request[..n].to_vec(); // an on-path attacker records exactly this
    let n = move_bytes(&request[..n], &mut wire);
    let m = meter.handle(&wire[..n], &mut response)?;
    println!("← {:?}", client.handle_response(&response[..m], &mut plain)?);
    println!("  breaker closed: {}\n", meter.store().breaker_closed);

    println!("→ the identical bytes again — a recorded frame, replayed");
    let n = move_bytes(&sent, &mut wire);
    let m = meter.handle(&wire[..n], &mut response)?;
    // The frame verifies perfectly: it really was sent under the real key. Only the
    // invocation counter tells the copy from the original, which is why the counter is a
    // control rather than bookkeeping.
    match client.handle_response(&response[..m], &mut plain) {
        Ok(Response::Exception(e)) => {
            // Named, not generic. A client told "deciphering error" learns nothing it can
            // act on and retries the same frame; this one is handed the counter to
            // resynchronise to — which is how a device that restarted from stale storage
            // recovers without a site visit.
            println!("← refused: {:?}", e.service_error);
            if let Some(expected) = e.expected_invocation_counter {
                println!("  the meter expects {expected} next");
            }
        }
        other => println!("← {other:?}"),
    }
    println!("  breaker still open, not opened twice: {}\n", !meter.store().breaker_closed);

    // ---- 5. Release, and persist the counter. ------------------------------------
    println!("→ RLRQ");
    let n = client.release_request(&mut request)?;
    let n = move_bytes(&request[..n], &mut wire);
    let m = meter.handle(&wire[..n], &mut response)?;
    println!("← {:?}\n", client.handle_response(&response[..m], &mut plain)?);

    // The one thing this crate cannot do for you. A device that restarts from zero
    // against an unchanged key repeats every nonce it has used, and a repeated GCM nonce
    // leaks the authentication subkey rather than a single reading.
    println!("persist these, or the next run reuses a nonce:");
    println!("  client invocation counter: {}", client.invocation_counter());
    println!("  meter  invocation counter: {}", meter.invocation_counter());
    Ok(())
}

/// Randomness is *injected*: a provider with no entropy source refuses to produce a high
/// level security challenge rather than returning something predictable.
///
/// This one is a counter, so the example prints the same bytes every run. Never do this
/// anywhere a network can reach — wire in `getrandom`, `rand`, or the platform's hardware
/// generator.
struct Rng;

impl dlms_cosem_rs::security::RandomSource for Rng {
    fn fill(&self, out: &mut [u8]) -> dlms_cosem_rs::codec::Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0xA0u8.wrapping_add(i as u8);
        }
        Ok(())
    }
}
