//! A meter simulator over TCP, so something can be pointed at it.
//!
//! ```sh
//! cargo run --example meter                 # then, in another shell:
//! cargo run --example read
//! ```
//!
//! It speaks the DLMS **wrapper** — eight bytes of header over TCP, IANA port 4059 — which
//! is what a head-end and most GPRS meters use, and what any third-party DLMS client can
//! be pointed at. That is deliberate: the crate's own largest gap is that almost every
//! test is this code agreeing with itself, and a simulator another implementation can
//! read is what closes it.
//!
//! It serves plain, unauthenticated associations. Pass `--ciphered` for authenticated and
//! encrypted with high level security; `examples/read.rs` takes the same flag.
//!
//! Nothing about associations, keys, access control or segmentation appears in the store
//! below — all of that is the framework's, which is the point of the `ObjectStore` seam.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use dlms_cosem_rs::acse::AuthMechanism;
use dlms_cosem_rs::axdr::{Data, DateTime, Unit};
use dlms_cosem_rs::codec::{Encode, Writer};
use dlms_cosem_rs::cosem::{AttributeAccess, MethodAccess};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use dlms_cosem_rs::server::{AuditEvent, ObjectStore, Server, ServerConfig, StoreResult};
use dlms_cosem_rs::transport::wrapper::{DEFAULT_PORT, StreamReassembler, Wpdu};
use dlms_cosem_rs::xdlms::{ActionResult, DataAccessResult, SelectiveAccess};

const GUEK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] =
    [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
const METER_TITLE: SystemTitle = SystemTitle::new(*b"MMM\x00\x00\xbcaN");

const ENERGY: Obis = Obis::new(1, 0, 1, 8, 0, 255);
const ENERGY_EXPORT: Obis = Obis::new(1, 0, 2, 8, 0, 255);
const POWER: Obis = Obis::new(1, 0, 1, 7, 0, 255);
const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255);
const BREAKER: Obis = Obis::new(0, 0, 96, 3, 10, 255);
const PROFILE: Obis = Obis::new(1, 0, 99, 1, 0, 255);

/// How many rows the load profile holds. Large enough that the encoded value does not fit
/// one APDU, so reading it exercises block transfer rather than pretending to.
const PROFILE_ROWS: u32 = 240;

struct Meter {
    energy_wh: u32,
    export_wh: u32,
    power_w: u32,
    time: DateTime,
    breaker_closed: bool,
}

impl ObjectStore for Meter {
    fn get_attribute(
        &self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        selective_access: Option<SelectiveAccess<'_>>,
        w: &mut dyn Writer,
    ) -> StoreResult<()> {
        let bad = |_| DataAccessResult::OtherReason;
        match (class_id, logical_name, attribute_id) {
            (_, name, 1) => Data::OctetString(name.as_bytes()).encode(w).map_err(bad),
            (3, ENERGY, 2) => Data::DoubleLongUnsigned(self.energy_wh).encode(w).map_err(bad),
            (3, ENERGY_EXPORT, 2) => Data::DoubleLongUnsigned(self.export_wh).encode(w).map_err(bad),
            (3, POWER, 2) => Data::DoubleLongUnsigned(self.power_w).encode(w).map_err(bad),
            // scaler_unit: structure { integer scaler, enum unit }
            (3, ENERGY | ENERGY_EXPORT, 3) => {
                w.write_bytes(&[0x02, 0x02, 0x0F, 0x00, 0x16, Unit::WATT_HOUR.0]).map_err(bad)
            }
            (3, POWER, 3) => w.write_bytes(&[0x02, 0x02, 0x0F, 0x00, 0x16, Unit::WATT.0]).map_err(bad),
            (8, CLOCK, 2) => Data::DateTime(self.time).encode(w).map_err(bad),
            (70, BREAKER, 2) => Data::Boolean(self.breaker_closed).encode(w).map_err(bad),
            (7, PROFILE, 2) => self.profile(selective_access, w),
            _ => Err(DataAccessResult::ObjectUndefined),
        }
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
            (8, CLOCK, 2, _) => Err(DataAccessResult::TypeUnmatched),
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
                Ok(false)
            }
            (70, BREAKER, 2) => {
                self.breaker_closed = true;
                Ok(false)
            }
            _ => Err(ActionResult::ObjectUndefined),
        }
    }

    fn attribute_access(&self, _: u16, logical_name: Obis, attribute_id: i8) -> AttributeAccess {
        if logical_name == CLOCK && attribute_id == 2 {
            return AttributeAccess::READ | AttributeAccess::WRITE;
        }
        AttributeAccess::READ
    }

    fn method_access(&self, _: u16, logical_name: Obis, _: i8) -> MethodAccess {
        if logical_name == BREAKER { MethodAccess::ACCESS } else { MethodAccess::empty() }
    }

    fn audit(&mut self, event: AuditEvent) {
        println!("  {event:?}");
    }
}

impl Meter {
    /// A load profile: an array of `structure { double-long-unsigned, long-unsigned }`,
    /// far too large for one APDU — which is what a real one is.
    ///
    /// Selector 2 narrows it by entry position. **Honouring the selector is the store's
    /// job**: the framework carries it here intact but cannot apply it, because only the
    /// store knows what its buffer is sorted by. A store that accepted a selector and
    /// ignored it would answer a day's request with a year of data and nothing in the
    /// exchange would say so.
    fn profile(&self, access: Option<SelectiveAccess<'_>>, w: &mut dyn Writer) -> StoreResult<()> {
        let bad = |_| DataAccessResult::OtherReason;
        let (from, to) = match access {
            None => (0, PROFILE_ROWS),
            Some(sa) if sa.selector == 2 => {
                let s = sa.parameters.as_structure().ok_or(DataAccessResult::TypeUnmatched)?;
                let first = s.get(0).map_err(|_| DataAccessResult::TypeUnmatched)?;
                let last = s.get(1).map_err(|_| DataAccessResult::TypeUnmatched)?;
                let first = first.as_u64().ok_or(DataAccessResult::TypeUnmatched)? as u32;
                let last = last.as_u64().ok_or(DataAccessResult::TypeUnmatched)? as u32;
                if first == 0 {
                    // Entries count from one; zero is not a position.
                    return Err(DataAccessResult::TypeUnmatched);
                }
                (first - 1, if last == 0 { PROFILE_ROWS } else { last.min(PROFILE_ROWS) })
            }
            // A selector this meter does not implement is refused rather than answered
            // with the whole buffer.
            Some(_) => return Err(DataAccessResult::ScopeOfAccessViolated),
        };
        if from > to {
            return Err(DataAccessResult::TypeUnmatched);
        }

        w.write_u8(0x01).map_err(bad)?; // array
        w.write_length((to - from) as usize).map_err(bad)?;
        for i in from..to {
            w.write_bytes(&[0x02, 0x02]).map_err(bad)?; // structure of two
            Data::DoubleLongUnsigned(1_000_000 + i * 17).encode(w).map_err(bad)?;
            Data::LongUnsigned((i * 7 % 1000) as u16).encode(w).map_err(bad)?;
        }
        Ok(())
    }
}

/// `N` bounds the largest *value* the store can produce — which is not the PDU size, and
/// is the limit a load profile runs into. This profile encodes to about two kilobytes.
type Simulator = Server<Meter, RustCryptoProvider<Rng>, 8192>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ciphered = std::env::args().any(|a| a == "--ciphered");
    let addr = format!("127.0.0.1:{DEFAULT_PORT}");
    let listener = TcpListener::bind(&addr)?;

    println!("meter listening on {addr}, {} association", if ciphered { "ciphered HLS" } else { "plain" });
    println!("  objects: 1-0:1.8.0, 1-0:2.8.0, 1-0:1.7.0, 0-0:1.0.0, 0-0:96.3.10, 1-0:99.1.0");
    println!("  try:     cargo run --example read{}\n", if ciphered { " -- --ciphered" } else { "" });

    for stream in listener.incoming() {
        let mut stream = stream?;
        println!("── client {}", stream.peer_addr()?);
        if let Err(e) = serve(&mut stream, ciphered) {
            println!("   link closed: {e}");
        }
        println!();
    }
    Ok(())
}

fn serve(stream: &mut TcpStream, ciphered: bool) -> Result<(), Box<dyn std::error::Error>> {
    let policy = if ciphered {
        SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0)
    } else {
        SecurityPolicy::NONE
    };
    let mut server: Simulator = Server::new(
        ServerConfig {
            system_title: Some(METER_TITLE),
            mechanism: if ciphered { AuthMechanism::HighGmac } else { AuthMechanism::None },
            security: policy,
            max_pdu_size: 512,
            // Persisted in a real device. Zero is right exactly once per key.
            invocation_counter: 0,
            ..Default::default()
        },
        Meter {
            energy_wh: 12_345_678,
            export_wh: 98_765,
            power_w: 1_193,
            time: DateTime::from_civil(2026, 9, 6, 12, 0, 0, 120),
            breaker_closed: true,
        },
        RustCryptoProvider::with_rng(
            if ciphered { KeyRing::new(GUEK, GAK) } else { KeyRing::default() },
            Rng,
        ),
    );

    // The wrapper may split one APDU across TCP segments and may pack two into one, so
    // the reassembler owns that and the bound is the largest APDU this meter accepts.
    let reassembler = StreamReassembler::new(2048);
    let mut buffered = Vec::new();
    let mut chunk = [0u8; 512];
    let mut out = [0u8; 2048];

    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            // A client that simply drops the connection never sends a release, and a
            // sans-I/O engine cannot see a closed socket — so the caller has to say so,
            // or the next client inherits this one's keys and negotiated terms.
            server.reset();
            return Ok(());
        }
        buffered.extend_from_slice(&chunk[..n]);

        while let Some((wpdu, used)) = reassembler.next_pdu(&buffered)? {
            let client_port = wpdu.header.source;
            let reply = server.handle(wpdu.apdu, &mut out)?;
            let mut framed = Vec::new();
            Wpdu::new(wpdu.header.destination, client_port, &out[..reply])?.encode(&mut framed)?;
            stream.write_all(&framed)?;
            buffered.drain(..used);
        }
    }
}

/// A counter, not a generator. Fine for a simulator on a loopback address and nowhere
/// else: a predictable challenge lets a recorded high-level-security reply authenticate.
struct Rng;

impl dlms_cosem_rs::security::RandomSource for Rng {
    fn fill(&self, out: &mut [u8]) -> dlms_cosem_rs::codec::Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0xB0u8.wrapping_add(i as u8);
        }
        Ok(())
    }
}
