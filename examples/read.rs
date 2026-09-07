//! Read a meter over TCP: associate, read some registers, pull a load profile, release.
//!
//! ```sh
//! cargo run --example meter                 # in one shell
//! cargo run --example read                  # in another
//!
//! cargo run --example meter -- --ciphered   # or the same pair, protected
//! cargo run --example read  -- --ciphered
//!
//! cargo run --example read -- 10.0.0.5:4059 # or a real meter
//! ```
//!
//! The session here is the same `ClientSession` that runs with no sockets at all in
//! `examples/association.rs`. Everything below it — the wrapper header, the stream
//! reassembly, the `TcpStream` — is this file's business and not the crate's, which is
//! what "sans-I/O" buys: the protocol logic is identical whether the bytes travel over
//! TCP, an optical probe, or a function call in a unit test.

use std::io::{Read, Write};
use std::net::TcpStream;

use dlms_cosem_rs::acse::AuthMechanism;
use dlms_cosem_rs::client::{AssociationStep, BlockCollector, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::codec::Encode;
use dlms_cosem_rs::cosem::EntryDescriptor;
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use dlms_cosem_rs::transport::wrapper::{DEFAULT_PORT, StreamReassembler, Wpdu};
use dlms_cosem_rs::xdlms::{AttributeDescriptor, AttributeDescriptorWithSelection, MethodDescriptor};

const GUEK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] =
    [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
const CLIENT_TITLE: SystemTitle = SystemTitle::new(*b"CLI\x00\x00\x00\x00\x01");

/// The wrapper's ports are the service access points: 0x10 is the public client, 0x20 a
/// meter reader, 0x30 management. The server side is the logical device, 1 being
/// management.
const CLIENT_SAP: u16 = 0x0010;
const LOGICAL_DEVICE: u16 = 0x0001;

const ENERGY: Obis = Obis::new(1, 0, 1, 8, 0, 255);
const ENERGY_EXPORT: Obis = Obis::new(1, 0, 2, 8, 0, 255);
const POWER: Obis = Obis::new(1, 0, 1, 7, 0, 255);
const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255);
const BREAKER: Obis = Obis::new(0, 0, 96, 3, 10, 255);
const PROFILE: Obis = Obis::new(1, 0, 99, 1, 0, 255);

/// Everything the crate does not do: a socket, a header, and a buffer that survives a
/// TCP segment boundary.
struct Link {
    stream: TcpStream,
    reassembler: StreamReassembler,
    buffered: Vec<u8>,
}

impl Link {
    fn connect(addr: &str) -> std::io::Result<Self> {
        Ok(Self {
            stream: TcpStream::connect(addr)?,
            // The bound on reassembly is the only thing standing between this and a peer
            // that announces a very large length and then stops sending.
            reassembler: StreamReassembler::new(4096),
            buffered: Vec::new(),
        })
    }

    /// Send one APDU and wait for one back.
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut framed = Vec::new();
        Wpdu::new(CLIENT_SAP, LOGICAL_DEVICE, apdu)?.encode(&mut framed)?;
        self.stream.write_all(&framed)?;

        let mut chunk = [0u8; 512];
        loop {
            if let Some((wpdu, used)) = self.reassembler.next_pdu(&self.buffered)? {
                let answer = wpdu.apdu.to_vec();
                self.buffered.drain(..used);
                return Ok(answer);
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err("the meter closed the connection".into());
            }
            self.buffered.extend_from_slice(&chunk[..n]);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ciphered = args.iter().any(|a| a == "--ciphered");
    let addr = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_PORT}"));

    let mut link = Link::connect(&addr)?;
    println!("connected to {addr}\n");

    let policy = if ciphered {
        SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0)
    } else {
        SecurityPolicy::NONE
    };
    let mut session: ClientSession<_> = ClientSession::new(
        ClientConfig {
            client_sap: 0x10,
            system_title: ciphered.then_some(CLIENT_TITLE),
            mechanism: if ciphered { AuthMechanism::HighGmac } else { AuthMechanism::None },
            security: policy,
            max_pdu_size: 512,
            invocation_counter: 0,
            ..Default::default()
        },
        RustCryptoProvider::with_rng(
            if ciphered { KeyRing::new(GUEK, GAK) } else { KeyRing::default() },
            Rng,
        ),
    );

    let mut request = [0u8; 1024];
    let mut plain = [0u8; 4096];

    // ---- associate ---------------------------------------------------------------
    let n = session.associate_request(&mut request)?;
    let answer = link.exchange(&request[..n])?;
    match session.handle_associate_response(&answer)? {
        // High level security needs two more passes, and the fourth is the meter proving
        // itself to *us*. A driver that looped on the step would not need this match at
        // all, which is why the step is a value rather than a callback.
        AssociationStep::HlsReplyRequired => {
            let n = session.hls_reply_request(&mut request)?;
            let answer = link.exchange(&request[..n])?;
            if session.handle_hls_reply_response(&answer)? != AssociationStep::Established {
                return Err("the meter did not prove it holds the key".into());
            }
        }
        AssociationStep::Established => {}
        AssociationStep::Rejected { result, diagnostic } => {
            return Err(format!("refused: {result:?} / {diagnostic:?}").into());
        }
        // A meter that cannot even reach an AARE answers with an exception. The one
        // worth acting on is `invocation-counter-error`: it names the value to move to.
        AssociationStep::Exception(e) => {
            if let Some(expected) = e.expected_invocation_counter {
                return Err(format!(
                    "the meter refused: {:?}. Its counter for us is {expected}; \
                     store that and set ClientConfig::invocation_counter to it.",
                    e.service_error
                )
                .into());
            }
            return Err(format!("the meter refused the AARQ outright: {e:?}").into());
        }
    }
    let negotiated = session.negotiated().ok_or("no InitiateResponse")?;
    println!(
        "associated — PDU size {}, conformance {:?}\n",
        negotiated.server_max_receive_pdu_size, negotiated.negotiated_conformance
    );

    // ---- read three registers in one round trip ----------------------------------
    // On a GPRS or LPWAN link the round trip is the whole cost, so this is three times
    // faster than three reads — and each item gets its own result, so one denied object
    // does not lose the others.
    let wanted = [
        ("import energy", AttributeDescriptor::new(3, ENERGY, 2)),
        ("export energy", AttributeDescriptor::new(3, ENERGY_EXPORT, 2)),
        ("active power", AttributeDescriptor::new(3, POWER, 2)),
    ];
    let items: Vec<_> = wanted
        .iter()
        .map(|(_, descriptor)| AttributeDescriptorWithSelection { descriptor: *descriptor, access: None })
        .collect();

    let n = session.get_request_with_list(&items, &mut request)?;
    let answer = link.exchange(&request[..n])?;
    if let Response::DataList(results) = session.handle_response(&answer, &mut plain)? {
        for ((label, _), result) in wanted.iter().zip(results.iter()) {
            match result?.value() {
                Ok(v) => println!("  {label:<16}{:?}", v.as_u64().unwrap_or_default()),
                Err(why) => println!("  {label:<16}refused: {why:?}"),
            }
        }
    }
    println!();

    // ---- read the clock and the breaker ------------------------------------------
    for (label, class, name) in [("clock", 8u16, CLOCK), ("breaker closed", 70, BREAKER)] {
        let n = session.get_request(AttributeDescriptor::new(class, name, 2), None, &mut request)?;
        let answer = link.exchange(&request[..n])?;
        match session.handle_response(&answer, &mut plain)? {
            Response::Data(v) => println!("  {label:<16}{v:?}"),
            other => println!("  {label:<16}{other:?}"),
        }
    }
    println!();

    // ---- a load profile: too large for one APDU, so it arrives in blocks ---------
    // Selective access narrows it at the *meter*, which is the difference between
    // fetching ten entries and fetching a year of them.
    // 120 entries encode to well over the 512-byte PDU size negotiated above, so this
    // read genuinely blocks rather than pretending to. Narrow it to a handful and the
    // answer arrives in one APDU instead — which is the same code path, one block long.
    let mut params = [0u8; 64];
    let selector = EntryDescriptor::entries(1, 120).to_selective_access(&mut params)?;

    let n = session.get_request(AttributeDescriptor::new(7, PROFILE, 2), Some(selector), &mut request)?;
    let answer = link.exchange(&request[..n])?;

    // The buffer is the caller's: how large a load profile may be is a property of the
    // deployment, not a decision for the crate.
    let mut storage = vec![0u8; 8192];
    let mut blocks = BlockCollector::new(&mut storage);
    let mut response = session.handle_response(&answer, &mut plain)?;
    let mut count = 0;

    loop {
        match response {
            Response::Block { last, number, data } => {
                // `push` insists blocks arrive consecutively from one. A duplicated or
                // reordered fragment concatenated in the wrong place usually still
                // *decodes* — into a reading that is wrong and carries no error.
                blocks.push(number, data)?;
                count += 1;
                if last {
                    break;
                }
                let n = session.get_next_block_request(number, &mut request)?;
                let answer = link.exchange(&request[..n])?;
                response = session.handle_response(&answer, &mut plain)?;
            }
            // Small enough for one APDU after all.
            Response::Data(value) => {
                let array = value.as_array().ok_or("the profile is not an array")?;
                println!("  load profile: {} rows, no block transfer needed", array.len());
                break;
            }
            other => return Err(format!("unexpected: {other:?}").into()),
        }
    }

    if count > 0 {
        // Only the concatenation decodes: a fragment boundary falls wherever the meter's
        // budget ran out, which is very often in the middle of a length prefix.
        let rows = blocks.value()?;
        let array = rows.as_array().ok_or("the profile is not an array")?;
        println!("  load profile: {} rows reassembled from {count} blocks", array.len());
        for (i, row) in array.iter().enumerate().take(3) {
            let row = row?;
            let fields = row.as_structure().ok_or("a row is not a structure")?;
            println!("    [{i}] energy {:?}  power {:?}", fields.get(0)?.as_u64(), fields.get(1)?.as_u64());
        }
        println!("    … {} more", array.len().saturating_sub(3));
    }
    println!();

    // ---- an ACTION that changes something ----------------------------------------
    // Access control lives at the meter: if this association may not invoke the method,
    // the store is never even asked and the refusal is what comes back.
    let n = session.action_request(MethodDescriptor::new(70, BREAKER, 1), None, &mut request)?;
    let answer = link.exchange(&request[..n])?;
    println!("  open the breaker: {:?}\n", session.handle_response(&answer, &mut plain)?);

    // ---- release, and persist the counter ----------------------------------------
    let n = session.release_request(&mut request)?;
    let answer = link.exchange(&request[..n])?;
    let _ = session.handle_response(&answer, &mut plain);

    if ciphered {
        // The one rule the crate cannot enforce: a device that restarts from zero against
        // an unchanged key repeats every nonce it has used.
        println!("persist the invocation counter: {}", session.invocation_counter());
    }
    println!("done");
    Ok(())
}

/// See the note in `examples/meter.rs`. A counter is not a generator.
struct Rng;

impl dlms_cosem_rs::security::RandomSource for Rng {
    fn fill(&self, out: &mut [u8]) -> dlms_cosem_rs::codec::Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0xA0u8.wrapping_add(i as u8);
        }
        Ok(())
    }
}
