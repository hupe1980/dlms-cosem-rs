//! A protocol translator: hexadecimal in, a decoded APDU out.
//!
//! ```sh
//! cargo run --example decode                       # a few built-in samples
//! cargo run --example decode -- C001810003 0100010800FF0200
//! ```
//!
//! This is the shape of tool you reach for with a capture in one hand and a meter that
//! will not answer in the other, and it shows two things the codec is built around.
//!
//! **A decoding failure names a byte.** `Error` carries the offset it happened at, so the
//! output is `byte 7: invalid tag 0x1b` rather than "parse error" — which is the
//! difference between a five-minute fix and an afternoon.
//!
//! **A protected APDU decodes without a key.** A ciphered service comes back with its
//! security header intact: the suite, the protection bits and the invocation counter are
//! all readable, and only the payload is not. A translator, a router or a fuzzer needs
//! that; a stack that could not do it would make every protected capture opaque.

use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::codec::Decode;
use dlms_cosem_rs::xdlms::Apdu;

/// A handful of real APDU shapes, so the example does something on its own.
const SAMPLES: &[(&str, &str)] = &[
    ("a GET request for 1-0:1.8.0*255 attribute 2", "C0 01 C1 00 03 01 00 01 08 00 FF 02 00"),
    ("the answer: a 32-bit register value", "C4 01 C1 00 06 00 BC 61 4E"),
    ("a refusal: the association may not read it", "C4 01 C1 01 03"),
    ("the same GET, protected with the global key set", "C8 0A 30 00 00 00 01 AA BB CC DD EE"),
    ("an exception response naming a counter error", "D8 01 06 00 00 00 2A"),
    ("a value with a tag nobody defines", "C4 01 C1 00 0B"),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        for (what, hex) in SAMPLES {
            println!("── {what}");
            report(hex);
            println!();
        }
        println!("pass your own hex as arguments to decode it.");
        return;
    }
    for hex in &args {
        report(hex);
    }
}

fn report(hex: &str) {
    let bytes = match unhex(hex) {
        Some(b) => b,
        None => {
            println!("   not hexadecimal: {hex}");
            return;
        }
    };
    println!("   {} bytes: {}", bytes.len(), pretty(&bytes));

    match Apdu::from_bytes(&bytes) {
        Ok(apdu) => {
            println!("   tag {:?} ({:#04x})", apdu.tag(), apdu.tag().as_u8());
            match apdu {
                // The interesting case: readable without a key, and honest about what it
                // is not telling you.
                Apdu::Ciphered { protection, service, body } => {
                    println!("   protected: {protection:?}, carrying {service:?}");
                    println!("     suite            {}", body.security_control.suite());
                    println!("     authenticated    {}", body.security_control.authenticated());
                    println!("     encrypted        {}", body.security_control.encrypted());
                    println!("     counter          {}", body.invocation_counter);
                    println!("     payload          {} bytes, needs a key", body.payload.len());
                }
                Apdu::GetResponse(r) => println!("   {r:?}"),
                Apdu::ExceptionResponse(e) => {
                    println!("   state:   {:?}", e.state_error);
                    println!("   service: {:?}", e.service_error);
                    if let Some(c) = e.expected_invocation_counter {
                        println!("   the sender expects counter {c} next");
                    }
                }
                other => println!("   {other:?}"),
            }
        }
        // Not an APDU. It may still be a bare value — a `Data` out of the middle of one,
        // which is what a capture tool usually hands you.
        Err(apdu_error) => match Data::from_bytes(&bytes) {
            Ok(value) => println!("   not an APDU, but a value: {value:?}"),
            Err(_) => println!("   {apdu_error}"),
        },
    }
}

/// Hex with any spacing, because a byte string pasted out of Wireshark has spaces in it
/// and a byte string pasted out of a log usually does not.
fn unhex(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b':').collect();
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    digits
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

fn pretty(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i == 24 {
            out.push('…');
            break;
        }
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}
