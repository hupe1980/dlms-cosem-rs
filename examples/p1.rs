//! Read a P1 telegram — the customer interface on a Dutch or Belgian meter.
//!
//! ```sh
//! cargo run --example p1                       # a built-in telegram
//! cat capture.txt | cargo run --example p1      # your own, or a live port
//! ```
//!
//! On a real installation the port emits one telegram a second at 115200 8N1, so in
//! production the loop below reads from a serial device instead of standard input and
//! never exits. Nothing else changes: `TelegramReader` works on a stream, resynchronises
//! after noise, and tells the caller how many leading bytes it may throw away — which is
//! the only thing keeping a receive buffer bounded when a connector is loose.
//!
//! Two details in here are the ones that cost people an afternoon:
//!
//! * `123456.789*kWh` is decoded as **123 456 789 Wh exactly**. The SI prefix and the
//!   decimal point both become the scaler and the mantissa stays an integer, because a
//!   reading a billing system will subtract from next month's must not go through an
//!   `f64` on the way in.
//! * A timestamp's trailing `S`/`W` says which of the local zone's two offsets applied.
//!   It is **not** a UTC offset, so the decoded value reports none rather than inventing
//!   `+0100` — a fabricated offset cannot be taken back later.

use std::io::Read;

use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::transport::p1::{Found, TelegramReader, crc16};

/// The example telegram from the DSMR 5.0.2 companion standard, with a checksum this
/// crate computes.
///
/// The standard prints its own CRC alongside this telegram; that value cannot be
/// reproduced from the printed characters, because the document is a word-processor
/// rendering and its line breaks are not the telegram's. So the *algorithm* is checked
/// against CRC-16/ARC's published check value in the test suite, and the telegram here
/// exercises the grammar. Quoting a CRC and adjusting the text until it matched would
/// have proved only that the text had been adjusted.
const SAMPLE_BODY: &str = concat!(
    "/ISk5\\2MT382-1000\r\n",
    "\r\n",
    "1-3:0.2.8(50)\r\n",
    "0-0:1.0.0(101209113020W)\r\n",
    "0-0:96.1.1(4B384547303034303436333935353037)\r\n",
    "1-0:1.8.1(123456.789*kWh)\r\n",
    "1-0:1.8.2(123456.789*kWh)\r\n",
    "1-0:2.8.1(000000.000*kWh)\r\n",
    "0-0:96.14.0(0002)\r\n",
    "1-0:1.7.0(01.193*kW)\r\n",
    "1-0:32.7.0(220.1*V)\r\n",
    "1-0:31.7.0(001*A)\r\n",
    "0-1:24.1.0(003)\r\n",
    "0-1:24.2.1(101209112500W)(12785.123*m3)\r\n",
    "!"
);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut buffered = Vec::new();
    std::io::stdin().read_to_end(&mut buffered)?;
    if buffered.is_empty() {
        buffered = format!("{SAMPLE_BODY}{:04X}\r\n", crc16(SAMPLE_BODY.as_bytes())).into_bytes();
        println!("(no input on stdin — using the DSMR 5.0.2 example telegram)\n");
    }

    // A reader that requires the checksum. DSMR 2.x and 3.x meters send none;
    // `TelegramReader::without_checksum` reads those, and it is a separate constructor
    // rather than a fallback because losing the only integrity check the format has
    // should be something the caller said out loud.
    let mut reader = TelegramReader::new();
    let mut at = 0usize;
    let mut telegrams = 0usize;

    loop {
        match reader.next_telegram(&buffered[at..])? {
            Found::Telegram { telegram, consumed } => {
                telegrams += 1;
                at += consumed;
                println!("meter {} — {}", telegram.manufacturer().unwrap_or("???"), telegram.identification);

                for line in telegram.lines() {
                    let line = line?;
                    print!("  {:<18}", line.obis.to_string());

                    // A value is not always a number, so it is converted by name.
                    if let Some(v) = line.as_scaled() {
                        // Exact: an integer and a power of ten, never a float.
                        println!("{} x 10^{} {}", v.value, v.scaler, v.unit);
                    } else if let Some(t) = line.as_timestamp() {
                        println!(
                            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} ({})",
                            t.year,
                            t.month,
                            t.day_of_month,
                            t.hour,
                            t.minute,
                            t.second,
                            if t.status.daylight_saving_active() { "summer" } else { "winter" },
                        );
                    } else {
                        // An equipment identifier is text that is really bytes.
                        let mut out = [0u8; 128];
                        match line.decode_hex(&mut out) {
                            Ok(n) => match core::str::from_utf8(&out[..n]) {
                                Ok(text) => println!("{text:?}"),
                                Err(_) => println!("{:02X?}", &out[..n]),
                            },
                            Err(_) => {
                                let values: Vec<&str> = line.values().collect();
                                println!("{}", values.join(" · "));
                            }
                        }
                    }
                }

                // A gas meter reports through the electricity meter, and its reading is
                // the *second* value on the line: a parser that only ever looks at the
                // first reports a gas meter that reads zero.
                if let Some(gas) = telegram.get(Obis::new(0, 1, 24, 2, 1, 255)) {
                    println!("\n  gas: {} at {}", gas.value(1).unwrap_or("?"), gas.value(0).unwrap_or("?"));
                }
            }
            Found::Incomplete { discard } => {
                if telegrams == 0 && discard > 0 {
                    println!("no complete telegram; {discard} bytes were not part of one");
                }
                break;
            }
        }
    }

    println!("\n{telegrams} telegram(s); {} bytes discarded as noise", reader.discarded());
    Ok(())
}
