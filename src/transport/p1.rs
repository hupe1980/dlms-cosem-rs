//! The P1 customer interface: DSMR and eMUCs telegrams.
//!
//! P1 is the socket on the front of a Dutch, Belgian or Luxembourg meter that the
//! customer is entitled to read. It is not DLMS on the wire — it is the ASCII data
//! readout of IEC 62056-21 with OBIS codes — but it *is* the same object model, and a
//! stack that speaks COSEM already knows what `1-0:1.8.1` means.
//!
//! ```text
//! /ISk5\2MT382-1000<CR><LF>
//! <CR><LF>
//! 1-0:1.8.1(123456.789*kWh)<CR><LF>
//! …
//! !EF2F<CR><LF>
//! ```
//!
//! Three things about this format cost people time, and each has a rule here:
//!
//! * **The checksum is over `/` through `!` inclusive**, including every CR and LF —
//!   `[DSMR §6.2]`. A parser that trims lines before checking gets a mismatch it cannot
//!   explain.
//! * **A value is not always a number.** `0-0:96.1.1(4B3845…)` is a hex-encoded octet
//!   string, `0-0:1.0.0(101209113020W)` is a timestamp with a daylight-saving flag, and
//!   `1-0:99.97.0(2)(0-0:96.7.19)(…)` is a log with an OBIS code *inside* a value. So
//!   values are handed over as text and converted by name.
//! * **A decimal is not a float.** `123456.789*kWh` is exactly 123 456 789 Wh, and
//!   [`Line::as_scaled`] returns that as an integer and an exponent. Parsing it into an
//!   `f64` loses the last digit of a meter reading that a billing system will later
//!   subtract from another one.
//!
//! Luxembourg's P1 is a different thing that arrives on the same connector: an
//! *encrypted DLMS `DataNotification`*, which is [`crate::client::NotificationListener`]
//! and not this module.

use crate::axdr::{ClockStatus, DEVIATION_NOT_SPECIFIED, DateTime, ScaledValue, Unit};
use crate::codec::{Error, ErrorKind, Result};
use crate::obis::Obis;

/// The CRC-16 a P1 telegram carries: reflected polynomial `0xA001`
/// (that is, x¹⁶+x¹⁵+x²+1), initial value zero, no final complement — CRC-16/ARC
/// `[DSMR §6.2]`.
///
/// Not the same CRC as HDLC's frame check sequence, which is X-25: different polynomial,
/// different initial value, and a final complement. Two CRCs in one crate is exactly the
/// situation where one gets used for the other.
///
/// ```
/// // The check value every published description of CRC-16/ARC quotes.
/// assert_eq!(dlms_cosem_rs::transport::p1::crc16(b"123456789"), 0xBB3D);
/// ```
#[must_use]
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for b in data {
        crc ^= u16::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xA001 } else { crc >> 1 };
        }
    }
    crc
}

/// A complete telegram whose checksum has been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Telegram<'a> {
    /// The identification line without its leading `/`, e.g. `ISk5\2MT382-1000`.
    pub identification: &'a str,
    /// The data lines, between the blank line and the `!`.
    body: &'a str,
}

impl<'a> Telegram<'a> {
    /// The three-character manufacturer identifier, when the identification has one.
    ///
    /// `ISk` is Iskraemeco, `KFM` Kaifa, `Ene` Sagemcom (`XMX` on older units), `KMP`
    /// Kamstrup. It is the first thing to look at when a telegram will not parse.
    #[must_use]
    pub fn manufacturer(&self) -> Option<&'a str> {
        self.identification.get(..3).filter(|s| s.is_ascii())
    }

    /// Every data line, in the order the meter sent them.
    ///
    /// A line whose OBIS code does not parse is yielded as an error rather than skipped:
    /// a meter emitting something this crate cannot read is a fact worth surfacing, and
    /// silently dropping lines is how a reading goes missing without a message.
    pub fn lines(&self) -> impl Iterator<Item = Result<Line<'a>>> + 'a {
        self.body.lines().filter(|l| !l.trim().is_empty()).map(Line::parse)
    }

    /// The first line with this OBIS code.
    ///
    /// P1 telegrams are short — a few dozen lines — so a scan is the right shape and a
    /// map would be a buffer the caller did not ask for.
    #[must_use]
    pub fn get(&self, obis: Obis) -> Option<Line<'a>> {
        self.lines().flatten().find(|l| l.obis == obis)
    }

    /// The raw body, for a caller that wants to do its own scanning.
    #[must_use]
    pub const fn body(&self) -> &'a str {
        self.body
    }
}

/// One data line: an OBIS code and its parenthesised values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line<'a> {
    /// Which object. P1 omits value group F, so it reads as 255.
    pub obis: Obis,
    /// Everything from the first `(` to the end of the line.
    raw: &'a str,
}

impl<'a> Line<'a> {
    fn parse(line: &'a str) -> Result<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        let at = line.find('(').ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
        let (name, raw) = line.split_at(at);
        let obis = Obis::parse(name).map_err(|_| Error::new(ErrorKind::InvalidValue, 0))?;
        Ok(Self { obis, raw })
    }

    /// The values, in order, without their parentheses.
    ///
    /// Most lines carry one. A gas reading carries two (a timestamp and a volume) and an
    /// event log carries a count followed by pairs.
    pub fn values(&self) -> impl Iterator<Item = &'a str> + 'a {
        let mut rest = self.raw;
        core::iter::from_fn(move || {
            let open = rest.find('(')?;
            let after = rest.get(open + 1..)?;
            let close = after.find(')')?;
            let value = after.get(..close)?;
            rest = after.get(close + 1..).unwrap_or("");
            Some(value)
        })
    }

    /// The `n`-th value.
    #[must_use]
    pub fn value(&self, n: usize) -> Option<&'a str> {
        self.values().nth(n)
    }

    /// The first value as text.
    #[must_use]
    pub fn as_str(&self) -> Option<&'a str> {
        self.values().next()
    }

    /// The first value as an unsigned integer, for the counters P1 sends as `00004`.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.as_str()?.parse().ok()
    }

    /// The first value as an exact decimal with its unit.
    ///
    /// `123456.789*kWh` becomes 123 456 789 with a scaler of 0 in `Wh`: the SI prefix
    /// goes into the scaler and the decimal point goes into the scaler, so the mantissa
    /// stays an integer and nothing is rounded. A reading that a billing system will
    /// subtract from next month's must not have been through a float on the way in.
    #[must_use]
    pub fn as_scaled(&self) -> Option<ScaledValue> {
        let text = self.as_str()?;
        let (number, unit_text) = match text.split_once('*') {
            Some((n, u)) => (n, u),
            None => (text, ""),
        };
        let (unit, prefix) = parse_unit(unit_text)?;
        let (mantissa, decimals) = parse_decimal(number)?;
        let scaler = i32::from(prefix).checked_sub(i32::from(decimals))?;
        Some(ScaledValue::new(mantissa, i8::try_from(scaler).ok()?, unit))
    }

    /// The first value as a P1 timestamp: `YYMMDDhhmmssX`, where `X` is `S` in summer
    /// time and `W` in winter.
    ///
    /// The flag is the only daylight-saving information P1 carries, and it is *not* a
    /// UTC offset: it says which of the local zone's two offsets was in force. The
    /// returned [`DateTime`] therefore has its deviation marked *not specified* and its
    /// clock status carries the daylight-saving bit, which is exactly what the meter
    /// said and no more. Inventing `+0100` or `+0200` here would be this crate guessing
    /// the meter's time zone.
    #[must_use]
    pub fn as_timestamp(&self) -> Option<DateTime> {
        parse_timestamp(self.as_str()?)
    }

    /// The first value as a hex-encoded octet string, decoded into `out`.
    ///
    /// The equipment identifier (`0-0:96.1.1`) and the message field (`0-0:96.13.0`) are
    /// sent this way: text that is really bytes. Returns how many bytes were written.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidValue`] when the value is not an even number of hex digits;
    /// [`ErrorKind::BufferTooSmall`] when `out` cannot hold the result.
    pub fn decode_hex(&self, out: &mut [u8]) -> Result<usize> {
        let text = self.as_str().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
        let bytes = text.as_bytes();
        if bytes.len() % 2 != 0 {
            return Err(Error::new(ErrorKind::InvalidValue, 0));
        }
        let n = bytes.len() / 2;
        if out.len() < n {
            return Err(Error::new(ErrorKind::BufferTooSmall { needed: n - out.len() }, 0));
        }
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_digit(pair[0]).ok_or_else(|| Error::new(ErrorKind::InvalidValue, i * 2))?;
            let lo = hex_digit(pair[1]).ok_or_else(|| Error::new(ErrorKind::InvalidValue, i * 2 + 1))?;
            *out.get_mut(i).ok_or_else(|| Error::new(ErrorKind::BufferTooSmall { needed: n }, 0))? =
                (hi << 4) | lo;
        }
        Ok(n)
    }
}

const fn hex_digit(b: u8) -> Option<u8> {
    Some(match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => return None,
    })
}

/// A decimal string as (mantissa, digits after the point).
fn parse_decimal(s: &str) -> Option<(i64, u8)> {
    let (sign, digits) = match s.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, s.strip_prefix('+').unwrap_or(s)),
    };
    let mut mantissa: i64 = 0;
    let mut decimals: u8 = 0;
    let mut seen_point = false;
    let mut any = false;
    for b in digits.bytes() {
        match b {
            b'0'..=b'9' => {
                any = true;
                mantissa = mantissa.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
                if seen_point {
                    decimals = decimals.checked_add(1)?;
                }
            }
            b'.' if !seen_point => seen_point = true,
            _ => return None,
        }
    }
    any.then_some((mantissa.checked_mul(sign)?, decimals))
}

/// A P1 unit symbol as a Blue Book unit and the power of ten its SI prefix stands for.
///
/// The Blue Book's table has no `kWh`: it has `Wh` and an exponent, which is the right
/// decomposition — it means two readings in `kWh` and `Wh` are the same type and can be
/// added.
fn parse_unit(symbol: &str) -> Option<(Unit, i8)> {
    Some(match symbol {
        "" => (Unit::NO_UNIT, 0),
        "W" => (Unit::WATT, 0),
        "kW" => (Unit::WATT, 3),
        "MW" => (Unit::WATT, 6),
        "Wh" => (Unit::WATT_HOUR, 0),
        "kWh" => (Unit::WATT_HOUR, 3),
        "MWh" => (Unit::WATT_HOUR, 6),
        "var" => (Unit::VAR, 0),
        "kvar" => (Unit::VAR, 3),
        "varh" => (Unit::VAR_HOUR, 0),
        "kvarh" => (Unit::VAR_HOUR, 3),
        "VA" => (Unit::VOLT_AMPERE, 0),
        "kVA" => (Unit::VOLT_AMPERE, 3),
        "VAh" => (Unit::VOLT_AMPERE_HOUR, 0),
        "kVAh" => (Unit::VOLT_AMPERE_HOUR, 3),
        "V" => (Unit::VOLT, 0),
        "A" => (Unit::AMPERE, 0),
        "Hz" => (Unit::HERTZ, 0),
        "s" => (Unit::SECOND, 0),
        "m3" | "m³" => (Unit::CUBIC_METRE, 0),
        "dm3" => (Unit::CUBIC_METRE, -3),
        "GJ" => (Unit::JOULE, 9),
        "MJ" => (Unit::JOULE, 6),
        "J" => (Unit::JOULE, 0),
        "kg" => (Unit::KILOGRAM, 0),
        "%" => (Unit::PERCENTAGE, 0),
        _ => return None,
    })
}

/// `YYMMDDhhmmssX` — the only date format P1 uses.
fn parse_timestamp(s: &str) -> Option<DateTime> {
    let b = s.as_bytes();
    if b.len() != 13 {
        return None;
    }
    let two = |i: usize| -> Option<u8> {
        let hi = b.get(i)?.checked_sub(b'0')?;
        let lo = b.get(i + 1)?.checked_sub(b'0')?;
        (hi <= 9 && lo <= 9).then_some(hi * 10 + lo)
    };
    let daylight_saving = match b.get(12)? {
        b'S' => true,
        b'W' => false,
        _ => return None,
    };
    // Two-digit years: the P1 port was specified in 2010 and these meters have a
    // twenty-year life, so the century is not in doubt. It is still an assumption, and
    // it is written here rather than left in an expression.
    let year = 2000u16.checked_add(u16::from(two(0)?))?;
    let mut dt = DateTime::from_civil(year, two(2)?, two(4)?, two(6)?, two(8)?, two(10)?, 0);
    // P1 carries no UTC offset — the flag says which of the local zone's two offsets
    // applied, not what it was — so the deviation is "not specified", which COSEM can
    // say and a fabricated offset cannot be taken back.
    dt.deviation = DEVIATION_NOT_SPECIFIED;
    dt.status = ClockStatus(if daylight_saving { 0x80 } else { 0x00 });
    Some(dt)
}

/// What a [`TelegramReader`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found<'a> {
    /// A complete telegram whose checksum verified.
    Telegram {
        /// The telegram.
        telegram: Telegram<'a>,
        /// How many bytes of the input it used, including anything discarded before it.
        consumed: usize,
    },
    /// No complete telegram yet.
    Incomplete {
        /// How many leading bytes are certainly not part of any telegram.
        ///
        /// The same bound [`crate::transport::hdlc::Found`] provides and for the same
        /// reason: without it a receive buffer grows without limit while a meter with a
        /// loose connector emits fragments.
        discard: usize,
    },
}

/// Finds complete, checksum-valid telegrams in a byte stream.
///
/// A P1 port emits one telegram a second, forever, and a reader that started in the
/// middle of one has to find the start of the next. So this scans for `/`, looks for the
/// `!` that closes the telegram, checks the CRC, and on failure resumes after that `/`
/// rather than giving up — the same shape as [`crate::transport::hdlc::Framer`].
///
/// ```
/// use dlms_cosem_rs::transport::p1::{Found, TelegramReader};
/// use dlms_cosem_rs::obis::Obis;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let body = "/XMX5LGBBFG10\r\n\r\n1-0:1.8.1(000123.456*kWh)\r\n!";
/// let mut stream = String::from(body);
/// stream.push_str(&format!("{:04X}\r\n", dlms_cosem_rs::transport::p1::crc16(body.as_bytes())));
///
/// let mut reader = TelegramReader::new();
/// let Found::Telegram { telegram, .. } = reader.next_telegram(stream.as_bytes())? else {
///     panic!("a complete telegram");
/// };
/// assert_eq!(telegram.manufacturer(), Some("XMX"));
/// let energy = telegram.get(Obis::new(1, 0, 1, 8, 1, 255)).unwrap();
/// let value = energy.as_scaled().unwrap();
/// assert_eq!((value.value, value.scaler), (123_456, 0));   // exactly 123456 Wh
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TelegramReader {
    discarded: usize,
    require_checksum: bool,
}

impl Default for TelegramReader {
    fn default() -> Self {
        Self::new()
    }
}

impl TelegramReader {
    /// A reader that accepts only telegrams whose checksum verifies.
    #[must_use]
    pub const fn new() -> Self {
        Self { discarded: 0, require_checksum: true }
    }

    /// A reader that also accepts a telegram carrying no checksum at all.
    ///
    /// DSMR 2.x and 3.x meters end their telegrams with a bare `!`. Accepting that is
    /// necessary to read them and is a deliberate loss of the only integrity check the
    /// format has, so it is a separate constructor rather than a fallback: a caller that
    /// reaches for it has said which meters it is talking to.
    #[must_use]
    pub const fn without_checksum() -> Self {
        Self { discarded: 0, require_checksum: false }
    }

    /// How many bytes have been thrown away. A rising count means a noisy or
    /// misconfigured port.
    #[must_use]
    pub const fn discarded(&self) -> usize {
        self.discarded
    }

    /// Find the next telegram in `buf`.
    ///
    /// # Errors
    /// Never: a malformed candidate is discarded rather than reported, which is what a
    /// reader on a continuous stream has to do. The signature keeps the `Result` so a
    /// future policy does not break callers.
    pub fn next_telegram<'b>(&mut self, buf: &'b [u8]) -> Result<Found<'b>> {
        let mut first_incomplete: Option<usize> = None;
        let mut start = 0usize;

        while start < buf.len() {
            let Some(rel) = buf.get(start..).and_then(|s| s.iter().position(|b| *b == b'/')) else {
                break;
            };
            let from = start.saturating_add(rel);
            let candidate = buf.get(from..).unwrap_or(&[]);
            match self.parse(candidate) {
                Ok(Some((telegram, used))) => {
                    self.discarded = self.discarded.saturating_add(from);
                    return Ok(Found::Telegram { telegram, consumed: from.saturating_add(used) });
                }
                // Nothing wrong with it yet — the `!` has not arrived.
                Ok(None) => {
                    if first_incomplete.is_none() {
                        first_incomplete = Some(from);
                    }
                    start = from.saturating_add(1);
                }
                // A bad checksum or a malformed telegram: this `/` did not begin one.
                Err(()) => start = from.saturating_add(1),
            }
        }

        let discard = first_incomplete.unwrap_or(buf.len());
        self.discarded = self.discarded.saturating_add(discard);
        Ok(Found::Incomplete { discard })
    }

    /// `Ok(Some(..))` a valid telegram, `Ok(None)` not finished yet, `Err(())` broken.
    #[allow(clippy::result_unit_err, reason = "a private tri-state; the public error is Found")]
    fn parse<'b>(&self, buf: &'b [u8]) -> core::result::Result<Option<(Telegram<'b>, usize)>, ()> {
        // The whole telegram must be valid UTF-8 to be text at all, and P1 is ASCII.
        let text = core::str::from_utf8(buf).map_err(|_| ())?;
        if !text.starts_with('/') {
            return Err(());
        }
        let Some(bang) = text.find('!') else { return Ok(None) };

        // The checksum covers `/` through `!` inclusive — every CR and LF included. A
        // parser that trims first gets a mismatch it cannot explain.
        let checked = text.get(..=bang).ok_or(())?;
        let after = text.get(bang + 1..).ok_or(())?;

        let used = if self.require_checksum {
            // Four hexadecimal characters, MSB first. Fewer than four have arrived means
            // the telegram is still coming, not that it is broken — the distinction is
            // the whole reason this returns three states rather than a `Result`.
            let Some(printed) = after.get(..4) else { return Ok(None) };
            if !printed.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(());
            }
            let expected = u16::from_str_radix(printed, 16).map_err(|_| ())?;
            if expected != crc16(checked.as_bytes()) {
                return Err(());
            }
            bang + 5
        } else {
            // A telegram with no checksum ends at the `!`; anything after it is the next
            // one, or a checksum this reader was told to ignore.
            let has_checksum = after.get(..4).is_some_and(|s| s.bytes().all(|b| b.is_ascii_hexdigit()));
            if has_checksum { bang + 5 } else { bang + 1 }
        };

        // The checksum is the completeness signal, not the newline after it: a telegram
        // whose CRC verifies is whole. The terminating CR LF is consumed when it is there
        // so the caller is left at the next `/`, and not waited for when it is not —
        // some meters omit it, and waiting would stall on a telegram already in hand.
        let used = match text.as_bytes().get(used..) {
            Some([b'\r', b'\n', ..]) => used.saturating_add(2),
            Some([b'\n', ..]) => used.saturating_add(1),
            _ => used,
        };

        let head = checked.get(1..bang).ok_or(())?;
        let (identification, body) = match head.find('\n') {
            Some(at) => (head.get(..at).ok_or(())?.trim_end(), head.get(at + 1..).ok_or(())?),
            None => (head.trim_end(), ""),
        };
        Ok(Some((Telegram { identification, body }, used)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    /// The DSMR 5.0.2 example telegram, transcribed from the printed standard.
    ///
    /// Its **structure** is third-party: the line set, the value formats, the two-value
    /// gas line and the event log with an OBIS code inside a value all come from the
    /// specification rather than from anyone here. Its **checksum** is not: the CRC
    /// printed alongside it (`EF2F`) cannot be reproduced from the printed characters —
    /// the document is a word-processor rendering and its line breaks are not the
    /// telegram's — so this test computes the checksum rather than quoting one.
    ///
    /// That distinction is the point. [`crc16`] itself is checked against CRC-16/ARC's
    /// published check value, which nobody here chose; the telegram exercises the
    /// grammar. Quoting `EF2F` and adjusting the text until it matched would have proved
    /// only that the text had been adjusted.
    const DSMR_5_BODY: &str = concat!(
        "/ISk5\\2MT382-1000\r\n",
        "\r\n",
        "1-3:0.2.8(50)\r\n",
        "0-0:1.0.0(101209113020W)\r\n",
        "0-0:96.1.1(4B384547303034303436333935353037)\r\n",
        "1-0:1.8.1(123456.789*kWh)\r\n",
        "1-0:1.8.2(123456.789*kWh)\r\n",
        "1-0:2.8.1(123456.789*kWh)\r\n",
        "1-0:2.8.2(123456.789*kWh)\r\n",
        "0-0:96.14.0(0002)\r\n",
        "1-0:1.7.0(01.193*kW)\r\n",
        "1-0:2.7.0(00.000*kW)\r\n",
        "0-0:96.7.21(00004)\r\n",
        "0-0:96.7.9(00002)\r\n",
        "1-0:99.97.0(2)(0-0:96.7.19)(101208152415W)(0000000240*s)(101208151004W)(0000000301*s)\r\n",
        "1-0:32.32.0(00002)\r\n",
        "1-0:32.36.0(00000)\r\n",
        "0-0:96.13.0(303132333435363738393A3B3C3D3E3F)\r\n",
        "1-0:32.7.0(220.1*V)\r\n",
        "1-0:31.7.0(001*A)\r\n",
        "1-0:21.7.0(01.111*kW)\r\n",
        "1-0:22.7.0(04.444*kW)\r\n",
        "0-1:24.1.0(003)\r\n",
        "0-1:96.1.0(3232323241424344313233343536373839)\r\n",
        "0-1:24.2.1(101209112500W)(12785.123*m3)\r\n",
        "!"
    );

    fn dsmr_5() -> String {
        format!("{DSMR_5_BODY}{:04X}\r\n", crc16(DSMR_5_BODY.as_bytes()))
    }

    /// CRC-16/ARC's published check value, computed by nobody who has heard of DSMR.
    #[test]
    fn the_checksum_matches_the_published_check_value() {
        assert_eq!(crc16(b"123456789"), 0xBB3D);
        assert_eq!(crc16(b""), 0x0000, "an empty message hashes to the initial value");
    }

    /// And it is *not* HDLC's frame check sequence. Two CRCs in one crate is exactly the
    /// situation where one gets used for the other.
    #[test]
    fn the_two_checksums_in_this_crate_are_different_functions() {
        assert_ne!(crc16(b"123456789"), crate::transport::hdlc::fcs16(b"123456789"));
        assert_eq!(crate::transport::hdlc::fcs16(b"123456789"), 0x906E);
    }

    #[test]
    fn the_specifications_example_telegram_parses() {
        let stream = dsmr_5();
        let mut reader = TelegramReader::new();
        let Found::Telegram { telegram, consumed } = reader.next_telegram(stream.as_bytes()).unwrap() else {
            panic!("the example telegram must parse")
        };
        assert_eq!(consumed, stream.len());
        assert_eq!(telegram.identification, r"ISk5\2MT382-1000");
        assert_eq!(telegram.manufacturer(), Some("ISk"));

        // Every line parses, and there are as many as were sent.
        let lines: alloc::vec::Vec<_> = telegram.lines().map(|l| l.unwrap()).collect();
        assert_eq!(lines.len(), 23);

        // A reading, exact: 123456.789 kWh is 123 456 789 Wh and not a float.
        let energy = telegram.get(Obis::new(1, 0, 1, 8, 1, 255)).unwrap();
        let v = energy.as_scaled().unwrap();
        assert_eq!(v.value, 123_456_789);
        assert_eq!(v.scaler, 0);
        assert_eq!(v.unit, Unit::WATT_HOUR);

        // A power in kW keeps its three decimals the same way.
        let power = telegram.get(Obis::new(1, 0, 1, 7, 0, 255)).unwrap();
        assert_eq!(power.as_scaled().unwrap(), ScaledValue::new(1193, 0, Unit::WATT));

        // A counter.
        assert_eq!(telegram.get(Obis::new(0, 0, 96, 7, 21, 255)).unwrap().as_u64(), Some(4));

        // A timestamp, with the daylight-saving flag and no invented offset.
        let clock = telegram.get(Obis::new(0, 0, 1, 0, 0, 255)).unwrap();
        let ts = clock.as_timestamp().unwrap();
        assert_eq!((ts.year, ts.month, ts.day_of_month), (2010, 12, 9));
        assert_eq!((ts.hour, ts.minute, ts.second), (11, 30, 20));
        assert_eq!(ts.deviation, DEVIATION_NOT_SPECIFIED, "P1 carries no UTC offset");
        assert_eq!(ts.utc_offset_minutes(), None, "and so it refuses to name one");
        assert!(!ts.status.daylight_saving_active(), "W is winter");

        // The equipment identifier is hex-encoded text.
        let id = telegram.get(Obis::new(0, 0, 96, 1, 1, 255)).unwrap();
        let mut out = [0u8; 32];
        let n = id.decode_hex(&mut out).unwrap();
        assert_eq!(&out[..n], b"K8EG004046395507");
    }

    /// The gas line carries two values, and the second is the reading.
    #[test]
    fn a_line_with_several_values_keeps_them_all() {
        let stream = dsmr_5();
        let mut reader = TelegramReader::new();
        let Found::Telegram { telegram, .. } = reader.next_telegram(stream.as_bytes()).unwrap() else {
            panic!()
        };
        let gas = telegram.get(Obis::new(0, 1, 24, 2, 1, 255)).unwrap();
        let values: alloc::vec::Vec<_> = gas.values().collect();
        assert_eq!(values, ["101209112500W", "12785.123*m3"]);
        assert_eq!(gas.as_timestamp().unwrap().year, 2010);
        // The reading is the *second* value, so a parser that only looks at the first
        // reports a gas meter that reads zero.
        assert_eq!(
            Line { obis: gas.obis, raw: "(12785.123*m3)" }.as_scaled(),
            Some(ScaledValue::new(12_785_123, -3, Unit::CUBIC_METRE))
        );
    }

    /// An event log puts an OBIS code *inside* a value. Splitting on `:` or `.` instead
    /// of on parentheses turns that line into nonsense.
    #[test]
    fn an_obis_code_inside_a_value_does_not_confuse_the_split() {
        let line = Line::parse(
            "1-0:99.97.0(2)(0-0:96.7.19)(101208152415W)(0000000240*s)(101208151004W)(0000000301*s)",
        )
        .unwrap();
        assert_eq!(line.obis, Obis::new(1, 0, 99, 97, 0, 255));
        let values: alloc::vec::Vec<_> = line.values().collect();
        assert_eq!(values.len(), 6);
        assert_eq!(values[1], "0-0:96.7.19");
        assert_eq!(line.as_u64(), Some(2), "the first value is the number of entries");
    }

    #[test]
    fn a_corrupted_telegram_is_refused_rather_than_read() {
        let mut stream = dsmr_5().into_bytes();
        // Flip a digit in a reading. The checksum is the only thing that can notice.
        let at = stream.windows(6).position(|w| w == b"123456").unwrap();
        stream[at] = b'9';
        let mut reader = TelegramReader::new();
        assert!(matches!(
            reader.next_telegram(&stream).unwrap(),
            Found::Incomplete { .. } | Found::Telegram { .. }
        ));
        // Specifically: it must not be returned as a telegram.
        assert!(
            !matches!(reader.next_telegram(&stream).unwrap(), Found::Telegram { .. }),
            "a telegram whose checksum fails must not be handed over as a reading"
        );
    }

    #[test]
    fn a_partial_telegram_is_waited_for_rather_than_discarded() {
        let stream = dsmr_5();
        let bytes = stream.as_bytes();
        let mut reader = TelegramReader::new();
        // Everything up to the last checksum digit is incomplete. From there on the
        // telegram is whole — the checksum is what says so, not the newline after it.
        let complete_at = bytes.len() - 2;
        for cut in 1..complete_at {
            assert_eq!(
                reader.next_telegram(bytes.get(..cut).unwrap()).unwrap(),
                Found::Incomplete { discard: 0 },
                "a telegram cut at {cut} must be waited for, not rejected or discarded"
            );
        }
        assert!(matches!(
            reader.next_telegram(bytes.get(..complete_at).unwrap()).unwrap(),
            Found::Telegram { .. }
        ));
        assert!(matches!(reader.next_telegram(bytes).unwrap(), Found::Telegram { .. }));
    }

    /// A reader that started mid-telegram has to find the start of the next one, and a
    /// port that has been running for hours is exactly that situation.
    #[test]
    fn a_reader_that_starts_mid_telegram_finds_the_next_one() {
        let one = dsmr_5();
        let mut stream = String::from("6.666*kW)\r\n!ABCD\r\n"); // the tail of a previous one
        stream.push_str(&one);
        let mut reader = TelegramReader::new();
        let Found::Telegram { telegram, consumed } = reader.next_telegram(stream.as_bytes()).unwrap() else {
            panic!("the whole telegram behind the fragment must be found")
        };
        assert_eq!(telegram.manufacturer(), Some("ISk"));
        assert_eq!(consumed, stream.len());
        assert!(reader.discarded() > 0);
    }

    #[test]
    fn two_telegrams_back_to_back_are_read_one_after_the_other() {
        let mut stream = dsmr_5();
        stream.push_str(&dsmr_5());
        let mut reader = TelegramReader::new();
        let Found::Telegram { consumed, .. } = reader.next_telegram(stream.as_bytes()).unwrap() else {
            panic!()
        };
        assert_eq!(consumed, stream.len() / 2, "the first telegram ends where the second begins");
        let rest = stream.as_bytes().get(consumed..).unwrap();
        assert!(matches!(reader.next_telegram(rest).unwrap(), Found::Telegram { .. }));
    }

    /// DSMR 2.x and 3.x meters send no checksum. Reading them is a deliberate choice with
    /// a name, not a fallback that quietly stops checking.
    #[test]
    fn a_telegram_with_no_checksum_needs_a_reader_that_says_so() {
        let stream = "/KMP5 KAM\r\n\r\n1-0:1.8.1(000123.456*kWh)\r\n!\r\n";
        assert!(matches!(
            TelegramReader::new().next_telegram(stream.as_bytes()).unwrap(),
            Found::Incomplete { .. }
        ));
        let Found::Telegram { telegram, .. } =
            TelegramReader::without_checksum().next_telegram(stream.as_bytes()).unwrap()
        else {
            panic!("the unchecked reader accepts it")
        };
        assert_eq!(telegram.manufacturer(), Some("KMP"));
    }

    #[test]
    fn a_decimal_keeps_every_digit_it_was_given() {
        assert_eq!(parse_decimal("123456.789"), Some((123_456_789, 3)));
        assert_eq!(parse_decimal("00.000"), Some((0, 3)));
        assert_eq!(parse_decimal("001"), Some((1, 0)));
        assert_eq!(parse_decimal("-1.5"), Some((-15, 1)));
        assert_eq!(parse_decimal("1.2.3"), None);
        assert_eq!(parse_decimal(""), None);
        assert_eq!(parse_decimal("12a"), None);
    }

    #[test]
    fn an_si_prefix_becomes_a_scaler_rather_than_a_new_unit() {
        assert_eq!(parse_unit("kWh"), Some((Unit::WATT_HOUR, 3)));
        assert_eq!(parse_unit("Wh"), Some((Unit::WATT_HOUR, 0)));
        assert_eq!(parse_unit("GJ"), Some((Unit::JOULE, 9)));
        assert_eq!(parse_unit("m3"), Some((Unit::CUBIC_METRE, 0)));
        assert_eq!(parse_unit("furlong"), None);
    }

    #[test]
    fn a_summer_timestamp_carries_the_daylight_saving_bit() {
        let summer = parse_timestamp("230704120000S").unwrap();
        assert!(summer.status.daylight_saving_active());
        assert_eq!((summer.year, summer.month, summer.day_of_month), (2023, 7, 4));
        assert!(parse_timestamp("2307041200000").is_none(), "the flag must be S or W");
        assert!(parse_timestamp("23070412000").is_none(), "and the length is fixed");
    }
}
