//! OBIS — the six-byte name every COSEM object carries.
//!
//! An OBIS code identifies *what* a value is, independently of the interface class that
//! holds it: `A-B:C.D.E*F`, where A is the medium, B the channel, C the physical
//! quantity, D the processing, E the tariff and F the billing period
//! (Blue Book Part 1, "OBIS code structure").
//!
//! ```
//! use dlms_cosem_rs::Obis;
//!
//! let total = Obis::parse("1-0:1.8.0*255").unwrap();
//! assert_eq!(total, Obis::new(1, 0, 1, 8, 0, 255));
//! assert_eq!(total.medium(), obis_medium());
//! # fn obis_medium() -> dlms_cosem_rs::obis::Medium { dlms_cosem_rs::obis::Medium::Electricity }
//! ```

use core::fmt;

use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, Writer};

/// The medium an object measures — OBIS value group A.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Medium {
    /// Abstract objects: clocks, association views, diagnostics. A = 0.
    Abstract,
    /// AC electricity. A = 1.
    Electricity,
    /// DC electricity. A = 2.
    ElectricityDc,
    /// Heat cost allocators. A = 4.
    HeatCostAllocator,
    /// Cooling (thermal energy, inlet). A = 5.
    Cooling,
    /// Heat (thermal energy). A = 6.
    Heat,
    /// Gas. A = 7.
    Gas,
    /// Cold water. A = 8.
    ColdWater,
    /// Hot water. A = 9.
    HotWater,
    /// Other media. A = 15.
    Other,
    /// A value group A this crate does not name.
    Reserved(u8),
}

impl Medium {
    /// The value group A byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Abstract => 0,
            Self::Electricity => 1,
            Self::ElectricityDc => 2,
            Self::HeatCostAllocator => 4,
            Self::Cooling => 5,
            Self::Heat => 6,
            Self::Gas => 7,
            Self::ColdWater => 8,
            Self::HotWater => 9,
            Self::Other => 15,
            Self::Reserved(v) => v,
        }
    }

    /// Classify a value group A byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Abstract,
            1 => Self::Electricity,
            2 => Self::ElectricityDc,
            4 => Self::HeatCostAllocator,
            5 => Self::Cooling,
            6 => Self::Heat,
            7 => Self::Gas,
            8 => Self::ColdWater,
            9 => Self::HotWater,
            15 => Self::Other,
            other => Self::Reserved(other),
        }
    }
}

/// A COSEM logical name: `A-B:C.D.E*F`, six bytes on the wire.
///
/// `Obis` is `const`-constructible so well-known codes are compile-time constants, and
/// it is a plain `[u8; 6]` so comparing, sorting and hashing are what they look like.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Obis(pub [u8; 6]);

impl Obis {
    /// From the six value groups.
    #[must_use]
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }

    /// From the six bytes as they appear on the wire.
    #[must_use]
    pub const fn from_bytes(b: [u8; 6]) -> Self {
        Self(b)
    }

    /// The six bytes as they appear on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Value group A — the medium.
    #[must_use]
    pub const fn a(&self) -> u8 {
        self.0[0]
    }

    /// Value group B — the channel.
    #[must_use]
    pub const fn b(&self) -> u8 {
        self.0[1]
    }

    /// Value group C — the physical quantity.
    #[must_use]
    pub const fn c(&self) -> u8 {
        self.0[2]
    }

    /// Value group D — the processing.
    #[must_use]
    pub const fn d(&self) -> u8 {
        self.0[3]
    }

    /// Value group E — the tariff or further classification.
    #[must_use]
    pub const fn e(&self) -> u8 {
        self.0[4]
    }

    /// Value group F — the billing period.
    #[must_use]
    pub const fn f(&self) -> u8 {
        self.0[5]
    }

    /// The medium, classified.
    #[must_use]
    pub const fn medium(&self) -> Medium {
        Medium::from_u8(self.0[0])
    }

    /// True for a code in a manufacturer-specific range.
    ///
    /// Blue Book Part 1 reserves `C` in 128..=199 and `D`/`E` in 128..=254 for
    /// manufacturers; a client should not attach standard semantics to one.
    #[must_use]
    pub const fn is_manufacturer_specific(&self) -> bool {
        (self.0[2] >= 128 && self.0[2] <= 199)
            || (self.0[3] >= 128 && self.0[3] <= 254)
            || (self.0[4] >= 128 && self.0[4] <= 254)
    }

    /// Parse the textual notation.
    ///
    /// Accepts `A-B:C.D.E*F`, `A-B:C.D.E` (F defaults to 255) and the reduced `C.D.E`
    /// used by IEC 62056-21 and the P1 port (A defaults to 1, B and E to 0, F to 255).
    /// Separators are accepted liberally — `.`, `-`, `:` and `*` all delimit — because
    /// meter documentation is not consistent about them, but the *number* of groups is
    /// not: three or six, never four or five.
    pub fn parse(s: &str) -> core::result::Result<Self, ObisParseError> {
        let mut groups = [0u16; 6];
        let mut n = 0usize;
        let mut have_digit = false;
        let mut cur: u16 = 0;
        for ch in s.bytes() {
            match ch {
                b'0'..=b'9' => {
                    if !have_digit {
                        cur = 0;
                    }
                    have_digit = true;
                    cur = cur
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(u16::from(ch - b'0')))
                        .ok_or(ObisParseError)?;
                    if cur > 255 {
                        return Err(ObisParseError);
                    }
                }
                b'-' | b':' | b'.' | b'*' | b'&' => {
                    if !have_digit || n >= 6 {
                        return Err(ObisParseError);
                    }
                    groups[n] = cur;
                    n += 1;
                    have_digit = false;
                }
                _ => return Err(ObisParseError),
            }
        }
        if !have_digit || n >= 6 {
            return Err(ObisParseError);
        }
        groups[n] = cur;
        n += 1;

        // Indexing a fixed array with a literal, written so the bound is discharged at
        // compile time rather than left as a runtime check.
        let g = |i: usize| groups.get(i).copied().unwrap_or(0) as u8;
        match n {
            3 => Ok(Self::new(1, 0, g(0), g(1), g(2), 255)),
            5 => Ok(Self::new(g(0), g(1), g(2), g(3), g(4), 255)),
            6 => Ok(Self::new(g(0), g(1), g(2), g(3), g(4), g(5))),
            _ => Err(ObisParseError),
        }
    }
}

/// The textual notation could not be read as an OBIS code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObisParseError;

impl fmt::Display for ObisParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an OBIS code")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ObisParseError {}

impl core::str::FromStr for Obis {
    type Err = ObisParseError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Obis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a}-{b}:{c}.{d}.{e}*{g}")
    }
}

impl fmt::Debug for Obis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Obis({self})")
    }
}

impl From<[u8; 6]> for Obis {
    fn from(v: [u8; 6]) -> Self {
        Self(v)
    }
}

impl From<Obis> for [u8; 6] {
    fn from(v: Obis) -> Self {
        v.0
    }
}

impl Encode for Obis {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_bytes(&self.0)
    }

    fn encoded_len(&self) -> usize {
        6
    }
}

impl<'a> Decode<'a> for Obis {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self(r.array::<6>()?))
    }
}

impl Obis {
    /// Read an OBIS code from an octet string that must be exactly six bytes.
    pub fn from_octet_string(bytes: &[u8], offset: usize) -> Result<Self> {
        let arr: [u8; 6] = bytes.try_into().map_err(|_| Error::new(ErrorKind::InvalidLength, offset))?;
        Ok(Self(arr))
    }
}

/// Well-known logical names.
///
/// Only codes whose meaning is fixed by the Blue Book and stable across profiles are
/// listed. A meter's own object list is the authority for everything else.
#[cfg(feature = "obis-names")]
pub mod names {
    use super::Obis;

    /// The clock object, `0-0:1.0.0*255`.
    pub const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255);
    /// COSEM logical device name, `0-0:42.0.0*255`.
    pub const LOGICAL_DEVICE_NAME: Obis = Obis::new(0, 0, 42, 0, 0, 255);
    /// The current association object, `0-0:40.0.0*255`.
    pub const CURRENT_ASSOCIATION: Obis = Obis::new(0, 0, 40, 0, 0, 255);
    /// Security setup for the management association, `0-0:43.0.0*255`.
    pub const SECURITY_SETUP: Obis = Obis::new(0, 0, 43, 0, 0, 255);
    /// SAP assignment, `0-0:41.0.0*255`.
    pub const SAP_ASSIGNMENT: Obis = Obis::new(0, 0, 41, 0, 0, 255);
    /// Device ID 1, the manufacturer's serial number, `0-0:96.1.0*255`.
    pub const DEVICE_ID_1: Obis = Obis::new(0, 0, 96, 1, 0, 255);
    /// The error register, `0-0:97.97.0*255`.
    pub const ERROR_REGISTER: Obis = Obis::new(0, 0, 97, 97, 0, 255);
    /// The standard event log, `0-0:99.98.0*255`.
    pub const EVENT_LOG: Obis = Obis::new(0, 0, 99, 98, 0, 255);
    /// IEC HDLC setup for port 0, `0-0:22.0.0*255`.
    pub const HDLC_SETUP: Obis = Obis::new(0, 0, 22, 0, 0, 255);
    /// Disconnect control, `0-0:96.3.10*255`.
    pub const DISCONNECT_CONTROL: Obis = Obis::new(0, 0, 96, 3, 10, 255);
    /// Push setup, `0-0:25.9.0*255`.
    pub const PUSH_SETUP: Obis = Obis::new(0, 0, 25, 9, 0, 255);
    /// Image transfer, `0-0:44.0.0*255`.
    pub const IMAGE_TRANSFER: Obis = Obis::new(0, 0, 44, 0, 0, 255);

    /// Active energy imported, total: `1-0:1.8.0*255`.
    pub const ACTIVE_ENERGY_IMPORT_TOTAL: Obis = Obis::new(1, 0, 1, 8, 0, 255);
    /// Active energy imported, rate 1: `1-0:1.8.1*255`.
    pub const ACTIVE_ENERGY_IMPORT_T1: Obis = Obis::new(1, 0, 1, 8, 1, 255);
    /// Active energy imported, rate 2: `1-0:1.8.2*255`.
    pub const ACTIVE_ENERGY_IMPORT_T2: Obis = Obis::new(1, 0, 1, 8, 2, 255);
    /// Active energy exported, total: `1-0:2.8.0*255`.
    pub const ACTIVE_ENERGY_EXPORT_TOTAL: Obis = Obis::new(1, 0, 2, 8, 0, 255);
    /// Reactive energy imported (Q1+Q2), total: `1-0:3.8.0*255`.
    pub const REACTIVE_ENERGY_IMPORT_TOTAL: Obis = Obis::new(1, 0, 3, 8, 0, 255);
    /// Reactive energy exported (Q3+Q4), total: `1-0:4.8.0*255`.
    pub const REACTIVE_ENERGY_EXPORT_TOTAL: Obis = Obis::new(1, 0, 4, 8, 0, 255);
    /// Instantaneous active power imported: `1-0:1.7.0*255`.
    pub const ACTIVE_POWER_IMPORT: Obis = Obis::new(1, 0, 1, 7, 0, 255);
    /// Instantaneous active power exported: `1-0:2.7.0*255`.
    pub const ACTIVE_POWER_EXPORT: Obis = Obis::new(1, 0, 2, 7, 0, 255);
    /// Instantaneous voltage, phase L1: `1-0:32.7.0*255`.
    pub const VOLTAGE_L1: Obis = Obis::new(1, 0, 32, 7, 0, 255);
    /// Instantaneous voltage, phase L2: `1-0:52.7.0*255`.
    pub const VOLTAGE_L2: Obis = Obis::new(1, 0, 52, 7, 0, 255);
    /// Instantaneous voltage, phase L3: `1-0:72.7.0*255`.
    pub const VOLTAGE_L3: Obis = Obis::new(1, 0, 72, 7, 0, 255);
    /// Instantaneous current, phase L1: `1-0:31.7.0*255`.
    pub const CURRENT_L1: Obis = Obis::new(1, 0, 31, 7, 0, 255);
    /// Instantaneous current, phase L2: `1-0:51.7.0*255`.
    pub const CURRENT_L2: Obis = Obis::new(1, 0, 51, 7, 0, 255);
    /// Instantaneous current, phase L3: `1-0:71.7.0*255`.
    pub const CURRENT_L3: Obis = Obis::new(1, 0, 71, 7, 0, 255);
    /// The load profile with a one-minute to one-hour capture period: `1-0:99.1.0*255`.
    pub const LOAD_PROFILE_1: Obis = Obis::new(1, 0, 99, 1, 0, 255);
    /// The daily profile: `1-0:99.2.0*255`.
    pub const LOAD_PROFILE_2: Obis = Obis::new(1, 0, 99, 2, 0, 255);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn textual_notation_round_trips() {
        #[cfg(feature = "std")]
        {
            use std::string::ToString;
            let o = Obis::new(1, 0, 1, 8, 0, 255);
            assert_eq!(o.to_string(), "1-0:1.8.0*255");
            assert_eq!(Obis::parse(&o.to_string()).unwrap(), o);
        }
    }

    #[test]
    fn the_three_accepted_shapes() {
        assert_eq!(Obis::parse("1-0:1.8.0*255").unwrap(), Obis::new(1, 0, 1, 8, 0, 255));
        assert_eq!(Obis::parse("1-0:1.8.0").unwrap(), Obis::new(1, 0, 1, 8, 0, 255));
        assert_eq!(Obis::parse("1.8.0").unwrap(), Obis::new(1, 0, 1, 8, 0, 255));
    }

    #[test]
    fn a_group_count_that_is_not_three_five_or_six_is_refused() {
        assert!(Obis::parse("1.8").is_err());
        assert!(Obis::parse("1-0:1.8").is_err());
        assert!(Obis::parse("1-0:1.8.0*255*1").is_err());
    }

    #[test]
    fn a_group_above_255_is_refused_rather_than_truncated() {
        assert!(Obis::parse("1-0:1.8.256").is_err());
        assert!(Obis::parse("1-0:1.8.99999").is_err());
    }

    #[test]
    fn junk_is_refused() {
        for s in ["", "-", "1-0:1.8.x", "1--0:1.8.0", "1-0:1.8.", "abc"] {
            assert!(Obis::parse(s).is_err(), "{s:?} should not parse");
        }
    }

    #[test]
    fn wire_form_is_six_bytes_in_order() {
        let o = Obis::new(1, 0, 1, 8, 0, 255);
        let mut buf = [0u8; 6];
        let mut w = SliceWriter::new(&mut buf);
        o.encode(&mut w).unwrap();
        assert_eq!(buf, [1, 0, 1, 8, 0, 255]);
        assert_eq!(Obis::from_bytes(buf), o);
    }

    #[test]
    fn manufacturer_ranges_are_recognised() {
        assert!(Obis::new(1, 0, 128, 8, 0, 255).is_manufacturer_specific());
        assert!(!Obis::new(1, 0, 1, 8, 0, 255).is_manufacturer_specific());
    }

    #[test]
    fn media_classify() {
        assert_eq!(Obis::new(0, 0, 1, 0, 0, 255).medium(), Medium::Abstract);
        assert_eq!(Obis::new(7, 0, 3, 0, 0, 255).medium(), Medium::Gas);
        assert_eq!(Obis::new(3, 0, 3, 0, 0, 255).medium(), Medium::Reserved(3));
    }
}
