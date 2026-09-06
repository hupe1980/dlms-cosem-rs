//! Units and scaled values.
//!
//! A register carries an integer and a `scaler_unit` structure: a power-of-ten exponent
//! and a unit code. [`ScaledValue`] keeps the pair rather than multiplying it out,
//! because a meter reading is an exact decimal and a float is not — 12 345 with a
//! scaler of −3 is exactly 12.345 kWh, and `12.345_f64` is not.

use core::fmt;

/// A unit code from the Blue Book unit table.
///
/// A newtype rather than an enum, so a unit this crate does not name still round-trips
/// and still prints its numeric code instead of being lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unit(pub u8);

macro_rules! units {
    ($($code:literal $konst:ident $symbol:literal $name:literal;)*) => {
        impl Unit {
            $(
                #[doc = concat!($name, " (code ", stringify!($code), ").")]
                pub const $konst: Self = Self($code);
            )*

            /// The symbol, for a unit in the table.
            #[must_use]
            pub const fn symbol(self) -> Option<&'static str> {
                match self.0 {
                    $($code => Some($symbol),)*
                    _ => None,
                }
            }

            /// The name, for a unit in the table.
            #[must_use]
            pub const fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($code => Some($name),)*
                    _ => None,
                }
            }
        }
    };
}

units! {
    1   YEAR                        "a"      "year";
    2   MONTH                       "mo"     "month";
    3   WEEK                        "wk"     "week";
    4   DAY                         "d"      "day";
    5   HOUR                        "h"      "hour";
    6   MINUTE                      "min"    "minute";
    7   SECOND                      "s"      "second";
    8   DEGREE                      "°"      "phase angle";
    9   DEGREE_CELSIUS              "°C"     "temperature";
    10  CURRENCY                    "¤"      "local currency";
    11  METRE                       "m"      "length";
    12  METRE_PER_SECOND            "m/s"    "speed";
    13  CUBIC_METRE                 "m³"     "volume";
    14  CUBIC_METRE_CORRECTED       "m³"     "corrected volume";
    15  CUBIC_METRE_PER_HOUR        "m³/h"   "volume flux";
    16  CUBIC_METRE_PER_HOUR_CORR   "m³/h"   "corrected volume flux";
    17  CUBIC_METRE_PER_DAY         "m³/d"   "volume flux per day";
    18  CUBIC_METRE_PER_DAY_CORR    "m³/d"   "corrected volume flux per day";
    19  LITRE                       "l"      "volume";
    20  KILOGRAM_PER_SECOND         "kg/s"   "mass flux";
    21  NEWTON                      "N"      "force";
    22  NEWTON_METRE                "Nm"     "energy";
    23  PASCAL                      "Pa"     "pressure";
    24  BAR                         "bar"    "pressure";
    25  JOULE                       "J"      "energy";
    26  JOULE_PER_HOUR              "J/h"    "thermal power";
    27  WATT                        "W"      "active power";
    28  VOLT_AMPERE                 "VA"     "apparent power";
    29  VAR                         "var"    "reactive power";
    30  WATT_HOUR                   "Wh"     "active energy";
    31  VOLT_AMPERE_HOUR            "VAh"    "apparent energy";
    32  VAR_HOUR                    "varh"   "reactive energy";
    33  AMPERE                      "A"      "current";
    34  COULOMB                     "C"      "electrical charge";
    35  VOLT                        "V"      "voltage";
    36  VOLT_PER_METRE              "V/m"    "electric field strength";
    37  FARAD                       "F"      "capacitance";
    38  OHM                         "Ω"      "resistance";
    39  OHM_METRE                   "Ωm²/m"  "resistivity";
    40  WEBER                       "Wb"     "magnetic flux";
    41  TESLA                       "T"      "magnetic flux density";
    42  AMPERE_PER_METRE            "A/m"    "magnetic field strength";
    43  HENRY                       "H"      "inductance";
    44  HERTZ                       "Hz"     "frequency";
    45  ACTIVE_ENERGY_METER_CONST   "1/Wh"   "active energy meter constant";
    46  REACTIVE_ENERGY_METER_CONST "1/varh" "reactive energy meter constant";
    47  APPARENT_ENERGY_METER_CONST "1/VAh"  "apparent energy meter constant";
    48  VOLT_SQUARED_HOUR           "V²h"    "volt-squared hours";
    49  AMPERE_SQUARED_HOUR         "A²h"    "ampere-squared hours";
    50  KILOGRAM                    "kg"     "mass";
    51  SIEMENS                     "S"      "conductance";
    52  KELVIN                      "K"      "temperature";
    53  VOLT_SQUARED_HOUR_CONST     "1/(V²h)" "volt-squared hour meter constant";
    54  AMPERE_SQUARED_HOUR_CONST   "1/(A²h)" "ampere-squared hour meter constant";
    55  VOLUME_METER_CONSTANT       "1/m³"   "volume meter constant";
    56  PERCENTAGE                  "%"      "percentage";
    57  AMPERE_HOUR                 "Ah"     "ampere-hours";
    60  ENERGY_PER_VOLUME           "Wh/m³"  "energy per volume";
    61  CALORIFIC_VALUE             "J/m³"   "calorific value";
    62  MOLE_PERCENT                "mol %"  "molar fraction of gas";
    63  MASS_DENSITY                "g/m³"   "mass density";
    64  PASCAL_SECOND               "Pa s"   "dynamic viscosity";
    65  SPECIFIC_ENERGY             "J/kg"   "specific energy";
    70  DBM                         "dBm"    "signal strength";
    71  DB_MICROVOLT                "dBµV"   "signal strength";
    72  DB                          "dB"     "logarithmic unit";
    254 OTHER_UNIT                  "?"      "other unit";
    255 NO_UNIT                     ""       "count, no unit";
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.symbol() {
            Some(s) => f.write_str(s),
            None => write!(f, "unit({})", self.0),
        }
    }
}

/// An integer with a power-of-ten scaler and a unit.
///
/// The pair is kept exact. [`ScaledValue::to_f64`] exists for display and refuses
/// nothing, but nothing inside this crate uses it: a value that must survive a
/// round trip stays an integer and an exponent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaledValue {
    /// The raw integer as the meter reported it.
    pub value: i64,
    /// The power of ten to multiply by.
    pub scaler: i8,
    /// The unit.
    pub unit: Unit,
}

impl ScaledValue {
    /// A value with a scaler and unit.
    #[must_use]
    pub const fn new(value: i64, scaler: i8, unit: Unit) -> Self {
        Self { value, scaler, unit }
    }

    /// The value as an `f64`. For display, not for arithmetic that must be exact.
    #[must_use]
    pub fn to_f64(self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let v = self.value as f64;
        v * libm_pow10(self.scaler)
    }

    /// The value rescaled to a different exponent, exactly, or `None` when that would
    /// lose digits or overflow.
    ///
    /// This is how two readings with different scalers are added without going through
    /// a float: bring both to the finer scaler, then add.
    #[must_use]
    pub fn rescale(self, scaler: i8) -> Option<Self> {
        let diff = i32::from(self.scaler) - i32::from(scaler);
        let value = match diff.cmp(&0) {
            core::cmp::Ordering::Equal => self.value,
            core::cmp::Ordering::Greater => {
                let mut v = self.value;
                for _ in 0..diff {
                    v = v.checked_mul(10)?;
                }
                v
            }
            core::cmp::Ordering::Less => {
                let mut v = self.value;
                for _ in 0..(-diff) {
                    if v % 10 != 0 {
                        return None;
                    }
                    v /= 10;
                }
                v
            }
        };
        Some(Self { value, scaler, unit: self.unit })
    }
}

fn libm_pow10(e: i8) -> f64 {
    let mut v = 1.0f64;
    if e >= 0 {
        for _ in 0..e {
            v *= 10.0;
        }
    } else {
        for _ in 0..(-i16::from(e)) {
            v /= 10.0;
        }
    }
    v
}

impl fmt::Display for ScaledValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print exactly: shift the decimal point rather than going through a float.
        let neg = self.value < 0;
        let mag = self.value.unsigned_abs();
        if neg {
            f.write_str("-")?;
        }
        match self.scaler {
            0 => write!(f, "{mag}")?,
            s if s > 0 => {
                write!(f, "{mag}")?;
                for _ in 0..s {
                    f.write_str("0")?;
                }
            }
            s => {
                let places = (-i16::from(s)) as u32;
                // A power of ten is never zero, and saying so in the type removes the
                // division-by-zero check the compiler would otherwise have to emit —
                // which is a panic path in a build that is supposed to have none.
                // A scaler past what `u64` can express leaves the divisor larger than
                // any magnitude, so the integer part is zero and the whole value is
                // printed as the fraction, which is what it is.
                let divisor = 10u64
                    .checked_pow(places)
                    .and_then(core::num::NonZeroU64::new)
                    .unwrap_or(core::num::NonZeroU64::MAX);
                let int = mag / divisor;
                let frac = mag % divisor;
                write!(f, "{int}.{frac:0width$}", width = places as usize)?;
            }
        }
        if let Some(sym) = self.unit.symbol() {
            if !sym.is_empty() {
                write!(f, " {sym}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_name_themselves() {
        assert_eq!(Unit::WATT_HOUR.symbol(), Some("Wh"));
        assert_eq!(Unit::WATT_HOUR.name(), Some("active energy"));
        assert_eq!(Unit(200).symbol(), None, "an unlisted unit is not invented");
        assert_eq!(Unit(200).0, 200, "and still round-trips");
    }

    #[test]
    fn a_reading_prints_exactly() {
        #[cfg(feature = "std")]
        {
            use std::string::ToString;
            assert_eq!(ScaledValue::new(12_345, -3, Unit::WATT_HOUR).to_string(), "12.345 Wh");
            assert_eq!(ScaledValue::new(-5, 0, Unit::WATT).to_string(), "-5 W");
            assert_eq!(ScaledValue::new(7, 3, Unit::WATT).to_string(), "7000 W");
            assert_eq!(ScaledValue::new(1, -2, Unit::NO_UNIT).to_string(), "0.01");
        }
    }

    #[test]
    fn rescaling_is_exact_or_refused() {
        let v = ScaledValue::new(12_345, -3, Unit::WATT_HOUR);
        assert_eq!(v.rescale(-4).unwrap().value, 123_450);
        assert_eq!(v.rescale(-2), None, "would drop the last digit");
        assert_eq!(ScaledValue::new(12_300, -3, Unit::WATT_HOUR).rescale(-1).unwrap().value, 123);
    }

    #[test]
    fn to_f64_is_display_only() {
        let v = ScaledValue::new(12_345, -3, Unit::WATT_HOUR);
        assert!((v.to_f64() - 12.345).abs() < 1e-9);
    }
}
