//! COSEM date and time.
//!
//! These are not calendar types. Every field may be a wildcard — a schedule says "the
//! last day of any month at 06:00" by putting `0xFF` in the year and `0xFE` in the day —
//! and the deviation from UTC may be absent. Converting one to a civil timestamp is
//! therefore fallible, and this crate refuses to guess: the conversions in this module
//! return `Option`, and the wildcard is preserved on the way back out.

use core::fmt;

/// Clock status flags carried by a date-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockStatus(pub u8);

impl ClockStatus {
    /// The value meaning "no status information".
    pub const NOT_SPECIFIED: Self = Self(0xFF);

    /// The clock is not synchronised and its value must not be trusted.
    #[must_use]
    pub const fn invalid(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// The clock may have drifted beyond the accepted tolerance.
    #[must_use]
    pub const fn doubtful(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// The value comes from a different clock base than the meter's own.
    #[must_use]
    pub const fn different_clock_base(self) -> bool {
        self.0 & 0x04 != 0
    }

    /// The status bits themselves are unreliable.
    #[must_use]
    pub const fn invalid_clock_status(self) -> bool {
        self.0 & 0x08 != 0
    }

    /// Daylight saving is in effect, so the deviation includes the summer-time offset.
    #[must_use]
    pub const fn daylight_saving_active(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// True when no status was given.
    #[must_use]
    pub const fn is_not_specified(self) -> bool {
        self.0 == 0xFF
    }
}

/// The twelve-byte COSEM date-time.
///
/// Fields are stored exactly as they arrived, wildcards included, so an encode after a
/// decode is byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    /// Year, or `0xFFFF` for "not specified".
    pub year: u16,
    /// Month 1–12; `0xFD` daylight-saving end, `0xFE` daylight-saving begin, `0xFF` any.
    pub month: u8,
    /// Day 1–31; `0xFD` second-last day of month, `0xFE` last day of month, `0xFF` any.
    pub day_of_month: u8,
    /// Day of week 1 (Monday) – 7 (Sunday), or `0xFF` for any.
    pub day_of_week: u8,
    /// Hour 0–23, or `0xFF`.
    pub hour: u8,
    /// Minute 0–59, or `0xFF`.
    pub minute: u8,
    /// Second 0–59, or `0xFF`.
    pub second: u8,
    /// Hundredths of a second 0–99, or `0xFF`.
    pub hundredths: u8,
    /// Minutes *behind* UTC — local time = UTC − deviation — or `0x8000` when absent.
    pub deviation: i16,
    /// Clock status.
    pub status: ClockStatus,
}

impl DateTime {
    /// The value in which every field is a wildcard.
    pub const WILDCARD: Self = Self {
        year: 0xFFFF,
        month: 0xFF,
        day_of_month: 0xFF,
        day_of_week: 0xFF,
        hour: 0xFF,
        minute: 0xFF,
        second: 0xFF,
        hundredths: 0xFF,
        deviation: DEVIATION_NOT_SPECIFIED,
        status: ClockStatus::NOT_SPECIFIED,
    };

    /// Decode from the twelve wire bytes. Cannot fail: every bit pattern is a value.
    #[must_use]
    pub const fn from_bytes(b: [u8; 12]) -> Self {
        Self {
            year: u16::from_be_bytes([b[0], b[1]]),
            month: b[2],
            day_of_month: b[3],
            day_of_week: b[4],
            hour: b[5],
            minute: b[6],
            second: b[7],
            hundredths: b[8],
            deviation: i16::from_be_bytes([b[9], b[10]]),
            status: ClockStatus(b[11]),
        }
    }

    /// Encode to the twelve wire bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 12] {
        let y = self.year.to_be_bytes();
        let d = self.deviation.to_be_bytes();
        [
            y[0],
            y[1],
            self.month,
            self.day_of_month,
            self.day_of_week,
            self.hour,
            self.minute,
            self.second,
            self.hundredths,
            d[0],
            d[1],
            self.status.0,
        ]
    }

    /// True when any field is a wildcard, which is what makes this a pattern rather
    /// than a timestamp.
    #[must_use]
    pub const fn has_wildcard(&self) -> bool {
        self.year == 0xFFFF
            || self.month >= 0xFD
            || self.day_of_month >= 0xFD
            || self.hour == 0xFF
            || self.minute == 0xFF
            || self.second == 0xFF
    }

    /// The offset from UTC in minutes, when one was given.
    #[must_use]
    pub const fn utc_offset_minutes(&self) -> Option<i16> {
        if self.deviation == DEVIATION_NOT_SPECIFIED { None } else { Some(-self.deviation) }
    }

    /// Seconds since the Unix epoch, when this is a complete civil timestamp with a
    /// known deviation.
    ///
    /// `None` for anything with a wildcard or without a deviation — a value that is
    /// missing its offset is not a point in time, and silently treating it as UTC is
    /// the bug this signature exists to prevent.
    #[must_use]
    pub fn to_unix_seconds(&self) -> Option<i64> {
        if self.has_wildcard() {
            return None;
        }
        let offset = self.utc_offset_minutes()?;
        if self.month == 0 || self.month > 12 || self.day_of_month == 0 {
            return None;
        }
        // "31 February" is not a date. Accepting it and letting the day-count arithmetic
        // roll it into March is how a meter reading lands on the wrong day rather than
        // being reported as the malformed value it is.
        if self.day_of_month > days_in_month(self.year, self.month) {
            return None;
        }
        // A leap second is not representable as a Unix timestamp: 23:59:60 and the
        // following 00:00:00 would have to be the same number. Refusing is the only
        // answer that does not silently claim a value is something it is not.
        if self.hour > 23 || self.minute > 59 || self.second > 59 {
            return None;
        }
        let days = days_from_civil(i32::from(self.year), self.month, self.day_of_month);
        let secs = i64::from(days) * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second);
        Some(secs - i64::from(offset) * 60)
    }

    /// Build a complete timestamp from civil fields and an offset in minutes.
    #[must_use]
    pub fn from_civil(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        utc_offset_minutes: i16,
    ) -> Self {
        Self {
            year,
            month,
            day_of_month: day,
            day_of_week: day_of_week(i32::from(year), month, day),
            hour,
            minute,
            second,
            hundredths: 0xFF,
            deviation: -utc_offset_minutes,
            status: ClockStatus(0),
        }
    }
}

/// The value of the deviation field that means "not specified".
pub const DEVIATION_NOT_SPECIFIED: i16 = -0x8000;

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = wildcard_or;
        if self.year == 0xFFFF {
            f.write_str("****")?;
        } else {
            write!(f, "{:04}", self.year)?;
        }
        f.write_str("-")?;
        n(self.month, 2, f)?;
        f.write_str("-")?;
        n(self.day_of_month, 2, f)?;
        f.write_str("T")?;
        n(self.hour, 2, f)?;
        f.write_str(":")?;
        n(self.minute, 2, f)?;
        f.write_str(":")?;
        n(self.second, 2, f)?;
        match self.utc_offset_minutes() {
            None => Ok(()),
            Some(0) => f.write_str("Z"),
            Some(m) => {
                let sign = if m < 0 { '-' } else { '+' };
                let a = m.unsigned_abs();
                write!(f, "{sign}{:02}:{:02}", a / 60, a % 60)
            }
        }
    }
}

/// The five-byte COSEM date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    /// Year, or `0xFFFF`.
    pub year: u16,
    /// Month, with the same wildcards as [`DateTime::month`].
    pub month: u8,
    /// Day of month, with the same wildcards as [`DateTime::day_of_month`].
    pub day_of_month: u8,
    /// Day of week, or `0xFF`.
    pub day_of_week: u8,
}

impl Date {
    /// Decode from the five wire bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 5]) -> Self {
        Self { year: u16::from_be_bytes([b[0], b[1]]), month: b[2], day_of_month: b[3], day_of_week: b[4] }
    }

    /// Encode to the five wire bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 5] {
        let y = self.year.to_be_bytes();
        [y[0], y[1], self.month, self.day_of_month, self.day_of_week]
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.year == 0xFFFF {
            f.write_str("****")?;
        } else {
            write!(f, "{:04}", self.year)?;
        }
        f.write_str("-")?;
        wildcard_or(self.month, 2, f)?;
        f.write_str("-")?;
        wildcard_or(self.day_of_month, 2, f)
    }
}

/// The four-byte COSEM time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    /// Hour, or `0xFF`.
    pub hour: u8,
    /// Minute, or `0xFF`.
    pub minute: u8,
    /// Second, or `0xFF`.
    pub second: u8,
    /// Hundredths, or `0xFF`.
    pub hundredths: u8,
}

impl Time {
    /// Decode from the four wire bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 4]) -> Self {
        Self { hour: b[0], minute: b[1], second: b[2], hundredths: b[3] }
    }

    /// Encode to the four wire bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 4] {
        [self.hour, self.minute, self.second, self.hundredths]
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        wildcard_or(self.hour, 2, f)?;
        f.write_str(":")?;
        wildcard_or(self.minute, 2, f)?;
        f.write_str(":")?;
        wildcard_or(self.second, 2, f)
    }
}

/// Print a field, or as many `*` as it is wide when it is a wildcard.
///
/// Every field that can be `0xFF` prints the same way, in every one of the three types.
/// A `Time` that printed `255:255:255` while a `DateTime` printed `**:**:**` for the
/// same bytes would be a display that has to be read twice.
fn wildcard_or(v: u8, width: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if v >= 0xFD {
        for _ in 0..width {
            f.write_str("*")?;
        }
        Ok(())
    } else {
        write!(f, "{v:0width$}")
    }
}

/// How many days the month has, leap years included.
const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let y = year as u32;
            if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// Days from 1970-01-01 to a civil date, by Howard Hinnant's algorithm.
const fn days_from_civil(y: i32, m: u8, d: u8) -> i32 {
    let m = m as i32;
    let d = d as i32;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// ISO day of week, 1 = Monday. `0xFF` when the date is not a real one.
const fn day_of_week(y: i32, m: u8, d: u8) -> u8 {
    // 1970-01-01 was a Thursday, ISO day 4.
    ((days_from_civil(y, m, d) + 3).rem_euclid(7) + 1) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_form_round_trips_including_wildcards() {
        let raw = [0x07, 0xE9, 0x0C, 0x1F, 0xFF, 0x17, 0x3B, 0x3B, 0xFF, 0x00, 0x3C, 0x00];
        let dt = DateTime::from_bytes(raw);
        assert_eq!(dt.year, 2025);
        assert_eq!(dt.month, 12);
        assert_eq!(dt.day_of_month, 31);
        assert_eq!(dt.hour, 23);
        assert_eq!(dt.deviation, 60);
        assert_eq!(dt.to_bytes(), raw);
    }

    #[test]
    fn deviation_is_minutes_behind_utc() {
        // Central European Time in winter is UTC+1, so the deviation is -60.
        let dt = DateTime::from_civil(2025, 1, 15, 12, 0, 0, 60);
        assert_eq!(dt.deviation, -60);
        assert_eq!(dt.utc_offset_minutes(), Some(60));
        // 2025-01-15T12:00:00+01:00 is 11:00 UTC.
        assert_eq!(dt.to_unix_seconds(), Some(1_736_938_800));
    }

    #[test]
    fn an_absent_deviation_is_not_utc() {
        let mut dt = DateTime::from_civil(2025, 1, 15, 12, 0, 0, 0);
        dt.deviation = DEVIATION_NOT_SPECIFIED;
        assert_eq!(dt.utc_offset_minutes(), None);
        assert_eq!(dt.to_unix_seconds(), None, "must refuse rather than assume UTC");
    }

    #[test]
    fn a_wildcard_is_not_a_timestamp() {
        assert!(DateTime::WILDCARD.has_wildcard());
        assert_eq!(DateTime::WILDCARD.to_unix_seconds(), None);
        let mut last_day = DateTime::from_civil(2025, 6, 1, 6, 0, 0, 120);
        last_day.day_of_month = 0xFE; // last day of month
        assert!(last_day.has_wildcard());
        assert_eq!(last_day.to_unix_seconds(), None);
    }

    #[test]
    fn epoch_and_a_leap_day() {
        let epoch = DateTime::from_civil(1970, 1, 1, 0, 0, 0, 0);
        assert_eq!(epoch.to_unix_seconds(), Some(0));
        assert_eq!(epoch.day_of_week, 4, "1970-01-01 was a Thursday");
        let leap = DateTime::from_civil(2024, 2, 29, 0, 0, 0, 0);
        assert_eq!(leap.to_unix_seconds(), Some(1_709_164_800));
        assert_eq!(leap.day_of_week, 4, "2024-02-29 was a Thursday");
    }

    #[test]
    fn out_of_range_fields_are_refused() {
        let mut dt = DateTime::from_civil(2025, 1, 1, 0, 0, 0, 0);
        dt.month = 13;
        assert_eq!(dt.to_unix_seconds(), None);
        let mut dt = DateTime::from_civil(2025, 1, 1, 0, 0, 0, 0);
        dt.hour = 24;
        assert_eq!(dt.to_unix_seconds(), None);
    }

    #[test]
    fn a_day_that_does_not_exist_in_its_month_is_refused() {
        let mut dt = DateTime::from_civil(2025, 2, 28, 12, 0, 0, 0);
        assert!(dt.to_unix_seconds().is_some());
        dt.day_of_month = 29;
        assert_eq!(dt.to_unix_seconds(), None, "2025 is not a leap year");
        let mut leap = DateTime::from_civil(2024, 2, 28, 12, 0, 0, 0);
        leap.day_of_month = 29;
        assert!(leap.to_unix_seconds().is_some(), "2024 is");
        let mut april = DateTime::from_civil(2025, 4, 30, 12, 0, 0, 0);
        assert!(april.to_unix_seconds().is_some());
        april.day_of_month = 31;
        assert_eq!(april.to_unix_seconds(), None, "April has thirty days");
        // The century rule.
        let mut y1900 = DateTime::from_civil(1900, 2, 28, 0, 0, 0, 0);
        y1900.day_of_month = 29;
        assert_eq!(y1900.to_unix_seconds(), None);
        let mut y2000 = DateTime::from_civil(2000, 2, 28, 0, 0, 0, 0);
        y2000.day_of_month = 29;
        assert!(y2000.to_unix_seconds().is_some());
    }

    #[test]
    fn a_leap_second_has_no_unix_timestamp() {
        let mut dt = DateTime::from_civil(2016, 12, 31, 23, 59, 59, 0);
        assert!(dt.to_unix_seconds().is_some());
        dt.second = 60;
        assert_eq!(dt.to_unix_seconds(), None, "23:59:60 is not a Unix second");
    }

    #[test]
    fn every_type_prints_a_wildcard_the_same_way() {
        assert_eq!(
            alloc::format!("{}", Time { hour: 0xFF, minute: 30, second: 0xFF, hundredths: 0xFF }),
            "**:30:**"
        );
        assert_eq!(
            alloc::format!("{}", Date { year: 0xFFFF, month: 0xFF, day_of_month: 0xFE, day_of_week: 0xFF }),
            "****-**-**",
            "the last day of any month is a pattern, not the 254th"
        );
        assert_eq!(alloc::format!("{}", DateTime::WILDCARD), "****-**-**T**:**:**");
    }

    #[test]
    fn clock_status_bits() {
        let s = ClockStatus(0x81);
        assert!(s.invalid());
        assert!(s.daylight_saving_active());
        assert!(!s.doubtful());
        assert!(ClockStatus::NOT_SPECIFIED.is_not_specified());
    }
}
