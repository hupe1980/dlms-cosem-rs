//! Profile generic: selective access and typed rows.

use crate::axdr::{Data, DateTime, Seq};
use crate::codec::{Encode, Error, ErrorKind, Result, Writer};
use crate::obis::Obis;
use crate::xdlms::SelectiveAccess;

/// Which capture object a range selection is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureObject {
    /// The class of the captured object.
    pub class_id: u16,
    /// Its logical name.
    pub logical_name: Obis,
    /// Which of its attributes was captured.
    pub attribute_index: i8,
    /// Which element of a structured attribute, or 0 for the whole thing.
    pub data_index: u16,
}

impl CaptureObject {
    /// A capture object.
    #[must_use]
    pub const fn new(class_id: u16, logical_name: Obis, attribute_index: i8, data_index: u16) -> Self {
        Self { class_id, logical_name, attribute_index, data_index }
    }

    /// The clock's time attribute, which is what nearly every profile sorts by.
    #[must_use]
    pub const fn clock() -> Self {
        Self::new(8, Obis::new(0, 0, 1, 0, 0, 255), 2, 0)
    }

    /// Decode one `capture_object_definition` structure.
    pub fn from_data(d: &Data<'_>) -> Result<Self> {
        let s = d.as_structure().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
        let bad = || Error::new(ErrorKind::InvalidValue, 0);
        Ok(Self {
            class_id: u16::try_from(s.get(0)?.as_u64().ok_or_else(bad)?).map_err(|_| bad())?,
            logical_name: s.get(1)?.as_obis().ok_or_else(bad)?,
            attribute_index: i8::try_from(s.get(2)?.as_i64().ok_or_else(bad)?).map_err(|_| bad())?,
            data_index: u16::try_from(s.get(3)?.as_u64().ok_or_else(bad)?).map_err(|_| bad())?,
        })
    }
}

impl Encode for CaptureObject {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_bytes(&[0x02, 0x04])?;
        w.write_bytes(&[0x12])?;
        w.write_u16(self.class_id)?;
        w.write_bytes(&[0x09, 0x06])?;
        w.write_bytes(self.logical_name.as_bytes())?;
        w.write_bytes(&[0x0F, self.attribute_index as u8])?;
        w.write_bytes(&[0x12])?;
        w.write_u16(self.data_index)
    }
}

/// Read the rows whose sort value falls in a range — selector 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeDescriptor {
    /// Which captured value the range applies to. Almost always the clock.
    pub restricting_object: CaptureObject,
    /// The first value to include.
    pub from: DateTime,
    /// The last value to include.
    pub to: DateTime,
}

impl RangeDescriptor {
    /// A range over the clock, which is what a load-profile read wants.
    #[must_use]
    pub const fn by_clock(from: DateTime, to: DateTime) -> Self {
        Self { restricting_object: CaptureObject::clock(), from, to }
    }

    /// The selective access descriptor this range becomes.
    pub fn to_selective_access<'b>(&self, buf: &'b mut [u8]) -> Result<SelectiveAccess<'b>> {
        let mut w = crate::codec::SliceWriter::new(buf);
        // structure { restricting_object, from, to, selected_values }
        w.write_bytes(&[0x02, 0x04])?;
        self.restricting_object.encode(&mut w)?;
        w.write_bytes(&[0x09, 0x0C])?;
        w.write_bytes(&self.from.to_bytes())?;
        w.write_bytes(&[0x09, 0x0C])?;
        w.write_bytes(&self.to.to_bytes())?;
        // An empty array selects every captured column.
        w.write_bytes(&[0x01, 0x00])?;
        let n = w.written();
        let parameters = Data::from_bytes_in(&buf[..n])?;
        Ok(SelectiveAccess { selector: 1, parameters })
    }
}

/// Read rows by their position in the buffer — selector 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryDescriptor {
    /// The first entry, counting from one.
    pub from_entry: u32,
    /// The last entry; zero means "to the end".
    pub to_entry: u32,
    /// The first column, counting from one.
    pub from_value: u16,
    /// The last column; zero means "every column".
    pub to_value: u16,
}

impl EntryDescriptor {
    /// Every column of a range of entries.
    #[must_use]
    pub const fn entries(from: u32, to: u32) -> Self {
        Self { from_entry: from, to_entry: to, from_value: 1, to_value: 0 }
    }

    /// The selective access descriptor this becomes.
    pub fn to_selective_access<'b>(&self, buf: &'b mut [u8]) -> Result<SelectiveAccess<'b>> {
        let mut w = crate::codec::SliceWriter::new(buf);
        w.write_bytes(&[0x02, 0x04])?;
        w.write_u8(0x06)?;
        w.write_u32(self.from_entry)?;
        w.write_u8(0x06)?;
        w.write_u32(self.to_entry)?;
        w.write_u8(0x12)?;
        w.write_u16(self.from_value)?;
        w.write_u8(0x12)?;
        w.write_u16(self.to_value)?;
        let n = w.written();
        let parameters = Data::from_bytes_in(&buf[..n])?;
        Ok(SelectiveAccess { selector: 2, parameters })
    }
}

/// The most capture objects [`ProfileBuffer::for_each_cell`] can undo compression for.
///
/// The previous row is held in a fixed array so the decoder needs no allocator. No
/// profile in the Blue Book comes close to this.
pub const MAX_COLUMNS: usize = 32;

/// Apply a delta to the previous value in the same column.
///
/// The six delta types of Green Book edition 10 carry the *difference* from the previous
/// row's value in the same column, which is what makes a load profile compress: a
/// register that climbs by a few hundred each interval sends a byte or two instead of
/// four. Expanding one therefore needs the neighbour it is relative to, and that is why
/// it happens here rather than in [`Data`] — a `Data` that knew its neighbours would be
/// a different type.
///
/// Two rules keep this honest:
///
/// * **The delta's width decides the base type**, and the previous value must already be
///   that type. A `delta-long-unsigned` after a `double-long-unsigned` is a column whose
///   type changed mid-buffer, which is a meter fault or a misread row — either way, not
///   something to paper over by widening silently.
/// * **The arithmetic wraps in the base type**, because that is where the meter's own
///   register wraps. An expansion that saturated would turn a register rollover into a
///   plateau, which reads as a meter that stopped counting.
///
/// The signed delta types add signed differences; the unsigned ones add unsigned
/// increments, which is what their names say and what makes them worth having — a
/// quantity known not to decrease does not need a sign bit. That reading is derived
/// rather than read from the normative text, whose relevant clause is not in the
/// excerpts this crate was built from.
fn apply_delta(previous: Data<'_>, delta: Data<'_>) -> Option<Data<'static>> {
    Some(match (previous, delta) {
        (Data::Integer(base), Data::DeltaInteger(d)) => Data::Integer(base.wrapping_add(d)),
        (Data::Long(base), Data::DeltaLong(d)) => Data::Long(base.wrapping_add(d)),
        (Data::DoubleLong(base), Data::DeltaDoubleLong(d)) => Data::DoubleLong(base.wrapping_add(d)),
        (Data::Unsigned(base), Data::DeltaUnsigned(d)) => Data::Unsigned(base.wrapping_add(d)),
        (Data::LongUnsigned(base), Data::DeltaLongUnsigned(d)) => Data::LongUnsigned(base.wrapping_add(d)),
        (Data::DoubleLongUnsigned(base), Data::DeltaDoubleLongUnsigned(d)) => {
            Data::DoubleLongUnsigned(base.wrapping_add(d))
        }
        _ => return None,
    })
}

/// A decoded profile buffer, with the columns it was captured against.
///
/// Rows are iterated out of the borrowed buffer. Both of the compressions a profile
/// buffer uses are undone here, because a caller that has to remember the previous row is
/// a caller that will forget:
///
/// * **Null-data compression** — a column that repeats the previous row's value is sent
///   as `null-data`, or, for a run at the end of a row, left out by making the row
///   shorter.
/// * **Delta encoding** — a column sends the *difference* from the previous row
///   `[GB Ed 10 changes]`, in one of the six delta types.
///
/// A caller that skipped either gets numbers rather than an error: zeroes where a
/// reading repeated, and differences where readings were meant.
#[derive(Debug, Clone, Copy)]
pub struct ProfileBuffer<'a> {
    rows: Seq<'a>,
}

impl<'a> ProfileBuffer<'a> {
    /// Wrap the array a `buffer` attribute returned.
    pub fn new(buffer: &Data<'a>) -> Result<Self> {
        let rows = buffer.as_array().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
        Ok(Self { rows })
    }

    /// How many rows.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Iterate the rows as they arrived, without undoing compression.
    pub fn raw_rows(&self) -> impl Iterator<Item = Result<Seq<'a>>> + 'a {
        self.rows.iter().map(|row| {
            row.and_then(|r| r.as_structure().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0)))
        })
    }

    /// Visit every cell with its row and column, undoing null-data compression against
    /// the previous row.
    ///
    /// `columns` is how many capture objects the profile has. Three compressions are
    /// undone: a column whose value repeats the previous row is sent as `null-data`; a
    /// run of repeated columns at the *end* of a row is sent by making the row shorter;
    /// and a column may send a **delta** from the previous row rather than a value. The
    /// visitor therefore sees exactly `columns` cells for every row, each an absolute
    /// value — which is the point.
    ///
    /// # Errors
    /// When `columns` exceeds [`MAX_COLUMNS`]; when a row is not a structure; when the
    /// first row omits a value or sends a delta and so has nothing to be relative to; or
    /// when a delta's base type does not match the value it follows.
    pub fn for_each_cell(
        &self,
        columns: usize,
        mut f: impl FnMut(usize, usize, Data<'a>) -> Result<()>,
    ) -> Result<()> {
        // The previous row's values. Stored as `Data` because it borrows the same
        // buffer the rows do and copying it costs nothing.
        let mut previous: [Option<Data<'a>>; MAX_COLUMNS] = [None; MAX_COLUMNS];
        if columns > previous.len() {
            return Err(Error::new(ErrorKind::Unsupported, 0));
        }
        for (row_index, row) in self.raw_rows().enumerate() {
            let row = row?;
            let mut seen = 0usize;
            for (col, cell) in row.iter().enumerate() {
                if col >= columns {
                    break;
                }
                let cell = cell?;
                // `col < columns <= previous.len()` holds, but saying so with `get_mut`
                // is what keeps the bound out of the generated code as a panic path
                // rather than in it.
                let slot = previous.get_mut(col).ok_or_else(|| Error::new(ErrorKind::Unsupported, 0))?;
                let value = if matches!(cell, Data::Null) {
                    // Repeat: this column is unchanged from the previous row.
                    slot.ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?
                } else if cell.tag().is_delta() {
                    // Relative: expand against the previous row's value in this column.
                    // A delta in the first row has nothing to be relative to, and a
                    // delta whose width disagrees with the base is a column whose type
                    // changed — both are refused rather than guessed at.
                    let base = slot.ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
                    apply_delta(base, cell).ok_or_else(|| Error::new(ErrorKind::TypeMismatch, 0))?
                } else {
                    cell
                };
                *slot = Some(value);
                f(row_index, col, value)?;
                seen = col + 1;
            }
            // A short row means the columns it left out are unchanged.
            for col in seen..columns {
                let value = previous
                    .get(col)
                    .copied()
                    .flatten()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
                f(row_index, col, value)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    #[test]
    fn a_range_descriptor_selects_by_clock() {
        let from = DateTime::from_civil(2025, 1, 1, 0, 0, 0, 60);
        let to = DateTime::from_civil(2025, 1, 2, 0, 0, 0, 60);
        let mut buf = [0u8; 64];
        let sa = RangeDescriptor::by_clock(from, to).to_selective_access(&mut buf).unwrap();
        assert_eq!(sa.selector, 1);
        let s = sa.parameters.as_structure().expect("a structure of four fields");
        assert_eq!(s.len(), 4);
        let restricting = s.get(0).unwrap();
        assert_eq!(restricting.as_structure().unwrap().len(), 4);
        assert_eq!(
            CaptureObject::from_data(&restricting).unwrap().logical_name,
            Obis::new(0, 0, 1, 0, 0, 255)
        );
    }

    #[test]
    fn an_entry_descriptor_selects_by_position() {
        let mut buf = [0u8; 32];
        let sa = EntryDescriptor::entries(1, 10).to_selective_access(&mut buf).unwrap();
        assert_eq!(sa.selector, 2);
        let s = sa.parameters.as_structure().unwrap();
        assert_eq!(s.get(0).unwrap().as_u64(), Some(1));
        assert_eq!(s.get(1).unwrap().as_u64(), Some(10));
        assert_eq!(s.get(3).unwrap().as_u64(), Some(0), "zero means every column");
    }

    #[test]
    fn null_data_compression_is_undone_against_the_previous_row() {
        // Two columns; the second row repeats the first column.
        let raw = [
            0x01, 0x02, //
            0x02, 0x02, 0x11, 0x07, 0x12, 0x00, 0x64, //
            0x02, 0x02, 0x00, 0x12, 0x00, 0xC8,
        ];
        let d = Data::from_bytes(&raw).unwrap();
        let buffer = ProfileBuffer::new(&d).unwrap();
        assert_eq!(buffer.len(), 2);
        let mut cells = alloc::vec::Vec::new();
        buffer
            .for_each_cell(2, |row, col, v| {
                cells.push((row, col, v.as_i64()));
                Ok(())
            })
            .unwrap();
        assert_eq!(cells[0], (0, 0, Some(7)));
        assert_eq!(cells[1], (0, 1, Some(100)));
        assert_eq!(cells[2], (1, 0, Some(7)), "the repeated column carried forward");
        assert_eq!(cells[3], (1, 1, Some(200)));
    }

    #[test]
    fn a_short_row_repeats_the_columns_it_left_out() {
        // Two columns. The second row carries only the first, so the second column is
        // unchanged — the other half of null-data compression, and the half a caller
        // notices only when a reading silently goes missing.
        let raw = [
            0x01, 0x02, //
            0x02, 0x02, 0x11, 0x07, 0x12, 0x00, 0x64, //
            0x02, 0x01, 0x11, 0x09,
        ];
        let d = Data::from_bytes(&raw).unwrap();
        let buffer = ProfileBuffer::new(&d).unwrap();
        let mut cells = alloc::vec::Vec::new();
        buffer
            .for_each_cell(2, |row, col, v| {
                cells.push((row, col, v.as_i64()));
                Ok(())
            })
            .unwrap();
        assert_eq!(cells.len(), 4, "every row yields every column");
        assert_eq!(cells[2], (1, 0, Some(9)));
        assert_eq!(cells[3], (1, 1, Some(100)), "the column the row left out carried forward");
    }

    /// Delta encoding: a column sends the difference from the previous row.
    ///
    /// A caller that skipped this gets no error — it gets *differences where readings
    /// were meant*, which for a rising register looks like a meter that suddenly reads
    /// almost nothing.
    #[test]
    fn delta_columns_are_expanded_against_the_previous_row() {
        // One column. Row 0 is an absolute double-long-unsigned 1 000 000; rows 1 and 2
        // send delta-double-long-unsigned increments of 250 and 300.
        let raw = [
            0x01, 0x03, //
            0x02, 0x01, 0x06, 0x00, 0x0F, 0x42, 0x40, //
            0x02, 0x01, 0x21, 0x00, 0x00, 0x00, 0xFA, //
            0x02, 0x01, 0x21, 0x00, 0x00, 0x01, 0x2C,
        ];
        let d = Data::from_bytes(&raw).unwrap();
        let buffer = ProfileBuffer::new(&d).unwrap();
        let mut values = alloc::vec::Vec::new();
        buffer
            .for_each_cell(1, |_, _, v| {
                values.push(v.as_u64());
                Ok(())
            })
            .unwrap();
        assert_eq!(values, [Some(1_000_000), Some(1_000_250), Some(1_000_550)]);
    }

    /// A signed delta may go down, and the expansion wraps where the meter's register
    /// wraps rather than saturating — a rollover that saturated would read as a meter
    /// that stopped counting.
    #[test]
    fn a_signed_delta_may_decrease_and_the_arithmetic_wraps() {
        assert_eq!(apply_delta(Data::Long(100), Data::DeltaLong(-30)), Some(Data::Long(70)));
        assert_eq!(
            apply_delta(Data::DoubleLongUnsigned(u32::MAX), Data::DeltaDoubleLongUnsigned(2)),
            Some(Data::DoubleLongUnsigned(1)),
            "a register rollover is a rollover, not a ceiling"
        );
    }

    /// A delta whose width disagrees with the value it follows is a column whose type
    /// changed mid-buffer. Widening it silently would hand back a number nobody sent.
    #[test]
    fn a_delta_of_the_wrong_width_is_refused_rather_than_widened() {
        assert_eq!(apply_delta(Data::DoubleLongUnsigned(1000), Data::DeltaLongUnsigned(5)), None);
        assert_eq!(apply_delta(Data::Unsigned(1), Data::DeltaInteger(1)), None);

        let raw = [
            0x01, 0x02, //
            0x02, 0x01, 0x06, 0x00, 0x0F, 0x42, 0x40, //
            0x02, 0x01, 0x20, 0x00, 0xFA,
        ];
        let d = Data::from_bytes(&raw).unwrap();
        let buffer = ProfileBuffer::new(&d).unwrap();
        assert_eq!(buffer.for_each_cell(1, |_, _, _| Ok(())).unwrap_err().kind, ErrorKind::TypeMismatch);
    }

    /// A delta in the first row is relative to nothing.
    #[test]
    fn a_leading_delta_is_refused_like_a_leading_null() {
        let raw = [0x01, 0x01, 0x02, 0x01, 0x21, 0x00, 0x00, 0x00, 0x05];
        let d = Data::from_bytes(&raw).unwrap();
        let buffer = ProfileBuffer::new(&d).unwrap();
        assert!(buffer.for_each_cell(1, |_, _, _| Ok(())).is_err());
    }

    #[test]
    fn a_leading_null_has_nothing_to_repeat_and_is_refused() {
        let raw = [0x01, 0x01, 0x02, 0x01, 0x00];
        let d = Data::from_bytes(&raw).unwrap();
        let buffer = ProfileBuffer::new(&d).unwrap();
        assert!(buffer.for_each_cell(1, |_, _, _| Ok(())).is_err());
    }
}
