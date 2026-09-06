//! A-XDR — the encoding xDLMS uses for data.
//!
//! The centrepiece is [`Data`], a *borrowed* view over the input: an array or structure
//! keeps the slice its elements live in and iterates it lazily, so a one-megabyte load
//! profile is decoded without allocating and its rows are read straight out of the
//! receive buffer. Nesting depth is bounded ([`MAX_DEPTH`]) because the encoding is
//! recursive and the input is hostile.
//!
//! [`DataBuf`] is the owned counterpart, available with the `alloc` feature.

mod compact;
mod data;
mod datetime;
mod unit;

pub use compact::{CompactArray, CompactLeaf, MAX_COMPACT_NODES, TypeDesc};
pub use data::{BitStr, Data, DataTag, MAX_DEPTH, Seq, SeqIter};
pub use datetime::{ClockStatus, DEVIATION_NOT_SPECIFIED, Date, DateTime, Time};
pub use unit::{ScaledValue, Unit};

#[cfg(feature = "alloc")]
pub use data::DataBuf;
