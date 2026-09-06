#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Everything in this crate faces the network before any key has been checked, so the
// ways a decoder can abort the process are denied outright rather than reviewed.
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::todo,
    clippy::unimplemented,
    clippy::mem_forget,
    clippy::exit
)]
#![warn(clippy::pedantic)]
// A test is allowed to abort: that is what a failing assertion is.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic, clippy::expect_used))]
// Bounds-checked indexing and checked arithmetic are the deeper hygiene: every site in
// this crate is guarded by a preceding length check, but the lints cannot see that, so
// they live behind `--cfg dlms_audit`, which CI turns on for an audit pass. A cfg rather
// than a feature, so `--all-features` and docs.rs never trip over them.
#![cfg_attr(dlms_audit, warn(clippy::indexing_slicing, clippy::arithmetic_side_effects))]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::wildcard_imports,
    clippy::match_same_arms,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::doc_markdown,
    clippy::redundant_closure_for_method_calls,
    clippy::needless_lifetimes,
    clippy::many_single_char_names,
    clippy::struct_field_names
)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Recipes for the things people actually do with this crate.
///
/// Every example here is compiled — and, where it needs no socket, run — as a doctest,
/// so a snippet that stops compiling fails the build rather than quietly misleading
/// somebody. That is the whole value of the page, and it is also why the module is
/// gated: a recipe reaches for the P1 reader and the well-known OBIS names, and a
/// doctest cannot be conditional on a feature the way a function can. Documenting a
/// recipe that will not compile in the reader's own configuration is exactly the kind of
/// quietly-wrong documentation the compilation is meant to prevent.
///
/// `docs.rs` builds with every feature, so the published documentation always has it.
#[cfg(all(
    feature = "std",
    feature = "client",
    feature = "server",
    feature = "hdlc",
    feature = "wrapper",
    feature = "p1",
    feature = "suite0",
    feature = "obis-names",
))]
#[doc = include_str!("../site/includes/cookbook.md")]
pub mod cookbook {}

pub mod codec;

pub mod acse;
pub mod ber;
pub mod cosem;
pub mod security;
pub mod transport;
pub mod xdlms;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;

pub mod axdr;
pub mod obis;

pub use codec::{Error, ErrorKind, Reader, Result, SliceWriter, Writer};
pub use obis::Obis;
pub use xdlms::Apdu;
