//! The COSEM object model: interface classes, access rights, profiles.
//!
//! Nothing here depends on [`crate::xdlms`]. The object model describes what a meter
//! *is*; the application layer describes how to ask it. Entangling the two is the one
//! criticism every user of the largest existing stack makes of it, and keeping them
//! apart is what lets the same model serve a server that hosts objects and a client
//! that reads them.

pub mod access;
pub mod class;
pub mod classes;
pub mod profile;
pub mod registry;
#[cfg(feature = "sn")]
pub mod sn;

pub use access::{
    AssociationVersion, AttributeAccess, AttributeRight, MethodAccess, MethodRight, ObjectListEntry,
};
pub use class::{
    AttrType, AttributeInfo, ClassDescriptor, DefaultAccess, InterfaceClass, MethodInfo, ObjectRef,
};
pub use profile::{CaptureObject, EntryDescriptor, MAX_COLUMNS, ProfileBuffer, RangeDescriptor};
pub use registry::{
    CLASS_COUNT, DETAILED_CLASS_COUNT, NAMED_CLASS_COUNT, attribute_name, class_name, describe, method_name,
};
#[cfg(feature = "sn")]
pub use sn::{ShortName, ShortNameTarget};
