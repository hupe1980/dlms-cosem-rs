//! Looking a class up.

use super::class::ClassDescriptor;
use super::classes::{DETAILED, NAMED};

/// The descriptor for a class and version.
///
/// A version this crate does not have falls back to any version of the same class, so a
/// translator can still name a `Register` version 1 that a future edition adds. The
/// caller can tell the difference: [`ClassDescriptor::version`] says which version the
/// answer describes.
#[must_use]
pub fn describe(class_id: u16, version: u8) -> Option<&'static ClassDescriptor> {
    exact(class_id, version).or_else(|| any_version(class_id))
}

/// The descriptor for exactly this class and version.
#[must_use]
pub fn exact(class_id: u16, version: u8) -> Option<&'static ClassDescriptor> {
    DETAILED.iter().chain(NAMED).find(|c| c.class_id == class_id && c.version == version)
}

/// Any tabulated version of this class.
#[must_use]
pub fn any_version(class_id: u16) -> Option<&'static ClassDescriptor> {
    DETAILED.iter().chain(NAMED).find(|c| c.class_id == class_id)
}

/// The class name, or `None` when the class is not in the registry at all.
#[must_use]
pub fn class_name(class_id: u16) -> Option<&'static str> {
    any_version(class_id).map(|c| c.name)
}

/// The name of an attribute, for a translator.
///
/// Attribute 1 is the logical name for every class, so it is answered even when only
/// the class name is tabulated.
#[must_use]
pub fn attribute_name(class_id: u16, version: u8, index: i8) -> Option<&'static str> {
    if index == 1 {
        return Some("logical_name");
    }
    describe(class_id, version)?.attribute(index).map(|a| a.name)
}

/// The name of a method, for a translator.
#[must_use]
pub fn method_name(class_id: u16, version: u8, index: i8) -> Option<&'static str> {
    describe(class_id, version)?.method(index).map(|m| m.name)
}

/// Every class the registry knows, detailed ones first.
pub fn all() -> impl Iterator<Item = &'static ClassDescriptor> {
    DETAILED.iter().chain(NAMED)
}

/// How many interface classes carry full attribute and method tables.
pub const DETAILED_CLASS_COUNT: usize = DETAILED.len();

/// How many carry a class id, a version and a name, and nothing more.
///
/// Refusing to name a class the crate has no attribute table for would help nobody: a
/// translator that can say *what an object is* is useful even when it cannot label every
/// field of it.
pub const NAMED_CLASS_COUNT: usize = NAMED.len();

/// How many interface classes the registry knows at either depth.
pub const CLASS_COUNT: usize = DETAILED_CLASS_COUNT + NAMED_CLASS_COUNT;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosem::class::InterfaceClass;
    use crate::cosem::classes::{Clock, ProfileGeneric, Register};

    #[test]
    fn a_class_type_and_its_descriptor_agree() {
        assert_eq!(Register::CLASS_ID, 3);
        assert_eq!(Register::VERSION, 0);
        let d = Register::descriptor();
        assert_eq!(d.class_id, 3);
        assert_eq!(d.attribute(3).unwrap().name, "scaler_unit");
        assert_eq!(d.method(1).unwrap().name, "reset");
    }

    #[test]
    fn the_registry_finds_both_depths() {
        assert_eq!(class_name(7), Some("Profile generic"));
        assert_eq!(class_name(152), Some("CoAP setup"));
        assert_eq!(class_name(9999), None);
        assert!(!describe(7, 1).unwrap().is_name_only());
        assert!(describe(152, 0).unwrap().is_name_only());
    }

    #[test]
    fn an_unknown_version_falls_back_but_says_so() {
        let d = describe(3, 9).unwrap();
        assert_eq!(d.class_id, 3);
        assert_eq!(d.version, 0, "the descriptor names the version it actually describes");
        assert!(exact(3, 9).is_none());
    }

    #[test]
    fn attribute_one_is_always_the_logical_name() {
        assert_eq!(attribute_name(7, 1, 1), Some("logical_name"));
        assert_eq!(attribute_name(152, 0, 1), Some("logical_name"), "even for a name-only class");
        assert_eq!(attribute_name(152, 0, 2), None);
    }

    #[test]
    fn the_translator_can_label_the_common_classes() {
        assert_eq!(attribute_name(8, 0, 2), Some("time"));
        assert_eq!(attribute_name(7, 1, 2), Some("buffer"));
        assert_eq!(method_name(70, 2, 1), Some("remote_disconnect"));
        assert_eq!(method_name(15, 3, 1), Some("reply_to_hls_authentication"));
    }

    /// The counts the architecture notes and the cookbook quote.
    ///
    /// A number in prose drifts silently; a number in an assertion cannot. Three
    /// documents quoted three different pairs of figures for this table before the check
    /// existed, and no reader could tell which was right.
    #[test]
    fn the_table_is_the_size_the_documents_say_it_is() {
        let detailed = DETAILED.len();
        let named = NAMED.len();
        assert_eq!(detailed, DETAILED_CLASS_COUNT, "classes with full attribute and method tables");
        assert_eq!(named, NAMED_CLASS_COUNT, "classes carrying an id, a version and a name");
        assert_eq!(all().count(), CLASS_COUNT);
        // And every detailed class is detailed: a name-only entry in the wrong list
        // would keep the count right and the meaning wrong.
        assert!(DETAILED.iter().all(|c| !c.is_name_only()));
        assert!(NAMED.iter().all(ClassDescriptor::is_name_only));
    }

    #[test]
    fn no_two_entries_describe_the_same_class_and_version() {
        let mut seen = alloc::vec::Vec::new();
        for c in all() {
            let key = (c.class_id, c.version);
            assert!(!seen.contains(&key), "duplicate entry for class {} v{}", c.class_id, c.version);
            seen.push(key);
        }
    }

    #[test]
    fn every_detailed_class_starts_with_its_logical_name() {
        for c in crate::cosem::classes::DETAILED {
            let first = c.attributes.first().expect("a detailed class has attributes");
            assert_eq!(first.index, 1, "{} does not start at attribute 1", c.name);
            assert_eq!(first.name, "logical_name", "{}'s attribute 1 is not the logical name", c.name);
        }
    }

    #[test]
    fn attribute_indices_are_ascending_and_unique() {
        for c in crate::cosem::classes::DETAILED {
            let mut last = 0i8;
            for a in c.attributes {
                assert!(a.index > last, "{}: attribute {} is out of order", c.name, a.index);
                last = a.index;
            }
            let mut last = 0i8;
            for m in c.methods {
                assert!(m.index > last, "{}: method {} is out of order", c.name, m.index);
                last = m.index;
            }
        }
    }

    #[test]
    fn clock_and_profile_generic_carry_the_versions_the_blue_book_gives_them() {
        assert_eq!(Clock::VERSION, 0);
        assert_eq!(ProfileGeneric::VERSION, 1, "profile generic is at version 1");
    }
}

#[cfg(test)]
mod size {
    //! The registry's size, pinned.
    //!
    //! The README and the documentation site quote these numbers. A figure in prose
    //! that nothing checks drifts from the table the first time somebody adds a class,
    //! and the document is then quietly wrong in a way no test notices.
    use super::super::classes::{DETAILED, NAMED};

    #[test]
    fn the_registry_holds_the_number_of_classes_the_documents_claim() {
        assert_eq!(DETAILED.len(), 25, "classes with full attribute and method tables");
        assert_eq!(NAMED.len(), 77, "classes carrying a name and version only");
        assert_eq!(DETAILED.len() + NAMED.len(), 102, "classes in the registry");
    }
}
