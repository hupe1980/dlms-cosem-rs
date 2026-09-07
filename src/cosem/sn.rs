//! Mapping short names onto objects.
//!
//! A short name is a sixteen-bit number standing for one attribute or one method of one
//! object, counted from that object's **base name** — which the meter publishes in its
//! own `Association SN` object list, so neither end has to know it in advance.
//!
//! Half the mapping is a formula and half is a table:
//!
//! * **Attributes.** Attribute *n* of an object based at `x` is `x + (n − 1) × 8`. Two
//!   independent sources state it, so it is computed here.
//! * **Methods.** Each interface class states its own method offset. `Register` has three
//!   attributes and puts `reset` at `x + 0x28` — not "after the attributes", and not any
//!   function of the attribute count. Those tables are in the Blue Book, which this
//!   project does not have.
//!
//! So [`ShortName::with_methods`] takes the offset as a value, and a class whose offset is
//! unknown has no addressable methods. The parties who need it already have it: a meter
//! knows its own, and a client reads base names off the meter. Invoking the wrong method
//! is worse than invoking none.

use crate::obis::Obis;

/// How far apart consecutive attributes of one object sit.
pub const ATTRIBUTE_STRIDE: u16 = 8;

/// What a short name turned out to address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortNameTarget {
    /// An attribute of the object.
    Attribute {
        /// The object's class.
        class_id: u16,
        /// The object's logical name.
        logical_name: Obis,
        /// Which attribute, counting from one.
        attribute_id: i8,
    },
    /// A method of the object.
    Method {
        /// The object's class.
        class_id: u16,
        /// The object's logical name.
        logical_name: Obis,
        /// Which method, counting from one.
        method_id: i8,
    },
}

/// One object's short-name mapping.
///
/// A store keeps a table of these — one per object it exposes to a short-name
/// association — and answers `ObjectStore::resolve_short_name` by scanning it.
///
/// ```
/// use dlms_cosem_rs::cosem::{ShortName, ShortNameTarget};
/// use dlms_cosem_rs::obis::Obis;
///
/// // A Register: three attributes at base name 0x0028, and one method — `reset` —
/// // which its class puts at x + 0x28.
/// let energy = ShortName::new(0x0028, 3, Obis::new(1, 0, 1, 8, 0, 255), 3).with_methods(0x28, 1);
///
/// assert_eq!(energy.attribute(2), Some(0x0030));       // `value`
/// assert_eq!(energy.method(1), Some(0x0050));          // `reset`
/// assert!(matches!(
///     energy.resolve(0x0030),
///     Some(ShortNameTarget::Attribute { attribute_id: 2, .. })
/// ));
/// assert_eq!(energy.resolve(0x0031), None, "not on the eight-byte grid");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortName {
    /// The object's base name — the short name of its attribute 1, the logical name.
    pub base: u16,
    /// The object's class.
    pub class_id: u16,
    /// The object's logical name.
    pub logical_name: Obis,
    /// Where this class's methods start, as an offset from `base`.
    ///
    /// `None` for a class with no methods, and for one whose offset the caller does not
    /// know — its methods are then not addressable, which beats invoking the wrong one.
    pub method_offset: Option<u16>,
    /// How many attributes the class has, so a name past the last one is refused.
    pub attributes: u8,
    /// How many methods the class has.
    pub methods: u8,
}

impl ShortName {
    /// An object at `base`, of class `class_id`, with `attributes` attributes and no
    /// methods addressable.
    ///
    /// The counts are not optional. An offset given without a count would let a name far
    /// past the object's end resolve to "method 32" — a wrong answer that looks like a
    /// right one.
    #[must_use]
    pub const fn new(base: u16, class_id: u16, logical_name: Obis, attributes: u8) -> Self {
        Self { base, class_id, logical_name, method_offset: None, attributes, methods: 0 }
    }

    /// Where this class's methods start, relative to the base name, and how many it has.
    ///
    /// The offset is the class's own; see the module documentation.
    #[must_use]
    pub const fn with_methods(self, offset: u16, count: u8) -> Self {
        Self { method_offset: Some(offset), methods: count, ..self }
    }

    /// The short name of attribute `index`, counting from one.
    #[must_use]
    pub const fn attribute(&self, index: i8) -> Option<u16> {
        if index < 1 || index as u8 > self.attributes {
            return None;
        }
        let steps = (index as u16).wrapping_sub(1);
        match steps.checked_mul(ATTRIBUTE_STRIDE) {
            Some(offset) => self.base.checked_add(offset),
            None => None,
        }
    }

    /// The short name of method `index`, counting from one.
    ///
    /// `None` when this object's method offset is not known, which is the answer that
    /// keeps a guess off the wire.
    #[must_use]
    pub const fn method(&self, index: i8) -> Option<u16> {
        let Some(method_offset) = self.method_offset else {
            return None;
        };
        if index < 1 || index as u8 > self.methods {
            return None;
        }
        let steps = (index as u16).wrapping_sub(1);
        let Some(offset) = steps.checked_mul(ATTRIBUTE_STRIDE) else {
            return None;
        };
        let Some(offset) = offset.checked_add(method_offset) else {
            return None;
        };
        self.base.checked_add(offset)
    }

    /// What `name` addresses in this object, if anything.
    ///
    /// `None` when the name is below the base, past the end, or off the eight-byte grid.
    /// All three mean "not this object" rather than "malformed", so a store scanning a
    /// table moves on to the next entry.
    #[must_use]
    pub const fn resolve(&self, name: u16) -> Option<ShortNameTarget> {
        let Some(offset) = name.checked_sub(self.base) else {
            return None;
        };
        if offset % ATTRIBUTE_STRIDE != 0 {
            return None;
        }
        let step = offset / ATTRIBUTE_STRIDE;
        // The method block wins where the two could overlap, because a class that states
        // a method offset has stated where its attributes stop.
        if let Some(method_offset) = self.method_offset {
            if offset >= method_offset {
                let steps = (offset - method_offset) / ATTRIBUTE_STRIDE;
                if steps < 0x80 && (steps as u8) < self.methods {
                    return Some(ShortNameTarget::Method {
                        class_id: self.class_id,
                        logical_name: self.logical_name,
                        method_id: (steps as i8).wrapping_add(1),
                    });
                }
                return None;
            }
        }
        if step >= 0x80 || (step as u8) >= self.attributes {
            return None;
        }
        Some(ShortNameTarget::Attribute {
            class_id: self.class_id,
            logical_name: self.logical_name,
            attribute_id: (step as i8).wrapping_add(1),
        })
    }
}

/// Find which of `objects` owns `name`.
///
/// A linear scan: short-name devices are the small ones, and a table of thirty entries is
/// cheaper to walk than to index.
#[must_use]
pub fn resolve(objects: &[ShortName], name: u16) -> Option<ShortNameTarget> {
    objects.iter().find_map(|o| o.resolve(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENERGY: Obis = Obis::new(1, 0, 1, 8, 0, 255);

    /// The attribute rule, which two sources state: attribute 1 is `x`, 2 is `x + 0x08`,
    /// 3 is `x + 0x10`.
    #[test]
    fn attributes_sit_eight_apart_from_the_base_name() {
        let r = ShortName::new(0x0028, 3, ENERGY, 3);
        assert_eq!(r.attribute(1), Some(0x0028));
        assert_eq!(r.attribute(2), Some(0x0030));
        assert_eq!(r.attribute(3), Some(0x0038));
        assert_eq!(r.attribute(4), None, "the class has three");
        assert_eq!(r.attribute(0), None, "indexes count from one");
    }

    /// `Register` has three attributes and puts `reset` at `x + 0x28` — which is *not*
    /// where "after the attributes" would put it. That is the whole reason the offset is
    /// a parameter rather than a formula.
    #[test]
    fn a_method_offset_is_the_classs_own_and_is_not_derivable() {
        let r = ShortName::new(0x0028, 3, ENERGY, 3).with_methods(0x28, 1);
        assert_eq!(r.method(1), Some(0x0050));
        assert_ne!(r.method(1), r.attribute(3).map(|a| a + 8), "not simply after the attributes");

        // Without the offset the methods are not addressable, which is the answer that
        // keeps a guess off the wire.
        let unknown = ShortName::new(0x0028, 3, ENERGY, 3);
        assert_eq!(unknown.method(1), None);
        assert_eq!(unknown.resolve(0x0050), None);
    }

    #[test]
    fn resolving_is_the_inverse_of_naming() {
        let r = ShortName::new(0x0028, 3, ENERGY, 3).with_methods(0x28, 1);
        for index in 1..=3i8 {
            let name = r.attribute(index).unwrap();
            assert_eq!(
                r.resolve(name),
                Some(ShortNameTarget::Attribute { class_id: 3, logical_name: ENERGY, attribute_id: index })
            );
        }
        let name = r.method(1).unwrap();
        assert_eq!(
            r.resolve(name),
            Some(ShortNameTarget::Method { class_id: 3, logical_name: ENERGY, method_id: 1 })
        );
    }

    #[test]
    fn a_name_that_is_not_this_objects_resolves_to_nothing() {
        let r = ShortName::new(0x0028, 3, ENERGY, 3).with_methods(0x28, 1);
        assert_eq!(r.resolve(0x0020), None, "below the base");
        assert_eq!(r.resolve(0x0029), None, "off the eight-byte grid");
        assert_eq!(r.resolve(0x0040), None, "between the last attribute and the methods");
        assert_eq!(r.resolve(0x0058), None, "past the only method");
    }

    #[test]
    fn a_table_finds_the_object_a_name_belongs_to() {
        const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255);
        let objects =
            [ShortName::new(0x0028, 3, ENERGY, 3).with_methods(0x28, 1), ShortName::new(0x0100, 8, CLOCK, 9)];
        assert!(matches!(
            resolve(&objects, 0x0030),
            Some(ShortNameTarget::Attribute { class_id: 3, attribute_id: 2, .. })
        ));
        assert!(matches!(
            resolve(&objects, 0x0108),
            Some(ShortNameTarget::Attribute { class_id: 8, attribute_id: 2, .. })
        ));
        assert_eq!(resolve(&objects, 0x0200), None);
    }

    /// A base name near the top of the range must not wrap into a name that belongs to
    /// something else. `0xFA00` is the current association object's base, and a meter
    /// with objects above it is ordinary.
    #[test]
    fn arithmetic_near_the_top_of_the_range_saturates_rather_than_wrapping() {
        let r = ShortName::new(0xFFF8, 1, ENERGY, 2);
        assert_eq!(r.attribute(1), Some(0xFFF8));
        assert_eq!(r.attribute(2), None, "0xFFF8 + 8 does not fit");
    }
}
