//! Interface classes: what an object is.

use crate::obis::Obis;

/// The data type an attribute holds, as the Blue Book's class descriptions give it.
///
/// [`AttrType::Any`] is for attributes whose type depends on the object — a `Data`
/// object's value, a register's value — and for the ones this crate has not tabulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum AttrType {
    Any,
    OctetString,
    VisibleString,
    Utf8String,
    Boolean,
    BitString,
    Integer,
    Long,
    DoubleLong,
    Long64,
    Unsigned,
    LongUnsigned,
    DoubleLongUnsigned,
    Long64Unsigned,
    Enum,
    Float32,
    Float64,
    DateTime,
    Date,
    Time,
    Array,
    Structure,
    /// The `scaler_unit` structure: an integer exponent and a unit enumeration.
    ScalerUnit,
    /// A six-byte octet string holding a logical name.
    ObisCode,
}

/// What an association may do with an attribute, before access rights narrow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAccess {
    /// Readable only.
    Read,
    /// Readable and writable.
    ReadWrite,
    /// Writable only.
    Write,
}

/// One attribute of a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeInfo {
    /// The attribute index, counting from 1.
    pub index: i8,
    /// The name the Blue Book gives it.
    pub name: &'static str,
    /// Its type.
    pub ty: AttrType,
    /// What the class definition allows.
    pub access: DefaultAccess,
}

/// One method of a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodInfo {
    /// The method index, counting from 1.
    pub index: i8,
    /// The name the Blue Book gives it.
    pub name: &'static str,
}

/// A class as data: what a translator prints and what a generic server hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassDescriptor {
    /// The class identifier.
    pub class_id: u16,
    /// The version this descriptor describes.
    pub version: u8,
    /// The class name.
    pub name: &'static str,
    /// Its attributes. Empty when only the class name is tabulated.
    pub attributes: &'static [AttributeInfo],
    /// Its methods.
    pub methods: &'static [MethodInfo],
}

impl ClassDescriptor {
    /// The attribute with this index.
    #[must_use]
    pub fn attribute(&self, index: i8) -> Option<&'static AttributeInfo> {
        self.attributes.iter().find(|a| a.index == index)
    }

    /// The method with this index.
    #[must_use]
    pub fn method(&self, index: i8) -> Option<&'static MethodInfo> {
        self.methods.iter().find(|m| m.index == index)
    }

    /// True when only the class name is known, not its attributes.
    #[must_use]
    pub const fn is_name_only(&self) -> bool {
        self.attributes.is_empty()
    }
}

/// A COSEM interface class, as a type.
///
/// The version is part of the type, not a runtime field: `AssociationLn` version 3
/// encodes its access rights differently from version 2, and a client that treats them
/// as one type reads the wrong thing out of the object list.
pub trait InterfaceClass {
    /// The class identifier.
    const CLASS_ID: u16;
    /// The version this type implements.
    const VERSION: u8;
    /// The class name.
    const NAME: &'static str;

    /// The runtime descriptor for this class.
    fn descriptor() -> &'static ClassDescriptor;
}

/// An object as a client sees it in an association's object list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRef {
    /// Which class.
    pub class_id: u16,
    /// Which version of it the server implements.
    pub version: u8,
    /// The object's logical name.
    pub logical_name: Obis,
}

impl ObjectRef {
    /// An object reference.
    #[must_use]
    pub const fn new(class_id: u16, version: u8, logical_name: Obis) -> Self {
        Self { class_id, version, logical_name }
    }

    /// The descriptor for this object's class, when the registry has one.
    #[must_use]
    pub fn describe(&self) -> Option<&'static ClassDescriptor> {
        super::registry::describe(self.class_id, self.version)
    }
}
