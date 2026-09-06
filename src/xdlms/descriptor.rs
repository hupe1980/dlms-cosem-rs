//! Attribute and method descriptors, and selective access.

use crate::axdr::Data;
use crate::codec::{Decode, Encode, Reader, Result, Writer};
use crate::obis::Obis;

/// Which attribute of which object: class, logical name, attribute index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeDescriptor {
    /// The interface class.
    pub class_id: u16,
    /// The object's logical name.
    pub instance_id: Obis,
    /// The attribute index. Attribute 1 is always the logical name; index 0 addresses
    /// every attribute at once, which a server only accepts if it said so in the
    /// conformance block.
    pub attribute_id: i8,
}

impl AttributeDescriptor {
    /// A descriptor.
    #[must_use]
    pub const fn new(class_id: u16, instance_id: Obis, attribute_id: i8) -> Self {
        Self { class_id, instance_id, attribute_id }
    }
}

impl Encode for AttributeDescriptor {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u16(self.class_id)?;
        w.write_bytes(self.instance_id.as_bytes())?;
        w.write_u8(self.attribute_id as u8)
    }

    fn encoded_len(&self) -> usize {
        9
    }
}

impl<'a> Decode<'a> for AttributeDescriptor {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { class_id: r.u16()?, instance_id: Obis::decode(r)?, attribute_id: r.i8()? })
    }
}

/// Which method of which object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodDescriptor {
    /// The interface class.
    pub class_id: u16,
    /// The object's logical name.
    pub instance_id: Obis,
    /// The method index, counting from 1.
    pub method_id: i8,
}

impl MethodDescriptor {
    /// A descriptor.
    #[must_use]
    pub const fn new(class_id: u16, instance_id: Obis, method_id: i8) -> Self {
        Self { class_id, instance_id, method_id }
    }
}

impl Encode for MethodDescriptor {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u16(self.class_id)?;
        w.write_bytes(self.instance_id.as_bytes())?;
        w.write_u8(self.method_id as u8)
    }

    fn encoded_len(&self) -> usize {
        9
    }
}

impl<'a> Decode<'a> for MethodDescriptor {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { class_id: r.u16()?, instance_id: Obis::decode(r)?, method_id: r.i8()? })
    }
}

/// A restriction on which part of an attribute is read or written.
///
/// The selector's meaning belongs to the interface class: for a profile generic,
/// selector 1 is a range of entries by capture-object value and selector 2 a range by
/// entry number.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectiveAccess<'a> {
    /// Which selector of the class.
    pub selector: u8,
    /// Its parameters.
    pub parameters: Data<'a>,
}

impl Encode for SelectiveAccess<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.selector)?;
        self.parameters.encode(w)
    }
}

impl<'a> Decode<'a> for SelectiveAccess<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { selector: r.u8()?, parameters: Data::decode(r)? })
    }
}

/// Write an A-XDR `OPTIONAL` field: a usage flag, then the value when present.
pub(crate) fn encode_optional<T: Encode>(w: &mut dyn Writer, v: Option<&T>) -> Result<()> {
    match v {
        None => w.write_u8(0),
        Some(v) => {
            w.write_u8(1)?;
            v.encode(w)
        }
    }
}

/// Read an A-XDR `OPTIONAL` field.
pub(crate) fn decode_optional<'a, T: Decode<'a>>(r: &mut Reader<'a>) -> Result<Option<T>> {
    if r.u8()? == 0 { Ok(None) } else { Ok(Some(T::decode(r)?)) }
}

/// An attribute descriptor together with an optional selective access descriptor, as
/// the `with-list` services carry them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttributeDescriptorWithSelection<'a> {
    /// Which attribute.
    pub descriptor: AttributeDescriptor,
    /// Which part of it.
    pub access: Option<SelectiveAccess<'a>>,
}

impl Encode for AttributeDescriptorWithSelection<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        self.descriptor.encode(w)?;
        encode_optional(w, self.access.as_ref())
    }
}

impl<'a> Decode<'a> for AttributeDescriptorWithSelection<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { descriptor: AttributeDescriptor::decode(r)?, access: decode_optional(r)? })
    }
}

/// The invoke id and priority byte carried by every confirmed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvokeId(pub u8);

impl InvokeId {
    /// A confirmed request at normal priority with invoke id `id` (0–15).
    #[must_use]
    pub const fn confirmed(id: u8) -> Self {
        Self((id & 0x0F) | 0x40)
    }

    /// The invoke id, 0–15.
    #[must_use]
    pub const fn id(self) -> u8 {
        self.0 & 0x0F
    }

    /// True when a response is expected.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        self.0 & 0x40 != 0
    }

    /// True when the request asked for high priority.
    #[must_use]
    pub const fn is_high_priority(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// The same invoke id at high priority.
    #[must_use]
    pub const fn with_high_priority(self) -> Self {
        Self(self.0 | 0x80)
    }
}

/// The four-byte invoke id and priority used by the ACCESS and notification services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongInvokeId(pub u32);

impl LongInvokeId {
    /// A long invoke id, 24 bits.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id & 0x00FF_FFFF)
    }

    /// The invoke id.
    #[must_use]
    pub const fn id(self) -> u32 {
        self.0 & 0x00FF_FFFF
    }

    /// True when a response is expected.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        self.0 & 0x2000_0000 != 0
    }

    /// True when the sender marked the message self-descriptive.
    #[must_use]
    pub const fn is_self_descriptive(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    /// The same id, marked confirmed.
    #[must_use]
    pub const fn confirmed(self) -> Self {
        Self(self.0 | 0x2000_0000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn an_attribute_descriptor_is_nine_bytes_in_order() {
        let d = AttributeDescriptor::new(3, Obis::new(1, 0, 1, 8, 0, 255), 2);
        let mut buf = [0u8; 16];
        let mut w = SliceWriter::new(&mut buf);
        d.encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x00, 0x03, 1, 0, 1, 8, 0, 255, 2]);
        assert_eq!(d.encoded_len(), 9);
        assert_eq!(AttributeDescriptor::from_bytes(w.as_slice()).unwrap(), d);
    }

    #[test]
    fn a_negative_attribute_index_survives_the_round_trip() {
        // Attribute ids are signed in the ASN.1; a server that reads them as unsigned
        // turns attribute -1 into 255 and addresses a different thing.
        let d = AttributeDescriptor::new(7, Obis::new(1, 0, 99, 1, 0, 255), -1);
        let mut buf = [0u8; 16];
        let mut w = SliceWriter::new(&mut buf);
        d.encode(&mut w).unwrap();
        assert_eq!(w.as_slice()[8], 0xFF);
        assert_eq!(AttributeDescriptor::from_bytes(w.as_slice()).unwrap().attribute_id, -1);
    }

    #[test]
    fn invoke_id_bits() {
        let i = InvokeId::confirmed(3);
        assert_eq!(i.id(), 3);
        assert!(i.is_confirmed());
        assert!(!i.is_high_priority());
        assert!(i.with_high_priority().is_high_priority());
        assert_eq!(i.0, 0x43);
    }

    #[test]
    fn long_invoke_id_bits() {
        let i = LongInvokeId::new(0x01_0203).confirmed();
        assert_eq!(i.id(), 0x01_0203);
        assert!(i.is_confirmed());
        assert!(!i.is_self_descriptive());
    }
}
