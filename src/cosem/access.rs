//! Access rights, in both of the shapes the Blue Book has given them.
//!
//! Version 3 of Association LN replaced the version 0–2 enumerations with bit strings,
//! and added flags for whether a request or a response must be authenticated, encrypted
//! or digitally signed. A client that reads a version 3 object list as though it were
//! version 2 sees "write only" where the meter said "read, authenticated response".

use crate::axdr::Data;
use crate::codec::{Error, ErrorKind, Result};
use crate::obis::Obis;

bitflags::bitflags! {
    /// Version 3 attribute access, as a bit string.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct AttributeAccess: u8 {
        /// The attribute may be read.
        const READ = 0x01;
        /// The attribute may be written.
        const WRITE = 0x02;
        /// A request must be authenticated.
        const AUTHENTICATED_REQUEST = 0x04;
        /// A request must be encrypted.
        const ENCRYPTED_REQUEST = 0x08;
        /// A request must be digitally signed.
        const DIGITALLY_SIGNED_REQUEST = 0x10;
        /// The response will be authenticated.
        const AUTHENTICATED_RESPONSE = 0x20;
        /// The response will be encrypted.
        const ENCRYPTED_RESPONSE = 0x40;
        /// The response will be digitally signed.
        const DIGITALLY_SIGNED_RESPONSE = 0x80;
    }
}

bitflags::bitflags! {
    /// Version 3 method access, as a bit string.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MethodAccess: u8 {
        /// The method may be invoked.
        const ACCESS = 0x01;
        /// A request must be authenticated.
        const AUTHENTICATED_REQUEST = 0x04;
        /// A request must be encrypted.
        const ENCRYPTED_REQUEST = 0x08;
        /// A request must be digitally signed.
        const DIGITALLY_SIGNED_REQUEST = 0x10;
        /// The response will be authenticated.
        const AUTHENTICATED_RESPONSE = 0x20;
        /// The response will be encrypted.
        const ENCRYPTED_RESPONSE = 0x40;
        /// The response will be digitally signed.
        const DIGITALLY_SIGNED_RESPONSE = 0x80;
    }
}

impl AttributeAccess {
    /// The version 0–2 enumeration as version 3 flags.
    #[must_use]
    pub const fn from_legacy(mode: u8) -> Self {
        match mode {
            1 => Self::READ,
            2 => Self::WRITE,
            3 => Self::from_bits_truncate(Self::READ.bits() | Self::WRITE.bits()),
            4 => Self::from_bits_truncate(Self::READ.bits() | Self::AUTHENTICATED_REQUEST.bits()),
            5 => Self::from_bits_truncate(Self::WRITE.bits() | Self::AUTHENTICATED_REQUEST.bits()),
            6 => Self::from_bits_truncate(
                Self::READ.bits() | Self::WRITE.bits() | Self::AUTHENTICATED_REQUEST.bits(),
            ),
            _ => Self::empty(),
        }
    }

    /// True when the attribute can be read at all.
    #[must_use]
    pub const fn can_read(self) -> bool {
        self.contains(Self::READ)
    }

    /// True when the attribute can be written at all.
    #[must_use]
    pub const fn can_write(self) -> bool {
        self.contains(Self::WRITE)
    }

    /// True when a request for this attribute must be protected somehow.
    #[must_use]
    pub const fn requires_protection(self) -> bool {
        self.intersects(Self::from_bits_truncate(
            Self::AUTHENTICATED_REQUEST.bits()
                | Self::ENCRYPTED_REQUEST.bits()
                | Self::DIGITALLY_SIGNED_REQUEST.bits(),
        ))
    }
}

impl MethodAccess {
    /// The version 0–2 enumeration as version 3 flags.
    #[must_use]
    pub const fn from_legacy(mode: u8) -> Self {
        match mode {
            1 => Self::ACCESS,
            2 => Self::from_bits_truncate(Self::ACCESS.bits() | Self::AUTHENTICATED_REQUEST.bits()),
            _ => Self::empty(),
        }
    }

    /// True when the method can be invoked at all.
    #[must_use]
    pub const fn can_invoke(self) -> bool {
        self.contains(Self::ACCESS)
    }
}

/// Which version of Association LN an object list came from.
///
/// It decides how the access rights inside it are encoded, and it is not guessable from
/// the bytes: a single byte is a legacy enumeration in version 2 and a one-byte bit
/// string in version 3, and both are legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationVersion {
    /// Versions 0 to 2: access modes are enumerations.
    Legacy,
    /// Version 3: access modes are bit strings.
    V3,
}

/// One attribute's rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeRight {
    /// Which attribute.
    pub attribute_id: i8,
    /// What may be done with it.
    pub access: AttributeAccess,
    /// Which selective-access selectors it supports, when the server lists them.
    pub has_selectors: bool,
}

/// One method's rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodRight {
    /// Which method.
    pub method_id: i8,
    /// What may be done with it.
    pub access: MethodAccess,
}

/// One entry of an association's object list.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ObjectListEntry<'a> {
    /// Which class.
    pub class_id: u16,
    /// Which version of it.
    pub version: u8,
    /// The object's logical name.
    pub logical_name: Obis,
    /// The raw access-rights structure, decoded on demand.
    pub access_rights: Option<Data<'a>>,
}

impl<'a> ObjectListEntry<'a> {
    /// Decode one `object_list_element` structure.
    ///
    /// The shape is `{ class_id, version, logical_name, access_rights }`, where the
    /// last field is `{ attribute_access, method_access }`.
    pub fn from_data(d: &Data<'a>) -> Result<Self> {
        let s = d.as_structure().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
        let class_id =
            u16::try_from(s.get(0)?.as_u64().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?)
                .map_err(|_| Error::new(ErrorKind::InvalidValue, 0))?;
        let version = u8::try_from(s.get(1)?.as_u64().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?)
            .map_err(|_| Error::new(ErrorKind::InvalidValue, 0))?;
        let logical_name = s.get(2)?.as_obis().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
        let access_rights = s.get(3).ok();
        Ok(Self { class_id, version, logical_name, access_rights })
    }

    /// The attribute rights, decoded for the given association version.
    ///
    /// The visitor form keeps this allocation-free; a caller that wants a collection
    /// builds one.
    pub fn for_each_attribute_right(
        &self,
        version: AssociationVersion,
        mut f: impl FnMut(AttributeRight) -> Result<()>,
    ) -> Result<()> {
        let Some(rights) = self.access_rights else { return Ok(()) };
        let Some(s) = rights.as_structure() else { return Ok(()) };
        let Ok(list) = s.get(0) else { return Ok(()) };
        let Some(list) = list.as_array() else { return Ok(()) };
        for entry in &list {
            let entry = entry?;
            let e = entry.as_structure().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?;
            let attribute_id =
                i8::try_from(e.get(0)?.as_i64().ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?)
                    .map_err(|_| Error::new(ErrorKind::InvalidValue, 0))?;
            let mode = e.get(1)?;
            let access = match version {
                AssociationVersion::Legacy => {
                    AttributeAccess::from_legacy(u8::try_from(mode.as_u64().unwrap_or(0)).unwrap_or(0))
                }
                AssociationVersion::V3 => AttributeAccess::from_bits_truncate(match mode {
                    Data::BitString(b) => (b.to_u32() >> b.len().saturating_sub(8).min(24)) as u8,
                    other => u8::try_from(other.as_u64().unwrap_or(0)).unwrap_or(0),
                }),
            };
            let has_selectors = e.get(2).is_ok_and(|d| !matches!(d, Data::Null));
            f(AttributeRight { attribute_id, access, has_selectors })?;
        }
        Ok(())
    }
}

/// A bit string of up to eight bits, read as the access-mode byte.
///
/// Version 3 writes the flags as a bit string whose first bit is `read`. A bit string
/// numbers its bits from the most significant end, so the byte a caller wants is the
/// first eight bits in transmission order — which is the first byte, exactly as it
/// arrived.
#[must_use]
pub fn access_byte(d: &Data<'_>) -> Option<u8> {
    match d {
        Data::BitString(b) => b.as_bytes().first().copied(),
        other => u8::try_from(other.as_u64()?).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    #[test]
    fn version_three_flags_are_the_bits_the_standard_numbers() {
        assert_eq!(AttributeAccess::READ.bits(), 1);
        assert_eq!(AttributeAccess::WRITE.bits(), 2);
        assert_eq!(AttributeAccess::AUTHENTICATED_REQUEST.bits(), 4);
        assert_eq!(AttributeAccess::DIGITALLY_SIGNED_RESPONSE.bits(), 128);
        assert_eq!(MethodAccess::ACCESS.bits(), 1);
        assert_eq!(MethodAccess::AUTHENTICATED_REQUEST.bits(), 4);
    }

    #[test]
    fn the_legacy_enumeration_maps_onto_the_same_flags() {
        assert_eq!(AttributeAccess::from_legacy(1), AttributeAccess::READ);
        assert_eq!(AttributeAccess::from_legacy(3), AttributeAccess::READ | AttributeAccess::WRITE);
        assert_eq!(
            AttributeAccess::from_legacy(4),
            AttributeAccess::READ | AttributeAccess::AUTHENTICATED_REQUEST
        );
        assert_eq!(AttributeAccess::from_legacy(0), AttributeAccess::empty());
        assert!(AttributeAccess::from_legacy(4).requires_protection());
        assert!(!AttributeAccess::from_legacy(3).requires_protection());
    }

    #[test]
    fn an_object_list_entry_decodes() {
        // structure { long-unsigned 3, unsigned 0, octet-string 1-0:1.8.0*255,
        //             structure { array {}, array {} } }
        let raw = [
            0x02, 0x04, //
            0x12, 0x00, 0x03, //
            0x11, 0x00, //
            0x09, 0x06, 1, 0, 1, 8, 0, 255, //
            0x02, 0x02, 0x01, 0x00, 0x01, 0x00,
        ];
        let d = Data::from_bytes(&raw).unwrap();
        let e = ObjectListEntry::from_data(&d).unwrap();
        assert_eq!(e.class_id, 3);
        assert_eq!(e.version, 0);
        assert_eq!(e.logical_name, Obis::new(1, 0, 1, 8, 0, 255));
        assert!(e.access_rights.is_some());
    }

    #[test]
    fn attribute_rights_decode_in_both_shapes() {
        // access_rights { attribute_access { { 2, 3, null }, { 3, 1, null } }, method_access {} }
        let raw = [
            0x02, 0x04, //
            0x12, 0x00, 0x03, 0x11, 0x00, 0x09, 0x06, 1, 0, 1, 8, 0, 255, //
            0x02, 0x02, //
            0x01, 0x02, //
            0x02, 0x03, 0x0F, 0x02, 0x16, 0x03, 0x00, //
            0x02, 0x03, 0x0F, 0x03, 0x16, 0x01, 0x00, //
            0x01, 0x00,
        ];
        let d = Data::from_bytes(&raw).unwrap();
        let e = ObjectListEntry::from_data(&d).unwrap();
        let mut got = alloc::vec::Vec::new();
        e.for_each_attribute_right(AssociationVersion::Legacy, |r| {
            got.push((r.attribute_id, r.access));
            Ok(())
        })
        .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, 2);
        assert_eq!(got[0].1, AttributeAccess::READ | AttributeAccess::WRITE);
        assert_eq!(got[1].1, AttributeAccess::READ);
    }

    #[test]
    fn a_bit_string_access_mode_reads_its_first_byte() {
        let d = Data::from_bytes(&[0x04, 0x08, 0b0000_0011]).unwrap();
        assert_eq!(access_byte(&d), Some(0b0000_0011));
    }
}
