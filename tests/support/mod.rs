//! A meter, small enough to read and complete enough to talk to.

use dlms_cosem_rs::axdr::{Data, DateTime, Unit};
use dlms_cosem_rs::codec::{Encode, Writer};
use dlms_cosem_rs::cosem::{AttributeAccess, MethodAccess};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::server::{AuditEvent, ObjectStore, StoreResult};
use dlms_cosem_rs::xdlms::{ActionResult, DataAccessResult, SelectiveAccess};

pub const ENERGY: Obis = Obis::new(1, 0, 1, 8, 0, 255);
pub const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255);
pub const BREAKER: Obis = Obis::new(0, 0, 96, 3, 10, 255);
pub const SECRET_LOG: Obis = Obis::new(0, 0, 99, 98, 0, 255);
pub const LOAD_PROFILE: Obis = Obis::new(1, 0, 99, 1, 0, 255);
/// An image-transfer-shaped object: one large octet string that can be written whole and
/// read back. Big enough that neither direction fits an ordinary PDU, which is the only
/// way to exercise block transfer for SET and for an ACTION parameter.
pub const IMAGE: Obis = Obis::new(0, 0, 44, 0, 0, 255);
/// An object whose store implementation is **wrong**: it reports success and writes
/// nothing. Every real store has this bug once, and the response it would produce is
/// malformed rather than merely wrong — a choice byte with no value behind it.
pub const BROKEN: Obis = Obis::new(0, 0, 96, 90, 0, 255);

/// How many rows the test load profile holds.
///
/// Chosen so the encoded buffer is several times any sensible PDU size: reading it is
/// only possible over block transfer, which is the point.
pub const PROFILE_ROWS: usize = 120;

/// A meter with one register, a clock, a breaker and one object nobody may read.
#[derive(Debug, Clone)]
pub struct TestMeter {
    pub energy_wh: i64,
    pub time: DateTime,
    pub breaker_closed: bool,
    pub breaker_operations: u32,
    /// The image-transfer blob, written and read back whole.
    pub image: Vec<u8>,
    /// The selector of the last selective-access descriptor a write carried, if any.
    ///
    /// A blocked SET carries its selector in the *first* block and needs it at the
    /// *last*, so this is how a test proves the descriptor survived in between rather
    /// than being quietly dropped — which is a write that lands somewhere else and says
    /// nothing about it.
    pub last_write_selector: Option<u8>,
    /// Everything the server was asked to do, in order.
    pub trail: Vec<AuditEvent>,
}

impl Default for TestMeter {
    fn default() -> Self {
        Self {
            energy_wh: 12_345_678,
            time: DateTime::from_civil(2026, 9, 6, 12, 0, 0, 120),
            breaker_closed: true,
            breaker_operations: 0,
            image: Vec::new(),
            last_write_selector: None,
            trail: Vec::new(),
        }
    }
}

impl ObjectStore for TestMeter {
    fn get_attribute(
        &self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        _selective_access: Option<SelectiveAccess<'_>>,
        w: &mut dyn Writer,
    ) -> StoreResult<()> {
        match (class_id, logical_name, attribute_id) {
            (_, SECRET_LOG, _) => Err(DataAccessResult::ScopeOfAccessViolated),
            (_, name, 1) => {
                Data::OctetString(name.as_bytes()).encode(w).map_err(|_| DataAccessResult::OtherReason)
            }
            (3, ENERGY, 2) => Data::DoubleLongUnsigned(self.energy_wh as u32)
                .encode(w)
                .map_err(|_| DataAccessResult::OtherReason),
            (3, ENERGY, 3) => w
                .write_bytes(&[0x02, 0x02, 0x0F, 0x00, 0x16, Unit::WATT_HOUR.0])
                .map_err(|_| DataAccessResult::OtherReason),
            (8, CLOCK, 2) => Data::DateTime(self.time).encode(w).map_err(|_| DataAccessResult::OtherReason),
            (70, BREAKER, 2) => {
                Data::Boolean(self.breaker_closed).encode(w).map_err(|_| DataAccessResult::OtherReason)
            }
            // A load profile: an array of `structure { double-long-unsigned, long-unsigned }`.
            // Far too large for one APDU, which is exactly what a real one is.
            (7, LOAD_PROFILE, 2) => {
                let bad = |_| DataAccessResult::OtherReason;
                // Selector 2 selects a range of entries by position, counting from one.
                // A meter that ignored it would answer a day's read with a year's data.
                let (from, to) = match _selective_access {
                    Some(sa) if sa.selector == 2 => {
                        let s = sa.parameters.as_structure().ok_or(DataAccessResult::TypeUnmatched)?;
                        let from = s.get(0).map_err(|_| DataAccessResult::TypeUnmatched)?;
                        let to = s.get(1).map_err(|_| DataAccessResult::TypeUnmatched)?;
                        let from = from.as_u64().ok_or(DataAccessResult::TypeUnmatched)? as usize;
                        let to = to.as_u64().ok_or(DataAccessResult::TypeUnmatched)? as usize;
                        // Entry zero is not a position; "to" of zero means "to the end".
                        if from == 0 {
                            return Err(DataAccessResult::TypeUnmatched);
                        }
                        (from - 1, if to == 0 { PROFILE_ROWS } else { to.min(PROFILE_ROWS) })
                    }
                    // Any other selector is one this meter does not offer.
                    Some(_) => return Err(DataAccessResult::ScopeOfAccessViolated),
                    None => (0, PROFILE_ROWS),
                };
                if from > to {
                    return Err(DataAccessResult::TypeUnmatched);
                }
                w.write_u8(0x01).map_err(bad)?;
                w.write_length(to - from).map_err(bad)?;
                for i in from..to {
                    w.write_bytes(&[0x02, 0x02]).map_err(bad)?;
                    Data::DoubleLongUnsigned(1_000_000 + i as u32).encode(w).map_err(bad)?;
                    Data::LongUnsigned((i * 7 % 1000) as u16).encode(w).map_err(bad)?;
                }
                Ok(())
            }
            (18, IMAGE, 2) => {
                Data::OctetString(&self.image).encode(w).map_err(|_| DataAccessResult::OtherReason)
            }
            // Reports success, writes nothing. Deliberately.
            (_, BROKEN, 2) => Ok(()),
            (_, _, _) => Err(DataAccessResult::ObjectUndefined),
        }
    }

    fn set_attribute(
        &mut self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        selective_access: Option<SelectiveAccess<'_>>,
        value: Data<'_>,
    ) -> StoreResult<()> {
        self.last_write_selector = selective_access.map(|sa| sa.selector);
        match (class_id, logical_name, attribute_id) {
            (8, CLOCK, 2) => match value {
                Data::DateTime(dt) => {
                    self.time = dt;
                    Ok(())
                }
                Data::OctetString(b) if b.len() == 12 => {
                    self.time = DateTime::from_bytes(b.try_into().unwrap());
                    Ok(())
                }
                _ => Err(DataAccessResult::TypeUnmatched),
            },
            (18, IMAGE, 2) => match value {
                Data::OctetString(b) => {
                    self.image.clear();
                    self.image.extend_from_slice(b);
                    Ok(())
                }
                _ => Err(DataAccessResult::TypeUnmatched),
            },
            _ => Err(DataAccessResult::ReadWriteDenied),
        }
    }

    fn invoke_method(
        &mut self,
        class_id: u16,
        logical_name: Obis,
        method_id: i8,
        _parameters: Option<Data<'_>>,
        w: &mut dyn Writer,
    ) -> Result<bool, ActionResult> {
        match (class_id, logical_name, method_id) {
            (70, BREAKER, 1) => {
                self.breaker_closed = false;
                self.breaker_operations += 1;
                Ok(false)
            }
            (70, BREAKER, 2) => {
                self.breaker_closed = true;
                self.breaker_operations += 1;
                Ok(false)
            }
            (3, ENERGY, 1) => {
                self.energy_wh = 0;
                Data::DoubleLongUnsigned(0).encode(w).map_err(|_| ActionResult::OtherReason)?;
                Ok(true)
            }
            // Claims a return value and writes none. Deliberately.
            (_, BROKEN, 1) => Ok(true),
            // Take a blob as a parameter and give it straight back, so one call
            // exercises a long parameter and a long return value at once.
            (18, IMAGE, 1) => {
                let Some(Data::OctetString(b)) = _parameters else {
                    return Err(ActionResult::TypeUnmatched);
                };
                self.image.clear();
                self.image.extend_from_slice(b);
                Data::OctetString(&self.image).encode(w).map_err(|_| ActionResult::OtherReason)?;
                Ok(true)
            }
            _ => Err(ActionResult::ObjectUndefined),
        }
    }

    fn attribute_access(&self, _class_id: u16, logical_name: Obis, attribute_id: i8) -> AttributeAccess {
        if logical_name == SECRET_LOG {
            return AttributeAccess::empty();
        }
        if (logical_name == CLOCK || logical_name == IMAGE) && attribute_id == 2 {
            return AttributeAccess::READ | AttributeAccess::WRITE;
        }
        AttributeAccess::READ
    }

    fn method_access(&self, _class_id: u16, logical_name: Obis, _method_id: i8) -> MethodAccess {
        if logical_name == BREAKER
            || logical_name == ENERGY
            || logical_name == IMAGE
            || logical_name == BROKEN
        {
            MethodAccess::ACCESS
        } else {
            MethodAccess::empty()
        }
    }

    fn audit(&mut self, event: AuditEvent) {
        self.trail.push(event);
    }

    /// The short-name table this meter publishes.
    ///
    /// Base names are this device's own choice; the method offsets are the ones the
    /// class tables give, which a meter knows because it implements the classes. A
    /// client learns the base names by reading the `Association SN` object list.
    #[cfg(feature = "sn")]
    fn resolve_short_name(&self, name: u16) -> Option<dlms_cosem_rs::cosem::ShortNameTarget> {
        dlms_cosem_rs::cosem::sn::resolve(SHORT_NAMES, name)
    }
}

/// Where each of this meter's objects sits in short-name space.
///
/// Deliberately not contiguous, and deliberately including one object with a method: the
/// interesting failures are a name that falls between two objects and a name that lands
/// in a method block.
#[cfg(feature = "sn")]
pub const SHORT_NAMES: &[dlms_cosem_rs::cosem::ShortName] = &[
    // Register, three attributes, `reset` at x + 0x28.
    dlms_cosem_rs::cosem::ShortName::new(0x0028, 3, ENERGY, 3).with_methods(0x28, 1),
    // Clock, nine attributes, whose methods this meter does not expose.
    dlms_cosem_rs::cosem::ShortName::new(0x0100, 8, CLOCK, 9),
    // Disconnect control: two attributes here, `remote_disconnect` at x + 0x28.
    dlms_cosem_rs::cosem::ShortName::new(0x0200, 70, BREAKER, 2).with_methods(0x28, 2),
    // Profile generic, whose buffer is far larger than any PDU.
    dlms_cosem_rs::cosem::ShortName::new(0x0300, 7, LOAD_PROFILE, 8),
    // The object nobody may read, so a refusal has somewhere to come from.
    dlms_cosem_rs::cosem::ShortName::new(0x0400, 1, SECRET_LOG, 2),
];
