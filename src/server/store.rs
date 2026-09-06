//! Where a server's objects live.

use crate::axdr::Data;
use crate::codec::Writer;
use crate::cosem::{AttributeAccess, MethodAccess};
use crate::obis::Obis;
use crate::xdlms::{ActionResult, DataAccessResult, SelectiveAccess};

/// What a store returns.
pub type StoreResult<T> = core::result::Result<T, DataAccessResult>;

/// The objects a server hosts.
///
/// An implementation answers three questions per object — what may be done with it,
/// what it holds, and what happens when a method is invoked — and nothing else.
/// Associations, authentication, access control, protection and framing are the
/// framework's, which is what lets the same store back a meter's flash and a
/// simulator's memory.
pub trait ObjectStore {
    /// Write the attribute's value into `w` as A-XDR `Data`.
    ///
    /// Writing straight into the response buffer is what keeps a large attribute —
    /// a profile buffer of thousands of rows — from existing twice.
    ///
    /// **`Ok(())` means something was written.** Returning it after writing nothing is
    /// the bug every store has once, and the response it would produce is a
    /// `get-data-result` choice byte with no value behind it — undecodable rather than
    /// merely wrong, and inside a batched read it would shift every later answer onto the
    /// wrong attribute. The server checks and answers
    /// [`DataAccessResult::OtherReason`] for that item rather than building it.
    ///
    /// # Errors
    /// A [`DataAccessResult`] the server sends back verbatim.
    fn get_attribute(
        &self,
        class_id: u16,
        logical_name: Obis,
        attribute_id: i8,
        selective_access: Option<SelectiveAccess<'_>>,
        w: &mut dyn Writer,
    ) -> StoreResult<()>;

    /// Write an attribute.
    ///
    /// # Errors
    /// A [`DataAccessResult`] the server sends back verbatim.
    fn set_attribute(
        &mut self,
        _class_id: u16,
        _logical_name: Obis,
        _attribute_id: i8,
        _selective_access: Option<SelectiveAccess<'_>>,
        _value: Data<'_>,
    ) -> StoreResult<()> {
        Err(DataAccessResult::ReadWriteDenied)
    }

    /// Invoke a method, writing any return value into `w`.
    ///
    /// Returns whether anything was written — and `Ok(true)` must mean it, for the same
    /// reason [`ObjectStore::get_attribute`]'s `Ok(())` must. A method that claims a
    /// return value and writes none is answered with [`ActionResult::OtherReason`].
    ///
    /// # Errors
    /// An [`ActionResult`] the server sends back verbatim.
    fn invoke_method(
        &mut self,
        _class_id: u16,
        _logical_name: Obis,
        _method_id: i8,
        _parameters: Option<Data<'_>>,
        _w: &mut dyn Writer,
    ) -> core::result::Result<bool, ActionResult> {
        Err(ActionResult::ObjectUndefined)
    }

    /// What this association may do with an attribute.
    ///
    /// The default refuses everything, so a store that forgets to implement it exposes
    /// nothing rather than everything.
    fn attribute_access(&self, _class_id: u16, _logical_name: Obis, _attribute_id: i8) -> AttributeAccess {
        AttributeAccess::empty()
    }

    /// What this association may do with a method.
    fn method_access(&self, _class_id: u16, _logical_name: Obis, _method_id: i8) -> MethodAccess {
        MethodAccess::empty()
    }

    /// Record what the server was asked to do and what came of it.
    ///
    /// Called for every association attempt, every attribute read and write and every
    /// method invocation, **after** the outcome is known and including the refusals —
    /// the framework decides access, so a store that only saw the calls it was asked to
    /// service would never learn that anything had been denied.
    ///
    /// The default does nothing, so a store that does not want a trail pays nothing for
    /// one. It lives here rather than behind a separate generic parameter because
    /// auditing and serving are the same object's business: a meter that records a
    /// breaker operation wants it in the same flash transaction as the operation.
    ///
    /// This is not a write-ahead log. The event is recorded after the fact, so a device
    /// that must have the record on disk *before* the relay moves has to do that inside
    /// [`ObjectStore::invoke_method`], where it has the ordering guarantee.
    fn audit(&mut self, _event: AuditEvent) {}
}

/// What a server was asked to do, and what came of it.
///
/// Every variant carries its **outcome**, because an audit trail that records only what
/// succeeded is the wrong half: after an incident the question is almost always which
/// refusals happened and in what order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEvent {
    /// An association was established, and with which authentication.
    Associated {
        /// How the client proved who it was.
        mechanism: crate::acse::AuthMechanism,
        /// Whether the association's APDUs are protected.
        ciphered: bool,
    },
    /// An association was refused, and why.
    AssociationRefused {
        /// What the AARE told the client.
        diagnostic: crate::acse::UserDiagnostic,
    },
    /// An association was released or reset.
    Released,
    /// An attribute was read, or refused.
    AttributeRead {
        /// Which class.
        class_id: u16,
        /// Which object.
        logical_name: Obis,
        /// Which attribute.
        attribute_id: i8,
        /// What the client was told.
        outcome: DataAccessResult,
    },
    /// An attribute was written, or refused.
    AttributeWritten {
        /// Which class.
        class_id: u16,
        /// Which object.
        logical_name: Obis,
        /// Which attribute.
        attribute_id: i8,
        /// What the client was told.
        outcome: DataAccessResult,
    },
    /// A method was invoked, or refused. Every one of these is worth recording: this is
    /// where a breaker opens.
    MethodInvoked {
        /// Which class.
        class_id: u16,
        /// Which object.
        logical_name: Obis,
        /// Which method.
        method_id: i8,
        /// What the client was told.
        outcome: ActionResult,
    },
}
