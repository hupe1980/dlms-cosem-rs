//! The DLMS application layer: every APDU, and the services they carry.
//!
//! [`Apdu`] is one enum over every tag the layer defines. Decoding never fails merely
//! because a message is protected: a ciphered service decodes with its security header
//! intact, so a translator, a fuzzer or a router can handle it without a key, and
//! [`crate::security`] turns one back into a plain APDU.
//!
//! Three things here are worth knowing before reading the types:
//!
//! * **The conformance block is negotiated, and then enforced.** Every service checks it
//!   before encoding, so a client cannot send an APDU the server said it does not
//!   understand.
//! * **`with-list` is about latency, not bytes.** The batched forms answer with one
//!   result per item, so a denied object costs its own slot instead of the whole exchange.
//! * **Two segmentation mechanisms live here and they are not alternatives.** Block
//!   transfer cuts a *value* into APDUs; [`GbtSender`] and [`GbtReceiver`] cut an *APDU*
//!   into blocks whatever service it carries. HDLC's, which cuts an APDU into frames, is a
//!   third and is in [`crate::transport::hdlc`].

mod access;
mod apdu;
mod conformance;
mod descriptor;
mod error;
mod gbt;
mod initiate;
mod notify;
mod protection;
mod result;
mod service;
mod tag;

pub use access::{
    AccessRequest, AccessRequestSpecification, AccessResponse, AccessResponseSpecification, MAX_ACCESS_ITEMS,
};
pub use apdu::Apdu;
pub use conformance::Conformance;
pub use descriptor::{
    AttributeDescriptor, AttributeDescriptorWithSelection, InvokeId, LongInvokeId, MethodDescriptor,
    SelectiveAccess,
};
pub use error::{ConfirmedServiceError, ExceptionResponse, ServiceError, StateError};
pub use gbt::{BlockControl, GBT_WINDOW_MAX, GbtAction, GbtReceiver, GbtSender, GeneralBlockTransfer};
pub use initiate::{DLMS_VERSION, InitiateRequest, InitiateResponse, VAA_NAME_LN};
pub use notify::{DataNotification, EventNotification, OptionalDateTime};
pub use protection::{
    CipheredService, GeneralCiphering, GeneralGloCiphering, GeneralSigning, KeyInfo, SecurityControl,
};
pub use result::{ActionResult, DataAccessResult, DataBlockG, DataBlockSA, GetDataResult, List};
pub use service::{
    ActionRequest, ActionResponse, ActionResponseWithOptionalData, GetRequest, GetResponse, SetRequest,
    SetResponse,
};
pub use tag::{ApduTag, Protection};
