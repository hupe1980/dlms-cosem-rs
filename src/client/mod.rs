//! The client: a sans-I/O state machine that talks to a meter.
//!
//! The session produces APDU bytes and consumes APDU bytes. It owns no socket, no
//! clock and no buffer of the caller's, so the same code drives a head-end over TCP, an
//! optical probe over HDLC and a test that runs a whole association in microseconds.
//!
//! A ciphered association is not a separate type: the policy decides whether an APDU is
//! wrapped on the way out and unwrapped on the way in, and the state machine refuses a
//! response whose protection is weaker than the policy demands.

mod notify;
mod session;

pub use notify::{NotificationListener, PushKeyLookup, ReceivedNotification, SingleMeterKeys};
pub use session::{
    AccessItem, AssociationStep, BlockCollector, BlockSender, ClientConfig, ClientSession, Referencing,
    Response, SessionState,
};
