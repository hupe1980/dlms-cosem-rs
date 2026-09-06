//! The two ways a server refuses an APDU outright.

use crate::codec::{Decode, Encode, Reader, Result, Writer};

/// Why the APDU was not acceptable at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// The service is not allowed in the current association state.
    ServiceNotAllowed,
    /// The service is not one the server knows.
    ServiceUnknown,
    /// A code this crate does not name.
    Other(u8),
}

impl StateError {
    /// From the wire byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ServiceNotAllowed,
            2 => Self::ServiceUnknown,
            other => Self::Other(other),
        }
    }

    /// The wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ServiceNotAllowed => 1,
            Self::ServiceUnknown => 2,
            Self::Other(v) => v,
        }
    }
}

/// What about the APDU was unacceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceError {
    /// The operation cannot be performed.
    OperationNotPossible,
    /// The service is not supported.
    ServiceNotSupported,
    /// Unspecified.
    OtherReason,
    /// The APDU exceeded the negotiated maximum size.
    PduTooLong,
    /// The APDU could not be deciphered: wrong key, wrong system title, bad tag.
    DecipheringError,
    /// The invocation counter was not greater than the last one accepted.
    InvocationCounterError,
    /// A code this crate does not name.
    Other(u8),
}

impl ServiceError {
    /// From the wire byte.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::OperationNotPossible,
            2 => Self::ServiceNotSupported,
            3 => Self::OtherReason,
            4 => Self::PduTooLong,
            5 => Self::DecipheringError,
            6 => Self::InvocationCounterError,
            other => Self::Other(other),
        }
    }

    /// The wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::OperationNotPossible => 1,
            Self::ServiceNotSupported => 2,
            Self::OtherReason => 3,
            Self::PduTooLong => 4,
            Self::DecipheringError => 5,
            Self::InvocationCounterError => 6,
            Self::Other(v) => v,
        }
    }
}

/// The server refused the APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionResponse {
    /// The state that made it unacceptable.
    pub state_error: StateError,
    /// What was wrong.
    pub service_error: ServiceError,
    /// For [`ServiceError::InvocationCounterError`], the counter value the server
    /// expects next.
    ///
    /// A client may use it to resynchronise **deliberately**; doing so automatically
    /// would let anyone who can spoof one exception response replay an old frame.
    pub expected_invocation_counter: Option<u32>,
}

impl Encode for ExceptionResponse {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.state_error.as_u8())?;
        w.write_u8(self.service_error.as_u8())?;
        if let Some(ic) = self.expected_invocation_counter {
            w.write_u32(ic)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ExceptionResponse {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let state_error = StateError::from_u8(r.u8()?);
        let service_error = ServiceError::from_u8(r.u8()?);
        // The counter is only present for the counter error, and only in the later
        // editions that added it — so it is decoded when it is there and not required.
        let expected_invocation_counter =
            if service_error == ServiceError::InvocationCounterError && r.remaining() >= 4 {
                Some(r.u32()?)
            } else {
                None
            };
        Ok(Self { state_error, service_error, expected_invocation_counter })
    }
}

/// A service-level error carried as its own APDU, used mostly by the ACSE-era services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedServiceError {
    /// Which service failed, as its `[n]` choice tag.
    pub service: u8,
    /// The error class.
    pub error_class: u8,
    /// The error code within the class.
    pub error_code: u8,
}

impl Encode for ConfirmedServiceError {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_bytes(&[self.service, self.error_class, self.error_code])
    }

    fn encoded_len(&self) -> usize {
        3
    }
}

impl<'a> Decode<'a> for ConfirmedServiceError {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { service: r.u8()?, error_class: r.u8()?, error_code: r.u8()? })
    }
}
