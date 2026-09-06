//! Push: the notification services.

use crate::axdr::{Data, DateTime};
use crate::codec::{Decode, Encode, ErrorKind, Reader, Result, Writer};

use super::descriptor::{AttributeDescriptor, LongInvokeId, decode_optional, encode_optional};

/// A date-time carried as an octet string that may be empty.
///
/// The notification services do not use the A-XDR `OPTIONAL` flag for their timestamp:
/// they send a zero-length octet string when there is none. A decoder that assumes
/// twelve bytes reads the notification body as a date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OptionalDateTime(pub Option<DateTime>);

impl Encode for OptionalDateTime {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        match self.0 {
            None => w.write_length(0),
            Some(dt) => w.write_length_prefixed(&dt.to_bytes()),
        }
    }

    fn encoded_len(&self) -> usize {
        if self.0.is_some() { 13 } else { 1 }
    }
}

impl<'a> Decode<'a> for OptionalDateTime {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = r.length_prefixed()?;
        match bytes.len() {
            0 => Ok(Self(None)),
            12 => Ok(Self(Some(DateTime::from_bytes(
                bytes.try_into().map_err(|_| r.err(ErrorKind::InvalidLength))?,
            )))),
            _ => Err(r.err(ErrorKind::InvalidLength)),
        }
    }
}

/// An unsolicited value sent by the server — the push service.
///
/// This is what a meter's customer interface emits: a `DataNotification` whose body is
/// a structure of the objects listed in its push setup. It is usually the only APDU a
/// listener ever sees, and it is usually ciphered.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataNotification<'a> {
    /// Identifies the notification; the confirmed variant expects it echoed back.
    pub long_invoke_id: LongInvokeId,
    /// When the values were captured, if the meter said.
    pub date_time: OptionalDateTime,
    /// The values.
    pub body: Data<'a>,
}

impl Encode for DataNotification<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u32(self.long_invoke_id.0)?;
        self.date_time.encode(w)?;
        self.body.encode(w)
    }
}

impl<'a> Decode<'a> for DataNotification<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            long_invoke_id: LongInvokeId(r.u32()?),
            date_time: OptionalDateTime::decode(r)?,
            body: Data::decode(r)?,
        })
    }
}

/// An unsolicited attribute value, named by its descriptor.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EventNotification<'a> {
    /// When it happened, if the meter said.
    pub time: Option<DateTime>,
    /// Which attribute changed.
    pub descriptor: AttributeDescriptor,
    /// Its value.
    pub value: Data<'a>,
}

/// A date-time wrapped so it encodes as a length-prefixed octet string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DateTimeOctets(DateTime);

impl Encode for DateTimeOctets {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_length_prefixed(&self.0.to_bytes())
    }
}

impl<'a> Decode<'a> for DateTimeOctets {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let bytes = r.length_prefixed()?;
        let arr: [u8; 12] = bytes.try_into().map_err(|_| r.err(ErrorKind::InvalidLength))?;
        Ok(Self(DateTime::from_bytes(arr)))
    }
}

impl Encode for EventNotification<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        encode_optional(w, self.time.map(DateTimeOctets).as_ref())?;
        self.descriptor.encode(w)?;
        self.value.encode(w)
    }
}

impl<'a> Decode<'a> for EventNotification<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let time = decode_optional::<DateTimeOctets>(r)?.map(|d| d.0);
        Ok(Self { time, descriptor: AttributeDescriptor::decode(r)?, value: Data::decode(r)? })
    }
}
