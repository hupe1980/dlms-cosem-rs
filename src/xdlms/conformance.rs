//! The conformance block.

use crate::codec::{Error, ErrorKind, Reader, Result, Writer};

bitflags::bitflags! {
    /// What a peer can do, negotiated when the association is established.
    ///
    /// The wire form is a 24-bit `BIT STRING` in which **bit 0 is transmitted first**,
    /// as the most significant bit of the first byte. The flag values here follow the
    /// specification's bit numbering — `GET` is bit 19 and so `1 << 19` — and
    /// [`Conformance::to_bytes`] does the reversal. Reading the three bytes as a
    /// big-endian integer instead is the classic way to end up proposing
    /// `unconfirmed-write` when you meant `action`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Conformance: u32 {
        /// Bit 0, reserved and always zero.
        const RESERVED_ZERO = 1 << 0;
        /// General protection: the `general-*ciphering` APDUs may be used.
        const GENERAL_PROTECTION = 1 << 1;
        /// General block transfer.
        const GENERAL_BLOCK_TRANSFER = 1 << 2;
        /// Short-name `Read`.
        const READ = 1 << 3;
        /// Short-name `Write`.
        const WRITE = 1 << 4;
        /// Short-name `UnconfirmedWrite`.
        const UNCONFIRMED_WRITE = 1 << 5;
        /// Delta value encoding in compact arrays (Green Book edition 10).
        const DELTA_VALUE_ENCODING = 1 << 6;
        /// Bit 7, reserved.
        const RESERVED_SEVEN = 1 << 7;
        /// `SET` may address attribute 0, meaning every attribute at once.
        const ATTRIBUTE0_SUPPORTED_WITH_SET = 1 << 8;
        /// The invoke-id priority field is honoured.
        const PRIORITY_MGMT_SUPPORTED = 1 << 9;
        /// `GET` may address attribute 0.
        const ATTRIBUTE0_SUPPORTED_WITH_GET = 1 << 10;
        /// Block transfer for `GET` and short-name `Read`.
        const BLOCK_TRANSFER_WITH_GET_OR_READ = 1 << 11;
        /// Block transfer for `SET` and short-name `Write`.
        const BLOCK_TRANSFER_WITH_SET_OR_WRITE = 1 << 12;
        /// Block transfer for `ACTION`.
        const BLOCK_TRANSFER_WITH_ACTION = 1 << 13;
        /// `with-list` variants may name more than one object.
        const MULTIPLE_REFERENCES = 1 << 14;
        /// Short-name `InformationReport`.
        const INFORMATION_REPORT = 1 << 15;
        /// `DataNotification` — the push service.
        const DATA_NOTIFICATION = 1 << 16;
        /// The `ACCESS` service.
        const ACCESS = 1 << 17;
        /// Short-name parameterised access.
        const PARAMETERIZED_ACCESS = 1 << 18;
        /// The `GET` service.
        const GET = 1 << 19;
        /// The `SET` service.
        const SET = 1 << 20;
        /// Selective access descriptors.
        const SELECTIVE_ACCESS = 1 << 21;
        /// `EventNotification`.
        const EVENT_NOTIFICATION = 1 << 22;
        /// The `ACTION` service.
        const ACTION = 1 << 23;
    }
}

impl Conformance {
    /// What a logical-name client normally proposes: the three services and ACCESS,
    /// selective access, block transfer in every direction, multiple references,
    /// notifications, and the general protection wrappers.
    ///
    /// Every bit here is a service this crate drives. A conformance block is a promise
    /// about behaviour, and proposing a service the code does not implement is how a
    /// peer is invited to use one.
    pub const CLIENT_DEFAULT: Self = Self::from_bits_truncate(
        Self::ACCESS.bits()
            | Self::GENERAL_PROTECTION.bits()
            | Self::GET.bits()
            | Self::SET.bits()
            | Self::ACTION.bits()
            | Self::SELECTIVE_ACCESS.bits()
            | Self::MULTIPLE_REFERENCES.bits()
            | Self::BLOCK_TRANSFER_WITH_GET_OR_READ.bits()
            | Self::BLOCK_TRANSFER_WITH_SET_OR_WRITE.bits()
            | Self::BLOCK_TRANSFER_WITH_ACTION.bits()
            | Self::ATTRIBUTE0_SUPPORTED_WITH_GET.bits()
            | Self::PRIORITY_MGMT_SUPPORTED.bits()
            | Self::EVENT_NOTIFICATION.bits()
            | Self::DATA_NOTIFICATION.bits(),
    );

    /// What a logical-name server normally offers.
    ///
    /// The same services, without the two notification bits: a `DataNotification` or
    /// `EventNotification` is something a *server* sends, so offering them back in the
    /// negotiated block says nothing about what the server will accept and everything
    /// about what it may emit — which is the client's half of the intersection.
    pub const SERVER_DEFAULT: Self = Self::from_bits_truncate(
        Self::GET.bits()
            | Self::SET.bits()
            | Self::ACTION.bits()
            | Self::SELECTIVE_ACCESS.bits()
            | Self::MULTIPLE_REFERENCES.bits()
            | Self::BLOCK_TRANSFER_WITH_GET_OR_READ.bits()
            | Self::BLOCK_TRANSFER_WITH_SET_OR_WRITE.bits()
            | Self::BLOCK_TRANSFER_WITH_ACTION.bits()
            | Self::ATTRIBUTE0_SUPPORTED_WITH_GET.bits()
            | Self::PRIORITY_MGMT_SUPPORTED.bits()
            | Self::ACCESS.bits()
            | Self::GENERAL_PROTECTION.bits(),
    );

    /// The three wire bytes.
    ///
    /// The conformance block is a BIT STRING, so conformance bit *n* is the *n*-th bit
    /// counted from the most significant bit of the first byte — the opposite order to
    /// the `u32` the flags live in. That is a 24-bit reversal, which is one instruction
    /// rather than a loop that indexes an array and leaves the compiler to prove the
    /// index is in range.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 3] {
        let r = self.bits().reverse_bits() >> 8;
        [(r >> 16) as u8, (r >> 8) as u8, r as u8]
    }

    /// From the three wire bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 3]) -> Self {
        let v = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        Self::from_bits_truncate((v << 8).reverse_bits())
    }

    /// Encode with the `[APPLICATION 31]` tag the InitiateRequest carries it under.
    pub fn encode_tagged(self, w: &mut dyn Writer) -> Result<()> {
        w.write_bytes(&[0x5F, 0x1F, 0x04, 0x00])?;
        w.write_bytes(&self.to_bytes())
    }

    /// Decode the `[APPLICATION 31]` form.
    pub fn decode_tagged(r: &mut Reader<'_>) -> Result<Self> {
        let t0 = r.u8()?;
        let t1 = r.u8()?;
        if t0 != 0x5F || t1 != 0x1F {
            return Err(r.err_back(ErrorKind::InvalidTag(t0), 2));
        }
        let len = r.u8()?;
        if len != 4 {
            return Err(r.err_back(ErrorKind::InvalidLength, 1));
        }
        let unused = r.u8()?;
        if unused != 0 {
            return Err(r.err_back(ErrorKind::InvalidValue, 1));
        }
        Ok(Self::from_bytes(r.array()?))
    }

    /// The services both sides can do.
    #[must_use]
    pub const fn negotiate(self, other: Self) -> Self {
        Self::from_bits_truncate(self.bits() & other.bits())
    }

    /// Fail unless every flag in `required` is present.
    ///
    /// Called before encoding anything the peer did not agree to, so a client cannot
    /// send an APDU the server said it does not understand.
    pub fn require(self, required: Self) -> Result<()> {
        if self.contains(required) { Ok(()) } else { Err(Error::new(ErrorKind::UnexpectedMessage, 0)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_zero_is_the_most_significant_bit_of_the_first_byte() {
        assert_eq!(Conformance::RESERVED_ZERO.to_bytes(), [0x80, 0x00, 0x00]);
        assert_eq!(Conformance::ACTION.to_bytes(), [0x00, 0x00, 0x01]);
        assert_eq!(Conformance::GET.to_bytes(), [0x00, 0x00, 0x10]);
    }

    #[test]
    fn the_conformance_meters_actually_send() {
        // 00 7E 1F is the block a great many logical-name meters negotiate.
        let c = Conformance::from_bytes([0x00, 0x7E, 0x1F]);
        assert!(c.contains(Conformance::GET));
        assert!(c.contains(Conformance::SET));
        assert!(c.contains(Conformance::ACTION));
        assert!(c.contains(Conformance::SELECTIVE_ACCESS));
        assert!(c.contains(Conformance::EVENT_NOTIFICATION));
        assert!(c.contains(Conformance::MULTIPLE_REFERENCES));
        assert!(c.contains(Conformance::BLOCK_TRANSFER_WITH_GET_OR_READ));
        assert!(!c.contains(Conformance::READ), "short-name services are not offered");
        assert!(!c.contains(Conformance::DATA_NOTIFICATION));
        assert_eq!(c.to_bytes(), [0x00, 0x7E, 0x1F]);
    }

    #[test]
    fn every_single_bit_round_trips() {
        for n in 0..24 {
            let c = Conformance::from_bits_truncate(1 << n);
            assert_eq!(Conformance::from_bytes(c.to_bytes()), c, "bit {n}");
        }
    }

    #[test]
    fn negotiation_is_intersection() {
        let client = Conformance::GET | Conformance::SET | Conformance::ACTION;
        let server = Conformance::GET | Conformance::ACTION;
        assert_eq!(client.negotiate(server), Conformance::GET | Conformance::ACTION);
        assert!(client.negotiate(server).require(Conformance::SET).is_err());
    }

    #[test]
    fn the_tagged_form_is_what_initiate_carries() {
        let mut buf = [0u8; 8];
        let mut w = crate::codec::SliceWriter::new(&mut buf);
        Conformance::from_bytes([0x00, 0x7E, 0x1F]).encode_tagged(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F]);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(Conformance::decode_tagged(&mut r).unwrap().to_bytes(), [0x00, 0x7E, 0x1F]);
    }
}
