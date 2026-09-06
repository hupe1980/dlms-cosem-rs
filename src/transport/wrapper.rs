//! The wrapper — DLMS over TCP and UDP.
//!
//! Eight bytes in front of the APDU: a version, the sending and receiving service
//! access points, and a length. Over UDP one datagram is one wrapper PDU; over TCP the
//! layer must reassemble, because an APDU may arrive in as many segments as the network
//! feels like.

use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, Writer};

/// The only wrapper version defined.
pub const VERSION: u16 = 0x0001;

/// The port IANA assigned to DLMS.
pub const DEFAULT_PORT: u16 = 4059;

/// The eight-byte wrapper header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Always [`VERSION`].
    pub version: u16,
    /// The sender's service access point — the client SAP in a request.
    pub source: u16,
    /// The receiver's service access point — the logical device in a request.
    pub destination: u16,
    /// How many bytes of APDU follow.
    pub length: u16,
}

impl Header {
    /// A header for an APDU of `length` bytes.
    #[must_use]
    pub const fn new(source: u16, destination: u16, length: u16) -> Self {
        Self { version: VERSION, source, destination, length }
    }

    /// The header size, which is fixed.
    pub const LEN: usize = 8;
}

impl Encode for Header {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u16(self.version)?;
        w.write_u16(self.source)?;
        w.write_u16(self.destination)?;
        w.write_u16(self.length)
    }

    fn encoded_len(&self) -> usize {
        Self::LEN
    }
}

impl<'a> Decode<'a> for Header {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let version = r.u16()?;
        if version != VERSION {
            return Err(r.err_back(ErrorKind::InvalidValue, 2));
        }
        Ok(Self { version, source: r.u16()?, destination: r.u16()?, length: r.u16()? })
    }
}

/// A wrapper PDU: a header and the APDU it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wpdu<'a> {
    /// The header.
    pub header: Header,
    /// The APDU.
    pub apdu: &'a [u8],
}

impl<'a> Wpdu<'a> {
    /// A PDU carrying `apdu` between two service access points.
    ///
    /// # Errors
    /// When the APDU is longer than the sixteen-bit length field can describe.
    pub fn new(source: u16, destination: u16, apdu: &'a [u8]) -> Result<Self> {
        let length = u16::try_from(apdu.len()).map_err(|_| Error::new(ErrorKind::InvalidLength, 0))?;
        Ok(Self { header: Header::new(source, destination, length), apdu })
    }
}

impl Encode for Wpdu<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        self.header.encode(w)?;
        w.write_bytes(self.apdu)
    }

    fn encoded_len(&self) -> usize {
        Header::LEN + self.apdu.len()
    }
}

impl<'a> Decode<'a> for Wpdu<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        let header = Header::decode(r)?;
        let apdu = r.take(usize::from(header.length))?;
        Ok(Self { header, apdu })
    }
}

/// Reassembles wrapper PDUs from a TCP stream.
///
/// Holds no buffer of its own: the caller keeps the bytes and is told how many were
/// consumed, which is what lets the same code serve a `Vec` on a head-end and a fixed
/// array in firmware.
#[derive(Debug, Default, Clone, Copy)]
pub struct StreamReassembler {
    max_apdu: u16,
}

impl StreamReassembler {
    /// A reassembler that refuses any PDU claiming more than `max_apdu` bytes.
    ///
    /// The bound matters: the length field is attacker-controlled, and a peer that
    /// announces 65 535 bytes must not be able to make the caller hold that much before
    /// anything has been authenticated.
    #[must_use]
    pub const fn new(max_apdu: u16) -> Self {
        Self { max_apdu }
    }

    /// The next complete PDU in `buf`, and how many bytes it used.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidValue`] for a bad version, [`ErrorKind::InvalidLength`] when
    /// the announced length exceeds the configured maximum.
    pub fn next_pdu<'b>(&self, buf: &'b [u8]) -> Result<Option<(Wpdu<'b>, usize)>> {
        if buf.len() < Header::LEN {
            return Ok(None);
        }
        let header = Header::decode(&mut Reader::new(buf))?;
        if self.max_apdu != 0 && header.length > self.max_apdu {
            return Err(Error::new(ErrorKind::InvalidLength, 6));
        }
        let total = Header::LEN + usize::from(header.length);
        if buf.len() < total {
            return Ok(None);
        }
        Ok(Some((Wpdu { header, apdu: &buf[Header::LEN..total] }, total)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SliceWriter;

    #[test]
    fn the_header_is_eight_bytes_big_endian() {
        let w = Wpdu::new(0x0010, 0x0001, &[0xC0, 0x01, 0x81]).unwrap();
        let mut buf = [0u8; 32];
        let mut sw = SliceWriter::new(&mut buf);
        w.encode(&mut sw).unwrap();
        assert_eq!(sw.as_slice(), [0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x03, 0xC0, 0x01, 0x81]);
        assert_eq!(Wpdu::from_bytes(sw.as_slice()).unwrap(), w);
    }

    #[test]
    fn a_wrong_version_is_refused() {
        assert_eq!(
            Header::from_bytes(&[0x00, 0x02, 0, 0x10, 0, 1, 0, 0]).unwrap_err().kind,
            ErrorKind::InvalidValue
        );
    }

    #[test]
    fn the_reassembler_waits_for_every_byte() {
        let w = Wpdu::new(0x0010, 0x0001, &[0xAA; 20]).unwrap();
        let mut buf = [0u8; 64];
        let mut sw = SliceWriter::new(&mut buf);
        w.encode(&mut sw).unwrap();
        let n = sw.written();
        let r = StreamReassembler::new(1024);
        for split in 0..n {
            assert!(r.next_pdu(&buf[..split]).unwrap().is_none(), "cut at {split}");
        }
        let (pdu, used) = r.next_pdu(&buf[..n]).unwrap().unwrap();
        assert_eq!(used, n);
        assert_eq!(pdu.apdu.len(), 20);
    }

    #[test]
    fn an_oversized_announcement_is_refused_before_it_is_buffered() {
        let r = StreamReassembler::new(256);
        let header = [0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0xFF, 0xFF];
        assert_eq!(r.next_pdu(&header).unwrap_err().kind, ErrorKind::InvalidLength);
    }

    #[test]
    fn two_pdus_back_to_back_are_returned_one_at_a_time() {
        let mut stream = alloc::vec::Vec::new();
        for i in 0..2u8 {
            let body = [i, i, i];
            let w = Wpdu::new(0x0010, 0x0001, &body).unwrap();
            w.encode(&mut stream).unwrap();
        }
        let r = StreamReassembler::new(1024);
        let (first, used) = r.next_pdu(&stream).unwrap().unwrap();
        assert_eq!(first.apdu, &[0, 0, 0]);
        let (second, _) = r.next_pdu(&stream[used..]).unwrap().unwrap();
        assert_eq!(second.apdu, &[1, 1, 1]);
    }
}
