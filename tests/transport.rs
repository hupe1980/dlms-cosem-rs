//! The same association, carried over a real transport.
//!
//! The application layer does not know what carries it, which is the claim this file
//! checks: the identical client and server drive an HDLC link and a wrapper stream, and
//! the bytes on each are what that transport's specification says they should be.

mod support;

use dlms_cosem_rs::client::{AssociationStep, BlockCollector, ClientConfig, ClientSession, Response};
use dlms_cosem_rs::codec::{Encode, SliceWriter, Writer};
use dlms_cosem_rs::security::{FixedRandom, KeyRing, RustCryptoProvider};
use dlms_cosem_rs::server::{Server, ServerConfig};
use dlms_cosem_rs::transport::hdlc::{
    self, Address, Control, Found, Frame, Framer, LLC_REQUEST, LLC_RESPONSE, Parameters, Reassembler,
    Segmenter,
};
use dlms_cosem_rs::transport::wrapper::{DEFAULT_PORT, StreamReassembler, Wpdu};
use dlms_cosem_rs::xdlms::AttributeDescriptor;
use support::{ENERGY, LOAD_PROFILE, PROFILE_ROWS, TestMeter};

type Client = ClientSession<RustCryptoProvider<FixedRandom>>;
type Meter = Server<TestMeter, RustCryptoProvider<FixedRandom>>;

fn pair() -> (Client, Meter) {
    (
        ClientSession::new(
            ClientConfig::default(),
            RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
        ),
        Server::new(
            ServerConfig::default(),
            TestMeter::default(),
            RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
        ),
    )
}

/// A half-duplex HDLC link with a client and a server address.
struct Link {
    client: Address,
    server: Address,
    ns: u8,
    nr: u8,
}

impl Link {
    fn new() -> Self {
        Self { client: Address::client(0x10), server: Address::server(1, 17), ns: 0, nr: 0 }
    }

    /// Wrap an APDU as an information frame with the LLC header a client sends.
    fn request(&mut self, apdu: &[u8], out: &mut [u8]) -> usize {
        let mut info = [0u8; 512];
        info[..3].copy_from_slice(&LLC_REQUEST);
        info[3..3 + apdu.len()].copy_from_slice(apdu);
        let frame = Frame {
            segmented: false,
            destination: self.server,
            source: self.client,
            control: Control::I { ns: self.ns, nr: self.nr, pf: true },
            information: &info[..3 + apdu.len()],
        };
        self.ns = (self.ns + 1) % 8;
        let mut w = SliceWriter::new(out);
        frame.encode(&mut w).unwrap();
        w.written()
    }

    /// Wrap an APDU as the server's answer.
    fn response(&mut self, apdu: &[u8], out: &mut [u8]) -> usize {
        let mut info = [0u8; 512];
        info[..3].copy_from_slice(&LLC_RESPONSE);
        info[3..3 + apdu.len()].copy_from_slice(apdu);
        let frame = Frame {
            segmented: false,
            destination: self.client,
            source: self.server,
            control: Control::I { ns: self.nr, nr: self.ns, pf: true },
            information: &info[..3 + apdu.len()],
        };
        self.nr = (self.nr + 1) % 8;
        let mut w = SliceWriter::new(out);
        frame.encode(&mut w).unwrap();
        w.written()
    }
}

/// Strip the frame and the LLC header, returning the APDU.
fn unwrap_frame(bytes: &[u8], expect_llc: [u8; 3]) -> Vec<u8> {
    let mut framer = Framer::new();
    let Found::Frame { frame, consumed } = framer.next_frame(bytes).unwrap() else {
        panic!("a complete frame");
    };
    assert_eq!(consumed, bytes.len(), "the frame used the whole buffer");
    assert_eq!(&frame.information[..3], &expect_llc, "the LLC header names the direction");
    frame.information[3..].to_vec()
}

#[test]
fn an_association_runs_over_hdlc() {
    let (mut client, mut server) = pair();
    let mut link = Link::new();
    let mut apdu = [0u8; 512];
    let mut wire = [0u8; 512];
    let mut plain = [0u8; 512];

    // SNRM and UA come first: the link is opened and its parameters negotiated before
    // a single APDU crosses it.
    let mut snrm_info = [0u8; 32];
    let mut iw = SliceWriter::new(&mut snrm_info);
    let proposed = Parameters { max_info_tx: 512, max_info_rx: 512, window_tx: 1, window_rx: 1 };
    proposed.encode(&mut iw).unwrap();
    let n = iw.written();
    let snrm = Frame {
        segmented: false,
        destination: link.server,
        source: link.client,
        control: Control::Snrm,
        information: &snrm_info[..n],
    };
    let mut w = SliceWriter::new(&mut wire);
    snrm.encode(&mut w).unwrap();
    let (decoded, _) = hdlc::decode_frame(w.as_slice()).unwrap();
    assert_eq!(decoded.control, Control::Snrm);
    let peer = Parameters::decode(decoded.information).unwrap();
    let negotiated = proposed.negotiate(peer);
    assert_eq!(negotiated.max_info_tx, 512);

    // AARQ.
    let n = client.associate_request(&mut apdu).unwrap();
    let n = link.request(&apdu[..n], &mut wire);
    let got = unwrap_frame(&wire[..n], LLC_REQUEST);
    let m = server.handle(&got, &mut apdu).unwrap();
    let m = link.response(&apdu[..m], &mut wire);
    let got = unwrap_frame(&wire[..m], LLC_RESPONSE);
    assert_eq!(client.handle_associate_response(&got).unwrap(), AssociationStep::Established);

    // A read.
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut apdu).unwrap();
    let n = link.request(&apdu[..n], &mut wire);
    let got = unwrap_frame(&wire[..n], LLC_REQUEST);
    let m = server.handle(&got, &mut apdu).unwrap();
    let m = link.response(&apdu[..m], &mut wire);
    let got = unwrap_frame(&wire[..m], LLC_RESPONSE);
    match client.handle_response(&got, &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("expected a value, got {other:?}"),
    }
}

#[test]
fn an_association_runs_over_the_wrapper_and_survives_a_split_stream() {
    let (mut client, mut server) = pair();
    let mut apdu = [0u8; 512];
    let mut plain = [0u8; 512];
    let reassembler = StreamReassembler::new(1024);

    let n = client.associate_request(&mut apdu).unwrap();
    let mut stream = Vec::new();
    Wpdu::new(0x0010, 0x0001, &apdu[..n]).unwrap().encode(&mut stream).unwrap();

    // Deliver the stream one byte at a time, as a network is entitled to.
    let mut held: Vec<u8> = Vec::new();
    let mut request = None;
    for b in &stream {
        held.push(*b);
        if let Some((pdu, used)) = reassembler.next_pdu(&held).unwrap() {
            request = Some(pdu.apdu.to_vec());
            assert_eq!(used, held.len());
            break;
        }
    }
    let request = request.expect("the wrapper reassembled the request");

    let m = server.handle(&request, &mut apdu).unwrap();
    let mut back = Vec::new();
    Wpdu::new(0x0001, 0x0010, &apdu[..m]).unwrap().encode(&mut back).unwrap();
    let (pdu, _) = reassembler.next_pdu(&back).unwrap().unwrap();
    assert_eq!(client.handle_associate_response(pdu.apdu).unwrap(), AssociationStep::Established);

    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut apdu).unwrap();
    let m = server.handle(&apdu[..n], &mut apdu.clone()).unwrap();
    let mut out = [0u8; 512];
    let m2 = server.handle(&apdu[..n], &mut out).unwrap();
    assert_eq!(m, m2, "the same request twice gives the same answer over a plain link");
    match client.handle_response(&out[..m2], &mut plain).unwrap() {
        Response::Data(d) => assert_eq!(d.as_u64(), Some(12_345_678)),
        other => panic!("expected a value, got {other:?}"),
    }
}

#[test]
fn the_wrapper_ports_are_the_service_access_points() {
    let apdu = [0xC0u8, 0x01, 0x81];
    let pdu = Wpdu::new(0x0030, 0x0001, &apdu).unwrap();
    let mut buf = Vec::new();
    pdu.encode(&mut buf).unwrap();
    assert_eq!(&buf[..8], [0x00, 0x01, 0x00, 0x30, 0x00, 0x01, 0x00, 0x03]);
    assert_eq!(DEFAULT_PORT, 4059);
}

#[test]
fn an_hdlc_link_recovers_from_a_burst_of_noise_between_frames() {
    let (mut client, mut server) = pair();
    let mut link = Link::new();
    let mut apdu = [0u8; 512];
    let mut wire = [0u8; 512];

    let n = client.associate_request(&mut apdu).unwrap();
    let n = link.request(&apdu[..n], &mut wire);

    // A half-duplex bus echoes what was just sent, and an optical probe sees the room
    // lights. Both look like this.
    let mut noisy = Vec::new();
    noisy.extend_from_slice(&[0xFF, 0x00, 0x7E, 0x7E, 0xA0]);
    noisy.extend_from_slice(&wire[..n]);

    let mut framer = Framer::new();
    let Found::Frame { frame, .. } = framer.next_frame(&noisy).unwrap() else {
        panic!("the real frame was not found behind the noise");
    };
    assert!(framer.discarded() >= 5, "and the noise was counted");
    let m = server.handle(&frame.information[3..], &mut apdu).unwrap();
    assert!(m > 0);
}

/// The two segmentation mechanisms, at once — which is what a real link does.
///
/// A meter on an optical probe negotiates a 128-byte information field and a
/// 1024-byte PDU size. Reading a load profile then needs *both*: application-layer block
/// transfer to cut the value into APDUs the PDU size can hold, and link-layer
/// segmentation to cut each of those into frames the information field can hold. A
/// stack with only one of the two works right up until somebody reads a profile.
#[test]
fn a_load_profile_crosses_a_segmented_hdlc_link() {
    // A server with room for the whole profile, and a small PDU size on top of a small
    // information field — the awkward combination, not the comfortable one.
    let mut client: Client = ClientSession::new(
        ClientConfig { max_pdu_size: 256, ..Default::default() },
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xA1)),
    );
    let mut server: Server<TestMeter, RustCryptoProvider<FixedRandom>, 4096> = Server::new(
        ServerConfig { max_pdu_size: 256, ..Default::default() },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );

    const MAX_INFO: u16 = 128;
    let client_addr = Address::client(0x10);
    let server_addr = Address::server(1, 17);

    /// Carry one APDU across the link and hand back what arrived, in whole frames.
    fn cross(
        apdu: &[u8],
        llc: [u8; 3],
        destination: Address,
        source: Address,
        out: &mut [u8],
    ) -> (usize, usize) {
        let mut lsdu = [0u8; 4096];
        lsdu[..3].copy_from_slice(&llc);
        lsdu[3..3 + apdu.len()].copy_from_slice(apdu);

        let mut segmenter = Segmenter::new(&lsdu[..3 + apdu.len()], MAX_INFO).unwrap();
        let mut wire = alloc_vec();
        let mut buf = [0u8; 256];
        let mut ns = 0u8;
        let mut frames = 0;
        while let Some(n) = segmenter.next_frame(destination, source, ns, 0, &mut buf).unwrap() {
            assert!(n <= usize::from(MAX_INFO) + 16, "a frame overran the link");
            wire.extend_from_slice(&buf[..n]);
            ns = (ns + 1) % 8;
            frames += 1;
        }

        // The receiving side: find frames in the stream, reassemble the unit.
        let mut storage = [0u8; 4096];
        let mut assembled = Reassembler::new(&mut storage);
        let mut framer = Framer::new();
        let mut offset = 0;
        loop {
            let Found::Frame { frame, consumed } = framer.next_frame(&wire[offset..]).unwrap() else {
                panic!("a complete frame")
            };
            offset += consumed;
            if assembled.push(&frame).unwrap() {
                break;
            }
        }
        let lsdu = assembled.lsdu();
        assert_eq!(&lsdu[..3], &llc, "the LLC header rides in the first segment only");
        let apdu = &lsdu[3..];
        out[..apdu.len()].copy_from_slice(apdu);
        (apdu.len(), frames)
    }

    let mut apdu = [0u8; 4096];
    let mut got = [0u8; 4096];
    let mut plain = [0u8; 512];

    // Associate.
    let n = client.associate_request(&mut apdu).unwrap();
    let (n, _) = cross(&apdu[..n], LLC_REQUEST, server_addr, client_addr, &mut got);
    let m = server.handle(&got[..n], &mut apdu).unwrap();
    let (m, _) = cross(&apdu[..m], LLC_RESPONSE, client_addr, server_addr, &mut got);
    assert_eq!(client.handle_associate_response(&got[..m]).unwrap(), AssociationStep::Established);

    // Read the profile.
    let mut storage = [0u8; 8192];
    let mut blocks = BlockCollector::new(&mut storage);
    let mut n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut apdu).unwrap();
    let mut total_frames = 0;
    let mut blocks_seen = 0;
    loop {
        let (len, _) = cross(&apdu[..n], LLC_REQUEST, server_addr, client_addr, &mut got);
        let m = server.handle(&got[..len], &mut apdu).unwrap();
        let (m, frames) = cross(&apdu[..m], LLC_RESPONSE, client_addr, server_addr, &mut got);
        total_frames += frames;
        match client.handle_response(&got[..m], &mut plain).unwrap() {
            Response::Block { last, number, data } => {
                blocks_seen += 1;
                blocks.push(number, data).unwrap();
                if last {
                    break;
                }
                n = client.get_next_block_request(number, &mut apdu).unwrap();
            }
            other => panic!("expected a block, got {other:?}"),
        }
        assert!(blocks_seen < 100, "the transfer should converge");
    }

    assert!(blocks_seen >= 5, "the PDU size forced several blocks, got {blocks_seen}");
    assert!(
        total_frames > blocks_seen,
        "and the information field forced more frames than blocks: {total_frames} frames for {blocks_seen} blocks"
    );

    let value = blocks.value().expect("the reassembled profile decodes");
    let rows = value.as_array().expect("an array");
    assert_eq!(rows.len(), PROFILE_ROWS);
    for (i, row) in rows.iter().enumerate() {
        let row = row.unwrap();
        assert_eq!(row.field(0).unwrap().as_u64(), Some(1_000_000 + i as u64));
    }
}

fn alloc_vec() -> Vec<u8> {
    Vec::new()
}
