//! Pushed notifications — the customer-interface case.
//!
//! A meter emits these on its own initiative with no association and nothing to
//! correlate. The only thing that says which key opens one is the system title inside
//! it, which is why the listener is a different object from a client session.

use dlms_cosem_rs::axdr::{Data, DateTime};
use dlms_cosem_rs::client::{NotificationListener, SingleMeterKeys};
use dlms_cosem_rs::codec::{Encode, ErrorKind, SliceWriter, Writer};
use dlms_cosem_rs::security::{
    KeyRing, Protector, ReplayWindow, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle,
};
use dlms_cosem_rs::xdlms::{
    Apdu, ApduTag, CipheredService, DataNotification, GeneralGloCiphering, LongInvokeId, OptionalDateTime,
};

const GUEK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] =
    [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
const METER: SystemTitle = SystemTitle::new([0x4C, 0x47, 0x5A, 0x00, 0x12, 0x34, 0x56, 0x78]);

/// Build the notification a meter would push: a structure of three captured values,
/// authenticated and encrypted, wrapped in `general-glo-ciphering` so the receiver can
/// find the key by system title.
fn push_frame(counter: u32, out: &mut [u8]) -> usize {
    let mut body = [0u8; 64];
    let mut bw = SliceWriter::new(&mut body);
    // structure { octet-string logical name, double-long-unsigned energy, date-time }
    bw.write_bytes(&[0x02, 0x03]).unwrap();
    Data::OctetString(&[1, 0, 1, 8, 0, 255]).encode(&mut bw).unwrap();
    Data::DoubleLongUnsigned(4_242_424).encode(&mut bw).unwrap();
    Data::DateTime(DateTime::from_civil(2026, 9, 6, 7, 30, 0, 120)).encode(&mut bw).unwrap();
    let body_len = bw.written();
    let notification_body = Data::from_bytes_in(&body[..body_len]).unwrap();

    let mut plain = [0u8; 128];
    let mut pw = SliceWriter::new(&mut plain);
    pw.write_u8(ApduTag::DataNotification.as_u8()).unwrap();
    DataNotification {
        long_invoke_id: LongInvokeId::new(counter),
        date_time: OptionalDateTime(None),
        body: notification_body,
    }
    .encode(&mut pw)
    .unwrap();
    let plain_len = pw.written();

    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let protector = Protector::new(RustCryptoProvider::new(KeyRing::new(GUEK, GAK)), policy);
    let mut payload = [0u8; 160];
    let payload = protector.protect(&METER, counter, &GAK, &plain[..plain_len], &mut payload).unwrap();

    let mut w = SliceWriter::new(out);
    w.write_u8(ApduTag::GeneralGloCiphering.as_u8()).unwrap();
    GeneralGloCiphering {
        system_title: METER.as_bytes(),
        ciphered: CipheredService {
            security_control: policy.control(),
            invocation_counter: counter,
            payload,
        },
    }
    .encode(&mut w)
    .unwrap();
    w.written()
}

fn listener() -> NotificationListener<RustCryptoProvider, SingleMeterKeys> {
    NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(METER, KeyRing::new(GUEK, GAK)),
        SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
    )
}

/// A listener that reorders: the window is a property of the meter, not of the listener.
fn listener_with_window(width: u32) -> NotificationListener<RustCryptoProvider, SingleMeterKeys> {
    let mut keys = SingleMeterKeys::new(METER, KeyRing::new(GUEK, GAK));
    keys.replay = ReplayWindow::new(width);
    NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        keys,
        SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
    )
}

#[test]
fn a_ciphered_push_is_decrypted_and_its_values_read() {
    let mut frame = [0u8; 256];
    let n = push_frame(1, &mut frame);
    let mut buf = [0u8; 256];
    let notification = listener().handle(&frame[..n], &mut buf).unwrap();

    assert_eq!(notification.system_title, Some(METER));
    assert_eq!(notification.invocation_counter, Some(1));
    let fields = notification.body.as_structure().expect("a structure of captured values");
    assert_eq!(fields.len(), 3);
    assert_eq!(fields.get(0).unwrap().as_obis(), Some(dlms_cosem_rs::Obis::new(1, 0, 1, 8, 0, 255)));
    assert_eq!(fields.get(1).unwrap().as_u64(), Some(4_242_424));
    match fields.get(2).unwrap() {
        // 2026-09-06T07:30:00+02:00 is 05:30 UTC. The value is what Python's
        // datetime gives for the same instant, computed by something that has never
        // seen this crate's calendar arithmetic.
        Data::DateTime(dt) => assert_eq!(dt.to_unix_seconds(), Some(1_788_672_600)),
        other => panic!("expected a date-time, got {other:?}"),
    }
}

#[test]
fn a_push_from_a_meter_we_have_no_key_for_is_refused_not_guessed() {
    let mut frame = [0u8; 256];
    let n = push_frame(1, &mut frame);
    let mut listener = NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(SystemTitle::new([0xFF; 8]), KeyRing::new(GUEK, GAK)),
        SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
    );
    let mut buf = [0u8; 256];
    assert_eq!(listener.handle(&frame[..n], &mut buf).unwrap_err().kind, ErrorKind::Unsupported);
}

#[test]
fn a_tampered_push_does_not_verify() {
    let mut frame = [0u8; 256];
    let n = push_frame(1, &mut frame);
    frame[n - 20] ^= 0x01;
    let mut buf = [0u8; 256];
    assert_eq!(listener().handle(&frame[..n], &mut buf).unwrap_err().kind, ErrorKind::BadTag);
}

#[test]
fn a_replayed_push_is_refused_once_a_counter_has_been_seen() {
    let mut listener = listener();
    let mut buf = [0u8; 256];

    let mut first = [0u8; 256];
    let n1 = push_frame(5, &mut first);
    listener.handle(&first[..n1], &mut buf).unwrap();

    // The same frame again.
    assert_eq!(
        listener.handle(&first[..n1], &mut buf).unwrap_err().kind,
        ErrorKind::BadTag,
        "a repeated invocation counter is a replay"
    );

    // An older one.
    let mut older = [0u8; 256];
    let n2 = push_frame(4, &mut older);
    assert_eq!(listener.handle(&older[..n2], &mut buf).unwrap_err().kind, ErrorKind::BadTag);

    // A newer one is fine.
    let mut newer = [0u8; 256];
    let n3 = push_frame(6, &mut newer);
    assert!(listener.handle(&newer[..n3], &mut buf).is_ok());
}

#[test]
fn a_reorder_window_only_opens_when_it_is_asked_for() {
    let mut buf = [0u8; 256];
    let mut strict = listener();
    let mut lenient = listener_with_window(10);

    let mut tenth = [0u8; 256];
    let n = push_frame(10, &mut tenth);
    strict.handle(&tenth[..n], &mut buf).unwrap();
    lenient.handle(&tenth[..n], &mut buf).unwrap();

    let mut eighth = [0u8; 256];
    let n = push_frame(8, &mut eighth);
    assert!(strict.handle(&eighth[..n], &mut buf).is_err());
    assert!(lenient.handle(&eighth[..n], &mut buf).is_ok(), "within the window");
}

#[test]
fn an_unprotected_data_notification_still_decodes() {
    let mut body = [0u8; 32];
    let mut bw = SliceWriter::new(&mut body);
    Data::DoubleLongUnsigned(7).encode(&mut bw).unwrap();
    let n = bw.written();
    let mut frame = [0u8; 64];
    let mut w = SliceWriter::new(&mut frame);
    Apdu::DataNotification(DataNotification {
        long_invoke_id: LongInvokeId::new(1),
        date_time: OptionalDateTime(None),
        body: Data::from_bytes_in(&body[..n]).unwrap(),
    })
    .encode(&mut w)
    .unwrap();
    let n = w.written();

    let mut buf = [0u8; 64];
    // A listener that demands protection must refuse an unprotected frame outright…
    assert_eq!(
        listener().handle(&frame[..n], &mut buf).unwrap_err().kind,
        ErrorKind::UnexpectedMessage,
        "an unprotected push is not what an authenticated-encrypted listener asked for"
    );
    // …and one that demands nothing decodes it, which is what a capture reader wants.
    let mut open = NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(METER, KeyRing::new(GUEK, GAK)),
        SecurityPolicy::NONE,
    );
    let notification = open.handle(&frame[..n], &mut buf).unwrap();
    assert_eq!(notification.system_title, None);
    assert_eq!(notification.invocation_counter, None);
    assert_eq!(notification.body.as_u64(), Some(7));
}

/// The hole a listener that reads its policy out of the frame leaves open.
///
/// `general-glo-ciphering` carries a security control byte, and a forger picks it. With
/// security control 0x00 there is no tag and no encryption, so anyone who can reach the
/// listener can post whatever meter reading they like under the meter's system title.
/// The listener must answer with the policy it was *given*, not the one it was sent.
#[test]
fn a_forged_push_that_claims_no_protection_is_refused() {
    let mut body = [0u8; 64];
    let mut bw = SliceWriter::new(&mut body);
    Apdu::DataNotification(DataNotification {
        long_invoke_id: LongInvokeId::new(1),
        date_time: OptionalDateTime(None),
        body: Data::DoubleLongUnsigned(999_999),
    })
    .encode(&mut bw)
    .unwrap();
    let body_len = bw.written();

    // A frame under the meter's identity, with the protection bits simply turned off.
    let mut frame = [0u8; 128];
    let mut w = SliceWriter::new(&mut frame);
    w.write_u8(ApduTag::GeneralGloCiphering.as_u8()).unwrap();
    GeneralGloCiphering {
        system_title: METER.as_bytes(),
        ciphered: CipheredService {
            security_control: SecurityPolicy::NONE.control(),
            invocation_counter: 9_000,
            payload: &body[..body_len],
        },
    }
    .encode(&mut w)
    .unwrap();
    let n = w.written();

    let mut buf = [0u8; 128];
    assert_eq!(
        listener().handle(&frame[..n], &mut buf).unwrap_err().kind,
        ErrorKind::UnexpectedMessage,
        "an unauthenticated frame must not pass a listener that requires authentication"
    );
}

/// A frame that fails to verify must not spend a counter.
///
/// Otherwise anyone who can send to the listener silences the meter for good: one forged
/// frame with a counter near the top of the range, and every genuine reading afterwards
/// looks like a replay.
#[test]
fn a_forged_counter_cannot_lock_the_real_meter_out() {
    let mut listener = listener();
    let mut buf = [0u8; 256];

    // A frame with a very high counter whose tag is wrong.
    let mut forged = [0u8; 256];
    let n = push_frame(4_000_000_000, &mut forged);
    forged[n - 1] ^= 0xFF;
    assert_eq!(listener.handle(&forged[..n], &mut buf).unwrap_err().kind, ErrorKind::BadTag);

    // The meter's next genuine reading must still be accepted.
    let mut genuine = [0u8; 256];
    let n = push_frame(1, &mut genuine);
    assert!(
        listener.handle(&genuine[..n], &mut buf).is_ok(),
        "a frame that never verified must not have advanced the replay window"
    );
}

/// `glo-event-notification` carries no system title, so it can only be decoded on a link
/// whose peer the caller already knows. Before `handle_from` existed there was no way to
/// tell the listener that, and the whole tag was undecodable.
#[test]
fn a_ciphered_event_notification_decodes_when_the_sender_is_supplied() {
    let mut body = [0u8; 64];
    let mut bw = SliceWriter::new(&mut body);
    // The plaintext of a glo-event-notification is the plain event-notification APDU.
    Apdu::DataNotification(DataNotification {
        long_invoke_id: LongInvokeId::new(3),
        date_time: OptionalDateTime(None),
        body: Data::DoubleLongUnsigned(4711),
    })
    .encode(&mut bw)
    .unwrap();
    let plain_len = bw.written();

    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let protector = Protector::new(RustCryptoProvider::new(KeyRing::new(GUEK, GAK)), policy);
    let mut sealed = [0u8; 128];
    let payload = protector.protect(&METER, 77, &GAK, &body[..plain_len], &mut sealed).unwrap();

    let mut frame = [0u8; 160];
    let mut w = SliceWriter::new(&mut frame);
    w.write_u8(ApduTag::GloEventNotification.as_u8()).unwrap();
    CipheredService { security_control: policy.control(), invocation_counter: 77, payload }
        .encode(&mut w)
        .unwrap();
    let n = w.written();

    let mut buf = [0u8; 160];
    // Without a sender there is no key to try.
    assert_eq!(
        listener().handle(&frame[..n], &mut buf).unwrap_err().kind,
        ErrorKind::Unsupported,
        "nothing in the frame says which meter sent it"
    );
    // With one, it decodes.
    let notification = listener().handle_from(METER, &frame[..n], &mut buf).unwrap();
    assert_eq!(notification.system_title, Some(METER));
    assert_eq!(notification.invocation_counter, Some(77));
    assert_eq!(notification.body.as_u64(), Some(4711));
}

/// The meter's side of the same story, driven by the crate rather than hand-built.
///
/// Every other test in this file constructs the frame by hand, which proves the listener
/// reads what the *test* believes a meter sends. This one has `PushSender` build it and
/// `NotificationListener` read it, so the two halves have to agree with each other about
/// the wrapper, the counter and the key — and neither can be quietly wrong on its own.
#[test]
fn a_sender_and_a_listener_agree_about_a_pushed_reading() {
    use dlms_cosem_rs::server::PushSender;

    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    let mut sender: PushSender<_> = PushSender::new(
        RustCryptoProvider::new(KeyRing::new(GUEK, GAK)),
        METER,
        policy,
        // Restored from flash. Not zero, because this meter has run before — which is
        // the case the API is shaped to make visible.
        41,
    );
    let mut listener = NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(METER, KeyRing::new(GUEK, GAK)),
        policy,
    );

    let mut body = [0u8; 64];
    let mut bw = SliceWriter::new(&mut body);
    bw.write_bytes(&[0x02, 0x02]).unwrap();
    Data::OctetString(&[1, 0, 1, 8, 0, 255]).encode(&mut bw).unwrap();
    Data::DoubleLongUnsigned(7_654_321).encode(&mut bw).unwrap();
    let n = bw.written();
    let value = Data::from_bytes_in(&body[..n]).unwrap();

    let captured = DateTime::from_civil(2026, 9, 6, 8, 0, 0, 120);
    let mut frame = [0u8; 256];
    let m = sender.notify(Some(captured), &value, &mut frame).unwrap();

    // A `DataNotification` has no `glo-` tag, so a protected push has exactly one form.
    assert_eq!(frame[0], ApduTag::GeneralGloCiphering.as_u8());
    assert_eq!(sender.invocation_counter(), 42, "one past the value it was given");

    let mut scratch = [0u8; 256];
    let push = listener.handle(&frame[..m], &mut scratch).unwrap();
    assert_eq!(push.system_title, Some(METER));
    assert_eq!(push.invocation_counter, Some(42));
    assert_eq!(push.captured_at, Some(captured), "when the values were taken, not when sent");
    let fields = push.body.as_structure().unwrap();
    assert_eq!(fields.get(1).unwrap().as_u64(), Some(7_654_321));

    // The same frame again is a replay, whatever it decrypts to.
    let mut scratch = [0u8; 256];
    assert_eq!(listener.handle(&frame[..m], &mut scratch).unwrap_err().kind, ErrorKind::BadTag);

    // And the next push spends the next counter, so the listener accepts it.
    let m = sender.notify(Some(captured), &value, &mut frame).unwrap();
    let mut scratch = [0u8; 256];
    assert_eq!(listener.handle(&frame[..m], &mut scratch).unwrap().invocation_counter, Some(43));
}

/// An unprotected push is a bare `DataNotification`, and a listener that was told to
/// require protection refuses it — which is the whole of D33 in two assertions.
#[test]
fn an_unprotected_sender_produces_a_frame_a_strict_listener_refuses() {
    use dlms_cosem_rs::server::PushSender;

    let mut sender: PushSender<_> =
        PushSender::new(RustCryptoProvider::new(KeyRing::default()), METER, SecurityPolicy::NONE, 0);
    let value = Data::DoubleLongUnsigned(1);
    let mut frame = [0u8; 128];
    let m = sender.notify(None, &value, &mut frame).unwrap();
    assert_eq!(frame[0], ApduTag::DataNotification.as_u8());
    assert_eq!(sender.invocation_counter(), 0, "an unprotected push spends no counter");

    let mut strict = NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(METER, KeyRing::new(GUEK, GAK)),
        SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
    );
    let mut scratch = [0u8; 128];
    assert_eq!(strict.handle(&frame[..m], &mut scratch).unwrap_err().kind, ErrorKind::UnexpectedMessage);

    // A listener that asked for nothing reads it.
    let mut permissive = NotificationListener::new(
        RustCryptoProvider::new(KeyRing::default()),
        SingleMeterKeys::new(METER, KeyRing::default()),
        SecurityPolicy::NONE,
    );
    let mut scratch = [0u8; 128];
    assert_eq!(permissive.handle(&frame[..m], &mut scratch).unwrap().body.as_u64(), Some(1));
}
