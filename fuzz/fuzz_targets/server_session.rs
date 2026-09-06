#![no_main]
//! The server state machine, driven by an attacker.
//!
//! A decoder target proves a single message cannot crash the parser. This proves a
//! *sequence* cannot: the same server sees message after message with no handshake, in
//! any order, and must answer or refuse each without aborting.

use dlms_cosem_rs::axdr::Data;
use dlms_cosem_rs::codec::Writer;
use dlms_cosem_rs::cosem::{AttributeAccess, MethodAccess};
use dlms_cosem_rs::obis::Obis;
use dlms_cosem_rs::security::{FixedRandom, KeyRing, RustCryptoProvider};
use dlms_cosem_rs::server::{ObjectStore, Server, ServerConfig, StoreResult};
use dlms_cosem_rs::xdlms::{DataAccessResult, SelectiveAccess};
use libfuzzer_sys::fuzz_target;

struct Meter;

impl ObjectStore for Meter {
    fn get_attribute(
        &self,
        _class_id: u16,
        _logical_name: Obis,
        _attribute_id: i8,
        _selective_access: Option<SelectiveAccess<'_>>,
        w: &mut dyn Writer,
    ) -> StoreResult<()> {
        use dlms_cosem_rs::codec::Encode;
        Data::DoubleLongUnsigned(1).encode(w).map_err(|_| DataAccessResult::OtherReason)
    }

    fn attribute_access(&self, _c: u16, _n: Obis, _a: i8) -> AttributeAccess {
        AttributeAccess::READ | AttributeAccess::WRITE
    }

    fn method_access(&self, _c: u16, _n: Obis, _m: i8) -> MethodAccess {
        MethodAccess::ACCESS
    }
}

fuzz_target!(|bytes: &[u8]| {
    let mut server: Server<Meter, RustCryptoProvider<FixedRandom>> = Server::new(
        ServerConfig::default(),
        Meter,
        RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(0xB2)),
    );
    let mut out = [0u8; 2048];
    // Split the input into messages on a marker byte, so one case is a whole session.
    for message in bytes.split(|b| *b == 0xFE) {
        if message.is_empty() {
            continue;
        }
        let _ = server.handle(message, &mut out);
    }
});
