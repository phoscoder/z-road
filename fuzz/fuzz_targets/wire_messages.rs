#![no_main]
//! Everything a peer can send over the network is parsed from untrusted JSON.
//! Parsing and opening must return errors, never panic.
use libfuzzer_sys::fuzz_target;
use zroad_core::msg::*;

const KEY: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<ExchangeRequest>(data) {
        let _ = req.request.payload();
        let _ = req.request.payload_sha256();
        let _ = b64_decode(&req.body_b64);
        let _ = req.request.open::<RequestEnvelope>(REQUEST_DOMAIN, &KEY);
        let _ = req.request.open::<ResponseEnvelope>(RESPONSE_DOMAIN, &KEY);
    }
    if let Ok(res) = serde_json::from_slice::<ExchangeResponse>(data) {
        let _ = res.response.open::<ResponseEnvelope>(RESPONSE_DOMAIN, &KEY);
    }
    if let Ok(proof) = serde_json::from_slice::<Proof>(data) {
        // a proof must never verify against an arbitrary key
        assert!(verify_proof(&proof, &KEY, &KEY).is_err());
    }
    if let Ok(t) = serde_json::from_slice::<TimestampToken>(data) {
        assert!(t.verify(&KEY).is_err());
    }
    let _ = serde_json::from_slice::<RequestEnvelope>(data);
    let _ = serde_json::from_slice::<ResponseEnvelope>(data);
});
