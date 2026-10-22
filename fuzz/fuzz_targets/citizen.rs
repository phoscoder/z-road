#![no_main]
//! Identity assertions come from a portal, which may be compromised, and are the
//! only thing that decides whose record is read. Verification must never panic
//! and must never accept anything not signed by a trusted key.
use libfuzzer_sys::fuzz_target;
use zroad_core::citizen::{verify, TrustedIssuer};

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else { return };
    let issuers = [TrustedIssuer { name: "fuzz".into(), public_key: vec![9; 32] }];
    let aud = "ZW/GOV/ZIMRA".parse().unwrap();
    // arbitrary input is never signed by the key (which has no known private half)
    assert!(verify(token, &issuers, &aud, 1_800_000_000_000).is_err());
});
