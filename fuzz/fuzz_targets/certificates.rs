#![no_main]
//! Certificates and requests come from the network and from enrolment: parsing
//! and signing must reject garbage without panicking.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zroad_core::pki::{self, CertAuthority};

fn ca() -> &'static CertAuthority {
    static CA: OnceLock<CertAuthority> = OnceLock::new();
    CA.get_or_init(|| CertAuthority::generate("fuzz CA", 30).unwrap().ca)
}

fuzz_target!(|data: &[u8]| {
    let _ = pki::inspect_cert_der(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = pki::cert_pem_to_der(text);
        let _ = pki::inspect_cert_pem(text);
        let member = "ZW/COM/1".parse().unwrap();
        // whatever the CSR says, an issued certificate is for the given member
        if let Ok(pem) = ca().sign_csr(text, &member, &["127.0.0.1".to_string()], 1) {
            assert_eq!(pki::inspect_cert_pem(&pem).unwrap().member, member);
        }
    }
});
