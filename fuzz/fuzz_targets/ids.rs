#![no_main]
//! Identifier parsing must never panic, and anything that parses must survive a
//! round trip unchanged.
use libfuzzer_sys::fuzz_target;
use zroad_core::id::{client_matches, ClientId, MemberId, ServiceId};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(m) = text.parse::<MemberId>() {
        assert_eq!(m.to_string().parse::<MemberId>().unwrap(), m);
    }
    if let Ok(s) = text.parse::<ServiceId>() {
        assert_eq!(s.to_string().parse::<ServiceId>().unwrap(), s);
        // no segment can be empty, `.` or `..`, so a parsed id is safe to place in a path
        for seg in s.to_string().split('/') {
            assert!(!seg.is_empty() && !seg.bytes().all(|b| b == b'.'), "{seg:?}");
        }
    }
    if let Ok(c) = text.parse::<ClientId>() {
        assert_eq!(c.to_string().parse::<ClientId>().unwrap(), c);
        // use the rest of the input as an access pattern
        let _ = client_matches(text, &c);
        let _ = client_matches("ZW/COM/*", &c);
    }
    for pat in text.split('\n') {
        let c: ClientId = "ZW/COM/1/ap".parse().unwrap();
        let _ = client_matches(pat, &c);
    }
});
