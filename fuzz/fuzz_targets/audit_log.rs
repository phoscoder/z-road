#![no_main]
//! A hostile or corrupted audit log file must be rejected or read, never panic.
use libfuzzer_sys::fuzz_target;
use zroad_core::audit;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.jsonl");
    std::fs::write(&path, data).unwrap();
    let _ = audit::read_entries(&path);
    let verified = audit::verify_file(&path);
    // opening must agree with verification: a log that does not verify is refused
    let opened = audit::AuditLog::open(&path);
    if verified.is_err() {
        assert!(opened.is_err());
    }
});
