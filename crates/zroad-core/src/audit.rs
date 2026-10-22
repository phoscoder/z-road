//! A hash-chained, append-only audit log.
//!
//! Every entry commits to the hash of the previous one, so removing or editing
//! an entry breaks the chain from that point on. Entries of type `anchor` carry
//! a trusted timestamp over the chain head, which proves the log existed in
//! that state at that time.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::crypto::sha256_hex;
use crate::msg::TimestampToken;
use crate::{now_ms, Error, Result};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    Start {
        note: String,
    },
    Exchange {
        /// `consumer` or `provider`.
        role: String,
        message_id: String,
        peer: String,
        client: String,
        service: String,
        request_sha256: String,
        response_sha256: Option<String>,
        status: Option<u16>,
        outcome: String,
        /// Keyed hash of the data subject, never the subject itself.
        subject_ref: Option<String>,
        /// The node that carried the request, when the peer spoke for a member
        /// hosted on it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<String>,
    },
    /// Written by a member's own signer service: one entry per signature made on
    /// the member's behalf, so a member can audit the node that hosts it.
    Signed {
        /// `request` or `response`.
        kind: String,
        message_id: String,
        service: String,
        /// The other party (the provider for requests, the consumer for responses),
        /// when the signer knows it.
        counterparty: Option<String>,
        payload_sha256: String,
        node: String,
    },
    Anchor {
        anchored_seq: u64,
        anchored_hash: String,
        token: TimestampToken,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts_ms: u64,
    pub prev_hash: String,
    #[serde(flatten)]
    pub event: AuditEvent,
    pub hash: String,
}

#[derive(Serialize)]
struct HashInput<'a> {
    seq: u64,
    ts_ms: u64,
    prev_hash: &'a str,
    event: &'a AuditEvent,
}

fn entry_hash(seq: u64, ts_ms: u64, prev_hash: &str, event: &AuditEvent) -> Result<String> {
    let bytes = serde_json::to_vec(&HashInput {
        seq,
        ts_ms,
        prev_hash,
        event,
    })?;
    Ok(sha256_hex(&bytes))
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub entries: u64,
    pub head_hash: String,
    pub anchors: Vec<(u64, TimestampToken)>,
}

/// Read and verify the whole chain. Fails on the first inconsistency.
pub fn verify_file(path: &Path) -> Result<VerifyReport> {
    let entries = read_entries(path)?;
    let mut prev = GENESIS_HASH.to_string();
    let mut anchors = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let expected_seq = i as u64 + 1;
        if e.seq != expected_seq {
            return Err(Error::Audit(format!(
                "entry {i}: expected seq {expected_seq}, found {}",
                e.seq
            )));
        }
        if e.prev_hash != prev {
            return Err(Error::Audit(format!(
                "entry {}: chain broken (prev_hash mismatch)",
                e.seq
            )));
        }
        let h = entry_hash(e.seq, e.ts_ms, &e.prev_hash, &e.event)?;
        if h != e.hash {
            return Err(Error::Audit(format!(
                "entry {}: contents do not match their hash",
                e.seq
            )));
        }
        if let AuditEvent::Anchor {
            anchored_seq,
            anchored_hash,
            token,
        } = &e.event
        {
            let target = (*anchored_seq as usize)
                .checked_sub(1)
                .and_then(|i| entries.get(i))
                .ok_or_else(|| Error::Audit(format!("entry {}: anchors a missing entry", e.seq)))?;
            if &target.hash != anchored_hash || &token.digest != anchored_hash {
                return Err(Error::Audit(format!(
                    "entry {}: anchor does not match the entry it covers",
                    e.seq
                )));
            }
            anchors.push((e.seq, token.clone()));
        }
        prev = e.hash.clone();
    }
    Ok(VerifyReport {
        entries: entries.len() as u64,
        head_hash: prev,
        anchors,
    })
}

pub fn read_entries(path: &Path) -> Result<Vec<AuditEntry>> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    BufReader::new(f)
        .lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(true))
        .map(|l| Ok(serde_json::from_str(&l?)?))
        .collect()
}

struct State {
    file: File,
    seq: u64,
    last_hash: String,
}

pub struct AuditLog {
    path: PathBuf,
    state: Mutex<State>,
    /// Failure injection for tests: negative = off, otherwise the number of
    /// appends still allowed before every append fails.
    fail_after: AtomicI64,
}

impl AuditLog {
    /// Open (creating if needed). An existing log must verify, otherwise the
    /// process refuses to continue appending to a corrupted history.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let report = verify_file(path)?;
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let log = Self {
            path: path.to_path_buf(),
            state: Mutex::new(State {
                file,
                seq: report.entries,
                last_hash: report.head_hash,
            }),
            fail_after: AtomicI64::new(-1),
        };
        log.append(AuditEvent::Start {
            note: "security server started".into(),
        })?;
        Ok(log)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Test hook: let `n` more appends succeed, then make every append fail,
    /// as a full disk or a dead volume would. Used to prove that callers fail
    /// closed.
    #[doc(hidden)]
    pub fn inject_write_failure_after(&self, n: u64) {
        self.fail_after.store(n as i64, Ordering::SeqCst);
    }

    /// Test hook: stop injecting failures.
    #[doc(hidden)]
    pub fn clear_write_failure(&self) {
        self.fail_after.store(-1, Ordering::SeqCst);
    }

    pub fn append(&self, event: AuditEvent) -> Result<AuditEntry> {
        match self.fail_after.load(Ordering::SeqCst) {
            0 => return Err(Error::Audit("injected write failure".into())),
            n if n > 0 => {
                self.fail_after.fetch_sub(1, Ordering::SeqCst);
            }
            _ => {}
        }
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let seq = st.seq + 1;
        let ts_ms = now_ms();
        let hash = entry_hash(seq, ts_ms, &st.last_hash, &event)?;
        let entry = AuditEntry {
            seq,
            ts_ms,
            prev_hash: st.last_hash.clone(),
            event,
            hash,
        };
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        st.file.write_all(&line)?;
        st.file.sync_data()?;
        st.seq = seq;
        st.last_hash = entry.hash.clone();
        Ok(entry)
    }

    /// `(seq, hash)` of the newest entry.
    pub fn head(&self) -> (u64, String) {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (st.seq, st.last_hash.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(n: u32) -> AuditEvent {
        AuditEvent::Exchange {
            role: "provider".into(),
            message_id: format!("m{n}"),
            peer: "ZW/COM/1".into(),
            client: "ZW/COM/1/ap".into(),
            service: "ZW/GOV/ZIMRA/a/b/v1".into(),
            request_sha256: "aa".into(),
            response_sha256: None,
            status: Some(200),
            outcome: "ok".into(),
            subject_ref: None,
            via: None,
        }
    }

    #[test]
    fn chain_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log.jsonl");
        let log = AuditLog::open(&p).unwrap();
        for n in 0..5 {
            log.append(ex(n)).unwrap();
        }
        let r = verify_file(&p).unwrap();
        assert_eq!(r.entries, 6);
        drop(log);

        // reopening continues the chain
        let log = AuditLog::open(&p).unwrap();
        log.append(ex(9)).unwrap();
        assert_eq!(verify_file(&p).unwrap().entries, 8);
        drop(log);

        // edit one entry
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replacen("\"m2\"", "\"mX\"", 1)).unwrap();
        assert!(verify_file(&p).is_err());
        assert!(AuditLog::open(&p).is_err());
    }

    #[test]
    fn chain_detects_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log.jsonl");
        let log = AuditLog::open(&p).unwrap();
        for n in 0..4 {
            log.append(ex(n)).unwrap();
        }
        drop(log);
        let text = std::fs::read_to_string(&p).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 2)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&p, kept.join("\n") + "\n").unwrap();
        assert!(verify_file(&p).is_err());
    }
}

#[cfg(test)]
mod hostile_log_tests {
    use super::*;

    #[test]
    fn anchor_pointing_at_entry_zero_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log.jsonl");
        let token = TimestampToken {
            tsa: "ZW/SYS/tsa".parse().unwrap(),
            digest: GENESIS_HASH.into(),
            time_ms: 1,
            serial: 1,
            signature_b64: String::new(),
        };
        let event = AuditEvent::Anchor {
            anchored_seq: 0,
            anchored_hash: GENESIS_HASH.into(),
            token,
        };
        let hash = entry_hash(1, 1, GENESIS_HASH, &event).unwrap();
        let entry = AuditEntry {
            seq: 1,
            ts_ms: 1,
            prev_hash: GENESIS_HASH.into(),
            event,
            hash,
        };
        std::fs::write(&p, serde_json::to_string(&entry).unwrap() + "\n").unwrap();
        assert!(verify_file(&p).is_err());
    }
}
