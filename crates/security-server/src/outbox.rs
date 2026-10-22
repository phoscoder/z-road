//! A durable outbox so consumers keep working through outages: async requests
//! are written to disk, retried with backoff and their results kept for pickup.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zroad_core::now_ms;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxItem {
    /// Also used as the Z-Road message id, so retries are idempotent.
    pub id: String,
    pub client: String,
    pub service: String,
    pub body_b64: String,
    pub content_type: String,
    pub subject: Option<String>,
    pub attempts: u32,
    pub next_attempt_ms: u64,
    pub created_ms: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxResult {
    pub id: String,
    /// `delivered` or `failed`.
    pub state: String,
    pub status: Option<u16>,
    pub body_b64: Option<String>,
    pub content_type: Option<String>,
    pub error: Option<String>,
    pub finished_ms: u64,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OutboxStatus {
    Pending { item: OutboxItem },
    Finished { result: OutboxResult },
}

pub struct Outbox {
    pending: PathBuf,
    done: PathBuf,
}

fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

impl Outbox {
    pub fn new(root: PathBuf) -> std::io::Result<Self> {
        let pending = root.join("pending");
        let done = root.join("done");
        std::fs::create_dir_all(&pending)?;
        std::fs::create_dir_all(&done)?;
        Ok(Self { pending, done })
    }

    fn write(path: PathBuf, value: &impl Serialize) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
        std::fs::rename(tmp, path)
    }

    pub fn put(&self, item: &OutboxItem) -> std::io::Result<()> {
        Self::write(self.pending.join(format!("{}.json", item.id)), item)
    }

    pub fn finish(&self, item: &OutboxItem, result: &OutboxResult) -> std::io::Result<()> {
        Self::write(self.done.join(format!("{}.json", item.id)), result)?;
        let _ = std::fs::remove_file(self.pending.join(format!("{}.json", item.id)));
        Ok(())
    }

    pub fn due(&self) -> Vec<OutboxItem> {
        let now = now_ms();
        let mut items: Vec<OutboxItem> = std::fs::read_dir(&self.pending)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| std::fs::read(e.path()).ok())
            .filter_map(|b| serde_json::from_slice::<OutboxItem>(&b).ok())
            .filter(|i| i.next_attempt_ms <= now)
            .collect();
        items.sort_by_key(|i| i.created_ms);
        items
    }

    pub fn status(&self, id: &str) -> Option<OutboxStatus> {
        if !safe_id(id) {
            return None;
        }
        if let Ok(b) = std::fs::read(self.done.join(format!("{id}.json"))) {
            return serde_json::from_slice(&b)
                .ok()
                .map(|result| OutboxStatus::Finished { result });
        }
        let b = std::fs::read(self.pending.join(format!("{id}.json"))).ok()?;
        serde_json::from_slice(&b)
            .ok()
            .map(|item| OutboxStatus::Pending { item })
    }
}

/// Exponential backoff: 1s, 2s, 4s ... capped at five minutes.
pub fn backoff_ms(attempts: u32) -> u64 {
    1000 * (1u64 << attempts.min(8)).min(300)
}
