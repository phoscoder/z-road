use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use rustls::ClientConfig;
use zroad_core::audit::AuditLog;
use zroad_core::crypto::Signer;
use zroad_core::directory::Directory;
use zroad_core::pki;
use zroad_net::central_client::CentralClient;

use crate::config::Config;
use crate::outbox::Outbox;

/// Local copy of the member directory. The last good copy is kept on disk so a
/// security server can restart and keep working while the central server is
/// unreachable.
pub struct DirectoryCache {
    central: CentralClient,
    path: PathBuf,
    current: RwLock<Arc<Directory>>,
    last_attempt: Mutex<Option<Instant>>,
}

impl DirectoryCache {
    pub fn new(central: CentralClient, path: PathBuf) -> Self {
        let cached = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Directory>(&b).ok())
            .unwrap_or_default();
        Self {
            central,
            path,
            current: RwLock::new(Arc::new(cached)),
            last_attempt: Mutex::new(None),
        }
    }

    pub fn snapshot(&self) -> Arc<Directory> {
        self.current
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub async fn refresh(&self) -> Result<()> {
        *self.last_attempt.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        let dir = self.central.directory().await?;
        if let Ok(bytes) = serde_json::to_vec_pretty(&dir) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
        *self.current.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(dir);
        Ok(())
    }

    /// Refresh unless one was attempted within `min_interval`. Used when a
    /// lookup misses, so an unknown peer cannot make us hammer the central server.
    pub async fn refresh_throttled(&self, min_interval: Duration) {
        let recent = self
            .last_attempt
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map(|t| t.elapsed() < min_interval)
            .unwrap_or(false);
        if !recent {
            if let Err(e) = self.refresh().await {
                tracing::warn!("directory refresh failed: {e}");
            }
        }
    }
}

pub enum DedupeState {
    InFlight,
    /// Answered before a restart; the answer itself was not kept.
    Processed,
    Done {
        status: u16,
        body: Bytes,
        content_type: String,
    },
}

pub struct DedupeEntry {
    pub expires_ms: u64,
    /// (client, service, body hash): a repeated message id must carry the same.
    pub fingerprint: (String, String, String),
    pub state: DedupeState,
}

pub struct AppState {
    pub cfg: Config,
    pub signer: Arc<dyn Signer>,
    pub cert_pem: String,
    pub audit: Arc<AuditLog>,
    pub dir: DirectoryCache,
    pub tls_client: Arc<ClientConfig>,
    pub dedupe: Mutex<HashMap<String, DedupeEntry>>,
    pub rate: Mutex<HashMap<String, (u64, u32)>>,
    pub subject_key: Vec<u8>,
    pub outbox: Outbox,
    pub proofs_dir: PathBuf,
    pub last_anchor_seq: AtomicU64,
}

impl AppState {
    pub fn own_info(&self) -> Result<pki::CertInfo> {
        pki::inspect_cert_pem(&self.cert_pem).map_err(|e| anyhow::anyhow!("{e}"))
    }
}
