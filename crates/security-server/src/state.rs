use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use rustls::ClientConfig;
use zroad_core::audit::AuditLog;
use zroad_core::crypto::AsyncSigner;
use zroad_core::directory::{Catalogue, Directory};
use zroad_core::pki;
use zroad_core::schema::CompiledSchema;
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
    /// Compiled request schemas from the catalogue, by service id, with the
    /// schema they were compiled from (so unchanged ones are not recompiled).
    request_schemas: RwLock<HashMap<String, (serde_json::Value, Arc<CompiledSchema>)>>,
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
            request_schemas: RwLock::new(HashMap::new()),
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
        // The catalogue only supplies optional early validation, so a failure
        // here must not fail the directory refresh.
        match self.central.catalogue().await {
            Ok(cat) => self.update_schemas(&cat),
            Err(e) => tracing::debug!("catalogue fetch failed: {e}"),
        }
        Ok(())
    }

    fn update_schemas(&self, cat: &Catalogue) {
        let old = self
            .request_schemas
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut next = HashMap::new();
        for e in &cat.entries {
            let Some(schema) = &e.request_schema else {
                continue;
            };
            let key = e.service.to_string();
            match old.get(&key) {
                Some((prev, compiled)) if prev == schema => {
                    next.insert(key, (prev.clone(), compiled.clone()));
                }
                _ => match CompiledSchema::compile(schema) {
                    Ok(c) => {
                        next.insert(key, (schema.clone(), Arc::new(c)));
                    }
                    Err(err) => tracing::warn!("ignoring the schema published for {key}: {err}"),
                },
            }
        }
        *self
            .request_schemas
            .write()
            .unwrap_or_else(|p| p.into_inner()) = next;
    }

    /// The published request schema of a service, if any.
    pub fn request_schema(
        &self,
        service: &zroad_core::id::ServiceId,
    ) -> Option<Arc<CompiledSchema>> {
        self.request_schemas
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&service.to_string())
            .map(|(_, c)| c.clone())
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

/// Everything that changes when a certificate is renewed.
pub struct Identity {
    pub signer: Arc<dyn AsyncSigner>,
    pub cert_pem: String,
    pub tls_client: Arc<ClientConfig>,
}

pub struct AppState {
    pub cfg: Config,
    pub ca_pem: String,
    pub identity: RwLock<Arc<Identity>>,
    pub server_cert: Arc<zroad_net::tls::ReloadableCert>,
    pub renewing: tokio::sync::Mutex<()>,
    pub audit: Arc<AuditLog>,
    pub dir: Arc<DirectoryCache>,
    pub dedupe: Mutex<HashMap<String, DedupeEntry>>,
    pub rate: Mutex<HashMap<String, (u64, u32)>>,
    pub subject_key: Vec<u8>,
    pub outbox: Outbox,
    pub auth: zroad_core::auth::Authenticator,
    /// Set when this member's signing key is held by its own signer service.
    pub remote_signer: Option<Arc<zroad_net::remote_signer::RemoteSigner>>,
    pub citizen_issuers: Vec<zroad_core::citizen::TrustedIssuer>,
    /// This member's own services' schemas, by `subsystem/service/version`.
    pub schemas: HashMap<String, ServiceSchemas>,
    pub proofs_dir: PathBuf,
    pub last_anchor_seq: AtomicU64,
}

impl AppState {
    pub fn new_identity_lock(id: Identity) -> RwLock<Arc<Identity>> {
        RwLock::new(Arc::new(id))
    }

    /// The current identity. Cheap; call it once per operation.
    pub fn identity(&self) -> Arc<Identity> {
        self.identity
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn set_identity(&self, id: Identity) {
        *self.identity.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(id);
    }

    /// Sign a protocol message with this member's key. If the key lives in a remote
    /// signer that has rotated it, the first attempt can fail verification against
    /// the key we still expect; follow the directory once and try again.
    pub async fn sign_message<T: serde::Serialize>(
        &self,
        domain: &str,
        value: &T,
    ) -> zroad_core::Result<zroad_core::msg::SignedMessage> {
        use zroad_core::msg::SignedMessage;
        let id = self.identity();
        match SignedMessage::sign_async(domain, value, id.signer.as_ref()).await {
            Err(first) if self.remote_signer.is_some() => {
                self.dir.refresh_throttled(Duration::from_secs(2)).await;
                crate::node::sync_remote_key(self);
                let id = self.identity();
                SignedMessage::sign_async(domain, value, id.signer.as_ref())
                    .await
                    .map_err(|_| first)
            }
            other => other,
        }
    }

    pub fn own_info(&self) -> Result<pki::CertInfo> {
        pki::inspect_cert_pem(&self.identity().cert_pem).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// A security server process: one or more hosted members behind shared
/// listeners.
pub struct Node {
    pub members: HashMap<zroad_core::id::MemberId, Arc<AppState>>,
    /// The one hosted member, when there is exactly one (the common case).
    pub only: Option<Arc<AppState>>,
}

impl Node {
    pub fn new(states: &[Arc<AppState>]) -> Self {
        Self {
            members: states
                .iter()
                .map(|s| (s.cfg.member_id.clone(), s.clone()))
                .collect(),
            only: (states.len() == 1).then(|| states[0].clone()),
        }
    }
}

pub struct ServiceSchemas {
    pub request: Option<(serde_json::Value, CompiledSchema)>,
    pub response: Option<(serde_json::Value, CompiledSchema)>,
    pub enforce_response: bool,
}
