//! The Z-Road security server.
//!
//! It runs two listeners: a mutual-TLS one that other members connect to, and a
//! plain-HTTP one on a private address for the organisation's own systems.

pub mod anchor;
pub mod config;
pub mod consumer;
pub mod internal;
pub mod outbox;
pub mod provider;
pub mod renew;
pub mod state;
pub mod worker;

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use axum::routing::post;
use axum::Router;
use tokio::task::JoinHandle;
use zroad_core::audit::{self, AuditLog};
use zroad_core::crypto::SoftwareSigner;
use zroad_core::{pki, random_secret};
use zroad_net::central_client::{write_private, CentralClient};
use zroad_net::server::{self, ServerHandle};
use zroad_net::tls;

pub use config::Config;
use state::{AppState, DirectoryCache};

pub struct Running {
    pub network: ServerHandle,
    pub internal: ServerHandle,
    pub state: Arc<AppState>,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    pub fn shutdown(&self) {
        self.network.shutdown();
        self.internal.shutdown();
        for t in &self.tasks {
            t.abort();
        }
    }

    pub async fn wait(self) {
        self.network.wait().await;
    }
}

pub async fn spawn(cfg: Config) -> Result<Running> {
    let dir = cfg.data_dir.clone();
    std::fs::create_dir_all(&dir)?;
    let read = |f: &str| {
        std::fs::read_to_string(dir.join(f)).with_context(|| {
            format!(
                "reading {} (run `zroad-cli enroll` first)",
                dir.join(f).display()
            )
        })
    };
    let (key, cert, ca) = (read("key.pem")?, read("cert.pem")?, read("ca.pem")?);
    let me = pki::inspect_cert_pem(&cert).map_err(|e| anyhow!("{e}"))?;
    if me.member != cfg.member_id {
        bail!(
            "certificate is for {}, but the config says {}",
            me.member,
            cfg.member_id
        );
    }

    let subject_key_path = dir.join("subject.key");
    if !subject_key_path.exists() {
        write_private(&subject_key_path, &random_secret())?;
    }
    let subject_key = std::fs::read_to_string(&subject_key_path)?
        .trim()
        .as_bytes()
        .to_vec();

    let audit_path = dir.join("audit").join("log.jsonl");
    let report = audit::verify_file(&audit_path)
        .map_err(|e| anyhow!("audit log is corrupt, refusing to start: {e}"))?;
    let last_anchor_seq = {
        let entries = audit::read_entries(&audit_path).map_err(|e| anyhow!("{e}"))?;
        entries
            .iter()
            .rev()
            .find(|e| matches!(e.event, audit::AuditEvent::Anchor { .. }))
            .map(|e| e.seq)
            .unwrap_or(0)
    };
    tracing::info!("audit log verified: {} entries", report.entries);
    let audit = Arc::new(AuditLog::open(&audit_path).map_err(|e| anyhow!("{e}"))?);

    let central = CentralClient::new(&cfg.central_url, &ca)?;
    let directory = DirectoryCache::new(central, dir.join("directory.json"));
    if let Err(e) = directory.refresh().await {
        tracing::warn!("central server unreachable at startup, using cached directory: {e}");
    }

    let tls_client = tls::client_config(&ca, Some((&cert, &key)))?;
    let server_cert = tls::ReloadableCert::new(&cert, &key)?;
    let proofs_dir = dir.join("proofs");
    std::fs::create_dir_all(&proofs_dir)?;
    let dedupe = seed_dedupe(&audit_path, &cfg);
    let st = Arc::new(AppState {
        ca_pem: ca.clone(),
        identity: AppState::new_identity_lock(state::Identity {
            signer: Arc::new(SoftwareSigner::from_pkcs8_pem(&key).map_err(|e| anyhow!("{e}"))?),
            cert_pem: cert.clone(),
            tls_client,
        }),
        server_cert: server_cert.clone(),
        renewing: tokio::sync::Mutex::new(()),
        audit,
        dir: directory,
        dedupe: Mutex::new(dedupe),
        rate: Mutex::new(HashMap::new()),
        subject_key,
        outbox: outbox::Outbox::new(dir.join("outbox"))?,
        proofs_dir,
        last_anchor_seq: AtomicU64::new(last_anchor_seq),
        cfg: cfg.clone(),
    });

    let net_router = Router::new()
        .route("/zroad/v1/exchange", post(provider::exchange))
        .layer(axum::extract::DefaultBodyLimit::max(
            cfg.max_body_bytes * 2 + 4096,
        ))
        .with_state(st.clone());
    let net_tls = tls::server_config_reloadable(&ca, server_cert, tls::ClientAuth::Required)?;
    let network = server::spawn(&cfg.network_listen, Some(net_tls), net_router).await?;
    let internal = server::spawn(&cfg.internal_listen, None, internal::router(st.clone())).await?;

    let tasks = vec![
        tokio::spawn(worker::directory_loop(st.clone())),
        tokio::spawn(worker::outbox_loop(st.clone())),
        tokio::spawn(worker::anchor_loop(st.clone())),
        tokio::spawn(renew::renew_loop(st.clone())),
    ];
    tracing::info!(
        "security server for {} up: network https://{} internal http://{}",
        cfg.member_id,
        network.addr,
        internal.addr
    );
    Ok(Running {
        network,
        internal,
        state: st,
        tasks,
    })
}

/// Rebuild the replay cache from the audit log, so a restart does not reopen
/// the replay window for messages answered in the last few minutes.
fn seed_dedupe(path: &std::path::Path, cfg: &Config) -> HashMap<String, state::DedupeEntry> {
    let now = zroad_core::now_ms();
    let mut map = HashMap::new();
    for e in audit::read_entries(path).unwrap_or_default() {
        if e.ts_ms + provider::DEDUPE_TTL_MS <= now {
            continue;
        }
        if let audit::AuditEvent::Exchange {
            role,
            message_id,
            peer,
            outcome,
            service,
            ..
        } = e.event
        {
            let ours = service.starts_with(&format!("{}/", cfg.member_id));
            if role == "provider" && ours && (outcome == "ok" || outcome == "duplicate") {
                map.insert(
                    format!("{peer}|{message_id}"),
                    state::DedupeEntry {
                        expires_ms: e.ts_ms + provider::DEDUPE_TTL_MS,
                        fingerprint: Default::default(),
                        state: state::DedupeState::Processed,
                    },
                );
            }
        }
    }
    map
}
