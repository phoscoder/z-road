//! The Z-Road security server.
//!
//! It runs two listeners: a mutual-TLS one that other members connect to, and a
//! plain-HTTP one on a private address for the organisation's own systems.

pub mod anchor;
pub mod catalogue;
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
    /// The first hosted member (the only one on an ordinary, non-shared server).
    pub state: Arc<AppState>,
    /// Every hosted member.
    pub members: Vec<Arc<AppState>>,
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

/// Run an ordinary security server for one member.
pub async fn spawn(cfg: Config) -> Result<Running> {
    let node_dir = cfg.data_dir.clone();
    spawn_node(config::NodeConfig {
        members: vec![cfg],
        node_dir,
    })
    .await
}

/// Run a security server that hosts one or more members behind shared listeners.
pub async fn spawn_node(node: config::NodeConfig) -> Result<Running> {
    let first = node
        .members
        .first()
        .ok_or_else(|| anyhow!("no members configured"))?;
    for m in &node.members {
        if m.network_listen != first.network_listen
            || m.internal_listen != first.internal_listen
            || m.central_url != first.central_url
        {
            bail!("all members of a node must share listeners and central_url");
        }
    }
    std::fs::create_dir_all(&node.node_dir)?;
    let ca = std::fs::read_to_string(first.data_dir.join("ca.pem")).with_context(|| {
        format!(
            "reading {} (run `zroad-cli enroll` first)",
            first.data_dir.join("ca.pem").display()
        )
    })?;
    let central = CentralClient::new(&first.central_url, &ca)?;
    let directory = Arc::new(DirectoryCache::new(
        central,
        node.node_dir.join("directory.json"),
    ));
    if let Err(e) = directory.refresh().await {
        tracing::warn!("central server unreachable at startup, using cached directory: {e}");
    }

    // The node's TLS server presents one hosted member's certificate. Peers
    // check it against the shared host name; who they are really talking to is
    // established by the provider's signature on every answer.
    // All members share one server certificate slot; whichever member renews
    // most recently puts its fresh certificate there.
    let mut states = Vec::new();
    let mut shared_cert: Option<Arc<tls::ReloadableCert>> = None;
    for cfg in &node.members {
        states.push(build_member(cfg.clone(), directory.clone(), &mut shared_cert).await?);
    }
    let server_cert = shared_cert.ok_or_else(|| anyhow!("no members configured"))?;
    let max_body = node
        .members
        .iter()
        .map(|m| m.max_body_bytes)
        .max()
        .unwrap_or(0);
    let host = Arc::new(state::Node::new(&states));

    let net_router = Router::new()
        .route("/zroad/v1/exchange", post(provider::exchange))
        .layer(axum::extract::DefaultBodyLimit::max(max_body * 2 + 4096))
        .with_state(host);
    let net_tls = tls::server_config_reloadable(&ca, server_cert, tls::ClientAuth::Required)?;
    let network = server::spawn(&first.network_listen, Some(net_tls), net_router).await?;

    let internal = server::spawn(&first.internal_listen, None, internal_router(&states)).await?;

    let mut tasks = vec![tokio::spawn(worker::directory_loop(states[0].clone()))];
    for st in &states {
        tasks.push(tokio::spawn(worker::outbox_loop(st.clone())));
        tasks.push(tokio::spawn(worker::anchor_loop(st.clone())));
        tasks.push(tokio::spawn(renew::renew_loop(st.clone())));
        tasks.push(tokio::spawn(catalogue::publish_loop(st.clone())));
        tracing::info!("hosting member {}", st.cfg.member_id);
    }
    tracing::info!(
        "security server up: network https://{} internal http://{}",
        network.addr,
        internal.addr
    );
    Ok(Running {
        network,
        internal,
        state: states[0].clone(),
        members: states,
        tasks,
    })
}

/// Internal API routes. A single-member node serves them at the root; every
/// node also serves each member under `/m/<member id>/`, which is the only form
/// that exists when several members share the node.
fn internal_router(states: &[Arc<AppState>]) -> Router {
    let mut app = Router::new();
    if let [only] = states {
        app = app.merge(internal::router(only.clone()));
    } else {
        app = app.route("/health", axum::routing::get(|| async { "ok" }));
    }
    for st in states {
        app = app.nest(
            &format!("/m/{}", st.cfg.member_id),
            internal::router(st.clone()),
        );
    }
    app
}

async fn build_member(
    cfg: Config,
    directory: Arc<DirectoryCache>,
    shared_cert: &mut Option<Arc<tls::ReloadableCert>>,
) -> Result<Arc<AppState>> {
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
    let report = audit::verify_file(&audit_path).map_err(|e| {
        anyhow!(
            "audit log of {} is corrupt, refusing to start: {e}",
            cfg.member_id
        )
    })?;
    let last_anchor_seq = {
        let entries = audit::read_entries(&audit_path).map_err(|e| anyhow!("{e}"))?;
        entries
            .iter()
            .rev()
            .find(|e| matches!(e.event, audit::AuditEvent::Anchor { .. }))
            .map(|e| e.seq)
            .unwrap_or(0)
    };
    tracing::info!(
        "audit log of {} verified: {} entries",
        cfg.member_id,
        report.entries
    );
    let audit = Arc::new(AuditLog::open(&audit_path).map_err(|e| anyhow!("{e}"))?);

    let tls_client = tls::client_config(&ca, Some((&cert, &key)))?;
    let server_cert = match shared_cert {
        Some(c) => c.clone(),
        None => {
            let c = tls::ReloadableCert::new(&cert, &key)?;
            *shared_cert = Some(c.clone());
            c
        }
    };
    let proofs_dir = dir.join("proofs");
    std::fs::create_dir_all(&proofs_dir)?;
    let dedupe = seed_dedupe(&audit_path, &cfg);
    Ok(Arc::new(AppState {
        ca_pem: ca.clone(),
        identity: AppState::new_identity_lock(state::Identity {
            signer: Arc::new(SoftwareSigner::from_pkcs8_pem(&key).map_err(|e| anyhow!("{e}"))?),
            cert_pem: cert.clone(),
            tls_client,
        }),
        server_cert,
        renewing: tokio::sync::Mutex::new(()),
        audit,
        dir: directory,
        dedupe: Mutex::new(dedupe),
        rate: Mutex::new(HashMap::new()),
        subject_key,
        outbox: outbox::Outbox::new(dir.join("outbox"))?,
        proofs_dir,
        last_anchor_seq: AtomicU64::new(last_anchor_seq),
        cfg,
    }))
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
