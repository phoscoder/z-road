//! The Z-Road timestamp authority. It signs `(digest, time, serial)` so that
//! members can prove an audit log head existed at a given time.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use zroad_core::crypto::SoftwareSigner;
use zroad_core::id::MemberId;
use zroad_core::msg::TimestampToken;
use zroad_core::{now_ms, pki};
use zroad_net::server::{self, PeerCert, ServerHandle};
use zroad_net::tls;

struct App {
    id: MemberId,
    signer: RwLock<Arc<SoftwareSigner>>,
    dir: PathBuf,
    serial: Mutex<u64>,
    serial_path: PathBuf,
}

#[derive(Deserialize, Serialize)]
pub struct TimestampRequest {
    /// SHA-256 digest, 64 hex characters.
    pub digest: String,
}

/// Optional behaviour of a running timestamp authority.
#[derive(Clone, Debug)]
pub struct Options {
    /// Where to renew this member's certificate. Without it, renewal is manual
    /// (`zroad-cli renew`, then restart).
    pub central_url: Option<String>,
    pub renew_before_days: i64,
    pub check_interval: std::time::Duration,
    /// Wait this long before the first check (mainly for tests).
    pub initial_delay: std::time::Duration,
    /// After renewing, keep signing with the old key for this long so every
    /// member's directory copy has learned the new one.
    pub activation_delay: std::time::Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            central_url: None,
            renew_before_days: 30,
            check_interval: std::time::Duration::from_secs(3600),
            initial_delay: std::time::Duration::ZERO,
            activation_delay: std::time::Duration::from_secs(65),
        }
    }
}

/// Serve on `addr`. `dir` holds `key.pem`, `cert.pem` and `ca.pem` (see
/// `zroad-cli enroll`). Clients must present a member certificate.
pub async fn spawn(dir: &Path, addr: &str) -> Result<ServerHandle> {
    spawn_with(dir, addr, Options::default()).await
}

pub async fn spawn_with(dir: &Path, addr: &str, opts: Options) -> Result<ServerHandle> {
    let read =
        |f: &str| std::fs::read_to_string(dir.join(f)).with_context(|| format!("reading {f}"));
    let (key, cert, ca) = (read("key.pem")?, read("cert.pem")?, read("ca.pem")?);
    let id = pki::inspect_cert_pem(&cert)
        .map_err(|e| anyhow!("{e}"))?
        .member;
    let serial_path = dir.join("serial");
    let serial = std::fs::read_to_string(&serial_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let app = Arc::new(App {
        id,
        signer: RwLock::new(Arc::new(
            SoftwareSigner::from_pkcs8_pem(&key).map_err(|e| anyhow!("{e}"))?,
        )),
        dir: dir.to_path_buf(),
        serial: Mutex::new(serial),
        serial_path,
    });
    let router = Router::new()
        .route("/v1/timestamp", post(timestamp))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024))
        .with_state(app.clone());
    let server_cert = tls::ReloadableCert::new(&cert, &key)?;
    let tls_cfg =
        tls::server_config_reloadable(&ca, server_cert.clone(), tls::ClientAuth::Required)?;
    if opts.central_url.is_some() {
        tokio::spawn(renew_loop(Arc::downgrade(&app), server_cert, opts));
    }
    Ok(server::spawn(addr, Some(tls_cfg), router).await?)
}

async fn timestamp(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Option<PeerCert>>,
    Json(req): Json<TimestampRequest>,
) -> Result<Json<TimestampToken>, (StatusCode, &'static str)> {
    if peer.is_none() {
        return Err((StatusCode::UNAUTHORIZED, "client certificate required"));
    }
    if req.digest.len() != 64 || !req.digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err((StatusCode::BAD_REQUEST, "digest must be 64 hex characters"));
    }
    let serial = {
        let mut s = app.serial.lock().unwrap_or_else(|p| p.into_inner());
        *s += 1;
        // Persist before issuing so a serial is never reused after a crash.
        std::fs::write(&app.serial_path, s.to_string())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "cannot persist serial"))?;
        *s
    };
    Ok(Json(TimestampToken::issue(
        &app.id,
        &req.digest.to_ascii_lowercase(),
        now_ms(),
        serial,
        app.signer
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref(),
    )))
}

/// Renew this member's certificate from the central server when little validity
/// remains, and switch the live server and the signing key over without a restart.
/// A new key is used from then on; tokens issued earlier stay verifiable because
/// the directory keeps the earlier certificates.
async fn renew_loop(
    app: std::sync::Weak<App>,
    server_cert: Arc<tls::ReloadableCert>,
    opts: Options,
) {
    let central = opts.central_url.clone().unwrap_or_default();
    tokio::time::sleep(opts.initial_delay).await;
    loop {
        let Some(app) = app.upgrade() else { return };
        match renew_if_due(
            &app,
            &server_cert,
            &central,
            opts.renew_before_days,
            opts.activation_delay,
        )
        .await
        {
            Ok(true) => tracing::info!("timestamp authority certificate renewed"),
            Ok(false) => {}
            Err(e) => tracing::error!("cannot renew the timestamp authority certificate: {e:#}"),
        }
        drop(app);
        tokio::time::sleep(opts.check_interval).await;
    }
}

async fn renew_if_due(
    app: &App,
    server_cert: &tls::ReloadableCert,
    central_url: &str,
    renew_before_days: i64,
    activation_delay: std::time::Duration,
) -> Result<bool> {
    let read =
        |f: &str| std::fs::read_to_string(app.dir.join(f)).with_context(|| format!("reading {f}"));
    let (key, cert, ca) = (read("key.pem")?, read("cert.pem")?, read("ca.pem")?);
    let info = pki::inspect_cert_pem(&cert).map_err(|e| anyhow!("{e}"))?;
    if (info.not_after - (now_ms() / 1000) as i64) / 86_400 >= renew_before_days {
        return Ok(false);
    }
    let sans = pki::cert_sans(&cert).map_err(|e| anyhow!("{e}"))?;
    let ident = pki::generate_identity(&app.id, &sans).map_err(|e| anyhow!("{e}"))?;
    let client =
        zroad_net::central_client::CentralClient::with_identity(central_url, &ca, &cert, &key)?;
    let resp = client
        .renew(&zroad_net::api::RenewRequest {
            csr_pem: ident.csr_pem,
        })
        .await?;
    let signer =
        Arc::new(SoftwareSigner::from_pkcs8_pem(&ident.key_pem).map_err(|e| anyhow!("{e}"))?);
    for f in ["key.pem", "cert.pem"] {
        let _ = std::fs::rename(app.dir.join(f), app.dir.join(format!("{f}.prev")));
    }
    zroad_net::central_client::write_private(&app.dir.join("key.pem"), &ident.key_pem)?;
    std::fs::write(app.dir.join("cert.pem"), &resp.cert_pem)?;
    tokio::time::sleep(activation_delay).await;
    server_cert.set(&resp.cert_pem, &ident.key_pem)?;
    *app.signer.write().unwrap_or_else(|p| p.into_inner()) = signer;
    Ok(true)
}
