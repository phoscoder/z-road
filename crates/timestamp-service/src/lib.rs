//! The Z-Road timestamp authority. It signs `(digest, time, serial)` so that
//! members can prove an audit log head existed at a given time.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use zroad_core::crypto::{Signer, SoftwareSigner};
use zroad_core::id::MemberId;
use zroad_core::msg::TimestampToken;
use zroad_core::{now_ms, pki};
use zroad_net::server::{self, PeerCert, ServerHandle};
use zroad_net::tls;

struct App {
    id: MemberId,
    signer: Box<dyn Signer>,
    serial: Mutex<u64>,
    serial_path: PathBuf,
}

#[derive(Deserialize, Serialize)]
pub struct TimestampRequest {
    /// SHA-256 digest, 64 hex characters.
    pub digest: String,
}

/// Serve on `addr`. `dir` holds `key.pem`, `cert.pem` and `ca.pem` (see
/// `zroad-cli enroll`). Clients must present a member certificate.
pub async fn spawn(dir: &Path, addr: &str) -> Result<ServerHandle> {
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
        signer: Box::new(SoftwareSigner::from_pkcs8_pem(&key).map_err(|e| anyhow!("{e}"))?),
        serial: Mutex::new(serial),
        serial_path,
    });
    let router = Router::new()
        .route("/v1/timestamp", post(timestamp))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024))
        .with_state(app);
    let tls_cfg = tls::server_config(&ca, &cert, &key, true)?;
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
        app.signer.as_ref(),
    )))
}
