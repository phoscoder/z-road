//! The member-run signer.
//!
//! A member that is hosted on somebody else's security server keeps its signing
//! key here, on its own machine. The hosting node asks this service to sign each
//! message; the key never leaves. The service only signs messages that are
//! really the member's to send (its own requests, its own answers), only for the
//! node it is configured for, within a rate limit, and it records every
//! signature in its own hash-chained audit log, so the member can check what the
//! node did in its name.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use zroad_core::audit::{AuditEvent, AuditLog};
use zroad_core::crypto::{sha256_hex, Signer, SoftwareSigner};
use zroad_core::id::MemberId;
use zroad_core::msg::*;
use zroad_core::now_ms;
use zroad_core::pki::{self, CertAuthority};
use zroad_net::api::{ErrorBody, SignRequest, SignResponse};
use zroad_net::central_client::write_private;
use zroad_net::server::{self, PeerCert, ServerHandle};
use zroad_net::tls;

/// Renewal behaviour of a running signer.
#[derive(Clone, Debug)]
pub struct Options {
    /// Central server URL. When set, the signer renews the member's key and
    /// certificate itself before they expire, and its own TLS certificate from
    /// the private CA it keeps. Without it, renewal is manual.
    pub central_url: Option<String>,
    pub renew_before_days: i64,
    pub check_interval: std::time::Duration,
    /// Wait this long before the first check (mainly for tests).
    pub initial_delay: std::time::Duration,
    /// After renewing, keep signing with the old key for this long so peers and
    /// the hosting node have learned the new one from the directory.
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

pub struct SignerConfig {
    /// Holds `key.pem`, `cert.pem`, `ca.pem` (from `zroad-cli enroll`) and
    /// `tls.pem`, `tls.key` (from [`init`]); the audit log is written here too.
    pub dir: std::path::PathBuf,
    pub listen: String,
    /// The member whose key this is.
    pub member: MemberId,
    /// The only node allowed to ask for signatures.
    pub node: MemberId,
    pub max_per_minute: u32,
    pub options: Options,
}

struct App {
    member: MemberId,
    node: MemberId,
    dir: std::path::PathBuf,
    signer: std::sync::RwLock<Arc<SoftwareSigner>>,
    audit: AuditLog,
    max_per_minute: u32,
    window: AtomicU64,
    count: AtomicU64,
}

/// Create the signer's own TLS identity: a private CA and a server certificate
/// for `sans`. The hosting node pins `signer-ca.pem`.
pub fn init(dir: &Path, sans: &[String]) -> Result<()> {
    if dir.join("tls.pem").exists() {
        bail!("{} is already initialised", dir.display());
    }
    std::fs::create_dir_all(dir)?;
    let new = CertAuthority::generate("Z-Road signer TLS CA", 3650).map_err(|e| anyhow!("{e}"))?;
    let me: MemberId = "ZW/SYS/signer".parse().map_err(|e| anyhow!("{e}"))?;
    let ident = pki::generate_identity(&me, sans).map_err(|e| anyhow!("{e}"))?;
    let leaf = new
        .ca
        .sign_csr(&ident.csr_pem, &me, sans, 365)
        .map_err(|e| anyhow!("{e}"))?;
    std::fs::write(dir.join("signer-ca.pem"), &new.ca.cert_pem)?;
    write_private(&dir.join("tls.key"), &ident.key_pem)?;
    std::fs::write(dir.join("tls.pem"), leaf)?;
    // The CA key stays here (private, 0600) so the signer can re-issue its own TLS
    // certificate without a restart. Delete it to make that renewal manual.
    write_private(&dir.join("signer-ca.key"), &new.key_pem)?;
    Ok(())
}

pub async fn spawn(cfg: SignerConfig) -> Result<ServerHandle> {
    let dir = &cfg.dir;
    let read = |f: &str| {
        std::fs::read_to_string(dir.join(f))
            .with_context(|| format!("reading {}", dir.join(f).display()))
    };
    let key = read("key.pem")?;
    let cert = read("cert.pem")?;
    let signer = SoftwareSigner::from_pkcs8_pem(&key).map_err(|e| anyhow!("{e}"))?;
    let info = pki::inspect_cert_pem(&cert).map_err(|e| anyhow!("{e}"))?;
    if info.member != cfg.member {
        bail!("cert.pem is for {}, expected {}", info.member, cfg.member);
    }
    if info.public_key != Signer::public_key(&signer) {
        bail!("key.pem does not match the key in cert.pem");
    }
    let audit = AuditLog::open(&dir.join("audit").join("log.jsonl")).map_err(|e| anyhow!("{e}"))?;
    let app = Arc::new(App {
        member: cfg.member,
        node: cfg.node,
        dir: cfg.dir.clone(),
        signer: std::sync::RwLock::new(Arc::new(signer)),
        audit,
        max_per_minute: cfg.max_per_minute,
        window: AtomicU64::new(0),
        count: AtomicU64::new(0),
    });
    // The node authenticates with its Z-Road certificate, so client
    // certificates are verified against the Z-Road CA; the server presents its
    // own certificate from the signer's private CA, which the node pins.
    let tls_cert = tls::ReloadableCert::new(&read("tls.pem")?, &read("tls.key")?)?;
    let tls_cfg = tls::server_config_reloadable(
        &read("ca.pem")?,
        tls_cert.clone(),
        tls::ClientAuth::Required,
    )?;
    tokio::spawn(renew_loop(Arc::downgrade(&app), tls_cert, cfg.options));
    let router = Router::new()
        .route("/v1/sign", post(sign))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(app);
    Ok(server::spawn(&cfg.listen, Some(tls_cfg), router).await?)
}

fn refuse(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error: code.into(),
            message: message.into(),
        }),
    )
        .into_response()
}

fn rate_limited(app: &App) -> bool {
    let minute = now_ms() / 60_000;
    if app.window.swap(minute, Ordering::SeqCst) != minute {
        app.count.store(0, Ordering::SeqCst);
    }
    app.count.fetch_add(1, Ordering::SeqCst) >= u64::from(app.max_per_minute)
}

async fn sign(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Option<PeerCert>>,
    Json(req): Json<SignRequest>,
) -> Response {
    use StatusCode as S;
    let Some(peer) = peer.and_then(|p| pki::inspect_cert_der(&p.0).ok()) else {
        return refuse(
            S::UNAUTHORIZED,
            "no_client_certificate",
            "client certificate required",
        );
    };
    if peer.member != app.node {
        tracing::warn!("refusing to sign for {}", peer.member);
        return refuse(
            S::FORBIDDEN,
            "not_the_node",
            "only the hosting node may ask for signatures",
        );
    }
    if rate_limited(&app) {
        return refuse(
            S::TOO_MANY_REQUESTS,
            "rate_limited",
            "signing rate limit reached",
        );
    }
    let Ok(message) = b64_decode(&req.message_b64) else {
        return refuse(S::BAD_REQUEST, "malformed", "message is not base64");
    };
    let Some(split) = message.iter().position(|b| *b == b'\n') else {
        return refuse(S::BAD_REQUEST, "malformed", "message has no domain");
    };
    let (domain, payload) = (&message[..split], &message[split + 1..]);
    let fresh = |ms: u64| now_ms().abs_diff(ms) <= MAX_CLOCK_SKEW_MS;

    // Only sign what is genuinely this member's to say.
    let event = if domain == REQUEST_DOMAIN.as_bytes() {
        let Ok(env) = serde_json::from_slice::<RequestEnvelope>(payload) else {
            return refuse(S::BAD_REQUEST, "malformed", "not a request envelope");
        };
        if env.client.member != app.member {
            return refuse(
                S::FORBIDDEN,
                "not_our_request",
                "the request is not made by this member",
            );
        }
        if env.version != PROTOCOL_VERSION || !fresh(env.issued_at_ms) {
            return refuse(
                S::BAD_REQUEST,
                "stale_or_unsupported",
                "wrong version or timestamp",
            );
        }
        AuditEvent::Signed {
            kind: "request".into(),
            message_id: env.message_id,
            service: env.service.to_string(),
            counterparty: Some(env.service.member.to_string()),
            payload_sha256: sha256_hex(payload),
            node: app.node.to_string(),
        }
    } else if domain == RESPONSE_DOMAIN.as_bytes() {
        let Ok(env) = serde_json::from_slice::<ResponseEnvelope>(payload) else {
            return refuse(S::BAD_REQUEST, "malformed", "not a response envelope");
        };
        if env.provider != app.member {
            return refuse(
                S::FORBIDDEN,
                "not_our_response",
                "the answer is not given by this member",
            );
        }
        if env.version != PROTOCOL_VERSION || !fresh(env.issued_at_ms) {
            return refuse(
                S::BAD_REQUEST,
                "stale_or_unsupported",
                "wrong version or timestamp",
            );
        }
        AuditEvent::Signed {
            kind: "response".into(),
            message_id: env.request_id,
            service: "-".into(),
            counterparty: None,
            payload_sha256: sha256_hex(payload),
            node: app.node.to_string(),
        }
    } else {
        return refuse(
            S::BAD_REQUEST,
            "unsupported_domain",
            "this signer only signs Z-Road requests and responses",
        );
    };

    // Record first: no signature is made that is not on the member's own record.
    if let Err(e) = app.audit.append(event) {
        tracing::error!("cannot write the signer audit log: {e}");
        return refuse(
            S::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "cannot record the signature, so it was not made",
        );
    }
    let signer = app.signer.read().unwrap_or_else(|p| p.into_inner()).clone();
    let sig = Signer::sign(signer.as_ref(), &message);
    Json(SignResponse {
        signature_b64: b64_encode(&sig),
    })
    .into_response()
}

fn days_left(not_after: i64) -> i64 {
    (not_after - (now_ms() / 1000) as i64) / 86_400
}

/// Keep both of the signer's certificates fresh without a restart:
///
/// * the member's own signing certificate, renewed through the central server
///   (needs `central_url`); the new key takes over for later signatures and the
///   hosting node follows it through the directory;
/// * the signer's TLS certificate, re-issued locally from the private CA it keeps.
async fn renew_loop(app: std::sync::Weak<App>, tls_cert: Arc<tls::ReloadableCert>, opts: Options) {
    tokio::time::sleep(opts.initial_delay).await;
    loop {
        let Some(app) = app.upgrade() else { return };
        if let Some(central) = &opts.central_url {
            match renew_member_cert(&app, central, opts.renew_before_days, opts.activation_delay)
                .await
            {
                Ok(true) => tracing::info!("{}: signing key and certificate renewed", app.member),
                Ok(false) => {}
                Err(e) => tracing::error!("cannot renew the member certificate: {e:#}"),
            }
        }
        match renew_tls_cert(&app, &tls_cert, opts.renew_before_days) {
            Ok(true) => tracing::info!("signer TLS certificate renewed"),
            Ok(false) => {}
            Err(e) => tracing::error!("cannot renew the signer TLS certificate: {e:#}"),
        }
        drop(app);
        tokio::time::sleep(opts.check_interval).await;
    }
}

async fn renew_member_cert(
    app: &App,
    central_url: &str,
    renew_before_days: i64,
    activation_delay: std::time::Duration,
) -> Result<bool> {
    let read =
        |f: &str| std::fs::read_to_string(app.dir.join(f)).with_context(|| format!("reading {f}"));
    let (key, cert, ca) = (read("key.pem")?, read("cert.pem")?, read("ca.pem")?);
    let info = pki::inspect_cert_pem(&cert).map_err(|e| anyhow!("{e}"))?;
    if days_left(info.not_after) >= renew_before_days {
        return Ok(false);
    }
    let sans = pki::cert_sans(&cert).map_err(|e| anyhow!("{e}"))?;
    let ident = pki::generate_identity(&app.member, &sans).map_err(|e| anyhow!("{e}"))?;
    let resp =
        zroad_net::central_client::CentralClient::with_identity(central_url, &ca, &cert, &key)?
            .renew(&zroad_net::api::RenewRequest {
                csr_pem: ident.csr_pem,
            })
            .await?;
    let new_signer =
        Arc::new(SoftwareSigner::from_pkcs8_pem(&ident.key_pem).map_err(|e| anyhow!("{e}"))?);
    // Persist first, then wait, then switch: the directory lists the new key already,
    // but peers and the node may not have seen it, so keep signing with the old key
    // until they have. A crash in between leaves usable files on disk.
    for f in ["key.pem", "cert.pem"] {
        let _ = std::fs::rename(app.dir.join(f), app.dir.join(format!("{f}.prev")));
    }
    write_private(&app.dir.join("key.pem"), &ident.key_pem)?;
    std::fs::write(app.dir.join("cert.pem"), &resp.cert_pem)?;
    tokio::time::sleep(activation_delay).await;
    *app.signer.write().unwrap_or_else(|p| p.into_inner()) = new_signer;
    Ok(true)
}

fn renew_tls_cert(
    app: &App,
    tls_cert: &tls::ReloadableCert,
    renew_before_days: i64,
) -> Result<bool> {
    let ca_key = match std::fs::read_to_string(app.dir.join("signer-ca.key")) {
        Ok(k) => k,
        Err(_) => return Ok(false), // CA key removed on purpose: renewal is manual
    };
    let current = std::fs::read_to_string(app.dir.join("tls.pem"))?;
    let info = pki::inspect_cert_pem(&current).map_err(|e| anyhow!("{e}"))?;
    if days_left(info.not_after) >= renew_before_days {
        return Ok(false);
    }
    let ca = CertAuthority::load(
        &std::fs::read_to_string(app.dir.join("signer-ca.pem"))?,
        &ca_key,
    )
    .map_err(|e| anyhow!("{e}"))?;
    let sans = pki::cert_sans(&current).map_err(|e| anyhow!("{e}"))?;
    let me: MemberId = "ZW/SYS/signer".parse().map_err(|e| anyhow!("{e}"))?;
    let ident = pki::generate_identity(&me, &sans).map_err(|e| anyhow!("{e}"))?;
    let leaf = ca
        .sign_csr(&ident.csr_pem, &me, &sans, 365)
        .map_err(|e| anyhow!("{e}"))?;
    tls_cert.set(&leaf, &ident.key_pem)?;
    write_private(&app.dir.join("tls.key"), &ident.key_pem)?;
    std::fs::write(app.dir.join("tls.pem"), leaf)?;
    Ok(true)
}
