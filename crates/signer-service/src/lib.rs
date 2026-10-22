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
}

struct App {
    member: MemberId,
    node: MemberId,
    signer: SoftwareSigner,
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
    // the CA key is not needed again; it is discarded on purpose
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
        signer,
        audit,
        max_per_minute: cfg.max_per_minute,
        window: AtomicU64::new(0),
        count: AtomicU64::new(0),
    });
    // The node authenticates with its Z-Road certificate, so client
    // certificates are verified against the Z-Road CA; the server presents its
    // own certificate from the signer's private CA, which the node pins.
    let tls_cfg = tls::server_config(
        &read("ca.pem")?,
        &read("tls.pem")?,
        &read("tls.key")?,
        tls::ClientAuth::Required,
    )?;
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
    let sig = Signer::sign(&app.signer, &message);
    Json(SignResponse {
        signature_b64: b64_encode(&sig),
    })
    .into_response()
}
