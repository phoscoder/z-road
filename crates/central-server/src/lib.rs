//! The Z-Road central server: the certificate authority and the member
//! directory. It never sees or stores exchanged data.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use zroad_core::crypto::{ct_eq, sha256_hex};
use zroad_core::directory::{Catalogue, CatalogueEntry, Directory, MemberRecord, MemberStatus};
use zroad_core::id::MemberId;
use zroad_core::pki::{self, CertAuthority};
use zroad_core::{now_ms, random_secret};
use zroad_net::api::*;
use zroad_net::central_client::write_private;
use zroad_net::server::{self, PeerCert, ServerHandle};
use zroad_net::tls;

const CERT_VALID_DAYS: i64 = 365;
const CA_VALID_DAYS: i64 = 3650;

#[derive(Serialize, Deserialize, Default)]
struct Stored {
    version: u64,
    members: Vec<MemberRecord>,
    /// SHA-256 of each outstanding enrolment token, by member id.
    token_hashes: BTreeMap<String, String>,
    /// Published services by member id.
    #[serde(default)]
    catalogue: BTreeMap<String, Vec<CatalogueEntry>>,
}

struct App {
    ca: CertAuthority,
    admin_token: String,
    state: Mutex<Stored>,
    state_path: PathBuf,
}

/// Create a new central server data directory: CA, TLS identity, admin token.
pub fn init(dir: &Path, sans: &[String]) -> Result<()> {
    if dir.join("ca.pem").exists() {
        bail!("{} is already initialised", dir.display());
    }
    std::fs::create_dir_all(dir)?;
    let new_ca =
        CertAuthority::generate("Z-Road Root CA", CA_VALID_DAYS).map_err(|e| anyhow!("{e}"))?;
    write_private(&dir.join("ca.key"), &new_ca.key_pem)?;
    std::fs::write(dir.join("ca.pem"), &new_ca.ca.cert_pem)?;

    let me: MemberId = "ZW/SYS/central".parse().map_err(|e| anyhow!("{e}"))?;
    let ident = pki::generate_identity(&me, sans).map_err(|e| anyhow!("{e}"))?;
    let cert = new_ca
        .ca
        .sign_csr(&ident.csr_pem, &me, sans, CERT_VALID_DAYS)
        .map_err(|e| anyhow!("{e}"))?;
    write_private(&dir.join("server.key"), &ident.key_pem)?;
    std::fs::write(dir.join("server.pem"), cert)?;
    write_private(&dir.join("admin_token"), &random_secret())?;
    save(&dir.join("state.json"), &Stored::default())?;
    Ok(())
}

fn save(path: &Path, s: &Stored) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Start serving on `addr` (TLS, server authentication only).
pub async fn spawn(dir: &Path, addr: &str) -> Result<ServerHandle> {
    let read =
        |f: &str| std::fs::read_to_string(dir.join(f)).with_context(|| format!("reading {f}"));
    let ca_pem = read("ca.pem")?;
    let ca = CertAuthority::load(&ca_pem, &read("ca.key")?).map_err(|e| anyhow!("{e}"))?;
    let state: Stored = serde_json::from_str(&read("state.json")?)?;
    let app = Arc::new(App {
        ca,
        admin_token: read("admin_token")?.trim().to_string(),
        state: Mutex::new(state),
        state_path: dir.join("state.json"),
    });
    let tls_cfg = tls::server_config(
        &ca_pem,
        &read("server.pem")?,
        &read("server.key")?,
        tls::ClientAuth::Optional,
    )?;
    let router = Router::new()
        .route("/v1/ca", get(get_ca))
        .route("/v1/directory", get(get_directory))
        .route("/v1/enroll", post(enroll))
        .route("/v1/renew", post(renew))
        .route("/v1/catalogue", get(get_catalogue).post(publish_catalogue))
        .route("/v1/admin/members", post(add_member))
        .route("/v1/admin/revoke", post(revoke))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(app);
    Ok(server::spawn(addr, Some(tls_cfg), router).await?)
}

struct ApiError(StatusCode, &'static str, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(ErrorBody {
                error: self.1.into(),
                message: self.2,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "bad_request", msg.into())
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("internal error: {e}");
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error".into(),
    )
}

fn require_admin(app: &App, headers: &HeaderMap) -> std::result::Result<(), ApiError> {
    let given = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if ct_eq(given.as_bytes(), app.admin_token.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "admin token required".into(),
        ))
    }
}

fn endpoint_host(endpoint: &str) -> std::result::Result<String, ApiError> {
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|_| bad("endpoint is not a valid URL"))?;
    if uri.scheme_str() != Some("https") {
        return Err(bad("endpoint must be an https:// URL"));
    }
    uri.host()
        .map(str::to_string)
        .ok_or_else(|| bad("endpoint has no host"))
}

async fn get_ca(State(app): State<Arc<App>>) -> String {
    app.ca.cert_pem.clone()
}

async fn get_directory(State(app): State<Arc<App>>) -> Json<Directory> {
    let st = app.state.lock().unwrap_or_else(|p| p.into_inner());
    Json(Directory {
        version: st.version,
        generated_at_ms: now_ms(),
        members: st.members.clone(),
    })
}

async fn add_member(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<AddMemberResponse> {
    require_admin(&app, &headers)?;
    endpoint_host(&req.endpoint)?;
    let token = random_secret();
    let mut st = app.state.lock().unwrap_or_else(|p| p.into_inner());
    match st.members.iter_mut().find(|m| m.id == req.id) {
        Some(m) if m.status == MemberStatus::Revoked => {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "revoked",
                "this member was revoked; register a new member code".into(),
            ))
        }
        // Re-issuing a token lets an existing member rotate its certificate.
        Some(m) => {
            m.name = req.name;
            m.endpoint = req.endpoint;
        }
        None => st.members.push(MemberRecord {
            id: req.id.clone(),
            name: req.name,
            endpoint: req.endpoint,
            status: MemberStatus::Pending,
            cert_pem: None,
        }),
    }
    st.token_hashes
        .insert(req.id.to_string(), sha256_hex(token.as_bytes()));
    st.version += 1;
    save(&app.state_path, &st).map_err(internal)?;
    Ok(Json(AddMemberResponse {
        member_id: req.id,
        enrollment_token: token,
    }))
}

async fn enroll(
    State(app): State<Arc<App>>,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<EnrollResponse> {
    let denied = || {
        ApiError(
            StatusCode::FORBIDDEN,
            "forbidden",
            "unknown member or invalid token".into(),
        )
    };
    let mut st = app.state.lock().unwrap_or_else(|p| p.into_inner());
    let key = req.member_id.to_string();
    let expected = st.token_hashes.get(&key).cloned().ok_or_else(denied)?;
    if !ct_eq(
        sha256_hex(req.enrollment_token.as_bytes()).as_bytes(),
        expected.as_bytes(),
    ) {
        return Err(denied());
    }
    let idx = st
        .members
        .iter()
        .position(|m| m.id == req.member_id)
        .ok_or_else(denied)?;
    if st.members[idx].status == MemberStatus::Revoked {
        return Err(denied());
    }
    let host = endpoint_host(&st.members[idx].endpoint)?;
    let cert_pem = app
        .ca
        .sign_csr(&req.csr_pem, &req.member_id, &[host], CERT_VALID_DAYS)
        .map_err(|e| bad(e.to_string()))?;
    st.members[idx].cert_pem = Some(cert_pem.clone());
    st.members[idx].status = MemberStatus::Active;
    st.token_hashes.remove(&key);
    st.version += 1;
    save(&app.state_path, &st).map_err(internal)?;
    Ok(Json(EnrollResponse {
        cert_pem,
        ca_pem: app.ca.cert_pem.clone(),
    }))
}

async fn revoke(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> ApiResult<serde_json::Value> {
    require_admin(&app, &headers)?;
    let mut st = app.state.lock().unwrap_or_else(|p| p.into_inner());
    let m = st
        .members
        .iter_mut()
        .find(|m| m.id == req.member_id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "not_found", "no such member".into()))?;
    m.status = MemberStatus::Revoked;
    st.token_hashes.remove(&req.member_id.to_string());
    st.version += 1;
    save(&app.state_path, &st).map_err(internal)?;
    Ok(Json(serde_json::json!({ "revoked": req.member_id })))
}

/// Issue a fresh certificate to an active member that proves possession of its
/// current one over mutual TLS. The old certificate stops being accepted by
/// peers as soon as they refresh their directory.
async fn renew(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Option<PeerCert>>,
    Json(req): Json<RenewRequest>,
) -> ApiResult<EnrollResponse> {
    let denied = || {
        ApiError(
            StatusCode::FORBIDDEN,
            "forbidden",
            "renewal needs the member's current, valid certificate".into(),
        )
    };
    let peer = peer.ok_or_else(denied)?;
    let info = pki::inspect_cert_der(&peer.0).map_err(|_| denied())?;
    let mut st = app.state.lock().unwrap_or_else(|p| p.into_inner());
    let idx = st
        .members
        .iter()
        .position(|m| m.id == info.member && m.status == MemberStatus::Active)
        .ok_or_else(denied)?;
    let registered = st.members[idx]
        .cert_pem
        .as_deref()
        .and_then(|p| pki::inspect_cert_pem(p).ok())
        .ok_or_else(denied)?;
    if registered.fingerprint != info.fingerprint {
        return Err(denied());
    }
    let host = endpoint_host(&st.members[idx].endpoint)?;
    let cert_pem = app
        .ca
        .sign_csr(&req.csr_pem, &info.member, &[host], CERT_VALID_DAYS)
        .map_err(|e| bad(e.to_string()))?;
    st.members[idx].cert_pem = Some(cert_pem.clone());
    st.version += 1;
    save(&app.state_path, &st).map_err(internal)?;
    Ok(Json(EnrollResponse {
        cert_pem,
        ca_pem: app.ca.cert_pem.clone(),
    }))
}

/// Active members whose certificate is the one presented.
fn authenticate_member(
    st: &Stored,
    peer: Option<PeerCert>,
) -> std::result::Result<MemberId, ApiError> {
    let denied = || {
        ApiError(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this needs the member's current, valid certificate".into(),
        )
    };
    let info = pki::inspect_cert_der(&peer.ok_or_else(denied)?.0).map_err(|_| denied())?;
    let registered = st
        .members
        .iter()
        .find(|m| m.id == info.member && m.status == MemberStatus::Active)
        .and_then(|m| m.cert_pem.as_deref())
        .and_then(|p| pki::inspect_cert_pem(p).ok())
        .ok_or_else(denied)?;
    if registered.fingerprint != info.fingerprint {
        return Err(denied());
    }
    Ok(info.member)
}

async fn get_catalogue(State(app): State<Arc<App>>) -> Json<Catalogue> {
    let st = app.state.lock().unwrap_or_else(|p| p.into_inner());
    let active = |id: &str| {
        st.members
            .iter()
            .any(|m| m.id.to_string() == id && m.status == MemberStatus::Active)
    };
    let mut entries: Vec<CatalogueEntry> = st
        .catalogue
        .iter()
        .filter(|(id, _)| active(id))
        .flat_map(|(_, v)| v.iter().cloned())
        .collect();
    entries.sort_by_key(|e| e.service.to_string());
    Json(Catalogue { entries })
}

const MAX_SERVICES_PER_MEMBER: usize = 200;

async fn publish_catalogue(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Option<PeerCert>>,
    Json(req): Json<PublishCatalogueRequest>,
) -> ApiResult<serde_json::Value> {
    let mut st = app.state.lock().unwrap_or_else(|p| p.into_inner());
    let member = authenticate_member(&st, peer)?;
    if req.services.len() > MAX_SERVICES_PER_MEMBER {
        return Err(bad("too many services"));
    }
    let mut entries = Vec::new();
    for item in req.services {
        let service: zroad_core::id::ServiceId = format!("{member}/{}", item.id)
            .parse()
            .map_err(|e: zroad_core::Error| bad(e.to_string()))?;
        if item.title.len() > 100 || item.description.len() > 500 {
            return Err(bad("title (100) or description (500) too long"));
        }
        for (what, schema) in [
            ("request", &item.request_schema),
            ("response", &item.response_schema),
        ] {
            if let Some(s) = schema {
                zroad_core::schema::CompiledSchema::compile(s)
                    .map_err(|e| bad(format!("{} {what}_schema: {e}", item.id)))?;
            }
        }
        entries.push(CatalogueEntry {
            service,
            title: item.title,
            description: item.description,
            request_schema: item.request_schema,
            response_schema: item.response_schema,
        });
    }
    let n = entries.len();
    st.catalogue.insert(member.to_string(), entries);
    save(&app.state_path, &st).map_err(internal)?;
    Ok(Json(serde_json::json!({ "published": n })))
}
