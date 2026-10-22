//! The internal API: what an organisation's own systems call, plus the
//! administrative endpoints (audit, proofs, citizen access log).

#![allow(clippy::result_large_err)] // the Err variant is an HTTP response we return as-is

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use zroad_core::audit::{self, AuditEvent};
use zroad_core::crypto::{ct_eq, hmac_sha256_hex};
use zroad_core::id::{ClientId, ServiceId};
use zroad_core::msg::b64_encode;
use zroad_core::{now_ms, random_id};
use zroad_net::api::ErrorBody;

use crate::consumer::{self, CallError, CallParams};
use crate::outbox::{OutboxItem, OutboxStatus};
use crate::state::AppState;

pub fn router(st: Arc<AppState>) -> Router {
    let limit = st.cfg.max_body_bytes + 1024;
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/r1/*path", post(call))
        .route("/internal/v1/outbox/:id", get(outbox_status))
        .route("/admin/v1/access-log", get(access_log))
        .route("/admin/v1/audit/status", get(audit_status))
        .route("/admin/v1/identity", get(identity))
        .route("/admin/v1/renew", post(renew_now))
        .route("/admin/v1/catalogue/publish", post(publish_catalogue))
        .route("/admin/v1/proofs/:id", get(proof))
        .route("/admin/v1/directory/refresh", post(refresh_directory))
        .route("/admin/v1/anchor", post(anchor_now))
        .layer(axum::extract::DefaultBodyLimit::max(limit))
        .with_state(st)
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    let mut r = (
        status,
        Json(ErrorBody {
            error: code.into(),
            message: message.into(),
        }),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(code) {
        r.headers_mut().insert("z-road-error", v);
    }
    r
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

fn check_internal(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    match &st.cfg.internal_token {
        Some(t) if !ct_eq(bearer(headers).as_bytes(), t.as_bytes()) => Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "internal token required",
        )),
        _ => Ok(()),
    }
}

fn check_admin(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if ct_eq(bearer(headers).as_bytes(), st.cfg.admin_token.as_bytes()) {
        Ok(())
    } else {
        Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "admin token required",
        ))
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

const PROOF_HEADER_MAX: usize = 48 * 1024;

async fn call(
    State(st): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_internal(&st, &headers) {
        return r;
    }
    let service: ServiceId = match path.parse() {
        Ok(s) => s,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("bad service path: {e}"),
            )
        }
    };
    let client: ClientId = match header(&headers, "z-road-client").map(str::parse) {
        Some(Ok(c)) => c,
        Some(Err(e)) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("bad Z-Road-Client: {e}"),
            )
        }
        None => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Z-Road-Client header required",
            )
        }
    };
    let params = CallParams {
        client,
        service,
        body: body.clone(),
        content_type: header(&headers, "content-type")
            .unwrap_or("application/json")
            .to_string(),
        subject: header(&headers, "z-road-subject").map(str::to_string),
        message_id: None,
    };

    if header(&headers, "z-road-mode")
        .map(|m| m.eq_ignore_ascii_case("async"))
        .unwrap_or(false)
    {
        let id = random_id();
        let item = OutboxItem {
            id: id.clone(),
            client: params.client.to_string(),
            service: params.service.to_string(),
            body_b64: b64_encode(&body),
            content_type: params.content_type,
            subject: params.subject,
            attempts: 0,
            next_attempt_ms: 0,
            created_ms: now_ms(),
            last_error: None,
        };
        if st.outbox.put(&item).is_err() {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "cannot write outbox",
            );
        }
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "message_id": id,
                "status_url": format!("/internal/v1/outbox/{id}"),
            })),
        )
            .into_response();
    }

    match consumer::call(&st, &params).await {
        Ok(ok) => {
            let mut resp = Response::new(axum::body::Body::from(ok.body));
            *resp.status_mut() = StatusCode::from_u16(ok.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let h = resp.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&ok.content_type) {
                h.insert("content-type", v);
            }
            if let Ok(v) = HeaderValue::from_str(&ok.message_id) {
                h.insert("z-road-message-id", v);
            }
            if let Ok(v) = HeaderValue::from_str(&params.service.member.to_string()) {
                h.insert("z-road-provider", v);
            }
            if let Ok(bytes) = serde_json::to_vec(&ok.proof) {
                if bytes.len() <= PROOF_HEADER_MAX {
                    if let Ok(v) = HeaderValue::from_str(&b64_encode(&bytes)) {
                        h.insert(HeaderName::from_static("z-road-proof"), v);
                    }
                }
            }
            resp
        }
        Err(e) => {
            let status = match &e {
                CallError::Invalid(_) | CallError::SchemaViolation(_) => StatusCode::BAD_REQUEST,
                CallError::UnknownProvider(_) => StatusCode::NOT_FOUND,
                CallError::Unreachable(_) => StatusCode::SERVICE_UNAVAILABLE,
                CallError::Remote { status, .. } => {
                    StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
                }
                CallError::BadResponse(_) => StatusCode::BAD_GATEWAY,
                CallError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            let mut r = error(status, e.code(), e.message());
            if e.retryable() {
                r.headers_mut()
                    .insert("retry-after", HeaderValue::from_static("5"));
            }
            r
        }
    }
}

async fn outbox_status(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = check_internal(&st, &headers) {
        return r;
    }
    match st.outbox.status(&id) {
        Some(s) => Json::<OutboxStatus>(s).into_response(),
        None => error(StatusCode::NOT_FOUND, "not_found", "unknown message id"),
    }
}

#[derive(Deserialize)]
struct AccessQuery {
    subject: String,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct AccessRecord {
    time_ms: u64,
    accessed_by: String,
    client: String,
    service: String,
    message_id: String,
    outcome: String,
}

/// Who has looked up this data subject? This is the data behind a citizen
/// facing "who accessed my data" page. It must sit behind the citizen's own
/// authentication; the admin token here is for the operator's portal backend.
async fn access_log(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AccessQuery>,
) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    let want = hmac_sha256_hex(&st.subject_key, q.subject.as_bytes());
    let entries = match audit::read_entries(st.audit.path()) {
        Ok(e) => e,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    };
    let mut out: Vec<AccessRecord> = entries
        .into_iter()
        .filter_map(|e| match e.event {
            AuditEvent::Exchange {
                role,
                subject_ref: Some(r),
                peer,
                client,
                service,
                message_id,
                outcome,
                ..
            } if role == "provider" && r == want && outcome != "received" => Some(AccessRecord {
                time_ms: e.ts_ms,
                accessed_by: peer,
                client,
                service,
                message_id,
                outcome,
            }),
            _ => None,
        })
        .collect();
    out.reverse();
    out.truncate(q.limit.unwrap_or(100).min(1000));
    Json(out).into_response()
}

async fn audit_status(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    match audit::verify_file(st.audit.path()) {
        Ok(r) => Json(serde_json::json!({
            "verified": true,
            "entries": r.entries,
            "head_hash": r.head_hash,
            "anchors": r.anchors.len(),
        }))
        .into_response(),
        Err(e) => {
            Json(serde_json::json!({ "verified": false, "error": e.to_string() })).into_response()
        }
    }
}

async fn proof(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "bad message id");
    }
    match std::fs::read(st.proofs_dir.join(format!("{id}.json"))) {
        Ok(b) => ([("content-type", "application/json")], b).into_response(),
        Err(_) => error(
            StatusCode::NOT_FOUND,
            "not_found",
            "no proof stored for this message id",
        ),
    }
}

async fn refresh_directory(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    match st.dir.refresh().await {
        Ok(()) => Json(serde_json::json!({ "version": st.dir.snapshot().version })).into_response(),
        Err(e) => error(
            StatusCode::BAD_GATEWAY,
            "central_unreachable",
            e.to_string(),
        ),
    }
}

async fn anchor_now(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    match crate::anchor::anchor_once(&st).await {
        Ok(Some(seq)) => Json(serde_json::json!({ "anchor_seq": seq })).into_response(),
        Ok(None) => {
            Json(serde_json::json!({ "anchor_seq": null, "note": "nothing new to anchor" }))
                .into_response()
        }
        Err(e) => error(StatusCode::BAD_GATEWAY, "anchor_failed", e.to_string()),
    }
}

/// Who this security server is and when its certificate expires.
async fn identity(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    match st.own_info() {
        Ok(i) => {
            let days_left = (i.not_after - (now_ms() / 1000) as i64) / 86_400;
            Json(serde_json::json!({
                "member": i.member,
                "certificate_fingerprint": i.fingerprint,
                "certificate_expires_unix": i.not_after,
                "certificate_days_left": days_left,
            }))
            .into_response()
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
    }
}

/// Renew this member's certificate now, without restarting.
async fn renew_now(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    match crate::renew::renew(&st).await {
        Ok(fp) => Json(serde_json::json!({ "renewed": true, "certificate_fingerprint": fp }))
            .into_response(),
        Err(e) => error(StatusCode::BAD_GATEWAY, "renew_failed", e.to_string()),
    }
}

/// Re-publish this member's services to the central catalogue now.
async fn publish_catalogue(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = check_admin(&st, &headers) {
        return r;
    }
    match crate::catalogue::publish(&st).await {
        Ok(n) => Json(serde_json::json!({ "published": n })).into_response(),
        Err(e) => error(StatusCode::BAD_GATEWAY, "publish_failed", format!("{e:#}")),
    }
}
