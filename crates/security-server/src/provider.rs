//! The provider side: authenticate the peer, verify and authorise the signed
//! request, forward it to the internal system and sign the answer.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use bytes::Bytes;
use zroad_core::audit::AuditEvent;
use zroad_core::crypto::{hmac_sha256_hex, sha256_hex};
use zroad_core::msg::*;
use zroad_core::{now_ms, pki};
use zroad_net::api::ErrorBody;
use zroad_net::server::PeerCert;

use crate::state::{AppState, DedupeEntry, DedupeState};

pub struct Reject {
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn reject(status: StatusCode, code: &'static str, message: impl Into<String>) -> Reject {
    Reject {
        status,
        code,
        message: message.into(),
    }
}

#[derive(Default)]
struct Attempt {
    message_id: String,
    peer: String,
    client: String,
    service: String,
    request_sha: String,
    subject_ref: Option<String>,
}

pub const DEDUPE_TTL_MS: u64 = 15 * 60 * 1000;
const DEDUPE_MAX: usize = 100_000;

/// The network entry point. A shared node hosts several members, so the first
/// job is to find the one being addressed. The envelope is only peeked at here
/// (unverified); the chosen member then checks everything properly.
pub async fn exchange(
    State(node): State<Arc<crate::state::Node>>,
    Extension(peer): Extension<Option<PeerCert>>,
    body: Bytes,
) -> Response {
    let st = match &node.only {
        Some(only) => only.clone(),
        None => match target_member(&body).and_then(|m| node.members.get(&m).cloned()) {
            Some(st) => st,
            None => {
                tracing::warn!("request for a member this node does not host");
                let mut r = (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: "wrong_provider".into(),
                        message: "this security server does not serve that member".into(),
                    }),
                )
                    .into_response();
                r.headers_mut()
                    .insert("z-road-error", "wrong_provider".parse().expect("static"));
                return r;
            }
        },
    };
    exchange_for(st, peer, body).await
}

fn target_member(raw: &[u8]) -> Option<zroad_core::id::MemberId> {
    #[derive(serde::Deserialize)]
    struct Wire {
        request: SignedMessage,
    }
    #[derive(serde::Deserialize)]
    struct Peek {
        service: zroad_core::id::ServiceId,
    }
    let wire: Wire = serde_json::from_slice(raw).ok()?;
    let peek: Peek = serde_json::from_slice(&wire.request.payload().ok()?).ok()?;
    Some(peek.service.member)
}

async fn exchange_for(st: Arc<AppState>, peer: Option<PeerCert>, body: Bytes) -> Response {
    let mut a = Attempt::default();
    match process(&st, peer, &body, &mut a).await {
        Ok((resp, status, response_sha, duplicate)) => {
            // Fail closed: an answer that cannot be recorded is not delivered.
            // The consumer retries; the message id makes that idempotent.
            let recorded = log(
                &st,
                &a,
                if duplicate { "duplicate" } else { "ok" }.into(),
                Some(status),
                Some(response_sha),
            );
            if !recorded {
                let mut r = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorBody {
                        error: "audit_unavailable".into(),
                        message: "the provider cannot record this exchange, so it did not answer"
                            .into(),
                    }),
                )
                    .into_response();
                r.headers_mut()
                    .insert("z-road-error", "audit_unavailable".parse().expect("static"));
                return r;
            }
            Json(resp).into_response()
        }
        Err(r) => {
            let outcome = if r.status.is_server_error() {
                format!("error:{}", r.code)
            } else {
                format!("denied:{}", r.code)
            };
            log(&st, &a, outcome, None, None);
            let mut resp = (
                r.status,
                Json(ErrorBody {
                    error: r.code.into(),
                    message: r.message,
                }),
            )
                .into_response();
            resp.headers_mut()
                .insert("z-road-error", r.code.parse().expect("static header value"));
            resp
        }
    }
}

/// Write the audit record. Returns false if it could not be written.
fn log(
    st: &AppState,
    a: &Attempt,
    outcome: String,
    status: Option<u16>,
    response_sha: Option<String>,
) -> bool {
    let r = st.audit.append(AuditEvent::Exchange {
        role: "provider".into(),
        message_id: a.message_id.clone(),
        peer: a.peer.clone(),
        client: a.client.clone(),
        service: a.service.clone(),
        request_sha256: a.request_sha.clone(),
        response_sha256: response_sha,
        status,
        outcome,
        subject_ref: a.subject_ref.clone(),
    });
    if let Err(e) = r {
        tracing::error!("cannot write audit log: {e}");
        return false;
    }
    true
}

fn rate_limited(st: &AppState, member: &str) -> bool {
    let sec = now_ms() / 1000;
    let mut m = st.rate.lock().unwrap_or_else(|p| p.into_inner());
    if m.len() > 10_000 {
        m.retain(|_, (s, _)| *s == sec);
    }
    let e = m.entry(member.to_string()).or_insert((sec, 0));
    if e.0 != sec {
        *e = (sec, 0);
    }
    e.1 += 1;
    e.1 > st.cfg.rate_limit_per_sec
}

/// Is `info` an active member whose registered certificate is the one presented?
fn is_active_peer(st: &AppState, info: &pki::CertInfo) -> bool {
    st.dir
        .snapshot()
        .get_active(&info.member)
        .and_then(|m| m.cert_pem.as_deref())
        .and_then(|pem| pki::inspect_cert_pem(pem).ok())
        .map(|c| c.fingerprint == info.fingerprint)
        .unwrap_or(false)
}

async fn process(
    st: &AppState,
    peer: Option<PeerCert>,
    raw: &[u8],
    a: &mut Attempt,
) -> Result<(ExchangeResponse, u16, String, bool), Reject> {
    use StatusCode as S;
    let peer = peer.ok_or_else(|| {
        reject(
            S::UNAUTHORIZED,
            "no_client_certificate",
            "client certificate required",
        )
    })?;
    let info = pki::inspect_cert_der(&peer.0)
        .map_err(|e| reject(S::UNAUTHORIZED, "bad_client_certificate", e.to_string()))?;
    a.peer = info.member.to_string();

    if rate_limited(st, &a.peer) {
        return Err(reject(
            S::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests",
        ));
    }
    if !is_active_peer(st, &info) {
        st.dir
            .refresh_throttled(std::time::Duration::from_secs(2))
            .await;
        if !is_active_peer(st, &info) {
            return Err(reject(
                S::FORBIDDEN,
                "member_not_active",
                "member is unknown, revoked or presented an outdated certificate",
            ));
        }
    }

    let wire: ExchangeRequest = serde_json::from_slice(raw).map_err(|e| {
        reject(
            S::BAD_REQUEST,
            "malformed",
            format!("unreadable request: {e}"),
        )
    })?;
    a.request_sha = wire
        .request
        .payload_sha256()
        .map_err(|e| reject(S::BAD_REQUEST, "malformed", e.to_string()))?;
    let env: RequestEnvelope = wire
        .request
        .open(REQUEST_DOMAIN, &info.public_key)
        .map_err(|e| reject(S::BAD_REQUEST, "bad_signature", e.to_string()))?;
    a.message_id = env.message_id.clone();
    a.client = env.client.to_string();
    a.service = env.service.to_string();
    a.subject_ref = env
        .subject
        .as_deref()
        .map(|s| hmac_sha256_hex(&st.subject_key, s.as_bytes()));

    if env.version != PROTOCOL_VERSION {
        return Err(reject(
            S::BAD_REQUEST,
            "unsupported_version",
            "unsupported protocol version",
        ));
    }
    if env.message_id.is_empty() || env.message_id.len() > 64 {
        return Err(reject(S::BAD_REQUEST, "malformed", "bad message id"));
    }
    if env.client.member != info.member {
        return Err(reject(
            S::FORBIDDEN,
            "client_mismatch",
            "client does not belong to the authenticated member",
        ));
    }
    if env.service.member != st.cfg.member_id {
        return Err(reject(
            S::BAD_REQUEST,
            "wrong_provider",
            "this security server does not serve that member",
        ));
    }
    let skew = now_ms().abs_diff(env.issued_at_ms);
    if skew > MAX_CLOCK_SKEW_MS {
        return Err(reject(
            S::BAD_REQUEST,
            "stale_request",
            "request timestamp is outside the allowed clock skew",
        ));
    }
    let body = b64_decode(&wire.body_b64)
        .map_err(|e| reject(S::BAD_REQUEST, "malformed", e.to_string()))?;
    if body.len() > st.cfg.max_body_bytes {
        return Err(reject(
            S::PAYLOAD_TOO_LARGE,
            "too_large",
            "request body too large",
        ));
    }
    if sha256_hex(&body) != env.body_sha256 {
        return Err(reject(
            S::BAD_REQUEST,
            "body_mismatch",
            "body does not match the signed hash",
        ));
    }

    let local = env.service.local_key();
    let upstream = st
        .cfg
        .upstream_for(&local)
        .ok_or_else(|| reject(S::NOT_FOUND, "unknown_service", "no such service"))?
        .to_string();
    if !st.cfg.is_allowed(&local, &env.client) {
        return Err(reject(
            S::FORBIDDEN,
            "access_denied",
            "client is not allowed to use this service",
        ));
    }

    // Structural validation: nothing malformed reaches the internal system.
    if let Some((_, schema)) = st.schemas.get(&local).and_then(|s| s.request.as_ref()) {
        if !zroad_core::schema::is_json_content_type(&env.content_type) {
            return Err(reject(
                S::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "this service only accepts JSON",
            ));
        }
        if let Err(errors) = schema.check_bytes(&body) {
            return Err(reject(
                S::BAD_REQUEST,
                "schema_violation",
                errors.join("; "),
            ));
        }
    }

    // Duplicate and replay handling.
    let key = format!("{}|{}", a.peer, env.message_id);
    let fingerprint = (a.client.clone(), a.service.clone(), env.body_sha256.clone());
    let now = now_ms();
    {
        let mut map = st.dedupe.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= DEDUPE_MAX {
            map.retain(|_, e| e.expires_ms > now);
            if map.len() >= DEDUPE_MAX {
                return Err(reject(
                    S::SERVICE_UNAVAILABLE,
                    "busy",
                    "too many outstanding messages",
                ));
            }
        }
        if let Some(e) = map.get(&key).filter(|e| e.expires_ms > now) {
            if matches!(e.state, DedupeState::Processed) {
                return Err(reject(
                    S::CONFLICT,
                    "already_processed",
                    "this message id was already answered before a restart; send a new message",
                ));
            }
            if e.fingerprint != fingerprint {
                return Err(reject(
                    S::CONFLICT,
                    "replay",
                    "message id reused with different content",
                ));
            }
            match &e.state {
                DedupeState::InFlight => {
                    return Err(reject(
                        S::CONFLICT,
                        "in_flight",
                        "message is already being processed",
                    ));
                }
                DedupeState::Done {
                    status,
                    body,
                    content_type,
                } => {
                    let (resp, sha) =
                        sign_response(st, &env, &a.request_sha, *status, body, content_type)?;
                    return Ok((resp, *status, sha, true));
                }
                DedupeState::Processed => unreachable!("handled above"),
            }
        }
        map.insert(
            key.clone(),
            DedupeEntry {
                expires_ms: now + DEDUPE_TTL_MS,
                fingerprint,
                state: DedupeState::InFlight,
            },
        );
    }

    // Write-ahead: record that the request is about to be forwarded. If the log
    // cannot be written the request is refused *before* it reaches the internal
    // system, so there is never an effect without a record.
    if !log(st, a, "received".into(), None, None) {
        st.dedupe
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
        return Err(reject(
            S::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "the provider cannot record this exchange, so it did not process it",
        ));
    }

    let forwarded = zroad_net::request(
        "POST",
        &upstream,
        &[
            ("content-type", env.content_type.as_str()),
            ("x-zroad-client", &a.client),
            ("x-zroad-member", &a.peer),
            ("x-zroad-message-id", &env.message_id),
        ],
        Bytes::from(body),
        None,
        std::time::Duration::from_secs(st.cfg.upstream_timeout_secs),
    )
    .await;
    let up = match forwarded {
        Ok(r) => r,
        Err(e) => {
            st.dedupe
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
            tracing::warn!("upstream {upstream} failed: {e}");
            return Err(reject(
                S::BAD_GATEWAY,
                "upstream_unavailable",
                "the provider's internal system did not answer",
            ));
        }
    };
    let content_type = up
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    if (200..300).contains(&up.status) {
        if let Some(sch) = st.schemas.get(&local) {
            if let Some((_, schema)) = &sch.response {
                if let Err(errors) = schema.check_bytes(&up.body) {
                    tracing::warn!(
                        "answer of {local} violates its response schema: {}",
                        errors.join("; ")
                    );
                    if sch.enforce_response {
                        st.dedupe
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&key);
                        return Err(reject(
                            S::BAD_GATEWAY,
                            "upstream_schema_violation",
                            "the provider's system returned an answer that does not match its published schema",
                        ));
                    }
                }
            }
        }
    }
    let (resp, sha) = sign_response(st, &env, &a.request_sha, up.status, &up.body, &content_type)?;
    {
        let mut map = st.dedupe.lock().unwrap_or_else(|p| p.into_inner());
        if up.status < 500 {
            if let Some(e) = map.get_mut(&key) {
                e.state = DedupeState::Done {
                    status: up.status,
                    body: up.body.clone(),
                    content_type,
                };
            }
        } else {
            map.remove(&key);
        }
    }
    Ok((resp, up.status, sha, false))
}

fn sign_response(
    st: &AppState,
    env: &RequestEnvelope,
    request_sha: &str,
    status: u16,
    body: &[u8],
    content_type: &str,
) -> Result<(ExchangeResponse, String), Reject> {
    let body_sha = sha256_hex(body);
    let envelope = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        request_id: env.message_id.clone(),
        request_sha256: request_sha.to_string(),
        provider: st.cfg.member_id.clone(),
        status,
        issued_at_ms: now_ms(),
        body_sha256: body_sha.clone(),
        content_type: content_type.to_string(),
    };
    let signed = SignedMessage::sign(RESPONSE_DOMAIN, &envelope, st.identity().signer.as_ref())
        .map_err(|e| reject(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
    Ok((
        ExchangeResponse {
            response: signed,
            body_b64: b64_encode(body),
        },
        body_sha,
    ))
}
