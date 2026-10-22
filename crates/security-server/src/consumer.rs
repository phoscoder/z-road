//! The consumer side: sign a request, send it over mutual TLS and verify the
//! signed answer.

use bytes::Bytes;
use zroad_core::audit::AuditEvent;
use zroad_core::crypto::sha256_hex;
use zroad_core::id::{ClientId, ServiceId};
use zroad_core::msg::*;
use zroad_core::{now_ms, pki, random_id};
use zroad_net::api::ErrorBody;
use zroad_net::{request, NetError};

use crate::state::AppState;

pub struct CallParams {
    pub client: ClientId,
    pub service: ServiceId,
    pub body: Bytes,
    pub content_type: String,
    pub subject: Option<String>,
    /// Reused across retries so the provider can recognise duplicates.
    pub message_id: Option<String>,
}

pub struct CallSuccess {
    pub status: u16,
    pub body: Bytes,
    pub content_type: String,
    pub message_id: String,
    pub proof: Proof,
}

#[derive(Debug)]
pub enum CallError {
    /// The request itself is wrong.
    Invalid(String),
    /// No active member owns this service.
    UnknownProvider(String),
    /// The provider could not be reached or did not answer. Retry later.
    Unreachable(String),
    /// The provider answered with an error (access denied, rate limited, ...).
    Remote {
        status: u16,
        code: String,
        message: String,
    },
    /// The answer failed verification.
    BadResponse(String),
    Internal(String),
}

impl CallError {
    pub fn retryable(&self) -> bool {
        match self {
            CallError::Unreachable(_) => true,
            CallError::Remote { status, code, .. } => {
                matches!(*status, 429 | 502 | 503 | 504) || code == "in_flight"
            }
            _ => false,
        }
    }

    pub fn code(&self) -> &str {
        match self {
            CallError::Invalid(_) => "invalid_request",
            CallError::UnknownProvider(_) => "unknown_provider",
            CallError::Unreachable(_) => "provider_unreachable",
            CallError::Remote { code, .. } => code,
            CallError::BadResponse(_) => "bad_response",
            CallError::Internal(_) => "internal",
        }
    }

    pub fn message(&self) -> String {
        match self {
            CallError::Invalid(m)
            | CallError::UnknownProvider(m)
            | CallError::Unreachable(m)
            | CallError::BadResponse(m)
            | CallError::Internal(m) => m.clone(),
            CallError::Remote { message, .. } => message.clone(),
        }
    }
}

pub async fn call(st: &AppState, p: &CallParams) -> Result<CallSuccess, CallError> {
    if p.client.member != st.cfg.member_id {
        return Err(CallError::Invalid(format!(
            "client {} does not belong to this member ({})",
            p.client, st.cfg.member_id
        )));
    }
    let message_id = p.message_id.clone().unwrap_or_else(random_id);
    let envelope = RequestEnvelope {
        version: PROTOCOL_VERSION,
        message_id: message_id.clone(),
        client: p.client.clone(),
        service: p.service.clone(),
        issued_at_ms: now_ms(),
        body_sha256: sha256_hex(&p.body),
        content_type: p.content_type.clone(),
        subject: p.subject.clone(),
    };
    let signed = SignedMessage::sign(REQUEST_DOMAIN, &envelope, st.signer.as_ref())
        .map_err(|e| CallError::Internal(e.to_string()))?;
    let request_sha = signed
        .payload_sha256()
        .map_err(|e| CallError::Internal(e.to_string()))?;

    let result = exchange(st, p, &signed, &message_id, &request_sha).await;

    let (response_sha, status, outcome) = match &result {
        Ok(ok) => (
            Some(sha256_hex(&ok.body)),
            Some(ok.status),
            "ok".to_string(),
        ),
        Err(e) => (None, None, format!("error:{}", e.code())),
    };
    let logged = st.audit.append(AuditEvent::Exchange {
        role: "consumer".into(),
        message_id: message_id.clone(),
        peer: p.service.member.to_string(),
        client: p.client.to_string(),
        service: p.service.to_string(),
        request_sha256: request_sha,
        response_sha256: response_sha,
        status,
        outcome,
        subject_ref: None,
    });
    if let Err(e) = logged {
        tracing::error!("cannot write audit log: {e}");
        return Err(CallError::Internal("audit log unavailable".into()));
    }
    if let Ok(ok) = &result {
        if let Ok(bytes) = serde_json::to_vec(&ok.proof) {
            let _ = std::fs::write(st.proofs_dir.join(format!("{message_id}.json")), bytes);
        }
    }
    result
}

async fn exchange(
    st: &AppState,
    p: &CallParams,
    signed: &SignedMessage,
    message_id: &str,
    request_sha: &str,
) -> Result<CallSuccess, CallError> {
    let mut dir = st.dir.snapshot();
    if dir.get_active(&p.service.member).is_none() {
        st.dir
            .refresh_throttled(std::time::Duration::from_secs(2))
            .await;
        dir = st.dir.snapshot();
    }
    let provider = dir.get_active(&p.service.member).ok_or_else(|| {
        CallError::UnknownProvider(format!("{} is not an active member", p.service.member))
    })?;
    let provider_info = pki::inspect_cert_pem(provider.cert_pem.as_deref().unwrap_or_default())
        .map_err(|e| CallError::Internal(format!("bad provider certificate in directory: {e}")))?;

    let wire = ExchangeRequest {
        request: signed.clone(),
        body_b64: b64_encode(&p.body),
    };
    let body = serde_json::to_vec(&wire).map_err(|e| CallError::Internal(e.to_string()))?;
    let url = format!(
        "{}/zroad/v1/exchange",
        provider.endpoint.trim_end_matches('/')
    );
    let resp = request(
        "POST",
        &url,
        &[("content-type", "application/json")],
        Bytes::from(body),
        Some(&st.tls_client),
        std::time::Duration::from_secs(st.cfg.upstream_timeout_secs + 5),
    )
    .await
    .map_err(|e: NetError| CallError::Unreachable(e.to_string()))?;

    if resp.status != 200 {
        let (code, message) = serde_json::from_slice::<ErrorBody>(&resp.body)
            .map(|e| (e.error, e.message))
            .unwrap_or_else(|_| {
                (
                    "remote_error".into(),
                    String::from_utf8_lossy(&resp.body)
                        .chars()
                        .take(200)
                        .collect(),
                )
            });
        return Err(CallError::Remote {
            status: resp.status,
            code,
            message,
        });
    }
    let wire: ExchangeResponse = serde_json::from_slice(&resp.body)
        .map_err(|e| CallError::BadResponse(format!("unreadable response: {e}")))?;
    let envelope: ResponseEnvelope = wire
        .response
        .open(RESPONSE_DOMAIN, &provider_info.public_key)
        .map_err(|e| CallError::BadResponse(e.to_string()))?;
    let body = b64_decode(&wire.body_b64).map_err(|e| CallError::BadResponse(e.to_string()))?;
    if envelope.request_id != message_id
        || envelope.request_sha256 != request_sha
        || envelope.provider != p.service.member
        || envelope.body_sha256 != sha256_hex(&body)
    {
        return Err(CallError::BadResponse(
            "response is not bound to our request".into(),
        ));
    }
    Ok(CallSuccess {
        status: envelope.status,
        content_type: envelope.content_type,
        message_id: envelope.request_id,
        proof: Proof {
            request: signed.clone(),
            request_body_b64: b64_encode(&p.body),
            response: wire.response,
            response_body_b64: wire.body_b64,
        },
        body: Bytes::from(body),
    })
}
