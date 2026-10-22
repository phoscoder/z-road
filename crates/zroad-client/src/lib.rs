//! A small client for the internal API of a Z-Road security server.
//!
//! ```no_run
//! # async fn demo() -> Result<(), zroad_client::ClientError> {
//! use zroad_client::{CallOptions, Client};
//!
//! let zroad = Client::new("http://127.0.0.1:7001", "ZW/COM/12345678/accounts-payable".parse().unwrap());
//! let reply = zroad
//!     .call_json(
//!         &"ZW/GOV/ZIMRA/tax-clearance/verify/v1".parse().unwrap(),
//!         &serde_json::json!({ "tin": "2000123456" }),
//!         &CallOptions::default().subject("2000123456"),
//!     )
//!     .await?;
//! println!("{}", reply.status);
//! # Ok(()) }
//! ```
//!
//! Answers from the provider's own system (including its 404s) come back as a
//! [`Reply`]. Problems raised by Z-Road itself, such as access denied, an
//! unknown provider or an unreachable provider, come back as
//! [`ClientError::ZRoad`] with a stable `code`.

use std::time::Duration;

use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zroad_core::directory::Directory;
use zroad_core::id::{ClientId, MemberId, ServiceId};
use zroad_core::msg::{b64_decode, Proof, RequestEnvelope, ResponseEnvelope};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Your own security server could not be reached.
    #[error("cannot reach the security server: {0}")]
    Unreachable(String),
    /// Z-Road refused or could not complete the exchange.
    #[error("z-road error {code} (HTTP {status}): {message}")]
    ZRoad {
        status: u16,
        code: String,
        message: String,
        /// Worth retrying later (provider unreachable, rate limited, ...).
        retryable: bool,
    },
    /// The security server's answer was not understood.
    #[error("unexpected response from the security server: {0}")]
    Protocol(String),
    #[error("timed out waiting for the queued request")]
    Timeout,
    #[error("the queued request failed: {0}")]
    Failed(String),
}

impl ClientError {
    /// The Z-Road error code, if this is a [`ClientError::ZRoad`].
    pub fn code(&self) -> Option<&str> {
        match self {
            ClientError::ZRoad { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::Unreachable(_) | ClientError::Timeout => true,
            ClientError::ZRoad { retryable, .. } => *retryable,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CallOptions {
    subject: Option<String>,
    content_type: Option<String>,
}

impl CallOptions {
    /// The data subject the query is about (for example a TIN). The provider
    /// keeps only a keyed hash of it, so the person can later see who looked.
    pub fn subject(mut self, s: impl Into<String>) -> Self {
        self.subject = Some(s.into());
        self
    }

    pub fn content_type(mut self, c: impl Into<String>) -> Self {
        self.content_type = Some(c.into());
        self
    }
}

/// The provider's answer.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The status returned by the provider's own system.
    pub status: u16,
    pub body: Bytes,
    pub content_type: String,
    pub message_id: String,
    /// Signed evidence of the exchange (present unless it was too large to
    /// attach; a copy is always stored by the security server).
    pub proof: Option<Proof>,
}

impl Reply {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, ClientError> {
        serde_json::from_slice(&self.body)
            .map_err(|e| ClientError::Protocol(format!("body is not the expected JSON: {e}")))
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check the signed proof offline against a member directory and return the
    /// verified request and response envelopes.
    pub fn verify(
        &self,
        directory: &Directory,
    ) -> Result<(RequestEnvelope, ResponseEnvelope), ClientError> {
        let proof = self
            .proof
            .as_ref()
            .ok_or_else(|| ClientError::Protocol("no proof attached to this reply".into()))?;
        directory
            .verify_proof(proof)
            .map_err(|e| ClientError::Protocol(format!("proof does not verify: {e}")))
    }
}

/// State of a request submitted with [`Client::submit`].
#[derive(Debug, Clone)]
pub enum Queued {
    Pending {
        attempts: u32,
        last_error: Option<String>,
    },
    Delivered(Box<Reply>),
    Failed(String),
}

#[derive(Clone)]
pub struct Client {
    base: String,
    client: ClientId,
    token: Option<String>,
    /// Set when the security server is a shared node hosting several members.
    prefix: String,
    timeout: Duration,
}

impl Client {
    /// `security_server` is the internal URL of your organisation's security
    /// server. `client` is the subsystem making the calls; its member decides
    /// which identity the exchange is made under.
    pub fn new(security_server: &str, client: ClientId) -> Self {
        Self {
            base: security_server.trim_end_matches('/').to_string(),
            client,
            token: None,
            prefix: String::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// The `internal_token` of your member, if the security server requires one.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Use the member-prefixed paths of a shared node (`/m/<member id>/...`).
    pub fn on_shared_node(mut self) -> Self {
        let m: &MemberId = &self.client.member;
        self.prefix = format!("/m/{m}");
        self
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    fn headers(
        &self,
        opts: &CallOptions,
        extra: &[(&'static str, String)],
    ) -> Vec<(String, String)> {
        let mut h = vec![
            ("z-road-client".to_string(), self.client.to_string()),
            (
                "content-type".to_string(),
                opts.content_type
                    .clone()
                    .unwrap_or_else(|| "application/json".into()),
            ),
        ];
        if let Some(s) = &opts.subject {
            h.push(("z-road-subject".into(), s.clone()));
        }
        if let Some(t) = &self.token {
            h.push(("authorization".into(), format!("Bearer {t}")));
        }
        h.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        h
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Bytes,
    ) -> Result<zroad_net::Response, ClientError> {
        let h: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        zroad_net::request(
            method,
            &format!("{}{path}", self.base),
            &h,
            body,
            None,
            self.timeout,
        )
        .await
        .map_err(|e| ClientError::Unreachable(e.to_string()))
    }

    /// Call a service and wait for the answer.
    pub async fn call(
        &self,
        service: &ServiceId,
        body: impl Into<Bytes>,
        opts: &CallOptions,
    ) -> Result<Reply, ClientError> {
        let path = format!("{}/r1/{service}", self.prefix);
        let resp = self
            .send("POST", &path, self.headers(opts, &[]), body.into())
            .await?;
        reply_from(resp)
    }

    /// Like [`call`](Self::call) with a JSON request body.
    pub async fn call_json<T: Serialize>(
        &self,
        service: &ServiceId,
        body: &T,
        opts: &CallOptions,
    ) -> Result<Reply, ClientError> {
        let bytes = serde_json::to_vec(body).map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.call(service, bytes, opts).await
    }

    /// Queue a request on the security server's durable outbox and return its
    /// message id straight away. Use this when the provider may be unreachable:
    /// the security server retries with backoff. Collect the result with
    /// [`poll`](Self::poll) or [`wait`](Self::wait).
    pub async fn submit(
        &self,
        service: &ServiceId,
        body: impl Into<Bytes>,
        opts: &CallOptions,
    ) -> Result<String, ClientError> {
        let path = format!("{}/r1/{service}", self.prefix);
        let resp = self
            .send(
                "POST",
                &path,
                self.headers(opts, &[("z-road-mode", "async".into())]),
                body.into(),
            )
            .await?;
        if resp.status != 202 {
            return Err(error_from(&resp).unwrap_or_else(|| {
                ClientError::Protocol(format!("expected 202, got {}", resp.status))
            }));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&resp.body).map_err(|e| ClientError::Protocol(e.to_string()))?;
        v["message_id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ClientError::Protocol("no message_id in the response".into()))
    }

    pub async fn poll(&self, message_id: &str) -> Result<Queued, ClientError> {
        let path = format!("{}/internal/v1/outbox/{message_id}", self.prefix);
        let h = self.headers(&CallOptions::default(), &[]);
        let resp = self.send("GET", &path, h, Bytes::new()).await?;
        if resp.status != 200 {
            return Err(error_from(&resp)
                .unwrap_or_else(|| ClientError::Protocol(format!("HTTP {}", resp.status))));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&resp.body).map_err(|e| ClientError::Protocol(e.to_string()))?;
        match v["state"].as_str() {
            Some("pending") => Ok(Queued::Pending {
                attempts: v["item"]["attempts"].as_u64().unwrap_or(0) as u32,
                last_error: v["item"]["last_error"].as_str().map(str::to_string),
            }),
            Some("finished") => {
                let r = &v["result"];
                if r["state"] == "delivered" {
                    let body = b64_decode(r["body_b64"].as_str().unwrap_or(""))
                        .map_err(|e| ClientError::Protocol(e.to_string()))?;
                    // The stored proof (if wanted) is fetched with the admin API; queued
                    // replies carry the provider's status and body.
                    Ok(Queued::Delivered(Box::new(Reply {
                        status: r["status"].as_u64().unwrap_or(0) as u16,
                        body: Bytes::from(body),
                        content_type: r["content_type"]
                            .as_str()
                            .unwrap_or("application/json")
                            .to_string(),
                        message_id: message_id.to_string(),
                        proof: None,
                    })))
                } else {
                    Ok(Queued::Failed(
                        r["error"].as_str().unwrap_or("failed").to_string(),
                    ))
                }
            }
            _ => Err(ClientError::Protocol("unrecognised outbox status".into())),
        }
    }

    /// Poll until the queued request is delivered or fails, up to `max_wait`.
    pub async fn wait(&self, message_id: &str, max_wait: Duration) -> Result<Reply, ClientError> {
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            match self.poll(message_id).await? {
                Queued::Delivered(r) => return Ok(*r),
                Queued::Failed(e) => return Err(ClientError::Failed(e)),
                Queued::Pending { .. } => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ClientError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    message: String,
}

/// Errors raised by Z-Road carry the `z-road-error` header, which is how they
/// are told apart from an error status returned by the provider's own system.
fn error_from(resp: &zroad_net::Response) -> Option<ClientError> {
    resp.headers.get("z-road-error")?;
    let body: ErrorBody = serde_json::from_slice(&resp.body).unwrap_or(ErrorBody {
        error: "unknown".into(),
        message: String::from_utf8_lossy(&resp.body)
            .chars()
            .take(200)
            .collect(),
    });
    let retryable = resp.headers.contains_key("retry-after");
    Some(ClientError::ZRoad {
        status: resp.status,
        code: body.error,
        message: body.message,
        retryable,
    })
}

fn reply_from(resp: zroad_net::Response) -> Result<Reply, ClientError> {
    if let Some(e) = error_from(&resp) {
        return Err(e);
    }
    let header = |n: &str| {
        resp.headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let proof = header("z-road-proof")
        .and_then(|p| b64_decode(&p).ok())
        .and_then(|b| serde_json::from_slice::<Proof>(&b).ok());
    Ok(Reply {
        status: resp.status,
        content_type: header("content-type").unwrap_or_else(|| "application/json".into()),
        message_id: header("z-road-message-id").unwrap_or_default(),
        proof,
        body: resp.body,
    })
}
