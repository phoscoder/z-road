//! A signer that lives on another machine, run by the member itself.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use rustls::ClientConfig;
use zroad_core::crypto::{self, AsyncSigner};
use zroad_core::msg::{b64_decode, b64_encode};
use zroad_core::{Error, Result};

use crate::api::{SignRequest, SignResponse};
use crate::http_client::request;

/// Asks a member's signer service to sign messages. The signature is checked
/// against the member's registered public key before it is used, so a broken or
/// malicious signer cannot make the node emit a message with a bad signature.
pub struct RemoteSigner {
    url: String,
    tls: RwLock<Arc<ClientConfig>>,
    public_keys: RwLock<Vec<Vec<u8>>>,
    timeout: Duration,
}

impl RemoteSigner {
    /// `tls` must trust the signer's own CA and present the node's certificate.
    pub fn new(base_url: &str, tls: Arc<ClientConfig>, public_key: Vec<u8>) -> Self {
        Self {
            url: format!("{}/v1/sign", base_url.trim_end_matches('/')),
            tls: RwLock::new(tls),
            public_keys: RwLock::new(vec![public_key]),
            timeout: Duration::from_secs(5),
        }
    }

    /// Switch to a new TLS configuration (the node renewed its certificate).
    pub fn set_tls(&self, tls: Arc<ClientConfig>) {
        *self.tls.write().unwrap_or_else(|p| p.into_inner()) = tls;
    }

    pub fn public_keys(&self) -> Vec<Vec<u8>> {
        self.public_keys
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The keys a signature may legitimately come from, current first: during a
    /// rotation the signer may still be signing with the key being replaced.
    pub fn set_public_keys(&self, keys: Vec<Vec<u8>>) {
        if !keys.is_empty() {
            *self.public_keys.write().unwrap_or_else(|p| p.into_inner()) = keys;
        }
    }
}

#[async_trait]
impl AsyncSigner for RemoteSigner {
    async fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(&SignRequest {
            message_b64: b64_encode(msg),
        })?;
        // copy the current config out first: no lock is held across the await
        let tls = self.tls.read().unwrap_or_else(|p| p.into_inner()).clone();
        let resp = request(
            "POST",
            &self.url,
            &[("content-type", "application/json")],
            Bytes::from(body),
            Some(&tls),
            self.timeout,
        )
        .await
        .map_err(|e| Error::Crypto(format!("signer unavailable: {e}")))?;
        if resp.status != 200 {
            return Err(Error::Crypto(format!(
                "signer refused (HTTP {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )));
        }
        let parsed: SignResponse = serde_json::from_slice(&resp.body)?;
        let sig = b64_decode(&parsed.signature_b64)?;
        let keys = self
            .public_keys
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if !keys.iter().any(|k| crypto::verify(k, msg, &sig).is_ok()) {
            return Err(Error::Crypto(
                "signer returned a signature that does not verify".into(),
            ));
        }
        Ok(sig)
    }

    fn verifying_key(&self) -> Vec<u8> {
        self.public_keys.read().unwrap_or_else(|p| p.into_inner())[0].clone()
    }
}
