//! A signer that lives on another machine, run by the member itself.

use std::sync::Arc;
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
    tls: Arc<ClientConfig>,
    public_key: Vec<u8>,
    timeout: Duration,
}

impl RemoteSigner {
    /// `tls` must trust the signer's own CA and present the node's certificate.
    pub fn new(base_url: &str, tls: Arc<ClientConfig>, public_key: Vec<u8>) -> Self {
        Self {
            url: format!("{}/v1/sign", base_url.trim_end_matches('/')),
            tls,
            public_key,
            timeout: Duration::from_secs(5),
        }
    }
}

#[async_trait]
impl AsyncSigner for RemoteSigner {
    async fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(&SignRequest {
            message_b64: b64_encode(msg),
        })?;
        let resp = request(
            "POST",
            &self.url,
            &[("content-type", "application/json")],
            Bytes::from(body),
            Some(&self.tls),
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
        crypto::verify(&self.public_key, msg, &sig).map_err(|_| {
            Error::Crypto("signer returned a signature that does not verify".into())
        })?;
        Ok(sig)
    }

    fn verifying_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}
