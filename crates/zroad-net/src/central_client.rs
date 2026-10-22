//! Client for the central server: directory, administration and enrolment.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use rustls::ClientConfig;
use serde::de::DeserializeOwned;
use serde::Serialize;
use zroad_core::directory::Directory;
use zroad_core::id::MemberId;
use zroad_core::pki;

use crate::api::*;
use crate::http_client::{request, DEFAULT_TIMEOUT};
use crate::tls;

pub struct CentralClient {
    base: String,
    tls: Arc<ClientConfig>,
}

impl CentralClient {
    /// `ca_pem` is the root certificate obtained out of band; it authenticates
    /// the central server.
    pub fn new(base_url: &str, ca_pem: &str) -> Result<Self> {
        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            tls: tls::client_config(ca_pem, None)?,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<T> {
        let auth = bearer.map(|t| format!("Bearer {t}"));
        let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        if let Some(a) = &auth {
            headers.push(("authorization", a));
        }
        let resp = request(
            method,
            &format!("{}{path}", self.base),
            &headers,
            Bytes::from(body.unwrap_or_default()),
            Some(&self.tls),
            DEFAULT_TIMEOUT,
        )
        .await
        .with_context(|| format!("{method} {path}"))?;
        if resp.status / 100 != 2 {
            let msg = serde_json::from_slice::<ErrorBody>(&resp.body)
                .map(|e| format!("{}: {}", e.error, e.message))
                .unwrap_or_else(|_| String::from_utf8_lossy(&resp.body).into_owned());
            bail!("central server returned {}: {msg}", resp.status);
        }
        Ok(serde_json::from_slice(&resp.body)?)
    }

    fn json<T: Serialize>(v: &T) -> Option<Vec<u8>> {
        serde_json::to_vec(v).ok()
    }

    pub async fn directory(&self) -> Result<Directory> {
        self.call("GET", "/v1/directory", None, None).await
    }

    pub async fn add_member(
        &self,
        admin_token: &str,
        id: &MemberId,
        name: &str,
        endpoint: &str,
    ) -> Result<AddMemberResponse> {
        let body = AddMemberRequest {
            id: id.clone(),
            name: name.into(),
            endpoint: endpoint.into(),
        };
        self.call(
            "POST",
            "/v1/admin/members",
            Some(admin_token),
            Self::json(&body),
        )
        .await
    }

    pub async fn revoke(&self, admin_token: &str, id: &MemberId) -> Result<()> {
        let body = RevokeRequest {
            member_id: id.clone(),
        };
        let _: serde_json::Value = self
            .call(
                "POST",
                "/v1/admin/revoke",
                Some(admin_token),
                Self::json(&body),
            )
            .await?;
        Ok(())
    }

    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse> {
        self.call("POST", "/v1/enroll", None, Self::json(req)).await
    }
}

/// Generate a key and CSR, enrol with the central server and write
/// `key.pem`, `cert.pem` and `ca.pem` into `out_dir`.
pub async fn enroll_to_dir(
    central_url: &str,
    ca_pem: &str,
    member: &MemberId,
    token: &str,
    sans: &[String],
    out_dir: &Path,
) -> Result<()> {
    let ident = pki::generate_identity(member, sans).map_err(|e| anyhow!("{e}"))?;
    let client = CentralClient::new(central_url, ca_pem)?;
    let resp = client
        .enroll(&EnrollRequest {
            member_id: member.clone(),
            enrollment_token: token.into(),
            csr_pem: ident.csr_pem,
        })
        .await?;
    std::fs::create_dir_all(out_dir)?;
    write_private(&out_dir.join("key.pem"), &ident.key_pem)?;
    std::fs::write(out_dir.join("cert.pem"), resp.cert_pem)?;
    std::fs::write(out_dir.join("ca.pem"), ca_pem)?;
    Ok(())
}

/// Write a file readable only by the current user.
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}
