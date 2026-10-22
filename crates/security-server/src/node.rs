//! The node's own member identity (for shared nodes whose hosted members keep
//! their keys elsewhere) and its automatic renewal.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use zroad_core::{now_ms, pki};
use zroad_net::api::RenewRequest;
use zroad_net::central_client::{write_private, CentralClient};
use zroad_net::remote_signer::RemoteSigner;
use zroad_net::tls;

use crate::config::NodeIdentityConfig;
use crate::state::{AppState, Identity};

#[derive(Clone)]
pub struct Creds {
    pub cert_pem: String,
    pub key_pem: String,
    pub tls_client: Arc<rustls::ClientConfig>,
}

/// The node's own member identity, used for TLS by remote-signed members.
pub struct NodeIdentity {
    cfg: NodeIdentityConfig,
    ca_pem: String,
    creds: RwLock<Creds>,
    pub server_cert: Arc<tls::ReloadableCert>,
    /// Every remote signer on this node, with the signer CA it pins, so a renewed
    /// node certificate can be handed to each of them.
    signers: Mutex<Vec<(Arc<RemoteSigner>, String)>>,
}

impl NodeIdentity {
    pub fn load(cfg: &NodeIdentityConfig) -> Result<Self> {
        let read = |f: &str| {
            std::fs::read_to_string(cfg.dir.join(f)).with_context(|| {
                format!(
                    "reading {} (enrol the node with `zroad-cli enroll`)",
                    cfg.dir.join(f).display()
                )
            })
        };
        let (key_pem, cert_pem, ca_pem) = (read("key.pem")?, read("cert.pem")?, read("ca.pem")?);
        let info = pki::inspect_cert_pem(&cert_pem).map_err(|e| anyhow!("{e}"))?;
        if info.member != cfg.member {
            bail!(
                "the node certificate is for {}, but node_member is {}",
                info.member,
                cfg.member
            );
        }
        Ok(Self {
            server_cert: tls::ReloadableCert::new(&cert_pem, &key_pem)?,
            creds: RwLock::new(Creds {
                tls_client: tls::client_config(&ca_pem, Some((&cert_pem, &key_pem)))?,
                cert_pem,
                key_pem,
            }),
            ca_pem,
            cfg: cfg.clone(),
            signers: Mutex::new(Vec::new()),
        })
    }

    pub fn creds(&self) -> Creds {
        self.creds.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn register_signer(&self, signer: Arc<RemoteSigner>, signer_ca_pem: String) {
        self.signers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((signer, signer_ca_pem));
    }

    /// Replace the node certificate (using the current one to authenticate), and
    /// switch every user of it over without a restart: the TLS server, the
    /// outbound TLS of each hosted member, and each remote signer connection.
    pub async fn renew(
        &self,
        central_url: &str,
        members: &[Arc<AppState>],
        activation_delay: Duration,
    ) -> Result<()> {
        let current = self.creds();
        let sans = pki::cert_sans(&current.cert_pem).map_err(|e| anyhow!("{e}"))?;
        let ident = pki::generate_identity(&self.cfg.member, &sans).map_err(|e| anyhow!("{e}"))?;
        let resp = CentralClient::from_tls(central_url, current.tls_client.clone())
            .renew(&RenewRequest {
                csr_pem: ident.csr_pem,
            })
            .await
            .context("central server refused the node's renewal")?;
        let info = pki::inspect_cert_pem(&resp.cert_pem).map_err(|e| anyhow!("{e}"))?;
        if info.member != self.cfg.member {
            bail!("central server returned a certificate for {}", info.member);
        }

        // build everything first, so a bad certificate cannot leave us half-switched
        let tls_client = tls::client_config(&self.ca_pem, Some((&resp.cert_pem, &ident.key_pem)))?;
        let mut new_signer_tls = Vec::new();
        for (signer, signer_ca) in self
            .signers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            new_signer_tls.push((
                signer.clone(),
                tls::client_config(signer_ca, Some((&resp.cert_pem, &ident.key_pem)))?,
            ));
        }
        // Persist now, switch later: the directory already lists the new certificate,
        // and peers accept the old one meanwhile, but some have not refreshed yet.
        // Presenting the new certificate only after they have avoids rejected calls.
        for f in ["key.pem", "cert.pem"] {
            let _ = std::fs::rename(self.cfg.dir.join(f), self.cfg.dir.join(format!("{f}.prev")));
        }
        write_private(&self.cfg.dir.join("key.pem"), &ident.key_pem)?;
        std::fs::write(self.cfg.dir.join("cert.pem"), &resp.cert_pem)?;
        tokio::time::sleep(activation_delay).await;
        self.server_cert.set(&resp.cert_pem, &ident.key_pem)?;

        *self.creds.write().unwrap_or_else(|p| p.into_inner()) = Creds {
            cert_pem: resp.cert_pem.clone(),
            key_pem: ident.key_pem.clone(),
            tls_client: tls_client.clone(),
        };
        for (signer, tls) in new_signer_tls {
            signer.set_tls(tls);
        }
        for st in members.iter().filter(|m| m.cfg.remote_signer.is_some()) {
            let id = st.identity();
            st.set_identity(Identity {
                signer: id.signer.clone(),
                cert_pem: id.cert_pem.clone(),
                tls_client: tls_client.clone(),
            });
        }
        if let Some(first) = members.first() {
            let _ = first.dir.refresh().await;
        }
        tracing::info!("node certificate renewed ({})", info.fingerprint);
        Ok(())
    }
}

/// Renew the node's own certificate when little validity remains.
pub async fn node_renew_loop(
    node: Arc<NodeIdentity>,
    members: Vec<Arc<AppState>>,
    central_url: String,
    renew_before_days: i64,
    initial_delay: Duration,
    activation_delay: Duration,
) {
    tokio::time::sleep(initial_delay).await;
    loop {
        let cert = node.creds().cert_pem;
        if let Ok(info) = pki::inspect_cert_pem(&cert) {
            let days = (info.not_after - (now_ms() / 1000) as i64) / 86_400;
            if renew_before_days > 0 && days < renew_before_days {
                if let Err(e) = node.renew(&central_url, &members, activation_delay).await {
                    tracing::error!("automatic renewal of the node certificate failed ({days} day(s) left): {e:#}");
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

/// A remote-signed member rotates its key on its own machine. Follow it: when the
/// directory shows a different certificate for the member, start verifying the
/// signer's signatures against the new key.
pub async fn key_sync_loop(st: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        sync_remote_key(&st);
    }
}

pub fn sync_remote_key(st: &AppState) {
    let Some(remote) = &st.remote_signer else {
        return;
    };
    let dir = st.dir.snapshot();
    let keys = dir.recent_keys(
        &st.cfg.member_id,
        now_ms(),
        st.cfg.rotation_grace_secs * 1000,
    );
    if keys.is_empty() || keys == remote.public_keys() {
        return;
    }
    remote.set_public_keys(keys);
    if let Some(pem) = dir.get(&st.cfg.member_id).and_then(|r| r.cert_pem.clone()) {
        let id = st.identity();
        st.set_identity(Identity {
            signer: id.signer.clone(),
            cert_pem: pem,
            tls_client: id.tls_client.clone(),
        });
    }
    tracing::info!("{} rotated its signing key; following it", st.cfg.member_id);
}
