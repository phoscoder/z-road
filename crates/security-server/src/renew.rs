//! Certificate renewal without a restart.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use zroad_core::crypto::SoftwareSigner;
use zroad_core::{now_ms, pki};
use zroad_net::api::RenewRequest;
use zroad_net::central_client::{write_private, CentralClient};
use zroad_net::tls;

use crate::state::{AppState, Identity};

/// Get a new certificate from the central server (authenticating with the
/// current one), write it to disk and start using it. The previous key and
/// certificate are kept as `*.prev`. Returns the new certificate's fingerprint.
pub async fn renew(st: &AppState) -> Result<String> {
    let _guard = st.renewing.lock().await;
    let current = st.identity();
    let host = {
        let dir = st.dir.snapshot();
        let rec = dir
            .get(&st.cfg.member_id)
            .ok_or_else(|| anyhow!("own member record not found in the directory"))?;
        rec.endpoint
            .parse::<http::Uri>()
            .ok()
            .and_then(|u| u.host().map(str::to_string))
            .ok_or_else(|| anyhow!("own endpoint in the directory has no host"))?
    };
    let ident = pki::generate_identity(&st.cfg.member_id, &[host]).map_err(|e| anyhow!("{e}"))?;
    let central = CentralClient::from_tls(&st.cfg.central_url, current.tls_client.clone());
    let resp = central
        .renew(&RenewRequest {
            csr_pem: ident.csr_pem,
        })
        .await
        .context("central server refused the renewal")?;

    // Build everything first, so a bad certificate cannot leave us half-switched.
    let info = pki::inspect_cert_pem(&resp.cert_pem).map_err(|e| anyhow!("{e}"))?;
    if info.member != st.cfg.member_id {
        return Err(anyhow!(
            "central server returned a certificate for {}",
            info.member
        ));
    }
    let signer =
        Arc::new(SoftwareSigner::from_pkcs8_pem(&ident.key_pem).map_err(|e| anyhow!("{e}"))?);
    let tls_client = tls::client_config(&st.ca_pem, Some((&resp.cert_pem, &ident.key_pem)))?;
    st.server_cert.set(&resp.cert_pem, &ident.key_pem)?;

    let dir = &st.cfg.data_dir;
    std::fs::rename(dir.join("key.pem"), dir.join("key.pem.prev"))?;
    std::fs::rename(dir.join("cert.pem"), dir.join("cert.pem.prev"))?;
    write_private(&dir.join("key.pem"), &ident.key_pem)?;
    std::fs::write(dir.join("cert.pem"), &resp.cert_pem)?;

    st.set_identity(Identity {
        signer,
        cert_pem: resp.cert_pem,
        tls_client,
    });
    // Pick up our own new certificate in the directory straight away.
    let _ = st.dir.refresh().await;
    tracing::info!("certificate renewed ({})", info.fingerprint);
    Ok(info.fingerprint)
}

/// Check hourly; renew when little validity remains.
pub async fn renew_loop(st: Arc<AppState>) {
    loop {
        if let Ok(info) = st.own_info() {
            let days = (info.not_after - (now_ms() / 1000) as i64) / 86_400;
            if days < st.cfg.renew_before_days {
                match renew(&st).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("automatic renewal failed ({days} day(s) left): {e:#}")
                    }
                }
            } else if days < 30 {
                tracing::warn!(
                    "this member's certificate expires in {days} day(s) and automatic renewal is off"
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
