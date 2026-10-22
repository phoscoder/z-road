use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::crypto::ring as provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

fn roots(ca_pem: &str) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in certs(ca_pem)? {
        store.add(cert).context("invalid CA certificate")?;
    }
    if store.is_empty() {
        return Err(anyhow!("no CA certificate found"));
    }
    Ok(store)
}

fn certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid certificate PEM")
}

fn key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .context("invalid private key PEM")?
        .ok_or_else(|| anyhow!("no private key found"))
}

/// TLS client configuration that trusts only `ca_pem`. With an identity it
/// presents a client certificate (mutual TLS).
pub fn client_config(ca_pem: &str, identity: Option<(&str, &str)>) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(Arc::new(provider::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots(ca_pem)?);
    let cfg = match identity {
        Some((cert_pem, key_pem)) => {
            builder.with_client_auth_cert(certs(cert_pem)?, key(key_pem)?)?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(cfg))
}

/// TLS server configuration. With `require_client_auth` every client must
/// present a certificate issued by `ca_pem`.
pub fn server_config(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
    require_client_auth: bool,
) -> Result<Arc<ServerConfig>> {
    let p = Arc::new(provider::default_provider());
    let builder =
        ServerConfig::builder_with_provider(p.clone()).with_safe_default_protocol_versions()?;
    let builder = if require_client_auth {
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots(ca_pem)?), p).build()?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    Ok(Arc::new(
        builder.with_single_cert(certs(cert_pem)?, key(key_pem)?)?,
    ))
}
