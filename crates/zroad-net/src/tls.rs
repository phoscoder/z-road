use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::crypto::ring as provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
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
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid certificate PEM")
}

fn key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).context("invalid private key PEM")
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

/// How a TLS server treats client certificates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientAuth {
    /// Never ask for one.
    None,
    /// Accept clients with a certificate from the CA and clients without one;
    /// handlers decide what an anonymous client may do.
    Optional,
    /// Reject clients that do not present a certificate from the CA.
    Required,
}

/// TLS server configuration.
pub fn server_config(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
    client_auth: ClientAuth,
) -> Result<Arc<ServerConfig>> {
    let p = Arc::new(provider::default_provider());
    let builder =
        ServerConfig::builder_with_provider(p.clone()).with_safe_default_protocol_versions()?;
    let builder = match client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Required | ClientAuth::Optional => {
            let mut v = WebPkiClientVerifier::builder_with_provider(Arc::new(roots(ca_pem)?), p);
            if client_auth == ClientAuth::Optional {
                v = v.allow_unauthenticated();
            }
            builder.with_client_cert_verifier(v.build()?)
        }
    };
    Ok(Arc::new(
        builder.with_single_cert(certs(cert_pem)?, key(key_pem)?)?,
    ))
}

/// A server certificate that can be swapped while the server keeps running, so
/// a renewed certificate takes effect for new connections without a restart.
#[derive(Debug)]
pub struct ReloadableCert {
    inner: std::sync::RwLock<Arc<CertifiedKey>>,
}

fn certified(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>> {
    let signing_key = provider::sign::any_supported_type(&key(key_pem)?)
        .map_err(|e| anyhow!("unsupported private key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(certs(cert_pem)?, signing_key)))
}

impl ReloadableCert {
    pub fn new(cert_pem: &str, key_pem: &str) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            inner: std::sync::RwLock::new(certified(cert_pem, key_pem)?),
        }))
    }

    pub fn set(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        let next = certified(cert_pem, key_pem)?;
        *self.inner.write().unwrap_or_else(|p| p.into_inner()) = next;
        Ok(())
    }
}

impl ResolvesServerCert for ReloadableCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.inner.read().unwrap_or_else(|p| p.into_inner()).clone())
    }
}

/// Like [`server_config`], but the certificate comes from `resolver`.
pub fn server_config_reloadable(
    ca_pem: &str,
    resolver: Arc<ReloadableCert>,
    client_auth: ClientAuth,
) -> Result<Arc<ServerConfig>> {
    let p = Arc::new(provider::default_provider());
    let builder =
        ServerConfig::builder_with_provider(p.clone()).with_safe_default_protocol_versions()?;
    let builder = match client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Required | ClientAuth::Optional => {
            let mut v = WebPkiClientVerifier::builder_with_provider(Arc::new(roots(ca_pem)?), p);
            if client_auth == ClientAuth::Optional {
                v = v.allow_unauthenticated();
            }
            builder.with_client_cert_verifier(v.build()?)
        }
    };
    Ok(Arc::new(builder.with_cert_resolver(resolver)))
}
