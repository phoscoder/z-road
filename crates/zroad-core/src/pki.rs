//! A small private CA, certificate requests and certificate inspection.
//!
//! Every member's identity is an Ed25519 key. The same key signs TLS handshakes
//! and Z-Road messages, and the certificate's common name is the member id.

use ::time::{Duration, OffsetDateTime};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ED25519,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::crypto::sha256_hex;
use crate::id::MemberId;
use crate::{Error, Result};

fn pki<E: std::fmt::Display>(e: E) -> Error {
    Error::Pki(e.to_string())
}

pub struct CertAuthority {
    cert: rcgen::Certificate,
    key: KeyPair,
    pub cert_pem: String,
}

pub struct NewCa {
    pub ca: CertAuthority,
    pub key_pem: String,
}

impl CertAuthority {
    pub fn generate(common_name: &str, valid_days: i64) -> Result<NewCa> {
        let key = KeyPair::generate_for(&PKCS_ED25519).map_err(pki)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(pki)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(valid_days);
        let cert = params.self_signed(&key).map_err(pki)?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        Ok(NewCa {
            ca: Self {
                cert,
                key,
                cert_pem,
            },
            key_pem,
        })
    }

    /// Reload a CA from PEM. The in-memory certificate is rebuilt from the
    /// original parameters, so issued certificates chain to the same subject and
    /// key as the published root.
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).map_err(pki)?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem).map_err(pki)?;
        let cert = params.self_signed(&key).map_err(pki)?;
        Ok(Self {
            cert,
            key,
            cert_pem: cert_pem.to_string(),
        })
    }

    /// Issue a member certificate from a CSR. The subject is always set to the
    /// member id, whatever the CSR asked for. Every subject alternative name in
    /// the CSR must be in `allowed_sans` (an address or host name).
    pub fn sign_csr(
        &self,
        csr_pem: &str,
        member: &MemberId,
        allowed_sans: &[String],
        valid_days: i64,
    ) -> Result<String> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).map_err(pki)?;
        if csr.public_key.algorithm() != &PKCS_ED25519 {
            return Err(Error::Pki("members must use Ed25519 keys".into()));
        }
        if csr.params.subject_alt_names.is_empty() {
            return Err(Error::Pki("CSR has no subject alternative names".into()));
        }
        for san in &csr.params.subject_alt_names {
            let text = match san {
                SanType::DnsName(d) => d.as_str().to_string(),
                SanType::IpAddress(ip) => ip.to_string(),
                other => return Err(Error::Pki(format!("unsupported SAN type: {other:?}"))),
            };
            if !allowed_sans.iter().any(|a| a == &text) {
                return Err(Error::Pki(format!(
                    "SAN `{text}` is not allowed for this member"
                )));
            }
        }
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, member.to_string());
        csr.params.distinguished_name = dn;
        csr.params.is_ca = IsCa::NoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        csr.params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        csr.params.not_after = OffsetDateTime::now_utc() + Duration::days(valid_days);
        let cert = csr.signed_by(&self.cert, &self.key).map_err(pki)?;
        Ok(cert.pem())
    }
}

/// A freshly generated member identity: private key plus certificate request.
pub struct NewIdentity {
    pub key_pem: String,
    pub csr_pem: String,
}

pub fn generate_identity(member: &MemberId, sans: &[String]) -> Result<NewIdentity> {
    let key = KeyPair::generate_for(&PKCS_ED25519).map_err(pki)?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(pki)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, member.to_string());
    params.distinguished_name = dn;
    params.subject_alt_names = sans
        .iter()
        .map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => s
                .clone()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|e| Error::Pki(format!("invalid DNS name `{s}`: {e}"))),
        })
        .collect::<Result<Vec<_>>>()?;
    let csr = params.serialize_request(&key).map_err(pki)?;
    Ok(NewIdentity {
        key_pem: key.serialize_pem(),
        csr_pem: csr.pem().map_err(pki)?,
    })
}

/// What Z-Road needs to know about a certificate presented by a peer.
#[derive(Clone, Debug)]
pub struct CertInfo {
    pub member: MemberId,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    /// End of validity, Unix seconds.
    pub not_after: i64,
}

pub fn cert_pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(pki)?;
    Ok(p.contents)
}

pub fn inspect_cert_der(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).map_err(pki)?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .ok_or_else(|| Error::Pki("certificate has no common name".into()))?;
    Ok(CertInfo {
        member: cn.parse()?,
        public_key: cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec(),
        fingerprint: sha256_hex(der),
        not_after: cert.validity().not_after.timestamp(),
    })
}

pub fn inspect_cert_pem(pem: &str) -> Result<CertInfo> {
    inspect_cert_der(&cert_pem_to_der(pem)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_inspect() {
        let new = CertAuthority::generate("Test CA", 30).unwrap();
        let reloaded = CertAuthority::load(&new.ca.cert_pem, &new.key_pem).unwrap();
        let member: MemberId = "ZW/GOV/ZIMRA".parse().unwrap();
        let id = generate_identity(&member, &["127.0.0.1".into(), "zimra.test".into()]).unwrap();
        let allowed = vec!["127.0.0.1".to_string(), "zimra.test".to_string()];
        let pem = reloaded
            .sign_csr(&id.csr_pem, &member, &allowed, 30)
            .unwrap();
        let info = inspect_cert_pem(&pem).unwrap();
        assert_eq!(info.member, member);
        assert_eq!(info.public_key.len(), 32);
        // only Ed25519 keys are accepted
        let ecdsa = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["zimra.test".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&ecdsa).unwrap().pem().unwrap();
        assert!(reloaded
            .sign_csr(&csr, &member, &["zimra.test".to_string()], 30)
            .is_err());
        // a SAN outside the allow-list is refused
        assert!(reloaded
            .sign_csr(&id.csr_pem, &member, &["127.0.0.1".to_string()], 30)
            .is_err());
    }
}
