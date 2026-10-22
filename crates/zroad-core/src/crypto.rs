//! Signing, hashing and constant-time comparison.

use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// Anything that can produce Ed25519 signatures. Software keys implement this
/// today; an HSM-backed implementation can be plugged in without touching the
/// protocol code.
pub trait Signer: Send + Sync {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn public_key(&self) -> Vec<u8>;
}

/// A signer that may be remote (a separate machine, an HSM): signing is async and
/// can fail. Every [`Signer`] is also an `AsyncSigner`.
#[async_trait::async_trait]
pub trait AsyncSigner: Send + Sync {
    async fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>>;
    fn verifying_key(&self) -> Vec<u8>;
}

#[async_trait::async_trait]
impl<T: Signer + ?Sized> AsyncSigner for T {
    async fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(Signer::sign(self, msg))
    }
    fn verifying_key(&self) -> Vec<u8> {
        Signer::public_key(self)
    }
}

pub struct SoftwareSigner(SigningKey);

impl SoftwareSigner {
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        SigningKey::from_pkcs8_pem(pem)
            .map(Self)
            .map_err(|e| Error::Crypto(format!("cannot load signing key: {e}")))
    }
}

impl Signer for SoftwareSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.sign(msg).to_bytes().to_vec()
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
}

pub fn verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<()> {
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::Verify("public key is not 32 bytes".into()))?;
    let pk = VerifyingKey::from_bytes(&pk).map_err(|e| Error::Verify(e.to_string()))?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| Error::Verify(format!("bad signature encoding: {e}")))?;
    pk.verify(msg, &sig)
        .map_err(|_| Error::Verify("signature does not match".into()))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let s = SoftwareSigner::from_pkcs8_pem(&kp.serialize_pem()).unwrap();
        let sig = s.sign(b"hello");
        verify(&s.public_key(), b"hello", &sig).unwrap();
        assert!(verify(&s.public_key(), b"hellp", &sig).is_err());
    }
}
