//! Wire messages. Payloads are signed as raw bytes (`payload_b64`) so there is
//! no canonicalisation ambiguity: the verifier checks the exact bytes the
//! sender signed and only then parses them.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, Signer};
use crate::id::{ClientId, MemberId, ServiceId};
use crate::{Error, Result};

pub const PROTOCOL_VERSION: u32 = 1;

pub const REQUEST_DOMAIN: &str = "zroad/v1/request";
pub const RESPONSE_DOMAIN: &str = "zroad/v1/response";
pub const TIMESTAMP_DOMAIN: &str = "zroad/v1/timestamp";

/// Maximum clock skew tolerated between members, in milliseconds.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s)
        .map_err(|e| Error::Encoding(format!("invalid base64: {e}")))
}

fn default_content_type() -> String {
    "application/json".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u32,
    pub message_id: String,
    pub client: ClientId,
    pub service: ServiceId,
    pub issued_at_ms: u64,
    pub body_sha256: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    /// The data subject the query is about (for example a TIN or national ID),
    /// if the consumer chooses to declare one. Providers never log it in clear:
    /// they store a keyed hash so that citizens can later be shown who looked
    /// them up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u32,
    pub request_id: String,
    /// SHA-256 of the exact signed request payload this response answers.
    pub request_sha256: String,
    pub provider: MemberId,
    pub status: u16,
    pub issued_at_ms: u64,
    pub body_sha256: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    pub payload_b64: String,
    pub signature_b64: String,
}

/// The exact bytes that are signed: `domain "\n" payload`.
pub fn signing_input(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + 1 + payload.len());
    v.extend_from_slice(domain.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(payload);
    v
}

impl SignedMessage {
    /// Like [`sign`](Self::sign), for signers that may be remote.
    pub async fn sign_async<T: Serialize>(
        domain: &str,
        value: &T,
        signer: &dyn crypto::AsyncSigner,
    ) -> Result<Self> {
        let payload = serde_json::to_vec(value)?;
        let sig = crypto::AsyncSigner::sign_bytes(signer, &signing_input(domain, &payload)).await?;
        Ok(Self {
            payload_b64: b64_encode(&payload),
            signature_b64: b64_encode(&sig),
        })
    }

    pub fn sign<T: Serialize>(domain: &str, value: &T, signer: &dyn Signer) -> Result<Self> {
        let payload = serde_json::to_vec(value)?;
        let sig = signer.sign(&signing_input(domain, &payload));
        Ok(Self {
            payload_b64: b64_encode(&payload),
            signature_b64: b64_encode(&sig),
        })
    }

    pub fn payload(&self) -> Result<Vec<u8>> {
        b64_decode(&self.payload_b64)
    }

    /// SHA-256 of the signed payload bytes.
    pub fn payload_sha256(&self) -> Result<String> {
        Ok(crypto::sha256_hex(&self.payload()?))
    }

    /// Verify the signature with `public_key`, then parse the payload.
    pub fn open<T: DeserializeOwned>(&self, domain: &str, public_key: &[u8]) -> Result<T> {
        let payload = self.payload()?;
        let sig = b64_decode(&self.signature_b64)?;
        crypto::verify(public_key, &signing_input(domain, &payload), &sig)?;
        Ok(serde_json::from_slice(&payload)?)
    }
}

/// What a consumer sends to a provider's `/zroad/v1/exchange`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExchangeRequest {
    pub request: SignedMessage,
    pub body_b64: String,
}

/// What a provider returns on success.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExchangeResponse {
    pub response: SignedMessage,
    pub body_b64: String,
}

/// Everything needed to prove, later and offline, that an exchange took place.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub request: SignedMessage,
    pub request_body_b64: String,
    pub response: SignedMessage,
    pub response_body_b64: String,
}

/// A trusted timestamp over a digest, issued by the timestamp authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimestampToken {
    pub tsa: MemberId,
    pub digest: String,
    pub time_ms: u64,
    pub serial: u64,
    pub signature_b64: String,
}

impl TimestampToken {
    pub fn signing_bytes(tsa: &MemberId, digest: &str, time_ms: u64, serial: u64) -> Vec<u8> {
        signing_input(
            TIMESTAMP_DOMAIN,
            format!("{tsa}\n{digest}\n{time_ms}\n{serial}").as_bytes(),
        )
    }

    pub fn issue(
        tsa: &MemberId,
        digest: &str,
        time_ms: u64,
        serial: u64,
        signer: &dyn Signer,
    ) -> Self {
        let sig = signer.sign(&Self::signing_bytes(tsa, digest, time_ms, serial));
        Self {
            tsa: tsa.clone(),
            digest: digest.into(),
            time_ms,
            serial,
            signature_b64: b64_encode(&sig),
        }
    }

    pub fn verify(&self, tsa_public_key: &[u8]) -> Result<()> {
        let sig = b64_decode(&self.signature_b64)?;
        crypto::verify(
            tsa_public_key,
            &Self::signing_bytes(&self.tsa, &self.digest, self.time_ms, self.serial),
            &sig,
        )
    }
}

/// Verify a [`Proof`] against the public keys of the two parties.
///
/// Returns the opened request and response envelopes on success.
pub fn verify_proof(
    proof: &Proof,
    consumer_public_key: &[u8],
    provider_public_key: &[u8],
) -> Result<(RequestEnvelope, ResponseEnvelope)> {
    let req: RequestEnvelope = proof.request.open(REQUEST_DOMAIN, consumer_public_key)?;
    let res: ResponseEnvelope = proof.response.open(RESPONSE_DOMAIN, provider_public_key)?;
    let req_body = b64_decode(&proof.request_body_b64)?;
    let res_body = b64_decode(&proof.response_body_b64)?;
    if crypto::sha256_hex(&req_body) != req.body_sha256 {
        return Err(Error::Verify("request body does not match its hash".into()));
    }
    if crypto::sha256_hex(&res_body) != res.body_sha256 {
        return Err(Error::Verify(
            "response body does not match its hash".into(),
        ));
    }
    if res.request_id != req.message_id || res.request_sha256 != proof.request.payload_sha256()? {
        return Err(Error::Verify(
            "response is not bound to this request".into(),
        ));
    }
    if res.provider != req.service.member {
        return Err(Error::Verify(
            "response signed by a different member than the service owner".into(),
        ));
    }
    Ok((req, res))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareSigner;
    use rand::{Rng, RngCore, SeedableRng};

    fn signer() -> SoftwareSigner {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        SoftwareSigner::from_pkcs8_pem(&kp.serialize_pem()).unwrap()
    }

    fn envelope() -> RequestEnvelope {
        RequestEnvelope {
            version: PROTOCOL_VERSION,
            message_id: "abc".into(),
            client: "ZW/COM/1/ap".parse().unwrap(),
            service: "ZW/GOV/ZIMRA/a/b/v1".parse().unwrap(),
            issued_at_ms: 1,
            body_sha256: crypto::sha256_hex(b"x"),
            content_type: "application/json".into(),
            subject: None,
        }
    }

    #[test]
    fn domain_separation() {
        let s = signer();
        let signed = SignedMessage::sign(REQUEST_DOMAIN, &envelope(), &s).unwrap();
        assert!(signed
            .open::<RequestEnvelope>(REQUEST_DOMAIN, &s.public_key())
            .is_ok());
        // a request signature is not valid as a response signature
        assert!(signed
            .open::<RequestEnvelope>(RESPONSE_DOMAIN, &s.public_key())
            .is_err());
    }

    /// Cheap robustness check in lieu of real fuzzing: hostile input must be
    /// rejected with an error, never a panic.
    #[test]
    fn garbage_never_panics() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let pk = signer().public_key();
        for _ in 0..2000 {
            let n = rng.gen_range(0..200);
            let mut bytes = vec![0u8; n];
            rng.fill_bytes(&mut bytes);
            let text: String = bytes.iter().map(|b| (*b % 95 + 32) as char).collect();
            let _ = text.parse::<crate::id::MemberId>();
            let _ = text.parse::<crate::id::ClientId>();
            let _ = text.parse::<crate::id::ServiceId>();
            let _ = b64_decode(&text);
            let msg = SignedMessage {
                payload_b64: b64_encode(&bytes),
                signature_b64: text.clone(),
            };
            assert!(msg.open::<RequestEnvelope>(REQUEST_DOMAIN, &pk).is_err());
            let _ = serde_json::from_slice::<ExchangeRequest>(&bytes);
            let _ = crate::pki::inspect_cert_der(&bytes);
        }
    }
}
