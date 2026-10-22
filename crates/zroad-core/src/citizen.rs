//! Citizen identity assertions.
//!
//! A citizen-facing portal must never be able to ask "who looked at X?" for an
//! arbitrary X. Instead, whatever system really authenticates the citizen (the
//! provider's own login, a national digital ID, a bank) issues a short-lived,
//! signed assertion "the person who just logged in controls identifier X". The
//! security server checks the assertion against the issuers it trusts and answers
//! only for that identifier, so a compromised portal can only read records for
//! which it holds a fresh assertion.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, Signer};
use crate::id::MemberId;
use crate::msg::{b64_decode, b64_encode, signing_input};
use crate::{Error, Result};

pub const CITIZEN_DOMAIN: &str = "zroad/v1/citizen-assertion";
/// An assertion may be valid for at most this long.
pub const MAX_LIFETIME_MS: u64 = 10 * 60 * 1000;
const SKEW_MS: u64 = 60 * 1000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Assertion {
    pub v: u32,
    /// The identifier the citizen controls, exactly as consumers pass it in
    /// `Z-Road-Subject` (for example a TIN or a national ID number).
    pub sub: String,
    /// The provider member this assertion is for.
    pub aud: MemberId,
    pub iat_ms: u64,
    pub exp_ms: u64,
    pub jti: String,
}

/// An issuer the security server trusts to authenticate citizens.
#[derive(Clone, Debug)]
pub struct TrustedIssuer {
    pub name: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
}

/// Issue `token = base64(payload) "." base64(signature)`.
pub fn issue(a: &Assertion, signer: &dyn Signer) -> Result<String> {
    let payload = serde_json::to_vec(a)?;
    let sig = signer.sign(&signing_input(CITIZEN_DOMAIN, &payload));
    Ok(format!("{}.{}", b64_encode(&payload), b64_encode(&sig)))
}

/// Verify a token against the trusted issuers and return the assertion and the
/// name of the issuer that signed it.
pub fn verify(
    token: &str,
    issuers: &[TrustedIssuer],
    expected_aud: &MemberId,
    now_ms: u64,
) -> Result<(Assertion, String)> {
    let bad = |m: &str| Error::Verify(format!("citizen assertion: {m}"));
    if token.len() > 4096 {
        return Err(bad("too long"));
    }
    let (p, s) = token.split_once('.').ok_or_else(|| bad("malformed"))?;
    let payload = b64_decode(p).map_err(|_| bad("malformed"))?;
    let sig = b64_decode(s).map_err(|_| bad("malformed"))?;
    let input = signing_input(CITIZEN_DOMAIN, &payload);
    let issuer = issuers
        .iter()
        .find(|i| crypto::verify(&i.public_key, &input, &sig).is_ok())
        .ok_or_else(|| bad("not signed by a trusted issuer"))?;
    let a: Assertion = serde_json::from_slice(&payload).map_err(|_| bad("malformed"))?;
    if a.v != 1 {
        return Err(bad("unsupported version"));
    }
    if &a.aud != expected_aud {
        return Err(bad("issued for a different provider"));
    }
    if a.sub.is_empty() || a.sub.len() > 128 {
        return Err(bad("bad subject"));
    }
    if a.exp_ms <= a.iat_ms || a.exp_ms - a.iat_ms > MAX_LIFETIME_MS {
        return Err(bad("lifetime out of range"));
    }
    if a.iat_ms > now_ms + SKEW_MS {
        return Err(bad("issued in the future"));
    }
    if a.exp_ms <= now_ms {
        return Err(bad("expired"));
    }
    Ok((a, issuer.name.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareSigner;

    fn signer() -> SoftwareSigner {
        SoftwareSigner::from_pkcs8_pem(
            &rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .unwrap()
                .serialize_pem(),
        )
        .unwrap()
    }

    fn assertion(now: u64) -> Assertion {
        Assertion {
            v: 1,
            sub: "2000123456".into(),
            aud: "ZW/GOV/ZIMRA".parse().unwrap(),
            iat_ms: now,
            exp_ms: now + 5 * 60 * 1000,
            jti: "j1".into(),
        }
    }

    #[test]
    fn accepts_only_what_it_should() {
        let (idp, other) = (signer(), signer());
        let issuers = vec![TrustedIssuer {
            name: "zimra-login".into(),
            public_key: Signer::public_key(&idp),
        }];
        let aud: MemberId = "ZW/GOV/ZIMRA".parse().unwrap();
        let now = 1_000_000_000_000;
        let good = issue(&assertion(now), &idp).unwrap();
        let (a, who) = verify(&good, &issuers, &aud, now + 1000).unwrap();
        assert_eq!(
            (a.sub.as_str(), who.as_str()),
            ("2000123456", "zimra-login")
        );

        // wrong issuer, wrong audience, expired, too long-lived, from the future
        assert!(verify(
            &issue(&assertion(now), &other).unwrap(),
            &issuers,
            &aud,
            now
        )
        .is_err());
        assert!(verify(&good, &issuers, &"ZW/GOV/OTHER".parse().unwrap(), now).is_err());
        assert!(verify(&good, &issuers, &aud, now + 6 * 60 * 1000).is_err());
        let mut long = assertion(now);
        long.exp_ms = now + MAX_LIFETIME_MS + 1;
        assert!(verify(&issue(&long, &idp).unwrap(), &issuers, &aud, now).is_err());
        assert!(verify(
            &issue(&assertion(now + 10 * 60 * 1000), &idp).unwrap(),
            &issuers,
            &aud,
            now
        )
        .is_err());
        // tampering with the subject breaks the signature
        let (p, s) = good.split_once('.').unwrap();
        let forged_payload = String::from_utf8(b64_decode(p).unwrap())
            .unwrap()
            .replace("2000123456", "2000999999");
        assert!(verify(
            &format!("{}.{s}", b64_encode(forged_payload.as_bytes())),
            &issuers,
            &aud,
            now
        )
        .is_err());
        // garbage
        for junk in ["", ".", "a.b", "no-dot", &"x".repeat(5000)] {
            assert!(verify(junk, &issuers, &aud, now).is_err());
        }
        // no trusted issuers means nothing verifies
        assert!(verify(&good, &[], &aud, now).is_err());
    }
}
