//! The member directory published by the central server.

use serde::{Deserialize, Serialize};

use crate::id::MemberId;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Pending,
    Active,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberRecord {
    pub id: MemberId,
    pub name: String,
    /// Base URL of the member's security server, e.g. `https://zimra.example:8443`.
    pub endpoint: String,
    pub status: MemberStatus,
    /// The registered certificate. For a hosted member this holds the member's
    /// signing key; the member's TLS identity is its node's.
    pub cert_pem: Option<String>,
    /// The node (itself a member) that carries this member's traffic. A hosted
    /// member signs its own messages, so the node never holds its key, but peers
    /// accept its messages only from that node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_by: Option<MemberId>,
    /// Earlier certificates of this member, newest first. Kept so that proofs and
    /// audit anchors signed with a key that has since been rotated still verify.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_certs: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Directory {
    pub version: u64,
    pub generated_at_ms: u64,
    pub members: Vec<MemberRecord>,
}

impl Directory {
    pub fn get(&self, id: &MemberId) -> Option<&MemberRecord> {
        self.members.iter().find(|m| &m.id == id)
    }

    /// An active member with a certificate. A hosted member is only reachable
    /// while its node is active too: revoke the node and everything it hosts goes
    /// with it.
    pub fn get_active(&self, id: &MemberId) -> Option<&MemberRecord> {
        let rec = self
            .get(id)
            .filter(|m| m.status == MemberStatus::Active && m.cert_pem.is_some())?;
        match &rec.hosted_by {
            None => Some(rec),
            Some(node) => self
                .get(node)
                .filter(|n| n.status == MemberStatus::Active && n.hosted_by.is_none())
                .map(|_| rec),
        }
    }
}

/// One published service in the catalogue.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CatalogueEntry {
    pub service: crate::id::ServiceId,
    pub title: String,
    pub description: String,
    /// JSON Schema the request body must satisfy. Providers enforce it; consumers
    /// can check against it before sending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_schema: Option<serde_json::Value>,
    /// JSON Schema describing successful (2xx) answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<serde_json::Value>,
}

/// Every service offered by an active member. The catalogue says what exists and
/// who offers it, not who may use it: access rules stay private to each provider.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Catalogue {
    pub entries: Vec<CatalogueEntry>,
}

/// How far outside a certificate's validity a signed time may fall, to absorb
/// clock differences.
const VALIDITY_SLACK_MS: u64 = 10 * 60 * 1000;

impl Directory {
    /// Public key of a member's current certificate.
    pub fn member_key(&self, id: &MemberId) -> crate::Result<Vec<u8>> {
        let rec = self
            .get(id)
            .ok_or_else(|| crate::Error::Verify(format!("{id} is not in the directory")))?;
        let pem = rec
            .cert_pem
            .as_deref()
            .ok_or_else(|| crate::Error::Verify(format!("{id} has no certificate")))?;
        Ok(crate::pki::inspect_cert_pem(pem)?.public_key)
    }

    /// The member's current key and, for `grace_ms` after a rotation, the key it
    /// replaced. Used when verifying live traffic: during a rotation some members
    /// have not yet seen the new certificate and the rotating member keeps using
    /// the old one until they have.
    pub fn recent_keys(&self, id: &MemberId, now_ms: u64, grace_ms: u64) -> Vec<Vec<u8>> {
        let Some(rec) = self.get(id) else {
            return Vec::new();
        };
        let Some(current) = rec
            .cert_pem
            .as_deref()
            .and_then(|p| crate::pki::inspect_cert_pem(p).ok())
        else {
            return Vec::new();
        };
        let mut keys = vec![current.public_key.clone()];
        // certificates are backdated five minutes, so issue time is not_before + 5 min
        let issued_ms = current.not_before.max(0) as u64 * 1000 + 5 * 60 * 1000;
        if grace_ms > 0 && now_ms < issued_ms + grace_ms {
            if let Some(prev) = rec
                .previous_certs
                .first()
                .and_then(|p| crate::pki::inspect_cert_pem(p).ok())
            {
                keys.push(prev.public_key);
            }
        }
        keys
    }

    /// Every key this member has had that was valid at `ts_ms`, current first.
    /// Something signed at that time can only have been signed by one of them.
    pub fn member_keys_at(&self, id: &MemberId, ts_ms: u64) -> Vec<Vec<u8>> {
        let Some(rec) = self.get(id) else {
            return Vec::new();
        };
        rec.cert_pem
            .iter()
            .chain(rec.previous_certs.iter())
            .filter_map(|pem| crate::pki::inspect_cert_pem(pem).ok())
            .filter(|c| {
                let (from, to) = (
                    c.not_before.max(0) as u64 * 1000,
                    c.not_after.max(0) as u64 * 1000,
                );
                ts_ms + VALIDITY_SLACK_MS >= from && ts_ms <= to + VALIDITY_SLACK_MS
            })
            .map(|c| c.public_key)
            .collect()
    }

    /// Check an exchange proof offline: read the parties and times it names, then
    /// verify both signatures with the keys those members had at those times, and
    /// the bindings between the messages. Works across certificate renewals.
    pub fn verify_proof(
        &self,
        proof: &crate::msg::Proof,
    ) -> crate::Result<(crate::msg::RequestEnvelope, crate::msg::ResponseEnvelope)> {
        let claimed: crate::msg::RequestEnvelope =
            serde_json::from_slice(&proof.request.payload()?)?;
        let answered: crate::msg::ResponseEnvelope =
            serde_json::from_slice(&proof.response.payload()?)?;
        let consumers = self.member_keys_at(&claimed.client.member, claimed.issued_at_ms);
        let providers = self.member_keys_at(&claimed.service.member, answered.issued_at_ms);
        if consumers.is_empty() || providers.is_empty() {
            return Err(crate::Error::Verify(
                "no certificate of the consumer or the provider covers the time of the exchange"
                    .into(),
            ));
        }
        let mut last = crate::Error::Verify("no key matched".into());
        for c in &consumers {
            for p in &providers {
                match crate::msg::verify_proof(proof, c, p) {
                    Ok(v) => return Ok(v),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// Verify a timestamp token with whichever key the authority had at the time.
    pub fn verify_timestamp(&self, token: &crate::msg::TimestampToken) -> crate::Result<()> {
        let mut last =
            crate::Error::Verify("the timestamp authority had no certificate at that time".into());
        for key in self.member_keys_at(&token.tsa, token.time_ms) {
            match token.verify(&key) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Signer, SoftwareSigner};
    use crate::pki::{generate_identity, CertAuthority};
    use ::time::{Duration, OffsetDateTime};

    #[test]
    fn keys_are_time_bounded_and_timestamps_survive_rotation() {
        let ca = CertAuthority::generate("t", 365).unwrap().ca;
        let tsa: MemberId = "ZW/SYS/tsa".parse().unwrap();
        let sans = vec!["127.0.0.1".to_string()];
        let now = OffsetDateTime::now_utc();
        let issue = |from: i64, to: i64| {
            let id = generate_identity(&tsa, &sans).unwrap();
            let pem = ca
                .sign_csr_window(
                    &id.csr_pem,
                    &tsa,
                    &sans,
                    now + Duration::days(from),
                    now + Duration::days(to),
                )
                .unwrap();
            (pem, SoftwareSigner::from_pkcs8_pem(&id.key_pem).unwrap())
        };
        let (old_pem, old_key) = issue(-60, -30);
        let (new_pem, new_key) = issue(-30, 335);
        let dir = Directory {
            version: 1,
            generated_at_ms: 0,
            members: vec![MemberRecord {
                id: tsa.clone(),
                name: "tsa".into(),
                endpoint: "https://127.0.0.1:1".into(),
                status: MemberStatus::Active,
                cert_pem: Some(new_pem),
                hosted_by: None,
                previous_certs: vec![old_pem],
            }],
        };
        let at = |days: i64| ((now + Duration::days(days)).unix_timestamp() as u64) * 1000;
        // 40 days ago only the old key was valid; today only the new one.
        assert_eq!(
            dir.member_keys_at(&tsa, at(-40)),
            vec![old_key.public_key()]
        );
        assert_eq!(dir.member_keys_at(&tsa, at(0)), vec![new_key.public_key()]);
        assert!(dir.member_keys_at(&tsa, at(-100)).is_empty());
        // a token issued with the old key verifies even though the key was rotated
        let token = crate::msg::TimestampToken::issue(&tsa, &"ab".repeat(32), at(-40), 7, &old_key);
        dir.verify_timestamp(&token).unwrap();
        // the same token claiming a time when only the new key was valid does not
        let backdated = crate::msg::TimestampToken {
            time_ms: at(0),
            ..token
        };
        assert!(dir.verify_timestamp(&backdated).is_err());
    }
}
