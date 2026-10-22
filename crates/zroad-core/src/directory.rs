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

impl Directory {
    /// Public key of a member, from its registered certificate.
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

    /// Check an exchange proof offline: read the parties it names, then verify
    /// both signatures with their registered keys and the bindings between them.
    pub fn verify_proof(
        &self,
        proof: &crate::msg::Proof,
    ) -> crate::Result<(crate::msg::RequestEnvelope, crate::msg::ResponseEnvelope)> {
        let claimed: crate::msg::RequestEnvelope =
            serde_json::from_slice(&proof.request.payload()?)?;
        crate::msg::verify_proof(
            proof,
            &self.member_key(&claimed.client.member)?,
            &self.member_key(&claimed.service.member)?,
        )
    }
}
