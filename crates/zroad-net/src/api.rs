//! Request and response bodies of the central server API.

use serde::{Deserialize, Serialize};
use zroad_core::id::MemberId;

#[derive(Debug, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub id: MemberId,
    pub name: String,
    /// Ignored when `hosted_by` is set: a hosted member is reached at its node's endpoint.
    pub endpoint: String,
    /// Register this member as hosted by an enrolled, active node. The member
    /// keeps its own signing key; the node carries its traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_by: Option<MemberId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddMemberResponse {
    pub member_id: MemberId,
    pub enrollment_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub member_id: MemberId,
    pub enrollment_token: String,
    pub csr_pem: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub cert_pem: String,
    pub ca_pem: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub member_id: MemberId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
}

/// Certificate renewal: the member authenticates with its current certificate.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenewRequest {
    pub csr_pem: String,
}

/// A service as a provider describes it; `id` is `subsystem/service/version`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogueItem {
    pub id: String,
    pub title: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<serde_json::Value>,
}

/// Replaces everything the calling member has published.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublishCatalogueRequest {
    pub services: Vec<CatalogueItem>,
    /// A node publishing on behalf of a member it hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<MemberId>,
}

/// Ask a member's signer service to sign `domain "\n" payload`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub message_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature_b64: String,
}
