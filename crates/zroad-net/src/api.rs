//! Request and response bodies of the central server API.

use serde::{Deserialize, Serialize};
use zroad_core::id::MemberId;

#[derive(Debug, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub id: MemberId,
    pub name: String,
    pub endpoint: String,
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
}
