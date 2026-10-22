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
