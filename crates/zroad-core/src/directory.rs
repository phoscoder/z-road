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
    pub cert_pem: Option<String>,
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

    pub fn get_active(&self, id: &MemberId) -> Option<&MemberRecord> {
        self.get(id)
            .filter(|m| m.status == MemberStatus::Active && m.cert_pem.is_some())
    }
}
