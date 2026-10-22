//! Operators, roles and API tokens for administrative endpoints.
//!
//! Each operator has their own random token. Only its SHA-256 is stored, which is
//! enough because tokens are 256-bit random values (there is nothing to brute
//! force and no need for a slow password hash). Checks compare against every entry
//! in constant time so timing does not reveal which operator exists.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{ct_eq, sha256_hex};
use crate::{random_secret, Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read-only: audit status, identity, proofs, privileged access-log lookups.
    Auditor,
    /// Everything an auditor can do, plus actions that change state: refresh the
    /// directory, anchor the log, renew, republish the catalogue, add members.
    Operator,
    /// Everything, including revoking members on the central server.
    Admin,
    /// A citizen-facing portal's backend. It can only call the citizen endpoint,
    /// and only together with a valid identity assertion for the person asking.
    Portal,
}

impl Role {
    fn rank(self) -> u8 {
        match self {
            Role::Auditor => 1,
            Role::Operator => 2,
            Role::Admin => 3,
            Role::Portal => 0,
        }
    }

    /// May a holder of this role do something that needs `needed`?
    /// `Portal` is separate from the ladder: it allows nothing else, and no other
    /// role stands in for it.
    pub fn allows(self, needed: Role) -> bool {
        match (self, needed) {
            (Role::Portal, Role::Portal) => true,
            (Role::Portal, _) | (_, Role::Portal) => false,
            _ => self.rank() >= needed.rank(),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Auditor => "auditor",
            Role::Operator => "operator",
            Role::Admin => "admin",
            Role::Portal => "portal",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "auditor" => Ok(Role::Auditor),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            "portal" => Ok(Role::Portal),
            other => Err(Error::InvalidId(format!(
                "unknown role `{other}` (auditor, operator, admin or portal)"
            ))),
        }
    }
}

/// One operator as stored in a config file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorEntry {
    pub name: String,
    pub role: Role,
    /// Lower-case hex SHA-256 of the operator's token.
    pub token_sha256: String,
}

/// Who a request was made by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub role: Role,
}

#[derive(Clone, Debug, Default)]
pub struct Authenticator {
    entries: Vec<OperatorEntry>,
}

/// Name given to the pre-existing single `admin_token`, for compatibility.
pub const LEGACY_ADMIN: &str = "legacy-admin";

pub fn hash_token(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// A fresh operator token: 256 random bits with a recognisable prefix.
pub fn new_token() -> String {
    format!("zroad_{}", random_secret())
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

impl Authenticator {
    pub fn new(entries: Vec<OperatorEntry>) -> Result<Self> {
        let mut names = HashSet::new();
        let mut hashes = HashSet::new();
        for e in &entries {
            if !valid_name(&e.name) {
                return Err(Error::InvalidId(format!("bad operator name `{}`", e.name)));
            }
            if e.token_sha256.len() != 64
                || !e
                    .token_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::InvalidId(format!(
                    "operator `{}`: token_sha256 must be 64 lower-case hex characters",
                    e.name
                )));
            }
            if !names.insert(e.name.clone()) {
                return Err(Error::InvalidId(format!(
                    "operator `{}` is listed twice",
                    e.name
                )));
            }
            if !hashes.insert(e.token_sha256.clone()) {
                return Err(Error::InvalidId(format!(
                    "operator `{}` shares a token with another operator",
                    e.name
                )));
            }
        }
        Ok(Self { entries })
    }

    /// Add the old single `admin_token` as an `admin` operator named `legacy-admin`.
    pub fn with_legacy_admin(mut self, token: Option<&str>) -> Self {
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            self.entries.push(OperatorEntry {
                name: LEGACY_ADMIN.into(),
                role: Role::Admin,
                token_sha256: hash_token(t),
            });
        }
        self
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[OperatorEntry] {
        &self.entries
    }

    /// Identify the holder of `token`, comparing against every entry.
    pub fn authenticate(&self, token: &str) -> Option<Principal> {
        let given = hash_token(token);
        let mut found = None;
        for e in &self.entries {
            if ct_eq(given.as_bytes(), e.token_sha256.as_bytes()) && found.is_none() {
                found = Some(Principal {
                    name: e.name.clone(),
                    role: e.role,
                });
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, role: Role, token: &str) -> OperatorEntry {
        OperatorEntry {
            name: name.into(),
            role,
            token_sha256: hash_token(token),
        }
    }

    #[test]
    fn role_ladder_and_portal_isolation() {
        assert!(Role::Admin.allows(Role::Operator) && Role::Admin.allows(Role::Auditor));
        assert!(Role::Operator.allows(Role::Auditor) && !Role::Operator.allows(Role::Admin));
        assert!(!Role::Auditor.allows(Role::Operator));
        // the portal role is a separate lane in both directions
        assert!(Role::Portal.allows(Role::Portal));
        assert!(!Role::Portal.allows(Role::Auditor) && !Role::Portal.allows(Role::Operator));
        assert!(!Role::Admin.allows(Role::Portal) && !Role::Auditor.allows(Role::Portal));
    }

    #[test]
    fn authenticates_by_token() {
        let a = Authenticator::new(vec![
            entry("alice", Role::Operator, "tok-a"),
            entry("bob", Role::Auditor, "tok-b"),
        ])
        .unwrap()
        .with_legacy_admin(Some("old-admin-token"));
        assert_eq!(a.authenticate("tok-a").unwrap().name, "alice");
        assert_eq!(a.authenticate("tok-b").unwrap().role, Role::Auditor);
        let legacy = a.authenticate("old-admin-token").unwrap();
        assert_eq!(
            (legacy.name.as_str(), legacy.role),
            (LEGACY_ADMIN, Role::Admin)
        );
        assert!(a.authenticate("nope").is_none());
        assert!(a.authenticate("").is_none());
    }

    #[test]
    fn config_is_validated() {
        let dup_name = vec![
            entry("a", Role::Auditor, "1"),
            entry("a", Role::Operator, "2"),
        ];
        assert!(Authenticator::new(dup_name).is_err());
        let dup_token = vec![
            entry("a", Role::Auditor, "1"),
            entry("b", Role::Operator, "1"),
        ];
        assert!(Authenticator::new(dup_token).is_err());
        let bad_hash = vec![OperatorEntry {
            name: "a".into(),
            role: Role::Auditor,
            token_sha256: "xyz".into(),
        }];
        assert!(Authenticator::new(bad_hash).is_err());
        assert!(Authenticator::new(vec![entry("bad name!", Role::Auditor, "1")]).is_err());
        assert!(Authenticator::default()
            .with_legacy_admin(Some(""))
            .is_empty());
    }

    #[test]
    fn tokens_are_random_and_prefixed() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert!(a.starts_with("zroad_") && a.len() == 6 + 64);
    }
}
