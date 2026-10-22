//! Identifiers: `instance/class/code[/subsystem[/service/version]]`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.bytes().all(|b| b == b'.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn split<'a>(s: &'a str, expected: usize, what: &str) -> Result<Vec<&'a str>> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != expected || !parts.iter().all(|p| valid_segment(p)) {
        return Err(Error::InvalidId(format!(
            "{what} must have {expected} segments of [A-Za-z0-9._-], got `{s}`"
        )));
    }
    Ok(parts)
}

macro_rules! string_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// An organisation on the network, e.g. `ZW/GOV/ZIMRA`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberId {
    pub instance: String,
    pub class: String,
    pub code: String,
}

impl MemberId {
    pub fn new(instance: &str, class: &str, code: &str) -> Result<Self> {
        format!("{instance}/{class}/{code}").parse()
    }
}

impl FromStr for MemberId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let p = split(s, 3, "member id")?;
        Ok(Self {
            instance: p[0].into(),
            class: p[1].into(),
            code: p[2].into(),
        })
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.instance, self.class, self.code)
    }
}
string_serde!(MemberId);

/// A consuming subsystem of a member, e.g. `ZW/COM/12345678/accounts-payable`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientId {
    pub member: MemberId,
    pub subsystem: String,
}

impl FromStr for ClientId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let p = split(s, 4, "client id")?;
        Ok(Self {
            member: MemberId::new(p[0], p[1], p[2])?,
            subsystem: p[3].into(),
        })
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.member, self.subsystem)
    }
}
string_serde!(ClientId);

/// A service offered by a member, e.g. `ZW/GOV/ZIMRA/tax-clearance/verify/v1`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServiceId {
    pub member: MemberId,
    pub subsystem: String,
    pub service: String,
    pub version: String,
}

impl ServiceId {
    /// The part a provider uses in its own configuration: `subsystem/service/version`.
    pub fn local_key(&self) -> String {
        format!("{}/{}/{}", self.subsystem, self.service, self.version)
    }
}

impl FromStr for ServiceId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let p = split(s, 6, "service id")?;
        Ok(Self {
            member: MemberId::new(p[0], p[1], p[2])?,
            subsystem: p[3].into(),
            service: p[4].into(),
            version: p[5].into(),
        })
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.member, self.subsystem, self.service, self.version
        )
    }
}
string_serde!(ServiceId);

/// Does `pattern` allow `client`?
///
/// A pattern has three segments (member level, e.g. `ZW/COM/*`) or four
/// (subsystem level, e.g. `ZW/COM/12345678/accounts-payable`). `*` matches any
/// single segment.
pub fn client_matches(pattern: &str, client: &ClientId) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let full = client.to_string();
    let cli: Vec<&str> = full.split('/').collect();
    if pat.len() != 3 && pat.len() != 4 {
        return false;
    }
    pat.iter().zip(cli.iter()).all(|(p, c)| *p == "*" || p == c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s: ServiceId = "ZW/GOV/ZIMRA/tax-clearance/verify/v1".parse().unwrap();
        assert_eq!(s.to_string(), "ZW/GOV/ZIMRA/tax-clearance/verify/v1");
        assert_eq!(s.local_key(), "tax-clearance/verify/v1");
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<ServiceId>(&j).unwrap(), s);
    }

    #[test]
    fn rejects_bad_ids() {
        assert!("ZW/GOV".parse::<MemberId>().is_err());
        assert!("ZW/GOV/..".parse::<MemberId>().is_err());
        assert!("ZW/GOV/a b".parse::<MemberId>().is_err());
        assert!("ZW/GOV/ZIMRA/x/y".parse::<ClientId>().is_err());
    }

    #[test]
    fn patterns() {
        let c: ClientId = "ZW/COM/123/ap".parse().unwrap();
        assert!(client_matches("ZW/COM/*", &c));
        assert!(client_matches("ZW/COM/123", &c));
        assert!(client_matches("ZW/COM/123/ap", &c));
        assert!(!client_matches("ZW/GOV/*", &c));
        assert!(!client_matches("ZW/COM/123/other", &c));
        assert!(!client_matches("ZW/*", &c));
    }
}
