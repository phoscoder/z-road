use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use zroad_core::id::{client_matches, MemberId};

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceConfig {
    /// `subsystem/service/version`, as it appears in the service id.
    pub id: String,
    /// Internal URL that answers requests for this service.
    pub upstream: String,
    /// Shown in the public catalogue (defaults to the id).
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// JSON Schema file for request bodies. When set, the security server
    /// rejects non-conforming requests before they reach the internal system, and
    /// publishes the schema in the catalogue.
    #[serde(default)]
    pub request_schema: Option<PathBuf>,
    /// JSON Schema file for successful answers.
    #[serde(default)]
    pub response_schema: Option<PathBuf>,
    /// Refuse to deliver answers that violate `response_schema` (default: only
    /// log a warning).
    #[serde(default)]
    pub enforce_response_schema: bool,
}

/// A member that keeps its own signing key on its own machine (see the
/// `signer-service` crate) instead of handing it to the node that hosts it.
#[derive(Clone, Debug, Deserialize)]
pub struct RemoteSignerConfig {
    /// `https://host:port` of the member's signer service.
    pub url: String,
    /// The signer's own CA certificate (`signer-ca.pem`), which this node pins.
    pub ca_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AccessRule {
    /// `subsystem/service/version` of a service this member provides.
    pub service: String,
    /// Allowed clients: `ZW/COM/*` (any subsystem of any member of that class),
    /// `ZW/COM/12345678` (one member) or `ZW/COM/12345678/accounts-payable`.
    pub allow: Vec<String>,
}

fn d_tsa() -> MemberId {
    "ZW/SYS/tsa".parse().expect("valid default")
}
fn d_refresh() -> u64 {
    30
}
fn d_anchor() -> u64 {
    60
}
fn d_rate() -> u32 {
    50
}
fn d_body() -> usize {
    2 * 1024 * 1024
}
fn d_timeout() -> u64 {
    15
}
fn d_renew() -> i64 {
    30
}
fn d_attempts() -> u32 {
    20
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub member_id: MemberId,
    pub data_dir: PathBuf,
    pub central_url: String,
    /// Address of the mutual-TLS listener other members connect to.
    pub network_listen: String,
    /// Address of the plain-HTTP listener for this organisation's own systems.
    /// Bind it to localhost or a private interface only.
    pub internal_listen: String,
    pub admin_token: String,
    #[serde(default)]
    pub internal_token: Option<String>,
    #[serde(default = "d_tsa")]
    pub tsa_member: MemberId,
    #[serde(default = "d_refresh")]
    pub directory_refresh_secs: u64,
    /// 0 disables audit log anchoring.
    #[serde(default = "d_anchor")]
    pub anchor_interval_secs: u64,
    #[serde(default = "d_rate")]
    pub rate_limit_per_sec: u32,
    #[serde(default = "d_body")]
    pub max_body_bytes: usize,
    #[serde(default = "d_timeout")]
    pub upstream_timeout_secs: u64,
    #[serde(default = "d_attempts")]
    pub outbox_max_attempts: u32,
    /// Renew the certificate automatically when fewer than this many days
    /// remain. 0 disables automatic renewal (a warning is still logged).
    #[serde(default = "d_renew")]
    pub renew_before_days: i64,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
    /// Set for a hosted member whose key is not held here. `data_dir` then needs
    /// only `cert.pem` and `ca.pem`: there is no `key.pem`.
    #[serde(default)]
    pub remote_signer: Option<RemoteSignerConfig>,
    /// The node's own identity (`key.pem`, `cert.pem`, `ca.pem`), used for TLS on
    /// behalf of remote-signed members.
    #[serde(default)]
    pub node_identity_dir: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if let Some(base) = path.parent() {
            if cfg.data_dir.is_relative() {
                cfg.data_dir = base.join(&cfg.data_dir);
            }
            resolve_schema_paths(&mut cfg.services, base);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.admin_token.len() < 16 {
            bail!("admin_token must be at least 16 characters");
        }
        if self.remote_signer.is_some() && self.node_identity_dir.is_none() {
            bail!("a remote-signed member needs the node's identity (node_identity_dir)");
        }
        if let Some(r) = &self.remote_signer {
            if !r.url.starts_with("https://") {
                bail!("remote_signer.url must be an https URL");
            }
        }
        for s in &self.services {
            if s.id.split('/').count() != 3 {
                bail!("service id `{}` must be subsystem/service/version", s.id);
            }
            if !(s.upstream.starts_with("http://") || s.upstream.starts_with("https://")) {
                bail!("service `{}` upstream must be an http(s) URL", s.id);
            }
        }
        for r in &self.access {
            if !self.services.iter().any(|s| s.id == r.service) {
                return Err(anyhow!("access rule for unknown service `{}`", r.service));
            }
            for p in &r.allow {
                let n = p.split('/').count();
                if n != 3 && n != 4 {
                    bail!("access pattern `{p}` must have 3 or 4 segments");
                }
            }
        }
        Ok(())
    }

    pub fn upstream_for(&self, local_key: &str) -> Option<&str> {
        self.services
            .iter()
            .find(|s| s.id == local_key)
            .map(|s| s.upstream.as_str())
    }

    pub fn is_allowed(&self, local_key: &str, client: &zroad_core::id::ClientId) -> bool {
        self.access
            .iter()
            .filter(|r| r.service == local_key)
            .flat_map(|r| r.allow.iter())
            .any(|p| client_matches(p, client))
    }
}

fn resolve_schema_paths(services: &mut [ServiceConfig], base: &Path) {
    for s in services {
        for p in [&mut s.request_schema, &mut s.response_schema]
            .into_iter()
            .flatten()
        {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
    }
}

/// A shared security server: one node that hosts several members. Each hosted
/// member keeps its own identity, audit log, outbox, tokens, services and
/// access rules; the node only shares the listeners and the directory cache.
#[derive(Clone, Debug, Deserialize)]
struct NodeFile {
    central_url: String,
    network_listen: String,
    internal_listen: String,
    /// Where the node keeps state that is not specific to one member
    /// (the directory cache). Defaults to `node` next to the config file.
    #[serde(default)]
    node_dir: Option<PathBuf>,
    /// The node's own member identity. Required when any hosted member keeps its
    /// key in a signer service: the node then authenticates TLS as itself.
    #[serde(default)]
    node_member: Option<MemberId>,
    #[serde(default)]
    node_data_dir: Option<PathBuf>,
    #[serde(default = "d_tsa")]
    tsa_member: MemberId,
    #[serde(default = "d_refresh")]
    directory_refresh_secs: u64,
    #[serde(default = "d_anchor")]
    anchor_interval_secs: u64,
    #[serde(default = "d_rate")]
    rate_limit_per_sec: u32,
    #[serde(default = "d_body")]
    max_body_bytes: usize,
    #[serde(default = "d_timeout")]
    upstream_timeout_secs: u64,
    #[serde(default = "d_attempts")]
    outbox_max_attempts: u32,
    #[serde(default = "d_renew")]
    renew_before_days: i64,
    members: Vec<NodeMember>,
}

#[derive(Clone, Debug, Deserialize)]
struct NodeMember {
    member_id: MemberId,
    data_dir: PathBuf,
    admin_token: String,
    #[serde(default)]
    internal_token: Option<String>,
    #[serde(default)]
    services: Vec<ServiceConfig>,
    #[serde(default)]
    access: Vec<AccessRule>,
    #[serde(default)]
    remote_signer: Option<RemoteSignerConfig>,
}

/// The node's own identity.
#[derive(Clone, Debug)]
pub struct NodeIdentityConfig {
    pub member: MemberId,
    pub dir: PathBuf,
}

/// The settings of a whole node: its members plus the directory cache location.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub members: Vec<Config>,
    pub node_dir: PathBuf,
    pub node_identity: Option<NodeIdentityConfig>,
}

impl NodeConfig {
    /// Load either a single-member file (the original format) or a shared-node
    /// file with a `[[members]]` list.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let value: toml::Value =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if value.get("members").is_none() {
            let cfg = Config::load(path)?;
            let node_dir = cfg.data_dir.clone();
            return Ok(Self {
                members: vec![cfg],
                node_dir,
                node_identity: None,
            });
        }
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Self::from_node_file(
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?,
            &base,
        )
    }

    fn from_node_file(f: NodeFile, base: &Path) -> Result<Self> {
        if f.members.is_empty() {
            bail!("a shared node needs at least one member");
        }
        let abs = |p: &Path| {
            if p.is_relative() {
                base.join(p)
            } else {
                p.to_path_buf()
            }
        };
        let mut members = Vec::new();
        for m in &f.members {
            let mut services = m.services.clone();
            resolve_schema_paths(&mut services, base);
            let mut remote_signer = m.remote_signer.clone();
            if let Some(r) = &mut remote_signer {
                if r.ca_file.is_relative() {
                    r.ca_file = base.join(&r.ca_file);
                }
            }
            let cfg = Config {
                member_id: m.member_id.clone(),
                data_dir: abs(&m.data_dir),
                central_url: f.central_url.clone(),
                network_listen: f.network_listen.clone(),
                internal_listen: f.internal_listen.clone(),
                admin_token: m.admin_token.clone(),
                internal_token: m.internal_token.clone(),
                tsa_member: f.tsa_member.clone(),
                directory_refresh_secs: f.directory_refresh_secs,
                anchor_interval_secs: f.anchor_interval_secs,
                rate_limit_per_sec: f.rate_limit_per_sec,
                max_body_bytes: f.max_body_bytes,
                upstream_timeout_secs: f.upstream_timeout_secs,
                outbox_max_attempts: f.outbox_max_attempts,
                renew_before_days: f.renew_before_days,
                services,
                access: m.access.clone(),
                remote_signer,
                node_identity_dir: f.node_data_dir.as_ref().map(|p| abs(p)),
            };
            cfg.validate()
                .with_context(|| format!("member {}", cfg.member_id))?;
            members.push(cfg);
        }
        for (i, a) in members.iter().enumerate() {
            for b in &members[i + 1..] {
                if a.member_id == b.member_id {
                    bail!("member {} is listed twice", a.member_id);
                }
                if a.data_dir == b.data_dir {
                    bail!(
                        "members {} and {} share a data_dir",
                        a.member_id,
                        b.member_id
                    );
                }
                if a.admin_token == b.admin_token {
                    bail!(
                        "members {} and {} share an admin_token",
                        a.member_id,
                        b.member_id
                    );
                }
            }
        }
        let node_dir = f
            .node_dir
            .map(|p| abs(&p))
            .unwrap_or_else(|| base.join("node"));
        let node_identity = match (f.node_member, f.node_data_dir) {
            (Some(member), Some(dir)) => Some(NodeIdentityConfig {
                member,
                dir: abs(&dir),
            }),
            (None, None) => None,
            _ => bail!("node_member and node_data_dir must be set together"),
        };
        if members.iter().any(|m| m.remote_signer.is_some()) && node_identity.is_none() {
            bail!("members with a remote_signer need node_member and node_data_dir");
        }
        Ok(Self {
            members,
            node_dir,
            node_identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(extra: &str) -> Result<NodeConfig> {
        let text = format!(
            r#"
central_url = "https://c:8443"
network_listen = "0.0.0.0:7443"
internal_listen = "127.0.0.1:7001"
[[members]]
member_id = "ZW/COM/1"
data_dir = "one"
admin_token = "token-one-0123456789"
[[members]]
member_id = "ZW/COM/2"
data_dir = "two"
admin_token = "token-two-0123456789"
{extra}
"#
        );
        NodeConfig::from_node_file(toml::from_str(&text)?, Path::new("/etc/zroad"))
    }

    #[test]
    fn expands_members_with_shared_settings() {
        let n = node("").unwrap();
        assert_eq!(n.members.len(), 2);
        assert_eq!(n.members[0].data_dir, Path::new("/etc/zroad/one"));
        assert_eq!(n.members[1].network_listen, "0.0.0.0:7443");
        assert_eq!(n.node_dir, Path::new("/etc/zroad/node"));
    }

    #[test]
    fn rejects_shared_secrets_and_duplicates() {
        let dup = r#"
[[members]]
member_id = "ZW/COM/2"
data_dir = "three"
admin_token = "token-three-0123456789"
"#;
        assert!(node(dup).is_err());
        let same_token = r#"
[[members]]
member_id = "ZW/COM/3"
data_dir = "three"
admin_token = "token-two-0123456789"
"#;
        assert!(node(same_token).is_err());
    }
}
