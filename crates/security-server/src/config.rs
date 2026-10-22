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
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.admin_token.len() < 16 {
            bail!("admin_token must be at least 16 characters");
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
