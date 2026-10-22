use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use zroad_core::audit::{self, AuditEvent};
use zroad_core::directory::Directory;
use zroad_core::id::MemberId;
use zroad_core::msg::Proof;
use zroad_core::pki;
use zroad_net::central_client::{enroll_to_dir, CentralClient};

#[derive(Parser)]
#[command(name = "zroad-cli", about = "Z-Road administration and audit tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct Central {
    /// Base URL of the central server, e.g. https://127.0.0.1:8443
    #[arg(long)]
    central: String,
    /// The root CA certificate, obtained out of band.
    #[arg(long)]
    ca: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register a new member and print its one-time enrolment token.
    MemberAdd {
        #[command(flatten)]
        central: Central,
        #[arg(long)]
        admin_token_file: PathBuf,
        #[arg(long)]
        id: MemberId,
        #[arg(long)]
        name: String,
        /// https URL of the member's security server.
        #[arg(long)]
        endpoint: String,
    },
    /// Revoke a member. Revocation is final.
    MemberRevoke {
        #[command(flatten)]
        central: Central,
        #[arg(long)]
        admin_token_file: PathBuf,
        #[arg(long)]
        id: MemberId,
    },
    /// Print the member directory.
    Directory {
        #[command(flatten)]
        central: Central,
    },
    /// List the services offered on the network.
    Catalogue {
        #[command(flatten)]
        central: Central,
    },
    /// Generate a key, enrol with the central server and store the identity.
    Enroll {
        #[command(flatten)]
        central: Central,
        #[arg(long)]
        id: MemberId,
        #[arg(long)]
        token: String,
        /// Host name or IP the security server is reachable at (repeatable).
        #[arg(long = "san", required = true)]
        sans: Vec<String>,
        /// Output directory for key.pem, cert.pem and ca.pem.
        #[arg(long)]
        out: PathBuf,
    },
    /// Replace this member's certificate and key (while the old one is still
    /// valid), then restart the security server.
    Renew {
        #[arg(long)]
        central: String,
        /// The directory holding key.pem, cert.pem and ca.pem.
        #[arg(long)]
        dir: PathBuf,
        #[arg(long = "san", required = true)]
        sans: Vec<String>,
    },
    /// Verify an audit log: hash chain and, with a directory, timestamp anchors.
    AuditVerify {
        #[arg(long)]
        log: PathBuf,
        /// A directory JSON file (a security server keeps one as directory.json).
        #[arg(long)]
        directory: Option<PathBuf>,
    },
    /// Verify an exchange proof offline against a directory.
    ProofVerify {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        directory: PathBuf,
    },
    /// Ask a security server who accessed a data subject.
    AccessLog {
        /// Internal URL of the provider's security server.
        #[arg(long)]
        security_server: String,
        #[arg(long)]
        admin_token: String,
        #[arg(long)]
        subject: String,
    },
}

fn read_ca(p: &Path) -> Result<String> {
    std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
}

fn read_dir_file(p: &Path) -> Result<Directory> {
    Ok(serde_json::from_slice(
        &std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
    )?)
}

fn member_key(dir: &Directory, id: &MemberId) -> Result<Vec<u8>> {
    let m = dir
        .get(id)
        .ok_or_else(|| anyhow!("{id} is not in the directory"))?;
    let pem = m
        .cert_pem
        .as_deref()
        .ok_or_else(|| anyhow!("{id} has no certificate"))?;
    Ok(pki::inspect_cert_pem(pem)
        .map_err(|e| anyhow!("{e}"))?
        .public_key)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::MemberAdd {
            central,
            admin_token_file,
            id,
            name,
            endpoint,
        } => {
            let c = CentralClient::new(&central.central, &read_ca(&central.ca)?)?;
            let token = std::fs::read_to_string(admin_token_file)?;
            let r = c.add_member(token.trim(), &id, &name, &endpoint).await?;
            println!("{}", r.enrollment_token);
            eprintln!(
                "member {} registered; give the token above to its operator (single use)",
                r.member_id
            );
        }
        Cmd::MemberRevoke {
            central,
            admin_token_file,
            id,
        } => {
            let c = CentralClient::new(&central.central, &read_ca(&central.ca)?)?;
            c.revoke(std::fs::read_to_string(admin_token_file)?.trim(), &id)
                .await?;
            println!("revoked {id}");
        }
        Cmd::Directory { central } => {
            let c = CentralClient::new(&central.central, &read_ca(&central.ca)?)?;
            println!("{}", serde_json::to_string_pretty(&c.directory().await?)?);
        }
        Cmd::Catalogue { central } => {
            let c = CentralClient::new(&central.central, &read_ca(&central.ca)?)?;
            let cat = c.catalogue().await?;
            if cat.entries.is_empty() {
                println!("no services published");
            }
            for e in cat.entries {
                println!("{}\n    {}", e.service, e.title);
                if !e.description.is_empty() {
                    println!("    {}", e.description);
                }
            }
        }
        Cmd::Enroll {
            central,
            id,
            token,
            sans,
            out,
        } => {
            enroll_to_dir(
                &central.central,
                &read_ca(&central.ca)?,
                &id,
                &token,
                &sans,
                &out,
            )
            .await?;
            println!("enrolled {id}; identity written to {}", out.display());
        }
        Cmd::Renew { central, dir, sans } => {
            let id = zroad_net::central_client::renew_in_dir(&central, &dir, &sans).await?;
            println!("renewed {id}; restart its security server to use the new certificate");
        }
        Cmd::AuditVerify { log, directory } => {
            let report = audit::verify_file(&log).map_err(|e| anyhow!("{e}"))?;
            println!(
                "chain OK: {} entries, head {}",
                report.entries, report.head_hash
            );
            let dir = directory.as_deref().map(read_dir_file).transpose()?;
            for (seq, token) in &report.anchors {
                let when = token.time_ms;
                match &dir {
                    Some(d) => {
                        let key = member_key(d, &token.tsa)?;
                        token
                            .verify(&key)
                            .map_err(|e| anyhow!("anchor at entry {seq}: {e}"))?;
                        println!(
                            "anchor at entry {seq}: signature OK ({}, serial {}, time {when} ms)",
                            token.tsa, token.serial
                        );
                    }
                    None => println!(
                        "anchor at entry {seq}: not checked (no --directory), time {when} ms"
                    ),
                }
            }
            let entries = audit::read_entries(&log).map_err(|e| anyhow!("{e}"))?;
            let exchanges = entries
                .iter()
                .filter(|e| matches!(e.event, AuditEvent::Exchange { .. }))
                .count();
            println!(
                "{exchanges} exchange record(s), {} anchor(s)",
                report.anchors.len()
            );
        }
        Cmd::ProofVerify { proof, directory } => {
            let p: Proof = serde_json::from_slice(&std::fs::read(&proof)?)?;
            let dir = read_dir_file(&directory)?;
            let (req, res) = dir.verify_proof(&p).map_err(|e| anyhow!("INVALID: {e}"))?;
            println!("VALID");
            println!("  consumer: {}", req.client);
            println!("  service:  {}", req.service);
            println!("  asked at: {} ms", req.issued_at_ms);
            println!(
                "  answered: status {} at {} ms",
                res.status, res.issued_at_ms
            );
        }
        Cmd::AccessLog {
            security_server,
            admin_token,
            subject,
        } => {
            let url = format!(
                "{}/admin/v1/access-log?subject={}",
                security_server.trim_end_matches('/'),
                subject
            );
            let auth = format!("Bearer {admin_token}");
            let r = zroad_net::request(
                "GET",
                &url,
                &[("authorization", &auth)],
                Bytes::new(),
                None,
                std::time::Duration::from_secs(10),
            )
            .await?;
            if r.status != 200 {
                bail!(
                    "security server returned {}: {}",
                    r.status,
                    String::from_utf8_lossy(&r.body)
                );
            }
            println!("{}", String::from_utf8_lossy(&r.body));
        }
    }
    Ok(())
}
