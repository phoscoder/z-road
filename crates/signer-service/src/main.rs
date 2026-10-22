use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Z-Road signer: lets a hosted member keep its own signing key")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the signer's TLS identity (private CA and server certificate).
    Init {
        #[arg(long)]
        dir: PathBuf,
        /// Host names or IP addresses the signer is reachable at (repeatable).
        #[arg(long = "san", required = true)]
        sans: Vec<String>,
    },
    /// Run the signer.
    Run {
        /// Directory with key.pem, cert.pem, ca.pem (zroad-cli enroll) and tls.pem, tls.key (init).
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9443")]
        listen: String,
        /// The member whose key this is.
        #[arg(long)]
        member: String,
        /// The only node allowed to ask for signatures.
        #[arg(long)]
        node: String,
        #[arg(long, default_value_t = 600)]
        max_per_minute: u32,
        /// Central server URL. When set, the signer renews the member's key and
        /// certificate before they expire, without a restart.
        #[arg(long)]
        central: Option<String>,
        #[arg(long, default_value_t = 30)]
        renew_before_days: i64,
        /// Seconds to keep signing with the old key after a renewal.
        #[arg(long, default_value_t = 65)]
        activation_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Init { dir, sans } => {
            signer_service::init(&dir, &sans)?;
            println!(
                "initialised {}; give {}/signer-ca.pem to the hosting node",
                dir.display(),
                dir.display()
            );
        }
        Cmd::Run {
            dir,
            listen,
            member,
            node,
            max_per_minute,
            central,
            renew_before_days,
            activation_secs,
        } => {
            let h = signer_service::spawn(signer_service::SignerConfig {
                dir,
                listen,
                member: member.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                node: node.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                max_per_minute,
                options: signer_service::Options {
                    central_url: central,
                    renew_before_days,
                    activation_delay: std::time::Duration::from_secs(activation_secs),
                    ..Default::default()
                },
            })
            .await?;
            tracing::info!("signer listening on https://{}", h.addr);
            h.wait().await;
        }
    }
    Ok(())
}
