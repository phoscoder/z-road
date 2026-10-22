use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Z-Road security server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the security server.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Check the configuration file and exit.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
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
        Cmd::Run { config } => {
            let running =
                security_server::spawn_node(security_server::config::NodeConfig::load(&config)?)
                    .await?;
            running.wait().await;
        }
        Cmd::CheckConfig { config } => {
            let node = security_server::config::NodeConfig::load(&config)?;
            for cfg in &node.members {
                println!(
                    "ok: {} provides {} service(s)",
                    cfg.member_id,
                    cfg.services.len()
                );
            }
        }
    }
    Ok(())
}
