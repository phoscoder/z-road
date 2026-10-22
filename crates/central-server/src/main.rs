use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Z-Road central server: certificate authority and member directory")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the CA, the server identity and the admin token.
    Init {
        #[arg(long)]
        dir: PathBuf,
        /// Host names or IP addresses the server is reachable at (repeatable).
        #[arg(long = "san", required = true)]
        sans: Vec<String>,
    },
    /// Serve the directory and enrolment API.
    Run {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
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
            central_server::init(&dir, &sans)?;
            println!("initialised {}", dir.display());
            println!(
                "distribute {}/ca.pem to every member (out of band)",
                dir.display()
            );
            println!("admin token is in {}/admin_token", dir.display());
        }
        Cmd::Run { dir, listen } => {
            let h = central_server::spawn(&dir, &listen).await?;
            tracing::info!("central server listening on https://{}", h.addr);
            h.wait().await;
        }
    }
    Ok(())
}
