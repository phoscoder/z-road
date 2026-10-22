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
    /// Add a named operator with a role (operator or admin; auditor is read-only)
    /// and print their token once.
    OperatorAdd {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        name: String,
        /// auditor, operator (add members) or admin (also revoke members).
        #[arg(long)]
        role: String,
    },
    OperatorRemove {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        name: String,
    },
    OperatorList {
        #[arg(long)]
        dir: PathBuf,
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
        Cmd::OperatorAdd { dir, name, role } => {
            let role = role.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            let token = central_server::add_operator(&dir, &name, role)?;
            println!("{token}");
            eprintln!("operator `{name}` added. This token is shown once; store it safely.");
        }
        Cmd::OperatorRemove { dir, name } => {
            central_server::remove_operator(&dir, &name)?;
            println!("removed {name}");
        }
        Cmd::OperatorList { dir } => {
            for o in central_server::list_operators(&dir)? {
                println!("{}\t{}", o.name, o.role.as_str());
            }
        }
        Cmd::Run { dir, listen } => {
            let h = central_server::spawn(&dir, &listen).await?;
            tracing::info!("central server listening on https://{}", h.addr);
            h.wait().await;
        }
    }
    Ok(())
}
