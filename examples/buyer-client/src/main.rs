//! A tiny consumer: asks ZIMRA, through this company's own security server,
//! whether a supplier's tax clearance is valid, and saves the signed proof.
//! It shows what an integration looks like with the `zroad-client` crate.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
use zroad_client::{CallOptions, Client};

#[derive(Parser)]
struct Cli {
    /// Internal URL of this company's security server.
    #[arg(long, default_value = "http://127.0.0.1:7001")]
    security_server: String,
    /// This company's subsystem making the request.
    #[arg(long, default_value = "ZW/COM/12345678/accounts-payable")]
    client: String,
    /// The supplier's TIN.
    #[arg(long)]
    tin: String,
    /// Queue the request instead of waiting (survives outages).
    #[arg(long = "async")]
    async_mode: bool,
    /// Where to write the signed proof of the exchange.
    #[arg(long)]
    proof_out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let zroad = Client::new(
        &cli.security_server,
        cli.client.parse().map_err(|e| anyhow!("{e}"))?,
    );
    let service = "ZW/GOV/ZIMRA/tax-clearance/verify/v1"
        .parse()
        .map_err(|e| anyhow!("{e}"))?;
    let body = serde_json::json!({ "tin": cli.tin });
    let opts = CallOptions::default().subject(&cli.tin);

    let reply = if cli.async_mode {
        let id = zroad
            .submit(&service, serde_json::to_vec(&body)?, &opts)
            .await?;
        println!("queued as {id}; waiting for delivery");
        zroad.wait(&id, Duration::from_secs(300)).await?
    } else {
        zroad.call_json(&service, &body, &opts).await?
    };

    println!("HTTP {}", reply.status);
    println!("{}", String::from_utf8_lossy(&reply.body));
    println!("message id: {}", reply.message_id);
    if let (Some(path), Some(proof)) = (&cli.proof_out, &reply.proof) {
        std::fs::write(path, serde_json::to_vec(proof)?)?;
        println!("signed proof written to {}", path.display());
    }
    Ok(())
}
