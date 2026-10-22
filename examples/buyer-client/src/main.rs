//! A tiny consumer: asks ZIMRA, through this company's own security server,
//! whether a supplier's tax clearance is valid, and saves the signed proof.

use std::path::PathBuf;

use anyhow::{bail, Result};
use bytes::Bytes;
use clap::Parser;
use zroad_core::msg::b64_decode;

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
    let url = format!(
        "{}/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1",
        cli.security_server.trim_end_matches('/')
    );
    let body = serde_json::to_vec(&serde_json::json!({ "tin": cli.tin }))?;
    let mut headers = vec![
        ("content-type", "application/json".to_string()),
        ("z-road-client", cli.client.clone()),
        ("z-road-subject", cli.tin.clone()),
    ];
    if cli.async_mode {
        headers.push(("z-road-mode", "async".into()));
    }
    let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let resp = zroad_net::request(
        "POST",
        &url,
        &h,
        Bytes::from(body),
        None,
        std::time::Duration::from_secs(30),
    )
    .await?;

    println!("HTTP {}", resp.status);
    println!("{}", String::from_utf8_lossy(&resp.body));
    if let Some(id) = resp.headers.get("z-road-message-id") {
        println!("message id: {}", id.to_str().unwrap_or("?"));
    }
    if let (Some(path), Some(proof)) = (&cli.proof_out, resp.headers.get("z-road-proof")) {
        std::fs::write(
            path,
            b64_decode(proof.to_str()?).map_err(|e| anyhow::anyhow!("{e}"))?,
        )?;
        println!("signed proof written to {}", path.display());
    }
    if resp.status / 100 != 2 && resp.status != 404 {
        bail!("request failed");
    }
    Ok(())
}
