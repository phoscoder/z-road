use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Z-Road timestamp authority")]
struct Cli {
    /// Directory with key.pem, cert.pem, ca.pem and the serial counter.
    #[arg(long)]
    dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8445")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let h = timestamp_service::spawn(&cli.dir, &cli.listen).await?;
    tracing::info!("timestamp service listening on https://{}", h.addr);
    h.wait().await;
    Ok(())
}
