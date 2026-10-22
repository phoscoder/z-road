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
    /// Central server URL. When set, the service renews its own certificate
    /// before it expires, without a restart.
    #[arg(long)]
    central: Option<String>,
    #[arg(long, default_value_t = 30)]
    renew_before_days: i64,
    /// Seconds to keep signing with the old key after a renewal.
    #[arg(long, default_value_t = 65)]
    activation_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let h = timestamp_service::spawn_with(
        &cli.dir,
        &cli.listen,
        timestamp_service::Options {
            central_url: cli.central,
            renew_before_days: cli.renew_before_days,
            activation_delay: std::time::Duration::from_secs(cli.activation_secs),
            ..Default::default()
        },
    )
    .await?;
    tracing::info!("timestamp service listening on https://{}", h.addr);
    h.wait().await;
    Ok(())
}
