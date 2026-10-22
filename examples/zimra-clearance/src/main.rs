//! A mock ZIMRA tax clearance system. In a real deployment this would be
//! ZIMRA's own application sitting behind its Z-Road security server. It only
//! answers the narrow question "is this TIN cleared?" and never returns
//! turnover or tax history.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:9001")]
    listen: String,
}

#[derive(Deserialize)]
struct Query {
    tin: String,
}

#[derive(Serialize, Clone)]
struct Clearance {
    tin: String,
    name: String,
    status: &'static str,
    valid_until: Option<&'static str>,
}

type Db = Arc<HashMap<&'static str, Clearance>>;

fn sample() -> Db {
    let rows = [
        (
            "2000123456",
            "Supplier (Pvt) Ltd",
            "VALID",
            Some("2026-12-31"),
        ),
        (
            "2000987654",
            "Late Filer Trading",
            "EXPIRED",
            Some("2025-06-30"),
        ),
        ("2000555111", "Revoked Holdings", "REVOKED", None),
    ];
    Arc::new(
        rows.into_iter()
            .map(|(tin, name, status, valid_until)| {
                (
                    tin,
                    Clearance {
                        tin: tin.into(),
                        name: name.into(),
                        status,
                        valid_until,
                    },
                )
            })
            .collect(),
    )
}

async fn verify(
    State(db): State<Db>,
    headers: HeaderMap,
    Json(q): Json<Query>,
) -> (StatusCode, Json<serde_json::Value>) {
    // The security server tells us who is asking; a real system could log or
    // further restrict on this.
    let who = headers
        .get("x-zroad-client")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    println!("clearance query for {} from {who}", q.tin);
    match db.get(q.tin.as_str()) {
        Some(c) => (
            StatusCode::OK,
            Json(serde_json::to_value(c).unwrap_or_default()),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "tin": q.tin, "status": "NOT_FOUND" })),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let app = Router::new()
        .route("/verify", post(verify))
        .with_state(sample());
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    println!(
        "mock ZIMRA clearance service on http://{}",
        listener.local_addr()?
    );
    axum::serve(listener, app).await?;
    Ok(())
}
