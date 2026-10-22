//! Publish this member's services to the central catalogue.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use zroad_net::api::{CatalogueItem, PublishCatalogueRequest};
use zroad_net::central_client::CentralClient;

use crate::state::AppState;

/// Replace this member's catalogue entries with the services in the config.
pub async fn publish(st: &AppState) -> Result<usize> {
    let services: Vec<CatalogueItem> = st
        .cfg
        .services
        .iter()
        .map(|s| CatalogueItem {
            id: s.id.clone(),
            title: s.title.clone().unwrap_or_else(|| s.id.clone()),
            description: s.description.clone().unwrap_or_default(),
            request_schema: st
                .schemas
                .get(&s.id)
                .and_then(|x| x.request.as_ref())
                .map(|(v, _)| v.clone()),
            response_schema: st
                .schemas
                .get(&s.id)
                .and_then(|x| x.response.as_ref())
                .map(|(v, _)| v.clone()),
        })
        .collect();
    let n = services.len();
    CentralClient::from_tls(&st.cfg.central_url, st.identity().tls_client.clone())
        .publish_catalogue(&PublishCatalogueRequest { services })
        .await
        .context("publishing the service catalogue")?;
    Ok(n)
}

/// Publish at startup and then hourly, so the catalogue follows the config and
/// heals after central server outages.
pub async fn publish_loop(st: Arc<AppState>) {
    loop {
        let wait = match publish(&st).await {
            Ok(_) => 3600,
            Err(e) => {
                tracing::warn!("could not publish the catalogue (will retry): {e:#}");
                30
            }
        };
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}
