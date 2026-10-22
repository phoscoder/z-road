//! Background jobs: directory refresh, outbox delivery, log anchoring.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use zroad_core::msg::{b64_decode, b64_encode};
use zroad_core::now_ms;

use crate::consumer::{self, CallParams};
use crate::outbox::{backoff_ms, OutboxItem, OutboxResult};
use crate::state::AppState;

pub async fn directory_loop(st: Arc<AppState>) {
    let every = Duration::from_secs(st.cfg.directory_refresh_secs.max(1));
    loop {
        tokio::time::sleep(every).await;
        if let Err(e) = st.dir.refresh().await {
            tracing::warn!("directory refresh failed (using cached copy): {e}");
        }
    }
}

pub async fn anchor_loop(st: Arc<AppState>) {
    if st.cfg.anchor_interval_secs == 0 {
        return;
    }
    let every = Duration::from_secs(st.cfg.anchor_interval_secs);
    loop {
        tokio::time::sleep(every).await;
        if let Err(e) = crate::anchor::anchor_once(&st).await {
            tracing::warn!("could not anchor the audit log (will retry): {e}");
        }
    }
}

/// At most this many outbox items are in flight at once.
const OUTBOX_CONCURRENCY: usize = 16;

pub async fn outbox_loop(st: Arc<AppState>) {
    let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        for item in st.outbox.due() {
            {
                let mut set = in_flight.lock().unwrap_or_else(|p| p.into_inner());
                if set.len() >= OUTBOX_CONCURRENCY || !set.insert(item.id.clone()) {
                    continue;
                }
            }
            let (st, in_flight) = (st.clone(), in_flight.clone());
            tokio::spawn(async move {
                let id = item.id.clone();
                deliver(&st, item).await;
                in_flight
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
            });
        }
    }
}

async fn deliver(st: &AppState, mut item: OutboxItem) {
    let parsed = (
        item.client.parse(),
        item.service.parse(),
        b64_decode(&item.body_b64),
    );
    let (Ok(client), Ok(service), Ok(body)) = parsed else {
        finish(st, &item, failed(&item, None, "corrupt outbox item".into()));
        return;
    };
    let params = CallParams {
        client,
        service,
        body: Bytes::from(body),
        content_type: item.content_type.clone(),
        subject: item.subject.clone(),
        message_id: Some(item.id.clone()),
    };
    match consumer::call(st, &params).await {
        Ok(ok) => {
            let result = OutboxResult {
                id: item.id.clone(),
                state: "delivered".into(),
                status: Some(ok.status),
                body_b64: Some(b64_encode(&ok.body)),
                content_type: Some(ok.content_type),
                error: None,
                finished_ms: now_ms(),
            };
            finish(st, &item, result);
        }
        Err(e) if e.retryable() && item.attempts + 1 < st.cfg.outbox_max_attempts => {
            item.attempts += 1;
            item.next_attempt_ms = now_ms() + backoff_ms(item.attempts);
            item.last_error = Some(format!("{}: {}", e.code(), e.message()));
            if let Err(err) = st.outbox.put(&item) {
                tracing::error!("cannot update outbox item: {err}");
            }
        }
        Err(e) => {
            let status = match &e {
                consumer::CallError::Remote { status, .. } => Some(*status),
                _ => None,
            };
            finish(
                st,
                &item,
                failed(&item, status, format!("{}: {}", e.code(), e.message())),
            );
        }
    }
}

fn failed(item: &OutboxItem, status: Option<u16>, error: String) -> OutboxResult {
    OutboxResult {
        id: item.id.clone(),
        state: "failed".into(),
        status,
        body_b64: None,
        content_type: None,
        error: Some(error),
        finished_ms: now_ms(),
    }
}

fn finish(st: &AppState, item: &OutboxItem, result: OutboxResult) {
    if let Err(e) = st.outbox.finish(item, &result) {
        tracing::error!("cannot record outbox result: {e}");
    }
}
