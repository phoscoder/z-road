//! Periodically anchor the audit log head with a trusted timestamp.

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use zroad_core::audit::AuditEvent;
use zroad_core::msg::TimestampToken;

use crate::state::AppState;

/// Ask the timestamp authority to sign the current log head and record the
/// token in the log. Returns the sequence number of the anchor entry, or `None`
/// if nothing new happened since the last anchor.
pub async fn anchor_once(st: &AppState) -> Result<Option<u64>> {
    let (seq, hash) = st.audit.head();
    if seq == st.last_anchor_seq.load(Ordering::SeqCst) {
        return Ok(None);
    }
    let mut dir = st.dir.snapshot();
    if dir.get_active(&st.cfg.tsa_member).is_none() {
        st.dir.refresh_throttled(Duration::from_secs(2)).await;
        dir = st.dir.snapshot();
    }
    let tsa = dir.get_active(&st.cfg.tsa_member).ok_or_else(|| {
        anyhow!(
            "timestamp authority {} is not an active member",
            st.cfg.tsa_member
        )
    })?;
    let resp = zroad_net::request(
        "POST",
        &format!("{}/v1/timestamp", tsa.endpoint.trim_end_matches('/')),
        &[("content-type", "application/json")],
        Bytes::from(serde_json::to_vec(&serde_json::json!({ "digest": hash }))?),
        Some(&st.identity().tls_client),
        Duration::from_secs(10),
    )
    .await?;
    if resp.status != 200 {
        bail!("timestamp authority returned {}", resp.status);
    }
    let token: TimestampToken = serde_json::from_slice(&resp.body)?;
    if token.digest != hash || token.tsa != st.cfg.tsa_member {
        bail!("timestamp token does not match the request");
    }
    let grace_ms = st.cfg.rotation_grace_secs * 1000;
    let acceptable = |st: &AppState| {
        st.dir
            .snapshot()
            .recent_keys(&st.cfg.tsa_member, zroad_core::now_ms(), grace_ms)
    };
    let mut keys = acceptable(st);
    if !keys.iter().any(|k| token.verify(k).is_ok()) {
        // The authority may have rotated its key since our directory copy.
        st.dir.refresh_throttled(Duration::from_secs(2)).await;
        keys = acceptable(st);
        if !keys.iter().any(|k| token.verify(k).is_ok()) {
            bail!("the timestamp token does not verify with the authority's key");
        }
    }
    let entry = st
        .audit
        .append(AuditEvent::Anchor {
            anchored_seq: seq,
            anchored_hash: hash,
            token,
        })
        .map_err(|e| anyhow!("{e}"))?;
    st.last_anchor_seq.store(entry.seq, Ordering::SeqCst);
    Ok(Some(entry.seq))
}
