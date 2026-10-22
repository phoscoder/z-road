//! A demo "who has looked at my data?" page.
//!
//! The portal never chooses whose record to read. It forwards a signed **citizen
//! identity assertion** (issued by whatever system really logged the person in)
//! to the provider's security server together with its own `portal` token, and the
//! security server answers only for the identifier inside the assertion.
//!
//! In production the assertion arrives with the logged-in citizen: pass it as
//! `?assertion=...` (for example after a redirect from the login system).
//!
//! **Demo only:** with `--demo-idp-key` this program plays the login system
//! itself and issues an assertion for whatever identifier is typed, *without
//! authenticating anyone*. That is exactly what a real deployment must never do.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use clap::Parser;
use serde::Deserialize;
use zroad_core::citizen::{self, Assertion};
use zroad_core::crypto::SoftwareSigner;
use zroad_core::directory::Directory;
use zroad_core::id::MemberId;

#[derive(Parser)]
struct Cli {
    /// Internal URL of the provider's security server.
    #[arg(long, default_value = "http://127.0.0.1:7002")]
    security_server: String,
    /// This portal's token (role `portal`) on that security server (or set
    /// ZROAD_PORTAL_TOKEN).
    #[arg(long, env = "ZROAD_PORTAL_TOKEN")]
    portal_token: String,
    /// The provider this portal is for, e.g. ZW/GOV/ZIMRA (the assertion audience).
    #[arg(long)]
    provider: MemberId,
    /// UNSAFE DEMO: a key file (see `zroad-cli citizen-key`) used to mint
    /// assertions for any identifier typed in, without logging anyone in.
    #[arg(long)]
    demo_idp_key: Option<PathBuf>,
    /// Optional directory.json, used to show organisation names.
    #[arg(long)]
    directory: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:9100")]
    listen: String,
}

struct App {
    ss: String,
    token: String,
    provider: MemberId,
    demo_idp: Option<SoftwareSigner>,
    names: HashMap<String, String>,
}

#[derive(Deserialize)]
struct Params {
    subject: Option<String>,
    assertion: Option<String>,
}

#[derive(Deserialize)]
struct Record {
    time_ms: u64,
    accessed_by: String,
    service: String,
    outcome: String,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Unix milliseconds to `YYYY-MM-DD HH:MM:SS UTC` (civil-from-days algorithm).
fn fmt_utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;margin:0;background:#f6f8f6;color:#14231a}\
main{max-width:760px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px}.sub{color:#5a6b61;margin:0 0 24px}\
.banner{background:#fff3c4;border:1px solid #e6b800;border-radius:10px;padding:10px 14px;margin-bottom:24px;font-size:14px}\
form{display:flex;gap:8px;margin-bottom:24px}input{flex:1;padding:12px;border:1px solid #c9d3cc;border-radius:10px;font-size:16px}\
button{background:#1f7a4d;color:#fff;border:0;border-radius:10px;padding:12px 20px;font-size:16px;cursor:pointer}\
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}\
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid #e6ebe7;font-size:14px}th{background:#e6f2ea}\
.empty{background:#fff;padding:18px;border-radius:10px}.err{color:#a11}";

fn page(body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>\
         <title>Who looked at my data</title><style>{STYLE}</style><main>\
         <h1>Who looked at my data?</h1><p class=sub>Every lookup of your record by another organisation is logged.</p>\
         <div class=banner><b>Demo only.</b> A real portal shows records only for the person the login system vouched for. With the demo key, anyone can enter any identifier.</div>\
         <form method=get action=/><input name=subject placeholder='Your TIN or ID number' autofocus required>\
         <button>Check</button></form>{body}</main></html>"
    ))
}

async fn index(State(app): State<Arc<App>>, Query(p): Query<Params>) -> Html<String> {
    // Where does the proof of who this is come from?
    let (assertion, subject) = match (&p.assertion, &p.subject, &app.demo_idp) {
        (Some(a), _, _) => (a.clone(), String::from("your record")),
        (None, Some(sub), Some(idp)) if !sub.trim().is_empty() => {
            let now = zroad_core::now_ms();
            let a = Assertion {
                v: 1,
                sub: sub.trim().to_string(),
                aud: app.provider.clone(),
                iat_ms: now,
                exp_ms: now + 300_000,
                jti: zroad_core::random_id(),
            };
            match citizen::issue(&a, idp) {
                Ok(t) => (t, sub.trim().to_string()),
                Err(e) => return page(&format!("<p class=err>{}</p>", esc(&e.to_string()))),
            }
        }
        (None, Some(sub), None) if !sub.trim().is_empty() => {
            return page("<p class=err>This portal has no login system attached. A citizen identity assertion is required.</p>");
        }
        _ => return page(""),
    };
    let url = format!("{}/citizen/v1/access-log", app.ss.trim_end_matches('/'));
    let auth = format!("Bearer {}", app.token);
    let resp = zroad_net::request(
        "GET",
        &url,
        &[
            ("authorization", &auth),
            ("z-road-citizen-assertion", &assertion),
        ],
        Bytes::new(),
        None,
        Duration::from_secs(10),
    )
    .await;
    let records: Vec<Record> = match resp {
        Ok(r) if r.status == 200 => serde_json::from_slice(&r.body).unwrap_or_default(),
        Ok(r) if r.status == 401 => {
            return page("<p class=err>The login could not be verified, so nothing is shown.</p>")
        }
        Ok(r) => {
            return page(&format!(
                "<p class=err>The security server answered {}.</p>",
                r.status
            ))
        }
        Err(e) => {
            return page(&format!(
                "<p class=err>Cannot reach the security server: {}</p>",
                esc(&e.to_string())
            ))
        }
    };
    if records.is_empty() {
        return page(&format!(
            "<div class=empty>No organisation has looked up <b>{}</b>.</div>",
            esc(subject.trim())
        ));
    }
    let rows: String = records
        .iter()
        .map(|r| {
            let who = app
                .names
                .get(&r.accessed_by)
                .map(|n| format!("{} ({})", n, r.accessed_by))
                .unwrap_or_else(|| r.accessed_by.clone());
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&fmt_utc(r.time_ms)),
                esc(&who),
                esc(&r.service),
                esc(&r.outcome)
            )
        })
        .collect();
    page(&format!(
        "<p>{} lookup(s) of <b>{}</b>, newest first:</p><table><tr><th>When</th><th>Who</th><th>Service</th><th>Result</th></tr>{rows}</table>",
        records.len(),
        esc(subject.trim())
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let names = match &cli.directory {
        Some(p) => serde_json::from_slice::<Directory>(&std::fs::read(p)?)?
            .members
            .into_iter()
            .map(|m| (m.id.to_string(), m.name))
            .collect(),
        None => HashMap::new(),
    };
    let demo_idp = match &cli.demo_idp_key {
        Some(p) => Some(
            SoftwareSigner::from_pkcs8_pem(&std::fs::read_to_string(p)?)
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
        None => None,
    };
    let app = Arc::new(App {
        ss: cli.security_server,
        token: cli.portal_token,
        provider: cli.provider,
        demo_idp,
        names,
    });
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    println!("citizen portal demo on http://{}", listener.local_addr()?);
    axum::serve(
        listener,
        Router::new().route("/", get(index)).with_state(app),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_utc(1_792_661_225_671), "2026-10-22 09:27:05 UTC");
        assert_eq!(fmt_utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
    }

    #[test]
    fn escaping() {
        assert_eq!(esc("<b>\"x\"&'"), "&lt;b&gt;&quot;x&quot;&amp;&#39;");
    }
}
