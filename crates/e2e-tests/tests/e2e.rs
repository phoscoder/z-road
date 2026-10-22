//! End-to-end tests: a whole Z-Road network (central server, timestamp
//! authority, two or three security servers and a mock ZIMRA system) running in
//! one process over real mutual-TLS connections.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use bytes::Bytes;
use security_server::{Config, Running};
use serde_json::{json, Value};
use zroad_core::audit;
use zroad_core::crypto::{sha256_hex, Signer, SoftwareSigner};
use zroad_core::id::MemberId;
use zroad_core::msg::*;
use zroad_core::{now_ms, pki, random_id};
use zroad_net::central_client::{enroll_to_dir, CentralClient};
use zroad_net::server::ServerHandle;
use zroad_net::tls;

const ADMIN: &str = "admin-token-1234567890";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Net {
    tmp: tempfile::TempDir,
    central: Option<ServerHandle>,
    central_url: String,
    ca_pem: String,
    admin_token: String,
    upstream_calls: Arc<AtomicUsize>,
    upstream_url: String,
    _tsa: Option<ServerHandle>,
}

struct Member {
    id: &'static str,
    net_port: u16,
    int_port: u16,
    dir: PathBuf,
}

impl Member {
    fn internal(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.int_port)
    }
    fn endpoint(&self) -> String {
        format!("https://127.0.0.1:{}", self.net_port)
    }
}

async fn upstream() -> (String, Arc<AtomicUsize>) {
    async fn verify(State(n): State<Arc<AtomicUsize>>, Json(q): Json<Value>) -> Json<Value> {
        n.fetch_add(1, Ordering::SeqCst);
        let tin = q["tin"].as_str().unwrap_or("");
        let status = if tin == "2000123456" {
            "VALID"
        } else {
            "NOT_FOUND"
        };
        Json(json!({ "tin": tin, "status": status }))
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/verify", post(verify))
        .with_state(calls.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/verify", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, calls)
}

impl Net {
    async fn start() -> Net {
        let tmp = tempfile::tempdir().unwrap();
        let cdir = tmp.path().join("central");
        central_server::init(&cdir, &["127.0.0.1".to_string()]).unwrap();
        let central = central_server::spawn(&cdir, "127.0.0.1:0").await.unwrap();
        let central_url = format!("https://{}", central.addr);
        let ca_pem = std::fs::read_to_string(cdir.join("ca.pem")).unwrap();
        let admin_token = std::fs::read_to_string(cdir.join("admin_token"))
            .unwrap()
            .trim()
            .to_string();

        let (upstream_url, upstream_calls) = upstream().await;
        let mut net = Net {
            tmp,
            central: Some(central),
            central_url,
            ca_pem,
            admin_token,
            upstream_calls,
            upstream_url,
            _tsa: None,
        };
        // timestamp authority
        let port = free_port();
        let dir = net.tmp.path().join("tsa");
        net.register("ZW/SYS/tsa", &format!("https://127.0.0.1:{port}"), &dir)
            .await;
        net._tsa = Some(
            timestamp_service::spawn(&dir, &format!("127.0.0.1:{port}"))
                .await
                .unwrap(),
        );
        net
    }

    /// Register and enrol a member; returns its data directory.
    async fn register(&self, id: &str, endpoint: &str, dir: &Path) {
        let c = CentralClient::new(&self.central_url, &self.ca_pem).unwrap();
        let mid: MemberId = id.parse().unwrap();
        let r = c
            .add_member(&self.admin_token, &mid, id, endpoint)
            .await
            .unwrap();
        enroll_to_dir(
            &self.central_url,
            &self.ca_pem,
            &mid,
            &r.enrollment_token,
            &["127.0.0.1".into()],
            dir,
        )
        .await
        .unwrap();
    }

    async fn member(&self, id: &'static str) -> Member {
        let m = Member {
            id,
            net_port: free_port(),
            int_port: free_port(),
            dir: self.tmp.path().join(id.replace('/', "_")),
        };
        self.register(id, &m.endpoint(), &m.dir).await;
        m
    }

    fn config(&self, m: &Member, provides: bool) -> Config {
        self.config_with(
            m,
            provides,
            ADMIN,
            &["ZW/COM/12345678", "ZW/COM/55555555/accounts"],
        )
    }

    fn config_with(&self, m: &Member, provides: bool, admin: &str, allow: &[&str]) -> Config {
        let services = if provides {
            json!([{ "id": "tax-clearance/verify/v1", "upstream": self.upstream_url,
                "title": "Tax clearance check", "description": "Is this TIN cleared? Returns status and expiry only." }])
        } else {
            json!([])
        };
        let access = if provides {
            json!([{ "service": "tax-clearance/verify/v1", "allow": allow }])
        } else {
            json!([])
        };
        serde_json::from_value(json!({
            "member_id": m.id,
            "data_dir": m.dir,
            "central_url": self.central_url,
            "network_listen": format!("127.0.0.1:{}", m.net_port),
            "internal_listen": format!("127.0.0.1:{}", m.int_port),
            "admin_token": admin,
            "directory_refresh_secs": 1,
            "anchor_interval_secs": 0,
            "services": services,
            "access": access,
        }))
        .unwrap()
    }

    async fn run(&self, m: &Member, provides: bool) -> Running {
        security_server::spawn(self.config(m, provides))
            .await
            .unwrap()
    }
}

async fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    body: &Value,
) -> (u16, Value, http::HeaderMap) {
    let mut h = vec![("content-type", "application/json")];
    h.extend_from_slice(headers);
    let r = zroad_net::request(
        "POST",
        url,
        &h,
        Bytes::from(body.to_string()),
        None,
        Duration::from_secs(20),
    )
    .await
    .unwrap();
    let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    (r.status, v, r.headers)
}

async fn get_json(url: &str, headers: &[(&str, &str)]) -> (u16, Value) {
    let r = zroad_net::request(
        "GET",
        url,
        headers,
        Bytes::new(),
        None,
        Duration::from_secs(20),
    )
    .await
    .unwrap();
    (
        r.status,
        serde_json::from_slice(&r.body).unwrap_or(Value::Null),
    )
}

const SERVICE_PATH: &str = "/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1";

async fn clearance(m: &Member, client: &str, tin: &str) -> (u16, Value, http::HeaderMap) {
    post_json(
        &m.internal(SERVICE_PATH),
        &[("z-road-client", client), ("z-road-subject", tin)],
        &json!({ "tin": tin }),
    )
    .await
}

fn read_proof(h: &http::HeaderMap) -> Proof {
    let raw = b64_decode(
        h.get("z-road-proof")
            .expect("proof header")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

fn member_key(dir: &Path, id: &str) -> Vec<u8> {
    let d: zroad_core::directory::Directory =
        serde_json::from_slice(&std::fs::read(dir.join("directory.json")).unwrap()).unwrap();
    let rec = d.get(&id.parse().unwrap()).unwrap();
    pki::inspect_cert_pem(rec.cert_pem.as_ref().unwrap())
        .unwrap()
        .public_key
}

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_proof_audit_and_citizen_access_log() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let _z = net.run(&zimra, true).await;
    let _b = net.run(&buyer, false).await;

    let (status, body, headers) =
        clearance(&buyer, "ZW/COM/12345678/accounts-payable", "2000123456").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "VALID");
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 1);

    // The signed proof verifies offline against the directory.
    let proof = read_proof(&headers);
    let (req, res) = verify_proof(
        &proof,
        &member_key(&buyer.dir, "ZW/COM/12345678"),
        &member_key(&buyer.dir, "ZW/GOV/ZIMRA"),
    )
    .unwrap();
    assert_eq!(req.client.to_string(), "ZW/COM/12345678/accounts-payable");
    assert_eq!(res.status, 200);

    // Tampering with the proven answer is detected.
    let mut forged = proof.clone();
    forged.response_body_b64 = b64_encode(br#"{"status":"VALID","tin":"9999999999"}"#);
    assert!(verify_proof(
        &forged,
        &member_key(&buyer.dir, "ZW/COM/12345678"),
        &member_key(&buyer.dir, "ZW/GOV/ZIMRA")
    )
    .is_err());
    // ... and so is checking it against the wrong party's key.
    assert!(verify_proof(
        &proof,
        &member_key(&buyer.dir, "ZW/GOV/ZIMRA"),
        &member_key(&buyer.dir, "ZW/GOV/ZIMRA")
    )
    .is_err());

    // Both sides logged the exchange and both logs verify.
    for m in [&zimra, &buyer] {
        let r = audit::verify_file(&m.dir.join("audit/log.jsonl")).unwrap();
        assert!(r.entries >= 2);
    }

    // The data subject can see who looked at their record, without the log ever
    // containing the raw TIN.
    let (s, log) = get_json(
        &zimra.internal("/admin/v1/access-log?subject=2000123456"),
        &[("authorization", &format!("Bearer {ADMIN}"))],
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(log.as_array().unwrap().len(), 1);
    assert_eq!(log[0]["accessed_by"], "ZW/COM/12345678");
    assert!(!std::fs::read_to_string(zimra.dir.join("audit/log.jsonl"))
        .unwrap()
        .contains("2000123456"));
    let (s, none) = get_json(
        &zimra.internal("/admin/v1/access-log?subject=0000000000"),
        &[("authorization", &format!("Bearer {ADMIN}"))],
    )
    .await;
    assert_eq!((s, none.as_array().unwrap().len()), (200, 0));
    // admin endpoints need the token
    let (s, _) = get_json(
        &zimra.internal("/admin/v1/access-log?subject=2000123456"),
        &[],
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn access_control_and_bad_requests() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let stranger = net.member("ZW/COM/77777777").await;
    let _z = net.run(&zimra, true).await;
    let _b = net.run(&buyer, false).await;
    let _s = net.run(&stranger, false).await;

    // A member that is on the network but not on ZIMRA's allow-list is refused.
    let (status, body, headers) =
        clearance(&stranger, "ZW/COM/77777777/accounts", "2000123456").await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "access_denied");
    assert!(headers.get("z-road-error").is_some());
    assert_eq!(
        net.upstream_calls.load(Ordering::SeqCst),
        0,
        "denied requests never reach the internal system"
    );

    // A consumer cannot claim to be someone else's subsystem.
    let (s, b, _) = clearance(&buyer, "ZW/COM/77777777/accounts", "2000123456").await;
    assert_eq!((s, b["error"].as_str().unwrap()), (400, "invalid_request"));

    // Unknown service on a known provider, and unknown provider.
    let (s, b, _) = post_json(
        &buyer.internal("/r1/ZW/GOV/ZIMRA/tax-clearance/nothing/v1"),
        &[("z-road-client", "ZW/COM/12345678/ap")],
        &json!({}),
    )
    .await;
    assert_eq!((s, b["error"].as_str().unwrap()), (404, "unknown_service"));
    let (s, b, _) = post_json(
        &buyer.internal("/r1/ZW/GOV/GHOST/x/y/v1"),
        &[("z-road-client", "ZW/COM/12345678/ap")],
        &json!({}),
    )
    .await;
    assert_eq!((s, b["error"].as_str().unwrap()), (404, "unknown_provider"));

    // Missing client header and a malformed path.
    let (s, _, _) = post_json(&buyer.internal(SERVICE_PATH), &[], &json!({})).await;
    assert_eq!(s, 400);
    let (s, _, _) = post_json(
        &buyer.internal("/r1/ZW/GOV"),
        &[("z-road-client", "ZW/COM/12345678/ap")],
        &json!({}),
    )
    .await;
    assert_eq!(s, 400);

    // Upstream answers (even "not found") are passed through and signed.
    let (s, b, h) = clearance(&buyer, "ZW/COM/12345678/ap", "2000000000").await;
    assert_eq!((s, b["status"].as_str().unwrap()), (200, "NOT_FOUND"));
    assert!(h.get("z-road-proof").is_some());
}

/// Talk to a provider's network port directly with a hand-built message, as a
/// malicious or buggy member would.
struct RawClient {
    tls: Arc<rustls::ClientConfig>,
    signer: SoftwareSigner,
    url: String,
    member: MemberId,
}

impl RawClient {
    fn new(from: &Member, to: &Member) -> Self {
        let read = |f: &str| std::fs::read_to_string(from.dir.join(f)).unwrap();
        let (key, cert, ca) = (read("key.pem"), read("cert.pem"), read("ca.pem"));
        Self {
            tls: tls::client_config(&ca, Some((&cert, &key))).unwrap(),
            signer: SoftwareSigner::from_pkcs8_pem(&key).unwrap(),
            url: format!("{}/zroad/v1/exchange", to.endpoint()),
            member: from.id.parse().unwrap(),
        }
    }

    fn envelope(&self, message_id: &str, body: &[u8]) -> RequestEnvelope {
        RequestEnvelope {
            version: PROTOCOL_VERSION,
            message_id: message_id.into(),
            client: format!("{}/accounts-payable", self.member).parse().unwrap(),
            service: "ZW/GOV/ZIMRA/tax-clearance/verify/v1".parse().unwrap(),
            issued_at_ms: now_ms(),
            body_sha256: sha256_hex(body),
            content_type: "application/json".into(),
            subject: None,
        }
    }

    async fn send(
        &self,
        env: &RequestEnvelope,
        body: &[u8],
        signer: Option<&dyn Signer>,
    ) -> (u16, Value) {
        let signed =
            SignedMessage::sign(REQUEST_DOMAIN, env, signer.unwrap_or(&self.signer)).unwrap();
        self.send_signed(signed, body).await
    }

    async fn send_signed(&self, signed: SignedMessage, body: &[u8]) -> (u16, Value) {
        let wire = ExchangeRequest {
            request: signed,
            body_b64: b64_encode(body),
        };
        let r = zroad_net::request(
            "POST",
            &self.url,
            &[("content-type", "application/json")],
            Bytes::from(serde_json::to_vec(&wire).unwrap()),
            Some(&self.tls),
            Duration::from_secs(20),
        )
        .await
        .unwrap();
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn protocol_attacks_are_rejected() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let _z = net.run(&zimra, true).await;
    let raw = RawClient::new(&buyer, &zimra);
    let body = br#"{"tin":"2000123456"}"#;

    // Baseline: a correctly formed message is accepted.
    let env = raw.envelope(&random_id(), body);
    let (s, v) = raw.send(&env, body, None).await;
    assert_eq!(s, 200, "{v}");

    // Body swapped after signing.
    let env = raw.envelope(&random_id(), body);
    let (s, v) = raw.send(&env, br#"{"tin":"2000999999"}"#, None).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (400, "body_mismatch"));

    // Signed by a key that is not the member's certificate key.
    let rogue = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let rogue = SoftwareSigner::from_pkcs8_pem(&rogue.serialize_pem()).unwrap();
    let env = raw.envelope(&random_id(), body);
    let (s, v) = raw.send(&env, body, Some(&rogue)).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (400, "bad_signature"));

    // Payload altered after signing.
    let env = raw.envelope(&random_id(), body);
    let mut signed = SignedMessage::sign(REQUEST_DOMAIN, &env, &raw.signer).unwrap();
    let mut payload = signed.payload().unwrap();
    payload[10] ^= 1;
    signed.payload_b64 = b64_encode(&payload);
    let (s, _) = raw.send_signed(signed, body).await;
    assert_eq!(s, 400);

    // Stale timestamp.
    let mut env = raw.envelope(&random_id(), body);
    env.issued_at_ms -= MAX_CLOCK_SKEW_MS + 60_000;
    let (s, v) = raw.send(&env, body, None).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (400, "stale_request"));

    // Claiming a client that belongs to a different member.
    let mut env = raw.envelope(&random_id(), body);
    env.client = "ZW/COM/55555555/accounts".parse().unwrap();
    let (s, v) = raw.send(&env, body, None).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (403, "client_mismatch"));

    // Addressing a different provider.
    let mut env = raw.envelope(&random_id(), body);
    env.service = "ZW/GOV/OTHER/tax-clearance/verify/v1".parse().unwrap();
    let (s, v) = raw.send(&env, body, None).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (400, "wrong_provider"));

    // Replay protection: the same message id is idempotent for identical
    // content and refused for different content.
    let before = net.upstream_calls.load(Ordering::SeqCst);
    let id = random_id();
    let env = raw.envelope(&id, body);
    assert_eq!(raw.send(&env, body, None).await.0, 200);
    assert_eq!(
        raw.send(&env, body, None).await.0,
        200,
        "retry of the same message is idempotent"
    );
    assert_eq!(
        net.upstream_calls.load(Ordering::SeqCst),
        before + 1,
        "duplicate did not reach the internal system twice"
    );
    let other = br#"{"tin":"2000123457"}"#;
    let env2 = raw.envelope(&id, other);
    let (s, v) = raw.send(&env2, other, None).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (409, "replay"));

    // No client certificate at all: the TLS handshake itself fails.
    let no_cert = tls::client_config(
        &std::fs::read_to_string(buyer.dir.join("ca.pem")).unwrap(),
        None,
    )
    .unwrap();
    let r = zroad_net::request(
        "POST",
        &raw.url,
        &[],
        Bytes::from("{}"),
        Some(&no_cert),
        Duration::from_secs(10),
    )
    .await;
    assert!(r.is_err() || r.as_ref().map(|x| x.status != 200).unwrap_or(false));

    // Rejections are in the provider's audit log too.
    let entries = audit::read_entries(&zimra.dir.join("audit/log.jsonl")).unwrap();
    let outcomes: Vec<String> = entries
        .iter()
        .filter_map(|e| match &e.event {
            audit::AuditEvent::Exchange { outcome, .. } => Some(outcome.clone()),
            _ => None,
        })
        .collect();
    for want in [
        "denied:body_mismatch",
        "denied:bad_signature",
        "denied:stale_request",
        "denied:replay",
        "duplicate",
    ] {
        assert!(
            outcomes.iter().any(|o| o == want),
            "missing {want} in {outcomes:?}"
        );
    }
    audit::verify_file(&zimra.dir.join("audit/log.jsonl")).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_members_are_cut_off() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let _z = net.run(&zimra, true).await;
    let _b = net.run(&buyer, false).await;

    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200
    );

    let c = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();
    c.revoke(&net.admin_token, &"ZW/COM/12345678".parse().unwrap())
        .await
        .unwrap();
    // directories refresh every second in the test config
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let (s, b, _) = clearance(&buyer, "ZW/COM/12345678/ap", "2000123456").await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (403, "member_not_active"),
        "{b}"
    );
    // revocation is final: the member cannot be re-registered
    assert!(c
        .add_member(
            &net.admin_token,
            &"ZW/COM/12345678".parse().unwrap(),
            "x",
            "https://127.0.0.1:1"
        )
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn async_requests_survive_a_provider_outage() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let _b = net.run(&buyer, false).await; // ZIMRA is enrolled but its server is down

    // Synchronous calls fail fast and say so.
    let (s, b, h) = clearance(&buyer, "ZW/COM/12345678/ap", "2000123456").await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (503, "provider_unreachable")
    );
    assert!(h.get("retry-after").is_some());

    // Async calls are accepted and queued on disk.
    let (s, q, _) = post_json(
        &buyer.internal(SERVICE_PATH),
        &[
            ("z-road-client", "ZW/COM/12345678/ap"),
            ("z-road-mode", "async"),
            ("z-road-subject", "2000123456"),
        ],
        &json!({ "tin": "2000123456" }),
    )
    .await;
    assert_eq!(s, 202);
    let id = q["message_id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (_, st) = get_json(&buyer.internal(&format!("/internal/v1/outbox/{id}")), &[]).await;
    assert_eq!(st["state"], "pending");
    assert!(st["item"]["attempts"].as_u64().unwrap() >= 1);

    // The provider comes back; the queued request is delivered by itself.
    let _z = net.run(&zimra, true).await;
    let mut delivered = Value::Null;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (_, st) = get_json(&buyer.internal(&format!("/internal/v1/outbox/{id}")), &[]).await;
        if st["state"] == "finished" {
            delivered = st;
            break;
        }
    }
    assert_eq!(delivered["result"]["state"], "delivered", "{delivered}");
    let body = b64_decode(delivered["result"]["body_b64"].as_str().unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["status"],
        "VALID"
    );
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_working_when_the_central_server_is_down_and_anchors_the_log() {
    let mut net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let z = net.run(&zimra, true).await;
    let b = net.run(&buyer, false).await;
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200
    );

    // Take the central server down.
    net.central.take().unwrap().shutdown();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200,
        "cached directory keeps traffic flowing"
    );

    // A restarted security server also comes up from its cached directory.
    b.shutdown();
    z.shutdown();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _z = net.run(&zimra, true).await;
    let _b = net.run(&buyer, false).await;
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200
    );

    // Anchor the provider's log with a trusted timestamp.
    let auth = format!("Bearer {ADMIN}");
    let r = zroad_net::request(
        "POST",
        &zimra.internal("/admin/v1/anchor"),
        &[("authorization", &auth)],
        Bytes::new(),
        None,
        Duration::from_secs(20),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let report = audit::verify_file(&zimra.dir.join("audit/log.jsonl")).unwrap();
    assert_eq!(report.anchors.len(), 1);
    let tsa_key = member_key(&zimra.dir, "ZW/SYS/tsa");
    report.anchors[0].1.verify(&tsa_key).unwrap();
    // nothing new since: a second anchor is a no-op
    let r = zroad_net::request(
        "POST",
        &zimra.internal("/admin/v1/anchor"),
        &[("authorization", &auth)],
        Bytes::new(),
        None,
        Duration::from_secs(20),
    )
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&r.body).contains("nothing new"));

    // The audit status endpoint agrees.
    let (_, st) = get_json(
        &zimra.internal("/admin/v1/audit/status"),
        &[("authorization", &auth)],
    )
    .await;
    assert_eq!(st["verified"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_window_survives_a_provider_restart() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let z = net.run(&zimra, true).await;
    let raw = RawClient::new(&buyer, &zimra);
    let body = br#"{"tin":"2000123456"}"#;

    let id = random_id();
    let env = raw.envelope(&id, body);
    assert_eq!(raw.send(&env, body, None).await.0, 200);
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 1);

    // After a restart the provider rebuilds its replay cache from the audit log.
    z.shutdown();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _z = net.run(&zimra, true).await;
    let env = raw.envelope(&id, body); // fresh timestamp, same message id
    let (s, v) = raw.send(&env, body, None).await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (409, "already_processed")
    );
    assert_eq!(
        net.upstream_calls.load(Ordering::SeqCst),
        1,
        "the internal system was not called again"
    );
    // a new message id still works
    assert_eq!(
        raw.send(&raw.envelope(&random_id(), body), body, None)
            .await
            .0,
        200
    );

    // The identity endpoint reports the certificate's remaining life.
    let (s, who) = get_json(
        &zimra.internal("/admin/v1/identity"),
        &[("authorization", &format!("Bearer {ADMIN}"))],
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(who["member"], "ZW/GOV/ZIMRA");
    assert!(who["certificate_days_left"].as_i64().unwrap() > 300);
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_renewal_retires_the_old_identity() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let _z = net.run(&zimra, true).await;
    let b = net.run(&buyer, false).await;
    let old_identity = RawClient::new(&buyer, &zimra);
    let body = br#"{"tin":"2000123456"}"#;
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200
    );
    assert_eq!(
        old_identity
            .send(&old_identity.envelope(&random_id(), body), body, None)
            .await
            .0,
        200
    );

    // Renewal needs the current certificate: an anonymous caller is refused.
    let anon = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();
    let csr =
        pki::generate_identity(&"ZW/COM/12345678".parse().unwrap(), &["127.0.0.1".into()]).unwrap();
    assert!(anon
        .renew(&zroad_net::api::RenewRequest {
            csr_pem: csr.csr_pem
        })
        .await
        .is_err());

    // Renew with the current certificate, then restart the security server.
    let id = zroad_net::central_client::renew_in_dir(
        &net.central_url,
        &buyer.dir,
        &["127.0.0.1".into()],
    )
    .await
    .unwrap();
    assert_eq!(id.to_string(), "ZW/COM/12345678");
    b.shutdown();
    tokio::time::sleep(Duration::from_millis(2500)).await; // let ZIMRA's directory pick up the new certificate
    let _b = net.run(&buyer, false).await;
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200,
        "new identity works"
    );

    // The previous key pair, though still signed by the CA, is no longer accepted.
    let (s, v) = old_identity
        .send(&old_identity.envelope(&random_id(), body), body, None)
        .await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (403, "member_not_active")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_without_restart() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let _z = net.run(&zimra, true).await;
    let _b = net.run(&buyer, false).await;
    let old = RawClient::new(&buyer, &zimra);
    let body = br#"{"tin":"2000123456"}"#;
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200
    );
    let fp_before = {
        let (_, who) = get_json(
            &buyer.internal("/admin/v1/identity"),
            &[("authorization", &format!("Bearer {ADMIN}"))],
        )
        .await;
        who["certificate_fingerprint"].as_str().unwrap().to_string()
    };

    // Renew the consumer and then the provider, both live.
    let auth = format!("Bearer {ADMIN}");
    for m in [&buyer, &zimra] {
        let r = zroad_net::request(
            "POST",
            &m.internal("/admin/v1/renew"),
            &[("authorization", &auth)],
            Bytes::new(),
            None,
            Duration::from_secs(20),
        )
        .await
        .unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
    let (_, who) = get_json(
        &buyer.internal("/admin/v1/identity"),
        &[("authorization", &auth)],
    )
    .await;
    assert_ne!(who["certificate_fingerprint"].as_str().unwrap(), fp_before);
    assert!(buyer.dir.join("cert.pem.prev").exists());

    // Traffic keeps flowing with the new certificates on both sides.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200
    );
    // The retired key is refused.
    let (s, v) = old
        .send(&old.envelope(&random_id(), body), body, None)
        .await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (403, "member_not_active")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn shared_node_hosts_several_members_in_isolation() {
    let net = Net::start().await;
    let (net_port, int_port) = (free_port(), free_port());
    let mk = |id: &'static str| Member {
        id,
        net_port,
        int_port,
        dir: net.tmp.path().join(id.replace('/', "_")),
    };
    let zimra = mk("ZW/GOV/ZIMRA");
    let a = mk("ZW/COM/11111111");
    let b = mk("ZW/COM/22222222");
    for m in [&zimra, &a, &b] {
        net.register(m.id, &m.endpoint(), &m.dir).await;
    }
    let standalone = net.member("ZW/COM/33333333").await;

    let (tok_z, tok_a, tok_b) = (
        "admin-token-zimra-0123",
        "admin-token-a-0123456789",
        "admin-token-b-0123456789",
    );
    let node = security_server::config::NodeConfig {
        members: vec![
            net.config_with(&zimra, true, tok_z, &["ZW/COM/11111111", "ZW/COM/33333333"]),
            net.config_with(&a, false, tok_a, &[]),
            net.config_with(&b, false, tok_b, &[]),
        ],
        node_dir: net.tmp.path().join("node"),
    };
    let running = security_server::spawn_node(node).await.unwrap();
    assert_eq!(running.members.len(), 3);
    let mut cfg = net.config(&standalone, false);
    cfg.admin_token = "admin-token-standalone-0123".into();
    let _s = security_server::spawn(cfg).await.unwrap();

    let prefixed = |m: &Member, rest: &str| m.internal(&format!("/m/{}{rest}", m.id));

    // Two members of the same node, and a stand-alone member, all reach ZIMRA.
    let (s, body, _) = post_json(
        &prefixed(&a, SERVICE_PATH),
        &[
            ("z-road-client", "ZW/COM/11111111/ap"),
            ("z-road-subject", "2000123456"),
        ],
        &json!({ "tin": "2000123456" }),
    )
    .await;
    assert_eq!((s, body["status"].as_str().unwrap()), (200, "VALID"));
    assert_eq!(
        clearance(&standalone, "ZW/COM/33333333/ap", "2000123456")
            .await
            .0,
        200
    );

    // ZIMRA's allow-list applies per member, even on the same node.
    let (s, body, _) = post_json(
        &prefixed(&b, SERVICE_PATH),
        &[("z-road-client", "ZW/COM/22222222/ap")],
        &json!({ "tin": "2000123456" }),
    )
    .await;
    assert_eq!((s, body["error"].as_str().unwrap()), (403, "access_denied"));

    // No bare root paths when several members share the node.
    let (s, _, _) = post_json(
        &a.internal(SERVICE_PATH),
        &[("z-road-client", "ZW/COM/11111111/ap")],
        &json!({}),
    )
    .await;
    assert_eq!(s, 404);
    // A member's internal API only speaks for that member.
    let (s, body, _) = post_json(
        &prefixed(&a, SERVICE_PATH),
        &[("z-road-client", "ZW/COM/22222222/ap")],
        &json!({}),
    )
    .await;
    assert_eq!(
        (s, body["error"].as_str().unwrap()),
        (400, "invalid_request")
    );

    // Admin credentials are per member.
    let wrong = format!("Bearer {tok_b}");
    let right = format!("Bearer {tok_a}");
    let (s, _) = get_json(
        &prefixed(&a, "/admin/v1/audit/status"),
        &[("authorization", &wrong)],
    )
    .await;
    assert_eq!(s, 401);
    let (s, st) = get_json(
        &prefixed(&a, "/admin/v1/audit/status"),
        &[("authorization", &right)],
    )
    .await;
    assert_eq!((s, &st["verified"]), (200, &json!(true)));

    // Audit logs are separate per member.
    let peers_of = |m: &Member| -> Vec<String> {
        audit::read_entries(&m.dir.join("audit/log.jsonl"))
            .unwrap()
            .into_iter()
            .filter_map(|e| match e.event {
                audit::AuditEvent::Exchange {
                    peer,
                    role,
                    outcome,
                    ..
                } => Some(format!("{role}:{peer}:{outcome}")),
                _ => None,
            })
            .collect()
    };
    let zl = peers_of(&zimra);
    assert!(
        zl.contains(&"provider:ZW/COM/11111111:ok".to_string()),
        "{zl:?}"
    );
    assert!(
        zl.contains(&"provider:ZW/COM/33333333:ok".to_string()),
        "{zl:?}"
    );
    assert!(
        zl.contains(&"provider:ZW/COM/22222222:denied:access_denied".to_string()),
        "{zl:?}"
    );
    assert_eq!(peers_of(&a), vec!["consumer:ZW/GOV/ZIMRA:ok"]);
    assert_eq!(
        peers_of(&b),
        vec!["consumer:ZW/GOV/ZIMRA:error:access_denied"]
    );

    // The citizen view on the shared node sees both consumers.
    let (s, log) = get_json(
        &prefixed(&zimra, "/admin/v1/access-log?subject=2000123456"),
        &[("authorization", &format!("Bearer {tok_z}"))],
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(log.as_array().unwrap().len(), 2, "{log}");

    // A request for a member the node does not host is refused up front.
    let raw = RawClient::new(&standalone, &zimra);
    let body = br#"{}"#;
    let mut env = raw.envelope(&random_id(), body);
    env.service = "ZW/GOV/OTHER/tax-clearance/verify/v1".parse().unwrap();
    let (s, v) = raw.send(&env, body, None).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (400, "wrong_provider"));
    running.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn catalogue_lists_services_of_active_members() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let _z = net.run(&zimra, true).await;
    let _b = net.run(&buyer, false).await;
    let public = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();

    // Services appear by themselves after startup.
    let mut cat = public.catalogue().await.unwrap();
    for _ in 0..20 {
        if !cat.entries.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        cat = public.catalogue().await.unwrap();
    }
    assert_eq!(cat.entries.len(), 1, "{cat:?}");
    assert_eq!(
        cat.entries[0].service.to_string(),
        "ZW/GOV/ZIMRA/tax-clearance/verify/v1"
    );
    assert_eq!(cat.entries[0].title, "Tax clearance check");

    // Only a member with its current certificate can publish.
    let anon = zroad_net::api::PublishCatalogueRequest {
        services: vec![zroad_net::api::CatalogueItem {
            id: "x/y/v1".into(),
            title: "t".into(),
            description: "d".into(),
        }],
    };
    assert!(public.publish_catalogue(&anon).await.is_err());

    // A member can only publish under its own id: the buyer's entry is attributed to the buyer.
    let read = |f: &str| std::fs::read_to_string(buyer.dir.join(f)).unwrap();
    let as_buyer = CentralClient::with_identity(
        &net.central_url,
        &read("ca.pem"),
        &read("cert.pem"),
        &read("key.pem"),
    )
    .unwrap();
    as_buyer.publish_catalogue(&anon).await.unwrap();
    let cat = public.catalogue().await.unwrap();
    assert!(cat
        .entries
        .iter()
        .any(|e| e.service.to_string() == "ZW/COM/12345678/x/y/v1"));
    assert!(!cat
        .entries
        .iter()
        .any(|e| e.service.member.to_string() != "ZW/COM/12345678" && e.service.service == "y"));

    // The admin endpoint re-publishes on demand.
    let r = zroad_net::request(
        "POST",
        &zimra.internal("/admin/v1/catalogue/publish"),
        &[("authorization", &format!("Bearer {ADMIN}"))],
        Bytes::new(),
        None,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);

    // Revoked members vanish from the catalogue.
    let c = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();
    c.revoke(&net.admin_token, &"ZW/GOV/ZIMRA".parse().unwrap())
        .await
        .unwrap();
    let cat = public.catalogue().await.unwrap();
    assert!(!cat
        .entries
        .iter()
        .any(|e| e.service.member.to_string() == "ZW/GOV/ZIMRA"));
}
