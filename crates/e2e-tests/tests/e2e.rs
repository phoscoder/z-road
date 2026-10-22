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
            "rotation_grace_secs": 0,
            "rotation_activation_secs": 0,
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
    // the forced anchor is itself an administrative action and is recorded first,
    // so there is always something new to anchor
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
    assert_eq!(r.status, 200);
    let again: Value = serde_json::from_slice(&r.body).unwrap();
    assert!(again["anchor_seq"].is_u64(), "{again}");
    let report = audit::verify_file(&zimra.dir.join("audit/log.jsonl")).unwrap();
    assert_eq!(report.anchors.len(), 2);

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
    let (st, _, headers) = clearance(&buyer, "ZW/COM/12345678/ap", "2000123456").await;
    assert_eq!(st, 200);
    let proof_before_renewal = read_proof(&headers);
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
    // A proof made before the rotation still verifies: the directory keeps each
    // member's earlier certificates and checks the key that was valid at the time.
    let directory: zroad_core::directory::Directory =
        serde_json::from_slice(&std::fs::read(buyer.dir.join("directory.json")).unwrap()).unwrap();
    assert!(
        directory
            .get(&"ZW/COM/12345678".parse().unwrap())
            .unwrap()
            .previous_certs
            .len()
            == 1
    );
    directory
        .verify_proof(&proof_before_renewal)
        .expect("old proof verifies after both parties rotated");
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
        node_identity: None,
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
            request_schema: None,
            response_schema: None,
        }],
        on_behalf_of: None,
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

#[tokio::test(flavor = "multi_thread")]
async fn rust_client_library() {
    use zroad_client::{CallOptions, Client, ClientError, Queued};
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let stranger = net.member("ZW/COM/77777777").await;
    let _b = net.run(&buyer, false).await; // ZIMRA is down for now
    let _s = net.run(&stranger, false).await;

    let svc: zroad_core::id::ServiceId = "ZW/GOV/ZIMRA/tax-clearance/verify/v1".parse().unwrap();
    let client = Client::new(
        &format!("http://127.0.0.1:{}", buyer.int_port),
        "ZW/COM/12345678/accounts-payable".parse().unwrap(),
    );
    let opts = CallOptions::default().subject("2000123456");

    // Provider down: a retryable Z-Road error with a stable code.
    let err = client
        .call_json(&svc, &json!({ "tin": "2000123456" }), &opts)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("provider_unreachable"));
    assert!(err.is_retryable());

    // Queue it, bring ZIMRA up, and collect the delivered answer.
    let id = client
        .submit(&svc, br#"{"tin":"2000123456"}"#.to_vec(), &opts)
        .await
        .unwrap();
    assert!(matches!(
        client.poll(&id).await.unwrap(),
        Queued::Pending { .. } | Queued::Delivered(_)
    ));
    let _z = net.run(&zimra, true).await;
    let queued = client.wait(&id, Duration::from_secs(30)).await.unwrap();
    assert_eq!(queued.json::<Value>().unwrap()["status"], "VALID");

    // A live call returns a verifiable proof.
    let reply = client
        .call_json(&svc, &json!({ "tin": "2000123456" }), &opts)
        .await
        .unwrap();
    assert!(reply.is_success());
    let directory: zroad_core::directory::Directory =
        serde_json::from_slice(&std::fs::read(buyer.dir.join("directory.json")).unwrap()).unwrap();
    let (req, res) = reply.verify(&directory).unwrap();
    assert_eq!(req.client.to_string(), "ZW/COM/12345678/accounts-payable");
    assert_eq!(res.status, 200);

    // The provider's own 404-style answers are replies, not errors.
    let nf = client
        .call_json(
            &svc,
            &json!({ "tin": "0000000000" }),
            &CallOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(nf.json::<Value>().unwrap()["status"], "NOT_FOUND");

    // Z-Road refusals are errors with codes.
    let other = Client::new(
        &format!("http://127.0.0.1:{}", stranger.int_port),
        "ZW/COM/77777777/ap".parse().unwrap(),
    );
    match other
        .call_json(&svc, &json!({}), &CallOptions::default())
        .await
    {
        Err(ClientError::ZRoad {
            status,
            code,
            retryable,
            ..
        }) => assert_eq!(
            (status, code.as_str(), retryable),
            (403, "access_denied", false)
        ),
        other => panic!("expected access_denied, got {other:?}"),
    }
    // Claiming another member's subsystem is rejected before leaving the building.
    let liar = Client::new(
        &format!("http://127.0.0.1:{}", buyer.int_port),
        "ZW/COM/77777777/ap".parse().unwrap(),
    );
    assert_eq!(
        liar.call_json(&svc, &json!({}), &CallOptions::default())
            .await
            .unwrap_err()
            .code(),
        Some("invalid_request")
    );
    // A dead security server is Unreachable.
    let dead = Client::new("http://127.0.0.1:1", "ZW/COM/12345678/ap".parse().unwrap());
    assert!(matches!(
        dead.call_json(&svc, &json!({}), &CallOptions::default())
            .await,
        Err(ClientError::Unreachable(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn schemas_are_published_and_enforced() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;

    let schemas = net.tmp.path().join("schemas");
    std::fs::create_dir_all(&schemas).unwrap();
    let req = schemas.join("req.json");
    let res = schemas.join("res.json");
    std::fs::write(
        &req,
        json!({
            "type": "object", "required": ["tin"], "additionalProperties": false,
            "properties": { "tin": { "type": "string", "pattern": "^[0-9]{10}$" } }
        })
        .to_string(),
    )
    .unwrap();
    // deliberately narrow: only VALID answers conform
    std::fs::write(
        &res,
        json!({
            "type": "object", "required": ["tin", "status"],
            "properties": { "status": { "enum": ["VALID"] } }
        })
        .to_string(),
    )
    .unwrap();

    // A broken schema file stops startup instead of silently running unvalidated.
    let mut broken = net.config(&zimra, true);
    broken.services[0].request_schema = Some(schemas.join("missing.json"));
    assert!(security_server::spawn(broken).await.is_err());
    let bad = schemas.join("bad.json");
    std::fs::write(&bad, r#"{"type":"nonsense"}"#).unwrap();
    let mut invalid = net.config(&zimra, true);
    invalid.services[0].request_schema = Some(bad);
    assert!(security_server::spawn(invalid).await.is_err());

    let mut cfg = net.config(&zimra, true);
    cfg.services[0].request_schema = Some(req);
    cfg.services[0].response_schema = Some(res);
    cfg.services[0].enforce_response_schema = true;
    let _z = security_server::spawn(cfg).await.unwrap();
    let _b = net.run(&buyer, false).await;

    // The schemas appear in the public catalogue.
    let public = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();
    let mut entry = None;
    for _ in 0..20 {
        entry = public.catalogue().await.unwrap().entries.into_iter().next();
        if entry.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let entry = entry.expect("catalogue entry");
    assert!(entry.request_schema.is_some() && entry.response_schema.is_some());

    // The central server refuses a schema that does not compile.
    let read = |f: &str| std::fs::read_to_string(buyer.dir.join(f)).unwrap();
    let as_buyer = CentralClient::with_identity(
        &net.central_url,
        &read("ca.pem"),
        &read("cert.pem"),
        &read("key.pem"),
    )
    .unwrap();
    let bad_item = zroad_net::api::PublishCatalogueRequest {
        services: vec![zroad_net::api::CatalogueItem {
            id: "a/b/v1".into(),
            title: "t".into(),
            description: "d".into(),
            request_schema: Some(json!({ "type": "nonsense" })),
            response_schema: None,
        }],
        on_behalf_of: None,
    };
    assert!(as_buyer.publish_catalogue(&bad_item).await.is_err());

    // Provider side, bypassing the consumer's own check: malformed bodies never
    // reach the internal system.
    let raw = RawClient::new(&buyer, &zimra);
    for body in [
        &br#"{"tin":"abc"}"#[..],
        br#"{"tin":"2000123456","x":1}"#,
        br#"{}"#,
        b"not json",
    ] {
        let (s, v) = raw
            .send(&raw.envelope(&random_id(), body), body, None)
            .await;
        assert_eq!(
            (s, v["error"].as_str().unwrap()),
            (400, "schema_violation"),
            "{body:?}"
        );
    }
    let body = br#"{"tin":"2000123456"}"#;
    let mut env = raw.envelope(&random_id(), body);
    env.content_type = "text/plain".into();
    let (s, v) = raw.send(&env, body, None).await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (415, "unsupported_media_type")
    );
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        raw.send(&raw.envelope(&random_id(), body), body, None)
            .await
            .0,
        200
    );
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 1);

    // Consumer side: once the catalogue has reached the buyer's security server,
    // a bad request fails fast without leaving the building.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let before = net.upstream_calls.load(Ordering::SeqCst);
    let (s, v, _) = clearance(&buyer, "ZW/COM/12345678/ap", "not-a-tin").await;
    assert_eq!((s, v["error"].as_str().unwrap()), (400, "schema_violation"));
    assert!(v["message"].as_str().unwrap().contains("/tin"), "{v}");
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), before);
    assert_eq!(
        clearance(&buyer, "ZW/COM/12345678/ap", "2000123456")
            .await
            .0,
        200
    );

    // Response enforcement: an answer outside the published schema is not delivered.
    let (s, v, _) = clearance(&buyer, "ZW/COM/12345678/ap", "2000000000").await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (502, "upstream_schema_violation"),
        "{v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_fails_closed_when_the_audit_log_cannot_be_written() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let z = net.run(&zimra, true).await;
    let _b = net.run(&buyer, false).await;
    let raw = RawClient::new(&buyer, &zimra);
    let body = br#"{"tin":"2000123456"}"#;
    let audit_log = z.state.audit.clone();
    let log_text = || std::fs::read_to_string(zimra.dir.join("audit/log.jsonl")).unwrap();

    assert_eq!(
        raw.send(&raw.envelope(&random_id(), body), body, None)
            .await
            .0,
        200
    );
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 1);

    // 1. The log is dead before the request arrives: it is refused up front and
    //    the internal system is never called, so there is no effect without a record.
    audit_log.inject_write_failure_after(0);
    let id = random_id();
    let (s, v) = raw.send(&raw.envelope(&id, body), body, None).await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (503, "audit_unavailable")
    );
    assert_eq!(
        net.upstream_calls.load(Ordering::SeqCst),
        1,
        "the internal system was not called"
    );
    // The consumer's side sees a retryable Z-Road error.
    let (s, v, h) = clearance(&buyer, "ZW/COM/12345678/ap", "2000123456").await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (503, "audit_unavailable"),
        "{v}"
    );
    assert!(h.get("retry-after").is_some(), "marked retryable");

    // 2. Recovery: the same message id can be retried and is processed once.
    audit_log.clear_write_failure();
    assert_eq!(raw.send(&raw.envelope(&id, body), body, None).await.0, 200);
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 2);

    // 3. The log dies after the write-ahead record but before the outcome: the
    //    request was forwarded, so it is on record, but the answer is withheld.
    audit_log.inject_write_failure_after(1);
    let id2 = random_id();
    let (s, v) = raw.send(&raw.envelope(&id2, body), body, None).await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (503, "audit_unavailable")
    );
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 3);
    audit_log.clear_write_failure();
    let text = log_text();
    assert!(
        text.contains(&id2) && text.contains("\"outcome\":\"received\""),
        "write-ahead record is on disk"
    );
    // 4. A retry after recovery gets the answer without calling the internal system again.
    assert_eq!(raw.send(&raw.envelope(&id2, body), body, None).await.0, 200);
    assert_eq!(net.upstream_calls.load(Ordering::SeqCst), 3);

    // The chain is intact throughout, and the citizen view does not double count.
    audit::verify_file(&zimra.dir.join("audit/log.jsonl")).unwrap();
}

/// Hosted members keep their signing keys on their own machines (signer
/// services). The node that carries their traffic never holds those keys.
#[tokio::test(flavor = "multi_thread")]
async fn members_keep_their_own_keys_on_a_shared_node() {
    use security_server::config::{NodeIdentityConfig, RemoteSignerConfig};
    use zroad_core::crypto::AsyncSigner;
    use zroad_net::remote_signer::RemoteSigner;

    let net = Net::start().await;
    let node_id = "ZW/NODE/acme-hosting";

    // Stand-alone members: a provider (ZIMRA) and a consumer.
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let standalone = net.member("ZW/COM/33333333").await;
    let _z = security_server::spawn(net.config_with(
        &zimra,
        true,
        ADMIN,
        &["ZW/COM/11111111", "ZW/COM/33333333"],
    ))
    .await
    .unwrap();
    let _s = net.run(&standalone, false).await;

    // The node has an identity of its own, used for TLS.
    let (node_net, node_int) = (free_port(), free_port());
    let node_dir = net.tmp.path().join("node-identity");
    net.register(node_id, &format!("https://127.0.0.1:{node_net}"), &node_dir)
        .await;

    // Each hosted member generates its key on its own machine and runs a signer there.
    let central = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();
    struct Hosted {
        member: Member,
        signer_dir: PathBuf,
        signer_port: u16,
    }
    let mut signer_handles: Vec<ServerHandle> = Vec::new();
    let mut hosted = Vec::new();
    for id in ["ZW/COM/11111111", "ZW/COM/22222222"] {
        let mid: MemberId = id.parse().unwrap();
        let tok = central
            .add_hosted_member(&net.admin_token, &mid, id, &node_id.parse().unwrap())
            .await
            .unwrap();
        let signer_dir = net
            .tmp
            .path()
            .join(format!("signer-{}", id.replace('/', "_")));
        enroll_to_dir(
            &net.central_url,
            &net.ca_pem,
            &mid,
            &tok.enrollment_token,
            &["127.0.0.1".into()],
            &signer_dir,
        )
        .await
        .unwrap();
        signer_service::init(&signer_dir, &["127.0.0.1".to_string()]).unwrap();
        let signer_port = free_port();
        signer_handles.push(
            signer_service::spawn(signer_service::SignerConfig {
                dir: signer_dir.clone(),
                listen: format!("127.0.0.1:{signer_port}"),
                member: mid,
                node: node_id.parse().unwrap(),
                max_per_minute: 1000,
                options: Default::default(),
            })
            .await
            .unwrap(),
        );
        // The node gets the member's certificate and CA, never its key.
        let data = net
            .tmp
            .path()
            .join(format!("node-{}", id.replace('/', "_")));
        std::fs::create_dir_all(&data).unwrap();
        for f in ["cert.pem", "ca.pem"] {
            std::fs::copy(signer_dir.join(f), data.join(f)).unwrap();
        }
        hosted.push(Hosted {
            member: Member {
                id,
                net_port: node_net,
                int_port: node_int,
                dir: data,
            },
            signer_dir,
            signer_port,
        });
    }
    let (a, b) = (&hosted[0], &hosted[1]);
    let tok_b = "admin-token-b-0123456789";
    let mut cfg_a = net.config_with(&a.member, false, "admin-token-a-0123456789", &[]);
    let mut cfg_b = net.config_with(
        &b.member,
        true,
        tok_b,
        &["ZW/COM/11111111", "ZW/COM/33333333"],
    );
    for (cfg, h) in [(&mut cfg_a, a), (&mut cfg_b, b)] {
        cfg.remote_signer = Some(RemoteSignerConfig {
            url: format!("https://127.0.0.1:{}", h.signer_port),
            ca_file: h.signer_dir.join("signer-ca.pem"),
        });
        cfg.node_identity_dir = Some(node_dir.clone());
    }
    let node = security_server::spawn_node(security_server::config::NodeConfig {
        members: vec![cfg_a, cfg_b],
        node_dir: net.tmp.path().join("node"),
        node_identity: Some(NodeIdentityConfig {
            member: node_id.parse().unwrap(),
            dir: node_dir.clone(),
        }),
    })
    .await
    .unwrap();
    // the stand-alone members learn about the node from their next directory refresh
    tokio::time::sleep(Duration::from_millis(2500)).await;
    for h in &hosted {
        assert!(
            !h.member.dir.join("key.pem").exists(),
            "the node must not hold {}'s key",
            h.member.id
        );
    }
    let directory = || -> zroad_core::directory::Directory {
        serde_json::from_slice(&std::fs::read(net.tmp.path().join("node/directory.json")).unwrap())
            .unwrap()
    };
    let prefixed = |m: &Member, rest: &str| m.internal(&format!("/m/{}{rest}", m.id));
    let a_url = prefixed(&a.member, SERVICE_PATH);
    let a_to_zimra = || {
        let url = a_url.clone();
        async move {
            post_json(
                &url,
                &[
                    ("z-road-client", "ZW/COM/11111111/ap"),
                    ("z-road-subject", "2000123456"),
                ],
                &json!({ "tin": "2000123456" }),
            )
            .await
        }
    };

    // 1. A hosted consumer calls a stand-alone provider. The proof verifies
    //    against A's own key, which only A's signer holds.
    let (s, body, headers) = a_to_zimra().await;
    assert_eq!(
        (s, body["status"].as_str().unwrap()),
        (200, "VALID"),
        "{body}"
    );
    let (req, _) = directory().verify_proof(&read_proof(&headers)).unwrap();
    assert_eq!(req.client.to_string(), "ZW/COM/11111111/ap");
    //    ZIMRA records who spoke and which node carried it.
    let zimra_log = audit::read_entries(&zimra.dir.join("audit/log.jsonl")).unwrap();
    assert!(
        zimra_log.iter().any(|e| matches!(&e.event,
        audit::AuditEvent::Exchange { peer, via: Some(v), role, outcome, .. }
            if peer == "ZW/COM/11111111" && v == node_id && role == "provider" && outcome == "ok")),
        "{zimra_log:?}"
    );
    //    A's signer has its own record of the signature.
    let signed = |dir: &Path| -> Vec<(String, String)> {
        audit::read_entries(&dir.join("audit/log.jsonl"))
            .unwrap()
            .into_iter()
            .filter_map(|e| match e.event {
                audit::AuditEvent::Signed { kind, node, .. } => Some((kind, node)),
                _ => None,
            })
            .collect()
    };
    assert_eq!(
        signed(&a.signer_dir),
        vec![("request".to_string(), node_id.to_string())]
    );

    // 2. A stand-alone consumer calls a hosted provider: the answer is signed by B's signer.
    let (s, body, headers) = post_json(
        &standalone.internal("/r1/ZW/COM/22222222/tax-clearance/verify/v1"),
        &[("z-road-client", "ZW/COM/33333333/ap")],
        &json!({ "tin": "2000123456" }),
    )
    .await;
    assert_eq!(
        (s, body["status"].as_str().unwrap()),
        (200, "VALID"),
        "{body}"
    );
    let (_, res) = directory().verify_proof(&read_proof(&headers)).unwrap();
    assert_eq!(res.provider.to_string(), "ZW/COM/22222222");
    assert_eq!(
        signed(&b.signer_dir),
        vec![("response".to_string(), node_id.to_string())]
    );
    //    Both hosted members on the same node can call each other.
    let (s, _, _) = post_json(
        &prefixed(&a.member, "/r1/ZW/COM/22222222/tax-clearance/verify/v1"),
        &[("z-road-client", "ZW/COM/11111111/ap")],
        &json!({ "tin": "2000123456" }),
    )
    .await;
    assert_eq!(s, 200);

    // 3. The node cannot forge a hosted member: signing with its own key is
    //    rejected, and it cannot speak for a member it does not host.
    let node_member = Member {
        id: node_id,
        net_port: node_net,
        int_port: node_int,
        dir: node_dir.clone(),
    };
    let as_node = RawClient::new(&node_member, &zimra);
    let body = br#"{"tin":"2000123456"}"#;
    let mut env = as_node.envelope(&random_id(), body);
    env.client = "ZW/COM/11111111/ap".parse().unwrap();
    let (s, v) = as_node.send(&env, body, None).await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (400, "bad_signature"),
        "{v}"
    );
    let mut env = as_node.envelope(&random_id(), body);
    env.client = "ZW/COM/33333333/ap".parse().unwrap();
    let (s, v) = as_node.send(&env, body, None).await;
    assert_eq!((s, v["error"].as_str().unwrap()), (403, "client_mismatch"));

    // 4. A hosted member must come through its node, even though it holds a
    //    valid certificate and key itself.
    let direct = RawClient::new(
        &Member {
            id: "ZW/COM/11111111",
            net_port: 0,
            int_port: 0,
            dir: a.signer_dir.clone(),
        },
        &zimra,
    );
    let (s, v) = direct
        .send(&direct.envelope(&random_id(), body), body, None)
        .await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (403, "hosted_member_must_use_node"),
        "{v}"
    );

    // 5. The signer enforces its own policy, whatever the node asks for.
    let read = |d: &Path, f: &str| std::fs::read_to_string(d.join(f)).unwrap();
    let a_key = pki::inspect_cert_pem(&read(&a.signer_dir, "cert.pem"))
        .unwrap()
        .public_key;
    let signer_url = format!("https://127.0.0.1:{}", a.signer_port);
    let signer_ca = read(&a.signer_dir, "signer-ca.pem");
    let as_caller = |who: &Path| {
        let tls = tls::client_config(
            &signer_ca,
            Some((&read(who, "cert.pem"), &read(who, "key.pem"))),
        )
        .unwrap();
        RemoteSigner::new(&signer_url, tls, a_key.clone())
    };
    let envelope_for = |client: &str| {
        let mut e = as_node.envelope(&random_id(), body);
        e.client = client.parse().unwrap();
        signing_input(REQUEST_DOMAIN, &serde_json::to_vec(&e).unwrap())
    };
    let node_caller = as_caller(&node_dir);
    assert!(node_caller
        .sign_bytes(&envelope_for("ZW/COM/11111111/ap"))
        .await
        .is_ok());
    let err = node_caller
        .sign_bytes(&envelope_for("ZW/COM/22222222/ap"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not_our_request"), "{err}");
    let err = node_caller
        .sign_bytes(b"zroad/v1/timestamp\nwhatever")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("unsupported_domain"), "{err}");
    let err = as_caller(&standalone.dir)
        .sign_bytes(&envelope_for("ZW/COM/11111111/ap"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not_the_node"), "{err}");

    // 6. Hosted providers are only reachable while their node is active.
    //    (Done before taking signers down.)
    // 7. If the member's signer is down, the node cannot act for it at all.
    signer_handles.remove(0).shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (s, v, h) = a_to_zimra().await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (503, "signer_unavailable"),
        "{v}"
    );
    assert!(h.get("retry-after").is_some());

    // 8. Revoking the node cuts off everything it hosts.
    central
        .revoke(&net.admin_token, &node_id.parse().unwrap())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let (s, v, _) = post_json(
        &standalone.internal("/r1/ZW/COM/22222222/tax-clearance/verify/v1"),
        &[("z-road-client", "ZW/COM/33333333/ap")],
        &json!({ "tin": "2000123456" }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (404, "unknown_provider"),
        "{v}"
    );
    node.shutdown();
}

fn operator(
    name: &str,
    role: zroad_core::auth::Role,
    token: &str,
) -> zroad_core::auth::OperatorEntry {
    zroad_core::auth::OperatorEntry {
        name: name.into(),
        role,
        token_sha256: zroad_core::auth::hash_token(token),
    }
}

async fn call_as(
    method: &str,
    url: &str,
    token: Option<&str>,
    extra: &[(&str, &str)],
) -> (u16, Value) {
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut h: Vec<(&str, &str)> = extra.to_vec();
    if let Some(a) = &auth {
        h.push(("authorization", a));
    }
    let r = zroad_net::request(method, url, &h, Bytes::new(), None, Duration::from_secs(20))
        .await
        .unwrap();
    (
        r.status,
        serde_json::from_slice(&r.body).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn operators_have_roles_and_their_actions_are_recorded() {
    use zroad_core::auth::Role;
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let idp = SoftwareSigner::from_pkcs8_pem(
        &rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .unwrap()
            .serialize_pem(),
    )
    .unwrap();

    let mut cfg = net.config(&zimra, true);
    cfg.operators = vec![
        operator("alice", Role::Auditor, "tok-alice"),
        operator("bob", Role::Operator, "tok-bob"),
        operator("carol", Role::Admin, "tok-carol"),
        operator("portal1", Role::Portal, "tok-portal"),
    ];
    cfg.citizen_assertion_keys = vec![security_server::config::CitizenKeyConfig {
        name: "zimra-login".into(),
        public_key_b64: b64_encode(&Signer::public_key(&idp)),
    }];
    // the original single credential keeps working, as the admin `legacy-admin`
    cfg.admin_token = ADMIN.into();
    let z = security_server::spawn(cfg.clone()).await.unwrap();
    let url = |p: &str| zimra.internal(p);

    // Unauthenticated and unknown tokens are refused, and guessing is slowed down.
    assert_eq!(
        call_as("GET", &url("/admin/v1/audit/status"), None, &[])
            .await
            .0,
        401
    );
    let t = std::time::Instant::now();
    assert_eq!(
        call_as("GET", &url("/admin/v1/audit/status"), Some("guess"), &[])
            .await
            .0,
        401
    );
    assert!(
        t.elapsed() >= Duration::from_millis(250),
        "failed logins are delayed"
    );

    // Auditor: read-only.
    assert_eq!(
        call_as(
            "GET",
            &url("/admin/v1/audit/status"),
            Some("tok-alice"),
            &[]
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call_as("GET", &url("/admin/v1/identity"), Some("tok-alice"), &[])
            .await
            .0,
        200
    );
    assert_eq!(
        call_as(
            "GET",
            &url("/admin/v1/access-log?subject=2000123456"),
            Some("tok-alice"),
            &[]
        )
        .await
        .0,
        200
    );
    for p in [
        "/admin/v1/directory/refresh",
        "/admin/v1/anchor",
        "/admin/v1/renew",
        "/admin/v1/catalogue/publish",
    ] {
        assert_eq!(
            call_as("POST", &url(p), Some("tok-alice"), &[]).await.0,
            403,
            "{p}"
        );
    }

    // Operator: may change state.
    assert_eq!(
        call_as(
            "POST",
            &url("/admin/v1/directory/refresh"),
            Some("tok-bob"),
            &[]
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call_as("POST", &url("/admin/v1/anchor"), Some("tok-bob"), &[])
            .await
            .0,
        200
    );
    assert_eq!(
        call_as("GET", &url("/admin/v1/audit/status"), Some("tok-bob"), &[])
            .await
            .0,
        200
    );

    // Admin and the legacy credential: everything.
    assert_eq!(
        call_as(
            "POST",
            &url("/admin/v1/catalogue/publish"),
            Some("tok-carol"),
            &[]
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call_as(
            "POST",
            &url("/admin/v1/directory/refresh"),
            Some(ADMIN),
            &[]
        )
        .await
        .0,
        200
    );

    // The portal role is a separate lane: nothing administrative.
    for (m, p) in [
        ("GET", "/admin/v1/audit/status"),
        ("GET", "/admin/v1/access-log?subject=1"),
        ("POST", "/admin/v1/directory/refresh"),
    ] {
        assert_eq!(
            call_as(m, &url(p), Some("tok-portal"), &[]).await.0,
            403,
            "{p}"
        );
    }
    // ... and without an assertion it cannot read anyone's record either.
    let (s, v) = call_as(
        "GET",
        &url("/citizen/v1/access-log"),
        Some("tok-portal"),
        &[],
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (401, "citizen_assertion_required")
    );
    // Admins and auditors are not portals.
    assert_eq!(
        call_as(
            "GET",
            &url("/citizen/v1/access-log"),
            Some("tok-carol"),
            &[]
        )
        .await
        .0,
        403
    );

    // Every privileged action is on the record, with who did it; refusals are not
    // actions. The subject is never in the log in clear.
    let log = std::fs::read_to_string(zimra.dir.join("audit/log.jsonl")).unwrap();
    let admin_events: Vec<(String, String)> =
        audit::read_entries(&zimra.dir.join("audit/log.jsonl"))
            .unwrap()
            .into_iter()
            .filter_map(|e| match e.event {
                audit::AuditEvent::Admin {
                    operator, action, ..
                } => Some((operator, action)),
                _ => None,
            })
            .collect();
    for want in [
        ("alice", "access_log_lookup"),
        ("bob", "directory_refresh"),
        ("bob", "anchor"),
        ("carol", "catalogue_publish"),
        ("legacy-admin", "directory_refresh"),
    ] {
        assert!(
            admin_events.contains(&(want.0.to_string(), want.1.to_string())),
            "{want:?} missing in {admin_events:?}"
        );
    }
    assert!(
        !admin_events
            .iter()
            .any(|(who, a)| who == "alice" && a == "anchor"),
        "refused attempts are not recorded as actions"
    );
    assert!(!log.contains("2000123456"));
    audit::verify_file(&zimra.dir.join("audit/log.jsonl")).unwrap();

    // Fail closed: an action that cannot be recorded is not performed.
    z.state.audit.inject_write_failure_after(0);
    let (s, v) = call_as(
        "POST",
        &url("/admin/v1/directory/refresh"),
        Some("tok-bob"),
        &[],
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str().unwrap()),
        (503, "audit_unavailable")
    );
    z.state.audit.clear_write_failure();
    z.shutdown();

    // Bad configuration is refused at startup.
    let mut dup = cfg.clone();
    dup.operators
        .push(operator("alice", Role::Admin, "another"));
    assert!(
        security_server::spawn(dup).await.is_err(),
        "duplicate operator name"
    );
    let mut no_keys = cfg.clone();
    no_keys.citizen_assertion_keys.clear();
    assert!(
        security_server::spawn(no_keys).await.is_err(),
        "portal without any citizen key"
    );
    let mut nobody = cfg;
    nobody.operators.clear();
    nobody.admin_token.clear();
    assert!(
        security_server::spawn(nobody).await.is_err(),
        "no way to administer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn citizens_can_only_see_their_own_record() {
    use zroad_core::auth::Role;
    use zroad_core::citizen::{issue, Assertion};
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let buyer = net.member("ZW/COM/12345678").await;
    let new_key = || {
        SoftwareSigner::from_pkcs8_pem(
            &rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .unwrap()
                .serialize_pem(),
        )
        .unwrap()
    };
    let (idp, rogue) = (new_key(), new_key());

    let mut cfg = net.config(&zimra, true);
    cfg.operators = vec![
        operator("portal1", Role::Portal, "tok-portal"),
        operator("alice", Role::Auditor, "tok-alice"),
    ];
    cfg.citizen_assertion_keys = vec![security_server::config::CitizenKeyConfig {
        name: "zimra-login".into(),
        public_key_b64: b64_encode(&Signer::public_key(&idp)),
    }];
    let _z = security_server::spawn(cfg).await.unwrap();
    let _b = net.run(&buyer, false).await;

    // Two different people are looked up, one of them twice.
    for tin in ["2000123456", "2000123456", "2000987654"] {
        assert_eq!(clearance(&buyer, "ZW/COM/12345678/ap", tin).await.0, 200);
    }

    let aud: MemberId = "ZW/GOV/ZIMRA".parse().unwrap();
    let assertion = |sub: &str, aud: &MemberId, iat: u64, ttl: u64, key: &SoftwareSigner| {
        issue(
            &Assertion {
                v: 1,
                sub: sub.into(),
                aud: aud.clone(),
                iat_ms: iat,
                exp_ms: iat + ttl,
                jti: random_id(),
            },
            key,
        )
        .unwrap()
    };
    let now = now_ms();
    let portal = |token: &str, assertion: &str, query: &str| {
        let url = zimra.internal(&format!("/citizen/v1/access-log{query}"));
        let (token, assertion) = (token.to_string(), assertion.to_string());
        async move {
            call_as(
                "GET",
                &url,
                Some(&token),
                &[("z-road-citizen-assertion", &assertion)],
            )
            .await
        }
    };

    // Each person sees exactly their own lookups, and only the fields a citizen needs.
    let (s, mine) = portal(
        "tok-portal",
        &assertion("2000123456", &aud, now, 300_000, &idp),
        "",
    )
    .await;
    assert_eq!(s, 200, "{mine}");
    assert_eq!(mine.as_array().unwrap().len(), 2);
    let first = mine[0].as_object().unwrap();
    assert_eq!(first["accessed_by"], "ZW/COM/12345678");
    assert!(
        first.get("client").is_none() && first.get("message_id").is_none(),
        "internal details are not shown: {first:?}"
    );
    let (_, theirs) = portal(
        "tok-portal",
        &assertion("2000987654", &aud, now, 300_000, &idp),
        "",
    )
    .await;
    assert_eq!(theirs.as_array().unwrap().len(), 1);
    let (_, nobody) = portal(
        "tok-portal",
        &assertion("2000555111", &aud, now, 300_000, &idp),
        "",
    )
    .await;
    assert_eq!(nobody.as_array().unwrap().len(), 0);

    // The portal cannot steer the lookup: a subject parameter is ignored.
    let good = assertion("2000123456", &aud, now, 300_000, &idp);
    let (_, steered) = portal("tok-portal", &good, "?subject=2000987654&limit=1").await;
    assert_eq!(
        steered.as_array().unwrap().len(),
        1,
        "limit applies, subject is ignored"
    );
    assert_eq!(steered[0]["accessed_by"], "ZW/COM/12345678");
    let (_, again) = portal("tok-portal", &good, "?subject=2000987654").await;
    assert_eq!(
        again.as_array().unwrap().len(),
        2,
        "still the asserting person's two lookups"
    );

    // Anything wrong with the proof of identity is refused.
    let bad: Vec<(&str, String)> = vec![
        (
            "signed by an unknown issuer",
            assertion("2000123456", &aud, now, 300_000, &rogue),
        ),
        (
            "meant for another provider",
            assertion(
                "2000123456",
                &"ZW/GOV/OTHER".parse().unwrap(),
                now,
                300_000,
                &idp,
            ),
        ),
        (
            "expired",
            assertion("2000123456", &aud, now - 700_000, 300_000, &idp),
        ),
        (
            "lifetime too long",
            assertion("2000123456", &aud, now, 3_600_000, &idp),
        ),
        ("not an assertion", "not-an-assertion".into()),
    ];
    for (why, token) in &bad {
        let (s, v) = portal("tok-portal", token, "").await;
        assert_eq!(
            (s, v["error"].as_str().unwrap()),
            (401, "invalid_citizen_assertion"),
            "{why}: {v}"
        );
    }
    // A forged subject breaks the signature.
    let (p, sig) = good.split_once('.').unwrap();
    let forged = String::from_utf8(b64_decode(p).unwrap())
        .unwrap()
        .replace("2000123456", "2000987654");
    let (s, _) = portal(
        "tok-portal",
        &format!("{}.{sig}", b64_encode(forged.as_bytes())),
        "",
    )
    .await;
    assert_eq!(s, 401);
    // Only a portal token may use the endpoint.
    assert_eq!(portal("tok-alice", &good, "").await.0, 403);
    assert_eq!(portal("wrong", &good, "").await.0, 401);

    // The lookups are themselves recorded, with a keyed hash of the subject, never the subject.
    let entries = audit::read_entries(&zimra.dir.join("audit/log.jsonl")).unwrap();
    let lookups: Vec<String> = entries
        .iter()
        .filter_map(|e| match &e.event {
            audit::AuditEvent::Admin {
                operator,
                action,
                detail,
                ..
            } if action == "citizen_access_log" && operator == "portal1" => detail.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(
        lookups.len(),
        5,
        "only answered lookups are recorded: {lookups:?}"
    );
    assert!(lookups
        .iter()
        .all(|d| d.contains("subject_ref=") && d.contains("issuer=zimra-login")));
    assert!(!std::fs::read_to_string(zimra.dir.join("audit/log.jsonl"))
        .unwrap()
        .contains("2000987654"));
}

#[tokio::test(flavor = "multi_thread")]
async fn central_server_operators_have_roles() {
    use zroad_core::auth::Role;
    let net = Net::start().await;
    let cdir = net.tmp.path().join("central");
    let reg = central_server::add_operator(&cdir, "registrar", Role::Operator).unwrap();
    let boss = central_server::add_operator(&cdir, "boss", Role::Admin).unwrap();
    let watcher = central_server::add_operator(&cdir, "watcher", Role::Auditor).unwrap();
    assert!(
        central_server::add_operator(&cdir, "boss", Role::Admin).is_err(),
        "names are unique"
    );
    assert!(
        central_server::add_operator(&cdir, "p", Role::Portal).is_err(),
        "no portal role here"
    );

    let c = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();
    let m: MemberId = "ZW/COM/12345678".parse().unwrap();
    let err = |e: anyhow::Error| e.to_string();

    // An operator can register members but not revoke them; an auditor can do neither.
    assert!(c
        .add_member(&watcher, &m, "x", "https://127.0.0.1:1")
        .await
        .map_err(err)
        .unwrap_err()
        .contains("403"));
    assert!(c
        .add_member("guess", &m, "x", "https://127.0.0.1:1")
        .await
        .map_err(err)
        .unwrap_err()
        .contains("401"));
    c.add_member(&reg, &m, "Acme", "https://127.0.0.1:1")
        .await
        .unwrap();
    assert!(c
        .revoke(&reg, &m)
        .await
        .map_err(err)
        .unwrap_err()
        .contains("403"));
    c.revoke(&boss, &m).await.unwrap();
    // The original admin token keeps working as an admin.
    c.add_member(
        &net.admin_token,
        &"ZW/COM/99999999".parse().unwrap(),
        "Other",
        "https://127.0.0.1:2",
    )
    .await
    .unwrap();

    // Removing an operator takes effect immediately, without a restart.
    central_server::remove_operator(&cdir, "registrar").unwrap();
    assert!(c
        .add_member(
            &reg,
            &"ZW/COM/88888888".parse().unwrap(),
            "Z",
            "https://127.0.0.1:3"
        )
        .await
        .map_err(err)
        .unwrap_err()
        .contains("401"));
    assert!(central_server::remove_operator(&cdir, "registrar").is_err());

    // Who did what is on the central server's own tamper-evident record.
    let entries = audit::read_entries(&cdir.join("audit/log.jsonl")).unwrap();
    let actions: Vec<(String, String)> = entries
        .into_iter()
        .filter_map(|e| match e.event {
            audit::AuditEvent::Admin {
                operator, action, ..
            } => Some((operator, action)),
            _ => None,
        })
        .collect();
    for want in [
        ("registrar", "member_add"),
        ("boss", "member_revoke"),
        ("legacy-admin", "member_add"),
    ] {
        assert!(
            actions.contains(&(want.0.into(), want.1.into())),
            "{want:?} missing in {actions:?}"
        );
    }
    audit::verify_file(&cdir.join("audit/log.jsonl")).unwrap();
}

/// What certificate does a TLS server actually present?
async fn served_cert(addr: std::net::SocketAddr, ca_pem: &str) -> zroad_core::pki::CertInfo {
    let cfg = tls::client_config(ca_pem, None).unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let stream = tokio_rustls::TlsConnector::from(cfg)
        .connect(name, tcp)
        .await
        .unwrap();
    let der = stream.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    pki::inspect_cert_der(&der).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn central_server_renews_its_own_certificate() {
    let tmp = tempfile::tempdir().unwrap();
    let cdir = tmp.path().join("central");
    // a server certificate that is already inside the renewal window
    central_server::init_with(&cdir, &["127.0.0.1".to_string()], 2).unwrap();
    let original =
        pki::inspect_cert_pem(&std::fs::read_to_string(cdir.join("server.pem")).unwrap()).unwrap();
    let ca = std::fs::read_to_string(cdir.join("ca.pem")).unwrap();
    let h = central_server::spawn_with(
        &cdir,
        "127.0.0.1:0",
        central_server::Options {
            renew_before_days: 30,
            check_interval: Duration::from_millis(200),
        },
    )
    .await
    .unwrap();

    // The running server switches to a fresh certificate without a restart, and
    // clients that trust the CA keep working throughout.
    let mut now = served_cert(h.addr, &ca).await;
    for _ in 0..50 {
        if now.fingerprint != original.fingerprint {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        now = served_cert(h.addr, &ca).await;
    }
    assert_ne!(
        now.fingerprint, original.fingerprint,
        "certificate was replaced"
    );
    assert!(
        now.not_after - zroad_core::now_ms() as i64 / 1000 > 300 * 86_400,
        "fresh certificate is long-lived"
    );
    assert_eq!(now.member.to_string(), "ZW/SYS/central");
    assert!(cdir.join("server.pem.prev").exists());
    let client = CentralClient::new(&format!("https://{}", h.addr), &ca).unwrap();
    assert!(client.directory().await.is_ok());
    // the host names carried over
    let sans = pki::cert_sans(&std::fs::read_to_string(cdir.join("server.pem")).unwrap()).unwrap();
    assert_eq!(sans, vec!["127.0.0.1".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn timestamp_authority_renews_and_old_anchors_stay_verifiable() {
    let net = Net::start().await;
    let zimra = net.member("ZW/GOV/ZIMRA").await;

    // A second timestamp authority that renews itself two seconds after starting.
    let (tsa_id, tsa_port) = ("ZW/SYS/tsa2", free_port());
    let tsa_dir = net.tmp.path().join("tsa2");
    net.register(tsa_id, &format!("https://127.0.0.1:{tsa_port}"), &tsa_dir)
        .await;
    let _tsa = timestamp_service::spawn_with(
        &tsa_dir,
        &format!("127.0.0.1:{tsa_port}"),
        timestamp_service::Options {
            central_url: Some(net.central_url.clone()),
            renew_before_days: 400,
            check_interval: Duration::from_secs(3600),
            initial_delay: Duration::from_secs(2),
            activation_delay: Duration::ZERO,
        },
    )
    .await
    .unwrap();
    let original_key = std::fs::read_to_string(tsa_dir.join("key.pem")).unwrap();

    let mut cfg = net.config(&zimra, true);
    cfg.tsa_member = tsa_id.parse().unwrap();
    let _z = security_server::spawn(cfg).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await; // learn about the new authority
    let auth = format!("Bearer {ADMIN}");
    let anchor = || async {
        zroad_net::request(
            "POST",
            &zimra.internal("/admin/v1/anchor"),
            &[("authorization", &auth)],
            Bytes::new(),
            None,
            Duration::from_secs(20),
        )
        .await
        .unwrap()
    };
    assert_eq!(anchor().await.status, 200);

    // After it has renewed itself (new key, no restart) the authority keeps working.
    for _ in 0..60 {
        if std::fs::read_to_string(tsa_dir.join("key.pem")).unwrap() != original_key {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_ne!(
        std::fs::read_to_string(tsa_dir.join("key.pem")).unwrap(),
        original_key,
        "authority rotated its key"
    );
    let r = anchor().await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // Both anchors verify against the directory, each with the key valid when it was
    // issued, even though the authority's current key is a different one.
    let report = audit::verify_file(&zimra.dir.join("audit/log.jsonl")).unwrap();
    let anchors: Vec<_> = report
        .anchors
        .iter()
        .filter(|(_, t)| t.tsa.to_string() == tsa_id)
        .collect();
    assert_eq!(anchors.len(), 2, "{anchors:?}");
    let directory: zroad_core::directory::Directory =
        serde_json::from_slice(&std::fs::read(zimra.dir.join("directory.json")).unwrap()).unwrap();
    let rec = directory.get(&tsa_id.parse().unwrap()).unwrap();
    assert_eq!(rec.previous_certs.len(), 1);
    for (_, token) in &anchors {
        directory
            .verify_timestamp(token)
            .expect("anchor verifies across the rotation");
    }
    assert_ne!(anchors[0].1.signature_b64, anchors[1].1.signature_b64);
}

/// A node and a hosted member (with its key in a signer service) both renew
/// themselves while traffic is flowing. Nothing is restarted.
#[tokio::test(flavor = "multi_thread")]
async fn node_and_hosted_member_renew_under_traffic() {
    use security_server::config::{NodeIdentityConfig, RemoteSignerConfig};
    let net = Net::start().await;
    let node_id = "ZW/NODE/acme-hosting";
    let zimra = net.member("ZW/GOV/ZIMRA").await;
    let mut zcfg = net.config_with(&zimra, true, ADMIN, &["ZW/COM/11111111"]);
    zcfg.rotation_grace_secs = 600; // seamless rotation for peers
    let _z = security_server::spawn(zcfg).await.unwrap();

    let (node_net, node_int) = (free_port(), free_port());
    let node_dir = net.tmp.path().join("node-identity");
    net.register(node_id, &format!("https://127.0.0.1:{node_net}"), &node_dir)
        .await;

    let central = CentralClient::new(&net.central_url, &net.ca_pem).unwrap();
    let mid: MemberId = "ZW/COM/11111111".parse().unwrap();
    let tok = central
        .add_hosted_member(&net.admin_token, &mid, "Acme", &node_id.parse().unwrap())
        .await
        .unwrap();
    let signer_dir = net.tmp.path().join("signer-acme");
    enroll_to_dir(
        &net.central_url,
        &net.ca_pem,
        &mid,
        &tok.enrollment_token,
        &["127.0.0.1".into()],
        &signer_dir,
    )
    .await
    .unwrap();
    signer_service::init(&signer_dir, &["127.0.0.1".to_string()]).unwrap();
    let signer_port = free_port();
    let _signer = signer_service::spawn(signer_service::SignerConfig {
        dir: signer_dir.clone(),
        listen: format!("127.0.0.1:{signer_port}"),
        member: mid.clone(),
        node: node_id.parse().unwrap(),
        max_per_minute: 100_000,
        options: signer_service::Options {
            central_url: Some(net.central_url.clone()),
            renew_before_days: 400,
            check_interval: Duration::from_secs(3600),
            initial_delay: Duration::from_secs(5), // the member rotates its key at ~5s
            activation_delay: Duration::from_secs(2),
        },
    })
    .await
    .unwrap();
    let data = net.tmp.path().join("node-acme");
    std::fs::create_dir_all(&data).unwrap();
    for f in ["cert.pem", "ca.pem"] {
        std::fs::copy(signer_dir.join(f), data.join(f)).unwrap();
    }
    let a = Member {
        id: "ZW/COM/11111111",
        net_port: node_net,
        int_port: node_int,
        dir: data,
    };
    let mut cfg = net.config_with(&a, false, "admin-token-a-0123456789", &[]);
    cfg.remote_signer = Some(RemoteSignerConfig {
        url: format!("https://127.0.0.1:{signer_port}"),
        ca_file: signer_dir.join("signer-ca.pem"),
    });
    cfg.node_identity_dir = Some(node_dir.clone());
    cfg.renew_before_days = 400; // the node renews its own identity ...
    cfg.renew_initial_delay_secs = 3; // ... at ~3s
    cfg.rotation_grace_secs = 600;
    cfg.rotation_activation_secs = Some(2); // old certificate stays in use 2s after renewal
    let node = security_server::spawn_node(security_server::config::NodeConfig {
        members: vec![cfg],
        node_dir: net.tmp.path().join("node"),
        node_identity: Some(NodeIdentityConfig {
            member: node_id.parse().unwrap(),
            dir: node_dir.clone(),
        }),
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await; // everyone learns about the node

    let url = a.internal(&format!("/m/{}{SERVICE_PATH}", a.id));
    let call = || {
        let url = url.clone();
        async move {
            post_json(
                &url,
                &[
                    ("z-road-client", "ZW/COM/11111111/ap"),
                    ("z-road-subject", "2000123456"),
                ],
                &json!({ "tin": "2000123456" }),
            )
            .await
        }
    };
    let (s, v, headers) = call().await;
    assert_eq!((s, v["status"].as_str().unwrap()), (200, "VALID"), "{v}");
    let proof_before = read_proof(&headers);

    // Keep calling for twelve seconds while the node (~3s) and the member (~5s) rotate.
    let mut results = Vec::new();
    for _ in 0..40 {
        let (s, v, _) = call().await;
        results.push((s, v["error"].as_str().unwrap_or("").to_string()));
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let failures: Vec<_> = results.iter().filter(|(s, _)| *s != 200).collect();
    assert!(
        failures.is_empty(),
        "traffic was interrupted by renewal: {failures:?}"
    );

    // Both really rotated: new certificates in the directory, history kept, old
    // files kept, and a proof made before the rotation still verifies.
    let directory = central.directory().await.unwrap();
    for id in [node_id, "ZW/COM/11111111"] {
        let rec = directory.get(&id.parse().unwrap()).unwrap();
        assert_eq!(rec.previous_certs.len(), 1, "{id} rotated once");
    }
    assert!(node_dir.join("key.pem.prev").exists() && signer_dir.join("key.pem.prev").exists());
    directory
        .verify_proof(&proof_before)
        .expect("old proof verifies after both rotations");
    // and the new keys are the ones in use
    let (s, v, headers) = call().await;
    assert_eq!(s, 200, "{v}");
    directory.verify_proof(&read_proof(&headers)).unwrap();
    node.shutdown();
}
