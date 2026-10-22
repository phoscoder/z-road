# Running Z-Road

This covers running the proof of concept. For production, read the
[threat model](threat-model.md) first: several hardening items are still open.

## Quick start

```sh
scripts/demo.sh
```

starts a central server, a timestamp authority, a mock ZIMRA clearance system and
two security servers on localhost, makes two clearance checks, verifies the signed
proof offline, shows the citizen's access view and verifies the timestamped audit
log. Everything lives under `/tmp/zroad-demo`.

## Setting up a network by hand

### 1. The central server (authority)

```sh
central-server init --dir ./central --san central.example.zw   # CA, TLS identity, admin token
central-server run  --dir ./central --listen 0.0.0.0:8443
```

`init` writes `ca.pem` (public, give it to every member), `ca.key` and
`admin_token` (secret). Back them up offline.

### 2. Register and enrol a member

On the authority side:

```sh
zroad-cli member-add --central https://central.example.zw:8443 --ca ca.pem \
  --admin-token-file ./central/admin_token \
  --id ZW/GOV/ZIMRA --name "ZIMRA" --endpoint https://ss.zimra.example.zw:7443
# prints a one-time enrolment token
```

On the member's side, with the token and `ca.pem` obtained out of band:

```sh
zroad-cli enroll --central https://central.example.zw:8443 --ca ca.pem \
  --id ZW/GOV/ZIMRA --token <token> --san ss.zimra.example.zw --out ./zimra
```

This writes `key.pem` (private), `cert.pem` and `ca.pem` into `./zimra`. The
`--san` must match the host in the registered endpoint.

Register and enrol the timestamp authority the same way, as `ZW/SYS/tsa`, then:

```sh
timestamp-service --dir ./tsa --listen 0.0.0.0:8445
```

### 3. Configure and run a security server

```toml
member_id        = "ZW/GOV/ZIMRA"
data_dir         = "zimra"                       # holds key.pem, cert.pem, ca.pem; state is written here
central_url      = "https://central.example.zw:8443"
network_listen   = "0.0.0.0:7443"                # mutual TLS, other members connect here
internal_listen  = "127.0.0.1:7002"              # plain HTTP, your own systems only
# operators are named, with roles and their own tokens (see access-control.md)
[[operators]]
name         = "alice"
role         = "operator"
token_sha256 = "…"     # from `zroad-cli operator-token`

# optional
internal_token         = "..."   # require Authorization: Bearer on the internal API
tsa_member             = "ZW/SYS/tsa"
directory_refresh_secs = 30
anchor_interval_secs   = 60      # 0 disables timestamp anchoring
rate_limit_per_sec     = 50      # per calling member
max_body_bytes         = 2097152
upstream_timeout_secs  = 15
outbox_max_attempts    = 20
rotation_activation_secs = 65     # keep the old certificate this long after renewing (default: 2 x directory refresh + 5)
rotation_grace_secs    = 600     # peers accept the previous certificate this long after a rotation
renew_before_days      = 30      # renew the certificate automatically; 0 = off (warns instead)

# a provider lists its services and who may use each one (default deny)
[[services]]
id       = "tax-clearance/verify/v1"
upstream = "http://10.0.0.5:9001/verify"
title    = "Tax clearance check"       # shown in the public catalogue (optional)
description = "Is this TIN cleared? Returns status and expiry only."
request_schema  = "schemas/verify.request.json"    # JSON Schema files (optional)
response_schema = "schemas/verify.response.json"
enforce_response_schema = false                    # true: withhold non-conforming answers

[[access]]
service = "tax-clearance/verify/v1"
allow   = ["ZW/COM/*"]              # or ZW/COM/12345678, or ZW/COM/12345678/accounts-payable
```

```sh
security-server check-config --config zimra.toml
security-server run --config zimra.toml
```

A pure consumer has no `[[services]]` or `[[access]]`.

## Shared nodes

One security server process can host several members, for example an accounting
vendor serving its small customers. Each member is enrolled separately (own key,
own certificate, same endpoint host) and keeps its own state. Use a node file:

```toml
central_url     = "https://central.example.zw:8443"
network_listen  = "0.0.0.0:7443"
internal_listen = "10.0.0.5:7001"
node_dir        = "node"                  # directory cache

[[members]]
member_id   = "ZW/COM/11111111"
data_dir    = "acme"
admin_token = "a-long-random-token-for-acme"
internal_token = "another-token-for-acme-systems"

[[members]]
member_id   = "ZW/COM/22222222"
data_dir    = "bravo"
admin_token = "a-different-long-token-for-bravo"
```

Each member's internal API lives under its own prefix:
`/m/ZW/COM/11111111/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1`, with admin
endpoints at `/m/ZW/COM/11111111/admin/v1/...`. Tokens, audit logs, outboxes,
proofs and access rules are per member, and a member's internal API only accepts
its own `Z-Road-Client` subsystems. Members must not share a `data_dir` or an
admin token (startup refuses). The operator holds every hosted member's private
key, so the operator can sign as them: only use this where the legal agreement
between member and operator says so. A single-member file in the original format
still works, and a single-member node also serves the unprefixed paths.

## Member-held keys on a shared node

If a hosted member must not give the operator its key, run a signer on its own
machine and let the operator's node carry the traffic. The steps:

1. **Authority:** enrol the node as a member of its own (`ZW/NODE/<name>`, a normal
   `member-add` and `enroll`, with the node's endpoint). Then register each hosted
   member against it:
   `zroad-cli member-add ... --id ZW/COM/11111111 --name "Acme" --hosted-by ZW/NODE/acme-hosting`
   (the endpoint is taken from the node).
2. **Hosted member, on its own machine:** enrol to obtain its key and certificate,
   using the node's host name as the SAN, then create the signer's TLS identity and run it:

   ```sh
   zroad-cli enroll --central https://central.example.zw:8443 --ca ca.pem \
     --id ZW/COM/11111111 --token <token> --san node.example.zw --out ./signer
   signer-service init --dir ./signer --san signer.acme.example
   signer-service run  --dir ./signer --listen 0.0.0.0:9443 \
     --member ZW/COM/11111111 --node ZW/NODE/acme-hosting
   ```

   Send the node's operator only `signer/cert.pem`, `signer/ca.pem` and
   `signer/signer-ca.pem`. **Never** `key.pem`.
3. **Node operator:** add the node identity and the member to the node file. The
   member's `data_dir` holds only `cert.pem` and `ca.pem`; startup refuses if a
   `key.pem` is there.

   ```toml
   node_member   = "ZW/NODE/acme-hosting"
   node_data_dir = "node-identity"          # key.pem, cert.pem, ca.pem of the node member

   [[members]]
   member_id   = "ZW/COM/11111111"
   data_dir    = "acme"                      # cert.pem + ca.pem only
   admin_token = "a-long-random-token-for-acme"
   remote_signer = { url = "https://signer.acme.example:9443", ca_file = "acme-signer-ca.pem" }
   ```

The signer writes `audit/log.jsonl` with one `signed` entry per signature. Check
it with `zroad-cli audit-verify --log ./signer/audit/log.jsonl`, and compare it
with what the node reports. Run the signer with `--central https://central.example.zw:8443` and it
renews the member's key and its own TLS certificate by itself; the node follows the new
key through the directory. The node renews its own identity automatically too.

## Calling a service

Application developers: see [integration.md](integration.md). The essentials:

From the consumer's own systems:

```sh
curl -X POST http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1 \
  -H 'Z-Road-Client: ZW/COM/12345678/accounts-payable' \
  -H 'Z-Road-Subject: 2000123456' \
  -H 'Content-Type: application/json' \
  -d '{"tin":"2000123456"}'
```

Add `-H 'Z-Road-Mode: async'` to queue the request when the provider might be
unreachable, then `GET /internal/v1/outbox/<message_id>`.

The response carries a `Z-Road-Proof` header. `zroad-cli proof-verify --proof
proof.json --directory <data_dir>/directory.json` checks it offline.

## Operations

| Task | How |
| --- | --- |
| Verify an audit log | `zroad-cli audit-verify --log <data_dir>/audit/log.jsonl --directory <data_dir>/directory.json` |
| Check the log through a running server | `GET /admin/v1/audit/status` (admin token) |
| Force a timestamp anchor | `POST /admin/v1/anchor` |
| Force a directory refresh | `POST /admin/v1/directory/refresh` |
| Revoke a member | `zroad-cli member-revoke …` (final) |
| See who looked up a subject | `zroad-cli access-log --security-server http://127.0.0.1:7002 --admin-token <auditor token> --subject 2000123456` (auditor or higher; the lookup is recorded) |
| Fetch a stored proof | `GET /admin/v1/proofs/<message_id>` |
| Renew a certificate now | `POST /admin/v1/renew` on a running security server (automatic when under `renew_before_days`; it returns once the new certificate is live, after the activation delay). Offline alternative: `zroad-cli renew --central … --dir … --san …`, then restart |
| See what the network offers | `zroad-cli catalogue --central https://central.example.zw:8443 --ca ca.pem` (add `--schemas` to print the JSON Schemas) |
| Republish your services now | `POST /admin/v1/catalogue/publish` |
| Add an operator | `zroad-cli operator-token --name alice --role operator`, add the printed `[[operators]]` entry, restart (central: `central-server operator-add`, no restart) |
| Let a citizen portal in | role `portal` token plus `[[citizen_assertion_keys]]`; see [access-control.md](access-control.md) |
| Check certificate expiry | `GET /admin/v1/identity` (a warning is also logged under 30 days) |
| Demo citizen page | `citizen-portal --security-server … --portal-token … --provider ZW/GOV/ZIMRA --demo-idp-key idp.key` (demo only: the demo key lets it vouch for anyone) |

### What to back up

* `key.pem`, `cert.pem`, `subject.key`: losing `subject.key` makes old log entries unsearchable by subject.
* `audit/log.jsonl`: the accountability record. Archive copies regularly; anchors make later tampering detectable.
* `outbox/`: queued requests and their results.
* For the central server: `ca.key`, `admin_token`, `state.json`.

### Production checklist (not yet met by the proof of concept)

* Keep the CA root offline, issue member certificates from an HSM-backed intermediate.
* Put the internal listener on a private interface, set `internal_token`.
* Run the network listener behind a firewall that allows only members' addresses where possible.
* Give each service a least-privilege upstream credential rather than an open URL.
* Renewal is automatic (365-day certificates, renewed 30 days out) for security servers, nodes, signers (`--central`), the timestamp authority (`--central`) and the central server's own certificate. Alert on `cannot renew` / `renewal failed` log lines.
* The **root CA** is valid for ten years and is not rotated automatically: the central server warns in its log within a year of expiry. Plan a CA rotation then (every member must be given the new `ca.pem`).
* Rotation tuning (security server config): `renew_before_days` (30), `rotation_activation_secs` (default twice the directory refresh interval plus 5 seconds: how long the old certificate stays in use after renewal so peers can learn the new one) and `rotation_grace_secs` (600: how long peers keep accepting the previous certificate). Keep the grace longer than the activation delay plus the directory refresh interval.
* Ship audit logs and the directory to append-only storage.
