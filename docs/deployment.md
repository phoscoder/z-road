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
admin_token      = "at-least-16-characters-long"

# optional
internal_token         = "..."   # require Authorization: Bearer on the internal API
tsa_member             = "ZW/SYS/tsa"
directory_refresh_secs = 30
anchor_interval_secs   = 60      # 0 disables timestamp anchoring
rate_limit_per_sec     = 50      # per calling member
max_body_bytes         = 2097152
upstream_timeout_secs  = 15
outbox_max_attempts    = 20

# a provider lists its services and who may use each one (default deny)
[[services]]
id       = "tax-clearance/verify/v1"
upstream = "http://10.0.0.5:9001/verify"

[[access]]
service = "tax-clearance/verify/v1"
allow   = ["ZW/COM/*"]              # or ZW/COM/12345678, or ZW/COM/12345678/accounts-payable
```

```sh
security-server check-config --config zimra.toml
security-server run --config zimra.toml
```

A pure consumer has no `[[services]]` or `[[access]]`.

## Calling a service

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
| See who looked up a subject | `zroad-cli access-log --security-server http://127.0.0.1:7002 --admin-token … --subject 2000123456` |
| Fetch a stored proof | `GET /admin/v1/proofs/<message_id>` |

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
* Monitor certificate expiry (certificates are valid for 365 days; there is no automatic renewal yet).
* Ship audit logs and the directory to append-only storage.
