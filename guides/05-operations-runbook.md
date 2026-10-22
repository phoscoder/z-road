# 05 · Operations runbook

*For the people who keep a Z-Road node running: security-server operators, node operators and the
authority's operators. Pair it with [02 · Deploy securely](02-deploy-securely.md).*

Admin calls below use an operator token on the **internal** listener, for example:

```sh
export SS=http://10.0.0.5:7002
export TOK=zroad_…            # your own named operator token; never share it
curl -s -H "Authorization: Bearer $TOK" $SS/admin/v1/identity
```

Who may do what is in [roles-and-access](diagrams/roles-and-access.svg): **auditor** reads,
**operator** may also trigger actions, **admin** may also manage, **portal** only serves citizens.

## Daily, weekly, monthly

| When | Task | How |
| --- | --- | --- |
| **Continuously** | Probe health | `GET /health` returns `ok` |
| **Continuously** | Probe the audit log | `GET /admin/v1/audit/status` shows `"verified": true`; alert otherwise |
| **Daily** | Read the warnings | `journalctl -u zroad-security-server@NAME -p warning --since yesterday` |
| **Daily** | Check certificate life | `GET /admin/v1/identity` → `certificate_days_left` (alert under 30; auto-renewal should keep it near 365) |
| **Weekly** | Verify the log and its anchors from a copy | `zroad-cli audit-verify --log log.jsonl --directory directory.json` |
| **Weekly** | Review who has access | `[[access]]` rules, operator list; remove leavers |
| **Monthly** | Restore test | Restore last backup to a scratch machine and start it with `check-config` |
| **Monthly** | Patch the OS and update Z-Road | See *Upgrading* in the deploy guide |
| **Quarterly** | Rotate operator tokens; review the [security checklist](08-security-checklist.md) | `operator-token`, then replace the config entry |

## Health at a glance

```sh
curl -s -H "Authorization: Bearer $TOK" $SS/admin/v1/identity
curl -s -H "Authorization: Bearer $TOK" $SS/admin/v1/audit/status
```

| Look for | Healthy | Act if |
| --- | --- | --- |
| `/health` | `ok` | Service down: `systemctl status`, `journalctl -u … -n 100` |
| `audit/status` | `verified: true`, entries growing | `verified: false` is serious: see [incident response](06-incident-response.md) |
| `identity` | `certificate_days_left` large | Under 30: `renew_failed`; see below |
| Anchors | recent timestamp anchors | Missing: the timestamp service is unreachable |
| Disk | under 80% | Grow the disk before the audit log cannot be written (the node then **stops serving**, by design) |

## Routine tasks

### Add or remove an operator

```sh
zroad-cli operator-token --name alice --role operator     # token shown once; add the entry to the config
sudo systemctl restart zroad-security-server@NAME           # or the unit your node uses
```

Remove a person by deleting their `[[operators]]` entry and restarting. The central server uses
`central-server operator-add/operator-remove/operator-list` the same way.

### Change who may call a service

Edit `[[access]]` (default is deny), run `security-server check-config --config …`, restart.
Changes are visible to auditors in the log's `Admin` entries.

### Publish or change a service

Edit `[[services]]` and the schemas, run `check-config`, restart, then confirm it appears with
`zroad-cli catalogue --central … --ca ca.pem`. To republish without restarting:
`POST /admin/v1/catalogue/publish` (operator).

### Refresh the member directory now

`POST /admin/v1/directory/refresh` (operator). Normally automatic.

### Force a timestamp anchor now

`POST /admin/v1/anchor` (operator).

### Look at one exchange

`GET /admin/v1/proofs/<message-id>` (auditor) returns the stored proof. Verify it offline with
`zroad-cli proof-verify --proof p.json --directory directory.json`.

### Who looked at this person's data?

```sh
zroad-cli access-log --security-server $SS --admin-token "$TOK" --subject 2000123456
```

## Certificates and rotation

![How a certificate is replaced without dropped calls](diagrams/rotation-timeline.svg)

Security servers renew **by themselves** as the certificate nears expiry: they get the new one, keep
using the old one for a short activation delay (so every peer learns the new one), then switch. Peers
accept the previous certificate for `rotation_grace_secs` (default 10 minutes).

| Situation | Do |
| --- | --- |
| Renew now (planned) | `POST /admin/v1/renew`, or `zroad-cli renew --central … --dir <data_dir> --san <host>` (restarts the server) |
| `renew_failed` in the log | Check the central server is reachable and your certificate has not already expired. If it expired, re-enrol with a new token from the authority |
| Key is suspected stolen | Do **not** wait: see [06 · Incident response](06-incident-response.md) |

Central and timestamp services renew too; watch for the same warnings in their journals.

## Backups

| What | Where | How often | Notes |
| --- | --- | --- | --- |
| `key.pem`, `cert.pem`, `ca.pem`, `subject.key` | `data_dir` | After enrol/renew | Encrypted, off the machine, tightly controlled. Anyone with `key.pem` is you |
| `audit/` | `data_dir/audit` | Hourly or continuous | The audit log is evidence. Ship it somewhere append-only |
| `outbox/`, `proofs/` | `data_dir` | Daily | Queued work and stored proofs |
| Config and schemas | `/etc/zroad` | On change | Keep in version control (without secrets) |
| **Authority only:** `ca.key` | central `data_dir` | Once, offline | Losing it means re-issuing every identity; leaking it means total compromise |

**A backup you have not restored is a hope.** Restore to a scratch machine each month and start it
with `check-config` and `audit-verify`.

## Restarts and what to expect

- Restarting is safe at any time. Queued (async) work survives. Replay protection is **rebuilt from the audit log**, so an in-flight retry after a restart is answered `already_processed` rather than run twice.
- If the audit log cannot be opened or fails its own check, the server **refuses to start**: that is protection, not a bug. See troubleshooting.
- Restart nodes one at a time. Peers retry on `Retry-After`.

## Capacity and limits

Rate limiting and body size limits are enforced (`rate_limited`, `too_large`). If legitimate callers
hit them, raise the limits in the config deliberately and note why. Watch for sudden spikes: they are
either a bug in a consumer or an attack.

## Handover checklist (when an operator leaves)

- [ ] Remove their operator token and restart
- [ ] Rotate any shared secret they knew (`internal_token`, signer tokens)
- [ ] Remove their SSH and sudo access
- [ ] Review the audit log's `Admin` entries for their last month

## Next

[Incident response](06-incident-response.md) · [Troubleshooting](07-troubleshooting.md) ·
[Security checklist](08-security-checklist.md)
