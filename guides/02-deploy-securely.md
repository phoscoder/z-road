# 02 · Set up and deploy Z-Road securely

*For the people who install and run it. About two hours for a first node if the hosts exist.*

This guide takes you from "we have some servers" to "we are on the network, and we would
be comfortable showing this setup to a security reviewer". Do the steps in order. Each ends with a
check so you know it worked.

> **Status.** Z-Road has **not** had an independent security review. Follow this guide for a
> pilot or lab. Do not carry real personal data until the [pilot gate](../ROADMAP.md#phase-6-pilot--gated) is met.

## What you are building

![A secure layout for one node](diagrams/secure-topology.svg)

Three rules shape everything below:

1. **One port faces other organisations** (the mutual-TLS port, 7443 by default). Everything else stays private.
2. **Every private key is a secret with one owner.** It is made where it will be used and never copied around.
3. **Everything privileged leaves a record**, and the record is checked.

## 0 · Decide first

| Decision | Example | Notes |
| --- | --- | --- |
| Who is the **authority**? | A named ministry or a neutral operator | One organisation, accountable for the central server and the root CA |
| **Instance code** | `ZW` | The first part of every id |
| **Member classes** | `GOV` agencies, `COM` companies, `SYS` infrastructure, `NODE` shared nodes | You may add classes; ids are `instance/class/code` |
| **Host names** | `central.example.zw`, `tsa.example.zw`, `ss.zimra.example.zw` | Each certificate is tied to the host name in the member's registered endpoint |
| **Time source** | NTP from two reliable servers | Messages are rejected if clocks differ by more than 5 minutes |
| **Who is allowed to do what** | Named operators with roles | Auditor, operator, admin. See [access control](../docs/access-control.md) |

## 1 · Prepare each host

Do this on **every** machine (central server, timestamp authority, each security server, each signer).

**Operating system**

- A current, supported Linux (Debian/Ubuntu LTS or similar). Automatic security updates on.
- Nothing else on the machine that you don't need. The central server and its CA key deserve a machine of their own.
- **Disk encryption** for any machine holding keys; the key is the secret, so a stolen disk must be useless.
- SSH by key only, no root login, access through a bastion or VPN, personal accounts (no shared logins).

**Time**

```sh
sudo apt install chrony
chronyc tracking        # offset should be milliseconds
```

**A service user and directories**

```sh
sudo deploy/systemd/install.sh        # creates user `zroad`, /etc/zroad, installs binaries and units
sudo install -d -m 0700 -o zroad -g zroad /var/lib/zroad
```

**Firewall (default deny).** Example with `ufw` for a provider's security server:

```sh
sudo ufw default deny incoming
sudo ufw allow from <admin-bastion-ip> to any port 22 proto tcp
sudo ufw allow from <member-range> to any port 7443 proto tcp     # other organisations, mutual TLS
sudo ufw allow from <app-subnet>   to any port 7002 proto tcp     # your own applications (internal listener)
sudo ufw enable
```

| Component | Port | Who may reach it |
| --- | --- | --- |
| Security server, network listener | 7443 | Other members only (allow-list their addresses if you can) |
| Security server, internal listener | 7001/7002 | **Your own applications and operators only. Never the internet.** |
| Central server | 8443 | Members and the authority's operators (the directory is public by design) |
| Timestamp authority | 8445 | Members |
| Signer service | 9443 | **Only the hosting node's address** |

> **Warning: do not terminate TLS in front of the security server.** The network port uses
> *mutual* TLS and reads the caller's certificate to know who is calling. A normal HTTPS reverse
> proxy would hide it and break identity. If you put anything in front, use pure TCP pass-through
> (nginx `stream`, HAProxy `mode tcp`) for connection limits and filtering.

## 2 · Key custody: protecting the secrets

![Who holds which key](diagrams/keys-and-trust.svg)

**The rules**

- Generate each key **on the machine that will use it** (the enrol command does this). Never create a member's key somewhere else and copy it.
- Private keys are files owned by the service user with mode `0600` and live under `/var/lib/zroad/<name>`. The installer and the units already enforce `UMask=0077`.
- Never put a key, token or `ca.key` in git, a chat, a ticket, a container image or a backup that is not encrypted.
- Operator tokens are shown **once**; store them in a password manager or vault. Only their hashes go into config files.

**The root CA key: the one that matters most**

Whoever holds `ca.key` can create an identity for any member. Today `central-server` reads it
from `/var/lib/zroad/central/ca.key` while running, so protect that machine like a vault:

- a dedicated machine (or VM) used for nothing else, encrypted disk, tightly limited admin access;
- an encrypted, offline, **tested** backup of the whole central directory, kept in two places;
- review access to it, and log everyone who logs in.

> **What an HSM would change.** A hardware security module (HSM) is a tamper-resistant device that holds a
> key and signs inside itself so the key can never be copied. The plan ([roadmap](../ROADMAP.md))
> is an **offline root CA key in an HSM or hardware token** that signs a short-lived online intermediate,
> so even a fully compromised central server cannot mint a lasting identity. Until that ships, the
> mitigations above are what you have, and the incident plan for a CA compromise is in
> [06 · Incident response](06-incident-response.md#the-ca-key-is-exposed).

## 3 · The authority: central server and timestamp authority

*Done once, by the authority operator. See also [Authority operator](users/authority-operator.md).*

**3.1 Create the CA and the central server**

```sh
sudo -u zroad central-server init --dir /var/lib/zroad/central --san central.example.zw
```

This writes `ca.pem` (public: give it to every member), `ca.key` (**secret**), the server's own
TLS identity, and an `admin_token` file. The server certificate is valid for a year and is
**renewed automatically**.

**3.2 Create named operators; stop using the shared token**

```sh
sudo -u zroad central-server operator-add --dir /var/lib/zroad/central --name alice --role admin     # prints her token once
sudo -u zroad central-server operator-add --dir /var/lib/zroad/central --name bob   --role operator
sudo -u zroad central-server operator-add --dir /var/lib/zroad/central --name audit --role auditor
```

Roles on the central server: `operator` registers members, `admin` can also revoke them, `auditor`
is read-only. The original `admin_token` file still works as an admin named `legacy-admin`. Once alice works,
overwrite its contents with a fresh random value that you never use and restart the server:
`head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | sudo -u zroad tee /var/lib/zroad/central/admin_token >/dev/null`.

**3.3 Start it under systemd**

```sh
sudo systemctl enable --now zroad-central
```

**3.4 Register and start the timestamp authority**

```sh
# on the central server (or any machine with the CA file and an operator token)
echo "<alice's token>" > /tmp/alice.token && chmod 600 /tmp/alice.token
zroad-cli member-add --central https://central.example.zw:8443 --ca ca.pem \
  --admin-token-file /tmp/alice.token \
  --id ZW/SYS/tsa --name "Timestamp Authority" --endpoint https://tsa.example.zw:8445
# prints a one-time enrolment token; then, ON THE TSA MACHINE:
zroad-cli enroll --central https://central.example.zw:8443 --ca ca.pem \
  --id ZW/SYS/tsa --token <token> --san tsa.example.zw --out /var/lib/zroad/tsa
sudo systemctl enable --now zroad-timestamp       # runs with --central: renews itself
shred -u /tmp/alice.token
```

**Check**

```sh
zroad-cli directory --central https://central.example.zw:8443 --ca ca.pem | head
```

You should see `ZW/SYS/tsa` with `"status": "active"`.

## 4 · Each organisation: a security server

*Done by every provider and consumer, on their own machine. See [Data provider](users/provider.md)
or [Consumer developer](users/consumer-developer.md).*

**4.1 Get your enrolment token from the authority**

The authority runs `zroad-cli member-add ... --id <your id> --endpoint https://<your host>:7443`
and gives you **the token** and **`ca.pem`**, through different channels (for example the
token by phone or in person). The token works once.

**4.2 Enrol: generate your own key and receive your certificate**

```sh
sudo -u zroad zroad-cli enroll --central https://central.example.zw:8443 --ca ca.pem \
  --id ZW/GOV/ZIMRA --token <token> --san ss.zimra.example.zw --out /var/lib/zroad/zimra
```

The `--san` **must** equal the host in your registered endpoint. The key never leaves this machine.

**4.3 Create your operators**

```sh
zroad-cli operator-token --name zimra-ops   --role operator
zroad-cli operator-token --name zimra-audit --role auditor
```

Each prints a token once (give it to that person) and the `[[operators]]` entry for your config.

**4.4 Write the configuration** (`/etc/zroad/zimra.toml`)

```toml
member_id       = "ZW/GOV/ZIMRA"
data_dir        = "/var/lib/zroad/zimra"
central_url     = "https://central.example.zw:8443"
network_listen  = "0.0.0.0:7443"          # other members connect here (mutual TLS)
internal_listen = "10.0.0.5:7002"         # your own systems only: a PRIVATE address
internal_token  = "<long random string>"  # applications send it as Authorization: Bearer
anchor_interval_secs = 60                 # timestamp the audit log every minute

[[operators]]
name = "zimra-ops"
role = "operator"
token_sha256 = "…"

[[operators]]
name = "zimra-audit"
role = "auditor"
token_sha256 = "…"

[[services]]
id       = "tax-clearance/verify/v1"
upstream = "http://10.0.0.9:9001/verify"
title    = "Tax clearance check"
request_schema  = "/etc/zroad/schemas/verify.request.json"
response_schema = "/etc/zroad/schemas/verify.response.json"
enforce_response_schema = true

[[access]]
service = "tax-clearance/verify/v1"
allow   = ["ZW/COM/*"]                    # default is deny: say who may call
```

A pure consumer has no `[[services]]` or `[[access]]`. Do **not** set the old `admin_token`.
Lock the file: `sudo chown root:zroad /etc/zroad/zimra.toml && sudo chmod 640 /etc/zroad/zimra.toml`.

**4.5 Check and start**

```sh
security-server check-config --config /etc/zroad/zimra.toml
sudo systemctl enable --now zroad-security-server@zimra
journalctl -u zroad-security-server@zimra -f
```

**Check** (from a machine that may reach the internal listener)

```sh
curl -fs http://10.0.0.5:7002/health                                  # ok
zroad-cli catalogue --central https://central.example.zw:8443 --ca ca.pem   # your service is listed
```

## 5 · Shared nodes and hosted members

If you run a node for others, or you are a small organisation that keeps its own key on a vendor's
node, use [Node operator](users/node-operator.md) and [Hosted member](users/hosted-member.md).
The key rule: a hosted member's private key stays on **its own** machine, in a signer service.

## 6 · Verify the whole thing

Do this before you call it live.

| Check | Command | Expect |
| --- | --- | --- |
| Directory shows you active | `zroad-cli directory --central … --ca ca.pem` | `"status": "active"` |
| Your port is the only one open | `nmap -p- <your host>` from outside | only 7443 (and 22 from the bastion) |
| The internal listener is private | `curl http://<public-ip>:7002/health` from outside | connection refused or timeout |
| A test call works | `curl … /r1/<service>` (see [consumer guide](users/consumer-developer.md)) | `200` and a `Z-Road-Proof` header |
| The proof verifies offline | `zroad-cli proof-verify --proof p.json --directory <data_dir>/directory.json` | `VALID` |
| The log verifies | `zroad-cli audit-verify --log <data_dir>/audit/log.jsonl --directory <data_dir>/directory.json` | `chain OK` and anchors OK |
| Roles work | an auditor token on `POST /admin/v1/anchor` | `403` |
| Certificates will renew | `curl -H "Authorization: Bearer <auditor>" http://…:7002/admin/v1/identity` | `certificate_days_left` about 365 |

Then work through the [security checklist](08-security-checklist.md).

## 7 · Day 2: logs, monitoring, backups

Full detail is in [05 · Operations runbook](05-operations-runbook.md). The minimum:

- **Watch** the journal for: `cannot renew`, `renewal failed`, `audit log … corrupt`, `refusing to start`,
  `could not publish the catalogue`, `central server unreachable`, `could not anchor`.
- **Probe** `/health` and `/admin/v1/audit/status` (`"verified": true`) every minute.
- **Back up** (encrypted, off the machine): `key.pem`, `cert.pem`, `ca.pem`, `subject.key`,
  `audit/`, `outbox/`, `proofs/`, your config. **Test a restore** before you rely on it.

## 8 · Upgrading

```sh
git pull && cargo build --release --workspace
sudo deploy/systemd/install.sh target/release     # new binaries and units
security-server check-config --config /etc/zroad/zimra.toml
sudo systemctl restart zroad-security-server@zimra
```

Restart one node at a time. The audit log and state formats are forward-compatible within a
release series; read the release notes before a major upgrade.

## Common mistakes

| Mistake | Why it hurts | Instead |
| --- | --- | --- |
| Putting the internal listener on `0.0.0.0` | Anyone who can reach it acts as your applications | Bind a private address and set `internal_token` |
| Terminating mutual TLS in a proxy | Callers can't be identified | TCP pass-through only |
| Reusing one admin token for everyone | No accountability, can't remove one person | One named operator each |
| Copying `key.pem` to a new server | Two places hold your identity | Re-enrol: ask the authority for a new token |
| No backup of `ca.key` (authority) | Losing it means re-issuing every identity | Encrypted offline backup, tested |
| Enrolment token and `ca.pem` sent together | An eavesdropper can enrol as you | Different channels |
| Wrong `--san` | The certificate is refused | Must match the registered endpoint host |
| Clocks drifting | Requests rejected as `stale_request` | chrony, alert on offset |
| Leaving the old `admin_token` | A shared secret that never rotates | Remove it once named operators exist |

## Next

[Security checklist](08-security-checklist.md) · [Operations runbook](05-operations-runbook.md) ·
[Incident response](06-incident-response.md)
