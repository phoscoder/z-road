# Data provider guide

*You are an agency or company that offers a service to others, such as ZIMRA's tax-clearance check.
You keep your data; Z-Road carries the question and the signed answer.*

![Journey of one request](../diagrams/request-journey.svg)

## What you will have at the end

- A **security server** on your own machine, with a certificate issued to you.
- One or more **services** published in the catalogue, each with a schema.
- **Access rules** saying exactly who may call each service.
- An **audit log** of every call, and proofs you can hand to a court or auditor.

## Before you start

| You need | From |
| --- | --- |
| A Linux host (2 CPU, 2 GB RAM is plenty) with a public name, e.g. `ss.zimra.example.zw` | Your IT team |
| An existing internal system that can answer the question over HTTP | Your developers |
| A one-time enrolment token and `ca.pem` | The authority ([they verify you first](authority-operator.md)) |
| Written permission to share this data | Your legal team |

## Steps

1. **Harden the host and install**, following [02 · Deploy securely](../02-deploy-securely.md) §1–§2.
2. **Enrol** (§4.2 there): `zroad-cli enroll … --san <your host> --out /var/lib/zroad/<name>`.
3. **Describe your service.** Write a JSON Schema for the request and for the answer. See [03 · Building a service](../03-building-a-service.md): it walks through a complete example.
4. **Configure**: `[[services]]` (the upstream URL and schemas) and `[[access]]` (who may call), as in §4.4.
5. **Check and start**:

   ```sh
   security-server check-config --config /etc/zroad/zimra.toml
   sudo systemctl enable --now zroad-security-server@zimra
   ```
6. **Confirm it is listed**: `zroad-cli catalogue --central https://central.example.zw:8443 --ca ca.pem`.
7. **Test with a friendly consumer**, then open to others.

## Access: you decide, and the default is no

```toml
[[access]]
service = "tax-clearance/verify/v1"
allow   = ["ZW/COM/*", "ZW/BANK/CBZ"]       # wildcards are deliberate; be as narrow as you can
```

A caller that is a valid member but not listed gets `access_denied`. Changing rules means editing and
restarting; the change is visible to auditors.

## Protect your own system

- Let **only the security server** reach your upstream (firewall it).
- Give the upstream a least-privilege credential; the security server does not need write access.
- Publish a **response schema** and set `enforce_response_schema = true`: if your system returns something unexpected, Z-Road returns `upstream_schema_violation` instead of leaking it.
- Treat the `Z-Road-Subject` header as a hint, not as authentication. Callers vouch for the subject; **you** authorise what they may ask.

## Day to day

Follow the [operations runbook](../05-operations-runbook.md). The points that matter most to you:

| Task | How |
| --- | --- |
| See who called what | The audit log; `zroad-cli audit-verify …` |
| Prove an answer | `GET /admin/v1/proofs/<id>` then `zroad-cli proof-verify` |
| Tell a person who looked at their record | `zroad-cli access-log … --subject <id>`; for self-service see [citizen portal](citizen-portal-developer.md) |
| Cut a caller off at once | Remove from `[[access]]` and restart (and ask the authority to revoke if it is a security matter) |
| Change a service | New **version** (`v2`) for breaking changes; keep `v1` running until callers move |

## Versioning rule of thumb

Adding an optional field is not breaking. Removing or renaming a field, or changing its meaning, is.
Publish `v2` beside `v1`, announce a date, then retire `v1`.

## If something goes wrong

[Troubleshooting](../07-troubleshooting.md) for messages; [incident response](../06-incident-response.md)
for security events.

[← All guides](../README.md) · [Security checklist](../08-security-checklist.md)
