# 03 · Building a service

*For developers at a provider organisation: you have data or a function and want other
organisations to use it safely.*

You do **not** write any Z-Road protocol code. You write an ordinary HTTP endpoint inside your
network; your security server turns it into a service on the network, with identity, access
control, validation, logging and proofs around it.

```
other members ──mTLS──▶ your security server ──plain HTTP──▶ YOUR ENDPOINT ──▶ your data
```

## 1 · Design the question

The best services answer **one narrow question** and return **no more than needed**.

| Good | Not good |
| --- | --- |
| "Is this TIN cleared? → status, expiry" | "Give me this taxpayer's record" |
| "Is this person a registered voter in ward 7? → yes/no" | "List registered voters" |
| "Verify this company registration number → name, status" | "Search companies by name" (bulk) |

Why it matters: a narrow answer is easier to justify in law, safe to offer widely, and cheap to
audit. A clearance check can be open to every registered company; a full tax return would not be.
Take the [legal checklist](../docs/legal-considerations.md) to your lawyer **per service** before you publish.

Pick a stable **name and version**: `subsystem/service/version`, for example `tax-clearance/verify/v1`.
The full id is `ZW/GOV/ZIMRA/tax-clearance/verify/v1`. Never change a published version's meaning; add `v2`.

## 2 · Write the contract (JSON Schema)

Describe the request and the answer. The security server enforces the request schema before your code
runs, and checks the answer against the response schema.

`schemas/verify.request.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Tax clearance check: request",
  "type": "object",
  "required": ["tin"],
  "additionalProperties": false,
  "properties": {
    "tin": { "description": "Taxpayer Identification Number: ten digits.", "type": "string", "pattern": "^[0-9]{10}$" }
  }
}
```

`schemas/verify.response.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Tax clearance check: answer",
  "type": "object",
  "required": ["tin", "name", "status", "valid_until"],
  "additionalProperties": false,
  "properties": {
    "tin": { "type": "string", "pattern": "^[0-9]{10}$" },
    "name": { "type": "string" },
    "status": { "enum": ["VALID", "EXPIRED", "REVOKED"] },
    "valid_until": { "type": ["string", "null"], "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" }
  }
}
```

Tips:

- Use `additionalProperties: false` and tight patterns. The tighter the request schema, the less your code must defend against.
- Schemas are **self-contained**: no `$ref` to other files or URLs (nothing is ever fetched). Max 64 KiB.
- Schemas check *structure*, not *meaning*. Your code still decides whether a TIN exists.
- Only **2xx** answers are checked against the response schema. Errors (4xx/5xx) may be any shape.

## 3 · Implement the endpoint

Your security server `POST`s the **request body** to your `upstream` URL. It adds four headers:

| Header | Meaning |
| --- | --- |
| `X-Zroad-Client` | The consuming subsystem, e.g. `ZW/COM/12345678/accounts-payable` |
| `X-Zroad-Member` | The authenticated member, e.g. `ZW/COM/12345678` |
| `X-Zroad-Message-Id` | Unique id of this request |
| `Content-Type` | As the consumer sent it (normally `application/json`) |

A complete, runnable example in Python (standard library only):

```python
# provider_service.py: run with: python3 provider_service.py
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

CLEARANCES = {"2000123456": ("Supplier (Pvt) Ltd", "VALID", "2026-12-31")}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        who = self.headers.get("X-Zroad-Client", "unknown")      # for your own logs
        msg = self.headers.get("X-Zroad-Message-Id", "")
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        row = CLEARANCES.get(body["tin"])                        # schema already guaranteed "tin" is 10 digits
        if row is None:
            return self.reply(404, {"tin": body["tin"], "status": "NOT_FOUND"})
        name, status, until = row
        self.reply(200, {"tin": body["tin"], "name": name, "status": status, "valid_until": until})

    def reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):                                    # do not log request bodies
        pass

HTTPServer(("10.0.0.9", 9001), Handler).serve_forever()           # a PRIVATE address
```

Rules for your endpoint:

1. **Listen only on a private address** that only your security server can reach. It trusts `X-Zroad-*` headers because nobody else can send them.
2. **Return the provider's own status code** (200, 404, 400, …). It passes through to the consumer inside a signed answer. A 404 "not found" is a real, provable answer.
3. **Be safe to repeat.** If your endpoint times out the consumer may retry the same message. For read-only services this is free. For services that **change state**, use `X-Zroad-Message-Id` as an idempotency key: if you have seen it, return the stored result.
4. **Respond within `upstream_timeout_secs`** (default 15 s). Slow means the consumer sees `upstream_unavailable` (502).
5. **Never put secrets in answers or logs.** The security server records *that* an exchange happened (who, which service, hashes), not the contents; your logs should be just as careful.
6. 5xx answers are not remembered, so a retry is processed again. 2xx/4xx answers are remembered for 15 minutes per message id.

## 4 · Publish it

Add to your security server config:

```toml
[[services]]
id       = "tax-clearance/verify/v1"
upstream = "http://10.0.0.9:9001/verify"
title    = "Tax clearance check"
description = "Is this TIN cleared? Returns status and expiry only."
request_schema  = "/etc/zroad/schemas/verify.request.json"
response_schema = "/etc/zroad/schemas/verify.response.json"
enforce_response_schema = true       # withhold answers that break the contract

[[access]]
service = "tax-clearance/verify/v1"
allow   = ["ZW/COM/*"]               # who may call it; empty means nobody
```

```sh
security-server check-config --config /etc/zroad/zimra.toml
sudo systemctl restart zroad-security-server@zimra
zroad-cli catalogue --central https://central.example.zw:8443 --ca ca.pem --schemas
```

Your service appears in the public catalogue **with its schemas**, so developers can generate types
and test against them. Who may *use* it stays private.

**Access rules**

| Pattern | Allows |
| --- | --- |
| `ZW/COM/*` | Any subsystem of any member of class `COM` |
| `ZW/COM/12345678` | One member, all its subsystems |
| `ZW/COM/12345678/accounts-payable` | One subsystem of one member |

A member not matching any rule gets `access_denied` and your endpoint never sees the request.

## 5 · Test it

1. **Unit-test your endpoint** directly with `curl` or your test framework, using good and bad bodies.
2. **Test the contract.** Validate your example bodies against the schema with any JSON Schema library
   (for example Python's `jsonschema`) before you deploy.
3. **Test end to end** from a consumer's security server: the demo network ([quickstart](01-quickstart.md)) is the
   easiest place. Check the four outcomes: a good request, a schema violation (`schema_violation`), an
   unauthorised member (`access_denied`), your endpoint being down (`upstream_unavailable`).
4. **Look at the log**: `zroad-cli audit-verify`, and the access-log lookup by an auditor token.

## 6 · Changing a service later

| Change | How |
| --- | --- |
| Add an optional field to the answer | Same version; update the response schema (consumers ignore unknown fields only if *their* code does: tell them) |
| Make the request stricter, change meaning, remove a field | New version `v2`, run both for a deprecation period, then retire `v1` |
| Retire a service | Remove it from `[[services]]` and restart; it disappears from the catalogue within the hour (or `POST /admin/v1/catalogue/publish`) |
| Change who may call it | Edit `[[access]]`, restart. Keep the old rule in git so the change is reviewable |

## 7 · Operating a service

- **Rate limit:** 50 requests/second per calling member by default (`rate_limit_per_sec`).
- **Body size:** 2 MiB by default (`max_body_bytes`).
- **Who called what:** auditors see it in the audit log; citizens see lookups of *their* record through the citizen endpoint.
- **Provide your own SLOs.** A service that others depend on needs an owner, an on-call and a status page.

## Checklist before you publish

- [ ] A lawyer has approved this service and its audience
- [ ] The question is narrow and the answer minimal
- [ ] Request and response schemas are tight and tested
- [ ] The endpoint is private, idempotent for retries, and fast
- [ ] Access rules name exactly who may call it
- [ ] An owner and a support contact exist
- [ ] You have tested success, `schema_violation`, `access_denied` and your own outage

## Next

[Data provider guide](users/provider.md) · [Operations runbook](05-operations-runbook.md) ·
[Access control](../docs/access-control.md)
