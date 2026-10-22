# 04 · How to develop an SDK

*For developers who want to give a language or platform a first-class Z-Road client:
PHP, C#, JavaScript/TypeScript, Java, Go, Ruby, Kotlin, or an ERP's own scripting language.*

There are already clients for **Rust** (`crates/zroad-client`) and **Python**
([z-road-python](https://github.com/phoscoder/z-road-python)). Read the Python one first: it is about 300
lines, standard library only, and passes every scenario in this guide.

## 1 · What an SDK is, and what it is not

![Where an SDK fits](diagrams/sdk-layers.svg)

Your application never speaks the Z-Road protocol. It makes **plain HTTP calls to its own security
server**, which does all the cryptography, mutual TLS, logging and retrying across the network. An SDK
is a thin, friendly wrapper over that HTTP API that gets the *conventions* right:

- builds the call (path, headers);
- tells Z-Road's errors from the provider's own answers;
- gives errors stable codes and a retry hint;
- offers a durable queue for outages;
- hands back the proof.

> **An SDK never signs, never holds a private key, and never speaks mutual TLS.** If you find yourself
> reaching for a crypto library to sign something, stop: you are rebuilding the security server.
> (Verifying a *proof* offline is the one exception; it is optional. See §6.)

That is why SDKs are cheap to build and safe to publish: they have no secrets and no trust decisions.

## 2 · The contract you implement

The full contract is the [OpenAPI file](../docs/openapi-internal.yaml). The parts an SDK needs:

### Make a call

```
POST {base}/r1/{instance}/{class}/{code}/{subsystem}/{service}/{version}
Z-Road-Client:  ZW/COM/12345678/accounts-payable          required
Z-Road-Subject: 2000123456                                optional, ≤ 256 bytes
Content-Type:   application/json                          default for JSON bodies
Authorization:  Bearer <internal token>                   if the server requires one
```

On a **shared node** every path is prefixed with `/m/{instance}/{class}/{code}` of the client's member
(`/m/ZW/COM/12345678/r1/...`).

### Read the answer

| What you see | Meaning | SDK result |
| --- | --- | --- |
| A response **without** `Z-Road-Error` | The provider's own answer, with the provider's status (200, 404, 400, …) | **Reply** (status, body, content type, `Z-Road-Message-Id`, proof) |
| A response **with** `Z-Road-Error: <code>` | Z-Road itself refused or failed. Body: `{"error": "<code>", "message": "..."}` | **Z-Road error** (status, code, message, retryable) |
| Connection refused / timeout to *your own* security server | It is down | **Unreachable** error |

`retryable` is true when the response has a `Retry-After` header. (The error table is in
[07 · Troubleshooting](07-troubleshooting.md).)

The proof is in the `Z-Road-Proof` header: base64 of a JSON document (see §6). Omitted when the
exchange is larger than 48 KiB; the security server stores every proof anyway.

### Queue work for when things break

```
POST {base}/r1/.../{version}            with header  Z-Road-Mode: async
→ 202  {"message_id": "…", "status_url": "/internal/v1/outbox/…"}

GET  {base}/internal/v1/outbox/{message_id}
→ 200  {"state":"pending","item":{"attempts":2,"last_error":"…"}}
     | {"state":"finished","result":{"state":"delivered","status":200,"body_b64":"…","content_type":"…"}}
     | {"state":"finished","result":{"state":"failed","error":"…"}}
```

The security server stores the request on disk and retries with growing pauses, reusing the same
message id so a retried request is processed once.

## 3 · The API your SDK should offer

Use your language's idioms, but offer these concepts, with these names where possible:

| Concept | Shape |
| --- | --- |
| **Client** | `Client(securityServerUrl, clientId, {token?, sharedNode?, timeout?})`. Validate `clientId` is `instance/class/code/subsystem` (four non-empty parts) and fail early |
| **call** | `call(service, body, {subject?, contentType?}) → Reply`. A JSON object/array body is serialised and sent as `application/json`; bytes and strings are sent as is |
| **Reply** | `status`, `body` (bytes), `contentType`, `messageId`, `proof?`, `json()`, `text()`, `ok` (2xx) |
| **submit** | `submit(service, body, opts) → messageId` |
| **poll** | `poll(messageId) → Queued` where state is `pending`, `delivered` (with a Reply) or `failed` (with text) |
| **wait** | `wait(messageId, {maxWait, interval}) → Reply`; raises *QueueFailed* or *QueueTimeout* |
| **Errors** | *ZRoadError* (`status`, `code`, `message`, `retryable`), *Unreachable* (retryable), *QueueFailed*, *QueueTimeout* (retryable) |

Keep the error types separate. Callers branch on them: retry on `retryable`, alert on `Unreachable`,
show `access_denied` to a human, log `schema_violation` as a bug in their request.

## 4 · Behaviours that must be right

These are the lessons behind the design. Each is covered by a conformance scenario (§5).

1. **Z-Road error vs provider error.** Use the `Z-Road-Error` header, **not** the status code. A provider may legitimately return 403 or 404.
2. **Never throw on a non-2xx from the provider.** A 404 "not found" is a provable answer. Return it as a Reply and let the caller look at `ok`.
3. **Be defensive about error bodies.** If a Z-Road error's body isn't the expected JSON, use code `unknown` and a truncated body as the message. Never crash while handling an error.
4. **Do not retry synchronous calls automatically.** The caller may not want a second attempt (cost, side effects). Offer `retryable`, and offer the durable queue (`submit`) for work that must survive outages. If you add an opt-in retry helper, it must reuse nothing and add jitter.
5. **Never invent a message id.** The security server owns them. For queued work the id comes from `submit`.
6. **Don't log secrets or data.** No tokens, bodies, or subjects in your logs or exception messages. Include the Z-Road code and status only.
7. **Timeouts.** Default 30 s total. Make it configurable. Treat a timeout of your own security server as *Unreachable*.
8. **No automatic redirects** to other hosts (the security server never redirects). Don't follow them.
9. **Connection reuse** is fine and good. The internal listener is plain HTTP on a private network; allow callers to supply their own HTTP client (for proxies, custom TLS in front of the internal listener, tracing).
10. **Configuration from the environment**, for twelve-factor deployments: `ZROAD_SECURITY_SERVER`, `ZROAD_CLIENT`, `ZROAD_TOKEN`.
11. **Thread/async safety.** A client holds no mutable state; it must be safe to share.

## 5 · Test it: the conformance scenarios

[`sdk-conformance/scenarios.json`](sdk-conformance/scenarios.json) holds 16 language-neutral scenarios
and a README that explains the format. Each one is: *a scripted fake security server, an operation, the
requests the server must receive, and the outcome you must produce*.

Your test harness needs only a tiny fake HTTP server that replays canned responses and records the
requests it gets. Then:

```text
for each scenario:
    start a fake server that replays scenario.responses in order (or none, if server_down)
    build a client from constants.client and scenario.client_options
    run scenario.operation
    assert the requests the fake received match scenario.expect_requests (subset of headers)
    assert the outcome matches scenario.expect
also: the constructor must reject every client id in invalid_clients
```

The Python client's [`tests/test_conformance.py`](https://github.com/phoscoder/z-road-python/blob/main/tests/test_conformance.py)
is a 100-line worked example. **Passing all 16 is the bar for calling your SDK compatible.**

They cover: success with proof and message id; a provider's 404 as a reply; Z-Road errors (not retryable,
retryable, unreadable body); the security server being down; bearer tokens; shared-node paths; `submit`
and its errors; `poll` (pending, delivered, failed); `wait` (success, failure, timeout).

**Then test against a real network.** Start the demo and point your SDK at it:

```sh
ZROAD_DEMO_KEEP_SECS=600 scripts/demo.sh     # leaves the company's security server on 127.0.0.1:7001
```

Write one integration test that checks, against `http://127.0.0.1:7001` as `ZW/COM/12345678/accounts-payable`:
a live call returns `VALID` with a proof; an unknown TIN (`0000000000`) returns a 404 *reply*; a queued call
(`2000987654`) completes with `EXPIRED`; claiming another member's subsystem raises `invalid_request`.
See [`tests/integration_demo.py`](https://github.com/phoscoder/z-road-python/blob/main/tests/integration_demo.py).

## 6 · Optional: verifying a proof offline

Most SDKs just hand back the proof and recommend `zroad-cli proof-verify`. If you implement
verification, you need an Ed25519 library, an X.509 parser, and a copy of the member directory
(`directory.json` from a security server's data folder, or `GET /v1/directory` on the central server).

**A proof** is JSON:

```json
{ "request":  { "payload_b64": "…", "signature_b64": "…" },
  "request_body_b64": "…",
  "response": { "payload_b64": "…", "signature_b64": "…" },
  "response_body_b64": "…" }
```

**Verify, in this order.** Stop at the first failure.

1. Decode both payloads (base64 → JSON). The request payload names `client` (a member plus subsystem), `service`, `message_id`, `issued_at_ms`, `body_sha256`; the response payload names `provider`, `request_id`, `request_sha256`, `issued_at_ms`, `body_sha256`.
2. In the directory, find the **client's member** and the **provider's member**. Collect each member's certificates: `cert_pem` plus `previous_certs`. Keep those whose validity (`notBefore`…`notAfter`, with ±10 minutes of slack) covers the message's `issued_at_ms`. Each certificate's **public key** is the raw 32-byte Ed25519 key.
3. Verify the request signature: Ed25519 over the bytes `"zroad/v1/request" + "\n" + payload_bytes` (the exact decoded bytes, not a re-serialisation), with a client key. Verify the response signature over `"zroad/v1/response" + "\n" + payload_bytes` with a provider key.
4. `sha256_hex(request_body) == request.body_sha256`; `sha256_hex(response_body) == response.body_sha256`.
5. `response.request_id == request.message_id` and `response.request_sha256 == sha256_hex(request payload bytes)`.
6. `response.provider == request.service.member`.

Never re-serialise JSON before checking a signature: verify the **decoded bytes** you were given.

## 7 · Packaging and publishing

| Topic | Guidance |
| --- | --- |
| **Repository** | One repository per language, named `z-road-<language>` (for example `z-road-php`). Keep SDKs out of the main repository so they release independently |
| **Licence** | MIT, to match the project |
| **Package name** | `zroad-client` on the language's registry (or the nearest free name) |
| **Dependencies** | As few as possible. An SDK should be easy to audit: standard library plus, at most, an HTTP client |
| **Versioning** | Semantic versioning. State which Z-Road internal API version it supports (`1.0`). A breaking change in the API is a major version |
| **Docs** | README with install, a 10-line example, the error table, shared-node and queue examples, and how to run the tests |
| **CI** | Run the unit tests and the conformance scenarios on the oldest and newest supported runtime. Run the integration test against the demo network on a schedule |
| **Security** | Publish with the registry's provenance or signing feature where it exists. No install scripts. Pin CI actions |
| **Support policy** | Say which language versions you support and for how long |

**README skeleton**

```markdown
# zroad-client (<Language>)
Client for a Z-Road security server's internal API.
## Install
## Use            ← the 10-line example
## Errors         ← table of ZRoadError codes and what to do
## Queue          ← submit / poll / wait
## Shared nodes
## Test           ← unit tests, conformance scenarios, integration test
## Status         ← API version supported, licence
```

## 8 · Language notes

| Language | HTTP client | Watch out for |
| --- | --- | --- |
| **PHP** | `curl` ext / Guzzle | Header names are case-insensitive but arrays are not: normalise. Set `CURLOPT_HEADER` handling carefully; don't treat curl success as HTTP success |
| **C#** | `HttpClient` | One shared `HttpClient`; set `Timeout`; `Headers.Contains("Z-Road-Error")` is on the response, content headers are separate |
| **JavaScript/TypeScript** | `fetch` | `fetch` resolves on 4xx/5xx; do your own header test. Node < 18 needs a polyfill. Browsers must not call the internal API directly (server side only) |
| **Java/Kotlin** | `java.net.http.HttpClient` | Configure `connectTimeout` and per-request `timeout`; don't let redirects follow |
| **Go** | `net/http` | Use `context` for deadlines; always close response bodies; set `CheckRedirect` to refuse redirects |
| **Ruby** | `Net::HTTP` | Set `open_timeout`/`read_timeout`; response headers are lowercase |

## 9 · Release checklist

- [ ] All 16 conformance scenarios pass
- [ ] The integration test passes against the demo network
- [ ] Errors: Z-Road vs provider distinguished by header, not status
- [ ] No tokens, bodies or subjects in logs or exception text
- [ ] Timeouts configurable; own-server timeouts raise *Unreachable*
- [ ] README has install, example, error table, queue and shared-node sections
- [ ] Versioned, changelogged, licensed (MIT)
- [ ] Added to the [clients list](../docs/integration.md) in the main repository

## Next

[Consumer developer guide](users/consumer-developer.md) ·
[OpenAPI file](../docs/openapi-internal.yaml) · [Protocol](../docs/protocol.md)
