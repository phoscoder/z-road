# Z-Road protocol, version 1 (draft)

This document describes what the code in this repository implements. It is a
draft written alongside the proof of concept, not a finished standard. Where the
code and this document disagree, that is a bug in one of them: please open an
issue.

## 1. Roles

| Component | Run by | Job |
| --- | --- | --- |
| **Security server** | every member | Signs and verifies messages, enforces access rights, keeps the audit log, talks mutual TLS to other security servers. |
| **Central server** | the governing authority | Certificate authority and member directory. Never sees exchanged data. |
| **Timestamp authority** | the governing authority (or a delegate) | Signs `(digest, time, serial)` so audit logs can be dated. It is itself an ordinary member. |
| **Consumer system** | a member | Calls its own security server's internal API. |
| **Provider system** | a member | Receives forwarded requests from its own security server. |

Internal systems never talk to another organisation directly. Only security
servers talk to each other.

## 2. Identifiers

```
member   instance/class/code                          ZW/GOV/ZIMRA
client   instance/class/code/subsystem                ZW/COM/12345678/accounts-payable
service  instance/class/code/subsystem/service/ver    ZW/GOV/ZIMRA/tax-clearance/verify/v1
```

Each segment is 1 to 64 characters from `A-Z a-z 0-9 . _ -` and may not consist
only of dots. A provider's configuration refers to its own services by the last
three segments (`tax-clearance/verify/v1`).

Access rules name clients with three segments (a member, where `*` matches one
segment, e.g. `ZW/COM/*`) or four (one subsystem).

## 3. Identity and enrolment

Every member has one **Ed25519 key pair**. The same key authenticates TLS
handshakes and signs Z-Road messages, so a peer's identity is established once,
by its certificate.

1. An operator of the central server registers the member (`id`, `name`,
   `endpoint`) and receives a one-time **enrolment token**, handed to the member
   out of band.
2. The member generates a key pair and a certificate signing request, and sends
   `{member_id, enrollment_token, csr_pem}` to the central server.
3. The central server checks the token, requires every subject alternative name
   in the CSR to match the host in the registered endpoint, then issues a
   certificate whose **common name is the member id** (whatever the CSR asked
   for). Extended key usage is server and client authentication.
4. The member stores `key.pem`, `cert.pem` and the root `ca.pem`. The root
   certificate must be obtained out of band; it is what authenticates the central
   server.

Revocation is final. A revoked member cannot re-enrol; it needs a new member
code.

**Renewal.** While its certificate is still valid, a member can call
`POST /v1/renew {csr_pem}` on the central server over mutual TLS. The central
server checks that the presented certificate is the one registered for an
`active` member, then issues a new one for the same member id and endpoint host
and updates the directory. Peers stop accepting the old certificate as soon as
they refresh their directory (the fingerprint no longer matches), even though it
is still signed by the CA and unexpired. A security server does this by itself when fewer than
`renew_before_days` (default 30) remain, and swaps the new certificate in without
a restart (`POST /admin/v1/renew` does it on demand). A member whose certificate has already
expired must be re-registered and re-enrolled with a new token.

## 4. Directory

`GET /v1/directory` on the central server returns every member's id, name,
endpoint, status (`pending`, `active`, `revoked`) and certificate. Security
servers refresh it periodically (default 30 s) and whenever a lookup misses
(throttled to once per 2 s), and keep the last good copy on disk so they work
through central server outages.

A provider accepts a peer only if the directory lists that member as `active`
**and** the certificate presented in the TLS handshake is the one registered
(compared by fingerprint). Revocation therefore takes effect within one refresh
interval.

## 4a. Service catalogue

A provider publishes what it offers with `POST /v1/catalogue` on the central
server (mutual TLS; the caller must be an `active` member presenting its
registered certificate). The body replaces everything that member published
before: `{services: [{id, title, description}]}` where `id` is
`subsystem/service/version`. The central server derives the full service id
from the authenticated member, so a member can only publish under its own name.
`GET /v1/catalogue` lists every service of every *active* member; revoked members
disappear. The catalogue says what exists and who offers it, never who may use
it: access rules stay private to each provider. Security servers publish at
startup and hourly, or on demand with `POST /admin/v1/catalogue/publish`.

## 4b. Schemas

A service can declare a **request schema** and a **response schema** (JSON Schema,
draft 2020-12 or earlier, at most 64 KiB each, no external `$ref`s: nothing is
ever fetched). They are published in the catalogue together with the service.

* **Provider side (enforced).** A provider with a request schema checks every
  incoming body *after* authentication and access control and *before* it reaches
  its internal system. A body that does not conform is refused with
  `schema_violation` (400) and a list of up to five violations; a non-JSON
  content type is refused with `unsupported_media_type` (415). Refusals are
  audit-logged (`denied:schema_violation`) and nothing reaches the internal
  system. A response schema is checked against successful (2xx) answers: a
  violation is logged as a warning, or with `enforce_response_schema = true` the
  answer is withheld and the consumer gets `upstream_schema_violation` (502).
* **Consumer side (convenience).** A consumer's security server learns request
  schemas from the catalogue (refreshed with the directory) and rejects a
  non-conforming request locally with `schema_violation` (400) before sending.
  The provider enforces the schema again, so this is never the control.
* **Central server.** Refuses to publish a schema that does not compile or is too
  large.
* A schema file that cannot be read or compiled stops a security server from
  starting, rather than letting the service run unvalidated.

Validation covers structure and types, not meaning: a schema cannot tell whether a
TIN exists, and it is not a substitute for the internal system's own checks.

## 5. Transport

Provider security servers listen for `POST /zroad/v1/exchange` over TLS with
**client certificates required**, verified against the root CA. Consumers verify
the provider's certificate against the same root and the host name in the
directory endpoint.

## 6. Messages

All bodies are JSON. Signed payloads travel as base64 of the exact bytes that
were signed, so nobody has to canonicalise JSON: the verifier checks those bytes
and only then parses them.

```
signature = Ed25519( domain "\n" payload_bytes )
domain    = "zroad/v1/request" | "zroad/v1/response" | "zroad/v1/timestamp"
```

### Request

`POST /zroad/v1/exchange`

```json
{
  "request": { "payload_b64": "…", "signature_b64": "…" },
  "body_b64": "…"
}
```

The signed payload is a `RequestEnvelope`:

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `message_id` | Unique per message (random 128 bit). Reused on retries. |
| `client` | The consuming subsystem. Its member must be the authenticated peer. |
| `service` | The service being called. |
| `issued_at_ms` | Sender's clock, Unix milliseconds. |
| `body_sha256` | SHA-256 of the body bytes, hex. |
| `content_type` | Of the body. |
| `subject` | Optional data subject the query is about (e.g. a TIN). |

### Response

```json
{
  "response": { "payload_b64": "…", "signature_b64": "…" },
  "body_b64": "…"
}
```

The signed payload is a `ResponseEnvelope` with `request_id`,
`request_sha256` (SHA-256 of the exact signed request payload, binding the answer
to the question), `provider`, `status` (the internal system's HTTP status),
`issued_at_ms`, `body_sha256` and `content_type`.

### Provider checks, in order

1. A client certificate was presented and names a member (`no_client_certificate`, `bad_client_certificate`).
2. Per-member rate limit (`rate_limited`).
3. The member is `active` and the certificate matches the directory (`member_not_active`).
4. The request parses and the signature verifies with the certificate's key (`malformed`, `bad_signature`).
5. Protocol version, message id, `client.member` equals the peer (`client_mismatch`), `service.member` is this provider (`wrong_provider`).
6. `issued_at_ms` within ±5 minutes (`stale_request`).
7. Body size limit and hash (`too_large`, `body_mismatch`).
8. The service exists (`unknown_service`) and an access rule allows the client (`access_denied`). **Default is deny.**
9. Duplicate handling, below.
10. Forward to the internal system, sign the answer, log.

### Idempotency and replay

A provider remembers `(peer, message_id)` for 15 minutes together with
`(client, service, body_sha256)`.

* Same id, same content, already answered: the stored answer is **re-signed**
  and returned. This makes retries after a lost response safe.
* Same id, different content: `replay` (409).
* Same id still being processed: `in_flight` (409).
* Same id answered before a provider restart: the replay cache is rebuilt from the audit log, but the stored answer is gone, so the provider returns `already_processed` (409). The consumer must send a new message.
* Internal system unreachable or 5xx: the entry is dropped so a retry is processed again.

## 7. Internal API (consumer side)

Served on a private HTTP listener.

```
POST /r1/{instance}/{class}/{code}/{subsystem}/{service}/{version}
Z-Road-Client:  ZW/COM/12345678/accounts-payable      (required)
Z-Road-Subject: 2000123456                            (optional)
Z-Road-Mode:    async                                 (optional)
```

Synchronous calls return the provider's status and body, plus
`Z-Road-Message-Id`, `Z-Road-Provider` and `Z-Road-Proof` (base64 of a
`Proof`, omitted if larger than 48 KiB; every proof is also stored on disk).
Errors generated by Z-Road carry a `Z-Road-Error` header and a JSON body
`{"error": "...", "message": "..."}`, so a Z-Road 403 is distinguishable from a
403 returned by the provider's own system.

`Z-Road-Mode: async` returns `202` with a message id and writes the request to a
durable outbox. A background worker retries with exponential backoff (1 s, 2 s,
… capped at 5 min, 20 attempts by default) using the same message id. Poll
`GET /internal/v1/outbox/{id}`.

Consumer-side error codes: `invalid_request` (400), `unknown_provider` (404),
`provider_unreachable` (503, with `Retry-After`), `bad_response` (502),
`internal` (500), plus any provider code passed through.

## 8. Proofs

A `Proof` bundles the signed request, request body, signed response and response
body. Anyone holding the directory can check, offline, that:

* the request was signed by the consumer's key and the response by the provider's;
* both bodies match their hashes;
* the response is bound to this request (`request_id`, `request_sha256`);
* the response was signed by the member that owns the service.

`zroad-cli proof-verify` does this. Note that verification uses the key in the
*current* directory; see the threat model on certificate rotation.

## 9. Audit log

Each security server keeps `audit/log.jsonl`, one JSON entry per line:

```json
{"seq":7,"ts_ms":1792661225671,"prev_hash":"…","type":"exchange","role":"provider",
 "message_id":"…","peer":"ZW/COM/12345678","client":"…","service":"…",
 "request_sha256":"…","response_sha256":"…","status":200,"outcome":"ok",
 "subject_ref":"…","hash":"…"}
```

`hash = SHA-256(JSON{seq, ts_ms, prev_hash, event})` and `prev_hash` is the
previous entry's hash (64 zeros for the first). Editing, removing or reordering
an entry breaks the chain; a security server refuses to start on a log that does
not verify.

Outcomes: `received`, `ok`, `duplicate`, `denied:<code>`, `error:<code>` (provider and
consumer sides both log; denied requests are logged too).

**Write-ahead on the provider.** Once a request has passed every check, and before
it is forwarded to the internal system, the provider appends a `received` entry.
If that entry cannot be written the request is refused with `audit_unavailable`
(503) and the internal system is never called, so an effect never happens without a
record. The final entry (`ok`, ...) follows the answer; if *that* cannot be
written the answer is withheld (`audit_unavailable`) although the request is on
record, and a retry with the same message id is answered from the stored result
without calling the internal system again. A consumer whose own log fails after an
exchange reports an internal error; the provider's log still holds the record.
`received` entries are not shown to data subjects in the access log.

`subject_ref` is `HMAC-SHA256(subject_key, subject)`; the clear subject is never
written. The provider can answer "who looked up this subject?" by recomputing
the HMAC (`GET /admin/v1/access-log?subject=…`).

### Anchoring

Every `anchor_interval_secs` (default 60) a security server sends the current
chain head to the timestamp authority and appends an `anchor` entry holding the
signed token. The token proves the log had that head at that time, so history
cannot later be rewritten, even by the log's owner, without the mismatch being
visible. `zroad-cli audit-verify --directory …` checks the chain and the token
signatures.

## 9a. Timestamp authority

`POST /v1/timestamp {"digest": "<64 hex>"}` (mutual TLS, any member) returns
`{tsa, digest, time_ms, serial, signature_b64}`. Serials are persisted before a
token is issued so they are never reused.

## 10. What is not specified yet

* Member-held keys for members on a shared security server (today the operator holds them).
* Verifying old proofs after a certificate rotation (the offline check uses the key in the current directory).
* Federation between several Z-Road instances or with other X-Road deployments.
* Streaming and large-object transfer (bodies are capped, default 2 MiB).
* Schemas for non-JSON content types.
