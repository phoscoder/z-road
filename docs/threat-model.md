# Threat model (draft)

A first-pass threat model for the proof of concept. It is a self-assessment: no
external security review has been done, and none of this should be read as
assurance for a production deployment.

## Assets

1. **Integrity of answers.** A buyer must be able to trust that "VALID" really came from ZIMRA.
2. **Confidentiality of exchanged data** in transit.
3. **Accountability.** Who asked what, when, and what was answered, in a form neither side can later deny or rewrite.
4. **Availability** of the network and of each member's own systems.
5. **Privacy of data subjects**, including not leaking who they are to anyone who does not need to know.
6. **Member private keys** and the CA key.

## Trust assumptions

* The **central server operator** is trusted to run the CA honestly and to approve only genuine organisations. It is the root of trust, and it is the biggest single point of failure.
* Each member trusts its **own** internal network and systems. The internal API is plain HTTP and, by default, unauthenticated apart from an optional bearer token.
* Clocks are within a few minutes of each other.

## Adversaries considered

| Adversary | Examples |
| --- | --- |
| Network attacker | Reads, alters, replays or injects traffic between members. |
| Rogue or compromised member | A valid member trying to read services it was not granted, impersonate another member, or tamper with answers. |
| Revoked member | A former member still holding a certificate. |
| Malicious insider at a member | Edits the member's own audit log to hide lookups. |
| Remote attacker against a security server | Malformed input, oversized bodies, slow connections, floods. |

## Threats and what the code does about them

| Threat | Mitigation in this repository | Residual risk |
| --- | --- | --- |
| Eavesdropping or tampering in transit | TLS 1.2/1.3 with mutual authentication, certificates from a private CA (`rustls`, `ring`). | Depends on key hygiene. |
| Impersonating another member | Certificate common name is set by the CA to the member id; the signed `client` must belong to the authenticated peer (`client_mismatch`); the signature key must be the certificate's key. | A stolen private key is a full impersonation until the member is revoked or renews (renewal retires the old key at once for every peer that has refreshed its directory). |
| Forged or altered answers | Responses are signed and bound to the request by hash; bodies are hash-checked; end-to-end tests cover swapped bodies, wrong keys and altered payloads. | |
| Replay | Per-peer message id cache, ±5 minute window, identical retries are idempotent and re-signed. | The cache is rebuilt from the audit log after a restart, so messages answered in the last 15 minutes are refused (`already_processed`) rather than answered again. The stored answer is not kept across restarts, so such a retry must use a new message id. Dedupe state is per security server instance: running several instances behind one endpoint needs a shared store. |
| Unauthorised access to a service | Default-deny access rules per service, evaluated by the provider on the signed, authenticated identity. Denied requests never reach the internal system. | Access rules live in a config file; there is no review workflow yet. |
| Revoked member keeps access | Directory status is checked on every request and refreshed every 30 s; the registered certificate fingerprint must match. | Up to one refresh interval of delay. If the central server is down, a stale directory means a revocation is not seen. There is no OCSP or CRL at the TLS layer. |
| Silent loss of accountability | The provider writes a `received` entry *before* forwarding a request and refuses with `audit_unavailable` (503) if it cannot, so no effect happens without a record; if the outcome entry then fails, the answer is withheld. A security server refuses to start on a corrupt log. Covered by an end-to-end test that injects write failures. | A consumer whose log fails after the exchange has still got the answer (the provider's record exists). A tampered log is detected, not prevented. |
| Rewriting history | Hash-chained log; startup refuses to continue on a broken chain; periodic anchors with a trusted timestamp. | Without anchors, whoever controls the log can rewrite the whole thing consistently. The latest entries since the last anchor are not yet dated. The timestamp authority is a trusted party. |
| Data subject enumeration through logs | The clear subject is never logged; only `HMAC(secret key, subject)`. | National IDs and TINs are low-entropy. Anyone who holds the secret key (the operator) can test candidate IDs. Protect `subject.key` and treat it as sensitive. |
| Resource exhaustion | Body size limits, connection cap (1024), handshake and header-read timeouts, per-member rate limit, bounded dedupe cache, upstream timeouts. | This is basic hardening, not DoS protection. Put a reverse proxy or firewall in front of public listeners. |
| Compromise of the CA key | Stored in a file with `0600` permissions. | **High.** Use an HSM or offline root with an online intermediate before any real use. The `Signer` trait exists so member signing can move to an HSM, but TLS keys currently load from files. |
| Stolen admin token | Constant-time comparison, minimum length. | Bearer tokens in config files are weak. Prefer a secrets manager and per-operator credentials. |
| Malicious internal caller | Optional `internal_token`. The client must belong to this member. | Anyone who can reach the internal port can act as any of the member's subsystems. Bind it to localhost or a private network. |
| Supply chain | Small dependency set from well-known crates; `unsafe` is forbidden in this workspace; CI runs clippy with `-D warnings` and `cargo audit` (weekly too). `Cargo.lock` is committed. | No `cargo vet`; no reproducible builds; no signed releases. |
| Malformed or malicious request bodies reaching a provider's system | Optional per-service JSON Schema enforced by the provider's security server before forwarding, with a size cap, no external `$ref` resolution, and a startup failure if a schema cannot be loaded. | Schemas check structure, not meaning, and only exist where a provider writes one. A pathological schema is a CPU risk for whoever compiles it; schemas are size-capped but not otherwise bounded. |
| Malformed input | Strict parsing; identifier grammar rejects `..`, `/` and whitespace in segments; hashes and signatures checked before use; a randomised test feeds garbage to every parser and verifier and requires an error, never a panic. | Coverage-guided fuzzing covers the id, wire message, audit log, certificate and schema parsers (`fuzz/`); only minutes of campaign so far, and the HTTP handlers and config parser are not fuzzed. |

## Shared nodes

When one security server hosts several members, the operator holds all their
private keys and can sign as any of them; members must trust it as they would a
bank trusts its card processor. Isolation between members is by configuration:
separate state directories, separate tokens, internal paths per member, and a
check that a member's internal API only accepts its own client ids. A bug in that
routing is the main risk, which is why it has a dedicated end-to-end test. The
node's TLS server certificate belongs to one hosted member at a time, so
transport-level identity on a shared node means "a registered node"; the
provider's signature on each answer is what proves which member answered.

## Known gaps (not yet addressed)

1. HSM or PKCS#11 support for keys, and an offline root CA.
2. Verifying old proofs after key rotation (a proof is checked against the key in today's directory). Renewal itself is automatic with hot reload; the timestamp authority and central server still need a restart to pick up a renewed certificate.
3. Replay cache shared between several instances of one security server.
4. Authenticated, role-based admin and citizen-facing access, instead of a shared bearer token. The citizen-facing "who accessed my data" view needs identity proofing of the citizen before the admin endpoint is ever called.
5. Directory integrity beyond TLS to the central server (for example signing directory snapshots).
6. Formal protocol analysis, fuzzing, and an independent penetration test and code audit.
7. Governance threats: who may join, how disputes are resolved, what happens when the authority itself misbehaves. These are institutional questions that no code solves.

## Reporting

There is no formal security contact yet. Until there is, please open an issue
that does not include exploit details and ask for a private channel.
