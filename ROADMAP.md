# Roadmap

Where Z-Road is, what comes next, and what has to happen outside the code before a
pilot can run.

![Roadmap: phases 0 to 4 done, phase 5 in progress, then pilot, production and scale](docs/diagrams/roadmap.svg)

**Where we are.** A working, tested system: the protocol, the security server, the central
server and timestamp authority, access control and citizen login, shared nodes with
member-held keys, automatic renewal, packaging, and a set of [guides](guides/README.md).
It has **not** had an independent security review and is **not** ready for real data.
What stands between it and a pilot is mostly governance, legal and assurance work, plus
a short list of hardening items.

Status key: ✅ done · 🔧 in progress · 🔜 next · 🗓️ planned · 💤 later.

## Done (phases 0–4)

| Area | What exists |
| --- | --- |
| Design | [Protocol spec](docs/protocol.md), [threat model](docs/threat-model.md), addressing, [legal checklist](docs/legal-considerations.md), [pilot plan](docs/pilot-plan.md) |
| Core system | Security server (provider and consumer), central server (CA and directory), timestamp authority, mutual TLS, signed and logged exchanges, signed proofs verifiable offline |
| Resilience | Durable outbox with backoff, idempotent retries, cached directory, replay protection that survives restarts |
| Accountability | Hash-chained audit logs on both sides, trusted-timestamp anchors, fail-closed logging with a write-ahead record |
| Access control | Named operators with roles, recorded admin actions, a citizen endpoint that answers only for the person a login system vouches for |
| Contracts | Service catalogue with JSON Schemas enforced by providers, checked early by consumers |
| Shared nodes | One node hosting many members, with operator-held or member-held keys (signer service) |
| Renewal | Automatic, switched in without a restart or dropped calls; old proofs and anchors stay verifiable |
| Integration | Plain-HTTP API with an [OpenAPI file](docs/openapi-internal.yaml), Rust and Python clients |
| Quality | End-to-end tests over real mutual TLS, fuzzing of the parsers, `cargo audit`, clippy and fmt in CI |
| Packaging | Docker Compose demo network, hardened systemd units, smoke tests (the container half is verified by CI) |
| Docs | [Guides](guides/README.md) for deploying, every kind of user, SDK authors, operations and incidents |

## Phase 5: hardening 🔧

Finish the security work that has to be done before anyone trusts it with real data.

| Item | Status | Notes |
| --- | --- | --- |
| **Key custody**: offline root CA with an HSM or hardware token, signing a short-lived online intermediate | 🔜 | Highest-value secret first. Member and signer keys follow (PKCS#11), with SoftHSM for tests. TLS keys need a PKCS#11 plug-in for the TLS library |
| Independent security review and penetration test | 🔜 | Needs a budget and a reviewer. The code, tests and threat model are ready to hand over |
| Longer fuzz campaigns and fuzzing the HTTP handlers and config parser | 🔧 | Parsers have been fuzzed for minutes, not weeks |
| Operator MFA or single sign-on | 🗓️ | Today operators use bearer tokens, suitable for scripts and consoles |
| A real citizen login integration at the first provider | 🗓️ | The assertion mechanism is built; the login is per provider |
| Per-service policy in the signer (allowed services, amounts) | 🗓️ | Today: ownership, freshness and a rate limit |
| Signed directory snapshots | 🗓️ | Today the directory is trusted through TLS to the central server |
| Root CA rotation procedure, rehearsed | 🗓️ | Ten-year root; a warning is logged within a year of expiry |

## Phase 6: pilot 🗓️ (gated)

One provider (ZIMRA is the natural start), a few consumers, one neutral operator for the
central server. See the [pilot plan](docs/pilot-plan.md) and its success measures.

**Gate: do not start until all of these are true.**

- [ ] An authority is chosen and accountable for the central server and its keys
- [ ] The root CA key is generated in a ceremony and held offline or in an HSM
- [ ] A lawyer has reviewed [the legal checklist](docs/legal-considerations.md); data-sharing agreements are signed; a data protection impact assessment is done; the regulator has been consulted
- [ ] An independent review has been done and its findings fixed
- [ ] The provider has a real citizen login (or the citizen page stays off)
- [ ] Runbooks have been rehearsed once: a revocation, a restore from backup, a certificate emergency
- [ ] Monitoring and alerting are in place (see the [operations runbook](guides/05-operations-runbook.md))

## Phase 7: production readiness 🗓️

| Item | Why |
| --- | --- |
| High availability: several security server instances behind one endpoint with a shared replay store | Today replay protection is per instance |
| Metrics and dashboards (Prometheus endpoint, ready-made dashboards and alerts) | Operators need to see health without reading logs |
| Signed releases, `.deb`/`.rpm` packages, SBOM, reproducible builds | Supply-chain trust |
| Per-consumer quotas and fair sharing per service | Protect providers from a noisy neighbour |
| Access-rule change workflow (propose, approve, audit) | Rules are a config file today |
| More client libraries in their own repositories: PHP, C#, JavaScript/TypeScript, Java | Meet ERPs where they are; see the [SDK guide](guides/04-sdk-development.md) |
| Rehearsed disaster recovery | Prove the backups work |

## Phase 8: scale 💤

More services and members; federation with other exchange layers (as Estonia and Finland did);
large payloads and streaming; ERP plug-ins; service-level reporting for providers; a
community of operators and integrators.

## Outside the code (decides whether any of this is used)

| Lane | What has to happen | Owner |
| --- | --- | --- |
| **Governance** | Choose the governing authority; decide who may join and how disputes are resolved; decide who runs the CA and the timestamp authority | Government / sponsors |
| **Legal** | Data protection review (Cyber and Data Protection Act, POTRAZ); data-sharing agreements per service; privacy notice | Counsel, regulator |
| **Assurance** | Commission the independent review and penetration test; publish a summary | Authority |
| **People** | Pilot partners; training for operators, developers and auditors; communications that explain, in plain words, that there is no central database | Project lead |
| **Funding and hosting** | Budget for HSMs, hosting, review, support | Sponsors |

## How this roadmap is kept

It changes as things are built or learned. The README's
[roadmap section](README.md#roadmap) is a short version of this page. If you want something
moved, open an issue with the reason.
