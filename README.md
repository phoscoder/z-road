# Z-Road

**A secure data exchange layer for Zimbabwe, written in Rust.**

Z-Road lets government agencies, banks, companies and other organisations query each other's data directly, safely and with a full audit trail, without anyone building a single central database. It is inspired by Estonia's [X-Road](https://x-road.global/) and designed around the realities of Zimbabwe: patchy connectivity, power cuts, modest hardware and the need for public trust.

> **Status: working proof of concept.** The protocol, security server, central server, timestamp authority and a first use case run end to end and are covered by automated tests. It has **not** had an independent security review and is **not** ready for real data. See the [Roadmap](#roadmap) and the [threat model](docs/threat-model.md).

---

## Table of contents

- [Why Z-Road](#why-z-road)
- [Core ideas](#core-ideas)
- [Architecture](#architecture)
- [How a request flows](#how-a-request-flows)
- [Worked example: tax clearance check](#worked-example-tax-clearance-check)
- [Joining the network](#joining-the-network)
- [Zimbabwe-specific design considerations](#zimbabwe-specific-design-considerations)
- [Why Rust](#why-rust)
- [Repository layout](#repository-layout)
- [Getting started](#getting-started)
- [What works today](#what-works-today)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## Why Z-Road

Today, proving something to another organisation in Zimbabwe usually means a PDF, a stamped letter or an email attachment. A supplier's tax clearance certificate, a proof of address, a company registration extract: each one is easy to forge, easy to let expire and slow to verify.

Z-Road replaces "send me a document" with "ask the source, get a signed answer":

- **Once-only data.** The state and its partners ask the owner of the data, not the citizen, for information that already exists.
- **Fast, verifiable services.** Pre-filled forms, instant KYC, live tax clearance checks.
- **Transparency.** Every query is logged, so people can eventually see who accessed their data and when.
- **No honeypot.** Each organisation keeps its own data. There is no central database to breach or abuse.

## Core ideas

| Principle | What it means |
| --- | --- |
| **Decentralised data** | Data stays with its owner. Z-Road only carries requests and answers. |
| **Signed and logged** | Every message is signed, timestamped and logged on both sides, so exchanges are provable later. |
| **Provider decides access** | The central authority vouches for *who you are*. The data provider decides *who may use its services*. |
| **Minimal answers** | Services answer the question asked ("is this TIN cleared?") and nothing more. |
| **Per-service permissions** | Access is granted per service, not per organisation. |
| **Open source** | The protocol and software are open for audit and independent implementation. |

## Architecture

Z-Road has three kinds of components.

<p align="center">
  <img src="docs/diagrams/architecture.svg" alt="Z-Road architecture: two organisations with security servers exchanging signed messages over mTLS, supported by a central server and timestamp service" width="860">
</p>

- **Security Server.** Runs at every member. It signs, encrypts, timestamps and logs messages, checks access rights and forwards requests to the internal system. This is the main piece of software and where most security-critical code lives.
- **Central Server.** Run by the governing authority. It keeps the list of members and their services and acts as the trust anchor. It does **not** see or store exchanged data.
- **Timestamp Service.** Provides trusted timestamps so that a signed exchange can be proven to have happened at a specific time.

An organisation's internal systems never talk to another organisation directly. Only security servers talk to each other.

### Addressing

Every participant and service is identified by a path:

```
instance / member-class / member-code / subsystem [/ service / version]
```

For example `ZW/GOV/ZIMRA/tax-clearance/verify/v1`.

## How a request flows

<p align="center">
  <img src="docs/diagrams/request-flow.svg" alt="Sequence diagram of a Z-Road request from consumer system to provider system and back" width="860">
</p>

Both sides keep their own logs, so either party can later prove what was asked and answered.

## Worked example: tax clearance check

Buyers in Zimbabwe regularly need to confirm that a supplier holds a valid ITF263 tax clearance before paying them. Today that is a PDF sent by email. With Z-Road:

1. A clerk at the buyer enters a supplier invoice. The ERP calls the buyer's security server with the supplier's TIN.
2. The buyer's security server signs and logs the request and sends it over mTLS to ZIMRA's security server.
3. ZIMRA's security server confirms the buyer is a registered member and is allowed to use the clearance service.
4. ZIMRA's system looks up the TIN and replies. The reply is signed, so the buyer can prove later that ZIMRA confirmed the supplier was cleared on that date.

Request:

```http
POST /r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1
Z-Road-Client: ZW/COM/12345678/accounts-payable
Z-Road-Id: 7f3c9a1e-...

{ "tin": "2000123456" }
```

Response:

```json
{
  "tin": "2000123456",
  "name": "Supplier (Pvt) Ltd",
  "status": "VALID",
  "valid_until": "2026-12-31"
}
```

Design notes:

- **Answer the question, not more.** The service returns status and expiry only, with no turnover or tax history. This data minimisation is what makes it reasonable to open the service to every member.
- **Live check beats a PDF.** The buyer can re-check before every payment instead of trusting a certificate that may have been revoked last week.
- **Shared nodes for small businesses.** One security server can host many members, so an accounting vendor, bank or chamber of commerce can run a node on behalf of customers.

## Joining the network

<p align="center">
  <img src="docs/diagrams/onboarding.svg" alt="Six steps to join Z-Road, from application to going live" width="860">
</p>

The authority vouches for identity. Each provider independently decides who may use each of its services. The Registrar General, for instance, decides whether ZIMRA can query the ID register.

## Zimbabwe-specific design considerations

- **Legal footing.** The Cyber and Data Protection Act and the role of POTRAZ as data protection authority shape what can be exchanged, logged and retained. Legal review is a prerequisite for any real deployment.
- **First adopters.** The Registrar General (national IDs, births), ZIMRA, and banks or mobile money operators (KYC) offer the quickest real-world wins.
- **Unreliable connectivity and power.** Security servers should queue, retry and resume gracefully rather than assume they are always online.
- **Modest hardware.** District offices may run nodes on small machines, so resource use matters.
- **Citizen visibility.** Letting people see who accessed their data is central to public trust and should be designed in from the start, not added later.

## Why Rust

The security server sits at the edge of every organisation and must be hard to break.

- Memory safety without a garbage collector.
- Low memory and CPU footprint.
- Strong ecosystem for the job: `tokio` and `axum` for networking, `rustls` for mTLS, `ring` or `aws-lc-rs` for cryptography, `serde` for message formats.
- Single static binaries are easy to deploy on constrained machines.

## Repository layout

A single Cargo workspace, so the protocol code is shared and end-to-end tests are simple. It can be split later if separate owners or release cycles emerge.

```
z-road/
  crates/
    zroad-core/         identifiers, signed messages, PKI helpers, hash-chained audit log
    zroad-net/          mutual TLS, small HTTP client, server with peer certificates, central API client
    security-server/    the main binary: provider and consumer sides, outbox, audit anchoring
    central-server/     certificate authority and member directory
    timestamp-service/  trusted timestamps for audit log anchoring
    zroad-cli/          admin and audit tool: enrol, revoke, verify logs and proofs, citizen access log
    e2e-tests/          whole-network tests over real mutual TLS
  examples/
    zimra-clearance/    mock provider system (tax clearance check)
    buyer-client/       sample consumer
    citizen-portal/     demo "who looked at my data?" page
  scripts/demo.sh       run a complete local network and make a signed, logged request
  docs/                 protocol, threat model, deployment, legal considerations, pilot plan
```

## Getting started

You need a recent stable Rust toolchain.

```sh
cargo test --workspace      # unit and end-to-end tests
scripts/demo.sh             # a full local network, step by step
```

The demo starts a central server, a timestamp authority, a mock ZIMRA clearance system and two security servers, then:

1. a buyer checks a supplier's tax clearance (`VALID`), and another that is `EXPIRED`;
2. the signed proof of the exchange is verified offline;
3. ZIMRA's log is queried for who looked up that TIN (the citizen's view), also as a web page on http://127.0.0.1:9100;
4. the audit log is verified, including its trusted timestamp.

See [docs/deployment.md](docs/deployment.md) for setting up a network by hand and the configuration reference.

## What works today

| Area | Implemented |
| --- | --- |
| Identity | Private CA; Ed25519 member keys; enrolment with one-time tokens; automatic renewal with hot reload that retires the old key; certificate subject always the member id |
| Transport | Mutual TLS between security servers (`rustls`, `ring`) |
| Messages | Signed requests and responses, bound together by hash; body hashes; ±5 minute clock window |
| Access control | Per-service, default-deny rules evaluated by the provider; revocation through the directory |
| Replay and retries | Per-peer message id cache (rebuilt from the audit log after a restart); identical retries are idempotent |
| Shared nodes | One security server can host many members with separate keys, logs, tokens and rules ([deployment guide](docs/deployment.md#shared-nodes)); the operator holds the keys |
| Resilience | Durable async outbox with backoff; cached directory keeps working if the central server is down |
| Accountability | Hash-chained audit log on both sides, refuses to start on a broken chain, periodic trusted-timestamp anchors |
| Proofs | A signed proof header on every answer, verifiable offline with `zroad-cli proof-verify` |
| Transparency | Provider-side "who looked up this subject" query, without storing the subject in clear |

## Roadmap

- [x] **Phase 0: Design.** [Protocol spec](docs/protocol.md), addressing scheme, [threat model](docs/threat-model.md).
- [x] **Phase 1: Proof of concept.** Security servers exchanging signed, logged requests over mTLS, plus a central server.
- [x] **Phase 2: First use case.** ZIMRA tax clearance provider and buyer client.
- [x] **Phase 3: Resilience.** Durable outbox, retries with backoff, idempotent redelivery, cached directory.
- [x] **Phase 4: Transparency.** Access log by data subject and a demo citizen page (`examples/citizen-portal`). A real citizen-facing service still needs identity proofing of the citizen.
- [~] **Phase 5: Hardening.** Done: trusted timestamp anchoring, protocol specification, rate limits and timeouts, adversarial tests, replay cache rebuilt after restarts, certificate renewal and expiry monitoring, `unsafe` forbidden, clippy in CI. Still open: HSM-backed keys, offline root CA, coverage-guided fuzzing, and an independent security review.
- [ ] **Phase 6: Pilot.** A [plan](docs/pilot-plan.md) exists; it needs the legal groundwork in [docs/legal-considerations.md](docs/legal-considerations.md) and the open Phase 5 items first.

Not started: member-held keys on shared nodes, a service catalogue, ERP plug-ins.

## Documentation

- [Protocol specification](docs/protocol.md)
- [Threat model](docs/threat-model.md)
- [Running Z-Road](docs/deployment.md)
- [Legal and regulatory considerations](docs/legal-considerations.md)
- [Pilot plan](docs/pilot-plan.md)
- [Design note: shared security servers](docs/design/shared-nodes.md) (partly implemented)
- [Security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md)

## Contributing

Ideas, critique and contributions are welcome at this early stage, particularly on:

- Zimbabwean legal and regulatory requirements
- Protocol and threat-model review
- Rust implementation
- Real-world use cases and pilot partners

Open an issue to start a discussion. Before sending code, run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`.

## Acknowledgements

Z-Road is inspired by [X-Road](https://x-road.global/), developed in Estonia and now maintained by the Nordic Institute for Interoperability Solutions (NIIS). Z-Road is an independent project and is not affiliated with X-Road or NIIS.

## License

To be decided. A permissive open-source licence (Apache-2.0 or MIT) is likely.
