# Z-Road

**A secure data exchange layer for Zimbabwe, written in Rust.**

Z-Road lets government agencies, banks, companies and other organisations query each other's data directly, safely and with a full audit trail, without anyone building a single central database. It is inspired by Estonia's [X-Road](https://x-road.global/) and designed around the realities of Zimbabwe: patchy connectivity, power cuts, modest hardware and the need for public trust.

> **Status: concept / early design.** Nothing here is production software yet. The first milestone is a working proof of concept (see the [Roadmap](#roadmap)).

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
- [Planned repository layout](#planned-repository-layout)
- [Roadmap](#roadmap)
- [Getting started](#getting-started)
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

## Planned repository layout

This will be a single Cargo workspace so the protocol code is shared and end-to-end tests are simple. It can be split later if separate owners or release cycles emerge.

```
z-road/
  Cargo.toml              workspace
  crates/
    zroad-core/           message format, IDs, signing, log types
    security-server/      the main binary (axum + rustls)
    central-server/       member registry and certificate issuing
    timestamp-service/    starts as a stub
  examples/
    zimra-clearance/      sample provider service
    buyer-client/         sample consumer
  deploy/                 docker-compose, test certificates
  docs/                   architecture, diagrams, legal notes
```

## Roadmap

- [ ] **Phase 0: Design.** Protocol spec, addressing scheme, threat model.
- [ ] **Phase 1: Proof of concept.** Two security servers exchanging signed, logged requests over mTLS, plus a minimal central server.
- [ ] **Phase 2: First use case.** ZIMRA tax clearance provider and buyer client.
- [ ] **Phase 3: Resilience.** Message queueing, retries, offline tolerance.
- [ ] **Phase 4: Transparency.** Citizen-facing access log.
- [ ] **Phase 5: Hardening.** Security review, trusted timestamping, HSM support, formal spec.
- [ ] **Phase 6: Pilot.** Legal review and a pilot with willing institutions.

## Getting started

There is no code to run yet. Once the proof of concept lands, this section will cover building the workspace, generating test certificates and running two nodes locally with `docker compose`.

## Contributing

Ideas, critique and contributions are welcome at this early stage, particularly on:

- Zimbabwean legal and regulatory requirements
- Protocol and threat-model review
- Rust implementation
- Real-world use cases and pilot partners

Open an issue to start a discussion.

## Acknowledgements

Z-Road is inspired by [X-Road](https://x-road.global/), developed in Estonia and now maintained by the Nordic Institute for Interoperability Solutions (NIIS). Z-Road is an independent project and is not affiliated with X-Road or NIIS.

## License

To be decided. A permissive open-source licence (Apache-2.0 or MIT) is likely.
