# Z-Road guides

Practical, step-by-step guides for everyone who sets up, uses, builds on, audits or
simply wants to understand a Z-Road network.

![Z-Road at a glance: an authority, providers, consumers, citizens and shared nodes](diagrams/network-overview.svg)

## Start here

| I want to… | Read |
| --- | --- |
| Understand what Z-Road is, in plain words | [00 · How Z-Road works](00-concepts.md) |
| See it running on my laptop in ten minutes | [01 · Quickstart](01-quickstart.md) |
| Set up and deploy a node **securely** | [02 · Deploy securely](02-deploy-securely.md) |
| Publish a service others can call | [03 · Building a service](03-building-a-service.md) |
| Write an SDK for a new language | [04 · SDK development](04-sdk-development.md) |
| Run it day to day | [05 · Operations runbook](05-operations-runbook.md) |
| Respond to a security incident | [06 · Incident response](06-incident-response.md) |
| Fix an error message | [07 · Troubleshooting](07-troubleshooting.md) |
| Check a deployment before go-live | [08 · Security checklist](08-security-checklist.md) |
| Look up a word | [09 · Glossary](09-glossary.md) |

## One guide per kind of user

Each of these starts from "who are you?" and ends with "you are connected". Pick yours.

| You are… | Your guide |
| --- | --- |
| A **decision-maker**: minister, director, regulator, funder | [Decision-maker](users/decision-maker.md) |
| The **authority operator**: you run the central server, the CA and the timestamps | [Authority operator](users/authority-operator.md) |
| A **data provider**: an agency or company that offers a service (for example ZIMRA) | [Data provider](users/provider.md) |
| A **developer** whose application calls services (ERP, accounting, banking, portals) | [Consumer developer](users/consumer-developer.md) |
| A **small organisation hosted** on a vendor's node, keeping its own key | [Hosted member](users/hosted-member.md) |
| A **vendor running a shared node** for several organisations | [Node operator](users/node-operator.md) |
| An **auditor** or compliance officer | [Auditor](users/auditor.md) |
| A **citizen** who wants to know who looked at their data | [Citizen](users/citizen.md) |
| A developer building a **citizen portal** | [Citizen portal developer](users/citizen-portal-developer.md) |

Not sure? [Which guide is mine?](users/README.md) has a short decision list.

## How the pieces fit

| Picture | What it shows |
| --- | --- |
| [Network at a glance](diagrams/network-overview.svg) | The cast: authority, providers, consumers, citizens, shared nodes |
| [Journey of one request](diagrams/request-journey.svg) | What happens from question to signed answer |
| [Who holds which key](diagrams/keys-and-trust.svg) | Every secret, who holds it, how bad a leak is |
| [A secure layout](diagrams/secure-topology.svg) | Network zones, ports and what faces whom |
| [Operators and roles](diagrams/roles-and-access.svg) | Who may do what |
| [Citizen view](diagrams/citizen-flow.svg) | How a citizen sees who looked at their record |
| [Hosted members](diagrams/hosted-member.svg) | A shared node with member-held keys |
| [Rotation](diagrams/rotation-timeline.svg) | How certificates are replaced without dropped calls |
| [Where an SDK fits](diagrams/sdk-layers.svg) | What an SDK does and never does |
| [Incident triage](diagrams/incident-triage.svg) | Where to start when something is wrong |

The diagrams are generated from [`diagrams/src`](diagrams/src); edit the Python and run
`python3 make_diagrams.py` to change them.

## Reference documents

The guides tell you *what to do*. The reference documents say *exactly how it works*:
[protocol](../docs/protocol.md) · [threat model](../docs/threat-model.md) ·
[deployment reference](../docs/deployment.md) · [access control](../docs/access-control.md) ·
[internal API (OpenAPI)](../docs/openapi-internal.yaml) · [integration](../docs/integration.md) ·
[packaging](../docs/packaging.md) · [legal considerations](../docs/legal-considerations.md) ·
[pilot plan](../docs/pilot-plan.md) · [roadmap](../ROADMAP.md)

## Conventions

- `code blocks` are commands you can copy. Replace anything in `<angle brackets>` or written like `example.zw`.
- Examples use the demo identities: `ZW/GOV/ZIMRA` (provider), `ZW/COM/12345678` (consumer), `ZW/SYS/tsa` (timestamp authority) and the central server at `https://central.example.zw:8443`.
- > **Tip** marks a shortcut. > **Warning** marks something that can hurt you if ignored.
- All commands were written against the code in this repository. Container steps are the exception: the author had no Docker to run them (see [packaging](../docs/packaging.md)).

> **Status.** Z-Road is a working, tested system that has **not** had an independent
> security review. Do not use it for real personal data until that has happened. See the
> [roadmap](../ROADMAP.md).
