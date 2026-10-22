# Pilot plan (draft)

Phase 6 of the roadmap is a pilot with willing institutions. This is a plan, not
something that has been run. The software in this repository is a proof of
concept and is not ready for production data; the pilot should start only after
the "before a pilot" items in [legal-considerations.md](legal-considerations.md)
and the high-severity gaps in [threat-model.md](threat-model.md) are closed.

## Goal

Show, with real organisations and low-risk data, that a signed and logged
exchange is faster and harder to forge than passing documents around, and learn
what breaks in real Zimbabwean network conditions.

## Candidate use case: supplier tax clearance check

* **Provider:** ZIMRA (or a ZIMRA-approved test environment). Service returns status and expiry for a TIN. No other data.
* **Consumers:** two or three companies with accounts-payable systems, plus an accounting software vendor running one shared node for several small customers (requires the shared-node feature, which does not exist yet).
* **Why this one:** read-only, narrow, low privacy risk, and a visible pain point today.

## Scope for a first pilot

* One provider, three consumers, one timestamp authority, one central server run by a neutral operator.
* Real certificates from a properly protected CA (offline root, HSM-backed intermediate).
* Real network conditions: at least one consumer on a connection that drops.
* No personal data beyond business TINs. A second phase can add a citizen-facing "who looked up my TIN" view.

## Success measures

| Measure | Target |
| --- | --- |
| Check latency (p95, normal conditions) | under 2 s |
| Requests completing through a 10 minute provider outage using the async outbox | 100% |
| Forged or expired certificates accepted | 0 |
| Operator time to onboard a new member | under 1 day |
| Users who prefer it to the emailed PDF | measured by survey |
| Audit log verifies end to end, with timestamp anchors | 100% |

## Work breakdown

1. **Governance.** Choose the authority; sign the agreements; DPIA; regulator engagement.
2. **Production readiness.** HSM or offline-root CA, durable replay cache, certificate renewal, authenticated admin, monitoring and alerting, packaging (container images, systemd units), backup and restore of keys and logs.
3. **Integration.** ZIMRA adapter that fronts their real system; ERP plug-ins or a small client library for consumers.
4. **Security.** Independent code review and penetration test; fix findings; publish a summary.
5. **Run.** Onboard participants, run for a fixed period, collect measures.
6. **Review.** Publish what was learned; decide whether to widen scope (Registrar General, banks and mobile money for KYC).

## Risks

| Risk | Mitigation |
| --- | --- |
| No institution is willing to host the authority | Start with a neutral technical operator under a memorandum of understanding, move to a statutory body later. |
| Data holders will not expose even narrow services | Begin with already-public checks; show value before asking for more. |
| Connectivity and power cuts | Async outbox and cached directory are built in; test them in the field, not just in CI. |
| Operational burden on small members | Shared nodes; hosted security server offered by a vendor. |
| Trust and perception (central surveillance fears) | Say plainly that no central database exists; publish the source; give citizens the "who looked at my data" view. |
