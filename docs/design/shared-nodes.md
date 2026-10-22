# Design note: shared security servers

**Status: partly implemented.** Operator-held keys (mode 1 below) work today: one
security server process can host several members, each with its own identity,
audit log, outbox, tokens, services and access rules, behind shared listeners.
Member-held keys (mode 2), SNI-based certificate selection and the open
questions are still proposals. See the *Shared nodes* section of
[deployment.md](../deployment.md) for how to run one.

### What was built, and how it differs from the sketch

* One mutual-TLS listener and one internal listener serve every hosted member.
* Incoming requests are routed by the `service.member` in the signed envelope
  (peeked at before verification, then fully verified by the chosen member).
  A request for a member the node does not host is refused as `wrong_provider`
  and only logged to the process log, because no hosted member is accountable
  for it.
* The node's TLS server presents one certificate slot shared by all its members;
  whichever member renewed most recently puts its fresh certificate there. Peers
  check chain and host name at the TLS layer. The identity they rely on is the
  provider's signature on each answer, checked against the directory.
* Outbound calls use the calling member's own certificate, so the provider sees
  the right authenticated peer.
* Internal API paths are `/m/<instance>/<class>/<code>/...` on a multi-member
  node, with per-member tokens. Members cannot call or administer each other.
* The directory cache is node-level (`node_dir`), not per member.


## Problem

A security server is real operational work: a host to run it, certificates to
renew, logs to keep, patches to apply. Large organisations can do that. A small
company, a rural clinic or a district office usually cannot, and if only large
organisations can join, most of the value of Z-Road is lost.

## Goal

Let a trusted operator (an accounting software vendor, a bank, a chamber of
commerce, a government ICT centre) run one security server on behalf of many
members, **without** the operator being able to impersonate those members and
without the members' audit trails being mixed up.

## Sketch

1. **One node, many members.** The node's configuration lists several member
   identities. Each member has its own key pair and certificate, issued by the
   central server as today, with the same endpoint host (the node's).
2. **Choosing the certificate.** The node's TLS listener picks the member
   certificate from the SNI name (`ss-12345678.nodes.example.zw`) or from a
   per-member path prefix. A custom `rustls` `ResolvesServerCert` does this.
   Outbound calls present the certificate of the member on whose behalf they are
   made.
3. **Per-member state.** Audit log, outbox, proofs, subject key, access rules and
   dedupe cache all become per-member directories under the node's data
   directory. `AppState` becomes a map from member id to the state we have today.
4. **Internal API.** Each member's systems authenticate with their own token. The
   `Z-Road-Client` header must belong to the member that token maps to.
5. **Keys.** Two modes:
   * *Operator-held keys*: simplest, but the operator can sign as the member.
     Acceptable only where the legal arrangement says so.
   * *Member-held keys*: the member keeps its private key (in an HSM, a hardware
     token, or its own small signer service) and the node asks it to sign each
     message through the `Signer` trait. TLS then needs a delegated certificate
     or a node-level TLS identity with application-level signing as the proof of
     authorship. This is the stronger model and the one to aim for.
6. **Directory.** Members registered on a shared node point to the same endpoint
   host; the central server must allow several members per host.

## Open questions

* TLS identity: is the TLS peer the node or the member? Today a peer's member id
  comes from its certificate and must match the signed `client`. With
  member-held keys and a node-level TLS identity, that check moves entirely to
  the message signature, and the TLS layer only proves "a registered node".
* Liability and contracts between member and operator.
* How a member leaves a node (key handover, log export) without losing its audit
  history.
* Per-member rate limits and fair sharing.

## What would change in the code

* `zroad-core`: nothing in the message format. Possibly a `NodeId`.
* `zroad-net`: SNI-based certificate resolver.
* `security-server`: per-member state map; config with several `[[member]]` blocks.
* `central-server`: allow several members per endpoint; record the node operator.
* Tests: two members on one node calling each other and a third party, with
  separate audit logs.
