# 09 · Glossary

| Term | Plain meaning |
| --- | --- |
| **Authority** | The body that runs the network's trust: it approves members and issues their certificates |
| **Central server** | The authority's software: certificate authority, member directory, catalogue |
| **Security server** | The gateway each organisation runs. It signs, logs, checks and forwards messages. Applications talk to it, never to other organisations directly |
| **Timestamp service (TSA)** | A service that signs the time, so logs can be proved to exist before a given moment |
| **Member** | An organisation on the network, identified like `ZW/GOV/ZIMRA` (instance / class / code) |
| **Subsystem** | One system inside a member, such as `accounts-payable`. A client id is member + subsystem |
| **Provider** | A member that offers services |
| **Consumer** | A member whose applications call services |
| **Service** | A named, versioned operation, such as `tax-clearance/verify/v1` |
| **Catalogue** | The published list of services and their schemas |
| **Schema** | A JSON Schema describing what a service accepts and returns |
| **Access rule** | A provider's `[[access]]` entry saying which members may call a service |
| **Enrolment token** | A one-time secret that lets a new member obtain its certificate |
| **CA** | Certificate authority: signs members' certificates |
| **Certificate** | A signed statement that a public key belongs to a member |
| **mTLS** | Mutual TLS: both sides prove who they are with certificates |
| **Ed25519** | The signature algorithm used for messages |
| **Envelope** | A signed request or response, bound to its body by a hash |
| **Proof** | The signed request and response of one exchange, checkable offline by anyone with the directory |
| **Audit log** | A hash-chained record of everything a node did; altering any entry breaks the chain |
| **Anchor** | A timestamp signed by the TSA over the log's current state |
| **Replay** | Sending a previously captured message again; Z-Road rejects it |
| **Idempotent** | Safe to repeat: a retry returns the original answer rather than acting twice |
| **Outbox / queue** | Durable storage of a request to deliver later, with retries |
| **Shared node** | A security server run by a vendor on behalf of several small members |
| **Hosted member** | A member that uses a shared node rather than running its own |
| **Signer service** | A small service on a hosted member's machine that holds its key and signs for the node |
| **Operator** | A named person with an admin token and a role |
| **Role** | Auditor (read), Operator (act), Admin (manage), Portal (citizen endpoint only) |
| **Citizen assertion** | A short-lived signed statement from a login system that a person controls an identifier |
| **Subject** | The data subject an exchange is about, such as a citizen's id or a company's TIN |
| **Rotation** | Replacing a certificate or key before it expires, without dropped calls |
| **Revocation** | Removing a member's trust; final |
| **HSM** | Hardware security module: tamper-resistant hardware that holds keys and signs without revealing them (roadmap) |
| **Directory** | The list of members, their endpoints and certificates |
| **Pass-through** | Forwarding TLS bytes untouched, without decrypting |
