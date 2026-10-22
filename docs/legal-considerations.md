# Legal and regulatory considerations

**This is not legal advice.** It is a list of questions to take to a Zimbabwean
lawyer and the relevant regulators before any real deployment. Statute names and
section references below should be checked against current text.

## Starting points

* **Cyber and Data Protection Act (2021).** Zimbabwe's data protection law. It
  designates POTRAZ as the Data Protection Authority. Check what it says about
  lawful bases for processing, data minimisation, cross-agency sharing,
  retention, data subject rights (access, correction, objection), breach
  notification, cross-border transfers, and the role of a data protection
  officer.
* **Sector rules** that already govern the likely first data holders: the
  Registrar General's Office (civil registry and national IDs), ZIMRA (tax
  confidentiality), the Reserve Bank and financial regulators (KYC and AML),
  telecom and mobile money regulation (POTRAZ, RBZ).
* **Electronic transactions and evidence law.** Whether a signed, logged
  Z-Road exchange is admissible and what weight it carries, and what is needed for
  its signatures to count as electronic signatures with legal effect.

## Questions to answer

### Who is who

* Who is the **governing authority** that runs the central server and decides who may join? A new body, an existing ministry, POTRAZ, ZICTA or another agency?
* Who is the **data controller** for each exchange? In this design the provider owns the data and decides who may use each service, and the consumer is a separate controller for what it does with the answer. Is that how the law sees it?
* Is the authority a **processor** or controller for anything? It sees membership and certificates but, by design, no exchanged data.

### What may be exchanged

* Per service: what is the legal basis, what is the minimum data, and who may call it? Example: a "is this TIN cleared?" check returns status and expiry only, no turnover or history.
* Does ZIMRA's tax confidentiality allow answering such a question to any registered company, or only with the taxpayer's consent? The design supports either (per-service access rules); the law decides which.
* Which services are **never** to be exposed (for example full tax returns, medical data) without explicit statutory authority?

### Citizen rights and transparency

* Must data subjects be able to see who accessed their data? The design records this (a keyed hash of the subject in the provider's log) and it is the basis of trust in Estonia's system. Decide who exposes it, how citizens authenticate, and for how long logs are kept.
* How are access requests, corrections and complaints handled across several organisations?

### Retention and evidence

* How long must audit logs be kept? Logs hold identifiers of members, services and message hashes, never the raw subject. Do they still count as personal data?
* Who is responsible for keeping proofs, and for how long?

### Security obligations

* Which minimum security controls does the law or a regulator expect for a national data exchange (key management, audits, incident reporting)?
* Is registration or licensing needed to operate a certificate authority issuing certificates used for electronic signatures?

### Cross-border

* May Z-Road be connected to other countries' exchange layers (as Estonia and Finland did)? Under what safeguards?

## Before a pilot

1. A written data sharing agreement for every service exposed, signed by provider and the authority.
2. A data protection impact assessment for the pilot.
3. Notification or consultation with the Data Protection Authority.
4. A published privacy notice that explains, in plain language, what is exchanged and how to see who accessed your data.
5. A named accountable owner for the central server and its keys.
