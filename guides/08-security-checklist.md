# 08 · Security checklist

*Tick every box before go-live, and again each quarter. If you cannot tick one, write down why.*

![A secure layout](diagrams/secure-topology.svg)

## Network

- [ ] Only the **network port** (7443) is reachable from outside, and only 22 from a bastion
- [ ] The **internal listener** is bound to a private address, never `0.0.0.0` on a public interface
- [ ] Mutual TLS is **passed through** (TCP) by any load balancer or firewall; nothing terminates it
- [ ] Outbound is allowed only to the central server, the timestamp service and your own upstream
- [ ] Provider upstream systems accept calls only from the security server
- [ ] DNS for the registered endpoint matches the certificate's `--san`
- [ ] Clocks are kept by NTP on every machine

## Keys and secrets

- [ ] `key.pem` is mode 600, owned by the service user, and exists on one machine only
- [ ] `ca.key` (authority) lives offline or in a protected store, with a tested encrypted backup
- [ ] The enrolment token and `ca.pem` were delivered through **different** channels
- [ ] Hosted members keep their key in a signer service on **their own** machine
- [ ] No secrets in the config repository, shell history, tickets or chat
- [ ] The legacy single `admin_token` is not set

## People and access

- [ ] Every operator has a **named** token with the least role they need
- [ ] The portal role is used only for citizen portals
- [ ] `[[access]]` rules are explicit: default is deny, wildcards (`ZW/COM/*`) are deliberate
- [ ] `internal_token` is set and long; applications send it as `Authorization: Bearer`
- [ ] A leaver process removes operator tokens and SSH access the same day

## Data and audit

- [ ] Services publish **request and response schemas**, with `enforce_response_schema = true` where possible
- [ ] The audit log is on its own volume with alerts before it fills
- [ ] The log is copied off the machine continuously and verified weekly with `audit-verify`
- [ ] Timestamp anchoring is on (`anchor_interval_secs` set) and anchors verify
- [ ] Retention is agreed and written down ([legal considerations](../docs/legal-considerations.md))
- [ ] Citizen endpoints answer only for the subject inside a valid assertion

## Host

- [ ] Services run as an unprivileged user under the provided systemd units (hardening on)
- [ ] The OS is patched; unattended security updates on
- [ ] Disk is encrypted; backups are encrypted
- [ ] Only needed packages are installed; SSH uses keys only
- [ ] A restore from backup has been tested

## Operations

- [ ] Alerts exist for: service down, `audit/status` not verified, certificate under 30 days, disk over 80%, repeated `bad_signature` or `access_denied`
- [ ] [Incident response](06-incident-response.md) has been read by the on-call team and a contact list exists
- [ ] The authority's contact for revocation is known and reachable out of hours
- [ ] Software versions are recorded and updates are planned

## Before opening to real data

- [ ] An independent security review of the deployment (and of Z-Road itself, which has not yet had one: see the [roadmap](../ROADMAP.md))
- [ ] The [pilot plan](../docs/pilot-plan.md) gates are met
- [ ] Legal basis, data-sharing agreements and data protection impact assessment are in place

> **Honest note.** Z-Road has been built and tested carefully, but it has **not** had an independent
> security audit, and key custody in hardware (an HSM) is still on the roadmap. Do not put sensitive
> production data through it until those are done.
