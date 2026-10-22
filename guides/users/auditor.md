# Auditor guide

*You check that the network does what it says: that logs are intact, access followed the rules, and
particular exchanges really happened. You need to trust nothing on faith, and Z-Road is built so you don't have to.*

## What you can check yourself

| Question | Evidence | Tool |
| --- | --- | --- |
| Was the log altered? | The log is a hash chain; any change breaks it | `zroad-cli audit-verify --log log.jsonl` |
| Did it exist at that time? | Timestamp anchors signed by the timestamp service | `zroad-cli audit-verify --log log.jsonl --directory directory.json` |
| Did this exchange happen as claimed? | The signed request and response (the **proof**) | `zroad-cli proof-verify --proof p.json --directory directory.json` |
| Who looked at this person's record? | The provider's log | `zroad-cli access-log --security-server … --admin-token … --subject …` |
| Who was allowed to call what? | The provider's `[[access]]` rules and the `Admin` entries in the log | Read the config and log |
| Were certificates valid at the time? | The directory keeps previous certificates | `proof-verify` checks them for the exchange's time |

## What you need

1. **An auditor token** from the organisation (role `auditor`: read-only; it cannot change anything).
2. **A copy of the directory**: `zroad-cli directory --central … --ca ca.pem > directory.json`, or the node's own `directory.json`. Get `ca.pem` from the authority yourself.
3. **A copy of the log** (ask for it; verify it on your own machine, not theirs).

## A basic audit

```sh
# 1. Is the log intact, and are the anchors genuine?
zroad-cli audit-verify --log log.jsonl --directory directory.json

# 2. Pick exchanges at random and check both sides
curl -s -H "Authorization: Bearer $AUDITOR" $SS/admin/v1/proofs/<message-id> > p.json
zroad-cli proof-verify --proof p.json --directory directory.json

# 3. Ask the other party for THEIR record of the same message id and compare
```

Both parties log every exchange. A discrepancy between the two logs is itself a finding.

## What to look for

| Red flag | Why |
| --- | --- |
| Chain break or missing anchors | Tampering, or lost data |
| Long gaps in anchors | Timestamp service outage, or hiding |
| Many `access_denied` or `bad_signature` for one member | Probing, or a compromised key |
| Admin actions at odd hours | Unauthorised changes |
| Exchanges for a subject with no legitimate purpose | Misuse of access |
| Shared tokens (one name used by many people) | No accountability |
| Wildcards in `[[access]]` that are wider than needed | Over-broad access |

## Limits to be honest about

- The log shows what was **asked and answered**, not whether the person asking had a lawful purpose. That needs your own checks.
- An organisation can refuse to give you a log; the **other party's** copy still covers shared exchanges.
- Z-Road has not had an independent security review yet ([roadmap](../../ROADMAP.md)).

Use the [security checklist](../08-security-checklist.md) as your audit programme.

[← All guides](../README.md)
