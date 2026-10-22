# Authority operator guide

*You run the heart of the network: the central server (certificate authority, directory, catalogue)
and the timestamp service. Everyone's trust rests on you, so this guide is strict.*

![A secure layout](../diagrams/secure-topology.svg)

## Your responsibilities

| Duty | How often |
| --- | --- |
| Verify who an organisation is **before** giving it an identity | Each new member |
| Keep `ca.key` safe | Always |
| Keep the central server and timestamp service up and patched | Always |
| Revoke members quickly when asked | On demand |
| Back up and test restores | Monthly |

## 1 · Set up (once)

Do the hardening in [02 · Deploy securely §1–§3](../02-deploy-securely.md). In short:

```sh
sudo -u zroad central-server init --dir /var/lib/zroad/central --san central.example.zw
sudo systemctl enable --now zroad-central
```

`init` creates the CA, the server identity and the first admin token. Then:

1. **Copy `ca.key` to encrypted offline storage** (two copies, two places). Protect it like a national seal.
2. Publish `ca.pem` somewhere members will trust (your website, in print, in person).
3. Enrol the timestamp service as a member and start it ([02 §3](../02-deploy-securely.md)).
4. Create **named** operators instead of using the first token:

```sh
central-server operator-add --dir /var/lib/zroad/central --name alice --role admin
central-server operator-add --dir /var/lib/zroad/central --name bob   --role auditor
central-server operator-list --dir /var/lib/zroad/central
```

## 2 · Onboarding a new member

![How an organisation joins](../../docs/diagrams/onboarding.svg)

1. **Verify the organisation**: legal identity, authority of the person applying, their endpoint. Keep a record.
2. **Register**:

   ```sh
   zroad-cli member-add --central https://central.example.zw:8443 --ca ca.pem \
     --admin-token-file admin.token --id ZW/GOV/ZIMRA --name "ZIMRA" \
     --endpoint https://ss.zimra.example.zw:7443
   ```

   It prints a **one-time enrolment token**.
3. **Send the token and `ca.pem` through different channels** (token by phone or in person; CA file by email or download). If one channel is intercepted the other alone is useless.
4. The member runs `zroad-cli enroll` (see the [provider](provider.md) or [consumer](consumer-developer.md) guide). **Their private key never leaves their machine.**
5. Confirm they are active:

   ```sh
   zroad-cli directory --central https://central.example.zw:8443 --ca ca.pem
   ```

**For a hosted member** add `--hosted-by ZW/NODE/<node>`. The endpoint is taken from the node. See [node operator](node-operator.md).

## 3 · Revoking a member

Revocation is **final**: the id cannot come back (they get a fresh registration after cleanup).

```sh
zroad-cli member-revoke --central https://central.example.zw:8443 --ca ca.pem \
  --admin-token-file admin.token --id ZW/COM/12345678
```

Peers stop trusting the member as they refresh the directory. Have an out-of-hours phone number members can call. See [incident response](../06-incident-response.md).

## 4 · Routine

Follow the [operations runbook](../05-operations-runbook.md). Authority-specific:

- Watch the central server's journal for `cannot renew` and for the **root CA expiry warning** (the root lasts ten years and is **not rotated automatically**).
- Review the directory monthly: unknown or stale members out.
- Keep the operator list short; remove leavers the same day.

## 5 · What can go wrong

| Event | Effect | Do |
| --- | --- | --- |
| Central server down | Members keep working from their last directory for a while; no new enrolments or renewals | Restore; keep a standby |
| `ca.key` leaked | An attacker can mint identities | [Playbook E](../06-incident-response.md) |
| Timestamp service down | New anchors fail; exchanges still work | Restore; anchors resume |
| Wrong member registered | They receive an identity | Revoke, investigate your verification step |

## Known gaps (be honest with your stakeholders)

`ca.key` is a file, not hardware; root-CA rotation is a rebuild; there is no operator multi-factor
login yet. All are on the [roadmap](../../ROADMAP.md) ahead of production.

[← All guides](../README.md) · [Security checklist](../08-security-checklist.md)
