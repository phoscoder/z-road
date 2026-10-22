# Access control: operators, roles and citizen login

Two different kinds of people touch a Z-Road node, and they are kept apart.

* **Operators** run and audit it: refresh the directory, renew certificates, read the
  audit log, register members. They have named accounts with roles.
* **Citizens** may ask one question: *who has looked at my record?* They are never
  given a token. A portal asks on their behalf and must prove, for each question,
  who is asking.

## Operators and roles

Every operator has their own random token (`zroad_` plus 256 random bits). The
configuration stores only its SHA-256, so a stolen config file does not leak working
credentials, and each person can be removed or investigated individually.

| Role | Can do | Typical holder |
| --- | --- | --- |
| `auditor` | read-only: audit status, identity, stored proofs, privileged access-log lookups | compliance, internal audit |
| `operator` | everything an auditor can, plus actions that change state: refresh the directory, anchor the log, renew the certificate, republish the catalogue (central: register members) | system administrators |
| `admin` | everything (central: also revoke members) | a small number of senior staff |
| `portal` | **only** the citizen endpoint, and only with a valid identity assertion | a citizen-facing web service |

`portal` is a separate lane: no other role can use the citizen endpoint, and a portal
token is refused everywhere else, so a compromised portal does not become an
administrator.

Create a token:

```sh
zroad-cli operator-token --name alice --role operator
# prints the token (once) and the config entry:
# [[operators]]
# name = "alice"
# role = "operator"
# token_sha256 = "…"
```

Security server (single member or per `[[members]]` entry):

```toml
[[operators]]
name = "alice"
role = "operator"
token_sha256 = "…"
```

The original single `admin_token` still works and is treated as an `admin` operator
named `legacy-admin`, so existing deployments keep running; prefer named operators and
remove it. At least one credential must be configured or the server refuses to start.
Invalid operator config (duplicate names or tokens, a portal with no citizen keys)
also stops startup.

Central server:

```sh
central-server operator-add --dir ./central --name registrar --role operator   # prints the token
central-server operator-list --dir ./central
central-server operator-remove --dir ./central --name registrar                 # effective immediately
```

Central operators are read from `operators.json` on every request, so adding or
removing one needs no restart. `operator` may register members, `admin` may also
revoke them, `auditor` can only read.

**Failed logins are slowed** (each costs 300 ms), which makes online guessing
pointless against 256-bit tokens without hurting anyone legitimate.

### Every privileged action is on the record

Before an administrative action runs, the security server (and the central server)
appends an `admin` entry to its hash-chained audit log: who (operator name and role),
what (`directory_refresh`, `anchor`, `certificate_renew`, `catalogue_publish`,
`proof_read`, `access_log_lookup`, `citizen_access_log`, central `member_add`,
`member_enroll`, `member_revoke`) and a detail such as a message id. If the entry
cannot be written, the action is **not performed** (503 `audit_unavailable`). Refused
attempts (wrong role) are logged to the process log, not as actions.

Lookups never put the data subject in the log in clear; they record the same keyed
hash that exchanges use. So the log answers "who looked up this person's access
history, and when" without containing the person's identifier. `zroad-cli
audit-verify` reports how many administrative actions a log holds.

## Citizen login: identity assertions

A citizen-facing page must not be able to read anybody's record by changing a
parameter. Instead:

1. Whatever system really authenticates the citizen logs them in. The natural choice
   is the provider's *own* login (a taxpayer logging in to ZIMRA e-services already
   proves they control their TIN). A national digital ID or a bank login also works.
2. That system issues a **signed identity assertion**: "the person who just logged in
   controls identifier X, for provider P, valid for at most 10 minutes". It is a small
   token: `base64(JSON) "." base64(Ed25519 signature)`.
3. The portal calls the provider's security server:

   ```
   GET /citizen/v1/access-log
   Authorization: Bearer <portal token>
   Z-Road-Citizen-Assertion: <assertion>
   ```

4. The security server checks the portal token (role `portal`), verifies the assertion
   against the issuers it trusts, checks it is for **this** provider and unexpired, and
   answers **only for the identifier inside the assertion**. Any `subject` parameter is
   ignored. A compromised portal can therefore read only the records of people who are
   logging in right now.

The answer lists, newest first, which organisation looked, when, for which service, and
the result. Internal details (which subsystem, message ids) are not shown to citizens.

Trusted issuers are configured on the provider:

```toml
[[citizen_assertion_keys]]
name = "zimra-login"
public_key_b64 = "…"     # raw Ed25519 public key, from `zroad-cli citizen-key`
```

An assertion is refused (`401 invalid_citizen_assertion`) if it is signed by an
unknown key, meant for another provider, expired, valid for longer than 10 minutes,
issued in the future, malformed, or altered (changing the subject breaks the
signature). Each answered lookup is recorded with the issuer and the assertion id.

### What is built and what is not

Built: the portal role, the assertion format and its verification, the endpoint, the
audit trail, a CLI to generate issuer keys and assertions for testing
(`zroad-cli citizen-key`, `zroad-cli citizen-assertion`), and an example portal
(`examples/citizen-portal`).

**Not built, and not possible to build generically: the login itself.** Something has
to authenticate the citizen and issue assertions. That is an integration with an
identity system (the provider's login, SMS or app one-time codes, a national ID if one
exists) that has to be done per provider. The example portal has a `--demo-idp-key`
mode in which the portal issues assertions to anyone who types an identifier. That
exists only so the demo can run end to end; it authenticates nobody and must never be
deployed.

### Residual risks

* The issuer is trusted completely for the identifiers it vouches for: a compromised
  login system can read any record it can mint an assertion for. Keep issuer keys
  protected (an HSM, if possible) and scope each issuer to one provider.
* A stolen assertion can be replayed until it expires (at most 10 minutes). Use short
  lifetimes; transport it over TLS only.
* Operator tokens are bearer secrets: anyone holding one is that operator. Store them
  in a secrets manager, never in chat or tickets, and rotate by removing and
  re-adding the operator.
* There is no single sign-on, multi-factor or session handling for operators; tokens
  are for scripts and consoles you control. Put a proper identity-aware proxy in front
  if people will use them interactively.
