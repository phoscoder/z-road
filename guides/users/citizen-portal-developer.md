# Citizen portal developer guide

*You are building the web page or app that lets a person see who has looked at their data. The hard
part is not the page: it is proving to the provider that the person in front of you controls the
identifier you are asking about.*

![How a citizen sees who looked](../diagrams/citizen-flow.svg)

## How it works

1. A system that really **authenticates** the person logs them in. Best choice: the provider's own login, because a taxpayer logging in to ZIMRA e-services already proves they control their TIN. A bank login or a national ID also works.
2. That system issues a **signed identity assertion**: "this person controls identifier X, for provider P, valid for at most 10 minutes". Format: `base64(JSON) "." base64(Ed25519 signature)`.
3. Your portal calls the provider's security server:

   ```http
   GET /citizen/v1/access-log
   Authorization: Bearer <portal token>
   Z-Road-Citizen-Assertion: <assertion>
   ```
4. The security server checks your portal token (role `portal`), checks the assertion (issuer trusted, for this provider, not expired, not tampered) and answers **only for the identifier inside it**. A `subject` parameter is ignored.

So a compromised portal can read only the records of people who are logging in right now.

## What you need

| Item | From |
| --- | --- |
| A **portal token** (role `portal`) | The provider's operator: `zroad-cli operator-token --name citizen-portal --role portal` |
| The provider's **internal** address | The provider |
| A trusted **issuer key** registered with the provider | The login system's owner: `zroad-cli citizen-key --out issuer.key --name zimra-login` prints the public key; the provider adds it as `[[citizen_assertion_keys]]` |

## Build it

1. Log the person in (your integration with the provider's login).
2. Create the assertion **server side** with the issuer's private key. Never in the browser. The key is kept by the login system, not by the portal.
3. Call the endpoint with the portal token and the assertion. Show the result.

To try it without a real login, use the CLI:

```sh
zroad-cli citizen-key --out issuer.key --name test-login          # prints the public key
zroad-cli citizen-assertion --key issuer.key --subject 2000123456 \
  --aud ZW/GOV/ZIMRA --ttl-secs 300
```

Provider config (`[[citizen_assertion_keys]] name = "test-login", public_key_b64 = "…"`), and an
operator with role `portal`. A complete example portal is in `examples/citizen-portal`.

> The example portal's `--demo-idp-key` mode issues assertions to **anyone who types an identifier**.
> It exists only so the demo runs end to end. **Never deploy it.**

## The answer

The list is newest first: which organisation looked, when, for which service, and the result.
Internal details (subsystem, message ids) are not included.

## Errors

| Code | Cause |
| --- | --- |
| `citizen_assertion_required` | Header missing |
| `invalid_citizen_assertion` | Unknown issuer, wrong provider, expired, over 10 minutes long, altered or malformed |
| `forbidden` | Your token is not the `portal` role (or you used a portal token elsewhere: it works nowhere else) |
| `unauthorized` | Missing or wrong token |

## Rules for a safe portal

- Issue assertions only after a real login. Short lifetime, one provider each.
- Keep the portal token and issuer key in a secret store; never ship them to a browser.
- Do not log assertions or personal identifiers.
- Show the person only what the endpoint returns.
- Scope each issuer key to one provider; rotate keys.

## Known gaps

The login itself is not part of Z-Road; each provider must integrate their identity system. A
compromised issuer can vouch for anyone it chooses; a stolen assertion works until it expires. See
[access control](../../docs/access-control.md).

[← All guides](../README.md)
