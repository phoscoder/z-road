# Hosted member guide

*You are a small organisation. A vendor runs the gateway (a **shared node**) for you, but **you keep
your own signing key** on your own machine. That means the vendor can carry your traffic but cannot
sign as you.*

![Hosted members](../diagrams/hosted-member.svg)

## Who holds what

| Item | Held by | Why |
| --- | --- | --- |
| Your private key (`key.pem`) | **You**, on your machine, used by the signer service | Only you can sign as you |
| Your certificate (`cert.pem`) and `ca.pem` | The node (public information) | The node needs them to check and present your identity |
| The network connection (TLS) | The node's own identity (`ZW/NODE/...`) | The node is the one connected |
| The audit log of your exchanges | The node, and the signer keeps its own list of what it signed | Compare the two to catch misuse |

## Before you start

- The authority has registered you with `--hosted-by ZW/NODE/<your-vendor>` and given you a one-time token and `ca.pem`.
- You have a small always-on machine (a VM or a spare server) that the node can reach on a port (default `9443`).
- You have agreed in writing with the vendor (contract, liability, how you leave: see [legal considerations](../../docs/legal-considerations.md)).

## Steps

1. **Enrol on your own machine**, using the node's host name as the SAN:

   ```sh
   zroad-cli enroll --central https://central.example.zw:8443 --ca ca.pem \
     --id ZW/COM/11111111 --token <token> --san node.example.zw --out ./signer
   ```
2. **Create the signer's own TLS identity and run it**:

   ```sh
   signer-service init --dir ./signer --san signer.acme.example
   signer-service run  --dir ./signer --listen 0.0.0.0:9443 \
     --member ZW/COM/11111111 --node ZW/NODE/acme-hosting \
     --central https://central.example.zw:8443
   ```

   With `--central` it renews your key and its own certificate automatically.
3. **Send the vendor only** `signer/cert.pem`, `signer/ca.pem` and `signer/signer-ca.pem`. **Never `key.pem`.**
4. The vendor adds you to the node ([node operator guide](node-operator.md)); it refuses to start if it finds a `key.pem` for you.
5. **Test**: call a service as in the [consumer guide](consumer-developer.md), using the node's address and the `/m/ZW/COM/11111111/` prefix (SDKs: `shared_node=True`).

## Keeping the signer healthy

| Task | How |
| --- | --- |
| Keep it running | Run it under systemd; restart on failure. If it is down your calls fail with `signer_unavailable` |
| Check what it signed | `zroad-cli audit-verify --log ./signer/audit/log.jsonl` |
| Compare with the node | The number and times of `signed` entries should match the exchanges the node reports |
| Back up | `signer/` (encrypted, off the machine) |
| Limit abuse | `--max-per-minute` caps how fast it will sign |

## What the node can and cannot do

| The node **can** | The node **cannot** |
| --- | --- |
| See your requests and responses as they pass | Sign as you |
| Refuse to carry your traffic | Change a signed message undetected |
| Keep or lose your logs | Make a provider accept a message you did not sign |

If you suspect the node, [revoke and move](../06-incident-response.md) (ask the authority).

## If something goes wrong

`signer_unavailable` → your signer is down or unreachable by the node. `hosting_mismatch`,
`not_the_node` → the registration and the node disagree. See [troubleshooting](../07-troubleshooting.md).

[← All guides](../README.md)
