# Integrating an application

Your systems never speak the Z-Road protocol. They make plain HTTP calls to
**your own** security server, which signs, encrypts, logs and delivers. Any
language that can make an HTTP request can integrate. The full contract is in
[openapi-internal.yaml](openapi-internal.yaml).

## The call

```
POST http://<your security server>/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1
Z-Road-Client:  ZW/COM/12345678/accounts-payable
Z-Road-Subject: 2000123456            (optional: who the query is about)
Content-Type:   application/json

{"tin":"2000123456"}
```

The response is the provider's answer, with the provider's own status code. Two
things to handle:

1. **Z-Road's own errors** have a `Z-Road-Error` header and a JSON body
   `{"error": "...", "message": "..."}`. `provider_unreachable` (503) and
   `rate_limited` (429) are worth retrying; `access_denied`, `unknown_provider`
   and `invalid_request` are not.
2. **Provider errors** (such as 404 "TIN not found") come back as normal
   responses without that header.

Keep the `Z-Road-Proof` response header (or fetch it later by message id) if you
may need to prove what was answered and when.

## When the provider might be down

Add `Z-Road-Mode: async`. You get `202` and a message id immediately; your
security server queues the request on disk and retries with backoff, safely
(the message id makes retries idempotent). Poll
`GET /internal/v1/outbox/<message_id>`.

Use synchronous calls for interactive screens, async for batch jobs, payment
runs and anything that must survive a provider outage or your own restart.

## Rust

```rust
use zroad_client::{CallOptions, Client};

let zroad = Client::new("http://127.0.0.1:7001", "ZW/COM/12345678/accounts-payable".parse()?);
let service = "ZW/GOV/ZIMRA/tax-clearance/verify/v1".parse()?;

let reply = zroad
    .call_json(&service, &serde_json::json!({ "tin": "2000123456" }), &CallOptions::default().subject("2000123456"))
    .await?;
let cleared = reply.json::<serde_json::Value>()?["status"] == "VALID";

// Queue it instead, and collect the answer later:
let id = zroad.submit(&service, br#"{"tin":"2000123456"}"#.to_vec(), &CallOptions::default()).await?;
let reply = zroad.wait(&id, std::time::Duration::from_secs(300)).await?;

// Prove it offline against a directory file:
let directory = serde_json::from_slice(&std::fs::read("directory.json")?)?;
let (request, response) = reply.verify(&directory)?;   // live replies only
```

`ClientError::ZRoad { code, retryable, .. }` carries Z-Road's error codes;
`ClientError::Unreachable` means your own security server is down.
`examples/buyer-client` is a complete small program.

## Other languages

The same call in a few lines. Treat a `Z-Road-Error` header as the error signal.

**Python**: there is a tested client library in its own repository ([phoscoder/z-road-python](https://github.com/phoscoder/z-road-python): `call`, `submit`/`wait`, typed errors). The bare-HTTP version:

```python
import requests
r = requests.post(
    "http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1",
    headers={"Z-Road-Client": "ZW/COM/12345678/accounts-payable", "Z-Road-Subject": tin},
    json={"tin": tin}, timeout=30)
if "Z-Road-Error" in r.headers:
    raise RuntimeError(r.json())          # r.json()["error"] is a stable code
cleared = r.json()["status"] == "VALID"
```

**PHP**

```php
$ch = curl_init('http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1');
curl_setopt_array($ch, [
  CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
  CURLOPT_HTTPHEADER => ['Z-Road-Client: ZW/COM/12345678/accounts-payable', 'Content-Type: application/json'],
  CURLOPT_POSTFIELDS => json_encode(['tin' => $tin]),
]);
```

**C#**

```csharp
var req = new HttpRequestMessage(HttpMethod.Post, "http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1")
{ Content = JsonContent.Create(new { tin }) };
req.Headers.Add("Z-Road-Client", "ZW/COM/12345678/accounts-payable");
var res = await http.SendAsync(req);
if (res.Headers.Contains("Z-Road-Error")) { /* Z-Road error: read res.Content as {error, message} */ }
```

The PHP and C# snippets are illustrations I have not run; the Python library has its own tests and was run against the demo network.

## Tips for ERP integrations

* Call from the server side, never from a browser. The internal API is not for end users.
* Put the security server's internal listener on a private network and set an `internal_token`; send it as `Authorization: Bearer ...`.
* Re-check a supplier's clearance **at payment time**, not only when the invoice is entered.
* Store the message id (and the proof, if you need evidence) next to the decision it supported.
* On a shared node, prefix paths with `/m/<your member id>`.
