# 01 · Quickstart: a whole network on your laptop

*Ten minutes. You will run a complete Z-Road network, make a signed request, and see every
safety feature work.*

**What you will have:** a central server (authority), a timestamp authority, a mock ZIMRA
tax-clearance system with its security server, and a company's security server, all on one machine.

> This is a **demo network**: one script creates every organisation's keys in one folder. A real
> network never does that; each organisation makes its own keys on its own machine. Do not
> expose the demo to anyone else.

## Option A: run it natively (needs Rust)

```sh
git clone https://github.com/phoscoder/z-road.git
cd z-road
scripts/demo.sh
```

The first run compiles for a few minutes. The script then walks through:

| Step | What you will see |
| --- | --- |
| What is on offer? | The service catalogue: `ZW/GOV/ZIMRA/tax-clearance/verify/v1` |
| A malformed request | `{"error":"schema_violation", ...}` — rejected **before** it reached ZIMRA's system |
| A valid supplier | `HTTP 200` and `"status":"VALID"` |
| An expired supplier | `"status":"EXPIRED"` |
| Verify the proof offline | `VALID`, plus who asked, what, and when |
| Who looked up this TIN? | The citizen's view, as JSON and as a web page |
| The audit log | `chain OK`, with a trusted timestamp |

Everything is under `/tmp/zroad-demo`. To keep the network running so you can try things:

```sh
ZROAD_DEMO_KEEP_SECS=300 scripts/demo.sh
```

## Option B: run it in containers (needs Docker)

```sh
docker compose -f deploy/docker-compose.yml up --build --wait
docker compose -f deploy/docker-compose.yml run --rm buyer-client
docker compose -f deploy/docker-compose.yml down -v      # when you are done
```

> The container files could not be run by their author; CI exercises them. If something fails,
> please open an issue with the output. See [packaging](../docs/packaging.md).

## Try it yourself

With the demo running (the company's security server listens on `127.0.0.1:7001`):

**1. Ask a question by hand**

```sh
curl -s -X POST http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1 \
  -H 'Z-Road-Client: ZW/COM/12345678/accounts-payable' \
  -H 'Content-Type: application/json' \
  -d '{"tin":"2000123456"}'
```

```json
{"name":"Supplier (Pvt) Ltd","status":"VALID","tin":"2000123456","valid_until":"2026-12-31"}
```

**2. Send something wrong**

```sh
curl -s -X POST http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1 \
  -H 'Z-Road-Client: ZW/COM/12345678/accounts-payable' \
  -H 'Content-Type: application/json' -d '{"tin":"not-a-tin"}'
```

```json
{"error":"schema_violation","message":"/tin: \"not-a-tin\" does not match \"^[0-9]{10}$\""}
```

**3. Pretend to be someone else**

```sh
curl -s -X POST http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1 \
  -H 'Z-Road-Client: ZW/COM/99999999/accounts-payable' -H 'Content-Type: application/json' -d '{}'
```

`invalid_request`: the company's security server only speaks for its own member.

**4. Use the Python or Rust client**

```python
# pip install -e path/to/z-road-python
from zroad_client import Client
z = Client("http://127.0.0.1:7001", "ZW/COM/12345678/accounts-payable")
print(z.call("ZW/GOV/ZIMRA/tax-clearance/verify/v1", {"tin": "2000123456"}).json())
```

**5. Queue a request for when the provider is down**

```sh
cargo run -q -p buyer-client -- --security-server http://127.0.0.1:7001 --tin 2000123456 --async
```

**6. Look at the evidence**

```sh
ls /tmp/zroad-demo/zimra/audit/      # the tamper-evident log
ls /tmp/zroad-demo/buyer/proofs/     # a signed proof per exchange
./target/debug/zroad-cli audit-verify \
   --log /tmp/zroad-demo/zimra/audit/log.jsonl \
   --directory /tmp/zroad-demo/zimra/directory.json
```

Now open the log, change one letter in the middle, and run `audit-verify` again: it fails at that entry.
That is what "tamper-evident" means.

**7. The citizen view**

Open <http://127.0.0.1:9100> and enter `2000123456`. You will see every organisation that looked
this TIN up. (The demo page vouches for whatever you type; a real one does not. See
[Citizen portal developer](users/citizen-portal-developer.md).)

## Run the tests

```sh
cargo test --workspace      # includes end-to-end tests over real mutual TLS
deploy/smoke-host.sh        # the whole compose network, as plain processes
```

## What next?

| I want to… | Go to |
| --- | --- |
| Understand what I just saw | [00 · How Z-Road works](00-concepts.md) |
| Deploy this for real | [02 · Deploy securely](02-deploy-securely.md) |
| Call a service from my application | [Consumer developer](users/consumer-developer.md) |
| Offer a service | [Data provider](users/provider.md) |
