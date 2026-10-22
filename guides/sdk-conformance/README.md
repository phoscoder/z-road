# SDK conformance scenarios

`scenarios.json` is a language-neutral list of behaviour tests for a Z-Road SDK. If your
SDK passes all of them, it behaves like the reference clients on everything that matters
for safety and error handling. See [04 · SDK development](../04-sdk-development.md).

## How to use it

1. Write a tiny fake HTTP server in your language that **replays the scenario's `responses`
   in order** (or, with `server_down: true`, is simply not running; with
   `repeat_last_response: true`, repeats the last response forever) and records every request it receives.
2. For each scenario: build a client from `constants.client` and `client_options`, pointing at the
   fake server; run `operation`; compare.
3. Replace `{client}` and `{service}` with `constants.client` and `constants.service`.

Each scenario has:

| Field | Meaning |
| --- | --- |
| `name`, `description` | What it tests |
| `client_options` | `token` (internal token), `shared_node` (use `/m/<member>` paths) |
| `operation` | `type` is `call`, `submit`, `poll` or `wait`, with `service`, `body`, `subject`, `message_id`, `max_wait_secs`, `interval_secs` |
| `responses` | What the fake server answers, in order: `status`, `headers`, `body` (an object is sent as JSON, a string as is) |
| `expect_requests` | What the server must have received. `headers` are a **subset**, compared case-insensitively; `json_body` is the parsed body |
| `expect` | The outcome, below |

`expect` is one of:

| Shape | Meaning |
| --- | --- |
| `{"reply": {"status", "ok", "json", "message_id", "proof_present"}}` | A reply; any listed field must match |
| `{"error": {"kind": "zroad", "status", "code", "retryable"}}` | An error raised by Z-Road |
| `{"error": {"kind": "unreachable", "retryable": true}}` | Your own security server could not be reached |
| `{"error": {"kind": "queue_failed"}}` / `{"error": {"kind": "timeout", "retryable": true}}` | A queued request failed / `wait` gave up |
| `{"message_id": "m1"}` | `submit` result |
| `{"queued": {"state", "attempts", "last_error", "reply", "error"}}` | `poll` result (`state` is `pending`, `delivered` or `failed`) |

`invalid_clients` lists client ids your constructor must reject.

The Python client's test suite runs these exact scenarios
([`tests/test_conformance.py`](https://github.com/phoscoder/z-road-python/blob/main/tests/test_conformance.py)):
read it as a worked example of a runner.
