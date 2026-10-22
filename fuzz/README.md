# Fuzzing

Coverage-guided fuzzing (libFuzzer via `cargo-fuzz`) of the code that parses
untrusted input. It needs a nightly toolchain, so this crate is kept out of the
main workspace.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run schema seeds/schema -- -max_total_time=120
```

| Target | What it attacks | Invariants checked |
| --- | --- | --- |
| `ids` | member, client and service id parsing, access patterns | never panics; parsed ids round-trip; no segment is empty, `.` or `..` |
| `wire_messages` | every JSON message a peer can send, signed-message opening, proof and timestamp verification | never panics; a proof or timestamp never verifies against an arbitrary key |
| `audit_log` | reading and verifying a hostile audit log file | never panics; `AuditLog::open` refuses exactly the logs that do not verify |
| `certificates` | certificate parsing, PEM handling, CSR signing | never panics; any issued certificate names the member it was issued for |
| `citizen` | citizen identity assertion verification | never panics; nothing not signed by a trusted key is ever accepted |
| `schema` | compiling schemas published by other members, checking instances | never panics; no pathological hang (libFuzzer's timeout would flag it) |

A crash is written to `fuzz/artifacts/<target>/`. Reproduce it with
`cargo +nightly fuzz run <target> artifacts/<target>/<file>`, fix the bug, and
add a regression test next to the code.

`seeds/` holds a few hand-written starting inputs; generated corpora are not
committed.

## What has been run

Each target was run for at least 45 seconds on the first pass (hundreds of
thousands of executions each), and the schema, wire message and audit log targets
for 150 seconds. The only crash found was a mistake in the fuzz target's own
assertion (it treated `a..b` as path traversal; only a whole segment of dots is),
which was fixed. That is a few minutes of fuzzing, which finds shallow bugs; it
says nothing about what a long campaign or a different strategy would find. A
weekly CI job (`.github/workflows/fuzz.yml`) keeps running them.

## What is not fuzzed

The HTTP handlers and the TLS stack as a whole (the end-to-end tests exercise
specific attacks but are not randomised), and the configuration parser.
