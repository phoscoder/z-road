# Contributing

Thanks for looking. At this stage the most useful contributions are critique of
the design and the threat model, Zimbabwean legal and regulatory input, and real
use cases.

For code:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace      # includes end-to-end tests over real mutual TLS
scripts/demo.sh             # sanity-check the whole flow
```

Guidelines:

* Keep the protocol described in [docs/protocol.md](docs/protocol.md) in step with the code.
* Add a test for every rejected-request path you add or change (see `crates/e2e-tests`).
* `unsafe` is forbidden in this workspace.
* Code that parses untrusted input should get a fuzz target in `fuzz/` (see `fuzz/README.md`).
* Prefer small dependencies from well-known maintainers and run `cargo audit`.
