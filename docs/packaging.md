# Packaging: containers and systemd

Two ready-made ways to run Z-Road without assembling it by hand.

| | For | What you get |
| --- | --- | --- |
| **Docker Compose** (`deploy/docker-compose.yml`) | trying it, demos, local development | a whole network on one machine with one command |
| **systemd units** (`deploy/systemd/`) | running a real node on a Linux server | hardened services, one per component |

> **Testing status.** The sandbox these files were written in has no Docker daemon, so
> the **Dockerfile and compose file have not been run by their author**. What has been
> checked: the compose file parses and its services are consistent; the bootstrap script
> and every command the compose services run are exercised end to end by
> `deploy/smoke-host.sh` (the same network as plain processes), which passes; the systemd
> units pass `systemd-analyze verify`. The container mechanics (image build, networking,
> healthchecks, read-only roots) are exercised by `deploy/smoke-compose.sh`, which CI runs
> on GitHub (`.github/workflows/containers.yml`). Treat the first CI run as the real test.

## Docker Compose: a complete demo network

```sh
docker compose -f deploy/docker-compose.yml up --build --wait   # build, bootstrap, start, wait until healthy
docker compose -f deploy/docker-compose.yml run --rm buyer-client   # a tax clearance check
```

Then:

* the buyer's security server API is on `http://127.0.0.1:7001` (bound to this machine only);
* the demo citizen page is on `http://127.0.0.1:9100` (type `2000123456`);
* tokens for the operators created by the bootstrap are in the volume under `/data/secrets`:
  `docker compose -f deploy/docker-compose.yml exec zimra-ss cat /data/secrets/zimra-auditor.token`;
* `docker compose -f deploy/docker-compose.yml down -v` removes everything.

What starts: `init` (a one-shot that creates the CA, enrols the members and writes
configuration and tokens into a volume), `central`, `tsa`, `zimra-system` (the mock tax
system), `zimra-ss` and `buyer-ss` (security servers), and `citizen-portal`.

Hardening in the compose file: every service runs as a non-root user (uid 10001) with all
capabilities dropped, `no-new-privileges`, and a read-only root file system (only the data
volume is writable); healthchecks gate start-up order; only the two demo ports are
published, and only on `127.0.0.1`.

**This is a demo network.** One bootstrap step creates every member's keys in one volume,
which is exactly what a real deployment must not do: there, each organisation generates
its own keys on its own machine and only a certificate request and enrolment token cross
between them ([deployment.md](deployment.md)). The citizen page vouches for whatever
identifier you type. Do not expose this network to anyone else.

### Using the image on its own

`docker build -t zroad:local .` builds one image with every binary (`central-server`,
`timestamp-service`, `security-server`, `signer-service`, `zroad-cli` and the examples).
It has no default service: pick one with a command, mount configuration and state at
`/data`, and run it as a non-root user. `/data` should be a persistent volume: it holds
keys and the audit log.

## systemd

```sh
cargo build --release --workspace
sudo deploy/systemd/install.sh            # user, directories, binaries, units; starts nothing
```

Units: `zroad-central`, `zroad-timestamp`, `zroad-security-server@<name>` (one instance
per `/etc/zroad/<name>.toml`) and `zroad-signer`. They run as the unprivileged `zroad`
user with state in `/var/lib/zroad/<name>` (mode 0700) and are sandboxed: no new
privileges, read-only system, private `/tmp`, no devices, no kernel tunables, only
IPv4/IPv6 sockets, no capabilities, `MemoryDenyWriteExecute`, `UMask=0077`. The security
server unit checks its configuration before starting (`ExecStartPre`) and restarts on
failure.

You still have to create the identities (CA, enrolment, keys) following
[deployment.md](deployment.md) and put them under `/var/lib/zroad`; edit the host names
and member ids in the unit files before enabling them. Services bind `0.0.0.0` on ports
above 1024 so they need no capabilities; put the internal listener of a security server
on a private address in its config, and firewall the network ports to known members where
you can.

## Smoke tests

```sh
deploy/smoke-host.sh       # no Docker: bootstrap + the compose commands as plain processes
deploy/smoke-compose.sh    # Docker: builds the image and checks the real compose network
```

Both check: bootstrap is idempotent and leaves no plaintext token in a config; the
catalogue lists the service; a clearance check returns `VALID`; a malformed request is
refused with `schema_violation`; the signed proof verifies offline; an auditor token can
read the access log but not change state; the portal token cannot reach admin endpoints;
the citizen page shows the lookup; and the audit log verifies. The compose version also
checks that containers run as uid 10001.
