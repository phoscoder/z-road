#!/usr/bin/env bash
# Start the same network docker-compose.yml describes, as plain processes on this machine,
# and check that it works end to end. It runs deploy/bootstrap.sh and then the very
# commands the compose services run, so it verifies everything except the container
# mechanics themselves (image build, networking, healthchecks), which CI checks with
# deploy/smoke-compose.sh.
#
#   deploy/smoke-host.sh            # uses target/debug (build first with cargo build --workspace)
#   BIN=target/release deploy/smoke-host.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug}"
DATA="$(mktemp -d /tmp/zroad-smoke.XXXXXX)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$DATA"; }
trap cleanup EXIT
fail() { echo "SMOKE TEST FAILED: $*" >&2; [ -f "$DATA/logs.txt" ] && tail -30 "$DATA/logs.txt" >&2; exit 1; }
bg() { "$@" >>"$DATA/logs.txt" 2>&1 & PIDS+=($!); }
wait_for() { # url
  for _ in $(seq 1 100); do curl -fs "$1" >/dev/null 2>&1 && return 0; sleep 0.3; done
  fail "timed out waiting for $1"
}
wait_port() { # port
  for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.3; done
  fail "timed out waiting for port $1"
}

echo "== bootstrap"
export DATA BIN LISTEN_ADDR=127.0.0.1 SCHEMAS="$ROOT/examples/zimra-clearance/schemas" \
       CENTRAL_HOST=127.0.0.1 TSA_HOST=127.0.0.1 ZIMRA_HOST=127.0.0.1 BUYER_HOST=127.0.0.1 UPSTREAM_HOST=127.0.0.1
bash "$ROOT/deploy/bootstrap.sh" >"$DATA/bootstrap.out" 2>&1 || { cat "$DATA/bootstrap.out"; fail "bootstrap"; }
bash "$ROOT/deploy/bootstrap.sh" 2>&1 | grep -q "already bootstrapped" || fail "bootstrap is not idempotent"
for f in zimra.toml buyer.toml secrets/central-admin.token secrets/zimra-auditor.token secrets/citizen-portal.token secrets/buyer-admin.token secrets/demo-idp.key central/ca.pem; do
  [ -s "$DATA/$f" ] || fail "bootstrap did not create $f"
done
# secrets are private, and no plaintext operator token reached a config file
[ "$(stat -c %a "$DATA/secrets")" = "700" ] || fail "secrets directory is not 0700"
if grep -q "zroad_" "$DATA"/*.toml; then fail "a plaintext token is in a config file"; fi

echo "== start the services (the commands docker-compose.yml runs)"
bg "$BIN/central-server" run --dir "$DATA/central" --listen 127.0.0.1:8443
wait_port 8443
bg "$BIN/timestamp-service" --dir="$DATA/tsa" --listen=127.0.0.1:8445 --central=https://127.0.0.1:8443
wait_port 8445
bg "$BIN/zimra-clearance" --listen 127.0.0.1:9001
wait_port 9001
bg "$BIN/security-server" run --config "$DATA/zimra.toml"
wait_for http://127.0.0.1:7002/health
bg "$BIN/security-server" run --config "$DATA/buyer.toml"
wait_for http://127.0.0.1:7001/health
sleep 1   # let the catalogue publish

echo "== catalogue"
"$BIN/zroad-cli" catalogue --central https://127.0.0.1:8443 --ca "$DATA/central/ca.pem" --schemas | grep -q "tax-clearance/verify/v1" || fail "catalogue is empty"

echo "== buyer-client, as in the compose demo"
out=$("$BIN/buyer-client" --security-server http://127.0.0.1:7001 --tin 2000123456 --proof-out "$DATA/proof.json") || fail "buyer-client"
echo "$out" | grep -q "HTTP 200" || fail "unexpected buyer-client output: $out"
echo "$out" | grep -q '"status":"VALID"' || fail "supplier not VALID: $out"

echo "== schema enforcement"
bad=$(curl -s -X POST http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1 \
      -H 'Z-Road-Client: ZW/COM/12345678/accounts-payable' -H 'Content-Type: application/json' -d '{"tin":"nope"}')
echo "$bad" | grep -q schema_violation || fail "malformed request was not rejected: $bad"

echo "== proof verifies offline"
"$BIN/zroad-cli" proof-verify --proof "$DATA/proof.json" --directory "$DATA/buyer/directory.json" | grep -q VALID || fail "proof did not verify"

echo "== operators and roles"
AUD=$(cat "$DATA/secrets/zimra-auditor.token")
"$BIN/zroad-cli" access-log --security-server http://127.0.0.1:7002 --admin-token "$AUD" --subject 2000123456 | grep -q ZW/COM/12345678 || fail "auditor cannot read the access log"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:7002/admin/v1/directory/refresh -H "Authorization: Bearer $AUD")
[ "$code" = "403" ] || fail "an auditor could change state (HTTP $code)"
PORTAL=$(cat "$DATA/secrets/citizen-portal.token")
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7002/admin/v1/audit/status -H "Authorization: Bearer $PORTAL")
[ "$code" = "403" ] || fail "the portal token reached an admin endpoint (HTTP $code)"

echo "== citizen portal"
bg "$BIN/citizen-portal" --listen 127.0.0.1:9100 --security-server http://127.0.0.1:7002 \
   --portal-token "$PORTAL" --provider ZW/GOV/ZIMRA --demo-idp-key "$DATA/secrets/demo-idp.key"
wait_for http://127.0.0.1:9100/
curl -s "http://127.0.0.1:9100/?subject=2000123456" | grep -q "ZW/COM/12345678" || fail "the citizen portal did not show the lookup"

echo "== audit log verifies"
out=$("$BIN/zroad-cli" audit-verify --log "$DATA/zimra/audit/log.jsonl" --directory "$DATA/zimra/directory.json" 2>&1) || fail "audit-verify: $(echo "$out" | head -3)"
echo "$out" | grep -q "chain OK" || fail "audit chain: $out"

echo "SMOKE TEST PASSED"
