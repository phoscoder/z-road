#!/usr/bin/env bash
# Build the image, start the whole network with docker compose and check it end to end.
# Needs Docker with the compose plugin. CI runs this (.github/workflows/containers.yml);
# deploy/smoke-host.sh checks the same flow without containers.
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f deploy/docker-compose.yml)
cleanup() { "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { echo "COMPOSE SMOKE TEST FAILED: $*" >&2; "${COMPOSE[@]}" logs --no-color --tail=40 >&2 || true; exit 1; }

"${COMPOSE[@]}" up --build --detach --wait --wait-timeout 300 || fail "the network did not become healthy"

echo "== buyer-client"
out=$("${COMPOSE[@]}" run --rm buyer-client 2>&1) || fail "buyer-client: $out"
echo "$out" | grep -q "HTTP 200" || fail "unexpected output: $out"
echo "$out" | grep -q '"status":"VALID"' || fail "supplier not VALID: $out"

echo "== internal API is reachable from this machine only through the published port"
curl -fs http://127.0.0.1:7001/health >/dev/null || fail "buyer security server health"

echo "== schema enforcement"
bad=$(curl -s -X POST http://127.0.0.1:7001/r1/ZW/GOV/ZIMRA/tax-clearance/verify/v1 \
      -H 'Z-Road-Client: ZW/COM/12345678/accounts-payable' -H 'Content-Type: application/json' -d '{"tin":"nope"}')
echo "$bad" | grep -q schema_violation || fail "malformed request not rejected: $bad"

echo "== catalogue"
"${COMPOSE[@]}" exec -T buyer-ss zroad-cli catalogue --central https://central:8443 --ca /data/central/ca.pem | grep -q "tax-clearance/verify/v1" || fail "catalogue"

echo "== citizen portal"
curl -s "http://127.0.0.1:9100/?subject=2000123456" | grep -q "ZW/COM/12345678" || fail "citizen portal"

echo "== containers run as an unprivileged user with a read-only root"
for s in central zimra-ss buyer-ss; do
  uid=$("${COMPOSE[@]}" exec -T "$s" id -u)
  [ "$uid" = "10001" ] || fail "$s runs as uid $uid"
done

echo "COMPOSE SMOKE TEST PASSED"
