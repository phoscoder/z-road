#!/usr/bin/env bash
# Run a complete local Z-Road network and make a tax clearance check.
#
#   central server ── timestamp authority
#        │
#   ZIMRA security server (provider) ── mock ZIMRA clearance system
#        │ mutual TLS
#   buyer security server (consumer) ── buyer-client
#
# Usage: scripts/demo.sh [workdir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-/tmp/zroad-demo}"
BIN="$ROOT/target/debug"
ADMIN_TOKEN="demo-admin-token-change-me"

cargo build --manifest-path "$ROOT/Cargo.toml" --workspace --quiet

rm -rf "$WORK"; mkdir -p "$WORK"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

CENTRAL=https://127.0.0.1:8443
CLI="$BIN/zroad-cli"
bg() { "$@" >>"$WORK/logs.txt" 2>&1 & PIDS+=($!); }

echo "==> central server"
"$BIN/central-server" init --dir "$WORK/central" --san 127.0.0.1 >/dev/null
bg "$BIN/central-server" run --dir "$WORK/central" --listen 127.0.0.1:8443
sleep 1
CA="$WORK/central/ca.pem"
TOKEN_FILE="$WORK/central/admin_token"

enroll() { # id name net-port dir
  local tok
  tok=$("$CLI" member-add --central $CENTRAL --ca "$CA" --admin-token-file "$TOKEN_FILE" \
        --id "$1" --name "$2" --endpoint "https://127.0.0.1:$3" 2>/dev/null)
  "$CLI" enroll --central $CENTRAL --ca "$CA" --id "$1" --token "$tok" --san 127.0.0.1 --out "$4" >/dev/null
}

echo "==> enrolling members"
enroll ZW/SYS/tsa      "Timestamp Authority" 8445 "$WORK/tsa"
enroll ZW/GOV/ZIMRA    "ZIMRA"               7443 "$WORK/zimra"
enroll ZW/COM/12345678 "Example Buyer (Pvt)" 7444 "$WORK/buyer"

echo "==> starting services"
bg "$BIN/timestamp-service" --dir "$WORK/tsa" --listen 127.0.0.1:8445
bg "$BIN/zimra-clearance" --listen 127.0.0.1:9001

cat >"$WORK/zimra.toml" <<EOF
member_id = "ZW/GOV/ZIMRA"
data_dir = "zimra"
central_url = "$CENTRAL"
network_listen = "127.0.0.1:7443"
internal_listen = "127.0.0.1:7002"
admin_token = "$ADMIN_TOKEN"
anchor_interval_secs = 5

[[services]]
id = "tax-clearance/verify/v1"
upstream = "http://127.0.0.1:9001/verify"
title = "Tax clearance check"
description = "Is this TIN cleared? Returns status and expiry only."

[[access]]
service = "tax-clearance/verify/v1"
allow = ["ZW/COM/*"]
EOF
cat >"$WORK/buyer.toml" <<EOF
member_id = "ZW/COM/12345678"
data_dir = "buyer"
central_url = "$CENTRAL"
network_listen = "127.0.0.1:7444"
internal_listen = "127.0.0.1:7001"
admin_token = "$ADMIN_TOKEN"
anchor_interval_secs = 5
EOF
bg "$BIN/security-server" run --config "$WORK/zimra.toml"
bg "$BIN/security-server" run --config "$WORK/buyer.toml"
sleep 2

echo
echo "==> what is on offer? (the public service catalogue)"
"$CLI" catalogue --central $CENTRAL --ca "$CA"
echo
echo "==> buyer checks a valid supplier"
"$BIN/buyer-client" --tin 2000123456 --proof-out "$WORK/proof.json"
echo
echo "==> buyer checks an expired supplier"
"$BIN/buyer-client" --tin 2000987654
echo
echo "==> verifying the signed proof offline"
"$CLI" proof-verify --proof "$WORK/proof.json" --directory "$WORK/buyer/directory.json"
echo
echo "==> who has looked up TIN 2000123456? (the citizen's view, from ZIMRA's log)"
"$CLI" access-log --security-server http://127.0.0.1:7002 --admin-token "$ADMIN_TOKEN" --subject 2000123456 | python3 -m json.tool 2>/dev/null || true
echo
echo "==> citizen portal demo: open http://127.0.0.1:9100 and enter 2000123456 (running until this script ends)"
bg "$BIN/citizen-portal" --security-server http://127.0.0.1:7002 --admin-token "$ADMIN_TOKEN" --directory "$WORK/zimra/directory.json"
sleep 1
curl -s "http://127.0.0.1:9100/?subject=2000123456" | grep -o "<td>[^<]*</td>" | head -4 || true
echo
echo "==> waiting for the audit log to be timestamped, then verifying it"
sleep 7
"$CLI" audit-verify --log "$WORK/zimra/audit/log.jsonl" --directory "$WORK/zimra/directory.json"
echo
echo "Logs: $WORK/logs.txt"
