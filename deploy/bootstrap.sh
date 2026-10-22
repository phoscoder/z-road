#!/usr/bin/env bash
# Generate the identities and configuration for a complete, self-contained Z-Road
# demo network: a central server (CA and directory), a timestamp authority, ZIMRA (a
# provider with a mock tax clearance system) and a buyer company (a consumer).
#
# It is meant to run once, before the services start (the `init` service in
# docker-compose.yml does that). It is also used by deploy/smoke-host.sh, which runs the
# same steps with plain processes. Everything is written under $DATA; running it
# again does nothing.
#
# This is a DEMO bootstrap. A real deployment has the authority, ZIMRA and the buyer
# on different machines run by different people, each generating its own keys:
# see docs/deployment.md.
set -euo pipefail

DATA="${DATA:-/data}"
BIN="${BIN:-/usr/local/bin}"
SCHEMAS="${SCHEMAS:-/usr/local/share/zroad/schemas}"
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0}"         # what the services bind to
OWNER="${OWNER:-}"                             # e.g. 10001:10001, to hand the files to the service user

# Host names the services are reached at (docker-compose service names by default).
CENTRAL_HOST="${CENTRAL_HOST:-central}"
TSA_HOST="${TSA_HOST:-tsa}"
ZIMRA_HOST="${ZIMRA_HOST:-zimra-ss}"
BUYER_HOST="${BUYER_HOST:-buyer-ss}"
UPSTREAM_HOST="${UPSTREAM_HOST:-zimra-system}"
# Ports (distinct, so the same script also works with everything on one machine).
CENTRAL_PORT="${CENTRAL_PORT:-8443}"
TSA_PORT="${TSA_PORT:-8445}"
ZIMRA_NET_PORT="${ZIMRA_NET_PORT:-7443}"
ZIMRA_INTERNAL_PORT="${ZIMRA_INTERNAL_PORT:-7002}"
BUYER_NET_PORT="${BUYER_NET_PORT:-7444}"
BUYER_INTERNAL_PORT="${BUYER_INTERNAL_PORT:-7001}"
UPSTREAM_PORT="${UPSTREAM_PORT:-9001}"

if [ -f "$DATA/.bootstrapped" ]; then
  echo "already bootstrapped ($DATA/.bootstrapped); nothing to do"
  exit 0
fi

CLI="$BIN/zroad-cli"
CENTRAL_LOCAL="https://127.0.0.1:$CENTRAL_PORT"   # the temporary central used for enrolment
CENTRAL_URL="https://$CENTRAL_HOST:$CENTRAL_PORT" # what the services use

mkdir -p "$DATA"/{central,tsa,zimra,buyer}
mkdir -m 700 -p "$DATA/secrets"

# unique --san arguments for the central server
sans=(--san 127.0.0.1)
[ "$CENTRAL_HOST" != "127.0.0.1" ] && sans+=(--san "$CENTRAL_HOST")

echo "==> central server: CA and directory"
"$BIN/central-server" init --dir "$DATA/central" "${sans[@]}" >/dev/null
"$BIN/central-server" run --dir "$DATA/central" --listen "127.0.0.1:$CENTRAL_PORT" >"$DATA/central-bootstrap.log" 2>&1 &
CENTRAL_PID=$!
trap 'kill "$CENTRAL_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  (exec 3<>"/dev/tcp/127.0.0.1/$CENTRAL_PORT") 2>/dev/null && break
  sleep 0.2
done

CA="$DATA/central/ca.pem"
TOKEN_FILE="$DATA/central/admin_token"
# A named administrator for the person running the demo, instead of the shared token.
"$BIN/central-server" operator-add --dir "$DATA/central" --name admin --role admin >"$DATA/secrets/central-admin.token" 2>/dev/null
chmod 600 "$DATA/secrets/central-admin.token"

enroll() { # id name host port dir
  local tok
  tok=$("$CLI" member-add --central "$CENTRAL_LOCAL" --ca "$CA" --admin-token-file "$TOKEN_FILE" \
        --id "$1" --name "$2" --endpoint "https://$3:$4" 2>/dev/null)
  "$CLI" enroll --central "$CENTRAL_LOCAL" --ca "$CA" --id "$1" --token "$tok" --san "$3" --out "$5" >/dev/null
}

echo "==> enrolling members"
enroll ZW/SYS/tsa      "Timestamp Authority" "$TSA_HOST"   "$TSA_PORT"        "$DATA/tsa"
enroll ZW/GOV/ZIMRA    "ZIMRA"               "$ZIMRA_HOST" "$ZIMRA_NET_PORT"  "$DATA/zimra"
enroll ZW/COM/12345678 "Example Buyer (Pvt)" "$BUYER_HOST" "$BUYER_NET_PORT"  "$DATA/buyer"

# Named operators with roles. Only each token's hash goes into a config; the tokens
# themselves are written once to $DATA/secrets.
mkop() { # name role config-file
  local tok
  tok=$("$CLI" operator-token --name "$1" --role "$2" 2>"$DATA/secrets/$1.snippet")
  printf '%s\n' "$tok" >"$DATA/secrets/$1.token"
  { echo; grep -v '^#' "$DATA/secrets/$1.snippet"; } >>"$3"
  rm -f "$DATA/secrets/$1.snippet"
}

echo "==> ZIMRA security server configuration"
cat >"$DATA/zimra.toml" <<EOF
member_id = "ZW/GOV/ZIMRA"
data_dir = "$DATA/zimra"
central_url = "$CENTRAL_URL"
network_listen = "$LISTEN_ADDR:$ZIMRA_NET_PORT"
internal_listen = "$LISTEN_ADDR:$ZIMRA_INTERNAL_PORT"
anchor_interval_secs = 30

[[services]]
id = "tax-clearance/verify/v1"
upstream = "http://$UPSTREAM_HOST:$UPSTREAM_PORT/verify"
title = "Tax clearance check"
description = "Is this TIN cleared? Returns status and expiry only."
request_schema = "$SCHEMAS/verify.request.json"
response_schema = "$SCHEMAS/verify.response.json"
enforce_response_schema = true

[[access]]
service = "tax-clearance/verify/v1"
allow = ["ZW/COM/*"]
EOF
mkop zimra-auditor auditor "$DATA/zimra.toml"
mkop citizen-portal portal "$DATA/zimra.toml"
"$CLI" citizen-key --out "$DATA/secrets/demo-idp.key" --name demo-login | grep -v '^private key' >"$DATA/secrets/demo-idp.snippet"
{ echo; cat "$DATA/secrets/demo-idp.snippet"; } >>"$DATA/zimra.toml"

echo "==> buyer security server configuration"
cat >"$DATA/buyer.toml" <<EOF
member_id = "ZW/COM/12345678"
data_dir = "$DATA/buyer"
central_url = "$CENTRAL_URL"
network_listen = "$LISTEN_ADDR:$BUYER_NET_PORT"
internal_listen = "$LISTEN_ADDR:$BUYER_INTERNAL_PORT"
anchor_interval_secs = 30
EOF
mkop buyer-admin admin "$DATA/buyer.toml"

kill "$CENTRAL_PID" 2>/dev/null || true
wait "$CENTRAL_PID" 2>/dev/null || true
trap - EXIT
rm -f "$DATA/central-bootstrap.log"

# Check the generated configuration before anything starts.
"$BIN/security-server" check-config --config "$DATA/zimra.toml"
"$BIN/security-server" check-config --config "$DATA/buyer.toml"

chmod -R go-rwx "$DATA"
[ -n "$OWNER" ] && chown -R "$OWNER" "$DATA"
date -u +%FT%TZ >"$DATA/.bootstrapped"
echo "==> done. Tokens (shown nowhere else) are in $DATA/secrets"
