#!/usr/bin/env bash
# Install Z-Road binaries and systemd units on this machine. Run as root.
# It does not enable or start anything: you generate identities first (docs/deployment.md).
#
#   cargo build --release --workspace
#   sudo deploy/systemd/install.sh [path-to-binaries]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HERE/../../target/release}"
for b in central-server timestamp-service security-server signer-service zroad-cli; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b (build with cargo build --release)" >&2; exit 1; }
done

id zroad >/dev/null 2>&1 || useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin zroad
install -m 0755 "$BIN"/{central-server,timestamp-service,security-server,signer-service,zroad-cli} /usr/local/bin/
install -d -m 0750 -o root -g zroad /etc/zroad
install -d -m 0755 /usr/local/share/zroad/schemas
install -m 0644 "$HERE/zroad-central.service" "$HERE/zroad-timestamp.service" \
        "$HERE/zroad-security-server@.service" "$HERE/zroad-signer.service" /etc/systemd/system/
systemctl daemon-reload

cat <<'MSG'
Installed. Next:
  1. Put each service's identity under /var/lib/zroad/<name> (owned by zroad, mode 0700) and
     its configuration under /etc/zroad (see docs/deployment.md).
  2. Edit the unit files for your host names (central URL, member ids).
  3. systemctl enable --now zroad-central            # on the authority's machine
     systemctl enable --now zroad-timestamp          # the timestamp authority
     systemctl enable --now zroad-security-server@zimra   # reads /etc/zroad/zimra.toml
     systemctl enable --now zroad-signer             # on a hosted member's own machine
Logs: journalctl -u zroad-security-server@zimra -f
MSG
