#!/usr/bin/env bash
#
# Take a fresh Ubuntu/Debian VPS to a running, publicly reachable Latebra SEED
# node — a prebuilt release binary under systemd, firewalled, restarting on
# reboot. No Rust toolchain, no compiling.
#
#   curl -fsSL https://raw.githubusercontent.com/latebranetwork/latebra-core/master/scripts/deploy-seed.sh \
#     | sudo bash -s -- --host seed1.latebra.network
#
# or, having cloned the repo:
#
#   sudo ./scripts/deploy-seed.sh --host seed1.latebra.network [--peer other:4040] [--version v0.1.0]
#
# ── This deploys a SEED, and deliberately does NOT mine ──────────────────────
# A seed's job is to be reachable and always on, which is an ordinary network
# service. Mining is different: most VPS providers (Hetzner, DigitalOcean,
# Vultr, Contabo, OVH) prohibit cryptocurrency mining in their terms, and
# enforcement is account suspension, which would take your seed down with it.
# Run the miner somewhere mining is permitted — your own hardware is fine, and
# a miner needs no inbound connectivity because it dials the seed itself.
# Pass --mine only if you are certain your provider allows it.
#
# Requires: a public IP, and DNS for --host already pointing at this machine.

set -euo pipefail

REPO="latebranetwork/latebra-core"
VERSION="latest"
HOST=""
PEERS=()
MINE=0
P2P_PORT=4040

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)    HOST="${2:-}"; shift 2 ;;
    --peer)    PEERS+=("${2:-}"); shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --port)    P2P_PORT="${2:-}"; shift 2 ;;
    --mine)    MINE=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
[[ -n "$HOST" ]] || { echo "missing --host <dns-name-or-ip> — this is what the node advertises to peers" >&2; exit 2; }

echo "==> installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl tar ca-certificates ufw >/dev/null

# The release binary needs glibc 2.34+ (built on Ubuntu 22.04). Debian 11 and
# CentOS 7 are too old — fail here rather than with a confusing loader error.
GLIBC=$(ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+$')
if [[ "$(printf '%s\n2.34' "$GLIBC" | sort -V | head -1)" != "2.34" ]]; then
  echo "glibc $GLIBC is too old — Latebra needs 2.34+ (Ubuntu 22.04+, Debian 12+, RHEL 9+)" >&2
  exit 1
fi
echo "    glibc $GLIBC OK"

echo "==> resolving release ($VERSION)"
if [[ "$VERSION" == "latest" ]]; then
  URL=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -oE '"browser_download_url": *"[^"]*x86_64-unknown-linux-gnu\.tar\.gz"' \
        | cut -d'"' -f4 | head -1)
else
  URL="https://github.com/$REPO/releases/download/$VERSION/latebra-${VERSION#v}-x86_64-unknown-linux-gnu.tar.gz"
fi
[[ -n "$URL" ]] || { echo "could not find a linux release asset" >&2; exit 1; }
echo "    $URL"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
curl -fsSL -O "$URL"
TARBALL=$(basename "$URL")

# Verify against the release's published checksums before running anything.
SUMS_URL="${URL%/*}/SHA256SUMS.txt"
if curl -fsSL -o SHA256SUMS.txt "$SUMS_URL" 2>/dev/null; then
  echo "==> verifying checksum"
  sha256sum -c SHA256SUMS.txt --ignore-missing
else
  echo "WARNING: no SHA256SUMS.txt published for this release — cannot verify the download" >&2
fi

tar xzf "$TARBALL"
BINDIR=$(find . -maxdepth 1 -type d -name 'latebra-*' | head -1)
install -m 0755 "$BINDIR/latebrad" "$BINDIR/lat-wallet" "$BINDIR/lat-explorer" /usr/local/bin/
echo "    installed latebrad, lat-wallet, lat-explorer"

echo "==> creating the latebra service user and data directory"
id -u latebra >/dev/null 2>&1 || useradd --system --home /var/lib/latebra --shell /usr/sbin/nologin latebra
install -d -o latebra -g latebra -m 0750 /var/lib/latebra

echo "==> firewall"
ufw allow 22/tcp   >/dev/null
ufw allow "$P2P_PORT"/tcp >/dev/null
# 4090 is metrics + JSON-RPC and stays on loopback. Exposing it publicly leaks
# peer/mempool internals; put it behind a reverse proxy if you want it public
# (DEPLOY.md §4-5 covers that, forwarding only /rpc, /status and /health).
ufw --force enable >/dev/null
echo "    22/tcp and $P2P_PORT/tcp open; metrics port NOT exposed"

ARGS=(--data /var/lib/latebra/chain.db
      --listen "0.0.0.0:$P2P_PORT"
      --public-addr "$HOST:$P2P_PORT"
      --metrics 127.0.0.1:4090)
for p in "${PEERS[@]:-}"; do [[ -n "$p" ]] && ARGS+=(--peer "$p"); done
[[ $MINE -eq 1 ]] && ARGS+=(--mine)

echo "==> writing systemd unit"
cat > /etc/systemd/system/latebrad.service <<UNIT
[Unit]
Description=Latebra node (seed)
After=network-online.target
Wants=network-online.target

[Service]
User=latebra
Group=latebra
ExecStart=/usr/local/bin/latebrad ${ARGS[@]}
Restart=always
RestartSec=5
# The node only ever needs its own data directory.
StateDirectory=latebra
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/latebra

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now latebrad >/dev/null
sleep 5

echo
if systemctl is-active --quiet latebrad; then
  echo "==> latebrad is RUNNING"
else
  echo "==> latebrad FAILED to start — logs follow" >&2
  journalctl -u latebrad -n 30 --no-pager >&2
  exit 1
fi

echo
echo "  advertise  : $HOST:$P2P_PORT   <- publish this; it is how others join"
echo "  status     : curl -s localhost:4090/status"
echo "  logs       : journalctl -u latebrad -f"
echo "  restart    : systemctl restart latebrad"
echo
if [[ ${#PEERS[@]} -eq 0 || -z "${PEERS[0]:-}" ]]; then
  echo "  NOTE: no --peer given, so this node starts a network of its own."
  echo "        That is correct for the FIRST seed. Every later node must pass"
  echo "        --peer $HOST:$P2P_PORT or it will mine a private chain in silence."
fi
if [[ $MINE -eq 0 ]]; then
  echo "  NOTE: this node does NOT mine, so the chain only advances once a miner"
  echo "        joins. Run one where mining is permitted:"
  echo "          latebrad --mine --peer $HOST:$P2P_PORT --data ./latebra-data/chain.db"
  echo "        Sync first, then mine — see INSTALL.md."
fi
echo
echo "  Next: put $HOST:$P2P_PORT in BOOTSTRAP_SEEDS (crates/latebrad/src/main.rs)"
echo "        and cut a release, so fresh nodes join with no arguments."
