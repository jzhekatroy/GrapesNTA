#!/usr/bin/env bash
# prod_cutover_sel_mlx5.sh — sel ConnectX-4 (enp4s0np0): build xdpflowd, stop goflow2,
# enable permanent xdpflowd with native XDP, verify NIC + ClickHouse.
#
# Run on sel as root:
#   cd /opt/GrapesNTA && sudo ./scripts/prod_cutover_sel_mlx5.sh
#
# Requires /etc/xdpflowd/sel.env with XDP_CH_DSN (copied from m61 if missing).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_INSTALL="${ENV_INSTALL:-/etc/xdpflowd/sel.env}"
ENV_TEMPLATE="$REPO_ROOT/deploy/sel/xdpflowd.env.example"
IFACE="${IFACE:-enp4s0np0}"
GIT_REF="${GIT_REF:-feature/dnsflowd-mvp}"
SAMPLER_ADDR="${SAMPLER_ADDR:-95.215.0.26}"

need_root() {
  [[ "${EUID:-}" -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }
}

upsert_env() {
  local file="$1" key="$2" value="$3"
  touch "$file"
  chmod 0600 "$file"
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

need_root

short="$(hostname -s 2>/dev/null || hostname | cut -d. -f1)"
if [[ "$short" != "sel" ]]; then
  echo "ERROR: expected hostname -s=sel, got $short" >&2
  exit 1
fi

if [[ ! -d "$REPO_ROOT/.git" ]]; then
  echo "ERROR: $REPO_ROOT is not a git checkout" >&2
  exit 1
fi

mkdir -p /etc/xdpflowd
if [[ ! -f "$ENV_INSTALL" ]]; then
  install -m 0600 "$ENV_TEMPLATE" "$ENV_INSTALL"
  echo "NOTE: created $ENV_INSTALL from template — set XDP_CH_DSN before continuing."
fi

# Preserve secrets; refresh operational profile for mlx5 / enp4s0np0 / native XDP.
upsert_env "$ENV_INSTALL" REPO_ROOT "$REPO_ROOT"
upsert_env "$ENV_INSTALL" XDPFLOWD_BIN '${REPO_ROOT}/bin/xdpflowd'
upsert_env "$ENV_INSTALL" IFACE "$IFACE"
upsert_env "$ENV_INSTALL" XDP_BPF_OBJ '${REPO_ROOT}/bpf/xdp_flow.o'
upsert_env "$ENV_INSTALL" XDP_MODE native
upsert_env "$ENV_INSTALL" XDP_ACTION drop
upsert_env "$ENV_INSTALL" XDP_DNS_PASSTHROUGH 0
upsert_env "$ENV_INSTALL" XDPFLOWD_SOURCE_ID netflow
upsert_env "$ENV_INSTALL" XDP_CH_TABLE default.flows_raw
upsert_env "$ENV_INSTALL" XDP_CH_SAMPLER_ADDR "$SAMPLER_ADDR"
upsert_env "$ENV_INSTALL" NF_DSTS 127.0.0.1:9996
upsert_env "$ENV_INSTALL" XDP_HEAVY_EXPORT 0
upsert_env "$ENV_INSTALL" XDP_NF_ACTIVE 60s
upsert_env "$ENV_INSTALL" XDP_NF_IDLE 10s
upsert_env "$ENV_INSTALL" XDP_NF_TEMPLATE_INTERVAL 60s
upsert_env "$ENV_INSTALL" XDP_NF_SCAN 1s
upsert_env "$ENV_INSTALL" XDP_DRAIN_MODE timer
upsert_env "$ENV_INSTALL" XDP_DRAIN_INTERVAL 0s
upsert_env "$ENV_INSTALL" XDP_FINAL_FLUSH 0
upsert_env "$ENV_INSTALL" XDP_AGG_ENABLE 0
upsert_env "$ENV_INSTALL" XDP_TOP 0
upsert_env "$ENV_INSTALL" XDP_INTERVAL 5s
upsert_env "$ENV_INSTALL" XDP_TOP_INTERVAL 60s
upsert_env "$ENV_INSTALL" XDP_JSON_OUT_ENABLE 0
upsert_env "$ENV_INSTALL" XDP_CLASSIFIER 1
upsert_env "$ENV_INSTALL" XDP_CLASSIFIER_REFRESH 60s
upsert_env "$ENV_INSTALL" XDP_CLASSIFIER_BGP_TABLE default.bgp_prefix_origin_current
upsert_env "$ENV_INSTALL" XDP_CLASSIFIER_L3_PREFIXES_VIEW default.net_l3_prefixes_enabled
upsert_env "$ENV_INSTALL" XDP_CLASSIFIER_L2_VLANS_VIEW default.net_l2_vlans_enabled
upsert_env "$ENV_INSTALL" XDP_CH_BATCH_SIZE 500
upsert_env "$ENV_INSTALL" XDP_CH_FLUSH_INTERVAL 1s
upsert_env "$ENV_INSTALL" XDP_CH_QUEUE_SIZE 64
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_MODE required
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_DIR /var/lib/xdpflowd/ch-spool
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_SEGMENT_SIZE 268435456
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_MAX_BYTES 214748364800
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_FRAME_MAX_RECORDS 50000
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_FSYNC_INTERVAL 1s
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_SHUTDOWN_DRAIN 30s
upsert_env "$ENV_INSTALL" XDP_CH_SPOOL_STALL_THRESHOLD 60s
upsert_env "$ENV_INSTALL" XDP_CH_WRITERS 8
upsert_env "$ENV_INSTALL" XDP_GOFLOW2_CONTAINERS kcg-goflow2-1
upsert_env "$ENV_INSTALL" XDPFLOWD_EXPECT_HOST_SHORT sel

set -a
# shellcheck disable=SC1090
source "$ENV_INSTALL"
set +a

if [[ -z "${XDP_CH_DSN:-}" ]]; then
  echo "ERROR: set XDP_CH_DSN in $ENV_INSTALL (same native DSN as m61, port 6124)" >&2
  echo "  Example: XDP_CH_DSN=clickhouse://develop:PASS%40URLENCODED@95.215.1.30:6124/default" >&2
  exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: mirror interface $IFACE not found" >&2
  exit 1
fi

echo "[$(date +%T)] git pull ($GIT_REF)..."
cd "$REPO_ROOT"
git fetch origin "$GIT_REF"
git checkout "$GIT_REF"
git pull --ff-only origin "$GIT_REF"

echo "[$(date +%T)] build xdpflowd + bpf..."
make clean && make && make bpf

echo "[$(date +%T)] NIC prep on $IFACE..."
ip link set "$IFACE" promisc on
ethtool -G "$IFACE" rx 8192 2>/dev/null || echo "NOTE: ethtool -G rx 8192 not supported or already set"

# Stop legacy goflow2 before enable (also done in prod_enable, but fail fast here).
if command -v docker >/dev/null 2>&1; then
  for c in ${XDP_GOFLOW2_CONTAINERS:-kcg-goflow2-1}; do
    if docker ps --format '{{.Names}}' | grep -qx "$c"; then
      echo "[$(date +%T)] stopping legacy container $c"
      docker stop "$c" >/dev/null
    fi
  done
fi

export XDP_ALLOW_NO_NETFLOW_RULE=1
export STATE_FILE="${STATE_FILE:-/root/xdpflowd_sel_permanent_state.env}"
export ENV_INSTALL
export ENV_TEMPLATE="$REPO_ROOT/deploy/sel/xdpflowd.env.example"
export SERVICE_TEMPLATE="$REPO_ROOT/deploy/sel/xdpflowd.service"
export EXEC_WRAPPER="$REPO_ROOT/deploy/sel/xdpflowd-exec.sh"
export BACKUP_TAG=sel-permanent

if systemctl is-active --quiet xdpflowd 2>/dev/null; then
  echo "[$(date +%T)] restarting existing xdpflowd with updated env..."
  systemctl restart xdpflowd
else
  "$SCRIPT_DIR/prod_enable_xdpflowd_sel.sh"
fi

sleep 5
if ! systemctl is-active --quiet xdpflowd; then
  journalctl -u xdpflowd -n 60 --no-pager >&2 || true
  exit 1
fi

echo ""
echo "======================================================================"
echo "Running native XDP verification (60s)..."
echo "======================================================================"
IFACE="$IFACE" ENV_FILE="$ENV_INSTALL" SOURCE_ID="${XDPFLOWD_SOURCE_ID:-netflow}" \
  WINDOW_SEC=60 "$SCRIPT_DIR/verify_sel_native_xdp.sh"

echo ""
echo "Cutover complete."
echo "  logs:     journalctl -u xdpflowd -f"
echo "  rollback: $REPO_ROOT/scripts/prod_rollback_legacy_sel.sh"
echo ""
echo "NOTE: if mirror is also on m61 with source_id=netflow, disable one collector"
echo "      to avoid double-counting in rollups."
