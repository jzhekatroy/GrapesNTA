#!/usr/bin/env bash
# prod_enable_xdpflowd.sh — enable permanent xdpflowd on a target host.
#
# What it does:
#   * save iptables backup + rollback state
#   * remove the single PREROUTING -j NETFLOW rule for the configured mirror iface
#   * stop goflow2 containers listed in the env file
#   * install xdpflowd systemd unit and start the service
#
# Defaults are generic. Override with env vars for host-specific profiles:
#   ENV_INSTALL=/etc/xdpflowd/sel.env
#   STATE_FILE=/root/xdpflowd_sel_permanent_state.env
#   ENV_TEMPLATE=/root/GrapesNTA/deploy/sel/xdpflowd.env.example
#   SERVICE_TEMPLATE=/root/GrapesNTA/deploy/sel/xdpflowd.service
#   EXEC_WRAPPER=/root/GrapesNTA/deploy/sel/xdpflowd-exec.sh
#   BACKUP_TAG=sel-permanent
#
# Usage:
#   sudo ./scripts/prod_enable_xdpflowd.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_FILE="${STATE_FILE:-/root/xdpflowd_permanent_state.env}"
SYSTEMD_UNIT_NAME="${SYSTEMD_UNIT_NAME:-xdpflowd.service}"
ENV_INSTALL="${ENV_INSTALL:-/etc/xdpflowd/xdpflowd.env}"
ENV_TEMPLATE="${ENV_TEMPLATE:-$REPO_ROOT/deploy/systemd/xdpflowd.env.example}"
SERVICE_TEMPLATE="${SERVICE_TEMPLATE:-$REPO_ROOT/deploy/systemd/xdpflowd.service}"
EXEC_WRAPPER="${EXEC_WRAPPER:-$REPO_ROOT/deploy/systemd/xdpflowd-exec.sh}"
BACKUP_TAG="${BACKUP_TAG:-permanent}"
SWAP_DONE=0
ENABLE_DONE=0

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing required command: $1" >&2
    exit 1
  }
}

need_root
need_cmd iptables
need_cmd iptables-save
need_cmd ip
need_cmd systemctl
need_cmd sed

if [[ ! -x "$REPO_ROOT/bin/xdpflowd" ]]; then
  echo "ERROR: $REPO_ROOT/bin/xdpflowd not found or not executable; run: cd $REPO_ROOT && make" >&2
  exit 1
fi

if [[ ! -r "$ENV_INSTALL" ]]; then
  if [[ ! -r "$ENV_TEMPLATE" ]]; then
    echo "ERROR: env template not readable: $ENV_TEMPLATE" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$ENV_INSTALL")"
  install -m 0600 "$ENV_TEMPLATE" "$ENV_INSTALL"
  echo "ERROR: created template env at $ENV_INSTALL; fill XDP_CH_DSN and review defaults, then re-run." >&2
  echo "       sudoedit $ENV_INSTALL" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_INSTALL"
set +a

IFACE="${IFACE:-enp5s0d1}"
XDP_GOFLOW2_CONTAINERS="${XDP_GOFLOW2_CONTAINERS:-kcg-goflow2-1}"

if [[ -n "${XDPFLOWD_EXPECT_HOST_SHORT:-}" ]]; then
  short="$(hostname -s 2>/dev/null || hostname | cut -d. -f1)"
  if [[ "$short" != "$XDPFLOWD_EXPECT_HOST_SHORT" ]]; then
    echo "ERROR: hostname -s=$short, expected $XDPFLOWD_EXPECT_HOST_SHORT (see XDPFLOWD_EXPECT_HOST_SHORT in $ENV_INSTALL)" >&2
    exit 1
  fi
fi

if [[ -z "${XDP_CH_DSN:-}" || -z "${XDP_CH_TABLE:-}" ]]; then
  echo "ERROR: $ENV_INSTALL must define XDP_CH_DSN and XDP_CH_TABLE" >&2
  exit 1
fi

if systemctl is-active --quiet "$SYSTEMD_UNIT_NAME" 2>/dev/null && [[ -f "$STATE_FILE" ]]; then
  echo "[$(date +%T)] $SYSTEMD_UNIT_NAME already active and $STATE_FILE exists — nothing to do."
  echo "            To re-run enable after manual changes: stop service, rollback, then run again."
  exit 0
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface $IFACE not found" >&2
  exit 1
fi

BPF_OBJ="${XDP_BPF_OBJ:-$REPO_ROOT/bpf/xdp_flow.o}"
if [[ ! -f "$BPF_OBJ" ]]; then
  echo "ERROR: BPF object missing: $BPF_OBJ (run: cd $REPO_ROOT && make bpf)" >&2
  exit 1
fi

SPOOL_DIR="${XDP_CH_SPOOL_DIR:-/var/lib/xdpflowd/ch-spool}"
mkdir -p "$SPOOL_DIR" "$(dirname "$ENV_INSTALL")"

# ---------- find exactly one ipt_NETFLOW rule on $IFACE ----------
RULE_TABLE=""
RULE_SPEC=""
for t in raw mangle nat; do
  lines=$(iptables-save -t "$t" 2>/dev/null | grep -E "^-A PREROUTING .*-j NETFLOW\b" || true)
  if [[ -n "$lines" ]]; then
    count=$(printf '%s\n' "$lines" | wc -l | awk '{print $1}')
    if (( count > 1 )); then
      echo "ERROR: found $count NETFLOW rules in table $t — refusing:" >&2
      printf '%s\n' "$lines" >&2
      exit 1
    fi
    if ! printf '%s\n' "$lines" | grep -q -- "-i $IFACE"; then
      echo "WARNING: NETFLOW rule in table $t does not match -i $IFACE — skipping table" >&2
      printf '%s\n' "$lines" >&2
      continue
    fi
    RULE_TABLE="$t"
    RULE_SPEC=$(printf '%s' "$lines" | sed -E 's/^-A PREROUTING //')
    break
  fi
done

if [[ -z "$RULE_TABLE" || -z "$RULE_SPEC" ]]; then
  echo "ERROR: no PREROUTING -j NETFLOW rule for -i $IFACE in raw/mangle/nat" >&2
  exit 1
fi

if ! iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null; then
  echo "ERROR: iptables -C does not confirm rule exists" >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
IPT_BACKUP="/root/iptables-save-before-xdpflowd-${BACKUP_TAG}-$TS.txt"
iptables-save > "$IPT_BACKUP"
echo "[$(date +%T)] iptables backup: $IPT_BACKUP"

rollback_on_error() {
  local rc=$?
  if (( rc == 0 || ENABLE_DONE == 1 )); then
    return "$rc"
  fi
  echo ""
  echo "[$(date +%T)] ERROR: enable failed (exit=$rc), rolling back best-effort..."
  if (( SWAP_DONE == 1 )); then
    if iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null; then
      echo "[$(date +%T)] rollback: NETFLOW rule already present"
    else
      iptables -t "$RULE_TABLE" -I PREROUTING 1 $RULE_SPEC || {
        echo "[$(date +%T)] CRITICAL: failed to restore NETFLOW rule; full backup: $IPT_BACKUP" >&2
      }
    fi
  fi
  systemctl stop "$SYSTEMD_UNIT_NAME" 2>/dev/null || true
  if command -v docker >/dev/null 2>&1; then
    for c in $XDP_GOFLOW2_CONTAINERS; do
      docker start "$c" >/dev/null 2>&1 || true
    done
  fi
  return "$rc"
}
trap rollback_on_error EXIT

{
  echo "# Written by prod_enable_xdpflowd.sh at $TS"
  printf 'REPO_ROOT=%q\n' "$REPO_ROOT"
  printf 'IFACE=%q\n' "$IFACE"
  printf 'RULE_TABLE=%q\n' "$RULE_TABLE"
  printf 'RULE_SPEC=%q\n' "$RULE_SPEC"
  printf 'IPT_BACKUP_FULL=%q\n' "$IPT_BACKUP"
  printf 'ENV_INSTALL=%q\n' "$ENV_INSTALL"
  printf 'SYSTEMD_UNIT_NAME=%q\n' "$SYSTEMD_UNIT_NAME"
  printf 'XDP_GOFLOW2_CONTAINERS=%q\n' "$XDP_GOFLOW2_CONTAINERS"
} > "$STATE_FILE"
chmod 0600 "$STATE_FILE" || true
echo "[$(date +%T)] rollback state: $STATE_FILE"

if [[ ! -r "$SERVICE_TEMPLATE" ]]; then
  echo "ERROR: service template not readable: $SERVICE_TEMPLATE" >&2
  exit 1
fi
if [[ ! -x "$EXEC_WRAPPER" ]]; then
  echo "ERROR: exec wrapper not executable: $EXEC_WRAPPER" >&2
  exit 1
fi

TMP_UNIT="$(mktemp)"
escape_sed() { printf '%s\n' "$1" | sed -e 's/[\/&]/\\&/g'; }
ESC_REPO="$(escape_sed "$REPO_ROOT")"
ESC_ENV_INSTALL="$(escape_sed "$ENV_INSTALL")"
sed \
  -e "s|/opt/GrapesNTA|${ESC_REPO}|g" \
  -e "s|/etc/xdpflowd/xdpflowd.env|${ESC_ENV_INSTALL}|g" \
  "$SERVICE_TEMPLATE" > "$TMP_UNIT"
install -m 0644 "$TMP_UNIT" "/etc/systemd/system/$SYSTEMD_UNIT_NAME"
rm -f "$TMP_UNIT"
chmod 0755 "$EXEC_WRAPPER" || true

echo "[$(date +%T)] removing iptables NETFLOW rule (table=$RULE_TABLE)..."
iptables -t "$RULE_TABLE" -D PREROUTING $RULE_SPEC
SWAP_DONE=1
echo "[$(date +%T)] ipt_NETFLOW removed."

if command -v docker >/dev/null 2>&1; then
  for c in $XDP_GOFLOW2_CONTAINERS; do
    echo "[$(date +%T)] stopping docker container: $c"
    docker stop "$c" >/dev/null 2>&1 || echo "[$(date +%T)] NOTE: docker stop failed or no such container: $c"
  done
else
  echo "[$(date +%T)] NOTE: docker not installed — skip stopping goflow2 containers"
fi

systemctl daemon-reload
systemctl enable "$SYSTEMD_UNIT_NAME"
systemctl restart "$SYSTEMD_UNIT_NAME"
sleep 3
if ! systemctl is-active --quiet "$SYSTEMD_UNIT_NAME"; then
  echo "ERROR: $SYSTEMD_UNIT_NAME is not active after restart" >&2
  journalctl -u "$SYSTEMD_UNIT_NAME" -n 80 --no-pager >&2 || true
  exit 1
fi
ENABLE_DONE=1
trap - EXIT

echo ""
echo "======================================================================"
echo "xdpflowd permanent mode ENABLED"
echo "  service:  $SYSTEMD_UNIT_NAME"
echo "  state:    $STATE_FILE"
echo "  iptables: $IPT_BACKUP (also recorded in state as IPT_BACKUP_FULL)"
echo "  logs:     journalctl -u $SYSTEMD_UNIT_NAME -f"
echo "  rollback: $REPO_ROOT/scripts/prod_rollback_legacy.sh"
echo "======================================================================"
