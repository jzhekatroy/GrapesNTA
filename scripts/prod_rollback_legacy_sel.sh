#!/usr/bin/env bash
# prod_rollback_legacy_sel.sh — быстрый ручной откат sel:
#   * остановить systemd xdpflowd
#   * снять XDP с интерфейса (best-effort)
#   * вернуть iptables ipt_NETFLOW правило из /root/xdpflowd_sel_permanent_state.env
#   * запустить goflow2 контейнеры из state
#
# Запуск:
#   sudo /opt/GrapesNTA/scripts/prod_rollback_legacy_sel.sh
#
set -euo pipefail

STATE_FILE="${STATE_FILE:-/root/xdpflowd_sel_permanent_state.env}"
SYSTEMD_UNIT_NAME="${SYSTEMD_UNIT_NAME:-xdpflowd.service}"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

if [[ ! -r "$STATE_FILE" ]]; then
  echo "ERROR: state file missing/unreadable: $STATE_FILE" >&2
  echo "       Without it, restore ipt_NETFLOW manually or use:" >&2
  echo "         ./scripts/prod_restore.sh --full-restore /root/iptables-save-before-....txt" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$STATE_FILE"
: "${IFACE:?state missing IFACE}"
: "${RULE_TABLE:?state missing RULE_TABLE}"
: "${RULE_SPEC:?state missing RULE_SPEC}"
: "${IPT_BACKUP_FULL:?state missing IPT_BACKUP_FULL}"

GOFLOW_CONTAINERS="${XDP_GOFLOW2_CONTAINERS:-kcg-goflow2-1}"

echo "[$(date +%T)] stopping $SYSTEMD_UNIT_NAME ..."
systemctl stop "$SYSTEMD_UNIT_NAME" 2>/dev/null || true
systemctl disable "$SYSTEMD_UNIT_NAME" 2>/dev/null || true

# stray processes (if any)
if pgrep -x xdpflowd >/dev/null 2>&1; then
  echo "[$(date +%T)] sending SIGTERM to remaining xdpflowd..."
  pkill -TERM -x xdpflowd || true
  sleep 2
  pkill -KILL -x xdpflowd || true
fi

echo "[$(date +%T)] attempting 'ip link set dev $IFACE xdp off' (ignore errors) ..."
ip link set dev "$IFACE" xdp off 2>/dev/null || true

if iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null; then
  echo "[$(date +%T)] ipt_NETFLOW rule already present — skip insert"
else
  echo "[$(date +%T)] re-inserting ipt_NETFLOW: iptables -t $RULE_TABLE -I PREROUTING 1 $RULE_SPEC"
  if ! iptables -t "$RULE_TABLE" -I PREROUTING 1 $RULE_SPEC; then
    echo "ERROR: targeted restore failed. Try full restore:" >&2
    echo "  iptables-restore < $IPT_BACKUP_FULL" >&2
    exit 1
  fi
fi

if command -v docker >/dev/null 2>&1; then
  for c in $GOFLOW_CONTAINERS; do
    echo "[$(date +%T)] starting docker container: $c"
    docker start "$c" >/dev/null 2>&1 || echo "[$(date +%T)] WARN: docker start failed for $c"
  done
else
  echo "[$(date +%T)] NOTE: docker not installed — start goflow2 manually"
fi

echo ""
echo "======================================================================"
echo "Rollback to legacy ipt_NETFLOW path complete"
echo "  iface:   $IFACE"
echo "  rule:    table=$RULE_TABLE PREROUTING $RULE_SPEC"
echo "  backup:  $IPT_BACKUP_FULL"
echo "  spool:   not deleted (inspect XDP_CH_SPOOL_DIR if needed)"
echo "======================================================================"
