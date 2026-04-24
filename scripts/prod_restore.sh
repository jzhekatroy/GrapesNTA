#!/usr/bin/env bash
# prod_restore.sh — аварийное восстановление после prod_ab_swap.sh / prod_ab_swap_afxdp.sh.
#
# Когда использовать:
#   * Если prod_ab_swap.sh / prod_ab_swap_afxdp.sh аварийно завершился и trap почему-то НЕ восстановил
#     правило iptables.
#   * Если вы хотите убедиться, что всё вернулось в исходное состояние.
#
# Как пользоваться:
#   1) Самый простой вариант — с файлом состояния:
#        sudo ./scripts/prod_restore.sh /tmp/xdpflowd_abswap_<TS>/state.env
#        sudo ./scripts/prod_restore.sh /tmp/afxdpflowd_abswap_<TS>/state.env
#   2) С явным указанием полного iptables backup:
#        sudo ./scripts/prod_restore.sh --full-restore /root/iptables-save-before-<TS>.txt
#   3) Без аргументов — только убьёт живые xdpflowd / afxdpflowd и покажет список
#     кандидатов для восстановления (ничего не меняет).

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

# ---------- обязательный шаг: убедиться, что экспортёры не крутятся ----------
if pgrep -x xdpflowd >/dev/null; then
  echo "[$(date +%T)] killing xdpflowd..."
  pkill -TERM -x xdpflowd || true
  sleep 2
  pkill -KILL -x xdpflowd || true
fi
if pgrep -x afxdpflowd >/dev/null; then
  echo "[$(date +%T)] killing afxdpflowd..."
  pkill -TERM -x afxdpflowd || true
  sleep 2
  pkill -KILL -x afxdpflowd || true
fi

# если передан --full-restore <file>
if [[ "${1:-}" == "--full-restore" ]]; then
  FILE="${2:-}"
  if [ -z "$FILE" ] || [ ! -r "$FILE" ]; then
    echo "ERROR: missing/unreadable backup file: $FILE" >&2
    exit 1
  fi
  echo "[$(date +%T)] full iptables-restore < $FILE"
  iptables-restore < "$FILE"
  echo "[$(date +%T)] done."
  exit 0
fi

# если передан путь к state.env
if [ -n "${1:-}" ]; then
  STATE="$1"
  if [ ! -r "$STATE" ]; then
    echo "ERROR: state file not readable: $STATE" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$STATE"
  : "${RULE_TABLE:?state missing RULE_TABLE}"
  : "${RULE_SPEC:?state missing RULE_SPEC}"
  : "${IPT_BACKUP:?state missing IPT_BACKUP}"

  echo "[$(date +%T)] state loaded from $STATE:"
  echo "            table=$RULE_TABLE"
  echo "            spec =$RULE_SPEC"
  echo "            full backup = $IPT_BACKUP"

  if iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null; then
    echo "[$(date +%T)] rule already present — nothing to do."
    exit 0
  fi
  echo "[$(date +%T)] re-inserting rule..."
  if iptables -t "$RULE_TABLE" -I PREROUTING 1 $RULE_SPEC; then
    echo "[$(date +%T)] ok."
    exit 0
  fi
  echo "ERROR: targeted restore failed. Trying full restore from $IPT_BACKUP..." >&2
  iptables-restore < "$IPT_BACKUP"
  echo "[$(date +%T)] full-restore done."
  exit 0
fi

# без аргументов — диагностика
echo "Usage:"
echo "  $0 /tmp/xdpflowd_abswap_<TS>/state.env"
echo "  $0 /tmp/afxdpflowd_abswap_<TS>/state.env"
echo "  $0 --full-restore /root/iptables-save-before-<TS>.txt"
echo ""
echo "Current NETFLOW rules in the kernel:"
for t in raw mangle nat filter; do
  lines=$(iptables-save -t "$t" 2>/dev/null | grep -E '\-j NETFLOW' || true)
  if [ -n "$lines" ]; then
    echo "  [table $t]"
    printf '%s\n' "$lines" | sed 's/^/    /'
  fi
done
echo ""
echo "Available state files (xdpflowd):"
ls -1t /tmp/xdpflowd_abswap_*/state.env 2>/dev/null | head -n 5 | sed 's/^/  /'
echo "Available state files (afxdpflowd):"
ls -1t /tmp/afxdpflowd_abswap_*/state.env 2>/dev/null | head -n 5 | sed 's/^/  /'
echo ""
echo "Available iptables backups:"
ls -1t /root/iptables-save-before-*.txt 2>/dev/null | head -n 5 | sed 's/^/  /'
