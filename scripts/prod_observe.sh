#!/usr/bin/env bash
# prod_observe.sh — Этап 1: параллельное наблюдение (нулевой риск).
#
# Что делает:
#   1) Запускает второй nfcapd на альтернативном UDP-порту.
#   2) Запускает xdpflowd в XDP_PASS на зеркальном интерфейсе; NFv9 шлёт
#      только на этот альтернативный порт (НЕ на 9996/9999).
#   3) ipt_NETFLOW при этом продолжает работать как работал — правило
#      iptables не трогается. goflow2/nfcapd/ClickHouse получают данные
#      из существующего пайплайна без изменений.
#   4) Через $DURATION секунд всё останавливается и печатает отчёт
#      для сравнения с ipt_NETFLOW.
#
# Что считаем "верно пишет":
#   * Объём (bytes/pkts) в xdpflowd ~= объём ipt_NETFLOW за тот же период
#   * Число flow в карте xdpflowd разумно (нет map_full)
#   * nfcapd на alt-порту реально принимает NFv9 и пишет файлы
#
# Риск: почти нулевой. XDP_PASS ничего не модифицирует. Если xdpflowd
# упадёт — XDP автоматически отцепится, ничего не сломается.
#
# Запуск:
#   sudo ./scripts/prod_observe.sh [duration_sec] [iface] [alt_port]
# По умолчанию: 300 сек (5 минут), enp5s0d1, порт 12055.
#
# Требуется: clang, libbpf-dev, go 1.23+, ethtool, nfcapd (nfdump пакет),
#            tcpdump (опционально). Построение происходит автоматически.

set -euo pipefail

DURATION="${1:-300}"
IFACE="${2:-enp5s0d1}"
ALT_PORT="${3:-12055}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORKDIR="/tmp/xdpflowd_observe_$(date +%Y%m%d_%H%M%S)"
NFCAPD_DIR="$WORKDIR/nfcapd"
LOG_XDP="$WORKDIR/xdpflowd.log"
LOG_NFCAPD="$WORKDIR/nfcapd.log"
JSON_OUT="$WORKDIR/xdpflowd.ndjson"

mkdir -p "$NFCAPD_DIR"

# ---------- проверки ----------
need_cmd() { command -v "$1" >/dev/null || { echo "ERROR: missing $1" >&2; exit 1; }; }
need_cmd go
need_cmd clang
need_cmd ethtool
need_cmd nfcapd
need_cmd ss

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root (needs CAP_BPF and raw iface access)" >&2
  exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface $IFACE not found" >&2
  exit 1
fi

if ss -ulnp 2>/dev/null | awk '{print $5}' | grep -qE "(^|:)$ALT_PORT\$"; then
  echo "ERROR: UDP port $ALT_PORT already in use. Pick another alt port." >&2
  exit 1
fi

# проверяем, что ipt_NETFLOW реально работает — иначе сравнивать будет не с чем
if ! [ -r /proc/net/stat/ipt_netflow ]; then
  echo "WARNING: /proc/net/stat/ipt_netflow not readable — is ipt_NETFLOW loaded?" >&2
fi

echo "[$(date +%T)] workdir: $WORKDIR"
echo "[$(date +%T)] iface=$IFACE alt_port=$ALT_PORT duration=${DURATION}s"

# ---------- сборка ----------
echo "[$(date +%T)] building xdpflowd (FLOWS_MAP_SIZE=4000000)..."
# если go.sum нет или go.mod требует обновления — мягко делаем tidy
: "${GO:=go}"
if [ ! -f go.sum ]; then
  echo "[$(date +%T)]   go.sum missing, running 'go mod tidy'..."
  "$GO" mod tidy
fi
make -s >/dev/null
[ -x ./bin/xdpflowd ] || { echo "build failed"; exit 1; }
[ -f ./bpf/xdp_flow.o ] || { echo "bpf object missing"; exit 1; }

# ---------- snapshot BEFORE ----------
echo "[$(date +%T)] capturing baseline..."
cat /proc/net/stat/ipt_netflow > "$WORKDIR/iptnetflow_before.txt" 2>/dev/null || true
ethtool -S "$IFACE" > "$WORKDIR/ethtool_before.txt" 2>/dev/null || true
cat /sys/class/net/"$IFACE"/statistics/rx_bytes   > "$WORKDIR/rx_bytes_before.txt"   || true
cat /sys/class/net/"$IFACE"/statistics/rx_packets > "$WORKDIR/rx_packets_before.txt" || true
date +%s > "$WORKDIR/t_start.txt"

# ---------- запуск nfcapd ----------
# nfdump 1.6 (Debian 11) использует -l <dir>; 1.7+ — -w <dir>. Синтаксис
# -l воспринимается обеими версиями (в 1.7 сохранён как legacy). Используем -l.
echo "[$(date +%T)] starting nfcapd on 127.0.0.1:$ALT_PORT -> $NFCAPD_DIR"
nfcapd -b 127.0.0.1 -p "$ALT_PORT" -l "$NFCAPD_DIR" -I xdp -t 60 -e \
  > "$LOG_NFCAPD" 2>&1 &
NFCAPD_PID=$!
sleep 2
if ! kill -0 $NFCAPD_PID 2>/dev/null; then
  echo "ERROR: nfcapd failed to start, see $LOG_NFCAPD"
  cat "$LOG_NFCAPD" | sed 's/^/    /'
  exit 1
fi

# ---------- запуск xdpflowd ----------
# -nf-dst ведёт ТОЛЬКО на alt-порт -> не мешает реальному пайплайну
# -nf-active 1800s, -nf-idle 15s — те же таймауты, что у ipt_NETFLOW
# -interval 30s — частота stats/json
echo "[$(date +%T)] starting xdpflowd (XDP_PASS, alt NFv9 -> 127.0.0.1:$ALT_PORT)"
./bin/xdpflowd \
  -iface "$IFACE" \
  -mode native \
  -bpf ./bpf/xdp_flow.o \
  -nf-dst "127.0.0.1:$ALT_PORT" \
  -nf-active 1800s \
  -nf-idle 15s \
  -nf-template-interval 60s \
  -interval 30s \
  -json-out "$JSON_OUT" \
  -json-interval 30s \
  > "$LOG_XDP" 2>&1 &
XDP_PID=$!
sleep 3
if ! kill -0 $XDP_PID 2>/dev/null; then
  echo "ERROR: xdpflowd failed to start. Last log:"
  tail -n 50 "$LOG_XDP"
  kill -TERM $NFCAPD_PID 2>/dev/null || true
  exit 1
fi

# ---------- cleanup trap ----------
cleanup() {
  local rc=$?
  echo ""
  echo "[$(date +%T)] cleanup (exit=$rc)"
  kill -TERM $XDP_PID   2>/dev/null || true
  kill -HUP  $NFCAPD_PID 2>/dev/null || true
  sleep 2
  kill -TERM $NFCAPD_PID 2>/dev/null || true
  wait $XDP_PID   2>/dev/null || true
  wait $NFCAPD_PID 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---------- ждём ----------
echo "[$(date +%T)] running for $DURATION seconds... (logs: $WORKDIR)"
for ((i=DURATION; i>0; i-=30)); do
  sleep 30
  # короткий heartbeat, чтобы видеть что процессы живы
  if ! kill -0 $XDP_PID 2>/dev/null;   then echo "xdpflowd died!"; break; fi
  if ! kill -0 $NFCAPD_PID 2>/dev/null; then echo "nfcapd died!";   break; fi
  xdp_tail=$(tail -n 1 "$LOG_XDP" 2>/dev/null | tr -d '\n' | cut -c -160)
  echo "[$(date +%T)] +$((DURATION-i+30))s  xdpflowd: $xdp_tail"
done

# ---------- snapshot AFTER ----------
echo "[$(date +%T)] stopping..."
kill -TERM $XDP_PID 2>/dev/null || true
wait $XDP_PID 2>/dev/null || true

cat /proc/net/stat/ipt_netflow > "$WORKDIR/iptnetflow_after.txt" 2>/dev/null || true
ethtool -S "$IFACE" > "$WORKDIR/ethtool_after.txt" 2>/dev/null || true
cat /sys/class/net/"$IFACE"/statistics/rx_bytes   > "$WORKDIR/rx_bytes_after.txt"   || true
cat /sys/class/net/"$IFACE"/statistics/rx_packets > "$WORKDIR/rx_packets_after.txt" || true
date +%s > "$WORKDIR/t_end.txt"

# форсируем rotate + exit у nfcapd, чтобы файлы записались на диск
kill -HUP  $NFCAPD_PID 2>/dev/null || true
sleep 1
kill -TERM $NFCAPD_PID 2>/dev/null || true
wait $NFCAPD_PID 2>/dev/null || true

# ---------- отчёт ----------
echo ""
echo "=============================================================="
echo " REPORT  ($WORKDIR)"
echo "=============================================================="

T_START=$(cat "$WORKDIR/t_start.txt")
T_END=$(cat "$WORKDIR/t_end.txt")
ELAPSED=$(( T_END - T_START ))
echo "duration: ${ELAPSED}s"

# NIC rx delta
RXB=$(( $(cat "$WORKDIR/rx_bytes_after.txt") - $(cat "$WORKDIR/rx_bytes_before.txt") ))
RXP=$(( $(cat "$WORKDIR/rx_packets_after.txt") - $(cat "$WORKDIR/rx_packets_before.txt") ))
echo ""
echo "-- NIC $IFACE delta --"
printf "  rx_bytes:   %'d\n" "$RXB"
printf "  rx_packets: %'d\n" "$RXP"
[ "$ELAPSED" -gt 0 ] && printf "  avg pps:    %'d\n" $(( RXP / ELAPSED ))
[ "$ELAPSED" -gt 0 ] && printf "  avg Mbit/s: %'d\n" $(( RXB * 8 / ELAPSED / 1000000 ))

# ipt_NETFLOW delta (v2.5 — строка с total содержит счётчики)
if [ -s "$WORKDIR/iptnetflow_before.txt" ] && [ -s "$WORKDIR/iptnetflow_after.txt" ]; then
  echo ""
  echo "-- ipt_NETFLOW delta --"
  # ipt_netflow /proc exposes ~50 counters; the simplest comparable field is
  # cumulative "pkt_total" и "traf_total" в заголовке
  echo "[before]"
  head -n 3 "$WORKDIR/iptnetflow_before.txt" | sed 's/^/    /'
  echo "[after]"
  head -n 3 "$WORKDIR/iptnetflow_after.txt" | sed 's/^/    /'
fi

# xdpflowd — берём ПОСЛЕДНИЙ JSON-снэпшот
echo ""
echo "-- xdpflowd last snapshot --"
if [ -s "$JSON_OUT" ]; then
  tail -n 1 "$JSON_OUT" | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        s = json.loads(line)
    except Exception as e:
        print("parse error:", e); continue
    st = s.get("stats", {})
    print("    ts:           ", s.get("ts"))
    print("    total_packets:", st.get("total_packets"))
    print("    parse_errors: ", st.get("parse_errors"))
    print("    map_full:     ", st.get("map_full"))
    print("    non_ip_pass:  ", st.get("non_ip_pass"))
    print("    flows_in_map: ", st.get("flows_in_map"))
'
else
  echo "  (no JSON snapshot — did xdpflowd run long enough?)"
fi

# NetFlow v9 — то, что ДОШЛО до nfcapd
echo ""
echo "-- nfcapd (xdpflowd output) --"
FILES=$(find "$NFCAPD_DIR" -type f -name 'nfcapd.*' ! -name '*.current*' | sort)
if [ -z "$FILES" ]; then
  echo "  WARNING: no nfcapd files produced. Log:"
  tail -n 20 "$LOG_NFCAPD" | sed 's/^/    /'
else
  # общая сводка
  if command -v nfdump >/dev/null; then
    nfdump -R "$NFCAPD_DIR" -t 0 -s proto/packets -n 10 2>/dev/null | head -n 30 | sed 's/^/    /'
    echo ""
    echo "  [top 5 srcip by bytes]"
    nfdump -R "$NFCAPD_DIR" -t 0 -s srcip/bytes -n 5 2>/dev/null | head -n 20 | sed 's/^/    /'
  else
    echo "  files:"
    ls -lah "$NFCAPD_DIR" | sed 's/^/    /'
  fi
fi

# xdpflowd logs: netflow export metrics
echo ""
echo "-- xdpflowd NFv9 export metrics (from logs) --"
grep -E 'netflow|stats' "$LOG_XDP" | tail -n 10 | sed 's/^/    /'

# critical errors
echo ""
echo "-- errors / warnings in xdpflowd log --"
grep -iE 'ERROR|WARN|panic|map_full' "$LOG_XDP" | head -n 20 | sed 's/^/    /'

echo ""
echo "=============================================================="
echo " FULL LOGS / DATA: $WORKDIR"
echo "=============================================================="
