#!/usr/bin/env bash
# traffic_coverage_check.sh — сверка «видимого» трафика с эталоном на mirror-интерфейсе.
#
# На mlx5 + native XDP + ACTION=drop пакеты дропаются в драйвере и НЕ попадают в
# /sys/class/net/<iface>/statistics/rx_packets. Эталон при работающем xdpflowd:
#   sum(ethtool -S rxN_xdp_drop)  — per-queue, БЕЗ общего rx_xdp_drop (двойной счёт).
#
# Сравниваем за окно WINDOW_SEC:
#   1) NIC wire (xdp_drop или sysfs rx при остановленном коллекторе)
#   2) xdpflowd BPF stats (journalctl msg=stats)
#   3) ClickHouse flows_raw (source_id=netflow)
#
# Usage (on collector, as root):
#   IFACE=ens1np0 WINDOW_SEC=300 ./scripts/traffic_coverage_check.sh
#   IFACE=ens1np0 WINDOW_SEC=60  MODE=stop_collector ./scripts/traffic_coverage_check.sh
#
# MODE:
#   running        — коллектор работает; wire = ethtool xdp_* если есть
#   xdp_vs_ch      — только xdpflowd vs ClickHouse (когда wire-счётчики недоступны)
#   stop_collector — кратко останавливает xdpflowd, wire = sysfs rx_*
#
set -euo pipefail

IFACE="${IFACE:-}"
WINDOW_SEC="${WINDOW_SEC:-300}"
MODE="${MODE:-running}"
SOURCE_ID="${SOURCE_ID:-netflow}"
XDP_UNIT="${XDP_UNIT:-xdpflowd}"
ENV_FILE="${ENV_FILE:-/etc/xdpflowd/xdpflowd.env}"
ROLLUPS_ENV="${ROLLUPS_ENV:-/etc/grapesnta/traffic-rollups.env}"

need_root() {
  [[ "${EUID:-}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
}

load_iface() {
  if [[ -n "$IFACE" ]]; then
    return
  fi
  if [[ -f "$ENV_FILE" ]]; then
    IFACE="$(grep -E '^XDPFLOWD_IFACE=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"
  fi
  IFACE="${IFACE:-ens1np0}"
}

sysfs_rx() {
  local iface="$1"
  local p="/sys/class/net/$iface/statistics"
  echo "$(cat "$p/rx_packets" 2>/dev/null || echo 0) $(cat "$p/rx_bytes" 2>/dev/null || echo 0)"
}

# Wire counters vary by driver/kernel. Prefer per-queue xdp_drop; fall back to other
# ethtool keys, then sysfs rx when XDP is generic or counters are unavailable.
nic_wire_pkts() {
  local iface="$1"
  local stats
  stats="$(ethtool -S "$iface" 2>/dev/null || true)"

  # mlx5 native drop: per-queue rxN_xdp_drop (never add global rx_xdp_drop).
  local sum
  sum="$(echo "$stats" | awk '
    /^[[:space:]]*rx[0-9]+_xdp_drop:/ { gsub(/:/, "", $2); sum += $2 }
    END { print sum + 0 }
  ')"
  if [[ "$sum" -gt 0 ]]; then
    echo "$sum"
    return
  fi

  # Some drivers expose rxN_xdp_packets instead.
  sum="$(echo "$stats" | awk '
    /^[[:space:]]*rx[0-9]+_xdp_packets:/ { gsub(/:/, "", $2); sum += $2 }
    END { print sum + 0 }
  ')"
  if [[ "$sum" -gt 0 ]]; then
    echo "$sum"
    return
  fi

  # Global fallbacks (use only when per-queue counters are absent).
  sum="$(echo "$stats" | awk '
    /^[[:space:]]*rx_xdp_drop:/ { gsub(/:/, "", $2); print $2; exit }
  ')"
  if [[ -n "$sum" && "$sum" -gt 0 ]]; then
    echo "$sum"
    return
  fi

  echo "0"
}

nic_wire_source() {
  local iface="$1"
  local stats
  stats="$(ethtool -S "$iface" 2>/dev/null || true)"
  if echo "$stats" | grep -qE '^[[:space:]]*rx[0-9]+_xdp_drop:'; then
    echo "ethtool:sum(rxN_xdp_drop)"
    return
  fi
  if echo "$stats" | grep -qE '^[[:space:]]*rx[0-9]+_xdp_packets:'; then
    echo "ethtool:sum(rxN_xdp_packets)"
    return
  fi
  if echo "$stats" | awk '/^[[:space:]]*rx_xdp_drop:/ {exit 0} END{exit 1}'; then
    echo "ethtool:rx_xdp_drop"
    return
  fi
  if xdp_attached "$iface"; then
    echo "unavailable (xdp attached, no xdp_* ethtool counters — use MODE=xdp_vs_ch or stop_collector)"
  else
    echo "sysfs:rx_packets"
  fi
}

show_nic_debug() {
  local iface="$1"
  echo ""
  echo "=== NIC debug ($iface) ==="
  ip -details link show "$iface" 2>/dev/null | grep -iE 'xdp|state|promisc' | sed 's/^/  /' || true
  echo "  sysfs rx_packets=$(cat /sys/class/net/$iface/statistics/rx_packets 2>/dev/null || echo 0)"
  echo "  sysfs rx_bytes=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo 0)"
  echo "  ethtool xdp-related counters:"
  ethtool -S "$iface" 2>/dev/null | grep -i xdp | head -20 | sed 's/^/    /' || echo "    (none)"
}

xdp_mode() {
  ip -details link show "$1" 2>/dev/null | grep -oE 'xdpdrv|xdpgeneric|xdpoffload|prog/xdp' | head -1 || echo "none"
}

xdp_attached() {
  ip -details link show "$1" 2>/dev/null | grep -qiE 'prog/xdp|xdpgeneric|xdpoffload|xdpdrv'
}

read_xdp_stats_line() {
  # Последняя строка msg=stats из journal за последние 2 минуты.
  journalctl -u "$XDP_UNIT" --since "2 minutes ago" --no-pager -o cat 2>/dev/null \
    | grep 'msg=stats' | tail -1
}

parse_stat() {
  local line="$1"
  local key="$2"
  echo "$line" | sed -n "s/.*${key}=\([0-9]*\).*/\1/p" | head -1
}

read_xdp_counters() {
  local line
  line="$(read_xdp_stats_line)"
  if [[ -z "$line" ]]; then
    echo "0 0 0 0 0 0 0"
    return
  fi
  local tp pe mf nip ap
  tp="$(parse_stat "$line" total_packets)"
  pe="$(parse_stat "$line" parse_errors)"
  mf="$(parse_stat "$line" map_full)"
  nip="$(parse_stat "$line" non_ip_pass)"
  ap="$(parse_stat "$line" accounted_packets)"
  local vlan ipv4 ipv6
  vlan="$(parse_stat "$line" vlan_tag_seen)"
  ipv4="$(parse_stat "$line" ipv4_packets)"
  ipv6="$(parse_stat "$line" ipv6_packets)"
  echo "${tp:-0} ${pe:-0} ${mf:-0} ${nip:-0} ${ap:-0} ${vlan:-0} ${ipv4:-0} ${ipv6:-0}"
}

pct() {
  awk -v a="$1" -v b="$2" 'BEGIN{
    if (b+0 <= 0) { print "n/a"; exit }
    printf "%.4f", (100.0 * a / b)
  }'
}

ch_client() {
  if [[ -f "$ROLLUPS_ENV" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$ROLLUPS_ENV"; set +a
  fi
  local host="${TRAFFIC_ROLLUP_CH_HOST:-${CH_HOST:-}}"
  local port="${TRAFFIC_ROLLUP_CH_PORT:-${CH_PORT:-6124}}"
  local user="${TRAFFIC_ROLLUP_CH_USER:-${CH_USER:-develop}}"
  local pass="${TRAFFIC_ROLLUP_CH_PASSWORD:-${CH_PASSWORD:-}}"
  if [[ -z "$host" || -z "$pass" ]]; then
    echo ""
    return 1
  fi
  clickhouse-client --host "$host" --port "$port" --user "$user" --password "$pass" "$@"
}

print_ch_seen() {
  local client
  client="$(command -v clickhouse-client || true)"
  [[ -n "$client" ]] || { echo "WARN: clickhouse-client not found; skip CH section"; return 0; }
  if ! ch_client --query "SELECT 1" >/dev/null 2>&1; then
    echo "WARN: ClickHouse not configured (set $ROLLUPS_ENV or CH_HOST/CH_PASSWORD); skip CH section"
    return 0
  fi

  echo ""
  echo "=== ClickHouse: что видим сейчас (последние ${WINDOW_SEC}s, source_id=${SOURCE_ID}) ==="
  ch_client --query "
SELECT
    direction,
    count() AS flows,
    sum(packets) AS packets,
    sum(bytes) AS bytes,
    round(sum(bytes) / 1e9, 3) AS gb
FROM default.flows_raw
WHERE source_id = '${SOURCE_ID}'
  AND time_received_ns >= now64(9) - INTERVAL ${WINDOW_SEC} SECOND
GROUP BY direction
ORDER BY bytes DESC
FORMAT PrettyCompact
"

  ch_client --query "
SELECT
    if(etype = 2048, 'ipv4', if(etype = 34525, 'ipv6', toString(etype))) AS l3,
    count() AS flows,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.flows_raw
WHERE source_id = '${SOURCE_ID}'
  AND time_received_ns >= now64(9) - INTERVAL ${WINDOW_SEC} SECOND
GROUP BY l3
ORDER BY bytes DESC
FORMAT PrettyCompact
"

  ch_client --query "
SELECT
    count() AS flows,
    sum(packets) AS packets,
    sum(bytes) AS bytes,
    round(sum(bytes) / 1e9, 3) AS gb,
    min(time_received_ns) AS min_ts,
    max(time_received_ns) AS max_ts
FROM default.flows_raw
WHERE source_id = '${SOURCE_ID}'
  AND time_received_ns >= now64(9) - INTERVAL ${WINDOW_SEC} SECOND
FORMAT PrettyCompact
"
}

compare_window() {
  local label="$1"
  local wire_pkt="$2" wire_byt="$3"
  local xdp_tp="$4" xdp_pe="$5" xdp_mf="$6" xdp_nip="$7" xdp_ap="$8"
  local ch_pkt="$9" ch_byt="${10}"

  local identity=$((xdp_ap + xdp_pe + xdp_mf + xdp_nip))
  echo ""
  echo "=== $label (${WINDOW_SEC}s window) ==="
  echo "wire (ground truth):  packets=$wire_pkt bytes=${wire_byt:-n/a}"
  echo "xdpflowd delta:       total_packets=$xdp_tp parse_errors=$xdp_pe map_full=$xdp_mf non_ip=$xdp_nip accounted=$xdp_ap"
  echo "xdp identity:         accounted+parse+map_full+non_ip = $identity (must equal total=$xdp_tp)"
  echo "ClickHouse in window: packets=$ch_pkt bytes=$ch_byt"

  if [[ "$xdp_tp" -gt 0 && "$identity" -ne "$xdp_tp" ]]; then
    echo "FAIL: xdpflowd internal identity broken (diff=$((xdp_tp - identity)) pkts)"
  else
    echo "PASS: xdpflowd internal identity holds"
  fi

  if [[ "$wire_pkt" -le 0 ]]; then
    echo "WARN: wire packet delta is 0 (idle mirror or wrong IFACE?)"
    return 0
  fi

  local pct_xdp pct_ch
  pct_xdp="$(pct "$xdp_tp" "$wire_pkt")"
  pct_ch="$(pct "$ch_pkt" "$wire_pkt")"
  echo "Ratio xdp_total / wire_packets     = ${pct_xdp}%"
  echo "Ratio CH_packets / wire_packets    = ${pct_ch}%"

  if awk -v p="$pct_xdp" 'BEGIN{exit (p+0 >= 99.9) ? 0 : 1}'; then
    echo "PASS: xdpflowd sees >=99.9% wire packets"
  else
    echo "WARN: xdpflowd packet ratio below 99.9% — check map_full, parse_errors, wrong IFACE"
  fi

  if [[ "$ch_pkt" -gt 0 ]]; then
    local pct_ch_xdp
    pct_ch_xdp="$(pct "$ch_pkt" "$xdp_ap")"
    echo "Ratio CH_packets / accounted       = ${pct_ch_xdp}% (export/insert lag; want close to 100%)"
  fi
}

query_ch_window() {
  local t0="$1"
  local t1="$2"
  if ! ch_client --query "SELECT 1" >/dev/null 2>&1; then
    echo "0 0"
    return 0
  fi
  ch_client --query "
SELECT sum(packets), sum(bytes)
FROM default.flows_raw
WHERE source_id = '${SOURCE_ID}'
  AND time_received_ns >= toDateTime64('${t0}', 9, 'UTC')
  AND time_received_ns <  toDateTime64('${t1}', 9, 'UTC')
FORMAT TSVRaw
" 2>/dev/null | awk '{print $1+0, $2+0}'
}

run_with_collector() {
  local w0_pkt w1_pkt wire_src
  local x0 x1
  local t0 t1 ch_pkt ch_byt

  wire_src="$(nic_wire_source "$IFACE")"
  w0_pkt="$(nic_wire_pkts "$IFACE")"
  read -r x0 <<<"$(read_xdp_counters)"
  t0="$(date -u '+%Y-%m-%d %H:%M:%S')"

  echo "START: ${t0} UTC"
  echo "IFACE=$IFACE XDP_MODE=$(xdp_mode "$IFACE") wire_source=$wire_src"
  echo "Snapshot wire_packets=$w0_pkt xdp_total=${x0%% *}"
  echo "Sleeping ${WINDOW_SEC}s ..."
  sleep "$WINDOW_SEC"

  t1="$(date -u '+%Y-%m-%d %H:%M:%S')"
  w1_pkt="$(nic_wire_pkts "$IFACE")"
  read -r x1 <<<"$(read_xdp_counters)"
  read -r ch_pkt ch_byt <<<"$(query_ch_window "$t0" "$t1")"

  local dw_pkt=$((w1_pkt - w0_pkt))
  local x0_tp x0_pe x0_mf x0_nip x0_ap
  local x1_tp x1_pe x1_mf x1_nip x1_ap
  read -r x0_tp x0_pe x0_mf x0_nip x0_ap _ _ _ <<<"$x0"
  read -r x1_tp x1_pe x1_mf x1_nip x1_ap _ _ _ <<<"$x1"
  local xdp_tp=$((x1_tp - x0_tp))
  local xdp_pe=$((x1_pe - x0_pe))
  local xdp_mf=$((x1_mf - x0_mf))
  local xdp_nip=$((x1_nip - x0_nip))
  local xdp_ap=$((x1_ap - x0_ap))

  if [[ "$dw_pkt" -le 0 ]]; then
    show_nic_debug "$IFACE"
    echo ""
    echo "WARN: wire packet delta is 0 — falling back to xdpflowd vs ClickHouse only"
    compare_xdp_vs_ch "$xdp_tp" "$xdp_pe" "$xdp_mf" "$xdp_nip" "$xdp_ap" "$ch_pkt" "$ch_byt"
    return
  fi

  compare_window "collector running ($wire_src)" \
    "$dw_pkt" "n/a" "$xdp_tp" "$xdp_pe" "$xdp_mf" "$xdp_nip" "$xdp_ap" "$ch_pkt" "$ch_byt"
}

compare_xdp_vs_ch() {
  local xdp_tp="$1" xdp_pe="$2" xdp_mf="$3" xdp_nip="$4" xdp_ap="$5"
  local ch_pkt="$6" ch_byt="$7"
  local identity=$((xdp_ap + xdp_pe + xdp_mf + xdp_nip))

  echo ""
  echo "=== xdpflowd vs ClickHouse (${WINDOW_SEC}s window) ==="
  echo "xdpflowd delta:       total_packets=$xdp_tp parse_errors=$xdp_pe map_full=$xdp_mf non_ip=$xdp_nip accounted=$xdp_ap"
  echo "xdp identity:         accounted+parse+map_full+non_ip = $identity (must equal total=$xdp_tp)"
  echo "ClickHouse in window: packets=$ch_pkt bytes=$ch_byt"

  if [[ "$xdp_tp" -gt 0 && "$identity" -ne "$xdp_tp" ]]; then
    echo "FAIL: xdpflowd internal identity broken (diff=$((xdp_tp - identity)) pkts)"
  else
    echo "PASS: xdpflowd internal identity holds"
  fi

  if [[ "$xdp_ap" -le 0 ]]; then
    echo "WARN: xdpflowd accounted delta is 0"
    return 0
  fi

  local pct_ch_xdp pct_ch_acc
  pct_ch_xdp="$(pct "$ch_pkt" "$xdp_tp")"
  pct_ch_acc="$(pct "$ch_pkt" "$xdp_ap")"
  echo "Ratio CH_packets / xdp_total     = ${pct_ch_xdp}%"
  echo "Ratio CH_packets / accounted     = ${pct_ch_acc}% (want close to 100%)"

  if awk -v p="$pct_ch_acc" 'BEGIN{exit (p+0 >= 95.0) ? 0 : 1}'; then
    echo "PASS: ClickHouse captures >=95% of accounted packets"
  else
    echo "WARN: ClickHouse ratio below 95% — check insert lag/errors, spool backlog"
  fi

  if [[ "$xdp_mf" -gt 0 ]]; then
    echo "WARN: map_full delta=$xdp_mf — packets lost before export"
  fi
}

run_xdp_vs_ch() {
  local x0 x1 t0 t1 ch_pkt ch_byt
  read -r x0 <<<"$(read_xdp_counters)"
  t0="$(date -u '+%Y-%m-%d %H:%M:%S')"
  echo "START: ${t0} UTC MODE=xdp_vs_ch (no wire counter required)"
  echo "Sleeping ${WINDOW_SEC}s ..."
  sleep "$WINDOW_SEC"
  t1="$(date -u '+%Y-%m-%d %H:%M:%S')"
  read -r x1 <<<"$(read_xdp_counters)"
  read -r ch_pkt ch_byt <<<"$(query_ch_window "$t0" "$t1")"

  local x0_tp x0_pe x0_mf x0_nip x0_ap
  local x1_tp x1_pe x1_mf x1_nip x1_ap
  read -r x0_tp x0_pe x0_mf x0_nip x0_ap _ _ _ <<<"$x0"
  read -r x1_tp x1_pe x1_mf x1_nip x1_ap _ _ _ <<<"$x1"
  compare_xdp_vs_ch \
    "$((x1_tp - x0_tp))" "$((x1_pe - x0_pe))" "$((x1_mf - x0_mf))" "$((x1_nip - x0_nip))" "$((x1_ap - x0_ap))" \
    "$ch_pkt" "$ch_byt"
}

run_stop_collector() {
  echo "MODE=stop_collector: stopping $XDP_UNIT for wire measurement (no new flows in CH during window)"
  systemctl stop "$XDP_UNIT"
  sleep 3

  local r0 r1
  read -r r0 <<<"$(sysfs_rx "$IFACE")"
  local ts_start
  ts_start="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "START: $ts_start IFACE=$IFACE (sysfs rx baseline)"
  echo "Sleeping ${WINDOW_SEC}s ..."
  sleep "$WINDOW_SEC"
  read -r r1 <<<"$(sysfs_rx "$IFACE")"

  systemctl start "$XDP_UNIT"
  sleep 5

  local drx_pkt=$(( ${r1%% *} - ${r0%% *} ))
  local drx_byt=$(( ${r1##* } - ${r0##* } ))
  echo ""
  echo "=== collector stopped (sysfs rx_packets) ==="
  echo "sysfs delta: rx_packets=$drx_pkt rx_bytes=$drx_byt"
  echo "NOTE: during this window ClickHouse did not receive new flows."
  echo "Use MODE=running for full xdpflowd vs wire vs CH comparison."
}

main() {
  need_root
  load_iface
  command -v ethtool >/dev/null || { echo "Install ethtool"; exit 1; }

  echo "=== Traffic coverage check ==="
  echo "IFACE=$IFACE WINDOW_SEC=$WINDOW_SEC MODE=$MODE SOURCE_ID=$SOURCE_ID"

  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "ERROR: interface $IFACE not found" >&2
    exit 1
  fi

  if [[ "$MODE" == "running" ]]; then
    if ! xdp_attached "$IFACE"; then
      echo "WARN: no XDP program on $IFACE — wire truth may be sysfs rx, not xdp_drop"
    fi
    print_ch_seen
    run_with_collector
  elif [[ "$MODE" == "xdp_vs_ch" ]]; then
    print_ch_seen
    run_xdp_vs_ch
  elif [[ "$MODE" == "stop_collector" ]]; then
    run_stop_collector
  else
    echo "Unknown MODE=$MODE (use running|xdp_vs_ch|stop_collector)" >&2
    exit 1
  fi

  echo ""
  echo "Done."
  echo "Tips:"
  echo "  - if ethtool xdp counters are 0: ethtool -S $IFACE | grep -i xdp"
  echo "  - MODE=xdp_vs_ch compares xdpflowd accounted vs ClickHouse (no wire counter)"
  echo "  - map_full_delta>0 in journal = real packet loss before ClickHouse"
  echo "  - compare vlan_tag_seen ≈ total_packets if 802.1Q mirror is healthy"
}

main "$@"
