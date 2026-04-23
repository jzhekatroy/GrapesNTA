#!/usr/bin/env bash
# prod_verify.sh — сверяет текущее состояние с эталонным slepkом (prod_snapshot.sh).
#
# Что проверяем (всё сопоставимо между "до" и "после" теста):
#   1) iptables rules — полный diff без счётчиков (счётчики не совпадут)
#   2) ip6tables rules — то же
#   3) net.netflow.* sysctl — совпадение
#   4) модуль ipt_NETFLOW загружен
#   5) на ключевых UDP-портах (9996/9999/2055) слушает процесс
#   6) docker-контейнеры goflow2 в состоянии "running"
#   7) правило NETFLOW присутствует в нужной таблице
#   8) XDP-программа отцеплена от интерфейса (после теста)
#   9) nfcapd/goflow2 процессы живы
#
# Использование:
#   sudo ./scripts/prod_verify.sh                       # /root/xdpflowd_baseline_latest
#   sudo ./scripts/prod_verify.sh /root/xdpflowd_baseline_<TS>
#
# Exit code: 0 — всё совпало; 1 — найдены расхождения.

set -uo pipefail

SNAP="${1:-/root/xdpflowd_baseline_latest}"
IFACE_OVERRIDE="${2:-}"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi
if [ ! -d "$SNAP" ]; then
  echo "ERROR: snapshot dir not found: $SNAP" >&2
  exit 1
fi

# Попытаемся достать iface из manifest'а (там упомянут)
IFACE="$IFACE_OVERRIDE"
if [ -z "$IFACE" ] && [ -r "$SNAP/manifest.txt" ]; then
  IFACE=$(grep -E '^iface:' "$SNAP/manifest.txt" | awk '{print $2}')
fi
IFACE="${IFACE:-enp5s0d1}"

FAIL=0
ok()   { echo "  [OK]   $*"; }
warn() { echo "  [WARN] $*"; }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

hdr()  { echo ""; echo "=== $* ==="; }

# ---------- 1) iptables rules ----------
hdr "iptables rules (diff vs snapshot)"
NOW_IPT=$(mktemp)
iptables-save > "$NOW_IPT" 2>/dev/null
if diff -u "$SNAP/10_iptables_save_rules.txt" "$NOW_IPT" > /tmp/ipt_diff.$$.txt 2>&1; then
  ok "iptables rules identical to baseline"
else
  bad "iptables rules differ — see /tmp/ipt_diff.$$.txt"
  head -n 40 /tmp/ipt_diff.$$.txt | sed 's/^/    /'
fi
rm -f "$NOW_IPT"

hdr "ip6tables rules (diff vs snapshot)"
NOW_IP6=$(mktemp)
ip6tables-save > "$NOW_IP6" 2>/dev/null
if diff -u "$SNAP/10_ip6tables_save_rules.txt" "$NOW_IP6" > /tmp/ip6_diff.$$.txt 2>&1; then
  ok "ip6tables rules identical to baseline"
else
  bad "ip6tables rules differ — see /tmp/ip6_diff.$$.txt"
  head -n 40 /tmp/ip6_diff.$$.txt | sed 's/^/    /'
fi
rm -f "$NOW_IP6"

# ---------- 2) NETFLOW rule специфично ----------
hdr "ipt_NETFLOW rule presence"
BASELINE_RULES=$(grep -E '\-j NETFLOW' "$SNAP/10_iptables_save_rules.txt" 2>/dev/null || true)
if [ -z "$BASELINE_RULES" ]; then
  warn "baseline had no NETFLOW rule — skipping"
else
  echo "  baseline:"
  echo "$BASELINE_RULES" | sed 's/^/    /'
  echo "  current:"
  NOW_RULES=$(iptables-save 2>/dev/null | grep -E '\-j NETFLOW' || true)
  if [ -z "$NOW_RULES" ]; then
    bad "NETFLOW rule missing from current iptables!"
  else
    echo "$NOW_RULES" | sed 's/^/    /'
    if [ "$BASELINE_RULES" = "$NOW_RULES" ]; then
      ok "NETFLOW rule matches baseline"
    else
      bad "NETFLOW rule differs from baseline"
    fi
  fi
fi

# ---------- 3) sysctl net.netflow.* ----------
hdr "net.netflow.* sysctl"
NOW_SYSCTL=$(mktemp)
sysctl -a 2>/dev/null | grep -E "^net\.netflow\." | sort > "$NOW_SYSCTL"
if [ ! -s "$SNAP/20_sysctl_netflow.txt" ]; then
  warn "baseline has empty sysctl_netflow.txt — skipping"
elif diff -u "$SNAP/20_sysctl_netflow.txt" "$NOW_SYSCTL" > /tmp/sysctl_diff.$$.txt 2>&1; then
  ok "net.netflow.* identical to baseline"
else
  bad "net.netflow.* differs:"
  head -n 20 /tmp/sysctl_diff.$$.txt | sed 's/^/    /'
fi
rm -f "$NOW_SYSCTL"

# ---------- 4) module loaded ----------
hdr "ipt_NETFLOW module"
if lsmod | grep -qiE "^ipt_netflow"; then
  ok "ipt_NETFLOW loaded"
else
  bad "ipt_NETFLOW NOT loaded!"
fi

# ---------- 5) listening ports ----------
hdr "listening UDP ports"
NOW_PORTS=$(ss -ulnp 2>/dev/null)
for p in 9996 9999 2055; do
  if grep -qE ":(${p})\b" "$SNAP/60_ss_udp.txt" 2>/dev/null; then
    if echo "$NOW_PORTS" | grep -qE ":(${p})\b"; then
      ok "UDP :$p — listening"
    else
      bad "UDP :$p was listening at baseline, now NOT"
    fi
  else
    warn "UDP :$p not in baseline — skipping"
  fi
done

# ---------- 6) docker goflow2 ----------
hdr "docker goflow2"
if command -v docker >/dev/null 2>&1; then
  # ищем по имени или образу
  GF_RUN=$(docker ps --format '{{.Names}} {{.Image}} {{.Status}}' 2>/dev/null | grep -iE "goflow" || true)
  if [ -n "$GF_RUN" ]; then
    ok "goflow2 running:"
    echo "$GF_RUN" | sed 's/^/    /'
  else
    # был ли он в snapshot?
    if grep -qi "goflow" "$SNAP/70_docker_ps.txt" 2>/dev/null; then
      bad "goflow2 container was present at baseline but NOT running now"
    else
      warn "no goflow2 in baseline — skipping"
    fi
  fi
else
  warn "docker not installed — skipping"
fi

# ---------- 7) XDP detached ----------
hdr "XDP attachment on $IFACE"
if ip link show "$IFACE" 2>/dev/null | grep -qE 'prog/xdp|xdp[a-z]*[[:space:]]+id'; then
  bad "XDP program still attached to $IFACE! (expected none after test)"
  ip -details link show "$IFACE" | grep -iE 'xdp' | head -5 | sed 's/^/    /'
else
  ok "no XDP program on $IFACE"
fi

# ---------- 8) процессы ----------
hdr "expected processes"
for proc in nfcapd goflow2; do
  if grep -qE "$proc" "$SNAP/80_ps_netflow_related.txt" 2>/dev/null; then
    if pgrep -f "$proc" >/dev/null; then
      ok "$proc running"
    else
      bad "$proc was running at baseline but NOT now"
    fi
  fi
done
# xdpflowd НЕ должен крутиться после теста
if pgrep -x xdpflowd >/dev/null; then
  bad "xdpflowd still running after test (pid=$(pgrep -x xdpflowd | tr '\n' ' '))"
else
  ok "xdpflowd not running (as expected after test)"
fi

# ---------- 9) ipt_NETFLOW counter прогресс ----------
hdr "ipt_NETFLOW throughput sanity"
NOW_ST=$(mktemp)
cat /proc/net/stat/ipt_netflow > "$NOW_ST" 2>/dev/null
if [ -s "$SNAP/20_proc_stat_netflow.txt" ] && [ -s "$NOW_ST" ]; then
  # первая строка заголовок, вторая — agregate. Сравним pkt_total (первая колонка на строке 2).
  BASE_PKTS=$(awk 'NR==2{print $1}' "$SNAP/20_proc_stat_netflow.txt")
  NOW_PKTS=$(awk 'NR==2{print $1}'  "$NOW_ST")
  if [[ "$BASE_PKTS" =~ ^[0-9]+$ ]] && [[ "$NOW_PKTS" =~ ^[0-9]+$ ]]; then
    if (( NOW_PKTS > BASE_PKTS )); then
      DELTA=$(( NOW_PKTS - BASE_PKTS ))
      ok "ipt_NETFLOW pkt_total grew by $DELTA since baseline"
    else
      bad "ipt_NETFLOW pkt_total did NOT grow (baseline=$BASE_PKTS, now=$NOW_PKTS) — module receiving 0 packets?"
    fi
  else
    warn "could not parse pkt_total from /proc/net/stat/ipt_netflow"
  fi
fi
rm -f "$NOW_ST"

hdr "summary"
if (( FAIL == 0 )); then
  echo "  ALL OK — state matches baseline $SNAP"
  exit 0
else
  echo "  $FAIL check(s) FAILED — compare with $SNAP"
  echo "  manual restore commands:"
  echo "    iptables-restore  < $SNAP/10_iptables_save_counters.txt"
  echo "    ip6tables-restore < $SNAP/10_ip6tables_save_counters.txt"
  echo "    ./scripts/prod_restore.sh /tmp/xdpflowd_abswap_*/state.env"
  exit 1
fi
