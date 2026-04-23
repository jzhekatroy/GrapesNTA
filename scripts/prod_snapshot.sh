#!/usr/bin/env bash
# prod_snapshot.sh — собирает эталонный слепок текущей рабочей схемы.
#
# Что сохраняется в /root/xdpflowd_baseline_<TS>/:
#   - iptables / ip6tables: все таблицы, со счётчиками и без
#   - sysctl: все net.* и отдельно /proc/sys/net/netflow/*
#   - /proc/net/stat/ipt_netflow (baseline счётчики модуля)
#   - lsmod / modinfo ipt_NETFLOW
#   - ip link / ip addr / ip route
#   - ethtool: drvinfo, rings, channels, coalesce, features, statistics
#   - ss -ulnp / ss -tlnp (кто слушает UDP/TCP)
#   - systemctl running units, netflow/docker/related
#   - docker ps + docker inspect для всех контейнеров (goflow2 и соседи)
#   - процессы nfcapd/goflow2/docker-proxy/xdpflowd
#   - /etc/systemd/system/*goflow* / *netflow* (если есть)
#   - NIC rx_bytes/rx_packets/rx_*drops baseline
#   - manifest.txt с кратким summary
#
# Симлинк /root/xdpflowd_baseline_latest обновляется на новый каталог.
#
# Использование:
#   sudo ./scripts/prod_snapshot.sh            # iface=enp5s0d1
#   sudo ./scripts/prod_snapshot.sh ens5f0     # кастомный интерфейс

set -euo pipefail

IFACE="${1:-enp5s0d1}"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="/root/xdpflowd_baseline_${TS}"
LATEST="/root/xdpflowd_baseline_latest"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

mkdir -p "$OUT"
chmod 700 "$OUT"

run() {
  # run "<label>" <command...> — выполняет команду, пишет в файл,
  # не валится если отсутствует команда или нет данных.
  local label="$1"; shift
  local out_file="$OUT/$label"
  if "$@" > "$out_file" 2>&1; then
    :
  else
    echo "(exit=$?)" >> "$out_file"
  fi
}

run_sh() {
  # run_sh "<label>" "<shell command>"
  local label="$1"; shift
  local out_file="$OUT/$label"
  bash -c "$*" > "$out_file" 2>&1 || echo "(exit=$?)" >> "$out_file"
}

echo "[$(date +%T)] writing snapshot to $OUT"

# ---------- системная инфа ----------
run 01_uname.txt             uname -a
run 01_hostname.txt          hostname -f
run 01_uptime.txt            uptime
run 01_date.txt              date -Iseconds
run 01_os_release.txt        cat /etc/os-release
run 01_clang_version.txt     bash -c 'clang --version 2>/dev/null || echo no-clang'

# ---------- iptables / ip6tables ----------
# ВАЖНО: сохраняем и с -c (со счётчиками, для backup/restore),
# и без (для сравнения rules позже — счётчики меняются).
run 10_iptables_save_counters.txt   iptables-save -c
run 10_iptables_save_rules.txt      iptables-save
run 10_ip6tables_save_counters.txt  ip6tables-save -c
run 10_ip6tables_save_rules.txt     ip6tables-save
run 10_iptables_L_v.txt             iptables -L -v -n
run 10_iptables_t_raw_L.txt         iptables -t raw    -L -v -n
run 10_iptables_t_mangle_L.txt      iptables -t mangle -L -v -n
run 10_iptables_t_nat_L.txt         iptables -t nat    -L -v -n

# ---------- ipt_NETFLOW ----------
run 20_lsmod_netflow.txt            bash -c 'lsmod | grep -iE "^(ipt_|ip6t_)?netflow"'
run 20_modinfo_ipt_NETFLOW.txt      modinfo ipt_NETFLOW
run_sh 20_sysctl_netflow.txt        'sysctl -a 2>/dev/null | grep -E "^net\.netflow\." | sort'
run_sh 20_proc_netflow_all.txt      'ls -la /proc/sys/net/netflow/ 2>/dev/null; echo ----; for f in /proc/sys/net/netflow/*; do echo "== $f =="; cat "$f"; done'
run 20_proc_stat_netflow.txt        cat /proc/net/stat/ipt_netflow

# ---------- сеть ----------
run 30_ip_link_det.txt              ip -details link show
run 30_ip_link_stats.txt            ip -s link show
run 30_ip_addr.txt                  ip addr show
run 30_ip_route.txt                 ip route show
run 30_ip_rule.txt                  ip rule show

# ---------- целевой интерфейс ----------
if ip link show "$IFACE" >/dev/null 2>&1; then
  run 40_iface_link.txt             ip -details link show "$IFACE"
  run 40_iface_stats.txt            ip -s link show "$IFACE"
  run 40_ethtool_drvinfo.txt        ethtool -i "$IFACE"
  run 40_ethtool_rings.txt          ethtool -g "$IFACE"
  run 40_ethtool_channels.txt       ethtool -l "$IFACE"
  run 40_ethtool_coalesce.txt       ethtool -c "$IFACE"
  run 40_ethtool_features.txt       ethtool -k "$IFACE"
  run 40_ethtool_stats.txt          ethtool -S "$IFACE"
  run 40_iface_statistics.txt       bash -c "for f in /sys/class/net/$IFACE/statistics/*; do echo \"== \${f##*/} =\$(cat \$f)\"; done"
  # baseline для сравнения в verify
  run_sh 40_iface_rxbytes.txt       "cat /sys/class/net/$IFACE/statistics/rx_bytes"
  run_sh 40_iface_rxpackets.txt     "cat /sys/class/net/$IFACE/statistics/rx_packets"
  run_sh 40_iface_rxdrops.txt       "cat /sys/class/net/$IFACE/statistics/rx_dropped 2>/dev/null || echo 0"
  run_sh 40_iface_rxfifo.txt        "cat /sys/class/net/$IFACE/statistics/rx_fifo_errors 2>/dev/null || echo 0"
  # XDP attachment (должен быть пустой на эталоне)
  run_sh 40_iface_xdp.txt           "ip -details link show $IFACE | grep -oE 'xdp[a-z]*[[:space:]]+id[[:space:]]+[0-9]+|prog/xdp' || echo 'no xdp attached'"
else
  echo "WARNING: iface $IFACE not found" > "$OUT/40_iface_MISSING.txt"
fi

# ---------- sysctl ----------
run_sh 50_sysctl_core.txt           'sysctl -a 2>/dev/null | grep -E "^net\.core\." | sort'
run_sh 50_sysctl_ipv4.txt           'sysctl -a 2>/dev/null | grep -E "^net\.ipv4\." | sort'
run_sh 50_sysctl_ipv6.txt           'sysctl -a 2>/dev/null | grep -E "^net\.ipv6\." | sort'
run_sh 50_sysctl_netfilter.txt      'sysctl -a 2>/dev/null | grep -E "^net\.netfilter\." | sort'

# ---------- слушатели ----------
run 60_ss_udp.txt                   ss -ulnp
run 60_ss_tcp.txt                   ss -tlnp
run_sh 60_ss_netflow_ports.txt      'ss -ulnp | grep -E ":(9996|9999|2055|12055)\b" || echo "no target ports listening"'

# ---------- docker ----------
if command -v docker >/dev/null; then
  run 70_docker_ps.txt              docker ps -a
  # inspect всех запущенных контейнеров (содержит image, networks, cmd, env)
  for cid in $(docker ps -q 2>/dev/null); do
    docker inspect "$cid" > "$OUT/70_docker_inspect_${cid}.json" 2>&1 || true
  done
  run 70_docker_compose_list.txt    docker compose ls
  # compose-файл goflow2 — частая штука в /opt/kcg или похожем месте
  run_sh 70_goflow2_compose.txt     'find /opt /root /srv /etc -maxdepth 5 -name "docker-compose*.yml" 2>/dev/null | head -10'
fi

# ---------- процессы ----------
run_sh 80_ps_netflow_related.txt    'ps -eo pid,ppid,user,pcpu,pmem,comm,args --sort=-pcpu | grep -iE "(ipt_netflow|nfcapd|goflow|docker-proxy|xdpflowd)" | grep -v "grep -iE"'
run 80_ps_top_cpu.txt               bash -c 'ps -eo pid,user,pcpu,pmem,comm,args --sort=-pcpu | head -30'

# ---------- systemd ----------
run_sh 90_systemd_running.txt       'systemctl list-units --state=running 2>/dev/null | head -80'
run_sh 90_systemd_netflow_goflow.txt 'systemctl list-units --all 2>/dev/null | grep -iE "(netflow|goflow|nfcapd)"'
# сохраняем текст сервис-файлов если найдены
for unit in goflow2 nfcapd xdpflowd; do
  if systemctl cat "$unit" >/dev/null 2>&1; then
    systemctl cat "$unit" > "$OUT/91_systemd_unit_${unit}.txt" 2>&1 || true
  fi
done

# ---------- /etc конфиги ----------
run_sh 95_etc_modprobe.txt          'find /etc/modprobe.d /etc/modules-load.d -type f 2>/dev/null | xargs -r grep -l -iE "netflow" 2>/dev/null | xargs -r cat'
# не тянем всё /etc — только релевантное
run_sh 95_sysctl_files.txt          'ls -la /etc/sysctl.d/ /etc/sysctl.conf 2>/dev/null'

# ---------- полезная сводка ----------
{
  echo "=== xdpflowd baseline snapshot ==="
  echo "timestamp:    $(date -Iseconds)"
  echo "host:         $(hostname -f 2>/dev/null || hostname)"
  echo "iface:        $IFACE"
  echo "path:         $OUT"
  echo ""
  echo "--- ipt_NETFLOW module ---"
  grep -iE "^(ipt_|ip6t_)?netflow" "$OUT/20_lsmod_netflow.txt" || echo "NOT LOADED"
  echo ""
  echo "--- ipt_NETFLOW destinations ---"
  grep -E "^net\.netflow\.destination" "$OUT/20_sysctl_netflow.txt" 2>/dev/null || \
    grep -E "destination" "$OUT/20_proc_netflow_all.txt" 2>/dev/null | head -5
  echo ""
  echo "--- NETFLOW iptables rules ---"
  grep -E "\-j NETFLOW" "$OUT/10_iptables_save_rules.txt" 2>/dev/null || echo "(none)"
  echo ""
  echo "--- listening ports (9996/9999/2055) ---"
  cat "$OUT/60_ss_netflow_ports.txt"
  echo ""
  echo "--- UDP processes on those ports ---"
  bash -c 'ss -ulnp | grep -E ":(9996|9999|2055)\b"' 2>/dev/null || true
  echo ""
  echo "--- $IFACE baseline counters ---"
  if [ -s "$OUT/40_iface_rxpackets.txt" ]; then
    echo "rx_packets:   $(cat $OUT/40_iface_rxpackets.txt)"
    echo "rx_bytes:     $(cat $OUT/40_iface_rxbytes.txt)"
    echo "rx_dropped:   $(cat $OUT/40_iface_rxdrops.txt)"
    echo "rx_fifo_err:  $(cat $OUT/40_iface_rxfifo.txt)"
  fi
  echo ""
  echo "--- xdp attached? ---"
  cat "$OUT/40_iface_xdp.txt"
} > "$OUT/manifest.txt"

# ---------- ссылка latest ----------
ln -sfn "$OUT" "$LATEST"

echo ""
echo "=== MANIFEST ==="
cat "$OUT/manifest.txt"
echo ""
echo "snapshot saved: $OUT"
echo "latest symlink: $LATEST -> $OUT"
echo ""
echo "to restore iptables exactly from this snapshot (full wipe + restore):"
echo "  sudo iptables-restore  < $OUT/10_iptables_save_counters.txt"
echo "  sudo ip6tables-restore < $OUT/10_ip6tables_save_counters.txt"
