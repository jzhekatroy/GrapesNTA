#!/usr/bin/env bash
# prod_audit.sh — single-run production server audit for NetFlow pipeline.
#
# Safe: read-only, does NOT change anything (no ethtool -G, no iptables edits,
# no module load/unload). Output goes to /root/xdp_audit/<hostname>_<ts>/.
#
# Usage:  sudo ./prod_audit.sh [SPAN_IFACE]
#   SPAN_IFACE — if known, pass the interface that receives mirror/SPAN traffic.
#                Otherwise script auto-detects candidates.

set -u

SPAN_HINT="${1:-}"
TS="$(date +%Y%m%d_%H%M%S)"
HOST="$(hostname)"
OUTDIR="/root/xdp_audit/${HOST}_${TS}"
mkdir -p "$OUTDIR"
cd "$OUTDIR"

run() {
  local label="$1"; shift
  echo "# === $label ==="
  echo "# cmd: $*"
  "$@" 2>&1
  echo
}

{
  run "HOSTNAME/UPTIME"  bash -c 'hostname; uptime; date -u +%FT%TZ'
  run "OS"               bash -c 'cat /etc/os-release 2>/dev/null | head -5'
  run "KERNEL"           uname -a
  run "CPU"              bash -c 'lscpu | head -25'
  run "RAM"              free -h
  run "DISK"             df -hT
  run "LOAD"             bash -c 'cat /proc/loadavg'
} > 01_system.txt

# ---- Network links + candidates for SPAN/TAP -------------------------------
{
  run "LINKS brief"  ip -br link
  run "LINKS full"   ip -s link
  echo "# === PROMISC / traffic candidates ==="
  for i in $(ls /sys/class/net/ | grep -Ev '^(lo|docker|veth|br-|virbr)'); do
    flags=$(cat /sys/class/net/$i/flags 2>/dev/null)
    rxp=$(cat /sys/class/net/$i/statistics/rx_packets 2>/dev/null)
    rxb=$(cat /sys/class/net/$i/statistics/rx_bytes 2>/dev/null)
    rxd=$(cat /sys/class/net/$i/statistics/rx_dropped 2>/dev/null)
    op=$(cat /sys/class/net/$i/operstate 2>/dev/null)
    promisc=$(printf "%d" "$((flags & 0x100))" 2>/dev/null || echo "?")
    printf "  iface=%-20s op=%-10s promisc_bit=%s rx_pkts=%-20s rx_bytes=%-20s rx_drop=%s\n" \
      "$i" "$op" "$promisc" "${rxp:-0}" "${rxb:-0}" "${rxd:-0}"
  done
} > 02_links.txt

# Auto-detect SPAN interface = highest rx_packets, promisc=on, operstate=up
if [[ -z "$SPAN_HINT" ]]; then
  SPAN_HINT=$(for i in $(ls /sys/class/net/ | grep -Ev '^(lo|docker|veth|br-|virbr)'); do
    flags=$(cat /sys/class/net/$i/flags 2>/dev/null)
    rxp=$(cat /sys/class/net/$i/statistics/rx_packets 2>/dev/null)
    op=$(cat /sys/class/net/$i/operstate 2>/dev/null)
    prom=$((flags & 0x100))
    [[ "$op" == "up" && "$prom" -gt 0 ]] && echo "$rxp $i"
  done | sort -rn | head -1 | awk '{print $2}')
fi
echo "SPAN_HINT=$SPAN_HINT" > 02_links.txt.hint
echo "Detected SPAN interface: $SPAN_HINT"

# ---- Flow-related processes ------------------------------------------------
{
  run "PROCESSES matching goflow|netflow|nfdump|fprobe|softflow|pmacct|ntopng" \
    bash -c "ps auxf | grep -iE 'goflow|netflow|nfdump|fprobe|softflow|pmacct|ntopng' | grep -v grep || echo 'none'"
  run "LOADED KERNEL MODULES (netflow|xdp|bpf)" \
    bash -c "lsmod | grep -iE 'ipt_netflow|xdp|bpf|mlx|ixgbe|i40e' | head -20 || echo 'none'"
  run "SYSTEMD UNITS (goflow|netflow|nfdump)" \
    bash -c "systemctl list-units --type=service --all | grep -iE 'goflow|netflow|nflow|nfdump' || echo 'none'"
  run "UDP LISTENERS (NetFlow/sFlow/IPFIX ports)" \
    bash -c "ss -tulnp | grep -E ':(2055|2056|4729|4739|6343|9995|9996|9999)\b' || echo 'none'"
} > 03_processes.txt

# ---- ipt_NETFLOW stats -----------------------------------------------------
{
  run "iptables NETFLOW rules" \
    bash -c "iptables-save 2>/dev/null | grep -i netflow || echo 'no ipt_netflow iptables rules'"
  run "ipt_NETFLOW /proc stats" \
    bash -c "cat /proc/net/stat/ipt_netflow 2>/dev/null || echo 'ipt_NETFLOW module not loaded'"
  run "ipt_NETFLOW sysctl" \
    bash -c "sysctl -a 2>/dev/null | grep -i netflow | head -30 || echo 'none'"
} > 04_iptnetflow.txt

# ---- Docker ---------------------------------------------------------------
{
  if command -v docker >/dev/null 2>&1; then
    run "Docker containers" docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
    run "Docker networks"   docker network ls
    echo "# === Container details (goflow2 / netflow / kafka) ==="
    for c in $(docker ps --format '{{.Names}}' | grep -iE 'goflow|netflow|kafka|flow' 2>/dev/null); do
      echo "--- $c ---"
      docker inspect "$c" 2>/dev/null | grep -E '"Image"|"Cmd"|"Entrypoint"|"NetworkMode"|"Binds"|"Source"|"Destination"' | head -20
      echo "--- $c: env with kafka/flow ---"
      docker inspect "$c" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -iE 'kafka|flow|broker|topic' | head
      echo
    done
  else
    echo "docker not installed"
  fi
} > 05_docker.txt

# ---- SPAN interface deep dive ---------------------------------------------
if [[ -n "$SPAN_HINT" ]]; then
  IFACE="$SPAN_HINT"
  {
    run "IFACE" echo "$IFACE"
    run "ethtool -i (driver info)" ethtool -i "$IFACE"
    run "ethtool link speed"       bash -c "ethtool '$IFACE' 2>/dev/null | grep -E 'Speed|Duplex|Link' || echo 'ethtool failed'"
    run "ethtool -l channels"      ethtool -l "$IFACE"
    run "ethtool -g ring buffer"   ethtool -g "$IFACE"
    run "ethtool -k features"      bash -c "ethtool -k '$IFACE' 2>/dev/null | grep -iE 'gro|lro|gso|rx-checksum|rx-udp-gro' | head -20"
    run "ethtool -S rx counters"   bash -c "ethtool -S '$IFACE' 2>/dev/null | grep -iE 'rx_(packets|bytes|errors|dropped|fifo|missed|crc|over|discards|no_buffer)' || echo 'stats unavailable'"
    run "sysfs statistics"         bash -c "for f in /sys/class/net/$IFACE/statistics/rx_* ; do echo \"  \$(basename \$f): \$(cat \$f)\" ; done"
    run "XDP attached?"            bash -c "ip link show '$IFACE' | grep -iE 'xdp|generic' || echo 'no XDP'"
    run "IRQ affinity (NIC)"       bash -c "
      for irq in \$(grep -E \"$IFACE|mlx|ixgbe|i40e\" /proc/interrupts 2>/dev/null | awk -F: '{print \$1}' | tr -d ' ' | head -32); do
        [[ -f /proc/irq/\$irq/smp_affinity_list ]] || continue
        aff=\$(cat /proc/irq/\$irq/smp_affinity_list)
        name=\$(grep \"^\\s*\$irq:\" /proc/interrupts | awk '{print \$NF}')
        printf 'IRQ %3d  affinity=%-15s  %s\n' \"\$irq\" \"\$aff\" \"\$name\"
      done
    "
  } > 06_span_iface.txt
else
  echo "SPAN interface not detected — skip section 06" > 06_span_iface.txt
fi

# ---- CPU load snapshot (no sleep, instant) --------------------------------
{
  run "mpstat ALL 1-sec"  bash -c "command -v mpstat >/dev/null && mpstat -P ALL 1 1 | tail -28 || echo 'mpstat not installed (apt install sysstat)'"
  run "top -bn1 (by %CPU)" bash -c "top -bn1 -o %CPU 2>/dev/null | head -25 || ps auxk-%cpu | head -20"
  run "softirq counters"   bash -c 'grep -E "NET_RX|NET_TX" /proc/softirqs | head -3'
} > 07_cpu_snapshot.txt

# ---- Local flow storage detection -----------------------------------------
{
  echo "# === nfcapd/nfdump directories ==="
  for d in /storage/nfdump /var/lib/nfdump /var/spool/nfdump /var/log/goflow2 /opt/flows /var/flows /srv/flows /data/flows /var/cache/nfdump; do
    if [[ -d "$d" ]]; then
      echo "--- $d ---"
      du -sh "$d" 2>/dev/null
      ls -la "$d" 2>/dev/null | head -10
      echo "last files:"
      find "$d" -type f -name 'nfcapd*' 2>/dev/null | sort | tail -3
      echo
    fi
  done
  echo "# === find recent big files (>50MB, last 2h) ==="
  find /var /opt /srv /data /storage /home -size +50M -mmin -120 -type f 2>/dev/null | head -20
  echo
  echo "# === find all nfcapd process cmdlines ==="
  for pid in $(pgrep nfcapd 2>/dev/null); do
    echo "--- nfcapd PID $pid ---"
    cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '
    echo
  done
} > 08_local_storage.txt

# ---- Kafka / DB connections ----------------------------------------------
{
  run "TCP connections to Kafka (9092/9093)" \
    bash -c "ss -tnp 2>/dev/null | grep -E ':9092|:9093' || echo 'no active kafka TCP'"
  run "TCP connections to ClickHouse (9000/8123/9440)" \
    bash -c "ss -tnp 2>/dev/null | grep -E ':9000|:8123|:9440' || echo 'no clickhouse TCP'"
  run "DNS resolve 'kafka'" \
    bash -c "getent hosts kafka 2>/dev/null || echo 'not in /etc/hosts or DNS'"
  run "/etc/hosts" \
    bash -c 'grep -v "^#" /etc/hosts 2>/dev/null'
} > 09_downstream.txt

# ---- 60-second mini-stats (background during rest of script) -------------
# Kick a 60-sec mpstat/pidstat run for background load characterization.
{
  echo "# === mpstat per CPU over 60 seconds (1 samples/5 sec) ==="
  if command -v mpstat >/dev/null; then
    mpstat -P ALL 5 12
  else
    echo "mpstat not installed — run: apt-get install -y sysstat"
  fi
} > 10_mpstat_60s.txt &
MPSTAT_BG=$!

{
  echo "# === pidstat TOP processes over 60 sec ==="
  if command -v pidstat >/dev/null; then
    pidstat -u 5 12
  else
    echo "pidstat not installed — run: apt-get install -y sysstat"
  fi
} > 11_pidstat_60s.txt &
PIDSTAT_BG=$!

# ---- perf profile in parallel (kernel functions) -------------------------
{
  echo "# === perf kernel profile (30 sec) ==="
  if command -v perf >/dev/null 2>&1 && [[ -x "$(command -v perf)" ]]; then
    perf record -a -g -F 99 -o /tmp/grapes_perf.data -- sleep 30 2>&1
    perf report --stdio -i /tmp/grapes_perf.data 2>/dev/null | head -60
    rm -f /tmp/grapes_perf.data
  else
    echo "perf not installed — run: apt-get install -y linux-perf"
  fi
} > 12_perf_30s.txt &
PERF_BG=$!

echo "Waiting for 60s background jobs (mpstat, pidstat, perf)..."
wait $MPSTAT_BG $PIDSTAT_BG $PERF_BG 2>/dev/null

# ---- NIC rate (measure pps/bps over the same 60-sec window) --------------
if [[ -n "$SPAN_HINT" ]]; then
  IFACE="$SPAN_HINT"
  {
    echo "# === NIC rate over 60 seconds ==="
    T0=$(date +%s)
    P0=$(cat /sys/class/net/$IFACE/statistics/rx_packets)
    B0=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
    D0=$(cat /sys/class/net/$IFACE/statistics/rx_dropped)
    F0=$(grep 'rx_fifo_errors' <(ethtool -S $IFACE 2>/dev/null) | awk '{print $2}' || echo 0)
    sleep 60
    T1=$(date +%s)
    P1=$(cat /sys/class/net/$IFACE/statistics/rx_packets)
    B1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
    D1=$(cat /sys/class/net/$IFACE/statistics/rx_dropped)
    F1=$(grep 'rx_fifo_errors' <(ethtool -S $IFACE 2>/dev/null) | awk '{print $2}' || echo 0)
    DT=$((T1 - T0))
    DP=$((P1 - P0))
    DB=$((B1 - B0))
    DD=$((D1 - D0))
    DF=$((F1 - F0))
    echo "Interval:        $DT seconds"
    echo "rx_packets:      $DP   ($((DP/DT)) pps)"
    echo "rx_bytes:        $DB   ($((DB*8/DT/1000000)) Mbit/s)"
    echo "rx_dropped:      $DD"
    echo "rx_fifo_errors:  $DF"
    if [[ $DP -gt 0 ]]; then
      LOSS=$(awk "BEGIN{printf \"%.4f\", 100.0*$DF/($DP+$DF)}")
      echo "Loss rate:       ${LOSS}%"
    fi
  } > 13_nic_rate_60s.txt
else
  echo "SPAN interface unknown — skip 13" > 13_nic_rate_60s.txt
fi

# ---- ipt_NETFLOW before/after (for rate calculation) -----------------------
# Single snapshot — rate inside /proc/net/stat/ipt_netflow is already averaged
{
  echo "# === ipt_NETFLOW rate line ==="
  grep -E 'Rate:|Total |drop:|Export: Rate' /proc/net/stat/ipt_netflow 2>/dev/null | head -10 \
    || echo "ipt_NETFLOW not loaded"
} > 14_iptnetflow_rate.txt

# ---- Summary file ----------------------------------------------------------
{
  echo "============================================================"
  echo " GrapesNTA production audit — $HOST @ $TS"
  echo "============================================================"
  echo
  echo "Generated in: $OUTDIR"
  echo
  echo "SPAN interface detected: ${SPAN_HINT:-<unknown>}"
  echo
  echo "Files:"
  ls -la
  echo
  echo "=========== QUICK-LOOK HIGHLIGHTS ==========="
  echo
  echo "--- CPU load averages ---"
  tail -1 /proc/loadavg
  echo
  echo "--- Softirq averages (from mpstat 60s) ---"
  grep -E '^Average.*all' 10_mpstat_60s.txt 2>/dev/null | head -3
  echo
  echo "--- NIC rate (from 13_nic_rate_60s.txt) ---"
  cat 13_nic_rate_60s.txt | grep -E 'rx_packets|rx_bytes|rx_fifo|Loss|Mbit|pps'
  echo
  echo "--- ipt_NETFLOW state ---"
  cat 14_iptnetflow_rate.txt
  echo
  echo "--- Top CPU processes (pidstat 60s avg top-10) ---"
  awk 'NR>3 && $NF != "Command"' 11_pidstat_60s.txt 2>/dev/null | \
    awk '{cpu[$NF]+=$8; cnt[$NF]++} END {for (p in cpu) if (cnt[p]>0) printf "%7.2f%%  %s\n", cpu[p]/cnt[p], p}' | \
    sort -rn | head -10
  echo
  echo "--- Top kernel functions (perf) ---"
  grep -E '^\s+[0-9]+\.[0-9]+%' 12_perf_30s.txt 2>/dev/null | head -15
  echo
  echo "============================================================"
  echo " Done. Tarball:"
  echo "============================================================"
} > 00_SUMMARY.txt

# Create tarball for easy transfer
TARBALL="/root/xdp_audit_${HOST}_${TS}.tar.gz"
tar czf "$TARBALL" -C /root/xdp_audit "${HOST}_${TS}"
echo
echo "=========================================="
echo "AUDIT COMPLETE"
echo "=========================================="
echo "Dir:     $OUTDIR"
echo "Tarball: $TARBALL  ($(du -h "$TARBALL" | awk '{print $1}'))"
echo
echo "Send the tarball back (scp to your laptop), or paste contents of 00_SUMMARY.txt:"
echo
cat "$OUTDIR/00_SUMMARY.txt"
