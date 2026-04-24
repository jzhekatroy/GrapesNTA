#!/usr/bin/env bash
# prod_tune_irq.sh — показать / раскидать / восстановить IRQ affinity сетевой карты.
#
# Типичная проблема на проде: все IRQ одной NIC прибиты к одному CPU →
# softirq в потолке на этом CPU, остальные простаивают. Этот скрипт берёт
# все IRQ интерфейса и раскладывает их по разным CPU круговым способом.
#
# Использование:
#   sudo ./scripts/prod_tune_irq.sh show    enp5s0d1
#   sudo ./scripts/prod_tune_irq.sh spread  enp5s0d1 [cpu_list]
#   sudo ./scripts/prod_tune_irq.sh restore enp5s0d1
#
#   cpu_list — опционально, список CPU через запятую (по умолчанию все online).
#              Пример: 4,5,6,7,8,9,10,11 — чтобы не трогать CPU 0-3.
#
# Гарантии:
#   * spread сохраняет старое состояние в /root/irq_affinity_backup_<iface>.txt
#   * restore читает этот файл и возвращает как было
#   * при spread автоматически останавливается irqbalance (он всё ломает),
#     при restore — запускается обратно.
#   * если IRQ для интерфейса не найдены — завершается без изменений.

set -euo pipefail

MODE="${1:-}"
IFACE="${2:-}"
CPU_LIST="${3:-}"

if [[ -z "$MODE" || -z "$IFACE" ]]; then
  echo "Usage: $0 show|spread|restore <iface> [cpu_list]" >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface $IFACE not found" >&2
  exit 1
fi

BACKUP="/root/irq_affinity_backup_${IFACE}.txt"

# ---------- найти IRQ интерфейса ----------
# Подходят три источника (в порядке приоритета):
#   1) /sys/class/net/<iface>/device/msi_irqs/ — точный список MSI-X IRQ
#   2) /proc/interrupts: имя содержит $IFACE (e.g. "enp5s0d1-TxRx-0")
#   3) /proc/interrupts: имя вида "mlx4-.*@pciID" с тем же PCI, что у $IFACE
detect_irqs() {
  local irqs=""

  # 1) sysfs
  local sysdir="/sys/class/net/${IFACE}/device/msi_irqs"
  if [[ -d "$sysdir" ]]; then
    irqs=$(ls "$sysdir" 2>/dev/null | sort -n | tr '\n' ' ')
  fi
  if [[ -n "$irqs" ]]; then
    # Фильтруем только те, что реально видны в /proc/interrupts (rx/tx-очереди,
    # а не управляющие/async — у mlx4 их может быть много мусорных).
    local keep=""
    for i in $irqs; do
      if grep -qE "^[[:space:]]*${i}:" /proc/interrupts; then
        keep+="$i "
      fi
    done
    # Но берём только те, у которых имя похоже на rx/tx/comp-очередь
    # (чтобы не прилепить admin/cmd/async IRQ).
    local filtered=""
    for i in $keep; do
      name=$(grep -E "^[[:space:]]*${i}:" /proc/interrupts | awk '{$1=""; print}')
      if echo "$name" | grep -qiE "(rx|tx|comp|queue|txrx|${IFACE})"; then
        filtered+="$i "
      fi
    done
    if [[ -n "$filtered" ]]; then
      echo "$filtered"
      return
    fi
    # Если фильтр слишком строгий — отдаём все sysfs IRQ
    echo "$keep"
    return
  fi

  # 2) match by iface name in /proc/interrupts
  irqs=$(grep -E "[[:space:]]${IFACE}([-@][^[:space:]]*)?$" /proc/interrupts \
    | awk '{gsub(":","",$1); print $1}' | tr '\n' ' ')
  if [[ -n "$irqs" ]]; then
    echo "$irqs"; return
  fi

  # 3) match by PCI id of interface
  if [[ -L "/sys/class/net/${IFACE}/device" ]]; then
    local pci=$(basename "$(readlink -f /sys/class/net/"$IFACE"/device)")
    irqs=$(grep -E "${pci}" /proc/interrupts \
      | awk '{gsub(":","",$1); print $1}' | tr '\n' ' ')
    if [[ -n "$irqs" ]]; then
      echo "$irqs"; return
    fi
  fi
}

IRQS=( $(detect_irqs) )
if (( ${#IRQS[@]} == 0 )); then
  echo "ERROR: no IRQs found for $IFACE" >&2
  echo "Tried: /sys/class/net/${IFACE}/device/msi_irqs and /proc/interrupts name/PCI match." >&2
  echo "Last 5 lines from /proc/interrupts for hint:" >&2
  tail -n 5 /proc/interrupts >&2
  exit 1
fi

# ---------- список CPU ----------
if [[ -n "$CPU_LIST" ]]; then
  IFS=',' read -r -a CPUS <<< "$CPU_LIST"
else
  # все online
  mapfile -t CPUS < <(awk 'BEGIN{FS="-"} {for(i=1;i<=NF;i++){} }' /dev/null || true)
  # честнее через /sys:
  ONLINE=$(cat /sys/devices/system/cpu/online)
  # развернуть диапазоны типа 0-47 в список
  CPUS=()
  IFS=',' read -r -a PARTS <<< "$ONLINE"
  for p in "${PARTS[@]}"; do
    if [[ "$p" == *-* ]]; then
      a="${p%-*}"; b="${p#*-}"
      for ((c=a; c<=b; c++)); do CPUS+=("$c"); done
    else
      CPUS+=("$p")
    fi
  done
fi

cpu_to_mask() {
  local cpu=$1
  local word=$((cpu / 32))
  local bit=$((cpu % 32))
  local mask_word=$(printf '%x' $((1 << bit)))
  if (( word == 0 )); then
    echo "$mask_word"
  else
    local result="$mask_word"
    for ((i=0; i<word; i++)); do result="${result},00000000"; done
    echo "$result"
  fi
}

# ---------- SHOW ----------
if [[ "$MODE" == "show" ]]; then
  printf "IRQs for %s: %d\n" "$IFACE" "${#IRQS[@]}"
  printf "Online CPUs: %s (%d total)\n" "$(cat /sys/devices/system/cpu/online)" "${#CPUS[@]}"
  printf "irqbalance: %s\n" "$(systemctl is-active irqbalance 2>/dev/null || echo inactive)"
  printf "\n%-8s %-40s %-12s %s\n" "IRQ" "Name" "Affinity" "TotalCount"
  printf "%-8s %-40s %-12s %s\n" "---" "----" "--------" "----------"
  for irq in "${IRQS[@]}"; do
    name=$(awk -v i="$irq:" '$1==i {for(j=NF;j>=2;j--) if($j !~ /^[0-9]+$/){print $j; exit}}' /proc/interrupts)
    aff=$(cat /proc/irq/"$irq"/smp_affinity 2>/dev/null || echo "?")
    total=$(awk -v i="$irq:" '$1==i {s=0; for(j=2;j<=NF;j++) if($j ~ /^[0-9]+$/) s+=$j; print s}' /proc/interrupts)
    printf "%-8s %-40s %-12s %s\n" "$irq" "$name" "$aff" "$total"
  done

  printf "\nPer-CPU totals from /proc/interrupts (these IRQs only):\n"
  # Собираем матрицу: IRQ x CPU
  declare -a PER_CPU
  NCPU=${#CPUS[@]}
  for ((i=0;i<NCPU;i++)); do PER_CPU[$i]=0; done
  for irq in "${IRQS[@]}"; do
    # читаем строку
    line=$(grep -E "^[[:space:]]*${irq}:" /proc/interrupts || true)
    [ -z "$line" ] && continue
    # поля 2..(1+NCPU_total) — счётчики по CPU; берём первые столько, сколько в системе
    read -r -a F <<< "$line"
    # F[0]=irq:, F[1..]=counts (до тех пор, пока числа)
    j=0
    for ((k=1; k<${#F[@]}; k++)); do
      if [[ "${F[$k]}" =~ ^[0-9]+$ ]]; then
        PER_CPU[$j]=$(( PER_CPU[$j] + F[$k] ))
        j=$((j+1))
      else
        break
      fi
    done
  done
  for ((i=0;i<NCPU;i++)); do
    if (( PER_CPU[$i] > 0 )); then
      printf "  CPU %2d: %d\n" "${CPUS[$i]}" "${PER_CPU[$i]}"
    fi
  done

  # Подсказка: всё на одном CPU?
  NONZERO=0
  for ((i=0;i<NCPU;i++)); do (( PER_CPU[$i] > 0 )) && NONZERO=$((NONZERO+1)); done
  if (( NONZERO <= 1 )); then
    echo ""
    echo "WARNING: все IRQ $IFACE бьют в $NONZERO CPU — запустите '$0 spread $IFACE' чтобы размазать."
  fi
  exit 0
fi

# ---------- SPREAD ----------
if [[ "$MODE" == "spread" ]]; then
  echo "== SPREAD IRQ for $IFACE across ${#CPUS[@]} CPUs =="
  echo "IRQs: ${IRQS[*]}"
  echo "CPUs: ${CPUS[*]}"
  echo ""

  # Сохранить текущее состояние
  {
    echo "# IRQ affinity backup for $IFACE at $(date -Is)"
    for irq in "${IRQS[@]}"; do
      cur=$(cat /proc/irq/"$irq"/smp_affinity 2>/dev/null || echo "?")
      echo "$irq $cur"
    done
  } > "$BACKUP"
  echo "Backup: $BACKUP"

  # Остановить irqbalance, чтобы не перетащил обратно
  IRQBAL_WAS_ACTIVE=0
  if systemctl is-active irqbalance >/dev/null 2>&1; then
    echo "Stopping irqbalance (will NOT auto-restart — use 'restore' to bring back)"
    systemctl stop irqbalance
    IRQBAL_WAS_ACTIVE=1
  fi
  echo "$IRQBAL_WAS_ACTIVE" > "${BACKUP}.irqbalance"

  # Раскидать
  i=0
  for irq in "${IRQS[@]}"; do
    cpu=${CPUS[$(( i % ${#CPUS[@]} ))]}
    mask=$(cpu_to_mask "$cpu")
    if echo "$mask" > /proc/irq/"$irq"/smp_affinity 2>/dev/null; then
      printf "  IRQ %-6s -> CPU %-3d (mask %s)\n" "$irq" "$cpu" "$mask"
    else
      printf "  IRQ %-6s -> CPU %-3d FAILED (kernel pins it)\n" "$irq" "$cpu"
    fi
    i=$((i+1))
  done

  echo ""
  echo "Done. Снять эффект: sudo $0 restore $IFACE"
  exit 0
fi

# ---------- RESTORE ----------
if [[ "$MODE" == "restore" ]]; then
  if [[ ! -f "$BACKUP" ]]; then
    echo "ERROR: no backup file $BACKUP — nothing to restore" >&2
    exit 1
  fi
  echo "== RESTORE IRQ for $IFACE from $BACKUP =="
  while read -r irq aff; do
    [[ -z "$irq" || "$irq" == "#"* ]] && continue
    [[ "$aff" == "?" ]] && continue
    if echo "$aff" > /proc/irq/"$irq"/smp_affinity 2>/dev/null; then
      printf "  IRQ %-6s -> %s\n" "$irq" "$aff"
    else
      printf "  IRQ %-6s -> %s FAILED\n" "$irq" "$aff"
    fi
  done < "$BACKUP"

  if [[ -f "${BACKUP}.irqbalance" ]] && [[ "$(cat "${BACKUP}.irqbalance")" == "1" ]]; then
    echo "Restarting irqbalance"
    systemctl start irqbalance || true
  fi

  echo "Done."
  exit 0
fi

echo "ERROR: unknown mode '$MODE' (use show|spread|restore)" >&2
exit 1
