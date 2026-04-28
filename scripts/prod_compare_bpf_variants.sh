#!/usr/bin/env bash
# prod_compare_bpf_variants.sh — run several BPF objects back-to-back and
# collect comparable phase3 summaries.
#
# Default 5-minute cycle:
#   full  -> ./bpf/xdp_flow.o       (current rich flow accounting)
#   fast  -> ./bpf/xdp_flow_fast.o  (lean flow accounting, NetFlow-compatible)
#   light -> ./bpf/xdp_light.o      (counter-only diagnostic, no NetFlow records)
#
# Example:
#   sudo XDP_MODE=generic XDP_ACTION=drop ./scripts/prod_compare_bpf_variants.sh 300 enp5s0d1
#
# Optional:
#   VARIANTS="full fast"     # skip light when checking ClickHouse completeness
#   MAP_SIZE=12000000        # build-time FLOWS_MAP_SIZE
#   SKIP_BUILD=1             # use already-built objects/binary

set -euo pipefail

DURATION="${1:-300}"
IFACE="${2:-enp5s0d1}"
VARIANTS="${VARIANTS:-full fast light}"
MAP_SIZE="${MAP_SIZE:-12000000}"
SKIP_BUILD="${SKIP_BUILD:-0}"

XDP_MODE="${XDP_MODE:-generic}"
XDP_ACTION="${XDP_ACTION:-drop}"
case "$XDP_MODE" in native|generic) ;; *) echo "ERROR: XDP_MODE must be native|generic" >&2; exit 1;; esac
case "$XDP_ACTION" in pass|drop) ;; *) echo "ERROR: XDP_ACTION must be pass|drop" >&2; exit 1;; esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="/tmp/bpf_variant_compare_${TS}"
mkdir -p "$OUT_DIR"

LOG="$OUT_DIR/compare.log"
SUMMARY="$OUT_DIR/SUMMARY.txt"

exec > >(tee -a "$LOG") 2>&1

variant_obj() {
  case "$1" in
    full)  echo "./bpf/xdp_flow.o" ;;
    fast)  echo "./bpf/xdp_flow_fast.o" ;;
    light) echo "./bpf/xdp_light.o" ;;
    *) echo "ERROR: unknown variant: $1" >&2; return 1 ;;
  esac
}

variant_note() {
  case "$1" in
    full)  echo "rich parser/map profile (production baseline)" ;;
    fast)  echo "lean parser/map profile (NetFlow-compatible)" ;;
    light) echo "counter-only diagnostic (no NetFlow records expected)" ;;
    *) echo "-" ;;
  esac
}

echo "======================================================================"
echo "BPF variant compare — $TS"
echo "iface=$IFACE duration=${DURATION}s xdp-mode=$XDP_MODE xdp-action=$XDP_ACTION map_size=$MAP_SIZE"
echo "variants: $VARIANTS"
echo "out_dir=$OUT_DIR"
echo "======================================================================"

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo ""
  echo "===== BUILDING BPF VARIANTS ====="
  make clean
  make -s "FLOWS_MAP_SIZE=$MAP_SIZE" bpf-variants build
fi

{
  echo "BPF variant compare — $(date -Is)"
  echo "iface=$IFACE duration=${DURATION}s xdp-mode=$XDP_MODE xdp-action=$XDP_ACTION map_size=$MAP_SIZE"
  echo ""
} > "$SUMMARY"

for v in $VARIANTS; do
  obj="$(variant_obj "$v")"
  if [[ ! -f "$obj" ]]; then
    echo "ERROR: $obj does not exist; build failed or SKIP_BUILD=1 was wrong" >&2
    exit 1
  fi

  echo ""
  echo "======================================================================"
  echo "RUN variant=$v obj=$obj note=$(variant_note "$v")"
  echo "======================================================================"

  run_log="$OUT_DIR/${v}.run.log"
  # Preserve caller-provided CH_* / XDP_NF_* / WATCHDOG_* env; only override the BPF object.
  XDP_MODE="$XDP_MODE" \
  XDP_ACTION="$XDP_ACTION" \
  XDP_BPF_OBJ="$obj" \
    "$REPO_ROOT/scripts/prod_phase3_drop.sh" "$DURATION" "$IFACE" \
    2>&1 | tee "$run_log"

  workdir="$(awk -F= '/^workdir=/{print $2; exit}' "$run_log" || true)"
  {
    echo "----- $v ($obj) -----"
    echo "note: $(variant_note "$v")"
    echo "run_log: $run_log"
    if [[ -n "$workdir" && -f "$workdir/SUMMARY.txt" ]]; then
      echo "workdir: $workdir"
      awk '
        /----- WINDOW A/ {show=1}
        /Full data in:/ {show=0}
        show {print}
        /----- NIC rate per window/ {nic=1}
        nic && /A \(baseline/ {print}
        nic && /B \(xdpflowd/ {print}
        /----- NIC fifo_errors lifecycle/ {fifo=1; print; next}
        fifo && /^  / {print; next}
        fifo && /^$/ {fifo=0}
      ' "$workdir/SUMMARY.txt"
    else
      echo "workdir: not found in run log"
    fi
    echo ""
  } >> "$SUMMARY"

  echo ""
  echo "variant=$v finished. Waiting 30s before next run..."
  sleep 30
done

echo ""
echo "======================================================================"
echo "COMPARISON SUMMARY: $SUMMARY"
echo "======================================================================"
cat "$SUMMARY"
