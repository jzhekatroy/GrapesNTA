#!/usr/bin/env bash
# Wrapper for systemd: load /etc/xdpflowd/sel.env and exec xdpflowd.
# Installed path may be ${REPO_ROOT}/deploy/sel/xdpflowd-exec.sh.

set -euo pipefail

ENV_FILE="${XDPFLOWD_ENV_FILE:-/etc/xdpflowd/sel.env}"
if [[ ! -r "$ENV_FILE" ]]; then
  echo "ERROR: env file not readable: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

if [[ -n "${XDPFLOWD_EXPECT_HOST_SHORT:-}" ]]; then
  short="$(hostname -s 2>/dev/null || hostname | cut -d. -f1)"
  if [[ "$short" != "$XDPFLOWD_EXPECT_HOST_SHORT" ]]; then
    echo "ERROR: hostname -s=$short expected $XDPFLOWD_EXPECT_HOST_SHORT (set XDPFLOWD_EXPECT_HOST_SHORT in $ENV_FILE)" >&2
    exit 1
  fi
fi

REPO_ROOT="${REPO_ROOT:-/opt/GrapesNTA}"
BIN="${XDPFLOWD_BIN:-$REPO_ROOT/bin/xdpflowd}"
IFACE="${IFACE:-enp5s0d1}"
XDP_BPF_OBJ="${XDP_BPF_OBJ:-$REPO_ROOT/bpf/xdp_flow.o}"
XDP_MODE="${XDP_MODE:-generic}"
XDP_ACTION="${XDP_ACTION:-drop}"
NF_DSTS="${NF_DSTS:-127.0.0.1:9996}"
XDP_TOP="${XDP_TOP:-0}"
XDP_INTERVAL="${XDP_INTERVAL:-5s}"
XDP_TOP_INTERVAL="${XDP_TOP_INTERVAL:-60s}"
XDP_JSON_OUT_ENABLE="${XDP_JSON_OUT_ENABLE:-0}"
XDP_JSON_INTERVAL="${XDP_JSON_INTERVAL:-10s}"
XDP_HEAVY_EXPORT="${XDP_HEAVY_EXPORT:-0}"

XDP_NF_ACTIVE="${XDP_NF_ACTIVE:-1800s}"
XDP_NF_IDLE="${XDP_NF_IDLE:-15s}"
XDP_NF_TEMPLATE_INTERVAL="${XDP_NF_TEMPLATE_INTERVAL:-60s}"
XDP_NF_SCAN="${XDP_NF_SCAN:-1s}"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: xdpflowd binary not executable: $BIN" >&2
  exit 1
fi
if [[ ! -f "$XDP_BPF_OBJ" ]]; then
  echo "ERROR: BPF object missing: $XDP_BPF_OBJ" >&2
  exit 1
fi

if [[ -z "${XDP_CH_DSN:-}" || -z "${XDP_CH_TABLE:-}" ]]; then
  echo "ERROR: XDP_CH_DSN and XDP_CH_TABLE must be set in $ENV_FILE" >&2
  exit 1
fi

CONFIG_ARGS=()
if [[ -n "${XDP_CONFIG_FILE:-}" ]]; then
  if [[ ! -r "$XDP_CONFIG_FILE" ]]; then
    echo "ERROR: XDP_CONFIG_FILE not readable: $XDP_CONFIG_FILE" >&2
    exit 1
  fi
  CONFIG_ARGS=( -config "$XDP_CONFIG_FILE" )
fi

JSON_ARGS=()
if [[ "$XDP_JSON_OUT_ENABLE" == "1" ]]; then
  : "${XDP_JSON_OUT_PATH:?XDP_JSON_OUT_ENABLE=1 requires XDP_JSON_OUT_PATH}"
  JSON_ARGS=( -json-out "$XDP_JSON_OUT_PATH" -json-interval "$XDP_JSON_INTERVAL" )
fi

CH_ARGS=(
  -ch-dsn "$XDP_CH_DSN"
  -ch-table "$XDP_CH_TABLE"
  -ch-batch-size "${XDP_CH_BATCH_SIZE:-500}"
  -ch-flush-interval "${XDP_CH_FLUSH_INTERVAL:-1s}"
  -ch-queue-size "${XDP_CH_QUEUE_SIZE:-64}"
)
if [[ -n "${XDP_CH_SAMPLER_ADDR:-}" ]]; then
  CH_ARGS+=( -ch-sampler-addr "$XDP_CH_SAMPLER_ADDR" )
fi
if [[ "${XDP_CLASSIFIER:-0}" == "1" ]]; then
  CH_ARGS+=(
    -classifier
    -classifier-refresh "${XDP_CLASSIFIER_REFRESH:-60s}"
    -classifier-bgp-table "${XDP_CLASSIFIER_BGP_TABLE:-default.bgp_prefix_origin_current}"
    -classifier-l3-prefixes-view "${XDP_CLASSIFIER_L3_PREFIXES_VIEW:-default.net_l3_prefixes_enabled}"
    -classifier-l2-vlans-view "${XDP_CLASSIFIER_L2_VLANS_VIEW:-default.net_l2_vlans_enabled}"
  )
fi

case "${XDP_CH_SPOOL_MODE:-off}" in
  off)
    echo "ERROR: permanent sel profile expects XDP_CH_SPOOL_MODE on or required (got: off)" >&2
    exit 1
    ;;
  on|required) ;;
  *)
    echo "ERROR: XDP_CH_SPOOL_MODE must be on|required (got: $XDP_CH_SPOOL_MODE)" >&2
    exit 1
    ;;
esac

: "${XDP_CH_SPOOL_DIR:?XDP_CH_SPOOL_DIR must be set for spool}"
CH_ARGS+=(
  -ch-spool-mode "$XDP_CH_SPOOL_MODE"
  -ch-spool-dir "$XDP_CH_SPOOL_DIR"
  -ch-spool-segment-size "${XDP_CH_SPOOL_SEGMENT_SIZE:-268435456}"
  -ch-spool-max-bytes "${XDP_CH_SPOOL_MAX_BYTES:-0}"
  -ch-spool-frame-max-records "${XDP_CH_SPOOL_FRAME_MAX_RECORDS:-50000}"
  -ch-spool-fsync-interval "${XDP_CH_SPOOL_FSYNC_INTERVAL:-1s}"
  -ch-spool-shutdown-drain "${XDP_CH_SPOOL_SHUTDOWN_DRAIN:-0s}"
  -ch-spool-stall-threshold "${XDP_CH_SPOOL_STALL_THRESHOLD:-60s}"
  -ch-writers "${XDP_CH_WRITERS:-4}"
)

HEAVY_ARGS=()
if [[ "$XDP_HEAVY_EXPORT" == "1" ]]; then
  HEAVY_ARGS=( -heavy-export )
fi

DNS_PASSTHROUGH_ARGS=()
if [[ "${XDP_DNS_PASSTHROUGH:-0}" == "1" ]]; then
  DNS_PASSTHROUGH_ARGS=( -dns-passthrough )
fi

STDBUF=()
if command -v stdbuf >/dev/null 2>&1; then
  STDBUF=( stdbuf -oL -eL )
fi

exec "${STDBUF[@]}" "$BIN" \
  "${CONFIG_ARGS[@]}" \
  -iface "$IFACE" \
  -mode "$XDP_MODE" \
  -xdp-action "$XDP_ACTION" \
  -bpf "$XDP_BPF_OBJ" \
  -nf-dst "$NF_DSTS" \
  "${HEAVY_ARGS[@]}" \
  "${DNS_PASSTHROUGH_ARGS[@]}" \
  -nf-active "$XDP_NF_ACTIVE" \
  -nf-idle "$XDP_NF_IDLE" \
  -nf-template-interval "$XDP_NF_TEMPLATE_INTERVAL" \
  -nf-scan "$XDP_NF_SCAN" \
  -top "$XDP_TOP" \
  -top-interval "$XDP_TOP_INTERVAL" \
  -interval "$XDP_INTERVAL" \
  -health-interval "${XDP_HEALTH_INTERVAL:-1m}" \
  -health-spool-lag-segments "${XDP_HEALTH_SPOOL_LAG_SEGMENTS:-10}" \
  -health-writer-lag-rows "${XDP_HEALTH_WRITER_LAG_ROWS:-100000}" \
  -health-drainer-age "${XDP_HEALTH_DRAINER_AGE:-2m}" \
  "${JSON_ARGS[@]}" \
  "${CH_ARGS[@]}"
