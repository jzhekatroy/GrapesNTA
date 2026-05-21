#!/usr/bin/env bash
# Wrapper: load /etc/dnsflowd/sel.env and exec dnsflowd.

set -euo pipefail

ENV_FILE="${DNSFLOWD_ENV_FILE:-/etc/dnsflowd/sel.env}"
if [[ ! -r "$ENV_FILE" ]]; then
  echo "ERROR: env file not readable: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

if [[ -n "${DNSFLOWD_EXPECT_HOST_SHORT:-}" ]]; then
  short="$(hostname -s 2>/dev/null || hostname | cut -d. -f1)"
  if [[ "$short" != "$DNSFLOWD_EXPECT_HOST_SHORT" ]]; then
    echo "ERROR: hostname -s=$short expected $DNSFLOWD_EXPECT_HOST_SHORT (set DNSFLOWD_EXPECT_HOST_SHORT in $ENV_FILE)" >&2
    exit 1
  fi
fi

REPO_ROOT="${REPO_ROOT:-/opt/GrapesNTA}"
BIN="${DNSFLOWD_BIN:-$REPO_ROOT/bin/dnsflowd}"
IFACE="${IFACE:-enp4s0np0}"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: dnsflowd binary not executable: $BIN" >&2
  exit 1
fi

if ! ip link set "$IFACE" promisc on; then
  echo "WARN: failed to set $IFACE promisc on (capture may miss frames)" >&2
fi
if [[ -z "${DNS_CH_DSN:-}" || -z "${DNS_CH_TABLE:-}" ]]; then
  echo "ERROR: DNS_CH_DSN and DNS_CH_TABLE must be set in $ENV_FILE" >&2
  exit 1
fi

bool_flag() {
  case "${1:-1}" in
    0|false|False|FALSE|no|NO) echo false ;;
    *) echo true ;;
  esac
}

STDBUF=()
if command -v stdbuf >/dev/null 2>&1; then
  STDBUF=( stdbuf -oL -eL )
fi

exec "${STDBUF[@]}" "$BIN" \
  -iface "$IFACE" \
  -ch-dsn "$DNS_CH_DSN" \
  -ch-table "$DNS_CH_TABLE" \
  -ch-answers-table "${DNS_CH_ANSWERS_TABLE:-default.dns_answers}" \
  -ch-raw-enabled "$(bool_flag "${DNS_CH_RAW_ENABLED:-1}")" \
  -ch-answers-enabled "$(bool_flag "${DNS_CH_ANSWERS_ENABLED:-1}")" \
  -ch-batch-size "${DNS_CH_BATCH_SIZE:-500}" \
  -ch-raw-batch-size "${DNS_CH_RAW_BATCH_SIZE:-0}" \
  -ch-answers-batch-size "${DNS_CH_ANSWERS_BATCH_SIZE:-0}" \
  -ch-flush-interval "${DNS_CH_FLUSH_INTERVAL:-1s}" \
  -ch-queue-size "${DNS_CH_QUEUE_SIZE:-65536}" \
  -ch-raw-queue-size "${DNS_CH_RAW_QUEUE_SIZE:-${DNS_CH_QUEUE_SIZE:-65536}}" \
  -ch-answers-queue-size "${DNS_CH_ANSWERS_QUEUE_SIZE:-262144}" \
  -ch-raw-writers "${DNS_CH_RAW_WRITERS:-1}" \
  -ch-answers-writers "${DNS_CH_ANSWERS_WRITERS:-2}" \
  -capture-batch-size "${DNS_CAPTURE_BATCH_SIZE:-1000}" \
  -capture-flush-interval "${DNS_CAPTURE_FLUSH_INTERVAL:-100ms}" \
  -ch-sampler-addr "${DNS_CH_SAMPLER_ADDR:-127.0.0.1}" \
  -interval "${DNS_INTERVAL:-5s}" \
  -health-interval "${DNS_HEALTH_INTERVAL:-1m}" \
  -health-lag-threshold "${DNS_HEALTH_LAG_THRESHOLD:-100000}"
