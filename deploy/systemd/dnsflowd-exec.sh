#!/usr/bin/env bash
# Wrapper: load /etc/dnsflowd/dnsflowd.env and exec dnsflowd.

set -euo pipefail

ENV_FILE="${DNSFLOWD_ENV_FILE:-/etc/dnsflowd/dnsflowd.env}"
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
IFACE="${IFACE:-enp5s0d1}"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: dnsflowd binary not executable: $BIN" >&2
  exit 1
fi
if [[ -z "${DNS_CH_DSN:-}" || -z "${DNS_CH_TABLE:-}" ]]; then
  echo "ERROR: DNS_CH_DSN and DNS_CH_TABLE must be set in $ENV_FILE" >&2
  exit 1
fi

STDBUF=()
if command -v stdbuf >/dev/null 2>&1; then
  STDBUF=( stdbuf -oL -eL )
fi

exec "${STDBUF[@]}" "$BIN" \
  -iface "$IFACE" \
  -ch-dsn "$DNS_CH_DSN" \
  -ch-table "$DNS_CH_TABLE" \
  -ch-batch-size "${DNS_CH_BATCH_SIZE:-500}" \
  -ch-flush-interval "${DNS_CH_FLUSH_INTERVAL:-1s}" \
  -ch-queue-size "${DNS_CH_QUEUE_SIZE:-64}" \
  -ch-sampler-addr "${DNS_CH_SAMPLER_ADDR:-127.0.0.1}" \
  -interval "${DNS_INTERVAL:-5s}"
