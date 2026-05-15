#!/usr/bin/env bash
# Wrapper: load /etc/bmpgrapes/bmpgrapes.env and exec bmpgrapes.

set -euo pipefail

ENV_FILE="${BMPGRAPES_ENV_FILE:-/etc/bmpgrapes/bmpgrapes.env}"
if [[ ! -r "$ENV_FILE" ]]; then
  echo "ERROR: env file not readable: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

REPO_ROOT="${REPO_ROOT:-/opt/GrapesNTA}"
BIN="${BMPGRAPES_BIN:-$REPO_ROOT/bin/bmpgrapes}"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: bmpgrapes binary not executable: $BIN" >&2
  exit 1
fi
if [[ -z "${BMP_CH_DSN:-}" ]]; then
  echo "ERROR: BMP_CH_DSN must be set in $ENV_FILE" >&2
  exit 1
fi

STDBUF=()
if command -v stdbuf >/dev/null 2>&1; then
  STDBUF=( stdbuf -oL -eL )
fi

exec "${STDBUF[@]}" "$BIN" \
  -listen "${BMP_LISTEN:-0.0.0.0:5000}" \
  -ch-dsn "$BMP_CH_DSN" \
  -ch-events-table "${BMP_CH_EVENTS_TABLE:-default.bmp_route_events}" \
  -ch-peers-table "${BMP_CH_PEERS_TABLE:-default.bmp_peers}" \
  -ch-batch-size "${BMP_CH_BATCH_SIZE:-1000}" \
  -ch-flush-interval "${BMP_CH_FLUSH_INTERVAL:-1s}" \
  -ch-queue-size "${BMP_CH_QUEUE_SIZE:-4096}" \
  -ch-queue-mode "${BMP_CH_QUEUE_MODE:-block}" \
  -allow-routers "${BMP_ALLOW_ROUTERS:-}" \
  -max-message-bytes "${BMP_MAX_MESSAGE_BYTES:-65535}" \
  -interval "${BMP_INTERVAL:-10s}" \
  -log-level "${BMP_LOG_LEVEL:-info}" \
  -log-format "${BMP_LOG_FORMAT:-text}" \
  -log-update-samples "${BMP_LOG_UPDATE_SAMPLES:-10}"
