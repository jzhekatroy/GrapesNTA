#!/usr/bin/env bash
# Apply universal GrapesNTA ClickHouse schema (flows/XDP/sFlow + DNS + BMP + UI).
# Fresh install target. Requires clickhouse-client or HTTP via CH_URL + curl.
# Dictionary SQL needs envsubst (gettext).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

if ! command -v envsubst >/dev/null 2>&1; then
  echo "envsubst is required (package gettext)" >&2
  exit 1
fi

: "${CH_DICT_HOST:=127.0.0.1}"
: "${CH_DICT_PORT:=9000}"

render_sql() {
  local f="$1"
  if [[ "$f" == *"_dict.sql" ]]; then
    export CH_DICT_HOST CH_DICT_PORT CH_DICT_USER CH_DICT_PASSWORD
    envsubst '${CH_DICT_HOST} ${CH_DICT_PORT} ${CH_DICT_USER} ${CH_DICT_PASSWORD}' < "$f"
  else
    cat "$f"
  fi
}

if [[ -n "${CH_URL:-}" ]]; then
  : "${CH_USER:?set CH_USER}"
  : "${CH_PASS:?set CH_PASS}"
  : "${CH_DICT_USER:=$CH_USER}"
  : "${CH_DICT_PASSWORD:=$CH_PASS}"
  run_sql() {
    local f="$1"
    bash "$ROOT/http_apply.sh" "$f"
  }
else
  : "${CH_HOST:=127.0.0.1}"
  : "${CH_PORT:=9000}"
  : "${CH_USER:=default}"
  : "${CH_DICT_USER:=$CH_USER}"
  : "${CH_DICT_PASSWORD:=${CH_PASS:-}}"
  CH_PASS_ARGS=()
  if [[ -n "${CH_PASS:-}" ]]; then
    CH_PASS_ARGS=(--password "$CH_PASS")
  fi
  run_sql() {
    local f="$1"
    echo "APPLY $f"
    render_sql "$f" | clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" "${CH_PASS_ARGS[@]}" --multiquery
  }
fi

FILTER=("$@")
match_filter() {
  local layer="$1"
  [[ ${#FILTER[@]} -eq 0 ]] && return 0
  local f
  for f in "${FILTER[@]}"; do
    [[ "$layer" == "$f" || "$layer" == *"$f"* ]] && return 0
  done
  return 1
}

shopt -s nullglob
for layer_dir in "$ROOT"/[0-9][0-9]_*/; do
  layer="$(basename "$layer_dir")"
  match_filter "$layer" || continue
  echo "=== layer $layer ==="
  for f in "$layer_dir"*.sql; do
    run_sql "$f"
  done
done

echo "OK: schema apply finished"
