#!/usr/bin/env bash
# Apply one or more SQL files to ClickHouse over HTTP, one statement per request.
#
# Required env: CH_URL, CH_USER, CH_PASS
# Usage:
#   ./deploy/schema/http_apply.sh file.sql [file.sql ...]
#   ./deploy/schema/http_apply.sh --ignore-unknown-table file.sql
set -euo pipefail

SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPLIT="${SCHEMA_DIR}/split_sql.py"
IGNORE_UNKNOWN_TABLE=0

if [[ "${1:-}" == "--ignore-unknown-table" ]]; then
  IGNORE_UNKNOWN_TABLE=1
  shift
fi

[[ $# -ge 1 ]] || { echo "usage: $0 [--ignore-unknown-table] file.sql ..." >&2; exit 1; }
[[ -n "${CH_URL:-}" ]] || { echo "set CH_URL" >&2; exit 1; }
[[ -n "${CH_USER:-}" ]] || { echo "set CH_USER" >&2; exit 1; }
: "${CH_PASS:=}"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

render_sql() {
  local f="$1"
  if [[ "$f" == *"_dict.sql" ]]; then
    : "${CH_DICT_HOST:=127.0.0.1}"
    : "${CH_DICT_PORT:=9000}"
    : "${CH_DICT_USER:=$CH_USER}"
    : "${CH_DICT_PASSWORD:=$CH_PASS}"
    export CH_DICT_HOST CH_DICT_PORT CH_DICT_USER CH_DICT_PASSWORD
    envsubst '${CH_DICT_HOST} ${CH_DICT_PORT} ${CH_DICT_USER} ${CH_DICT_PASSWORD}' < "$f"
  else
    cat "$f"
  fi
}

post_stmt() {
  local file="$1"
  local body http code text
  body="$(mktemp)"
  http="$(mktemp)"
  if ! curl -sS -o "$body" -w '%{http_code}' --user "${CH_USER}:${CH_PASS}" \
    "${CH_URL%/}/" --data-binary @"$file" >"$http"; then
    echo "curl failed for ${file}" >&2
    cat "$body" >&2 || true
    rm -f "$body" "$http"
    return 1
  fi
  code="$(cat "$http")"
  text="$(cat "$body")"
  rm -f "$body" "$http"
  if [[ "$code" == "200" ]]; then
    return 0
  fi
  if [[ "${IGNORE_UNKNOWN_TABLE}" -eq 1 ]] && echo "$text" | grep -q 'UNKNOWN_TABLE'; then
    echo "skip (unknown table): ${text}" >&2
    return 0
  fi
  echo "${text}" >&2
  echo "HTTP ${code}" >&2
  return 1
}

for src in "$@"; do
  [[ -f "$src" ]] || { echo "missing $src" >&2; exit 1; }
  echo "APPLY $src"
  tmp="$(mktemp -d)"
  render_sql "$src" | python3 "$SPLIT" --dir "$tmp"
  shopt -s nullglob
  stmts=("$tmp"/*.sql)
  if [[ ${#stmts[@]} -eq 0 ]]; then
    echo "  (no statements)"
    rm -rf "$tmp"
    continue
  fi
  idx=0
  for stmt in "${stmts[@]}"; do
    idx=$((idx + 1))
    echo "  stmt ${idx}/${#stmts[@]}"
    post_stmt "$stmt"
  done
  rm -rf "$tmp"
done
