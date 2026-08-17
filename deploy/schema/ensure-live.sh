#!/usr/bin/env bash
# Idempotent schema ensure for an already-live ClickHouse.
# Reads credentials from deploy/ui/.env unless CH_URL/CH_USER/CH_PASS are set.
# Files to apply: deploy/schema/ensure.list
set -euo pipefail

SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCHEMA_DIR}/../.." && pwd)"
UI_ENV="${UI_ENV:-${REPO_ROOT}/deploy/ui/.env}"
LIST="${SCHEMA_DIR}/ensure.list"
HTTP_APPLY="${SCHEMA_DIR}/http_apply.sh"

if [[ -z "${CH_URL:-}" || -z "${CH_USER:-}" ]]; then
  [[ -f "${UI_ENV}" ]] || { echo "missing ${UI_ENV} and CH_URL/CH_USER unset" >&2; exit 1; }
  set -a
  # shellcheck disable=SC1090
  . "${UI_ENV}"
  set +a
  CH_URL="${CH_URL:-${CLICKHOUSE_URL:-}}"
  CH_USER="${CH_USER:-${CLICKHOUSE_WRITE_USER:-${CLICKHOUSE_USER:-}}}"
  CH_PASS="${CH_PASS:-${CLICKHOUSE_WRITE_PASSWORD:-${CLICKHOUSE_PASSWORD:-}}}"
fi

export CH_URL CH_USER CH_PASS
[[ -n "${CH_URL}" ]] || { echo "CLICKHOUSE_URL is empty in ${UI_ENV}" >&2; exit 1; }
[[ -n "${CH_USER}" ]] || { echo "CLICKHOUSE user is empty in ${UI_ENV}" >&2; exit 1; }
[[ -f "${LIST}" ]] || { echo "missing ${LIST}" >&2; exit 1; }

echo "ensure-live ClickHouse ${CH_URL} as ${CH_USER}"

files=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -n "$line" ]] || continue
  if [[ "$line" != /* ]]; then
    line="${REPO_ROOT}/${line}"
  fi
  files+=("$line")
done < "${LIST}"

if [[ ${#files[@]} -eq 0 ]]; then
  echo "ensure.list is empty"
  exit 0
fi

exec bash "${HTTP_APPLY}" --ignore-unknown-table "${files[@]}"
