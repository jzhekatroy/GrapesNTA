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
  # GRANT может выдать только пользователь с GRANT OPTION.
  # На стенде это CLICKHOUSE_USER (обычно default), а не ui_admin:
  # ui_admin словарь создаёт, но право dictGet раздать не может.
  GRANT_USER="${CLICKHOUSE_USER:-}"
  GRANT_PASS="${CLICKHOUSE_PASSWORD:-}"
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

grant_files=()
schema_files=()
for f in "${files[@]}"; do
  if [[ "$(basename "$f")" == grant_*.sql ]]; then
    grant_files+=("$f")
  else
    schema_files+=("$f")
  fi
done

if [[ ${#schema_files[@]} -gt 0 ]]; then
  bash "${HTTP_APPLY}" --ignore-unknown-table "${schema_files[@]}"
fi

if [[ ${#grant_files[@]} -eq 0 ]]; then
  exit 0
fi

# Пустой CLICKHOUSE_USER значит, что схема и гранты идут одним пользователем.
if [[ -z "${GRANT_USER:-}" ]]; then
  GRANT_USER="${CH_USER}"
  GRANT_PASS="${CH_PASS}"
fi
echo "ensure grants ClickHouse ${CH_URL} as ${GRANT_USER}"
CH_USER="${GRANT_USER}" CH_PASS="${GRANT_PASS}" bash "${HTTP_APPLY}" "${grant_files[@]}"
