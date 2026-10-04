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

# ui_admin словарь создаёт, но dictGet раздать не может (нет GRANT OPTION).
# Ищем пользователя вроде default: сначала CLICKHOUSE_USER, потом учётки
# загрузчиков, которые на стенде как раз от администратора базы.
env_value() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 0
  bash -c 'set +u; set -a; . "$1" >/dev/null 2>&1; set +a; printf %s "${!2-}"' bash "$file" "$key" 2>/dev/null || true
}

try_grant() {
  local user="$1" pass="$2" from="$3"
  [[ -n "$user" ]] || return 1
  case "$user" in
    ui_admin|ui_read|collector_write) return 1 ;;
  esac
  local mark="${user}@${from}"
  case " ${tried_grants} " in
    *" ${mark} "*) return 1 ;;
  esac
  tried_grants="${tried_grants} ${mark}"
  echo "ensure grants ClickHouse ${CH_URL} as ${user} (${from})"
  if CH_USER="$user" CH_PASS="$pass" bash "${HTTP_APPLY}" "${grant_files[@]}"; then
    return 0
  fi
  echo "grant as ${user} failed" >&2
  return 1
}

tried_grants=""
granted=0
if try_grant "${GRANT_USER:-}" "${GRANT_PASS:-}" "deploy/ui/.env"; then
  granted=1
fi
if [[ "$granted" -eq 0 ]]; then
  enrich_env="${REPO_ROOT}/deploy/enrichment/.env"
  worker_env="${REPO_ROOT}/deploy/worker/.env"
  legacy_env="${REPO_ROOT}/../grapes/ui/.env"
  [[ -f /opt/grapes/ui/.env ]] && legacy_env=/opt/grapes/ui/.env
  for spec in \
    "${enrich_env}|GEOLOADERD_CH_USER|GEOLOADERD_CH_PASSWORD" \
    "${enrich_env}|SNMP_SYNC_CH_USER|SNMP_SYNC_CH_PASSWORD" \
    "${enrich_env}|BGPORIGIN_DICT_SOURCE_USER|BGPORIGIN_DICT_SOURCE_PASSWORD" \
    "${worker_env}|CLICKHOUSE_USER|CLICKHOUSE_PASSWORD" \
    "${legacy_env}|CLICKHOUSE_USER|CLICKHOUSE_PASSWORD"
  do
    file="${spec%%|*}"
    rest="${spec#*|}"
    ukey="${rest%%|*}"
    pkey="${rest#*|}"
    if try_grant "$(env_value "$file" "$ukey")" "$(env_value "$file" "$pkey")" "$file"; then
      granted=1
      break
    fi
  done
fi
if [[ "$granted" -eq 0 ]] && command -v clickhouse-client >/dev/null 2>&1; then
  echo "ensure grants via local clickhouse-client as default"
  if clickhouse-client --user default --multiquery < <(cat "${grant_files[@]}"); then
    granted=1
  else
    echo "grant via clickhouse-client failed" >&2
  fi
fi
dictget_works() {
  local user="$1" pass="$2"
  [[ -n "$user" ]] || return 1
  local body http code
  body="$(mktemp)"
  http="$(mktemp)"
  if ! curl -sS -o "$body" -w '%{http_code}' --user "${user}:${pass}" \
    "${CH_URL%/}/" \
    --data-binary "SELECT dictGetOrDefault('default.net_isp_prefix_dict', 'entity_id', tuple(toIPv4('176.123.128.10')), '')" >"$http"; then
    rm -f "$body" "$http"
    return 1
  fi
  code="$(cat "$http")"
  rm -f "$body" "$http"
  [[ "$code" == "200" ]]
}

if [[ "$granted" -eq 0 ]]; then
  read_user="${CLICKHOUSE_READ_USER:-}"
  read_pass="${CLICKHOUSE_READ_PASSWORD:-}"
  if [[ -z "$read_user" ]]; then
    read_user="$(env_value "${UI_ENV}" CLICKHOUSE_READ_USER)"
    read_pass="$(env_value "${UI_ENV}" CLICKHOUSE_READ_PASSWORD)"
  fi
  if dictget_works "$read_user" "$read_pass"; then
    echo "ensure grants: ${read_user} уже читает словарь провайдеров, GRANT повторно не нужен"
    granted=1
  fi
fi
if [[ "$granted" -eq 0 ]]; then
  echo "ERROR: грант dictGet не выдан. ui_admin не может раздавать права, а другой пользователь базы в deploy/ui/.env не задан (нужен CLICKHOUSE_USER=default)." >&2
  exit 1
fi
