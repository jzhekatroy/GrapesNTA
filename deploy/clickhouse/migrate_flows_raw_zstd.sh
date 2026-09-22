#!/usr/bin/env bash
# Перевести уже существующую default.flows_raw на ZSTD.
# Чистая установка этого скрипта не требует: apply.sh создаёт таблицу сразу с ZSTD.
#
# Берёт доступ из deploy/ui/.env (CLICKHOUSE_URL и пользователь записи),
# поэтому работает и когда ClickHouse на другой машине.
#
#   cd /opt/GrapesNTA && ./deploy/clickhouse/migrate_flows_raw_zstd.sh
#
# Команда возвращается сразу. Уже лежащие куски переписываются в фоне.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SQL="${ROOT}/deploy/clickhouse/migrate_flows_raw_zstd.sql"
UI_ENV="${UI_ENV:-${ROOT}/deploy/ui/.env}"

if [[ -z "${CH_URL:-}" || -z "${CH_USER:-}" ]]; then
  [[ -f "${UI_ENV}" ]] || { echo "нет ${UI_ENV} и не заданы CH_URL/CH_USER" >&2; exit 1; }
  set -a
  # shellcheck disable=SC1090
  . "${UI_ENV}"
  set +a
  CH_URL="${CH_URL:-${CLICKHOUSE_URL:-}}"
  CH_USER="${CH_USER:-${CLICKHOUSE_WRITE_USER:-${CLICKHOUSE_USER:-}}}"
  CH_PASS="${CH_PASS:-${CLICKHOUSE_WRITE_PASSWORD:-${CLICKHOUSE_PASSWORD:-}}}"
fi

[[ -n "${CH_URL}" ]] || { echo "CLICKHOUSE_URL пуст" >&2; exit 1; }
[[ -n "${CH_USER}" ]] || { echo "пользователь ClickHouse пуст" >&2; exit 1; }
[[ -f "${SQL}" ]] || { echo "нет ${SQL}" >&2; exit 1; }

ch_query() {
  curl -sS --fail-with-body --max-time 60 \
    --user "${CH_USER}:${CH_PASS}" \
    "${CH_URL%/}/?database=default" \
    --data-binary "$1"
}

engine="$(ch_query "SELECT engine FROM system.tables WHERE database='default' AND name='flows_raw' FORMAT TSVRaw")"
if [[ -z "${engine}" ]]; then
  echo "таблицы default.flows_raw нет: на чистой базе её создаст ./deploy/schema/apply.sh" >&2
  exit 1
fi
if [[ "${engine}" != "MergeTree" ]]; then
  echo "default.flows_raw имеет движок ${engine}, ждали MergeTree. Обёртку flows_all не пережимаем." >&2
  exit 1
fi

pending="$(ch_query "
SELECT count()
FROM system.columns
WHERE database = 'default'
  AND table = 'flows_raw'
  AND name IN ('src_addr', 'dst_addr', 'bytes', 'time_received_ns')
  AND compression_codec NOT LIKE '%ZSTD%'
FORMAT TSVRaw
")"

if [[ "${pending}" == "0" ]]; then
  echo "flows_raw уже на ZSTD, переписывать нечего"
  exit 0
fi

echo "переключаю упаковку flows_raw на ZSTD, колонок без ZSTD среди проверяемых: ${pending}"
curl -sS --fail-with-body --max-time 120 \
  --user "${CH_USER}:${CH_PASS}" \
  "${CH_URL%/}/?database=default&mutations_sync=0" \
  --data-binary @"${SQL}"
echo
echo "команда принята. старые куски переписываются в фоне, новые записи уже идут в ZSTD."
echo "проверка:"
echo "  SELECT is_done, parts_to_do, latest_fail_reason FROM system.mutations WHERE database='default' AND table='flows_raw' AND is_done=0"
