#!/usr/bin/env bash
# client_loadtest.sh — нагрузочный тест клиентских агрегатов на реальном трафике.
#
# Идея: завести тестовых клиентов на реальные /22 своей сети так, чтобы доля
# размеченных строк в flows_raw вышла на заданный процент, и замерить, во что
# это обходится роллапам, витринам и мержам.
#
# Разметка идёт только вперёд: уже лежащие в flows_raw строки не перетегируются.
# Классификатор перечитывает каталог раз в минуту, перезапуск коллектора не нужен.
# После apply нужна выдержка минимум в один полный час, иначе часовые витрины
# посчитаются по недогруженному часу.
#
# Usage (на сервере с ClickHouse, под админским пользователем БД):
#   ./scripts/client_loadtest.sh plan
#   ./scripts/client_loadtest.sh apply 1        # ~25% размеченных строк
#   ./scripts/client_loadtest.sh status
#   ./scripts/client_loadtest.sh snapshot tier1 > /tmp/loadtest-tier1.txt
#   ./scripts/client_loadtest.sh apply 2        # ~50%
#   ./scripts/client_loadtest.sh apply 3        # потолок ~88%
#   ./scripts/client_loadtest.sh cleanup
#
# Переменные окружения:
#   CH_HOST, CH_PORT, CH_USER, CH_PASSWORD, CH_DB — доступ к ClickHouse
#   CH_HTTP_URL — если задан, ходим по HTTP вместо нативного clickhouse-client
#   ENV_FILE — файл с ними же (по умолчанию /etc/grapesnta/traffic-rollups.env)
#   PLAN_WINDOW_MIN — окно для расчёта плана, минут (по умолчанию 10)
#
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/grapesnta/traffic-rollups.env}"
PLAN_WINDOW_MIN="${PLAN_WINDOW_MIN:-10}"
ID_PREFIX="loadtest:"

# Доли от ВСЕХ строк flows_raw. Потолок ~88%: только in/out IPv4 строки имеют
# «свою» сторону, к которой вообще можно привязать клиента.
TIER1_PCT="${TIER1_PCT:-25}"
TIER2_PCT="${TIER2_PCT:-50}"
TIER3_PCT="${TIER3_PCT:-100}"

CLIENT_TABLES=(
  traffic_client_1m
  traffic_client_1h
  traffic_client_1d
  traffic_client_country_1h
  traffic_client_country_1d
  traffic_client_service_1h
  traffic_client_service_1d
  traffic_client_anomaly_1m
  dns_client_domain_1h
)

load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a; . "$ENV_FILE"; set +a
  fi
  CH_HOST="${CH_HOST:-${TRAFFIC_ROLLUP_CH_HOST:-127.0.0.1}}"
  CH_PORT="${CH_PORT:-${TRAFFIC_ROLLUP_CH_PORT:-6124}}"
  CH_USER="${CH_USER:-${TRAFFIC_ROLLUP_CH_USER:-develop}}"
  CH_PASSWORD="${CH_PASSWORD:-${TRAFFIC_ROLLUP_CH_PASSWORD:-}}"
  CH_DB="${CH_DB:-${TRAFFIC_ROLLUP_CH_DATABASE:-default}}"
}

# Нативный клиент есть не на каждом хосте, поэтому при заданном CH_HTTP_URL
# ходим по HTTP. Формат ответа задаётся самим запросом через FORMAT.
chq() {
  if [[ -n "${CH_HTTP_URL:-}" ]]; then
    local out
    out="$(curl -sS --fail-with-body --max-time "${CH_HTTP_TIMEOUT:-600}" \
      "${CH_HTTP_URL}/?database=${CH_DB}&default_format=PrettyCompactMonoBlock" \
      -H "X-ClickHouse-User: ${CH_USER}" \
      -H "X-ClickHouse-Key: ${CH_PASSWORD}" \
      --data-binary "$1")" || { echo "$out" >&2; return 1; }
    [[ -n "$out" ]] && printf '%s\n' "$out"
    return 0
  fi
  local args=(--host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" --database "$CH_DB")
  [[ -n "$CH_PASSWORD" ]] && args+=(--password "$CH_PASSWORD")
  clickhouse-client "${args[@]}" --query "$1"
}

# Снимок метрик лезет в system.query_log и system.part_log, а у роллапного
# пользователя доступа к ним может не быть. Такая дырка в снимке не повод
# ронять весь замер.
chq_soft() {
  if ! chq "$1" 2>&1; then
    echo "  (недоступно)"
  fi
}

# Окно расчёта: последние PLAN_WINDOW_MIN полных минут.
window_sql() {
  cat <<SQL
toStartOfMinute(now('UTC')) - INTERVAL ${PLAN_WINDOW_MIN} MINUTE AS t0,
toStartOfMinute(now('UTC')) AS t1
SQL
}

# Своя сторона потока: для 'out' это источник, для 'in' — получатель.
own_ip_sql() {
  cat <<'SQL'
if(direction = 'out',
   toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))),
   toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
SQL
}

# Сети /22 с накопительной долей от всех строк flows_raw в окне.
# Публичные адреса: RFC1918 в клиенты не отдаём, они дают шум без нагрузки.
nets_cte() {
  cat <<SQL
WITH $(window_sql)
SELECT
    net22,
    rows,
    round(100 * sum(rows) OVER (ORDER BY rows DESC, net22 ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
          / (SELECT count() FROM ${CH_DB}.flows_raw WHERE time_received_ns >= t0 AND time_received_ns < t1), 2) AS cum_pct_total
FROM (
    SELECT
        concat(toString(IPv4CIDRToRange(own_ip, 22).1), '/22') AS net22,
        count() AS rows
    FROM (
        SELECT $(own_ip_sql) AS own_ip
        FROM ${CH_DB}.flows_raw
        WHERE time_received_ns >= t0 AND time_received_ns < t1
          AND etype = 2048
          AND direction IN ('in', 'out')
    )
    WHERE NOT isIPAddressInRange(toString(own_ip), '10.0.0.0/8')
      AND NOT isIPAddressInRange(toString(own_ip), '172.16.0.0/12')
      AND NOT isIPAddressInRange(toString(own_ip), '192.168.0.0/16')
      AND NOT isIPAddressInRange(toString(own_ip), '100.64.0.0/10')
      AND NOT isIPAddressInRange(toString(own_ip), '169.254.0.0/16')
    GROUP BY net22
)
ORDER BY rows DESC, net22
SQL
}

tier_pct() {
  case "$1" in
    1) echo "$TIER1_PCT" ;;
    2) echo "$TIER2_PCT" ;;
    3) echo "$TIER3_PCT" ;;
    *) echo "unknown tier: $1" >&2; exit 1 ;;
  esac
}

cmd_plan() {
  echo "== окно расчёта: последние ${PLAN_WINDOW_MIN} мин, границы тиров в % от всех строк flows_raw"
  echo
  chq "$(cat <<SQL
SELECT
    multiIf(cum_pct_total <= ${TIER1_PCT}, 1,
            cum_pct_total <= ${TIER2_PCT}, 2, 3) AS tier,
    count() AS clients,
    max(cum_pct_total) AS coverage_pct_total
FROM ($(nets_cte))
GROUP BY tier
ORDER BY tier
FORMAT PrettyCompactMonoBlock
SQL
)"
  echo
  echo "== сети по тирам"
  chq "$(cat <<SQL
SELECT
    multiIf(cum_pct_total <= ${TIER1_PCT}, 1,
            cum_pct_total <= ${TIER2_PCT}, 2, 3) AS tier,
    net22,
    rows,
    cum_pct_total
FROM ($(nets_cte))
FORMAT PrettyCompactMonoBlock
SQL
)"
}

cmd_apply() {
  local tier="${1:-}"
  [[ -n "$tier" ]] || { echo "usage: $0 apply <1|2|3>" >&2; exit 1; }
  local pct; pct="$(tier_pct "$tier")"

  echo "== завожу клиентов до tier ${tier} (<= ${pct}% размеченных строк)"

  # Тиры кумулятивные: apply 2 добавляет к тому, что создал apply 1.
  # ReplacingMergeTree по client_id / (family, prefix) — повторный apply безвреден.
  chq "$(cat <<SQL
INSERT INTO ${CH_DB}.net_clients (client_id, display_name, comment, bind_mode, enabled, updated_at)
SELECT
    concat('${ID_PREFIX}', replaceAll(replaceAll(net22, '.', '-'), '/', '-')) AS client_id,
    net22 AS display_name,
    'loadtest tier ${tier}' AS comment,
    'prefixes' AS bind_mode,
    1 AS enabled,
    now() AS updated_at
FROM ($(nets_cte))
WHERE cum_pct_total <= ${pct}
  AND net22 NOT IN (SELECT prefix FROM ${CH_DB}.net_client_prefixes)
SQL
)"

  # net_client_prefixes сортируется по (family, prefix), то есть владелец префикса
  # перезаписывается по ключу. Уже занятые боевыми клиентами префиксы пропускаем.
  chq "$(cat <<SQL
INSERT INTO ${CH_DB}.net_client_prefixes (client_id, prefix, family, enabled, updated_at)
SELECT
    concat('${ID_PREFIX}', replaceAll(replaceAll(net22, '.', '-'), '/', '-')) AS client_id,
    net22 AS prefix,
    4 AS family,
    1 AS enabled,
    now() AS updated_at
FROM ($(nets_cte))
WHERE cum_pct_total <= ${pct}
  AND net22 NOT IN (SELECT prefix FROM ${CH_DB}.net_client_prefixes)
SQL
)"

  echo "готово. классификатор подхватит каталог в течение минуты."
  cmd_status
}

cmd_status() {
  echo
  echo "== каталог тестовых клиентов"
  chq "SELECT count() AS clients FROM ${CH_DB}.net_clients_enabled WHERE client_id LIKE '${ID_PREFIX}%' FORMAT PrettyCompactMonoBlock"
  chq "SELECT count() AS prefixes FROM ${CH_DB}.net_client_prefixes_enabled WHERE client_id LIKE '${ID_PREFIX}%' FORMAT PrettyCompactMonoBlock"

  echo "== фактическая доля размеченных строк за последнюю полную минуту"
  chq "$(cat <<SQL
SELECT
    toStartOfMinute(now('UTC')) - INTERVAL 1 MINUTE AS minute,
    count() AS rows,
    countIf(src_client != '' OR dst_client != '') AS tagged,
    round(100 * countIf(src_client != '' OR dst_client != '') / count(), 2) AS tagged_pct,
    round(100 * countIf((src_client LIKE '${ID_PREFIX}%') OR (dst_client LIKE '${ID_PREFIX}%')) / count(), 2) AS loadtest_pct
FROM ${CH_DB}.flows_raw
WHERE time_received_ns >= toStartOfMinute(now('UTC')) - INTERVAL 1 MINUTE
  AND time_received_ns < toStartOfMinute(now('UTC'))
FORMAT PrettyCompactMonoBlock
SQL
)"
}

cmd_snapshot() {
  local label="${1:-snapshot}"
  local since_min="${SNAPSHOT_WINDOW_MIN:-30}"
  echo "############ snapshot: ${label} @ $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
  echo "############ окно метрик: последние ${since_min} мин"

  cmd_status

  echo
  echo "== состояние джобов роллапов"
  chq "$(cat <<SQL
SELECT job, last_bucket, status, rows_written, duration_ms, updated_at
FROM ${CH_DB}.traffic_rollup_state
WHERE job LIKE '%client%' OR job LIKE '%dns%'
ORDER BY job
FORMAT PrettyCompactMonoBlock
SQL
)"

  echo "== стоимость запросов роллапов (system.query_log)"
  # Роллап пишет 'INSERT INTO <db>.<table>\nSELECT ...', поэтому цель определяем
  # по началу запроса, а не регуляркой по всему тексту.
  chq_soft "$(cat <<SQL
SELECT
    arrayFirst(t -> startsWith(query, concat('INSERT INTO ${CH_DB}.', t)),
               [$(printf "'%s'," "${CLIENT_TABLES[@]}" | sed 's/,$//')]) AS target,
    count() AS runs,
    round(avg(query_duration_ms)) AS avg_ms,
    max(query_duration_ms) AS max_ms,
    formatReadableQuantity(avg(read_rows)) AS avg_read_rows,
    formatReadableSize(avg(read_bytes)) AS avg_read_bytes,
    formatReadableSize(max(memory_usage)) AS max_mem
FROM system.query_log
WHERE type = 'QueryFinish'
  AND event_time >= now() - INTERVAL ${since_min} MINUTE
  AND startsWith(query, 'INSERT INTO ${CH_DB}.')
GROUP BY target
HAVING target != ''
ORDER BY avg_ms DESC
FORMAT PrettyCompactMonoBlock
SQL
)"

  echo "== запросы, обрезанные лимитом чтения (read_overflow_mode)"
  chq_soft "$(cat <<SQL
SELECT count() AS truncated_queries
FROM system.query_log
WHERE type = 'QueryFinish'
  AND event_time >= now() - INTERVAL ${since_min} MINUTE
  AND startsWith(query, 'INSERT INTO ${CH_DB}.')
  AND read_rows >= 100000000
FORMAT PrettyCompactMonoBlock
SQL
)"

  echo "== размер клиентских таблиц"
  chq_soft "$(cat <<SQL
SELECT
    table,
    sum(rows) AS rows,
    formatReadableSize(sum(bytes_on_disk)) AS on_disk,
    count() AS parts
FROM system.parts
WHERE active AND database = '${CH_DB}' AND table IN ($(printf "'%s'," "${CLIENT_TABLES[@]}" | sed 's/,$//'))
GROUP BY table
ORDER BY table
FORMAT PrettyCompactMonoBlock
SQL
)"

  echo "== строк в витринах за последний полный час"
  chq "$(cat <<SQL
SELECT 'traffic_client_1h' AS vitrine, count() AS rows, uniqExact(client_id) AS clients
FROM ${CH_DB}.traffic_client_1h WHERE hour = toStartOfHour(now('UTC')) - INTERVAL 1 HOUR
UNION ALL
SELECT 'traffic_client_country_1h', count(), uniqExact(client_id)
FROM ${CH_DB}.traffic_client_country_1h WHERE hour = toStartOfHour(now('UTC')) - INTERVAL 1 HOUR
UNION ALL
SELECT 'traffic_client_service_1h', count(), uniqExact(client_id)
FROM ${CH_DB}.traffic_client_service_1h WHERE hour = toStartOfHour(now('UTC')) - INTERVAL 1 HOUR
UNION ALL
SELECT 'dns_client_domain_1h', count(), uniqExact(client_id)
FROM ${CH_DB}.dns_client_domain_1h WHERE hour = toStartOfHour(now('UTC')) - INTERVAL 1 HOUR
UNION ALL
SELECT 'traffic_client_1m', count(), uniqExact(client_id)
FROM ${CH_DB}.traffic_client_1m WHERE minute >= now('UTC') - INTERVAL 5 MINUTE
UNION ALL
SELECT 'traffic_client_anomaly_1m', count(), uniqExact(client_id)
FROM ${CH_DB}.traffic_client_anomaly_1m WHERE minute >= now('UTC') - INTERVAL 5 MINUTE
FORMAT PrettyCompactMonoBlock
SQL
)"

  echo "== мержи клиентских таблиц"
  chq_soft "$(cat <<SQL
SELECT
    table,
    count() AS merges,
    round(avg(duration_ms)) AS avg_ms,
    formatReadableSize(sum(read_bytes)) AS read_total
FROM system.part_log
WHERE event_type = 'MergeParts'
  AND event_time >= now() - INTERVAL ${since_min} MINUTE
  AND database = '${CH_DB}'
  AND table IN ($(printf "'%s'," "${CLIENT_TABLES[@]}" | sed 's/,$//'))
GROUP BY table
ORDER BY merges DESC
FORMAT PrettyCompactMonoBlock
SQL
)"

  echo "== разметка в dns_log за последнюю полную минуту"
  chq "$(cat <<SQL
SELECT
    count() AS rows,
    countIf(client_id != '') AS tagged,
    round(100 * countIf(client_id != '') / count(), 2) AS tagged_pct
FROM ${CH_DB}.dns_log
WHERE ts >= toStartOfMinute(now('UTC')) - INTERVAL 1 MINUTE
  AND ts < toStartOfMinute(now('UTC'))
FORMAT PrettyCompactMonoBlock
SQL
)"
}

cmd_cleanup() {
  echo "== убираю тестовых клиентов из каталога (коллектор перестанет метить в течение минуты)"
  chq "ALTER TABLE ${CH_DB}.net_clients DELETE WHERE client_id LIKE '${ID_PREFIX}%' SETTINGS mutations_sync = 2"
  chq "ALTER TABLE ${CH_DB}.net_client_prefixes DELETE WHERE client_id LIKE '${ID_PREFIX}%' SETTINGS mutations_sync = 2"

  echo "== жду 90 секунд, чтобы классификатор перечитал каталог"
  sleep 90

  echo "== чищу строки витрин"
  for t in "${CLIENT_TABLES[@]}"; do
    echo "  -> ${t}"
    chq "ALTER TABLE ${CH_DB}.${t} DELETE WHERE client_id LIKE '${ID_PREFIX}%' SETTINGS mutations_sync = 2"
  done

  echo "== проверка: не осталось ли следов"
  chq "$(cat <<SQL
SELECT 'net_clients' AS src, count() AS rows FROM ${CH_DB}.net_clients WHERE client_id LIKE '${ID_PREFIX}%'
UNION ALL
SELECT 'net_client_prefixes', count() FROM ${CH_DB}.net_client_prefixes WHERE client_id LIKE '${ID_PREFIX}%'
$(for t in "${CLIENT_TABLES[@]}"; do printf "UNION ALL SELECT '%s', count() FROM %s.%s WHERE client_id LIKE '%s%%'\n" "$t" "$CH_DB" "$t" "$ID_PREFIX"; done)
FORMAT PrettyCompactMonoBlock
SQL
)"

  cat <<'NOTE'

Метки в flows_raw и dns_log остаются в колонках до истечения TTL (6 и 30 дней).
Переписывать их мутацией на таблицах такого размера дороже самого теста, а на
выдачу это не влияет: витрины вычищены, клиентов в каталоге нет.
NOTE
}

main() {
  load_env
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    plan)     cmd_plan "$@" ;;
    apply)    cmd_apply "$@" ;;
    status)   cmd_status "$@" ;;
    snapshot) cmd_snapshot "$@" ;;
    cleanup)  cmd_cleanup "$@" ;;
    *)
      sed -n '2,30p' "$0"
      exit 1
      ;;
  esac
}

main "$@"
