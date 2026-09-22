#!/usr/bin/env bash
# Сравнивает два способа найти клиента по сети, к которой принадлежит адрес:
# перебор правил через arrayFirst и поиск по словарю IP_TRIE.
#
# Проверяет и права: запросы интерфейса идут под урезанным пользователем,
# которому dictGet может быть запрещён, — без этого словарь не годится.
#
# Часть тестовых сетей берётся из живого трафика, чтобы совпадения реально
# находились, остальные добиваются синтетикой до нужного количества: перебор
# должен столкнуться с полным каталогом, как на рабочей установке.
#
#   probe-cabinet-prefix-dict.sh [число_сетей] [минут_окна]
set -euo pipefail

ROOT=${ROOT:-/opt/GrapesNTA}
ENV_FILE=${ENV_FILE:-${ROOT}/deploy/ui/.env}
PREFIXES=${1:-19028}
MINUTES=${2:-25}

get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"''; }

CH_URL=$(get CLICKHOUSE_URL); CH_URL=${CH_URL:-http://127.0.0.1:8123}
ADMIN_USER=$(get CLICKHOUSE_WRITE_USER); ADMIN_USER=${ADMIN_USER:-$(get CLICKHOUSE_USER)}
ADMIN_PASS=$(get CLICKHOUSE_WRITE_PASSWORD); ADMIN_PASS=${ADMIN_PASS:-$(get CLICKHOUSE_PASSWORD)}
READ_USER=$(get CLICKHOUSE_READ_USER); READ_USER=${READ_USER:-$ADMIN_USER}
READ_PASS=$(get CLICKHOUSE_READ_PASSWORD); READ_PASS=${READ_PASS:-$ADMIN_PASS}
FLOWS=$(get CLICKHOUSE_FLOWS_RAW_TABLE); FLOWS=${FLOWS:-flows_raw}
DICT_PORT=${DICT_PORT:-9000}
DICT_HOST=${DICT_HOST:-127.0.0.1}

as_admin() { curl -sS --user "${ADMIN_USER}:${ADMIN_PASS}" "${CH_URL%/}/" --data-binary "$1"; }
as_read()  { curl -sS --user "${READ_USER}:${READ_PASS}"  "${CH_URL%/}/" --data-binary "$1"; }

# Время берём у curl: на сервере может не быть bc, а точности до миллисекунд
# здесь более чем достаточно.
timed_read() { curl -sS -o /dev/null -w '%{time_total}' \
  --user "${READ_USER}:${READ_PASS}" "${CH_URL%/}/" --data-binary "$1"; }

die() { echo "ОШИБКА: $*" >&2; exit 1; }

echo "база ${CH_URL}, таблица ${FLOWS}"
echo "администратор ${ADMIN_USER}, читатель ${READ_USER}"
echo

echo "=== 1. разрешён ли читателю поиск по словарю ==="
probe=$(as_read "SELECT dictGetOrDefault('default.geo_country_dict', 'cc', tuple(toIPv4('8.8.8.8')), '?')" 2>&1)
if echo "$probe" | grep -qi 'ACCESS_DENIED\|Not enough privileges'; then
  echo "  НЕТ: dictGet запрещён пользователю ${READ_USER} — словарь не подойдёт"
  echo "  нужен грант: GRANT dictGet ON default.* TO ${READ_USER}"
  exit 1
fi
echo "  да, разрешён (проверено на geo_country_dict: '${probe}')"
echo

IP16="src_addr"
IS4="length(${IP16}) = 16 AND substring(${IP16}, 5) = unhex('000000000000000000000000')"
IP4="toIPv4(reinterpretAsUInt32(reverse(substring(${IP16}, 1, 4))))"
IPSTR="if(${IS4}, toString(${IP4}), IPv6NumToString(${IP16}))"
WHERE="date >= today() - 1 AND time_received_ns >= now() - INTERVAL ${MINUTES} MINUTE"

echo "=== 2. готовлю ${PREFIXES} тестовых привязок ==="
# Словарь удаляется первым: пока он существует, таблицу-источник удалить нельзя.
as_admin "DROP DICTIONARY IF EXISTS default.probe_prefix_dict" >/dev/null
out=$(as_admin "DROP TABLE IF EXISTS default.probe_prefix_src" 2>&1)
echo "$out" | grep -qi Exception && die "не убрать остатки прошлого прогона: $out"
out=$(as_admin "
CREATE TABLE default.probe_prefix_src (prefix String, client_id String)
ENGINE = MergeTree ORDER BY prefix" 2>&1)
echo "$out" | grep -qi Exception && die "не создать таблицу: $out"

# Реальные /24 из окна: по ним поиск будет находить клиента.
out=$(as_admin "
INSERT INTO default.probe_prefix_src
SELECT prefix, concat('client:', toString(rowNumberInAllBlocks() % 4000)) AS client_id
FROM (
  SELECT DISTINCT concat(IPv4NumToString(bitAnd(toUInt32(${IP4}), 4294967040)), '/24') AS prefix
  FROM default.${FLOWS}
  WHERE ${WHERE} AND (${IS4})
  LIMIT $((PREFIXES / 2))
)" 2>&1)
echo "$out" | grep -qi Exception && die "не наполнить реальными сетями: $out"
real=$(as_admin "SELECT count() FROM default.probe_prefix_src")
echo "  из живого трафика: ${real}"

# Добивка синтетикой в диапазоне 100.64.0.0/10 (он не маршрутизируется в
# интернете, поэтому не пересечётся с реальными сетями и не исказит ответы).
pad=$((PREFIXES - real))
if [ "$pad" -gt 0 ]; then
  out=$(as_admin "
  INSERT INTO default.probe_prefix_src
  SELECT
    concat(IPv4NumToString(toUInt32(1681915904 + number * 256)), '/24') AS prefix,
    concat('client:pad', toString(number % 4000)) AS client_id
  FROM numbers(${pad})" 2>&1)
  echo "$out" | grep -qi Exception && die "не добить синтетикой: $out"
fi
total=$(as_admin "SELECT count() FROM default.probe_prefix_src")
echo "  всего привязок: ${total}"
echo

echo "=== 3. словарь IP_TRIE ==="
as_admin "DROP DICTIONARY IF EXISTS default.probe_prefix_dict" >/dev/null
out=$(as_admin "
CREATE DICTIONARY default.probe_prefix_dict
(
    prefix String,
    client_id String
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(HOST '${DICT_HOST}' PORT ${DICT_PORT} USER '${ADMIN_USER}' PASSWORD '${ADMIN_PASS}' DB 'default' TABLE 'probe_prefix_src'))
LIFETIME(MIN 0 MAX 0)
LAYOUT(IP_TRIE)" 2>&1)
echo "$out" | grep -qi Exception && die "не создать словарь: $out"
# Принудительная перезагрузка требует отдельного гранта, которого у пользователя
# интерфейса нет. Это не помеха: словарь подгружается сам при первом обращении.
out=$(as_admin "SYSTEM RELOAD DICTIONARY default.probe_prefix_dict" 2>&1)
if echo "$out" | grep -qi 'ACCESS_DENIED'; then
  echo "  перезагрузить принудительно нельзя (нет гранта) — грузится при первом обращении"
elif echo "$out" | grep -qi Exception; then
  die "словарь не загрузился: $out"
fi
# Проверяем загрузку не по system.dictionaries (она бывает закрыта), а поиском.
sample=$(as_admin "SELECT prefix FROM default.probe_prefix_src WHERE prefix NOT LIKE '100.%' LIMIT 1")
hit=$(as_read "SELECT dictGetOrDefault('default.probe_prefix_dict', 'client_id', tuple(toIPv4(splitByChar('/', '${sample}')[1])), '<не найдено>')")
echo "  словарь загружен, проверка на ${sample}: ${hit}"
echo

SCAN="nullIf(tupleElement(arrayFirst(x -> isIPAddressInRange(${IPSTR}, x.2), (SELECT groupArray(tuple(client_id, prefix)) FROM default.probe_prefix_src)), 1), '')"
DICT="if(${IS4}, dictGetOrDefault('default.probe_prefix_dict', 'client_id', tuple(${IP4}), ''), dictGetOrDefault('default.probe_prefix_dict', 'client_id', tuple(${IP16}), ''))"

run() { # run <подпись> <выражение>
  local label=$1 expr=$2 sql counts secs
  sql="SELECT count(), countIf(k != '') FROM (
         SELECT ifNull(${expr}, '') AS k FROM default.${FLOWS} WHERE ${WHERE}
       ) FORMAT TSV"
  counts=$(as_read "${sql}" 2>&1)
  if echo "$counts" | grep -qi 'Exception'; then
    printf '  %-20s ОШИБКА: %s\n' "$label" "$(echo "$counts" | head -c 200)"
    return
  fi
  secs=$(timed_read "${sql}")
  printf '  %-20s %8s с    строк %s, клиент найден у %s\n' \
    "$label" "$secs" "$(echo "$counts" | cut -f1)" "$(echo "$counts" | cut -f2)"
}

echo "=== 4. замер на окне ${MINUTES} минут ==="
run "перебор правил" "${SCAN}"
run "поиск по словарю" "${DICT}"
echo

echo "=== 5. совпадают ли ответы ==="
as_read "
SELECT
  countIf(a = b) AS \"совпало\",
  countIf(a != b) AS \"разошлось\",
  countIf(a != '') AS \"перебор нашёл\",
  countIf(b != '') AS \"словарь нашёл\"
FROM (
  SELECT ifNull(${SCAN}, '') AS a, ${DICT} AS b
  FROM default.${FLOWS}
  WHERE ${WHERE}
  LIMIT 2000000
) FORMAT Vertical" 2>&1 | sed 's/^/  /'

echo
echo "=== убираю за собой ==="
as_admin "DROP DICTIONARY IF EXISTS default.probe_prefix_dict" >/dev/null
as_admin "DROP TABLE IF EXISTS default.probe_prefix_src" >/dev/null
echo "  готово"
