#!/usr/bin/env bash
# Сверяет, что поиск клиента по словарю IP_TRIE отвечает так же, как прежний
# перебор правил, и показывает единственное место, где ответы расходятся: сети,
# вложенные друг в друга.
#
# Перебор возвращает первую подходящую сеть в порядке каталога, словарь — самую
# точную. Для непересекающихся сетей это одно и то же; для вложенных словарь
# отдаёт более конкретную привязку, и такой ответ устойчив, тогда как у перебора
# он зависит от порядка строк в каталоге.
#
# Данные синтетические, сырой журнал не нужен.
set -euo pipefail

ROOT=${ROOT:-/opt/GrapesNTA}
ENV_FILE=${ENV_FILE:-${ROOT}/deploy/ui/.env}

get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"''; }
CH_URL=$(get CLICKHOUSE_URL); CH_URL=${CH_URL:-http://127.0.0.1:8123}
ADMIN_USER=$(get CLICKHOUSE_WRITE_USER); ADMIN_USER=${ADMIN_USER:-$(get CLICKHOUSE_USER)}
ADMIN_PASS=$(get CLICKHOUSE_WRITE_PASSWORD); ADMIN_PASS=${ADMIN_PASS:-$(get CLICKHOUSE_PASSWORD)}
DICT_HOST=${DICT_HOST:-127.0.0.1}
DICT_PORT=${DICT_PORT:-9000}

ch() { curl -sS --user "${ADMIN_USER}:${ADMIN_PASS}" "${CH_URL%/}/" --data-binary "$1"; }
die() { echo "ОШИБКА: $*" >&2; exit 1; }

echo "база ${CH_URL} как ${ADMIN_USER}"
echo

ch "DROP DICTIONARY IF EXISTS default.probe_sem_dict" >/dev/null
out=$(ch "DROP TABLE IF EXISTS default.probe_sem_src" 2>&1)
echo "$out" | grep -qi Exception && die "не убрать остатки: $out"

out=$(ch "
CREATE TABLE default.probe_sem_src (prefix String, client_id String)
ENGINE = MergeTree ORDER BY prefix" 2>&1)
echo "$out" | grep -qi Exception && die "не создать таблицу: $out"

# Каталог намеренно содержит и вложенные сети, и IPv6, и сеть-одиночку.
out=$(ch "
INSERT INTO default.probe_sem_src VALUES
  ('10.0.0.0/8', 'client:wide'),
  ('10.1.2.0/24', 'client:narrow'),
  ('203.0.113.0/24', 'client:plain'),
  ('2001:db8::/32', 'client:v6wide'),
  ('2001:db8:dead::/48', 'client:v6narrow')" 2>&1)
echo "$out" | grep -qi Exception && die "не наполнить: $out"

out=$(ch "
CREATE DICTIONARY default.probe_sem_dict (prefix String, client_id String)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(HOST '${DICT_HOST}' PORT ${DICT_PORT} USER '${ADMIN_USER}' PASSWORD '${ADMIN_PASS}' DB 'default' TABLE 'probe_sem_src'))
LIFETIME(MIN 0 MAX 0)
LAYOUT(IP_TRIE)" 2>&1)
echo "$out" | grep -qi Exception && die "не создать словарь: $out"

echo "=== IPv4: словарь против перебора ==="
ch "
WITH
  (SELECT groupArray(tuple(client_id, prefix)) FROM default.probe_sem_src) AS rules,
  ['10.1.2.5', '10.9.9.9', '203.0.113.7', '8.8.8.8'] AS probes
SELECT
  ip AS \"адрес\",
  ifNull(nullIf(tupleElement(arrayFirst(x -> isIPAddressInRange(ip, x.2), rules), 1), ''), '—') AS \"перебор\",
  dictGetOrDefault('default.probe_sem_dict', 'client_id', tuple(toIPv4(ip)), '—') AS \"словарь\"
FROM (SELECT arrayJoin(probes) AS ip)
FORMAT PrettyCompactMonoBlock" 2>&1 | sed 's/^/  /'

echo
echo "=== IPv6: словарь против перебора ==="
ch "
WITH
  (SELECT groupArray(tuple(client_id, prefix)) FROM default.probe_sem_src) AS rules,
  ['2001:db8:dead::1', '2001:db8:beef::1', '2600::1'] AS probes
SELECT
  ip AS \"адрес\",
  ifNull(nullIf(tupleElement(arrayFirst(x -> isIPAddressInRange(ip, x.2), rules), 1), ''), '—') AS \"перебор\",
  dictGetOrDefault('default.probe_sem_dict', 'client_id', tuple(toIPv6(ip)), '—') AS \"словарь\"
FROM (SELECT arrayJoin(probes) AS ip)
FORMAT PrettyCompactMonoBlock" 2>&1 | sed 's/^/  /'

echo
echo "=== порядок каталога меняет ответ перебора, но не словаря ==="
# Тот же адрес, тот же каталог, но правила перечислены в обратном порядке.
ch "
WITH
  (SELECT groupArray(tuple(client_id, prefix)) FROM (SELECT * FROM default.probe_sem_src ORDER BY prefix ASC)) AS asc_rules,
  (SELECT groupArray(tuple(client_id, prefix)) FROM (SELECT * FROM default.probe_sem_src ORDER BY prefix DESC)) AS desc_rules
SELECT
  '10.1.2.5' AS \"адрес\",
  tupleElement(arrayFirst(x -> isIPAddressInRange('10.1.2.5', x.2), asc_rules), 1) AS \"перебор по возрастанию\",
  tupleElement(arrayFirst(x -> isIPAddressInRange('10.1.2.5', x.2), desc_rules), 1) AS \"перебор по убыванию\",
  dictGetOrDefault('default.probe_sem_dict', 'client_id', tuple(toIPv4('10.1.2.5')), '—') AS \"словарь\"
FORMAT Vertical" 2>&1 | sed 's/^/  /'

echo
echo "=== адрес из потока: 16 байт, IPv4 в первых четырёх ==="
# Так адреса лежат в сыром журнале, и так их разбирает интерфейс.
ch "
WITH
  toFixedString(unhex('0A010205') || unhex('000000000000000000000000'), 16) AS ip16
SELECT
  IPv4NumToString(reinterpretAsUInt32(reverse(substring(ip16, 1, 4)))) AS \"разобранный адрес\",
  length(ip16) = 16 AND substring(ip16, 5) = unhex('000000000000000000000000') AS \"признан IPv4\",
  dictGetOrDefault('default.probe_sem_dict', 'client_id',
    tuple(toIPv4(reinterpretAsUInt32(reverse(substring(ip16, 1, 4))))), '—') AS \"словарь\"
FORMAT Vertical" 2>&1 | sed 's/^/  /'

echo
ch "DROP DICTIONARY IF EXISTS default.probe_sem_dict" >/dev/null
ch "DROP TABLE IF EXISTS default.probe_sem_src" >/dev/null
echo "убрано"
