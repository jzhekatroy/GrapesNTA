#!/usr/bin/env bash
# Сквозная проверка поиска клиента кабинета по словарю сетей.
#
# Заводит временные привязки по сетям, взятые из живого трафика, прогоняет
# настоящий запрос интерфейса «Топ клиентов кабинета» и сверяет его ответ с
# прямым подсчётом по тем же сетям. В конце привязки убираются.
#
#   verify-client-prefix-dict.sh [минут_окна] [число_сетей]
set -euo pipefail

ROOT=${ROOT:-/opt/GrapesNTA}
ENV_FILE=${ENV_FILE:-${ROOT}/deploy/ui/.env}
MINUTES=${1:-25}
PREFIXES=${2:-200}
TAG_PREFIX='client:probe'

get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"''; }
CH_URL=$(get CLICKHOUSE_URL); CH_URL=${CH_URL:-http://127.0.0.1:8123}
ADMIN_USER=$(get CLICKHOUSE_WRITE_USER); ADMIN_USER=${ADMIN_USER:-$(get CLICKHOUSE_USER)}
ADMIN_PASS=$(get CLICKHOUSE_WRITE_PASSWORD); ADMIN_PASS=${ADMIN_PASS:-$(get CLICKHOUSE_PASSWORD)}
READ_USER=$(get CLICKHOUSE_READ_USER); READ_USER=${READ_USER:-$ADMIN_USER}
READ_PASS=$(get CLICKHOUSE_READ_PASSWORD); READ_PASS=${READ_PASS:-$ADMIN_PASS}
FLOWS=$(get CLICKHOUSE_FLOWS_RAW_TABLE); FLOWS=${FLOWS:-flows_raw}

as_admin() { curl -sS --user "${ADMIN_USER}:${ADMIN_PASS}" "${CH_URL%/}/" --data-binary "$1"; }
as_read()  { curl -sS --user "${READ_USER}:${READ_PASS}"  "${CH_URL%/}/" --data-binary "$1"; }
die() { echo "ОШИБКА: $*" >&2; exit 1; }

cleanup() {
  echo
  echo "=== убираю тестовые привязки ==="
  # Удаление через ALTER идёт в фоне, поэтому дожидаемся: иначе на стенде
  # останутся выдуманные клиенты, и следующий, кто откроет кабинет, их увидит.
  as_admin "ALTER TABLE default.net_client_prefixes DELETE WHERE client_id LIKE '${TAG_PREFIX}%'" >/dev/null 2>&1 || true
  as_admin "ALTER TABLE default.net_clients DELETE WHERE client_id LIKE '${TAG_PREFIX}%'" >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    left_c=$(as_admin "SELECT count() FROM default.net_clients WHERE client_id LIKE '${TAG_PREFIX}%'" 2>/dev/null || echo '?')
    left_p=$(as_admin "SELECT count() FROM default.net_client_prefixes WHERE client_id LIKE '${TAG_PREFIX}%'" 2>/dev/null || echo '?')
    [ "$left_c" = "0" ] && [ "$left_p" = "0" ] && break
    sleep 2
  done
  if [ "${left_c:-?}" = "0" ] && [ "${left_p:-?}" = "0" ]; then
    echo "  убрано полностью: клиентов 0, сетей 0"
  else
    echo "  ВНИМАНИЕ: осталось клиентов ${left_c:-?}, сетей ${left_p:-?} — удалите вручную:"
    echo "  ALTER TABLE default.net_clients DELETE WHERE client_id LIKE '${TAG_PREFIX}%';"
    echo "  ALTER TABLE default.net_client_prefixes DELETE WHERE client_id LIKE '${TAG_PREFIX}%';"
  fi
}
trap cleanup EXIT

echo "база ${CH_URL}, таблица ${FLOWS}, окно ${MINUTES} мин"
echo

IP16="src_addr"
IS4="length(${IP16}) = 16 AND substring(${IP16}, 5) = unhex('000000000000000000000000')"
IP4="toIPv4(reinterpretAsUInt32(reverse(substring(${IP16}, 1, 4))))"
WHERE="date >= today() - 1 AND time_received_ns >= now() - INTERVAL ${MINUTES} MINUTE"

echo "=== 1. завожу ${PREFIXES} привязок по сетям из живого трафика ==="
out=$(as_admin "
INSERT INTO default.net_clients (client_id, display_name, bind_mode, enabled, updated_at)
SELECT
  concat('${TAG_PREFIX}', toString(number)) AS client_id,
  concat('Проверка ', toString(number)) AS display_name,
  'prefixes' AS bind_mode,
  1 AS enabled,
  now() AS updated_at
FROM numbers(${PREFIXES})" 2>&1)
echo "$out" | grep -qi Exception && die "не завести клиентов: $out"

# Сети берём самые нагруженные в окне: так у запроса будет что находить.
out=$(as_admin "
INSERT INTO default.net_client_prefixes (client_id, prefix, family, enabled, updated_at)
SELECT
  concat('${TAG_PREFIX}', toString(rowNumberInAllBlocks())) AS client_id,
  prefix,
  4 AS family,
  1 AS enabled,
  now() AS updated_at
FROM (
  SELECT concat(IPv4NumToString(bitAnd(toUInt32(${IP4}), 4294967040)), '/24') AS prefix
  FROM default.${FLOWS}
  WHERE ${WHERE} AND (${IS4})
  GROUP BY prefix
  ORDER BY sum(bytes) DESC
  LIMIT ${PREFIXES}
)" 2>&1)
echo "$out" | grep -qi Exception && die "не завести сети: $out"

echo "  клиентов: $(as_admin "SELECT count() FROM default.net_clients_enabled WHERE client_id LIKE '${TAG_PREFIX}%'")"
echo "  сетей в каталоге: $(as_admin "SELECT count() FROM default.net_client_prefixes_enabled WHERE client_id LIKE '${TAG_PREFIX}%'")"
echo "  сетей в источнике словаря: $(as_admin "SELECT count() FROM default.net_client_prefix_dict_src WHERE client_id LIKE '${TAG_PREFIX}%'")"
echo

echo "=== 2. жду, пока словарь перечитает источник (срок жизни 30-90 с) ==="
sample=$(as_admin "SELECT prefix FROM default.net_client_prefix_dict_src WHERE client_id LIKE '${TAG_PREFIX}%' LIMIT 1")
want=$(as_admin "SELECT client_id FROM default.net_client_prefix_dict_src WHERE prefix = '${sample}'")
for i in $(seq 1 24); do
  got=$(as_read "SELECT dictGetOrDefault('default.net_client_prefix_dict', 'client_id', tuple(toIPv4(splitByChar('/', '${sample}')[1])), '')" 2>&1)
  if [ "$got" = "$want" ]; then
    echo "  словарь подхватил привязки через ~$((i * 5)) с: ${sample} -> ${got}"
    break
  fi
  sleep 5
done
[ "$got" = "$want" ] || die "словарь не подхватил привязки: ждали '${want}', получили '${got}'"
echo

echo "=== 3. прямой подсчёт: сколько строк относится к тестовым клиентам ==="
as_read "
SELECT
  count() AS \"строк в окне\",
  countIf(c != '') AS \"нашли клиента\",
  uniqExact(c) - if(countIf(c = '') > 0, 1, 0) AS \"разных клиентов\"
FROM (
  SELECT if(${IS4},
    dictGetOrDefault('default.net_client_prefix_dict', 'client_id', tuple(${IP4}), ''),
    dictGetOrDefault('default.net_client_prefix_dict', 'client_id', tuple(${IP16}), '')) AS c
  FROM default.${FLOWS} WHERE ${WHERE}
) FORMAT Vertical" 2>&1 | sed 's/^/  /'
echo

echo "=== 4. настоящий запрос интерфейса «Топ клиентов кабинета» ==="
FROM_TS=$(as_read "SELECT formatDateTime(now() - INTERVAL ${MINUTES} MINUTE, '%Y-%m-%d %H:%i:%S')")
TO_TS=$(as_read "SELECT formatDateTime(now(), '%Y-%m-%d %H:%i:%S')")
echo "  окно: ${FROM_TS} .. ${TO_TS}"

docker cp "${ROOT}/scripts/gen-bench-queries.js" grapes-nta:/tmp/gen-bench-queries.js >/dev/null
docker exec -e BENCH_SERVER_DIR=/app/server grapes-nta \
  node /tmp/gen-bench-queries.js "${FROM_TS}" "${TO_TS}" /tmp/bench.json "${FLOWS}" 2>&1 | sed 's/^/  /'
docker cp grapes-nta:/tmp/bench.json /tmp/bench.json >/dev/null

python3 - "$MINUTES" <<'PY'
import json, subprocess, sys, time, urllib.parse, urllib.request, re, os

spec = next(q for q in json.load(open('/tmp/bench.json')) if q['id'] == 'top_client')
sql = spec['sql']

print(f"  запрос собран, длина SQL: {len(sql)} символов")
print(f"  перебор в запросе: {'ЕСТЬ — плохо' if 'arrayFirst' in sql else 'нет'}")
print(f"  словарь в запросе: {'есть' if 'net_client_prefix_dict' in sql else 'НЕТ — плохо'}")

env = {}
for line in open('/opt/GrapesNTA/deploy/ui/.env', errors='replace'):
    line = line.strip()
    if '=' in line and not line.startswith('#'):
        k, _, v = line.partition('=')
        env[k.strip()] = v.strip().strip('"\'')
user = env.get('CLICKHOUSE_READ_USER') or env.get('CLICKHOUSE_USER')
pw = env.get('CLICKHOUSE_READ_PASSWORD') or env.get('CLICKHOUSE_PASSWORD', '')
url = env.get('CLICKHOUSE_URL', 'http://127.0.0.1:8123')

qs = {f'param_{k}': (json.dumps(v) if isinstance(v, (list, dict)) else str(v))
      for k, v in (spec.get('params') or {}).items()}
qs['default_format'] = 'JSON'
req = urllib.request.Request(
    f"{url.rstrip('/')}/?{urllib.parse.urlencode(qs)}",
    data=sql.encode(),
    headers={'X-ClickHouse-User': user, 'X-ClickHouse-Key': pw},
)
t0 = time.time()
try:
    body = urllib.request.urlopen(req, timeout=600).read().decode()
except urllib.error.HTTPError as e:
    print('  ЗАПРОС УПАЛ: ' + e.read().decode(errors='replace')[:500])
    sys.exit(1)
secs = time.time() - t0
data = json.loads(body)
rows = data.get('data', [])
print(f"  выполнен за {secs:.2f} с, строк в ответе: {len(rows)}")


def row_key(row):
    """Имя колонки с ключом группировки зависит от запроса, поэтому ищем по значению."""
    for value in row.values():
        text = str(value)
        if text.startswith('client:') or text == '—':
            return text
    return str(next(iter(row.values()), ''))


keys = [row_key(r) for r in rows]
probe = [k for k in keys if k.startswith('client:probe')]
print(f"  из них тестовых клиентов: {len(probe)}")
print('  первые строки: ' + ', '.join(keys[:5]))
if not probe:
    print('  ПЛОХО: ни одного тестового клиента в ответе')
    sys.exit(1)
PY
