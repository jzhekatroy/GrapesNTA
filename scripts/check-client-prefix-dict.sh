#!/usr/bin/env bash
# Проверяет, что словарь сетей клиентов создан, загружается и отвечает.
#
# Ничего не заводит и не меняет — годится для рабочей установки. Проверка нужна
# потому, что словарь подключается к базе по «родному» порту, а не по HTTP:
# если порт или реквизиты не те, поломка увидится только при первом обращении,
# то есть когда пользователь откроет разбор трафика.
#
# База берётся из deploy/ui/.env, поэтому работает и когда ClickHouse вынесена
# на отдельный сервер.
set -euo pipefail

ROOT=${ROOT:-/opt/GrapesNTA}
ENV_FILE=${ENV_FILE:-${ROOT}/deploy/ui/.env}
DICT=${DICT:-default.net_client_prefix_dict}
SRC=${SRC:-default.net_client_prefix_dict_src}

[ -f "$ENV_FILE" ] || { echo "нет файла настроек ${ENV_FILE}" >&2; exit 1; }

get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"''; }
CH_URL=$(get CLICKHOUSE_URL); CH_URL=${CH_URL:-http://127.0.0.1:8123}
READ_USER=$(get CLICKHOUSE_READ_USER); READ_USER=${READ_USER:-$(get CLICKHOUSE_USER)}
READ_PASS=$(get CLICKHOUSE_READ_PASSWORD); READ_PASS=${READ_PASS:-$(get CLICKHOUSE_PASSWORD)}

ch() { curl -sS --user "${READ_USER}:${READ_PASS}" "${CH_URL%/}/" --data-binary "$1" 2>&1; }
bad() { echo; echo "ИТОГ: $*"; exit 1; }

echo "база ${CH_URL} как ${READ_USER}"
echo "словарь ${DICT}"
echo

echo "=== 1. словарь объявлен? ==="
exists=$(ch "EXISTS DICTIONARY ${DICT}")
if [ "$exists" != "1" ]; then
  echo "  нет (ответ: ${exists})"
  bad "словарь не создан. Выложите схему: ./deploy/deploy.sh --no-pull ui"
fi
echo "  да"
echo

echo "=== 2. источник читается? ==="
count=$(ch "SELECT count() FROM ${SRC}")
case "$count" in
  ''|*[!0-9]*) echo "  нет: ${count}"; bad "источник словаря недоступен" ;;
esac
echo "  привязок по сетям в источнике: ${count}"
echo

echo "=== 3. словарь загружается и отвечает? ==="
# Обращение по адресу из реальной привязки: так проверяется и загрузка, и ответ.
sample=$(ch "SELECT prefix FROM ${SRC} ORDER BY prefix LIMIT 1")
if [ "$count" = "0" ] || [ -z "$sample" ]; then
  echo "  привязок по сетям нет, проверяю только загрузку произвольным адресом"
  probe=$(ch "SELECT dictGetOrDefault('${DICT}', 'client_id', tuple(toIPv4('192.0.2.1')), '<нет привязки>')")
else
  want=$(ch "SELECT client_id FROM ${SRC} WHERE prefix = '${sample}'")
  probe=$(ch "SELECT dictGetOrDefault('${DICT}', 'client_id', tuple(toIPv4(splitByChar('/', '${sample}')[1])), '<не найдено>')")
fi

if echo "$probe" | grep -qi 'ACCESS_DENIED\|Not enough privileges'; then
  echo "  запрещено: ${probe}"
  bad "пользователю ${READ_USER} запрещён dictGet. Нужен грант:
  GRANT dictGet ON default.* TO ${READ_USER};"
fi
if echo "$probe" | grep -qi 'Connection refused\|Timeout\|NETWORK_ERROR\|ATTEMPT_TO_READ_AFTER_EOF'; then
  echo "  не загрузился: ${probe}"
  bad "словарь не может подключиться к базе по «родному» порту.
  По умолчанию берётся 127.0.0.1:9000. Если порт другой, задайте его при
  выкладке схемы и повторите:
  CH_DICT_PORT=<порт> ./deploy/deploy.sh --no-pull ui"
fi
if echo "$probe" | grep -qi 'Exception'; then
  echo "  ошибка: ${probe}"
  bad "словарь не отвечает"
fi

if [ "$count" = "0" ]; then
  echo "  загружается, ответ на 192.0.2.1: ${probe}"
  echo
  echo "ИТОГ: словарь работает. Привязок по сетям нет, поэтому находить ему пока нечего."
  exit 0
fi

echo "  ${sample} -> ${probe}"
if [ "$probe" = "$want" ]; then
  echo "  совпадает с источником"
else
  echo "  источник говорит: ${want}"
  echo "  расхождение возможно, если сети вложены друг в друга: словарь отдаёт"
  echo "  самую точную, а не первую по порядку. Проверьте вручную."
fi
echo
echo "ИТОГ: словарь работает, привязок ${count}."
