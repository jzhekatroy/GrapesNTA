#!/usr/bin/env python3
"""Перевод flows_raw на раскладку, пригодную для быстрого разбора трафика.

Что делает:

1. Строит новую таблицу flows_raw_next по образцу живой flows_raw — тот же набор
   колонок, те же скип-индексы, тот же TTL и те же настройки, но с другим ключом
   сортировки и секундным временем.
2. Одной командой меняет таблицы местами:
       RENAME TABLE flows_raw TO flows_v1, flows_raw_next TO flows_raw
   Команда атомарна, окна без таблицы flows_raw не возникает, поэтому коллектор
   ничего не замечает: он как писал в default.flows_raw, так и пишет.
3. Создаёт flows_all — обёртку ENGINE = Merge поверх новой и старой таблиц.
   Читатели на время переходного периода смотрят в неё и видят непрерывную
   историю. Старая таблица доживает свой TTL и удаляется.

Колонки, набор индексов, TTL и настройки читаются с живой таблицы, а не берутся
из репозитория: на разных установках они отличаются.

Порядок такой, чтобы читатели не оставались без данных ни на минуту. Обёртка
создаётся первой: её регулярное выражение сейчас совпадает только с текущей
таблицей, поэтому читатели переводятся на неё заранее и ничего не замечают.
Подмена делается уже после, и обёртка мгновенно накрывает обе таблицы.

База берётся из deploy/ui/.env, поэтому скрипт одинаково работает и когда
ClickHouse стоит рядом в контейнере, и когда она вынесена на отдельный сервер.

Использование:
    migrate-flows-layout.py --check    # проверить, можно ли мигрировать
    migrate-flows-layout.py            # показать, что будет сделано
    migrate-flows-layout.py --wrapper  # только обёртка, до переключения читателей
    migrate-flows-layout.py --apply    # новая таблица и подмена
    migrate-flows-layout.py --rollback # вернуть как было
"""

import argparse
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_ENV = Path(os.environ.get("UI_ENV") or REPO_ROOT / "deploy" / "ui" / ".env")


def read_env_file(path):
    """Читает KEY=VALUE из .env так же, как это делает ensure-live.sh."""
    values = {}
    if not path.is_file():
        return values
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


ENV = read_env_file(UI_ENV)


def setting(*names, default=""):
    """Переменная окружения важнее файла: так удобно переопределять на ходу."""
    for name in names:
        value = os.environ.get(name) or ENV.get(name)
        if value:
            return value.strip()
    return default


# База данных бывает не на той же машине, что сервисы: на части установок
# ClickHouse стоит отдельным сервером. Поэтому обращение идёт по HTTP с
# реквизитами из deploy/ui/.env, а не через docker exec в локальный контейнер.
CH_URL = setting("CH_URL", "CLICKHOUSE_URL", default="http://127.0.0.1:8123")
CH_USER = setting("CH_USER", "CLICKHOUSE_WRITE_USER", "CLICKHOUSE_USER", default="default")
CH_PASS = setting("CH_PASS", "CLICKHOUSE_WRITE_PASSWORD", "CLICKHOUSE_PASSWORD")

DB = setting("CLICKHOUSE_DATABASE", default="default")
# Мигрируется физическая таблица. Если читателей уже перевели на обёртку, имя
# для записи остаётся физическим — его и берём в первую очередь.
LIVE = setting("CLICKHOUSE_FLOWS_RAW_WRITE_TABLE", "CLICKHOUSE_FLOWS_RAW_TABLE",
               default="flows_raw")
OLD = "flows_v1"        # куда уезжает прежняя таблица
NEXT = "flows_raw_next"  # временное имя новой таблицы до подмены
WRAP = "flows_all"      # обёртка на время переходного периода

# Ключ сортировки. Первые четыре колонки образуют разреженный индекс, по ним
# идёт отсечение гранул. Пятая — само время: внутри одной группы оно снова
# возрастает, поэтому DoubleDelta на нём работает как раньше и колонка времени
# не раздувается от пересортировки.
PRIMARY_KEY = "(toStartOfFiveMinutes(time_received_ns), sampler_address, in_if, out_if)"
ORDER_BY = "(toStartOfFiveMinutes(time_received_ns), sampler_address, in_if, out_if, time_received_ns)"

# Время переводится в секундную точность: при пересортировке доли секунды
# перестают сжиматься и колонки раздуваются втрое. Экспортёры доли секунды
# сюда и не отдают, а обнаружение атак работает минутными окнами.
RETYPE = {
    "time_received_ns": "DateTime",
    "time_flow_start_ns": "DateTime",
    "time_inserted_ns": "DateTime",
}


def post(sql, timeout=900):
    url = f"{CH_URL.rstrip('/')}/?max_execution_time={timeout}"
    req = urllib.request.Request(
        url,
        data=sql.encode(),
        headers={"X-ClickHouse-User": CH_USER, "X-ClickHouse-Key": CH_PASS},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout + 60) as resp:
            return resp.read().decode(errors="replace").strip()
    except urllib.error.HTTPError as e:
        raise RuntimeError(e.read().decode(errors="replace").strip()[:400]) from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"{CH_URL} недоступна: {e.reason}") from None


def ch(sql, fmt="TSVRaw", timeout=900):
    return post(sql if fmt is None else f"{sql} FORMAT {fmt}", timeout)


def exec_sql(sql, timeout=900):
    return post(sql, timeout)


def table_exists(name):
    return ch(f"SELECT count() FROM system.tables WHERE database='{DB}' AND name='{name}'") == "1"


def live_ddl():
    return ch(f"SHOW CREATE TABLE {DB}.{LIVE}")


def parse_ddl(ddl):
    """Разбирает DDL живой таблицы на части, которые надо перенести без изменений."""
    body = ddl[ddl.index("(") + 1: ddl.rindex(")\nENGINE")]

    cols, indexes = [], []
    for raw in body.split("\n"):
        line = raw.strip().rstrip(",")
        if not line:
            continue
        (indexes if line.startswith("INDEX ") else cols).append(line)

    def grab(pat):
        m = re.search(pat, ddl)
        return m.group(1).strip() if m else None

    return {
        "columns": cols,
        "indexes": indexes,
        "partition_by": grab(r"PARTITION BY (.+)"),
        "ttl": grab(r"\nTTL (.+)"),
        "settings": grab(r"\nSETTINGS (.+)"),
    }


def transform_column(line):
    """Меняет тип времени и заменяет ZSTD на LZ4: узкое место процессорное."""
    m = re.match(r"`([^`]+)`\s+(.*)$", line)
    if not m:
        return line
    name, rest = m.group(1), m.group(2)

    if name in RETYPE:
        codec = "CODEC(DoubleDelta, LZ4)"
        return f"`{name}` {RETYPE[name]} {codec}"

    rest = rest.replace("ZSTD(1)", "LZ4")
    return f"`{name}` {rest}"


def build_create(target, parsed, engine, order_by=None, primary_key=None):
    cols = [transform_column(c) for c in parsed["columns"]]
    parts = cols + parsed["indexes"]
    sql = f"CREATE TABLE {DB}.{target}\n(\n    " + ",\n    ".join(parts) + "\n)\n"
    sql += f"ENGINE = {engine}\n"
    if engine.startswith("MergeTree"):
        sql += f"PARTITION BY {parsed['partition_by']}\n"
        if primary_key:
            sql += f"PRIMARY KEY {primary_key}\n"
        sql += f"ORDER BY {order_by}\n"
        if parsed["ttl"]:
            sql += f"TTL {parsed['ttl']}\n"
        if parsed["settings"]:
            sql += f"SETTINGS {parsed['settings']}"
    return sql.strip()


def build_wrapper(parsed):
    """Обёртка объявляется с типами новой таблицы: старые значения приводятся сами.

    Скип-индексы и способы сжатия обёртке не нужны: данных она не хранит, всё
    это берётся у физических таблиц.
    """
    cols = [
        re.sub(r"\s*CODEC\([^)]*(?:\([^)]*\))?[^)]*\)", "", transform_column(c))
        for c in parsed["columns"]
    ]
    sql = f"CREATE TABLE {DB}.{WRAP}\n(\n    " + ",\n    ".join(cols) + "\n)\n"
    sql += f"ENGINE = Merge({DB}, '^({LIVE}|{OLD})$')"
    return sql


def counts():
    out = {}
    for t in (LIVE, OLD, WRAP):
        if table_exists(t):
            out[t] = ch(f"SELECT count() FROM {DB}.{t}")
    return out


def do_check():
    """Всё, что стоит посмотреть до миграции, одной командой.

    Собрано здесь, потому что база бывает на отдельном сервере: собирать к ней
    запросы руками неудобно, а пропустить незавершённую перезапись нельзя —
    она занимает диск на часы и не даст сделать подмену.
    """
    ok = True

    def try_ch(sql, fmt="TSVRaw"):
        """Часть системных таблиц закрыта от пользователя интерфейса.

        Возвращает значение и ошибку: проверку, которая упёрлась в права,
        нельзя молча считать пройденной — о ней надо сказать.
        """
        try:
            return ch(sql, fmt=fmt), None
        except RuntimeError as e:
            text = str(e)
            return None, "нет прав" if "ACCESS_DENIED" in text else text

    version = ch("SELECT version()")
    print(f"связь с базой есть, ClickHouse {version}")

    if not table_exists(LIVE):
        print(f"таблицы {DB}.{LIVE} нет — проверьте CLICKHOUSE_FLOWS_RAW_TABLE")
        return 1

    engine_full = ch(
        f"SELECT ifNull(any(engine_full), '') FROM system.tables "
        f"WHERE database='{DB}' AND name='{LIVE}'"
    )
    m = re.search(r"TTL (.+?)(?: SETTINGS |$)", engine_full)
    print(f"таблица {DB}.{LIVE} на месте, срок хранения: "
          f"{m.group(1).strip() if m else 'не задан'}")

    size, err = try_ch(
        f"SELECT ifNull(sum(rows), 0), formatReadableSize(ifNull(sum(bytes_on_disk), 0)) "
        f"FROM system.parts WHERE database='{DB}' AND table='{LIVE}' AND active",
        fmt="TSV",
    )
    if size:
        rows, on_disk = size.split("\t")
        print(f"строк: {rows}, на диске: {on_disk}")
    else:
        print(f"размер таблицы посмотреть не удалось ({err}) — не помеха")

    mutations, err = try_ch(
        f"SELECT mutation_id, substring(command, 1, 70), parts_to_do "
        f"FROM system.mutations WHERE database='{DB}' AND table='{LIVE}' AND NOT is_done",
        fmt="TSV",
    )
    if err:
        print(f"\nНЕЗАВЕРШЁННЫЕ ПЕРЕЗАПИСИ ПРОВЕРИТЬ НЕ УДАЛОСЬ ({err}).")
        print("  Пропускать эту проверку нельзя: перезапись занимает диск на")
        print("  часы и не даст сделать подмену. Выполните под административным")
        print("  пользователем базы:")
        print(f"  SELECT mutation_id, command FROM system.mutations")
        print(f"  WHERE database='{DB}' AND table='{LIVE}' AND NOT is_done;")
        ok = False
    elif mutations:
        print("\nНЕЗАВЕРШЁННАЯ ПЕРЕЗАПИСЬ — мигрировать нельзя, сначала снять:")
        for line in mutations.splitlines():
            print(f"  {line}")
        print(f"  KILL MUTATION WHERE database='{DB}' AND table='{LIVE}' "
              f"AND mutation_id='<из строки выше>'")
        ok = False
    else:
        print("незавершённых перезаписей нет")

    for name, what in ((OLD, "прежняя таблица"), (WRAP, "обёртка")):
        if table_exists(name):
            print(f"{what} {DB}.{name} уже существует")

    # Клиенты, привязанные по сетям: при большом их числе группировка по
    # клиенту останется медленной, и это надо знать заранее.
    prefixes, _ = try_ch(f"SELECT count() FROM {DB}.net_client_prefixes_enabled")
    if prefixes is not None:
        print(f"привязок по сетям: {prefixes}")
        if int(prefixes) >= 100:
            print("  их ищет словарь, а не перебор; проверьте его: "
                  "bash scripts/check-client-prefix-dict.sh")

    print("\nвсё готово к миграции" if ok else "\nмигрировать пока нельзя")
    return 0 if ok else 1


def do_rollback():
    if not table_exists(OLD):
        print(f"нечего откатывать: таблицы {OLD} нет")
        return 1
    print("возвращаю таблицы на место")
    if table_exists(WRAP):
        exec_sql(f"DROP TABLE {DB}.{WRAP}")
        print(f"  удалена обёртка {WRAP}")
    exec_sql(f"RENAME TABLE {DB}.{LIVE} TO {DB}.{NEXT}, {DB}.{OLD} TO {DB}.{LIVE}")
    print(f"  {LIVE} -> {NEXT}, {OLD} -> {LIVE}")
    print(f"\nновая таблица сохранена как {NEXT}, строки из неё не потеряны.")
    print(f"когда убедитесь, что она не нужна: DROP TABLE {DB}.{NEXT}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="проверить готовность к миграции")
    ap.add_argument("--apply", action="store_true", help="выполнить, а не показать")
    ap.add_argument("--wrapper", action="store_true", help="создать только обёртку")
    ap.add_argument("--rollback", action="store_true", help="вернуть как было")
    args = ap.parse_args()

    print(f"база: {CH_URL} как {CH_USER}, таблица {DB}.{LIVE}")
    if UI_ENV.is_file():
        print(f"реквизиты из {UI_ENV}")
    print()

    if LIVE == WRAP:
        print(f"мигрировать надо физическую таблицу, а не обёртку {WRAP}.")
        print("укажите её явно: CLICKHOUSE_FLOWS_RAW_WRITE_TABLE=flows_raw")
        return 1

    if args.check:
        return do_check()

    if args.rollback:
        return do_rollback()

    if not table_exists(LIVE):
        print(f"таблицы {DB}.{LIVE} нет")
        return 1

    if args.wrapper:
        if table_exists(WRAP):
            print(f"обёртка {DB}.{WRAP} уже есть")
            return 0
        parsed = parse_ddl(live_ddl())
        exec_sql(build_wrapper(parsed))
        print(f"обёртка {WRAP} создана поверх {LIVE}")
        # Сверяем на закрытом вчерашнем дне, а не на всей таблице: коллектор
        # пишет непрерывно, и два подсчёта подряд по живым данным всегда разойдутся.
        # Предел чтения у пользователя интерфейса бывает 100 миллионов строк,
        # а сутки на установке — больше. Сверка тогда не выполняется, но сама
        # обёртка уже создана, и это не повод её откатывать.
        probe = ("SELECT count(), sum(bytes), sum(packets) FROM {t} "
                 "WHERE date = today() - 1 "
                 "SETTINGS max_rows_to_read = 0 FORMAT TSV")
        try:
            a = ch(probe.format(t=f"{DB}.{LIVE}"), fmt=None)
            b = ch(probe.format(t=f"{DB}.{WRAP}"), fmt=None)
        except RuntimeError as e:
            print(f"сверить вчерашний день не удалось: {e}")
            print("обёртка при этом создана, читателей можно переводить")
            return 0
        print(f"за вчера строк/байт/пакетов:")
        print(f"  через таблицу: {a}")
        print(f"  через обёртку: {b}")
        print(f"  {'совпадает' if a == b else 'РАСХОДИТСЯ'}")
        print(f"\nтеперь можно переводить читателей: CLICKHOUSE_FLOWS_RAW_TABLE={WRAP}")
        return 0 if a == b else 1

    if table_exists(OLD):
        print(f"таблица {DB}.{OLD} уже существует — миграция, похоже, уже сделана")
        return 1

    parsed = parse_ddl(live_ddl())
    create_next = build_create(NEXT, parsed, "MergeTree", ORDER_BY, PRIMARY_KEY)
    rename = (f"RENAME TABLE {DB}.{LIVE} TO {DB}.{OLD}, {DB}.{NEXT} TO {DB}.{LIVE}")
    create_wrap = build_wrapper(parsed)

    print(f"колонок: {len(parsed['columns'])}, индексов: {len(parsed['indexes'])}")
    print(f"TTL переносится как есть: {parsed['ttl']}")
    print(f"настройки переносятся как есть: {parsed['settings']}")
    print()

    if not args.apply:
        print("=== 1. новая таблица ===")
        print(create_next)
        print("\n=== 2. атомарная подмена ===")
        print(rename)
        print("\n=== 3. обёртка на переходный период ===")
        print(create_wrap)
        print("\nэто был показ. чтобы выполнить: --apply")
        return 0

    print("=== 1. создаю новую таблицу ===")
    exec_sql(create_next)
    print(f"  {NEXT} создана")

    print("=== 2. атомарная подмена ===")
    exec_sql(rename)
    print(f"  {LIVE} -> {OLD}, {NEXT} -> {LIVE}")

    print("=== 3. обёртка ===")
    if table_exists(WRAP):
        print(f"  {WRAP} уже была создана заранее — теперь накрывает обе таблицы")
    else:
        exec_sql(create_wrap)
        print(f"  {WRAP} создана поверх {LIVE} и {OLD}")

    print("\nстрок в таблицах сразу после подмены:")
    for t, n in counts().items():
        print(f"  {t:<12} {n}")

    print("\nдальше: перевести читателей на обёртку,")
    print(f"  CLICKHOUSE_FLOWS_RAW_TABLE={WRAP}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(f"ОШИБКА: {e}")
        sys.exit(1)
