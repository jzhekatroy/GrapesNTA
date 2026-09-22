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

Использование:
    migrate-flows-layout.py            # показать, что будет сделано
    migrate-flows-layout.py --apply    # выполнить
    migrate-flows-layout.py --rollback # вернуть как было
"""

import argparse
import re
import subprocess
import sys

DB = "default"
LIVE = "flows_raw"      # имя, в которое пишет коллектор и которое читают сервисы
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


def ch(sql, fmt="TSVRaw", timeout=900):
    cmd = [
        "docker", "exec", "-i", "grapes-clickhouse", "clickhouse-client",
        "--max_execution_time", str(timeout), "-q",
        sql if fmt is None else f"{sql} FORMAT {fmt}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:400])
    return r.stdout.strip()


def exec_sql(sql, timeout=900):
    cmd = [
        "docker", "exec", "-i", "grapes-clickhouse", "clickhouse-client",
        "--max_execution_time", str(timeout), "-q", sql,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:400])
    return r.stdout.strip()


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
    ap.add_argument("--apply", action="store_true", help="выполнить, а не показать")
    ap.add_argument("--rollback", action="store_true", help="вернуть как было")
    args = ap.parse_args()

    if args.rollback:
        return do_rollback()

    if not table_exists(LIVE):
        print(f"таблицы {DB}.{LIVE} нет")
        return 1
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
