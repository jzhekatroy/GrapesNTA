#!/usr/bin/env python3
"""Прогоняет готовый SQL интерфейса тем же путём, каким его отправляет интерфейс.

Нативный клиент на этих запросах спотыкается: параметры внутри CTE он
подставляет неправильно и падает с CANNOT_PARSE_QUOTED_STRING. Поэтому запрос
уходит по HTTP с параметрами в строке запроса, как это делает интерфейс.

    run-generated-query.py <файл.sql> ключ=значение [...]
"""
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode

HTTP = "http://127.0.0.1:8123/"


def credentials():
    """Учётные данные берём у контейнера интерфейса, чтобы не держать их в скрипте."""
    out = subprocess.run(
        ["docker", "exec", "grapes-nta", "printenv", "CLICKHOUSE_USER"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    pwd = subprocess.run(
        ["docker", "exec", "grapes-nta", "printenv", "CLICKHOUSE_PASSWORD"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    return (out or "default"), pwd


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip())
        return 2
    sql = open(sys.argv[1]).read()
    qs = {"default_format": "PrettyCompact", "max_execution_time": "180"}
    for arg in sys.argv[2:]:
        key, _, value = arg.partition("=")
        qs["param_" + key] = value
    user, pwd = credentials()
    req = urllib.request.Request(
        HTTP + "?" + urlencode(qs),
        data=sql.encode(),
        headers={"X-ClickHouse-User": user, "X-ClickHouse-Key": pwd},
    )
    try:
        with urllib.request.urlopen(req, timeout=240) as resp:
            print(resp.read().decode(errors="replace"))
        return 0
    except urllib.error.HTTPError as e:
        print("ОШИБКА:", e.read().decode(errors="replace")[:800])
        return 1


if __name__ == "__main__":
    sys.exit(main())
