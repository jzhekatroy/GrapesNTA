#!/usr/bin/env python3
"""Замер набора реальных запросов разбора трафика по одной или двум раскладкам.

На вход подаются JSON-файлы, подготовленные gen-bench-queries.js: в них лежит
тот самый SQL, который интерфейс отправляет в ClickHouse, вместе с параметрами.

Каждый запрос выполняется несколько раз, берётся лучший прогон. Перед каждым
прогоном сбрасываются кэши засечек и распакованных блоков, иначе второй вариант
получил бы фору от прогретого кэша.

Использование:
    bench-flows-layout.py <метка>=<файл.json> [<метка>=<файл.json> ...]
                          [--repeat N] [--timeout SEC]
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlencode

REPEAT = 3
TIMEOUT = 600

# Запросы уходят по HTTP, а не через нативный клиент: интерфейс работает именно
# так, и только на этом пути параметры внутри CTE подставляются правильно.
# Нативный клиент на таком запросе спотыкается с CANNOT_PARSE_QUOTED_STRING.
HTTP = os.environ.get("BENCH_CH_URL", "http://127.0.0.1:8123/")


def ch_credentials():
    """Учётные данные берём у контейнера интерфейса, чтобы не хранить их в скрипте."""
    user = os.environ.get("BENCH_CH_USER")
    password = os.environ.get("BENCH_CH_PASSWORD")
    if user and password is not None:
        return user, password
    r = subprocess.run(
        ["docker", "exec", "grapes-nta", "sh", "-c",
         "printf '%s\\n%s' \"$CLICKHOUSE_USER\" \"$CLICKHOUSE_PASSWORD\""],
        capture_output=True, text=True, timeout=60,
    )
    parts = (r.stdout or "").split("\n")
    return (parts[0] or "default"), (parts[1] if len(parts) > 1 else "")


CH_USER, CH_PASSWORD = ch_credentials()


def ch(sql, timeout=None):
    """Служебный запрос через нативный клиент: тут параметров нет."""
    cmd = [
        "docker", "exec", "-i", "grapes-clickhouse", "clickhouse-client",
        "--max_execution_time", str(timeout or TIMEOUT), "-q", sql,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=(timeout or TIMEOUT) + 60)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def http_query(sql, params, qid, timeout):
    """Запрос замера — тем же путём, каким его отправляет интерфейс."""
    qs = {"query_id": qid, "max_execution_time": str(timeout), "default_format": "Null"}
    for k, v in (params or {}).items():
        qs[f"param_{k}"] = str(v)
    req = urllib.request.Request(
        HTTP + "?" + urlencode(qs),
        data=sql.encode(),
        headers={"X-ClickHouse-User": CH_USER, "X-ClickHouse-Key": CH_PASSWORD},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout + 30) as resp:
            return False, resp.read().decode(errors="replace").strip()
    except urllib.error.HTTPError as e:
        return True, e.read().decode(errors="replace").strip()
    except Exception as e:  # noqa: BLE001
        return True, str(e)


def run_one(case, timeout):
    """Один прогон запроса. Возвращает метрики из журнала или причину отказа."""
    qid = f"bench-{uuid.uuid4().hex[:16]}"

    ch("SYSTEM DROP MARK CACHE", timeout=60)
    ch("SYSTEM DROP UNCOMPRESSED CACHE", timeout=60)

    failed, body = http_query(case["sql"], case.get("params"), qid, timeout)
    ch("SYSTEM FLUSH LOGS", timeout=120)

    _, out, _ = ch(f"""
        SELECT round(query_duration_ms / 1000, 3), read_rows, read_bytes,
               memory_usage, result_rows
        FROM system.query_log
        WHERE query_id = '{qid}' AND type = 'QueryFinish'
        ORDER BY event_time DESC LIMIT 1 FORMAT TSV
    """, timeout=120)

    if failed or not out:
        short = body.replace("\n", " ")
        m = re.search(r"DB::Exception[^\n]{0,160}", short)
        return {"error": (m.group(0) if m else short[:160]) or "нет записи в журнале"}

    sec, rows, byts, mem, res = out.split("\t")
    return {
        "sec": float(sec), "rows": int(rows), "bytes": int(byts),
        "mem": int(mem), "result_rows": int(res),
    }


def human(n, unit):
    if unit == "rows":
        for lim, suf in ((1e9, "млрд"), (1e6, "млн"), (1e3, "тыс")):
            if n >= lim:
                return f"{n / lim:.2f} {suf}"
        return str(n)
    for lim, suf in ((1024 ** 4, "ТиБ"), (1024 ** 3, "ГиБ"), (1024 ** 2, "МиБ"), (1024, "КиБ")):
        if n >= lim:
            return f"{n / lim:.2f} {suf}"
    return f"{n} Б"


def main():
    args = sys.argv[1:]
    repeat, timeout = REPEAT, TIMEOUT
    sources = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--repeat":
            repeat = int(args[i + 1]); i += 2; continue
        if a == "--timeout":
            timeout = int(args[i + 1]); i += 2; continue
        label, _, path = a.partition("=")
        sources.append((label, json.load(open(path))))
        i += 1

    if not sources:
        print(__doc__)
        return 2

    results = {}
    for label, cases in sources:
        print(f"\n### раскладка: {label}  ({len(cases)} запросов, лучший из {repeat})", flush=True)
        results[label] = {}
        for case in cases:
            best = None
            err = None
            for _ in range(repeat):
                r = run_one(case, timeout)
                if "error" in r:
                    err = r["error"]
                    break
                if best is None or r["sec"] < best["sec"]:
                    best = r
            if best is None:
                results[label][case["id"]] = {"error": err}
                print(f"  {case['label']:<48} ОТКАЗ: {err}", flush=True)
            else:
                results[label][case["id"]] = best
                print(
                    f"  {case['label']:<48} {best['sec']:>8.3f} с  "
                    f"{human(best['rows'], 'rows'):>10}  {human(best['bytes'], 'b'):>10}  "
                    f"память {human(best['mem'], 'b')}",
                    flush=True,
                )

    if len(sources) < 2:
        return 0

    base_label = sources[0][0]
    labels = [s[0] for s in sources[1:]]
    by_id = {c["id"]: c["label"] for _, cases in sources for c in cases}

    print(f"\n\n### сравнение с «{base_label}»\n")
    head = f"{'запрос':<48}{base_label:>12}"
    for l in labels:
        head += f"{l:>12}{'выигрыш':>10}"
    print(head)
    print("-" * len(head))

    for qid, qlabel in by_id.items():
        base = results[base_label].get(qid)
        if not base or "error" in base:
            continue
        line = f"{qlabel:<48}{base['sec']:>10.3f} с"
        for l in labels:
            cur = results[l].get(qid)
            if not cur or "error" in cur:
                line += f"{'отказ':>12}{'':>10}"
            else:
                gain = base["sec"] / cur["sec"] if cur["sec"] > 0 else 0
                line += f"{cur['sec']:>10.3f} с{gain:>9.1f}x"
        print(line)

    print(f"\n### прочитано с диска\n")
    for qid, qlabel in by_id.items():
        base = results[base_label].get(qid)
        if not base or "error" in base:
            continue
        line = f"{qlabel:<48}{human(base['bytes'], 'b'):>12}"
        for l in labels:
            cur = results[l].get(qid)
            if cur and "error" not in cur:
                gain = base["bytes"] / cur["bytes"] if cur["bytes"] > 0 else 0
                line += f"{human(cur['bytes'], 'b'):>12}{gain:>9.1f}x"
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
