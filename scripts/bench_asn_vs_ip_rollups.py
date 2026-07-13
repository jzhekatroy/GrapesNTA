#!/usr/bin/env python3
"""Benchmark ASN vs IP rollup-shaped aggregates on real flows_raw.

Goal: estimate whether ASN talker/pair rollups are light enough to not
recreate the IP talker/pair OOM / watermark-stall problem.

Usage:
  export CH_URL=http://95.215.1.30:6123
  export CH_USER=ui_read
  export CH_PASSWORD=...
  python3 scripts/bench_asn_vs_ip_rollups.py

Optional:
  CH_MINUTES=1          # closed-minute window size (default 1)
  CH_SAFETY_LAG_MIN=10  # end = now - lag (default 10)
  CH_SOURCE_ID=         # optional filter, e.g. sflow-default
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def ch_request(
    url: str,
    user: str,
    password: str,
    sql: str,
    *,
    with_totals: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], float]:
    """Run SQL via HTTP JSONEachRow; return rows, summary, wall_seconds."""
    params = {
        "default_format": "JSONEachRow",
        "wait_end_of_query": "1",
    }
    if with_totals:
        params["default_format"] = "JSON"
    full = f"{url.rstrip('/')}/?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        full,
        data=sql.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "X-ClickHouse-User": user,
            "X-ClickHouse-Key": password,
        },
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            body = resp.read().decode("utf-8")
            summary_raw = resp.headers.get("X-ClickHouse-Summary", "{}")
            try:
                summary = json.loads(summary_raw)
            except json.JSONDecodeError:
                summary = {"raw": summary_raw}
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ClickHouse HTTP {exc.code}: {err}") from exc
    wall = time.perf_counter() - started

    rows: List[Dict[str, Any]] = []
    if with_totals:
        payload = json.loads(body) if body.strip() else {}
        rows = payload.get("data", [])
        # Prefer server stats from JSON meta when present.
        if "statistics" in payload:
            summary = {**summary, **payload["statistics"]}
    else:
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows, summary, wall


def fmt_bytes(n: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}"
        v /= 1024
    return f"{n:.0f} B"


def fmt_num(n: float) -> str:
    if n >= 1_000_000:
        return f"{n/1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return f"{n:.0f}"


def pick_window(ch_url: str, user: str, password: str, minutes: int, lag_min: int) -> Tuple[str, str]:
    """Return [start, end) ISO timestamps for a closed window ending before lag."""
    sql = f"""
SELECT
    formatDateTime(toStartOfMinute(now() - INTERVAL {lag_min} MINUTE) - INTERVAL {minutes} MINUTE, '%Y-%m-%d %H:%i:%S') AS start_ts,
    formatDateTime(toStartOfMinute(now() - INTERVAL {lag_min} MINUTE), '%Y-%m-%d %H:%i:%S') AS end_ts
"""
    rows, _, _ = ch_request(ch_url, user, password, sql)
    if not rows:
        raise RuntimeError("failed to pick time window")
    return str(rows[0]["start_ts"]), str(rows[0]["end_ts"])


def source_filter(source_id: str) -> str:
    if not source_id:
        return "AND source_id IN (SELECT source_id FROM default.net_flow_sources_enabled)"
    return f"AND source_id = '{source_id}'"


def build_queries(start_ts: str, end_ts: str, source_id: str) -> List[Tuple[str, str]]:
    """Rollup-shaped queries: IP vs ASN for talkers and pairs."""
    src = source_filter(source_id)
    time_filter = (
        f"time_received_ns >= toDateTime64('{start_ts}', 9) "
        f"AND time_received_ns < toDateTime64('{end_ts}', 9) "
        f"{src}"
    )

    # IP talker: explode src/dst IP like traffic_talker_1m (without heavy geo/name joins).
    ip_talker = f"""
SELECT
    endpoint_side,
    endpoint_ip,
    endpoint_asn,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows
FROM
(
    SELECT
        direction,
        bytes,
        packets,
        tupleElement(row, 1) AS endpoint_side,
        tupleElement(row, 2) AS endpoint_ip,
        tupleElement(row, 3) AS endpoint_asn
    FROM default.flows_raw
    ARRAY JOIN arrayZip(
        ['src', 'dst'],
        [
            if(etype = 2048,
               toString(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4))))),
               IPv6NumToString(src_addr)),
            if(etype = 2048,
               toString(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4))))),
               IPv6NumToString(dst_addr))
        ],
        [src_asn, dst_asn]
    ) AS row
    WHERE {time_filter}
)
GROUP BY endpoint_side, endpoint_ip, endpoint_asn, direction
SETTINGS max_memory_usage = 20000000000
"""

    # ASN talker: same shape, group by ASN only (no IP string conversion in GROUP BY).
    asn_talker = f"""
SELECT
    endpoint_side,
    endpoint_asn,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows
FROM
(
    SELECT
        direction,
        bytes,
        packets,
        tupleElement(row, 1) AS endpoint_side,
        tupleElement(row, 2) AS endpoint_asn
    FROM default.flows_raw
    ARRAY JOIN arrayZip(
        ['src', 'dst'],
        [src_asn, dst_asn]
    ) AS row
    WHERE {time_filter}
)
GROUP BY endpoint_side, endpoint_asn, direction
SETTINGS max_memory_usage = 20000000000
"""

    # IP pair: src_ip → dst_ip (+ asn kept as attributes like current pair job).
    ip_pair = f"""
SELECT
    direction,
    if(etype = 2048,
       toString(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4))))),
       IPv6NumToString(src_addr)) AS src_ip,
    if(etype = 2048,
       toString(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4))))),
       IPv6NumToString(dst_addr)) AS dst_ip,
    src_asn,
    dst_asn,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows
FROM default.flows_raw
WHERE {time_filter}
GROUP BY direction, src_ip, dst_ip, src_asn, dst_asn
SETTINGS max_memory_usage = 20000000000
"""

    # ASN pair: src_asn → dst_asn only.
    asn_pair = f"""
SELECT
    direction,
    src_asn,
    dst_asn,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows
FROM default.flows_raw
WHERE {time_filter}
GROUP BY direction, src_asn, dst_asn
SETTINGS max_memory_usage = 20000000000
"""

    # Baseline: how many raw rows in the window.
    raw_count = f"""
SELECT
    count() AS rows,
    uniqExact(
        if(etype = 2048,
           toString(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4))))),
           IPv6NumToString(src_addr))
    ) AS uniq_src_ip,
    uniqExact(
        if(etype = 2048,
           toString(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4))))),
           IPv6NumToString(dst_addr))
    ) AS uniq_dst_ip,
    uniqExact(src_asn) AS uniq_src_asn,
    uniqExact(dst_asn) AS uniq_dst_asn,
    sum(bytes) AS bytes
FROM default.flows_raw
WHERE {time_filter}
SETTINGS max_memory_usage = 20000000000
"""

    return [
        ("raw_window_stats", raw_count),
        ("ip_talker_1m_shaped", ip_talker),
        ("asn_talker_1m_shaped", asn_talker),
        ("ip_pair_1m_shaped", ip_pair),
        ("asn_pair_1m_shaped", asn_pair),
    ]


def summary_int(summary: Dict[str, Any], *keys: str) -> Optional[int]:
    for k in keys:
        if k in summary and summary[k] is not None:
            try:
                return int(summary[k])
            except (TypeError, ValueError):
                continue
    return None


def run_one(
    ch_url: str,
    user: str,
    password: str,
    name: str,
    sql: str,
) -> Dict[str, Any]:
    # For aggregates we only need cardinality + top bytes check, not full dump.
    # Wrap SELECT to return only counts / top1 to keep client light.
    if name == "raw_window_stats":
        rows, summary, wall = ch_request(ch_url, user, password, sql)
        row = rows[0] if rows else {}
        return {
            "name": name,
            "wall_s": wall,
            "result_rows": 1,
            "read_rows": summary_int(summary, "read_rows"),
            "read_bytes": summary_int(summary, "read_bytes"),
            "memory_usage": summary_int(summary, "memory_usage"),
            "elapsed_ns": summary_int(summary, "elapsed_ns"),
            "extra": row,
            "ok": True,
            "error": "",
        }

    wrapped = f"""
SELECT
    count() AS group_rows,
    sum(bytes) AS total_bytes,
    max(bytes) AS max_group_bytes
FROM (
{sql}
)
"""
    try:
        rows, summary, wall = ch_request(ch_url, user, password, wrapped)
        row = rows[0] if rows else {}
        return {
            "name": name,
            "wall_s": wall,
            "result_rows": int(row.get("group_rows") or 0),
            "total_bytes": int(row.get("total_bytes") or 0),
            "read_rows": summary_int(summary, "read_rows"),
            "read_bytes": summary_int(summary, "read_bytes"),
            "memory_usage": summary_int(summary, "memory_usage"),
            "elapsed_ns": summary_int(summary, "elapsed_ns"),
            "extra": {},
            "ok": True,
            "error": "",
        }
    except Exception as exc:  # noqa: BLE001 - report per-query failure
        return {
            "name": name,
            "wall_s": 0.0,
            "result_rows": None,
            "read_rows": None,
            "read_bytes": None,
            "memory_usage": None,
            "elapsed_ns": None,
            "extra": {},
            "ok": False,
            "error": str(exc)[:500],
        }


def ratio(a: Optional[float], b: Optional[float]) -> str:
    if a is None or b is None or b == 0:
        return "n/a"
    return f"{a / b:.1f}x"


def print_table(results: List[Dict[str, Any]]) -> None:
    by_name = {r["name"]: r for r in results}
    print()
    print("=== Per-query ===")
    hdr = (
        f"{'query':<24} {'ok':<4} {'wall_s':>8} {'groups':>10} "
        f"{'read_rows':>12} {'read':>10} {'mem':>10}"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        if not r["ok"]:
            print(f"{r['name']:<24} FAIL {r['error']}")
            continue
        elapsed = (r["elapsed_ns"] or 0) / 1e9 if r["elapsed_ns"] else r["wall_s"]
        print(
            f"{r['name']:<24} {'yes':<4} {elapsed:8.2f} "
            f"{fmt_num(r['result_rows'] or 0):>10} "
            f"{fmt_num(r['read_rows'] or 0):>12} "
            f"{fmt_bytes(r['read_bytes'] or 0):>10} "
            f"{fmt_bytes(r['memory_usage'] or 0):>10}"
        )

    print()
    print("=== ASN vs IP speedup (higher = ASN better) ===")
    pairs = [
        ("talker", "ip_talker_1m_shaped", "asn_talker_1m_shaped"),
        ("pair", "ip_pair_1m_shaped", "asn_pair_1m_shaped"),
    ]
    for label, ip_name, asn_name in pairs:
        ip = by_name.get(ip_name)
        asn = by_name.get(asn_name)
        if not ip or not asn or not ip["ok"] or not asn["ok"]:
            print(f"{label}: incomplete")
            continue
        ip_t = (ip["elapsed_ns"] or 0) / 1e9 if ip["elapsed_ns"] else ip["wall_s"]
        asn_t = (asn["elapsed_ns"] or 0) / 1e9 if asn["elapsed_ns"] else asn["wall_s"]
        print(
            f"{label}: time IP={ip_t:.2f}s ASN={asn_t:.2f}s → ASN faster by {ratio(ip_t, asn_t)}; "
            f"groups IP={fmt_num(ip['result_rows'] or 0)} ASN={fmt_num(asn['result_rows'] or 0)} "
            f"→ cardinality {ratio(ip['result_rows'], asn['result_rows'])} smaller on ASN; "
            f"mem IP={fmt_bytes(ip['memory_usage'] or 0)} ASN={fmt_bytes(asn['memory_usage'] or 0)} "
            f"→ mem {ratio(ip['memory_usage'], asn['memory_usage'])} less on ASN"
        )


def verdict(results: List[Dict[str, Any]]) -> None:
    by_name = {r["name"]: r for r in results}
    ip_t = by_name.get("ip_talker_1m_shaped")
    asn_t = by_name.get("asn_talker_1m_shaped")
    ip_p = by_name.get("ip_pair_1m_shaped")
    asn_p = by_name.get("asn_pair_1m_shaped")
    raw = by_name.get("raw_window_stats")

    print()
    print("=== Verdict (will ASN rollups break the system?) ===")
    if raw and raw["ok"]:
        e = raw["extra"]
        print(
            f"window raw: rows={fmt_num(int(e.get('rows') or 0))}, "
            f"uniq_src_ip={fmt_num(int(e.get('uniq_src_ip') or 0))}, "
            f"uniq_dst_ip={fmt_num(int(e.get('uniq_dst_ip') or 0))}, "
            f"uniq_src_asn={fmt_num(int(e.get('uniq_src_asn') or 0))}, "
            f"uniq_dst_asn={fmt_num(int(e.get('uniq_dst_asn') or 0))}"
        )

    risks = []
    goods = []
    for label, ip, asn in (("talker", ip_t, asn_t), ("pair", ip_p, asn_p)):
        if not ip or not asn or not ip["ok"] or not asn["ok"]:
            risks.append(f"{label}: query failed — cannot conclude")
            continue
        groups = asn["result_rows"] or 0
        mem = asn["memory_usage"] or 0
        t = (asn["elapsed_ns"] or 0) / 1e9 if asn["elapsed_ns"] else asn["wall_s"]
        if groups < 50_000 and mem < 2_000_000_000 and t < 30:
            goods.append(
                f"{label}: ASN looks safe (groups={fmt_num(groups)}, "
                f"mem={fmt_bytes(mem)}, time={t:.1f}s per minute-bucket)"
            )
        elif groups < 500_000 and mem < 8_000_000_000 and t < 90:
            goods.append(
                f"{label}: ASN probably OK with separate timer "
                f"(groups={fmt_num(groups)}, mem={fmt_bytes(mem)}, time={t:.1f}s)"
            )
        else:
            risks.append(
                f"{label}: ASN still heavy "
                f"(groups={fmt_num(groups)}, mem={fmt_bytes(mem)}, time={t:.1f}s) — rethink"
            )

        # Compare to IP failure mode
        ip_groups = ip["result_rows"] or 0
        if ip_groups > 0 and groups > 0 and ip_groups / max(groups, 1) >= 20:
            goods.append(
                f"{label}: ASN cardinality ≥20× smaller than IP "
                f"({fmt_num(ip_groups)} → {fmt_num(groups)})"
            )

    for g in goods:
        print(f"+ {g}")
    if risks:
        for r in risks:
            print(f"! {r}")
    else:
        print("+ No red flags for ASN minute rollups on this window.")


def main() -> int:
    ch_url = env("CH_URL", "http://95.215.1.30:6123")
    user = env("CH_USER", "ui_read")
    password = env("CH_PASSWORD")
    if not password:
        print("CH_PASSWORD is required", file=sys.stderr)
        return 2

    minutes = int(env("CH_MINUTES", "1") or "1")
    lag_min = int(env("CH_SAFETY_LAG_MIN", "10") or "10")
    source_id = env("CH_SOURCE_ID")

    start_ts, end_ts = pick_window(ch_url, user, password, minutes, lag_min)
    print(f"ClickHouse: {ch_url} user={user}")
    print(f"Window: [{start_ts}, {end_ts})  minutes={minutes}  source={source_id or 'enabled'}")

    queries = build_queries(start_ts, end_ts, source_id)
    results: List[Dict[str, Any]] = []
    for name, sql in queries:
        print(f"running {name} ...", flush=True)
        results.append(run_one(ch_url, user, password, name, sql))

    print_table(results)
    verdict(results)

    # Machine-readable dump for later.
    out_path = env("CH_BENCH_OUT", "")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "window": {"start": start_ts, "end": end_ts, "minutes": minutes},
                    "source_id": source_id,
                    "results": results,
                },
                f,
                indent=2,
                default=str,
            )
        print(f"\nWrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
