#!/usr/bin/env python3
"""Write enrichment job status into ClickHouse enrichment_job_status via HTTP."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TABLE = "default.enrichment_job_status"
MAX_LOG_CHARS = 12_000


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def ch_http_post(sql: str) -> None:
    host = os.environ.get("CLICKHOUSE_HTTP_HOST") or os.environ.get("GEOLOADERD_CH_HOST") or "127.0.0.1"
    port = os.environ.get("CLICKHOUSE_HTTP_PORT") or "8123"
    user = (
        os.environ.get("CLICKHOUSE_HTTP_USER")
        or os.environ.get("GEOLOADERD_CH_USER")
        or os.environ.get("BGPORIGIN_CH_USER")
        or "default"
    )
    password = (
        os.environ.get("CLICKHOUSE_HTTP_PASSWORD")
        or os.environ.get("GEOLOADERD_CH_PASSWORD")
        or os.environ.get("BGPORIGIN_CH_PASSWORD")
        or ""
    )
    qs = urllib.parse.urlencode({"user": user, "password": password})
    url = f"http://{host}:{port}/?{qs}"
    req = urllib.request.Request(url, data=sql.encode("utf-8"), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"CH HTTP {e.code}: {body}") from e


def escape_ch_string(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\x00", "")
    )


def ensure_table() -> None:
    ch_http_post(
        f"""
CREATE TABLE IF NOT EXISTS {TABLE}
(
  job LowCardinality(String),
  status LowCardinality(String) DEFAULT 'idle',
  started_at Nullable(DateTime64(3)),
  finished_at Nullable(DateTime64(3)),
  duration_ms Nullable(UInt32),
  exit_code Nullable(Int32),
  message String DEFAULT '',
  log_tail String DEFAULT '',
  metrics_json String DEFAULT '{{}}',
  host String DEFAULT '',
  updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY job
"""
    )


def read_log_tail(path: str | None) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.is_file():
        return ""
    data = p.read_bytes()
    if len(data) > MAX_LOG_CHARS * 2:
        data = data[-(MAX_LOG_CHARS * 2) :]
    text = data.decode("utf-8", errors="replace")
    if len(text) > MAX_LOG_CHARS:
        text = "…\n" + text[-MAX_LOG_CHARS:]
    return text


def extract_message(log_text: str, exit_code: int | None, status: str) -> str:
    lines = [ln.strip() for ln in log_text.splitlines() if ln.strip()]
    # Prefer last informative line from loaders.
    for ln in reversed(lines):
        low = ln.lower()
        if any(
            k in low
            for k in (
                "done",
                "prefix_rows",
                "inserted rows",
                "swapped",
                "staging rows",
                "asns to lookup",
                "error",
                "failed",
                "validation failed",
            )
        ):
            return ln[:500]
    if status == "error":
        return lines[-1][:500] if lines else f"exit={exit_code}"
    if status == "running":
        return "running"
    if status == "skipped":
        return lines[-1][:500] if lines else "skipped"
    return lines[-1][:500] if lines else ("ok" if exit_code == 0 else f"exit={exit_code}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", required=True)
    ap.add_argument("--status", required=True, choices=["running", "ok", "error", "skipped", "idle"])
    ap.add_argument("--exit-code", type=int, default=None)
    ap.add_argument("--started-at", default=None, help="UTC DateTime64 string")
    ap.add_argument("--finished-at", default=None)
    ap.add_argument("--duration-ms", type=int, default=None)
    ap.add_argument("--log-file", default=None)
    ap.add_argument("--message", default=None)
    ap.add_argument("--metrics-json", default="{}")
    args = ap.parse_args()

    try:
        ensure_table()
    except Exception as e:
        print(f"report_job_status: ensure_table failed: {e}", file=sys.stderr)
        # Continue — insert may still work if table exists.

    log_tail = read_log_tail(args.log_file)
    message = args.message or extract_message(log_tail, args.exit_code, args.status)
    try:
        metrics = json.loads(args.metrics_json) if args.metrics_json else {}
        if not isinstance(metrics, dict):
            metrics = {}
    except json.JSONDecodeError:
        metrics = {}
    metrics_s = json.dumps(metrics, ensure_ascii=False, separators=(",", ":"))

    started = args.started_at
    finished = args.finished_at
    now = utc_now()
    if args.status == "running" and not started:
        started = now
    if args.status in ("ok", "error", "skipped") and not finished:
        finished = now

    def nlit(v: str | None) -> str:
        if v is None:
            return "NULL"
        return f"toDateTime64('{escape_ch_string(v)}', 3)"

    def i32(v: int | None) -> str:
        return "NULL" if v is None else str(int(v))

    def u32(v: int | None) -> str:
        return "NULL" if v is None else str(max(0, int(v)))

    host = socket.gethostname()
    sql = f"""
INSERT INTO {TABLE}
(job, status, started_at, finished_at, duration_ms, exit_code, message, log_tail, metrics_json, host, updated_at)
VALUES (
  '{escape_ch_string(args.job)}',
  '{escape_ch_string(args.status)}',
  {nlit(started)},
  {nlit(finished)},
  {u32(args.duration_ms)},
  {i32(args.exit_code)},
  '{escape_ch_string(message)}',
  '{escape_ch_string(log_tail)}',
  '{escape_ch_string(metrics_s)}',
  '{escape_ch_string(host)}',
  now64(3)
)
"""
    try:
        ch_http_post(sql)
    except Exception as e:
        print(f"report_job_status: insert failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
