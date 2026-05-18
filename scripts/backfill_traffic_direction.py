#!/usr/bin/env python3
"""
Backfill minute aggregates from enriched default.flows_raw rows.

This script does not classify historical raw rows. It only aggregates columns
already written by xdpflowd (`direction`, labels, operators). Old rows with
DEFAULT values will be aggregated as direction='unknown'.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def parse_utc(value: str) -> datetime:
    value = value.strip().replace("T", " ").replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError("expected UTC time like 2026-05-18 12:00:00")


def sql_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def clickhouse_base_args(args: argparse.Namespace) -> list[str]:
    cmd = [args.clickhouse_client]
    cmd += ["--host", args.host]
    cmd += ["--port", str(args.port)]
    cmd += ["--user", args.user]
    if args.password:
        cmd += ["--password", args.password]
    cmd += ["--database", args.database]
    return cmd


def ch_run_query(base: Sequence[str], query: str) -> None:
    proc = subprocess.run(list(base) + ["--query", query], capture_output=True)
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"clickhouse-client failed (exit {proc.returncode})\nstderr: {stderr}")


def insert_direction_query(args: argparse.Namespace, start: datetime, end: datetime) -> str:
    return f"""
INSERT INTO {args.direction_table}
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM {args.flows_table}
WHERE time_received_ns >= toDateTime('{sql_dt(start)}', 'UTC')
  AND time_received_ns <  toDateTime('{sql_dt(end)}', 'UTC')
GROUP BY minute, direction
SETTINGS max_threads = {args.max_threads}
"""


def insert_uplink_query(args: argparse.Namespace, start: datetime, end: datetime) -> str:
    return f"""
INSERT INTO {args.uplink_table}
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    multiIf(
        direction = 'out', dst_label,
        direction = 'in', src_label,
        src_label != '', src_label,
        dst_label
    ) AS uplink,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM {args.flows_table}
WHERE time_received_ns >= toDateTime('{sql_dt(start)}', 'UTC')
  AND time_received_ns <  toDateTime('{sql_dt(end)}', 'UTC')
  AND direction IN ('in', 'out', 'transit')
  AND (src_label != '' OR dst_label != '')
GROUP BY minute, direction, uplink
SETTINGS max_threads = {args.max_threads}
"""


def insert_customer_query(args: argparse.Namespace, start: datetime, end: datetime) -> str:
    return f"""
INSERT INTO {args.customer_table}
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    multiIf(
        direction = 'out', src_operator,
        direction = 'in', dst_operator,
        src_operator != '', src_operator,
        dst_operator
    ) AS operator_id,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM {args.flows_table}
WHERE time_received_ns >= toDateTime('{sql_dt(start)}', 'UTC')
  AND time_received_ns <  toDateTime('{sql_dt(end)}', 'UTC')
  AND direction IN ('in', 'out', 'internal')
  AND (src_operator != '' OR dst_operator != '')
GROUP BY minute, direction, operator_id
SETTINGS max_threads = {args.max_threads}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill enriched traffic aggregates.")
    port_s = env("TRAFFIC_BACKFILL_CH_PORT")
    default_port = int(port_s) if port_s and port_s.isdigit() else 9000
    parser.add_argument("--clickhouse-client", default=env("TRAFFIC_BACKFILL_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"))
    parser.add_argument("--host", default=env("TRAFFIC_BACKFILL_CH_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--user", default=env("TRAFFIC_BACKFILL_CH_USER", "default"))
    parser.add_argument("--password", default=env("TRAFFIC_BACKFILL_CH_PASSWORD"))
    parser.add_argument("--database", default=env("TRAFFIC_BACKFILL_CH_DATABASE", "default"))
    parser.add_argument("--from", dest="from_ts", required=True, type=parse_utc)
    parser.add_argument("--to", dest="to_ts", required=True, type=parse_utc)
    parser.add_argument("--chunk-minutes", type=int, default=int(env("TRAFFIC_BACKFILL_CHUNK_MINUTES", "15") or 15))
    parser.add_argument("--flows-table", default=env("TRAFFIC_BACKFILL_FLOWS_TABLE", "default.flows_raw"))
    parser.add_argument("--direction-table", default=env("TRAFFIC_BACKFILL_DIRECTION_TABLE", "default.traffic_direction_1m"))
    parser.add_argument("--uplink-table", default=env("TRAFFIC_BACKFILL_UPLINK_TABLE", "default.traffic_uplink_1m"))
    parser.add_argument("--customer-table", default=env("TRAFFIC_BACKFILL_CUSTOMER_TABLE", "default.traffic_customer_1m"))
    parser.add_argument("--max-threads", type=int, default=int(env("TRAFFIC_BACKFILL_MAX_THREADS", "4") or 4))
    parser.add_argument("--skip-uplink", action="store_true")
    parser.add_argument("--skip-customer", action="store_true")
    args = parser.parse_args()

    if args.to_ts <= args.from_ts:
        raise RuntimeError("--to must be greater than --from")
    if args.chunk_minutes <= 0:
        raise RuntimeError("--chunk-minutes must be positive")
    if not os.path.isfile(args.clickhouse_client):
        raise FileNotFoundError(f"clickhouse-client not found: {args.clickhouse_client}")

    base = clickhouse_base_args(args)
    cur = args.from_ts
    step = timedelta(minutes=args.chunk_minutes)
    while cur < args.to_ts:
        nxt = min(cur + step, args.to_ts)
        print(f"backfill {sql_dt(cur)} -> {sql_dt(nxt)}", file=sys.stderr)
        ch_run_query(base, insert_direction_query(args, cur, nxt))
        if not args.skip_uplink:
            ch_run_query(base, insert_uplink_query(args, cur, nxt))
        if not args.skip_customer:
            ch_run_query(base, insert_customer_query(args, cur, nxt))
        cur = nxt
    print("backfill_traffic_direction: done", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)
