#!/usr/bin/env python3
"""
Async traffic rollups for GrapesNTA (replaces sync traffic_*_mv on ingest path).

Runs one closed bucket at a time per job, tracks progress in
default.traffic_rollup_state, and logs problems to stderr and optional file.

Typical usage on collector m61:

  python3 scripts/traffic_rollup_async.py \\
    --host 95.215.1.30 --port 6124 \\
    --user develop --password '***' \\
    --log-file /var/log/grapesnta/traffic_rollups.log

Before first run:

  ./deploy/schema/apply.sh 60_traffic
  clickhouse-client ... --multiquery < deploy/clickhouse/detach_traffic_mvs.sql

Keep all traffic_*_mv detached while this script is the rollup source.
Deploy timer: deploy/systemd/traffic-rollups.timer (see CLICKHOUSE_DB_SETUP_RUNBOOK.md §7).
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from traffic_rollup_jobs import RollupJob, sorted_jobs


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def resolve_clickhouse_client(path: str) -> str:
    if os.path.isfile(path):
        return path
    found = shutil.which("clickhouse-client")
    if found:
        return found
    return path


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def add_bucket(dt: datetime, kind: str) -> datetime:
    if kind == "minute":
        return dt + timedelta(minutes=1)
    if kind == "hour":
        return dt + timedelta(hours=1)
    if kind == "day":
        return dt + timedelta(days=1)
    raise ValueError(f"unknown bucket kind: {kind}")


def truncate_bucket(dt: datetime, kind: str) -> datetime:
    if kind == "minute":
        return dt.replace(second=0, microsecond=0)
    if kind == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    if kind == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"unknown bucket kind: {kind}")


def bucket_column(job: RollupJob) -> str:
    if job.bucket_kind == "minute":
        return "minute"
    if job.bucket_kind == "hour":
        return "hour"
    if job.bucket_kind == "day":
        return "day"
    raise ValueError(job.bucket_kind)


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def split_table_name(table: str, default_db: str = "default") -> Tuple[str, str]:
    if "." in table:
        db, name = table.split(".", 1)
        return db, name
    return default_db, table


# Leave this much of --live-wall-sec unused so the outer `timeout` in
# cron-traffic-rollups.sh (LIVE_TIMEOUT, default 55s) cannot SIGKILL a
# still-running clickhouse-client. A killed client leaves ALTER DELETE
# mutations queued; the next tick then stacks another DELETE.
HARD_KILL_RESERVE_SEC = 8
# Queue ticks share one wall clock across every job in the request. After the
# 1m tables a leftover of 6–15s used to start traffic_client_country_1h (full
# hour from flows_raw) and then mark the request error. Live already defers
# on timeout; the queue must do the same and not begin a query it cannot finish.
QUEUE_MIN_BUDGET_SEC = {"minute": 20, "hour": 60, "day": 60}


class JobDeferred(Exception):
    """Skip this job this tick without failing the run or advancing the cursor."""


@dataclass
class JobState:
    last_bucket: Optional[datetime]
    status: str
    last_error: str


class ClickHouseClient:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base = self._base_cmd(args)
        self.timeout_s = max(0, int(getattr(args, "query_timeout_sec", 0) or 0)) or None

    @staticmethod
    def _base_cmd(args: argparse.Namespace) -> List[str]:
        cmd = [args.clickhouse_client]
        cmd += ["--host", args.host]
        cmd += ["--port", str(args.port)]
        cmd += ["--user", args.user]
        if args.password is not None and args.password != "":
            cmd += ["--password", args.password]
        cmd += ["--database", args.database]
        return cmd

    def query(self, sql: str, *, display: Optional[str] = None) -> str:
        try:
            proc = subprocess.run(
                self.base + ["--query", sql],
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            # The caller runs under a flock held for the whole cron tick, so a
            # query that never returns silences every following tick. Surface it
            # as a normal failure and let the next tick retry.
            shown = display if display is not None else sql
            raise RuntimeError(
                f"clickhouse query timed out after {self.timeout_s}s\n"
                f"query: {shown[:800]}{'...' if len(shown) > 800 else ''}"
            ) from None
        if proc.returncode != 0:
            shown = display if display is not None else sql
            err = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(
                f"clickhouse query failed (exit {proc.returncode})\n"
                f"query: {shown[:800]}{'...' if len(shown) > 800 else ''}\n"
                f"stderr: {err}"
            )
        # Preserve trailing tabs in TabSeparated output. Some state rows have an
        # empty last_error column; stripping all whitespace would drop that final
        # field on the last row and make the state parser skip it.
        return (proc.stdout or "").rstrip("\n")

    def execute(self, sql: str, *, display: Optional[str] = None) -> None:
        self.query(sql, display=display)


def setup_logging(log_file: Optional[str], verbose: bool) -> logging.Logger:
    logger = logging.getLogger("traffic_rollup")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_file:
        try:
            parent = os.path.dirname(log_file)
            if parent:
                os.makedirs(parent, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            # Host bind-mount is often root:root; the container runs as uid 1001.
            # Graphs must still roll up — file log is optional.
            logger.warning("cannot write log file %s: %s; stderr only", log_file, exc)

    return logger


def ensure_state_table(ch: ClickHouseClient, logger: logging.Logger) -> None:
    exists = ch.query(
        "SELECT count() FROM system.tables "
        "WHERE database = 'default' AND name = 'traffic_rollup_state'",
        display="check traffic_rollup_state exists",
    )
    if exists == "0":
        raise RuntimeError(
            "table default.traffic_rollup_state is missing; run "
            "deploy/schema/60_traffic/01_traffic_rollup_state.sql first"
        )
    logger.debug("state table present")


def load_states(ch: ClickHouseClient) -> Dict[str, JobState]:
    rows = ch.query(
        "SELECT job, last_bucket, status, last_error "
        "FROM default.traffic_rollup_state FINAL "
        "ORDER BY job",
        display="load rollup states",
    )
    out: Dict[str, JobState] = {}
    if not rows:
        return out
    for line in rows.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        job, bucket_raw, status = parts[0], parts[1], parts[2]
        last_error = parts[3] if len(parts) > 3 else ""
        bucket = None
        if bucket_raw and bucket_raw != "1970-01-01 00:00:00":
            bucket = datetime.strptime(bucket_raw, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        out[job] = JobState(last_bucket=bucket, status=status, last_error=last_error)
    return out


def save_state(
    ch: ClickHouseClient,
    job_id: str,
    bucket: datetime,
    status: str,
    last_error: str,
    rows_written: int,
    duration_ms: int,
) -> None:
    err = last_error.replace("'", "''")
    sql = (
        "INSERT INTO default.traffic_rollup_state "
        "(job, last_bucket, status, last_error, rows_written, duration_ms, updated_at) "
        f"VALUES ('{job_id}', toDateTime('{fmt_dt(bucket)}', 'UTC'), "
        f"'{status}', '{err}', {rows_written}, {duration_ms}, now('UTC'))"
    )
    ch.execute(sql, display=f"save state for {job_id}")


def check_attached_mvs(ch: ClickHouseClient) -> int:
    return int(
        ch.query(
            "SELECT count() FROM system.tables "
            "WHERE database = 'default' "
            "AND engine = 'MaterializedView' "
            "AND name LIKE 'traffic_%'",
            display="count attached traffic MVs",
        )
    )


def raw_lag_seconds(ch: ClickHouseClient) -> int:
    value = ch.query(
        "SELECT dateDiff('second', max(time_received_ns), now64(9)) "
        "FROM default.flows_raw "
        "WHERE date >= today() - 1",
        display="flows_raw lag seconds",
    )
    return int(value or "0")


@dataclass
class SpoolSource:
    source_id: str
    lag_segments: int
    age_seconds: int


def spool_backlog_sources(
    ch: ClickHouseClient,
    logger: logging.Logger,
    *,
    max_lag_segments: int,
    snapshot_max_age_sec: int,
) -> Optional[List[SpoolSource]]:
    """Enabled sources whose collector spool is still draining a backlog.

    Returns the list of sources with a *fresh* health snapshot that reports
    lag_segments above the allowed threshold. An empty list means "drained"
    (safe to advance). None means the signal is unavailable (missing table /
    query error) — callers must fail open and not hold the cursor forever.

    Rationale: during spool catch-up after a ClickHouse outage the collector
    re-inserts backlog rows with their *original* time_received_ns while also
    ingesting live traffic, so raw_lag_seconds() (now - max(time_received_ns))
    stays ~0 and cannot detect the incomplete window. collector_health_snapshots
    .lag_segments falls monotonically to 0 exactly when the spool is drained, so
    it is the correct completeness gate.
    """
    try:
        rows = ch.query(
            "SELECT source_id, "
            "argMax(lag_segments, ts) AS lag, "
            "dateDiff('second', max(ts), now64(3)) AS age "
            "FROM default.collector_health_snapshots "
            "WHERE ts >= now() - INTERVAL 30 MINUTE "
            "AND source_id IN (SELECT source_id FROM default.net_flow_sources_enabled) "
            "GROUP BY source_id",
            display="spool backlog state",
        )
    except RuntimeError as exc:
        logger.warning("spool gate: signal unavailable, failing open: %s", exc)
        return None

    draining: List[SpoolSource] = []
    for line in rows.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            lag = int(parts[1] or "0")
            age = int(parts[2] or "0")
        except ValueError:
            continue
        # A stale snapshot cannot confirm a backlog; skip it (fail open) so a
        # silent/stopped collector never deadlocks the rollup.
        if age > snapshot_max_age_sec:
            continue
        if lag > max_lag_segments:
            draining.append(SpoolSource(source_id=parts[0], lag_segments=lag, age_seconds=age))
    return draining


def bootstrap_bucket(
    ch: ClickHouseClient,
    job: RollupJob,
    days: int,
    safety_lag_minutes: int,
) -> datetime:
    """Start catch-up at the retention floor without scanning raw tables.

    min(time) over N days of flows_raw/dns_log reads billions of rows, saturates
    ClickHouse, and on a live stand is then clamped to the same floor anyway.
    """
    lookback = max(int(days), 1)
    occupied = ch.query(
        f"SELECT 1 FROM {job.source_table} LIMIT 1",
        display=f"bootstrap occupancy for {job.job_id}",
    )
    if occupied.strip() == "":
        # Fresh stand: do not backfill empty bootstrap_days of silent buckets.
        return truncate_bucket(
            utc_now() - timedelta(minutes=safety_lag_minutes),
            job.bucket_kind,
        )
    return truncate_bucket(utc_now() - timedelta(days=lookback), job.bucket_kind)


def flows_raw_enabled_min_bucket(
    ch: ClickHouseClient,
    job: RollupJob,
    *,
    lookback_days: int = 7,
    cache: Optional[Dict[str, Optional[datetime]]] = None,
) -> Optional[datetime]:
    """Earliest occupied bucket in flows_raw for enabled sources.

    Finds the first occupied date partition with LIMIT 1, then the first
    time_received_ns in that partition (ORDER BY matches the table key).
    Jumping to midnight of that day would grind empty morning hours on a
    fresh stand that started sFlow at noon.
    """
    if job.source_table != "default.flows_raw":
        return None
    cache_key = f"{job.bucket_kind}:{lookback_days}"
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    lookback = max(int(lookback_days), 1)
    today = truncate_bucket(utc_now(), "day")
    result: Optional[datetime] = None
    for offset in range(lookback, -1, -1):
        day = today - timedelta(days=offset)
        day_s = day.strftime("%Y-%m-%d")
        hit = ch.query(
            "SELECT 1 FROM default.flows_raw "
            f"WHERE date = toDate('{day_s}') "
            "AND source_id IN (SELECT source_id FROM default.net_flow_sources_enabled) "
            "LIMIT 1",
            display=f"probe flows_raw {day_s} for {job.job_id}",
        )
        if not hit.strip():
            continue
        first = ch.query(
            "SELECT toStartOfMinute(time_received_ns) "
            "FROM default.flows_raw "
            f"WHERE date = toDate('{day_s}') "
            "AND source_id IN (SELECT source_id FROM default.net_flow_sources_enabled) "
            "ORDER BY time_received_ns ASC "
            "LIMIT 1",
            display=f"first flows_raw minute {day_s} for {job.job_id}",
        )
        if first.strip():
            result = truncate_bucket(parse_utc_dt(first.strip()), job.bucket_kind)
        else:
            result = truncate_bucket(day, job.bucket_kind)
        break
    if cache is not None:
        cache[cache_key] = result
    return result


def subtract_bucket(dt: datetime, kind: str) -> datetime:
    if kind == "minute":
        return dt - timedelta(minutes=1)
    if kind == "hour":
        return dt - timedelta(hours=1)
    if kind == "day":
        return dt - timedelta(days=1)
    raise ValueError(f"unknown bucket kind: {kind}")


def skip_forward_stale_bucket(
    ch: ClickHouseClient,
    logger: logging.Logger,
    job: RollupJob,
    bucket_start: datetime,
    states: Dict[str, JobState],
    *,
    bootstrap_days: int,
    raw_min_cache: Optional[Dict[str, Optional[datetime]]] = None,
) -> datetime:
    """Jump rollup state forward when it trails real flows_raw data."""
    if job.source_table != "default.flows_raw":
        return bucket_start
    # Live edge: do not probe. The old 2-day guard skipped the same-day empty
    # prefix (sFlow started at 09:17, cursor walked 00:00..06:17 UTC).
    if bucket_start >= utc_now() - timedelta(minutes=30):
        return bucket_start

    data_min = flows_raw_enabled_min_bucket(
        ch,
        job,
        lookback_days=max(int(bootstrap_days), 7),
        cache=raw_min_cache,
    )
    if data_min is None or bucket_start >= data_min:
        return bucket_start

    prev_bucket = truncate_bucket(subtract_bucket(data_min, job.bucket_kind), job.bucket_kind)
    logger.info(
        "job=%s action=skip_forward stale_bucket=%s data_min=%s new_last_bucket=%s",
        job.job_id,
        fmt_dt(bucket_start),
        fmt_dt(data_min),
        fmt_dt(prev_bucket),
    )
    save_state(ch, job.job_id, prev_bucket, "skip_forward", "", 0, 0)
    states[job.job_id] = JobState(
        last_bucket=prev_bucket,
        status="skip_forward",
        last_error="",
    )
    return data_min


def safe_until(args: argparse.Namespace) -> datetime:
    return truncate_bucket(
        utc_now() - timedelta(minutes=args.safety_lag_minutes),
        "minute",
    )


def safe_until_for_job(job: RollupJob, args: argparse.Namespace) -> datetime:
    return truncate_bucket(
        utc_now() - timedelta(minutes=args.safety_lag_minutes),
        job.bucket_kind,
    )


def _column_time_range(col: str, start: datetime, end: datetime) -> str:
    start_s = fmt_dt(start)
    end_s = fmt_dt(end)
    if col.split(".")[-1] in ("time_received_ns", "time_flow_start_ns"):
        return (
            f"{col} >= toDateTime64('{start_s}', 9, 'UTC') "
            f"AND {col} < toDateTime64('{end_s}', 9, 'UTC')"
        )
    return (
        f"{col} >= toDateTime('{start_s}', 'UTC') "
        f"AND {col} < toDateTime('{end_s}', 'UTC')"
    )


def _source_id_ref(job: RollupJob) -> str:
    """source_id column for the job, matching the table alias used in its SELECT.

    Jobs that read flows_raw as `... AS f` set time_filter_column='f.time_received_ns';
    we reuse that prefix so the source gate references f.source_id, not source_id.
    """
    col = job.time_filter_column or job.time_column
    if "." in col:
        return f"{col.split('.')[0]}.source_id"
    return "source_id"


def build_time_filter(job: RollupJob, start: datetime, end: datetime) -> str:
    primary = _column_time_range(job.time_filter_column or job.time_column, start, end)
    guard_minutes = job.received_guard_minutes
    if guard_minutes:
        # flows_raw is ordered by time_received_ns, so a flow-start filter alone
        # forces a wide scan. Add a guard on the indexed received column widened
        # by guard_minutes. received_ns >= flow_start_ns and trails it by at most
        # one active timeout, so the widened window cannot drop matching flows.
        guard = _column_time_range(
            "time_received_ns",
            start - timedelta(minutes=guard_minutes),
            end + timedelta(minutes=guard_minutes),
        )
        base = f"({primary}) AND ({guard})"
    else:
        base = primary
    if job.source_table == "default.flows_raw":
        # Self-protection: only aggregate sources registered and enabled in the
        # catalog. A retired/legacy source (e.g. xdp-default) set enabled=0 then
        # disappears from rollups automatically, without manual cleanup. Jobs that
        # read derived tables (traffic_*_1m) inherit the gate from upstream.
        base = (
            f"{base} AND {_source_id_ref(job)} IN "
            "(SELECT source_id FROM default.net_flow_sources_enabled)"
        )
    return base


def dependency_ready(
    job: RollupJob,
    bucket_start: datetime,
    bucket_end: datetime,
    states: Dict[str, JobState],
) -> Tuple[bool, str]:
    if not job.depends_on:
        return True, ""
    for dep in job.depends_on:
        dep_state = states.get(dep)
        if dep_state is None or dep_state.last_bucket is None:
            return False, f"dependency {dep} has no state yet"
        if job.bucket_kind == "hour":
            required = bucket_end - timedelta(minutes=1)
        elif job.bucket_kind == "day":
            required = bucket_end - timedelta(minutes=1)
        else:
            required = bucket_end - timedelta(minutes=1)
        if dep_state.last_bucket < required:
            return (
                False,
                f"dependency {dep} last_bucket={fmt_dt(dep_state.last_bucket)} "
                f"< required {fmt_dt(required)}",
            )
    return True, ""


def count_source_rows(
    ch: ClickHouseClient,
    job: RollupJob,
    time_filter: str,
) -> Optional[int]:
    if job.source_table != "default.flows_raw":
        return None
    sql = f"SELECT count() FROM {job.source_table} WHERE {time_filter}"
    try:
        return int(ch.query(sql, display=f"count source rows for {job.job_id}"))
    except RuntimeError:
        return None


def wait_table_mutations(
    ch: ClickHouseClient,
    logger: logging.Logger,
    table: str,
    *,
    timeout_s: int = 900,
    poll_s: float = 2.0,
) -> None:
    db, name = split_table_name(table)
    deadline = time.monotonic() + timeout_s
    while True:
        pending_raw = ch.query(
            "SELECT count() FROM system.mutations "
            f"WHERE database = {sql_string(db)} "
            f"AND table = {sql_string(name)} "
            "AND is_done = 0",
            display=f"wait mutations for {table}",
        )
        pending = int(pending_raw or "0")
        if pending == 0:
            return
        if time.monotonic() >= deadline:
            reason = ch.query(
                "SELECT any(latest_fail_reason) FROM system.mutations "
                f"WHERE database = {sql_string(db)} "
                f"AND table = {sql_string(name)} "
                "AND is_done = 0",
                display=f"mutation failure reason for {table}",
            )
            raise RuntimeError(
                f"timed out waiting for mutations on {table}: "
                f"pending={pending} latest_fail_reason={reason}"
            )
        logger.info("table=%s action=wait_mutations pending=%s", table, pending)
        time.sleep(poll_s)


def is_retryable_queue_error(msg: str) -> bool:
    text = (msg or "").lower()
    return (
        "timed out" in text
        or "pending mutations" in text
        or "cannot read system.mutations" in text
    )


def remaining_budget_s(started: float, wall_sec: int) -> float:
    if not wall_sec:
        return float("inf")
    return float(wall_sec) - (time.monotonic() - started) - HARD_KILL_RESERVE_SEC


def apply_query_timeout(
    ch: ClickHouseClient,
    started: float,
    wall_sec: int,
    cap_s: int,
) -> int:
    left = remaining_budget_s(started, wall_sec)
    if left == float("inf"):
        timeout = max(1, cap_s)
    else:
        timeout = max(1, min(cap_s, int(left)))
    ch.timeout_s = timeout
    return timeout


def pending_mutations(ch: ClickHouseClient, table: str) -> Optional[int]:
    db, name = split_table_name(table)
    try:
        raw = ch.query(
            "SELECT count() FROM system.mutations "
            f"WHERE database = {sql_string(db)} "
            f"AND table = {sql_string(name)} "
            "AND is_done = 0",
            display=f"pending mutations for {table}",
        )
        return int(raw or "0")
    except RuntimeError:
        return None


def parse_bucket_value(raw: str, kind: str) -> datetime:
    text = raw.strip()
    if kind == "day" and len(text) >= 10 and text[4] == "-":
        try:
            return datetime.strptime(text[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def dest_table_exists(ch: ClickHouseClient, job: RollupJob) -> bool:
    raw = str(job.dest_table or "")
    if "." in raw:
        database, name = raw.split(".", 1)
    else:
        database, name = "default", raw
    if not database.isidentifier() or not name.isidentifier():
        return False
    try:
        out = ch.query(
            f"SELECT 1 FROM system.tables "
            f"WHERE database = '{database}' AND name = '{name}' LIMIT 1",
            display=f"exists {job.dest_table}",
        )
    except RuntimeError:
        return False
    return bool(out.strip())


def probe_existing_buckets(
    ch: ClickHouseClient,
    job: RollupJob,
    start: datetime,
    end: datetime,
) -> Optional[set]:
    col = bucket_column(job)
    lo = f"toDateTime('{fmt_dt(start)}', 'UTC')"
    hi = f"toDateTime('{fmt_dt(end)}', 'UTC')"
    try:
        raw = ch.query(
            f"SELECT {col} FROM {job.dest_table} "
            f"WHERE {col} >= {lo} AND {col} < {hi} "
            f"GROUP BY {col}",
            display=f"existing buckets for {job.job_id}",
        )
    except RuntimeError:
        return None
    found: set = set()
    if not raw:
        return found
    for line in raw.splitlines():
        if line.strip():
            found.add(parse_bucket_value(line, job.bucket_kind))
    return found


def split_window(
    buckets: Sequence[datetime],
    existing: set,
    kind: str,
) -> Tuple[Optional[datetime], Optional[datetime], Optional[datetime]]:
    """Return (skip_last, insert_from, insert_end_exclusive) for a bucket list."""
    if not buckets:
        return None, None, None
    skip_last: Optional[datetime] = None
    insert_from: Optional[datetime] = None
    empty: List[datetime] = []
    for bucket in buckets:
        if insert_from is None:
            if bucket in existing:
                skip_last = bucket
                continue
            insert_from = bucket
        elif bucket in existing:
            break
        empty.append(bucket)
    if not empty:
        return skip_last, None, None
    return skip_last, empty[0], add_bucket(empty[-1], kind)


def _insert_window(
    ch: ClickHouseClient,
    logger: logging.Logger,
    job: RollupJob,
    start: datetime,
    end: datetime,
    args: argparse.Namespace,
) -> Tuple[datetime, int, str]:
    time_filter = build_time_filter(job, start, end)
    select_sql = job.select_sql.format(time_filter=time_filter)
    insert_sql = f"INSERT INTO {job.dest_table}\n{select_sql}"
    source_rows = None
    if args.preflight_count:
        source_rows = count_source_rows(ch, job, time_filter)
        if source_rows is not None:
            logger.info(
                "job=%s from=%s to=%s source_rows=%s",
                job.job_id,
                fmt_dt(start),
                fmt_dt(end),
                source_rows,
            )
    started = time.monotonic()
    ch.execute(
        insert_sql,
        display=f"insert rollup for {job.job_id} {fmt_dt(start)}..{fmt_dt(end)}",
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    last = truncate_bucket(subtract_bucket(end, job.bucket_kind), job.bucket_kind)
    n_buckets = len(iter_range_buckets(job, start, end))
    logger.info(
        "job=%s from=%s to=%s buckets=%s status=ok duration_ms=%s source_rows=%s",
        job.job_id,
        fmt_dt(start),
        fmt_dt(end),
        n_buckets,
        duration_ms,
        source_rows if source_rows is not None else "unknown",
    )
    return last, duration_ms, "ok"


def run_window(
    ch: ClickHouseClient,
    logger: logging.Logger,
    job: RollupJob,
    start: datetime,
    end: datetime,
    args: argparse.Namespace,
    *,
    force_delete: bool = False,
) -> Tuple[datetime, int, str]:
    """Write [start, end). Returns (last_committed_bucket, duration_ms, action)."""
    buckets = iter_range_buckets(job, start, end)
    if not buckets:
        raise ValueError(f"empty window for {job.job_id}")
    window_end = add_bucket(buckets[-1], job.bucket_kind)

    pending = pending_mutations(ch, job.dest_table)
    rebuild = bool(force_delete or args.delete_before_insert)
    if rebuild:
        if pending is None:
            raise JobDeferred(f"cannot read system.mutations for {job.dest_table}")
        if pending > 0:
            raise JobDeferred(f"pending mutations={pending} on {job.dest_table}")
    elif pending is not None and pending > 0:
        raise JobDeferred(f"pending mutations={pending} on {job.dest_table}")

    if rebuild and job.pre_delete_sql:
        col = bucket_column(job)
        lo = f"toDateTime('{fmt_dt(start)}', 'UTC')"
        hi = f"toDateTime('{fmt_dt(window_end)}', 'UTC')"
        logger.info(
            "job=%s action=delete from=%s to=%s reason=rebuild",
            job.job_id,
            fmt_dt(start),
            fmt_dt(window_end),
        )
        ch.execute(
            f"ALTER TABLE {job.dest_table} DELETE WHERE {col} >= {lo} AND {col} < {hi}",
            display=f"range delete for {job.job_id}",
        )
        wait_s = ch.timeout_s if ch.timeout_s else 30
        wait_table_mutations(ch, logger, job.dest_table, timeout_s=max(5, wait_s))
        return _insert_window(ch, logger, job, start, window_end, args)

    existing = probe_existing_buckets(ch, job, start, window_end)
    if existing is None:
        col = bucket_column(job)
        bucket_dt = f"toDateTime('{fmt_dt(start)}', 'UTC')"
        one = ch.query(
            f"SELECT 1 FROM {job.dest_table} WHERE {col} = {bucket_dt} LIMIT 1",
            display=f"idempotency probe for {job.job_id}",
        )
        existing = {start} if one.strip() else set()
        if existing:
            logger.info(
                "job=%s action=skip_existing bucket=%s",
                job.job_id,
                fmt_dt(start),
            )
            return start, 0, "skip_existing"

    skip_last, insert_from, insert_end = split_window(buckets, existing, job.bucket_kind)
    if insert_from is None:
        last = skip_last if skip_last is not None else buckets[-1]
        logger.info(
            "job=%s action=skip_existing from=%s to=%s",
            job.job_id,
            fmt_dt(start),
            fmt_dt(add_bucket(last, job.bucket_kind)),
        )
        return last, 0, "skip_existing"

    last, duration_ms, action = _insert_window(
        ch, logger, job, insert_from, insert_end, args
    )
    return last, duration_ms, action


def run_bucket(
    ch: ClickHouseClient,
    logger: logging.Logger,
    job: RollupJob,
    bucket_start: datetime,
    args: argparse.Namespace,
) -> Tuple[bool, int, str]:
    bucket_end = add_bucket(bucket_start, job.bucket_kind)
    last, duration_ms, action = run_window(
        ch, logger, job, bucket_start, bucket_end, args
    )
    return True, duration_ms, action


def next_bucket(
    job: RollupJob,
    state: Optional[JobState],
    ch: ClickHouseClient,
    bootstrap_days: int,
    safety_lag_minutes: int,
) -> datetime:
    if state is None or state.last_bucket is None:
        start = bootstrap_bucket(ch, job, bootstrap_days, safety_lag_minutes)
        return truncate_bucket(start, job.bucket_kind)
    return truncate_bucket(add_bucket(state.last_bucket, job.bucket_kind), job.bucket_kind)


def clamp_future_last_bucket(
    job: RollupJob,
    state: Optional[JobState],
    *,
    now: datetime,
    safety_lag_minutes: int,
) -> Optional[datetime]:
    """If last_bucket is in the future, rewind to the live closed edge.

    A leftover or TZ-mixed cursor (last_bucket > now) makes next_bucket stay
    ahead of safe_until forever, so every tick skips with reason=safe_lag.
    Returns the new last_bucket, or None if no clamp is needed.
    """
    if state is None or state.last_bucket is None:
        return None
    if state.last_bucket <= now:
        return None
    edge = truncate_bucket(now - timedelta(minutes=max(int(safety_lag_minutes), 0)), job.bucket_kind)
    return subtract_bucket(edge, job.bucket_kind)


def dest_max_bucket(ch: ClickHouseClient, job: RollupJob) -> Optional[datetime]:
    raw = ch.query(
        f"SELECT max({bucket_column(job)}) FROM {job.dest_table}",
        display=f"dest max for {job.job_id}",
    ).strip()
    if not raw or raw.startswith("1970-01-01"):
        return None
    try:
        return parse_utc_dt(raw)
    except ValueError:
        return None


def flows_raw_enabled_max_minute(
    ch: ClickHouseClient,
    cache: Optional[Dict[str, Optional[datetime]]] = None,
) -> Optional[datetime]:
    cache_key = "enabled_max_minute"
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    raw = ch.query(
        "SELECT toStartOfMinute(max(time_received_ns)) "
        "FROM default.flows_raw "
        "WHERE date >= today() - 1 "
        "AND source_id IN (SELECT source_id FROM default.net_flow_sources_enabled)",
        display="flows_raw enabled max minute",
    ).strip()
    result: Optional[datetime] = None
    if raw and not raw.startswith("1970-01-01"):
        try:
            result = parse_utc_dt(raw)
        except ValueError:
            result = None
    if cache is not None:
        cache[cache_key] = result
    return result


def rewind_if_dest_lags_raw(
    ch: ClickHouseClient,
    logger: logging.Logger,
    job: RollupJob,
    bucket_start: datetime,
    job_until: datetime,
    states: Dict[str, JobState],
    *,
    safety_lag_minutes: int,
    raw_max_cache: Optional[Dict[str, Optional[datetime]]],
    dry_run: bool,
) -> datetime:
    """Rewind a live-edge cursor if dest tables missed newly enabled sources.

    skip_forward only jumps *old* cursors toward the first raw minute. When a
    source is added after the cursor already reached now, dest.max stays stale
    while last_bucket keeps skipping safe_lag. Re-open dest.max so those
    minutes are aggregated again (writes are idempotent).
    """
    if job.source_table != "default.flows_raw":
        return bucket_start
    dest_max = dest_max_bucket(ch, job)
    if dest_max is None:
        return bucket_start
    if bucket_start <= add_bucket(dest_max, job.bucket_kind):
        return bucket_start
    # Stay at least two closed buckets behind the live edge to avoid a
    # rewind → still-safe_lag loop on the same tick.
    if dest_max >= subtract_bucket(job_until, job.bucket_kind):
        return bucket_start
    raw_max = flows_raw_enabled_max_minute(ch, raw_max_cache)
    if raw_max is None:
        return bucket_start
    raw_edge = truncate_bucket(
        raw_max - timedelta(minutes=max(int(safety_lag_minutes), 0)),
        job.bucket_kind,
    )
    if dest_max >= raw_edge:
        return bucket_start
    logger.info(
        "job=%s action=rewind_dest_lag dest_max=%s cursor=%s raw_max=%s new_last=%s",
        job.job_id,
        fmt_dt(dest_max),
        fmt_dt(bucket_start),
        fmt_dt(raw_max),
        fmt_dt(dest_max),
    )
    if not dry_run:
        save_state(ch, job.job_id, dest_max, "rewind_dest_lag", "", 0, 0)
    states[job.job_id] = JobState(
        last_bucket=dest_max,
        status="rewind_dest_lag",
        last_error="",
    )
    return add_bucket(dest_max, job.bucket_kind)


def parse_args() -> argparse.Namespace:
    port_s = env("TRAFFIC_ROLLUP_CH_PORT", env("GEOLOADERD_CH_PORT", "6124"))
    parser = argparse.ArgumentParser(description="Async GrapesNTA traffic rollups")
    parser.add_argument(
        "--clickhouse-client",
        default=env("TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"),
    )
    parser.add_argument("--host", default=env("TRAFFIC_ROLLUP_CH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(port_s or "6124"))
    parser.add_argument("--user", default=env("TRAFFIC_ROLLUP_CH_USER", "develop"))
    parser.add_argument("--password", default=env("TRAFFIC_ROLLUP_CH_PASSWORD"))
    parser.add_argument("--database", default=env("TRAFFIC_ROLLUP_CH_DATABASE", "default"))
    parser.add_argument(
        "--log-file",
        default=env("TRAFFIC_ROLLUP_LOG_FILE", "/var/log/grapesnta/traffic_rollups.log"),
    )
    parser.add_argument("--no-log-file", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--jobs",
        default="",
        help="comma-separated job ids; default = all jobs in priority order",
    )
    parser.add_argument(
        "--max-buckets-per-job",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB", "1") or "1"),
    )
    parser.add_argument(
        "--max-range-buckets",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_MAX_RANGE_BUCKETS", "15") or "15"),
        help=(
            "catch-up window size for a lagging job in one INSERT; "
            "SELECT already groups by bucket so N minutes is one query"
        ),
    )
    parser.add_argument(
        "--sleep-between-buckets",
        type=float,
        default=float(env("TRAFFIC_ROLLUP_SLEEP_BETWEEN_BUCKETS", "0") or "0"),
        help="seconds to sleep after each written bucket to reduce ClickHouse pressure",
    )
    parser.add_argument(
        "--safety-lag-minutes",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_SAFETY_LAG_MINUTES", "5") or "5"),
    )
    parser.add_argument(
        "--max-raw-lag-seconds",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_MAX_RAW_LAG_SECONDS", "120") or "120"),
        help="skip rollups while flows_raw is fresher than this many seconds behind now",
    )
    parser.add_argument(
        "--ignore-raw-lag",
        action="store_true",
        help="run even if flows_raw lag is high (use only after spool catch-up)",
    )
    parser.add_argument(
        "--require-spool-drained",
        dest="require_spool_drained",
        action="store_true",
        default=(env("TRAFFIC_ROLLUP_REQUIRE_SPOOL_DRAINED", "1") or "1").lower()
        in ("1", "true", "yes", "on"),
        help=(
            "hold the rollup cursor while any enabled collector's spool is still "
            "draining a backlog (collector_health_snapshots.lag_segments). Prevents "
            "gaps after a ClickHouse outage; on by default"
        ),
    )
    parser.add_argument(
        "--no-require-spool-drained",
        dest="require_spool_drained",
        action="store_false",
        help="disable the spool-drain gate",
    )
    parser.add_argument(
        "--spool-max-lag-segments",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_SPOOL_MAX_LAG_SEGMENTS", "0") or "0"),
        help="allowed collector spool backlog (segments) before holding the cursor",
    )
    parser.add_argument(
        "--spool-snapshot-max-age-sec",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_SPOOL_SNAPSHOT_MAX_AGE_SEC", "180") or "180"),
        help=(
            "ignore collector_health_snapshots older than this (a stale snapshot "
            "cannot confirm a backlog, so the gate fails open to avoid deadlock)"
        ),
    )
    parser.add_argument(
        "--bootstrap-days",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_BOOTSTRAP_DAYS", "7") or "7"),
    )
    parser.add_argument(
        "--delete-before-insert",
        action="store_true",
        default=(env("TRAFFIC_ROLLUP_DELETE_BEFORE_INSERT", "0") or "0").lower()
        in ("1", "true", "yes", "on"),
        help=(
            "force delete of the target bucket before every insert, skipping the "
            "auto idempotency probe. Writes are already exactly-once by default "
            "(a bucket that already has rows is deleted before re-insert); use "
            "this only for an unconditional rebuild"
        ),
    )
    parser.add_argument(
        "--preflight-count",
        action="store_true",
        default=(env("TRAFFIC_ROLLUP_PREFLIGHT_COUNT", "0") or "0").lower()
        in ("1", "true", "yes", "on"),
        help="count source rows before insert (extra CH load, useful for debugging)",
    )
    parser.add_argument(
        "--allow-attached-mv",
        action="store_true",
        default=(env("TRAFFIC_ROLLUP_ALLOW_ATTACHED_MV", "0") or "0").lower()
        in ("1", "true", "yes", "on"),
        help="do not abort when traffic_* MaterializedView tables are still attached",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="log planned buckets without writing to ClickHouse",
    )
    parser.add_argument(
        "--range-from",
        default="",
        help="UTC 'YYYY-MM-DD HH:MM:SS' — process this closed range (with --range-to)",
    )
    parser.add_argument(
        "--range-to",
        default="",
        help="UTC exclusive end of range backfill",
    )
    parser.add_argument(
        "--process-queue",
        action="store_true",
        help="claim and process one pending row from traffic_rollup_backfill_queue",
    )
    parser.add_argument(
        "--queue-wall-sec",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_QUEUE_WALL_SEC", "180") or "180"),
        help="max wall seconds to spend on a queue request per cron tick",
    )
    parser.add_argument(
        "--live-wall-sec",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_LIVE_WALL_SEC", "45") or "45"),
        help=(
            "max wall seconds for a live tick; the cursor is saved per bucket, so "
            "the next tick resumes where this one stopped. Keeps a slow ClickHouse "
            "from holding the cron flock past its own interval (0 = no limit)"
        ),
    )
    parser.add_argument(
        "--query-timeout-sec",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_QUERY_TIMEOUT_SEC", "180") or "180"),
        help="abort a single ClickHouse query after this many seconds (0 = wait forever)",
    )
    parser.add_argument(
        "--rewind-minutes",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_REWIND_MINUTES", "0") or "0"),
        help=(
            "one-shot: set last_bucket of minute jobs to now()-N so the next "
            "buckets (including newly enabled sources) are re-aggregated. "
            "Hourly/daily cursors in the future are clamped separately"
        ),
    )
    return parser.parse_args()


DEFAULT_BACKFILL_JOBS = [
    "traffic_dashboard_1m",
    "traffic_protocol_1m",
    "traffic_direction_1m",
    "traffic_role_1m",
    "traffic_entity_1m",
    "traffic_client_1m",
    # traffic_client_anomaly_1m: not scheduled until detection ships
    "traffic_vlan_1m",
    "traffic_country_1m",
    "traffic_service_1m",
    "traffic_unknown_port_1m",
    "traffic_asn_1m",
    "traffic_asn_pair_1m",
    "traffic_dashboard_1h",
    "traffic_client_1h",
    "traffic_client_country_1h",
    "traffic_client_service_1h",
    "traffic_asn_1h",
    "traffic_asn_pair_1h",
    "traffic_dashboard_1d",
    "traffic_client_1d",
    "traffic_client_country_1d",
    "traffic_client_service_1d",
]

BACKFILL_QUEUE_TABLE = "default.traffic_rollup_backfill_queue"


def parse_utc_dt(raw: str) -> datetime:
    text = (raw or "").strip().replace("T", " ").rstrip("Z")
    if not text:
        raise ValueError("empty datetime")
    if "." in text:
        text = text.split(".", 1)[0]
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def ensure_backfill_queue(ch: ClickHouseClient, logger: logging.Logger) -> None:
    ch.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {BACKFILL_QUEUE_TABLE}
        (
            request_id String,
            created_at DateTime64(3, 'UTC') DEFAULT now64(3),
            from_minute DateTime('UTC'),
            to_minute DateTime('UTC'),
            jobs Array(String) DEFAULT [],
            include_observations UInt8 DEFAULT 1,
            status LowCardinality(String) DEFAULT 'pending',
            error String DEFAULT '',
            progress_job String DEFAULT '',
            progress_minute DateTime('UTC') DEFAULT toDateTime(0, 'UTC'),
            updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY request_id
        TTL toDateTime(created_at) + toIntervalDay(30)
        SETTINGS index_granularity = 8192
        """,
        display="ensure backfill queue table",
    )
    logger.debug("backfill queue table present")


def save_queue_row(
    ch: ClickHouseClient,
    *,
    request_id: str,
    created_at: str,
    from_minute: datetime,
    to_minute: datetime,
    jobs: Sequence[str],
    include_observations: int,
    status: str,
    error: str = "",
    progress_job: str = "",
    progress_minute: Optional[datetime] = None,
) -> None:
    jobs_sql = "[" + ",".join(sql_string(j) for j in jobs) + "]"
    prog = progress_minute or datetime(1970, 1, 1, tzinfo=timezone.utc)
    err = (error or "").replace("\\", "\\\\").replace("'", "\\'")
    ch.execute(
        f"INSERT INTO {BACKFILL_QUEUE_TABLE} "
        "(request_id, created_at, from_minute, to_minute, jobs, include_observations, "
        "status, error, progress_job, progress_minute, updated_at) VALUES "
        f"({sql_string(request_id)}, parseDateTime64BestEffort({sql_string(created_at)}, 3, 'UTC'), "
        f"toDateTime('{fmt_dt(from_minute)}', 'UTC'), toDateTime('{fmt_dt(to_minute)}', 'UTC'), "
        f"{jobs_sql}, {int(include_observations)}, {sql_string(status)}, {sql_string(err)}, "
        f"{sql_string(progress_job)}, toDateTime('{fmt_dt(prog)}', 'UTC'), now64(3))",
        display=f"save queue {request_id} status={status}",
    )


def claim_queue_request(ch: ClickHouseClient, logger: logging.Logger) -> Optional[dict]:
    """Return one pending/running request (FINAL), or None."""
    rows = ch.query(
        f"""
        SELECT
          request_id,
          toString(created_at) AS created_at,
          from_minute,
          to_minute,
          arrayStringConcat(jobs, ',') AS jobs_csv,
          include_observations,
          status,
          progress_job,
          progress_minute
        FROM {BACKFILL_QUEUE_TABLE} FINAL
        WHERE status IN ('pending', 'running')
        ORDER BY
          if(status = 'running', 0, 1),
          created_at ASC
        LIMIT 1
        """,
        display="claim backfill queue request",
    )
    if not rows.strip():
        return None
    parts = rows.split("\t")
    if len(parts) < 9:
        logger.warning("malformed queue row: %s", rows[:200])
        return None
    jobs_csv = parts[4].strip()
    jobs = [j for j in jobs_csv.split(",") if j] if jobs_csv else list(DEFAULT_BACKFILL_JOBS)
    prog_raw = parts[8].strip()
    prog = None
    if prog_raw and prog_raw != "1970-01-01 00:00:00":
        prog = parse_utc_dt(prog_raw)
    return {
        "request_id": parts[0],
        "created_at": parts[1],
        "from_minute": parse_utc_dt(parts[2]),
        "to_minute": parse_utc_dt(parts[3]),
        "jobs": jobs,
        "include_observations": int(parts[5] or "0"),
        "status": parts[6],
        "progress_job": parts[7] or "",
        "progress_minute": prog,
    }


def iter_range_buckets(job: RollupJob, start: datetime, end: datetime) -> List[datetime]:
    """Closed buckets of job.bucket_kind that overlap [start, end)."""
    if end <= start:
        return []
    cur = truncate_bucket(start, job.bucket_kind)
    # If start is mid-bucket, still include that bucket (truncate already floored).
    out: List[datetime] = []
    while cur < end:
        out.append(cur)
        cur = add_bucket(cur, job.bucket_kind)
    return out


def run_range_backfill(
    ch: ClickHouseClient,
    logger: logging.Logger,
    jobs: Sequence[RollupJob],
    args: argparse.Namespace,
    *,
    range_from: datetime,
    range_to: datetime,
    resume_job: str = "",
    resume_minute: Optional[datetime] = None,
    wall_sec: int = 180,
    on_progress=None,
    cancel_check=None,
) -> Tuple[str, Optional[datetime], int, int, Optional[str]]:
    """
    Process [range_from, range_to) for jobs (priority order).
    Returns (next_job_id or '', next_minute or None, ok_count, fail_count, error).
    Empty next_job means finished. next_job '__cancelled__' means operator abort.
    """
    # Idempotency is handled per-bucket by run_bucket's probe: it deletes only
    # when the target bucket already has rows, then inserts. Do NOT force
    # delete_before_insert here — most backfill buckets are empty holes, and a
    # forced DELETE would fire one synchronous mutation per (bucket, job) even
    # for empty buckets, which is slow and hammers ClickHouse.
    args.delete_before_insert = False
    states = load_states(ch)
    started = time.monotonic()
    ok_count = 0
    fail_count = 0
    since_cancel_check = 0
    skipping = bool(resume_job)

    for job in jobs:
        # Never write a bucket that is still open. The bucket would be filled
        # from the part of it that exists right now, state would advance past it,
        # and the live runner only moves forward - so the target keeps a partial
        # bucket for good. This actually happened: a hand-run backfill whose
        # --range-to reached into the current hour left dns_client_domain_1h with
        # 15 of that hour's 83 queries and skipped the hour before it entirely.
        job_range_to = min(range_to, safe_until_for_job(job, args))
        if job_range_to < range_to:
            logger.info(
                "job=%s action=clamp_open_bucket requested_to=%s effective_to=%s",
                job.job_id,
                fmt_dt(range_to),
                fmt_dt(job_range_to),
            )

        if skipping:
            if job.job_id != resume_job:
                continue
            skipping = False
            bucket_list = iter_range_buckets(job, range_from, job_range_to)
            if resume_minute is not None:
                bucket_list = [b for b in bucket_list if b >= resume_minute]
        else:
            bucket_list = iter_range_buckets(job, range_from, job_range_to)

        if not bucket_list:
            logger.info(
                "job=%s action=range_empty from=%s to=%s",
                job.job_id,
                fmt_dt(range_from),
                fmt_dt(job_range_to),
            )
            continue

        # One range DELETE per job instead of a per-minute mutation. Live
        # catch-up no longer deletes (it skips existing buckets); rebuilds
        # still need the dest empty before INSERT. Wait for the mutation
        # ourselves — mutations_sync=1 plus an outer timeout orphans it.
        if not args.dry_run and job.pre_delete_sql and bucket_list:
            cap = max(1, int(getattr(args, "query_timeout_sec", 180) or 180))
            need = min(cap, QUEUE_MIN_BUDGET_SEC.get(job.bucket_kind, 20))
            left = remaining_budget_s(started, wall_sec)
            if left < need:
                logger.info(
                    "queue leftover too small before delete job=%s left=%.0fs need=%ss",
                    job.job_id,
                    left,
                    need,
                )
                if on_progress:
                    on_progress(job.job_id, bucket_list[0])
                return job.job_id, bucket_list[0], ok_count, fail_count, None
            col = bucket_column(job)
            lo_dt = f"toDateTime('{fmt_dt(bucket_list[0])}', 'UTC')"
            hi_dt = f"toDateTime('{fmt_dt(job_range_to)}', 'UTC')"
            try:
                has_rows = ch.query(
                    f"SELECT 1 FROM {job.dest_table} "
                    f"WHERE {col} >= {lo_dt} AND {col} < {hi_dt} LIMIT 1",
                    display=f"range idempotency probe for {job.job_id}",
                ).strip()
            except RuntimeError:
                has_rows = "1"  # probe failed → delete to stay idempotent
            if has_rows:
                pending = pending_mutations(ch, job.dest_table)
                if pending is None or pending > 0:
                    logger.info(
                        "job=%s action=defer reason=pending_mutations table=%s pending=%s",
                        job.job_id,
                        job.dest_table,
                        pending,
                    )
                    if on_progress:
                        on_progress(job.job_id, bucket_list[0])
                    return job.job_id, bucket_list[0], ok_count, fail_count, None
                logger.info(
                    "job=%s action=range_delete from=%s to=%s",
                    job.job_id,
                    fmt_dt(bucket_list[0]),
                    fmt_dt(job_range_to),
                )
                apply_query_timeout(
                    ch,
                    started,
                    wall_sec,
                    max(1, int(getattr(args, "query_timeout_sec", 180) or 180)),
                )
                ch.execute(
                    f"ALTER TABLE {job.dest_table} DELETE "
                    f"WHERE {col} >= {lo_dt} AND {col} < {hi_dt}",
                    display=f"range delete for {job.job_id}",
                )
                left = remaining_budget_s(started, wall_sec)
                wait_s = 120 if left == float("inf") else max(5, min(120, int(left)))
                try:
                    wait_table_mutations(
                        ch, logger, job.dest_table, timeout_s=wait_s
                    )
                except RuntimeError as exc:
                    msg = str(exc)
                    if is_retryable_queue_error(msg):
                        logger.info(
                            "job=%s action=defer reason=mutation_wait table=%s err=%s",
                            job.job_id,
                            job.dest_table,
                            msg,
                        )
                        if on_progress:
                            on_progress(job.job_id, bucket_list[0])
                        return job.job_id, bucket_list[0], ok_count, fail_count, None
                    return (
                        job.job_id,
                        bucket_list[0],
                        ok_count,
                        fail_count,
                        msg,
                    )

        for bucket_start in bucket_list:
            since_cancel_check += 1
            if cancel_check and since_cancel_check >= 25:
                since_cancel_check = 0
                if cancel_check():
                    logger.info(
                        "queue cancelled by operator job=%s bucket=%s ok=%s",
                        job.job_id,
                        fmt_dt(bucket_start),
                        ok_count,
                    )
                    return "__cancelled__", bucket_start, ok_count, fail_count, None

            if time.monotonic() - started >= wall_sec:
                logger.info(
                    "queue wall budget reached job=%s bucket=%s ok=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    ok_count,
                )
                if on_progress:
                    on_progress(job.job_id, bucket_start)
                return job.job_id, bucket_start, ok_count, fail_count, None

            cap = max(1, int(getattr(args, "query_timeout_sec", 180) or 180))
            need = min(cap, QUEUE_MIN_BUDGET_SEC.get(job.bucket_kind, 20))
            left = remaining_budget_s(started, wall_sec)
            if left < need:
                logger.info(
                    "queue leftover too small job=%s bucket=%s left=%.0fs need=%ss",
                    job.job_id,
                    fmt_dt(bucket_start),
                    left,
                    need,
                )
                if on_progress:
                    on_progress(job.job_id, bucket_start)
                return job.job_id, bucket_start, ok_count, fail_count, None
            apply_query_timeout(ch, started, wall_sec, cap)

            bucket_end = add_bucket(bucket_start, job.bucket_kind)
            ready, reason = dependency_ready(job, bucket_start, bucket_end, states)
            if not ready:
                # An hour/day bucket whose period has not closed yet (e.g. today's
                # 1d bucket during a mid-day gap fill) can NEVER satisfy its 1m
                # dependency until the period ends. Blocking on it would stall the
                # whole queue (and the observation rewind that runs after) for
                # hours. The live rollup builds such buckets when the period
                # closes, so skip them here instead of deferring forever.
                safe_point = utc_now() - timedelta(minutes=args.safety_lag_minutes)
                if bucket_end > safe_point:
                    logger.info(
                        "job=%s action=skip reason=period_open bucket=%s "
                        "bucket_end=%s > safe=%s (live rollup will build it)",
                        job.job_id,
                        fmt_dt(bucket_start),
                        fmt_dt(bucket_end),
                        fmt_dt(safe_point),
                    )
                    continue
                # Period is closed but the dependency is still catching up —
                # transient, re-check on the next tick.
                logger.warning(
                    "job=%s action=defer reason=dependency bucket=%s detail=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    reason,
                )
                if on_progress:
                    on_progress(job.job_id, bucket_start)
                return job.job_id, bucket_start, ok_count, fail_count, None

            if args.dry_run:
                logger.info(
                    "job=%s action=dry_run_range bucket=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                )
                ok_count += 1
                continue

            try:
                _, duration_ms, _ = run_bucket(ch, logger, job, bucket_start, args)
                state = states.get(job.job_id)
                # Advance live cursor only forward — never rewind it for a hole fill.
                if state is None or state.last_bucket is None or bucket_start > state.last_bucket:
                    save_state(ch, job.job_id, bucket_start, "ok", "", 0, duration_ms)
                    states[job.job_id] = JobState(
                        last_bucket=bucket_start, status="ok", last_error=""
                    )
                ok_count += 1
                if args.sleep_between_buckets > 0:
                    time.sleep(args.sleep_between_buckets)
            except JobDeferred as exc:
                logger.info(
                    "job=%s action=defer bucket=%s reason=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    exc,
                )
                if on_progress:
                    on_progress(job.job_id, bucket_start)
                return job.job_id, bucket_start, ok_count, fail_count, None
            except Exception as exc:
                msg = str(exc)
                if is_retryable_queue_error(msg):
                    logger.info(
                        "job=%s action=defer reason=query_timeout bucket=%s err=%s",
                        job.job_id,
                        fmt_dt(bucket_start),
                        msg,
                    )
                    if on_progress:
                        on_progress(job.job_id, bucket_start)
                    return job.job_id, bucket_start, ok_count, fail_count, None
                logger.error(
                    "job=%s bucket=%s status=error err=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    msg,
                )
                fail_count += 1
                return job.job_id, bucket_start, ok_count, fail_count, msg

    return "", None, ok_count, fail_count, None


def rewind_observations(
    logger: logging.Logger,
    from_minute: datetime,
    to_minute: datetime,
) -> None:
    script = "/app/bin/rewind-obs-for-backfill.js"
    if not os.path.isfile(script):
        logger.warning("observation rewind script missing: %s", script)
        return
    cmd = [
        "node",
        script,
        from_minute.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        to_minute.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    ]
    logger.info("rewinding observation cursors: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd="/app/analytics")
    if proc.returncode != 0:
        raise RuntimeError(
            f"observation rewind failed (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '').strip()}"
        )
    if proc.stdout:
        logger.info("observation rewind: %s", proc.stdout.strip()[:500])


def process_queue(args: argparse.Namespace, logger: logging.Logger) -> int:
    ch = ClickHouseClient(args)
    ensure_state_table(ch, logger)
    ensure_backfill_queue(ch, logger)

    if args.require_spool_drained and not args.dry_run:
        draining = spool_backlog_sources(
            ch,
            logger,
            max_lag_segments=args.spool_max_lag_segments,
            snapshot_max_age_sec=args.spool_snapshot_max_age_sec,
        )
        if draining:
            detail = ",".join(
                f"{s.source_id}:lag={s.lag_segments}(age={s.age_seconds}s)" for s in draining
            )
            logger.warning(
                "action=hold reason=spool_draining queue_paused sources=%s",
                detail,
            )
            return 0

    req = claim_queue_request(ch, logger)
    if not req:
        logger.info("backfill queue empty")
        return 0

    request_id = req["request_id"]

    def is_cancelled() -> bool:
        try:
            cur = ch.query(
                f"SELECT status FROM {BACKFILL_QUEUE_TABLE} FINAL "
                f"WHERE request_id = {sql_string(request_id)}",
                display="check queue cancel",
            ).strip()
        except RuntimeError:
            return False
        return cur == "cancelled"
    jobs_selected = req["jobs"] or list(DEFAULT_BACKFILL_JOBS)
    known = {j.job_id for j in sorted_jobs()}
    jobs_selected = [j for j in jobs_selected if j in known]
    jobs = sorted_jobs(jobs_selected)
    if not jobs:
        save_queue_row(
            ch,
            request_id=request_id,
            created_at=req["created_at"],
            from_minute=req["from_minute"],
            to_minute=req["to_minute"],
            jobs=req["jobs"],
            include_observations=req["include_observations"],
            status="error",
            error="no valid jobs",
        )
        return 1

    if req["status"] == "pending":
        save_queue_row(
            ch,
            request_id=request_id,
            created_at=req["created_at"],
            from_minute=req["from_minute"],
            to_minute=req["to_minute"],
            jobs=jobs_selected,
            include_observations=req["include_observations"],
            status="running",
            progress_job=jobs[0].job_id,
            progress_minute=truncate_bucket(req["from_minute"], jobs[0].bucket_kind),
        )
        req["progress_job"] = jobs[0].job_id
        req["progress_minute"] = truncate_bucket(req["from_minute"], jobs[0].bucket_kind)

    logger.info(
        "queue claim id=%s from=%s to=%s jobs=%s resume=%s@%s",
        request_id,
        fmt_dt(req["from_minute"]),
        fmt_dt(req["to_minute"]),
        ",".join(jobs_selected),
        req["progress_job"] or "-",
        fmt_dt(req["progress_minute"]) if req["progress_minute"] else "-",
    )

    def on_progress(job_id: str, minute: datetime) -> None:
        save_queue_row(
            ch,
            request_id=request_id,
            created_at=req["created_at"],
            from_minute=req["from_minute"],
            to_minute=req["to_minute"],
            jobs=jobs_selected,
            include_observations=req["include_observations"],
            status="running",
            progress_job=job_id,
            progress_minute=minute,
        )

    next_job, next_min, ok_count, fail_count, err = run_range_backfill(
        ch,
        logger,
        jobs,
        args,
        range_from=req["from_minute"],
        range_to=req["to_minute"],
        resume_job=req["progress_job"] or "",
        resume_minute=req["progress_minute"],
        wall_sec=max(30, int(args.queue_wall_sec)),
        on_progress=on_progress,
        cancel_check=is_cancelled,
    )

    if next_job == "__cancelled__":
        # Leave status='cancelled' as set by operator; do not overwrite.
        logger.info("queue cancelled id=%s ok=%s", request_id, ok_count)
        return 0

    if err:
        save_queue_row(
            ch,
            request_id=request_id,
            created_at=req["created_at"],
            from_minute=req["from_minute"],
            to_minute=req["to_minute"],
            jobs=jobs_selected,
            include_observations=req["include_observations"],
            status="error",
            error=err[:2000],
            progress_job=next_job or "",
            progress_minute=next_min,
        )
        return 1

    if next_job:
        on_progress(next_job, next_min or req["from_minute"])
        logger.info(
            "queue progress id=%s ok=%s next=%s@%s",
            request_id,
            ok_count,
            next_job,
            fmt_dt(next_min) if next_min else "-",
        )
        return 0

    # Traffic range done — optionally rewind observation cursors once.
    if req["include_observations"]:
        try:
            rewind_observations(logger, req["from_minute"], req["to_minute"])
        except Exception as exc:
            save_queue_row(
                ch,
                request_id=request_id,
                created_at=req["created_at"],
                from_minute=req["from_minute"],
                to_minute=req["to_minute"],
                jobs=jobs_selected,
                include_observations=req["include_observations"],
                status="error",
                error=f"traffic ok; observation rewind failed: {exc}"[:2000],
            )
            return 1

    save_queue_row(
        ch,
        request_id=request_id,
        created_at=req["created_at"],
        from_minute=req["from_minute"],
        to_minute=req["to_minute"],
        jobs=jobs_selected,
        include_observations=req["include_observations"],
        status="done",
        progress_job="",
        progress_minute=None,
    )
    logger.info("queue done id=%s ok_buckets=%s", request_id, ok_count)
    return 0


def live_job_step(
    ch: ClickHouseClient,
    logger: logging.Logger,
    job: RollupJob,
    args: argparse.Namespace,
    states: Dict[str, JobState],
    raw_min_cache: Dict[str, Optional[datetime]],
    *,
    started: float,
    wall_sec: int,
    window_buckets: int,
) -> str:
    """Process one live window. Returns ok|skip|defer|error|wall|rewound."""
    if not dest_table_exists(ch, job):
        logger.warning(
            "job=%s action=skip reason=missing_dest_table table=%s",
            job.job_id,
            job.dest_table,
        )
        return "skip"
    if remaining_budget_s(started, wall_sec) < 3:
        return "wall"
    # Pass 1 skips hour/day. Pass 2 may still have <35s left; do not refuse
    # here — apply_query_timeout caps the query, and a timeout is deferred
    # without marking the job error.
    cap = max(1, int(getattr(args, "query_timeout_sec", 180) or 180))
    apply_query_timeout(ch, started, wall_sec, cap)

    job_until = safe_until_for_job(job, args)
    state = states.get(job.job_id)
    clamped = clamp_future_last_bucket(
        job,
        state,
        now=utc_now(),
        safety_lag_minutes=args.safety_lag_minutes,
    )
    if clamped is not None:
        logger.warning(
            "job=%s action=clamp_future last_bucket=%s now=%s new_last=%s",
            job.job_id,
            fmt_dt(state.last_bucket) if state and state.last_bucket else "-",
            fmt_dt(utc_now()),
            fmt_dt(clamped),
        )
        if not args.dry_run:
            save_state(ch, job.job_id, clamped, "clamp_future", "", 0, 0)
        state = JobState(last_bucket=clamped, status="clamp_future", last_error="")
        states[job.job_id] = state

    bucket_start = next_bucket(
        job,
        state,
        ch,
        args.bootstrap_days,
        args.safety_lag_minutes,
    )
    bucket_start = skip_forward_stale_bucket(
        ch,
        logger,
        job,
        bucket_start,
        states,
        bootstrap_days=args.bootstrap_days,
        raw_min_cache=raw_min_cache,
    )
    state = states.get(job.job_id)

    if bucket_start >= job_until:
        rewound = rewind_if_dest_lags_raw(
            ch,
            logger,
            job,
            bucket_start,
            job_until,
            states,
            safety_lag_minutes=args.safety_lag_minutes,
            raw_max_cache=raw_min_cache,
            dry_run=args.dry_run,
        )
        if rewound < job_until:
            return "rewound"
        logger.info(
            "job=%s action=skip reason=safe_lag bucket=%s safe_until=%s",
            job.job_id,
            fmt_dt(bucket_start),
            fmt_dt(job_until),
        )
        if not args.dry_run:
            heartbeat = (
                state.last_bucket
                if state and state.last_bucket
                else subtract_bucket(bucket_start, job.bucket_kind)
            )
            save_state(ch, job.job_id, heartbeat, "ok", "", 0, 0)
            states[job.job_id] = JobState(
                last_bucket=heartbeat,
                status="ok",
                last_error="",
            )
        return "skip"

    window_end = bucket_start
    for _ in range(max(1, int(window_buckets))):
        nxt = add_bucket(window_end, job.bucket_kind)
        if nxt > job_until:
            break
        window_end = nxt
    if window_end <= bucket_start:
        window_end = add_bucket(bucket_start, job.bucket_kind)
    if window_end > job_until:
        window_end = job_until

    while window_end > bucket_start:
        ready, reason = dependency_ready(job, bucket_start, window_end, states)
        if ready:
            break
        if add_bucket(bucket_start, job.bucket_kind) == window_end:
            logger.warning(
                "job=%s action=skip reason=dependency bucket=%s detail=%s",
                job.job_id,
                fmt_dt(bucket_start),
                reason,
            )
            return "skip"
        window_end = subtract_bucket(window_end, job.bucket_kind)
        window_end = truncate_bucket(window_end, job.bucket_kind)

    if args.dry_run:
        last = truncate_bucket(
            subtract_bucket(window_end, job.bucket_kind), job.bucket_kind
        )
        logger.info(
            "job=%s action=dry_run from=%s to=%s dest=%s",
            job.job_id,
            fmt_dt(bucket_start),
            fmt_dt(window_end),
            job.dest_table,
        )
        states[job.job_id] = JobState(
            last_bucket=last,
            status="dry_run",
            last_error="",
        )
        return "ok"

    try:
        last, duration_ms, action = run_window(
            ch, logger, job, bucket_start, window_end, args
        )
        save_state(ch, job.job_id, last, "ok", "", 0, duration_ms)
        states[job.job_id] = JobState(
            last_bucket=last,
            status="ok",
            last_error="",
        )
        if action == "skip_existing":
            logger.info(
                "job=%s action=skip_existing committed=%s",
                job.job_id,
                fmt_dt(last),
            )
        if args.sleep_between_buckets > 0:
            time.sleep(args.sleep_between_buckets)
        return "ok"
    except JobDeferred as exc:
        logger.info(
            "job=%s action=defer bucket=%s reason=%s",
            job.job_id,
            fmt_dt(bucket_start),
            exc,
        )
        return "defer"
    except Exception as exc:
        msg = str(exc)
        logger.error(
            "job=%s bucket=%s status=error err=%s",
            job.job_id,
            fmt_dt(bucket_start),
            msg,
        )
        if "timed out" in msg.lower():
            logger.info(
                "job=%s action=defer reason=query_timeout bucket=%s",
                job.job_id,
                fmt_dt(bucket_start),
            )
            return "defer"
        prev = state.last_bucket if state and state.last_bucket else subtract_bucket(
            bucket_start, job.bucket_kind
        )
        try:
            save_state(ch, job.job_id, prev, "error", msg, 0, 0)
        except Exception as save_exc:
            logger.error(
                "job=%s failed to persist error state: %s",
                job.job_id,
                save_exc,
            )
        states[job.job_id] = JobState(
            last_bucket=prev,
            status="error",
            last_error=msg,
        )
        return "error"


def _live_lag_seconds(
    job: RollupJob,
    states: Dict[str, JobState],
    args: argparse.Namespace,
    ch: ClickHouseClient,
    blocked: set,
) -> float:
    if job.job_id in blocked:
        return 0.0
    state = states.get(job.job_id)
    job_until = safe_until_for_job(job, args)
    try:
        bucket_start = next_bucket(
            job, state, ch, args.bootstrap_days, args.safety_lag_minutes
        )
    except Exception:
        return 0.0
    if bucket_start >= job_until:
        return 0.0
    ready, _ = dependency_ready(
        job, bucket_start, add_bucket(bucket_start, job.bucket_kind), states
    )
    if not ready:
        return 0.0
    return max(0.0, (job_until - bucket_start).total_seconds())


def run_live(args: argparse.Namespace, logger: logging.Logger) -> int:
    selected = [item.strip() for item in args.jobs.split(",") if item.strip()] or None
    if selected:
        known = {job.job_id for job in sorted_jobs()}
        unknown = sorted(set(selected) - known)
        if unknown:
            logger.error("unknown jobs requested: %s", ",".join(unknown))
            return 2
    jobs = sorted_jobs(selected)
    if not jobs:
        logger.error("no jobs selected")
        return 2

    if args.range_from or args.range_to:
        if not args.range_from or not args.range_to:
            logger.error("both --range-from and --range-to are required")
            return 2
        range_from = parse_utc_dt(args.range_from)
        range_to = parse_utc_dt(args.range_to)
        if range_to <= range_from:
            logger.error("range-to must be after range-from")
            return 2
        ch = ClickHouseClient(args)
        ensure_state_table(ch, logger)
        if args.require_spool_drained and not args.dry_run:
            draining = spool_backlog_sources(
                ch,
                logger,
                max_lag_segments=args.spool_max_lag_segments,
                snapshot_max_age_sec=args.spool_snapshot_max_age_sec,
            )
            if draining:
                logger.warning("range backfill held: spool still draining")
                return 0
        next_job, _, ok_count, fail_count, err = run_range_backfill(
            ch,
            logger,
            jobs,
            args,
            range_from=range_from,
            range_to=range_to,
            wall_sec=max(60, int(args.queue_wall_sec) * 10),
        )
        if err:
            logger.error("range backfill error: %s", err)
            return 1
        if next_job:
            logger.warning("range backfill incomplete (wall); resume via queue")
            return 1
        logger.info("range backfill complete ok=%s failed=%s", ok_count, fail_count)
        return 1 if fail_count else 0

    ch = ClickHouseClient(args)
    started = time.monotonic()
    ok_count = 0
    skip_count = 0
    fail_count = 0

    try:
        ensure_state_table(ch, logger)
    except RuntimeError as exc:
        logger.error("precheck failed: %s", exc)
        return 1

    if not args.allow_attached_mv:
        attached = check_attached_mvs(ch)
        if attached > 0:
            logger.error(
                "found %s attached traffic_* MaterializedView tables; "
                "detach them first or pass --allow-attached-mv",
                attached,
            )
            return 1
        logger.info("precheck ok: no attached traffic_* MV")

    if not args.ignore_raw_lag and not args.dry_run:
        lag_s = raw_lag_seconds(ch)
        if lag_s > args.max_raw_lag_seconds:
            logger.warning(
                "skip rollups: flows_raw lag_s=%s exceeds max_raw_lag_seconds=%s "
                "(wait for spool catch-up or pass --ignore-raw-lag)",
                lag_s,
                args.max_raw_lag_seconds,
            )
            return 0
        logger.info("precheck ok: flows_raw lag_s=%s", lag_s)

    if args.require_spool_drained and not args.dry_run:
        draining = spool_backlog_sources(
            ch,
            logger,
            max_lag_segments=args.spool_max_lag_segments,
            snapshot_max_age_sec=args.spool_snapshot_max_age_sec,
        )
        if draining:
            detail = ",".join(
                f"{s.source_id}:lag={s.lag_segments}(age={s.age_seconds}s)" for s in draining
            )
            logger.warning(
                "action=hold reason=spool_draining sources=%s "
                "(flows_raw incomplete for recent buckets; holding cursor until drained)",
                detail,
            )
            return 0
        logger.info("precheck ok: collector spool drained")

    states = load_states(ch)
    until = safe_until(args)
    raw_min_cache: Dict[str, Optional[datetime]] = {}
    rewind_minutes = max(0, int(getattr(args, "rewind_minutes", 0) or 0))
    if rewind_minutes > 0:
        target = truncate_bucket(utc_now() - timedelta(minutes=rewind_minutes), "minute")
        new_last = subtract_bucket(target, "minute")
        for job in jobs:
            if job.bucket_kind != "minute":
                continue
            logger.info(
                "job=%s action=rewind_minutes last_bucket=%s",
                job.job_id,
                fmt_dt(new_last),
            )
            if not args.dry_run:
                save_state(ch, job.job_id, new_last, "rewind", "", 0, 0)
            states[job.job_id] = JobState(
                last_bucket=new_last,
                status="rewind",
                last_error="",
            )
    max_range = max(
        1,
        int(getattr(args, "max_range_buckets", 15) or 15),
        int(getattr(args, "max_buckets_per_job", 1) or 1),
    )
    logger.info(
        "run start jobs=%s max_range_buckets=%s sleep_between_buckets=%s "
        "safe_until=%s live_wall_s=%s dry_run=%s",
        ",".join(job.job_id for job in jobs),
        max_range,
        args.sleep_between_buckets,
        fmt_dt(until),
        int(args.live_wall_sec or 0),
        args.dry_run,
    )

    wall_sec = max(0, int(args.live_wall_sec or 0))
    wall_reached = False
    blocked: set = set()

    def _step(job: RollupJob, window_buckets: int) -> str:
        return live_job_step(
            ch,
            logger,
            job,
            args,
            states,
            raw_min_cache,
            started=started,
            wall_sec=wall_sec,
            window_buckets=window_buckets,
        )

    # Pass 1: every minute job gets one bucket so a lagging head cannot
    # starve the 1m tail. Hour/day wait for pass 2 — they used to be
    # deferred+blocked here and then never ran.
    for job in jobs:
        if job.bucket_kind in ("hour", "day"):
            continue
        if remaining_budget_s(started, wall_sec) < 3:
            wall_reached = True
            logger.info(
                "action=stop reason=live_wall wall_s=%s ok=%s pass=fair",
                wall_sec,
                ok_count,
            )
            break
        result = _step(job, 1)
        if result == "rewound":
            result = _step(job, 1)
        if result == "ok":
            ok_count += 1
        elif result == "skip":
            skip_count += 1
        elif result == "defer":
            skip_count += 1
            blocked.add(job.job_id)
        elif result == "error":
            fail_count += 1
            blocked.add(job.job_id)
        elif result == "wall":
            wall_reached = True
            break

    # Pass 2: remaining budget goes to the most lagging writable job, as a range.
    while not wall_reached and remaining_budget_s(started, wall_sec) >= 3:
        best: Optional[RollupJob] = None
        best_lag = 0.0
        for job in jobs:
            lag = _live_lag_seconds(job, states, args, ch, blocked)
            if lag > best_lag:
                best_lag = lag
                best = job
        if best is None:
            break
        result = _step(best, max_range)
        if result == "rewound":
            result = _step(best, max_range)
        if result == "ok":
            ok_count += 1
        elif result == "skip":
            skip_count += 1
            blocked.add(best.job_id)
        elif result == "defer":
            skip_count += 1
            blocked.add(best.job_id)
        elif result == "error":
            fail_count += 1
            blocked.add(best.job_id)
        elif result == "wall":
            wall_reached = True
            break

    elapsed = time.monotonic() - started
    logger.info(
        "run complete ok=%s skipped=%s failed=%s elapsed_s=%.1f wall_reached=%s",
        ok_count,
        skip_count,
        fail_count,
        elapsed,
        wall_reached,
    )
    return 1 if fail_count else 0


def main() -> int:
    args = parse_args()
    args.clickhouse_client = resolve_clickhouse_client(args.clickhouse_client)
    log_file = None if args.no_log_file else args.log_file
    logger = setup_logging(log_file, args.verbose)

    if not os.path.isfile(args.clickhouse_client):
        logger.error("clickhouse-client not found: %s", args.clickhouse_client)
        return 2

    if args.process_queue:
        return process_queue(args, logger)
    return run_live(args, logger)


if __name__ == "__main__":
    sys.exit(main())
