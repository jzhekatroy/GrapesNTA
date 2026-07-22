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

  clickhouse-client ... --multiquery < deploy/clickhouse/traffic_rollup_state.sql
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


@dataclass
class JobState:
    last_bucket: Optional[datetime]
    status: str
    last_error: str


class ClickHouseClient:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base = self._base_cmd(args)

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
        proc = subprocess.run(
            self.base + ["--query", sql],
            capture_output=True,
            text=True,
        )
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
        parent = os.path.dirname(log_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

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
            "deploy/clickhouse/traffic_rollup_state.sql first"
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
        f"'{status}', '{err}', {rows_written}, {duration_ms}, now())"
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
    col = job.time_column
    table = job.source_table
    if job.bucket_kind == "minute":
        expr = f"toStartOfMinute({col})"
    elif job.bucket_kind == "hour":
        expr = f"toStartOfHour({col})"
    else:
        expr = f"toStartOfDay({col})"
    # Bound by retention window — full-history min() on flows_raw is too expensive
    # on high-EPS stands and was burning ClickHouse CPU every rollup tick.
    lookback = max(int(days), 1)
    if table == "default.flows_raw":
        sql = (
            f"SELECT ifNull(min({expr}), toDateTime('1970-01-01 00:00:00', 'UTC')) "
            f"FROM {table} "
            f"WHERE date >= today() - {lookback}"
        )
    else:
        sql = (
            f"SELECT ifNull(min({expr}), toDateTime('1970-01-01 00:00:00', 'UTC')) "
            f"FROM {table}"
        )
    raw = ch.query(sql, display=f"bootstrap min bucket for {job.job_id}")
    if raw == "1970-01-01 00:00:00":
        # Fresh stand: do not backfill empty bootstrap_days of silent buckets.
        return truncate_bucket(
            utc_now() - timedelta(minutes=safety_lag_minutes),
            job.bucket_kind,
        )
    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    floor = truncate_bucket(utc_now() - timedelta(days=days), job.bucket_kind)
    return dt if dt > floor else floor


def flows_raw_enabled_min_bucket(
    ch: ClickHouseClient,
    job: RollupJob,
    *,
    lookback_days: int = 7,
    cache: Optional[Dict[str, Optional[datetime]]] = None,
) -> Optional[datetime]:
    """Earliest bucket in flows_raw for enabled catalog sources (bounded + cached)."""
    if job.source_table != "default.flows_raw":
        return None
    cache_key = f"{job.bucket_kind}:{lookback_days}"
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    # time_filter_column may be aliased (f.time_received_ns); this query has no alias.
    col = (job.time_filter_column or job.time_column).split(".")[-1]
    if job.bucket_kind == "minute":
        expr = f"toStartOfMinute({col})"
    elif job.bucket_kind == "hour":
        expr = f"toStartOfHour({col})"
    else:
        expr = f"toStartOfDay({col})"
    lookback = max(int(lookback_days), 1)
    raw = ch.query(
        f"SELECT ifNull(min({expr}), toDateTime('1970-01-01 00:00:00', 'UTC')) "
        "FROM default.flows_raw "
        f"WHERE date >= today() - {lookback} "
        "AND source_id IN (SELECT source_id FROM default.net_flow_sources_enabled)",
        display=f"enabled flows_raw min bucket for {job.job_id}",
    )
    if raw == "1970-01-01 00:00:00":
        result = None
    else:
        result = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
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
    # Steady-state / near-realtime cursor: never pay for a global min() scan.
    # skip_forward only matters when state is stuck far behind the first real data.
    if bucket_start >= utc_now() - timedelta(days=2):
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


def run_bucket(
    ch: ClickHouseClient,
    logger: logging.Logger,
    job: RollupJob,
    bucket_start: datetime,
    args: argparse.Namespace,
) -> Tuple[bool, int, str]:
    bucket_end = add_bucket(bucket_start, job.bucket_kind)
    time_filter = build_time_filter(job, bucket_start, bucket_end)
    bucket_dt = f"toDateTime('{fmt_dt(bucket_start)}', 'UTC')"
    bucket_col = bucket_column(job)

    # Idempotent write: a rollup bucket must never be summed twice into the
    # SummingMergeTree target. The target only ADDS rows, so any reprocessing of
    # a bucket that already has rows silently inflates every metric (this is what
    # caused the historical ~6-9x over-count). Guarantee exactly-once per bucket:
    #
    #   * steady-state forward run  -> bucket is brand new, the probe below hits
    #     no primary-key granule and returns instantly, so no delete happens
    #     (mutations stay off the hot path);
    #   * reprocessing (manual backfill, state re-bootstrap, or a crash between
    #     INSERT and state commit) -> the bucket already has rows, so we delete
    #     them before re-inserting.
    #
    # --delete-before-insert forces the delete unconditionally (explicit rebuild)
    # and skips the probe. bucket_col is the first ORDER BY column of every target
    # table, so both the probe and the DELETE predicate are primary-key scoped.
    needs_delete = bool(args.delete_before_insert)
    delete_reason = "flag"
    if not needs_delete and job.pre_delete_sql:
        existing = ch.query(
            f"SELECT 1 FROM {job.dest_table} WHERE {bucket_col} = {bucket_dt} LIMIT 1",
            display=f"idempotency probe for {job.job_id}",
        )
        if existing.strip() != "":
            needs_delete = True
            delete_reason = "bucket_exists"

    if needs_delete and job.pre_delete_sql:
        delete_sql = job.pre_delete_sql.format(bucket_dt=bucket_dt)
        # Make the DELETE synchronous so we don't depend on reading
        # system.mutations afterwards (the worker's ui_admin user may lack
        # SELECT on system.mutations, which otherwise fails the wait step).
        delete_sql = f"{delete_sql} SETTINGS mutations_sync = 1"
        logger.info(
            "job=%s action=delete bucket=%s reason=%s",
            job.job_id,
            fmt_dt(bucket_start),
            delete_reason,
        )
        ch.execute(delete_sql, display=f"delete bucket for {job.job_id}")
        # mutations_sync=1 already waited for completion; poll only as a
        # best-effort and never fail the bucket if system.mutations is denied.
        try:
            wait_table_mutations(ch, logger, job.dest_table)
        except RuntimeError as exc:
            logger.warning(
                "job=%s action=wait_mutations_skipped detail=%s",
                job.job_id,
                str(exc).splitlines()[0][:200],
            )

    select_sql = job.select_sql.format(time_filter=time_filter)
    insert_sql = f"INSERT INTO {job.dest_table}\n{select_sql}"

    source_rows = None
    if args.preflight_count:
        source_rows = count_source_rows(ch, job, time_filter)
        if source_rows is not None:
            logger.info(
                "job=%s bucket=%s source_rows=%s",
                job.job_id,
                fmt_dt(bucket_start),
                source_rows,
            )

    started = time.monotonic()
    ch.execute(insert_sql, display=f"insert rollup for {job.job_id} {fmt_dt(bucket_start)}")
    duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "job=%s bucket=%s status=ok duration_ms=%s source_rows=%s",
        job.job_id,
        fmt_dt(bucket_start),
        duration_ms,
        source_rows if source_rows is not None else "unknown",
    )
    return True, duration_ms, ""


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
    return parser.parse_args()


DEFAULT_BACKFILL_JOBS = [
    "traffic_dashboard_1m",
    "traffic_protocol_1m",
    "traffic_direction_1m",
    "traffic_role_1m",
    "traffic_entity_1m",
    "traffic_vlan_1m",
    "traffic_country_1m",
    "traffic_service_1m",
    "traffic_unknown_port_1m",
    "traffic_asn_1m",
    "traffic_asn_pair_1m",
    "traffic_dashboard_1h",
    "traffic_asn_1h",
    "traffic_asn_pair_1h",
    "traffic_dashboard_1d",
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
    # Force idempotent rewrite of existing buckets in the hole.
    args.delete_before_insert = True
    states = load_states(ch)
    started = time.monotonic()
    ok_count = 0
    fail_count = 0
    since_cancel_check = 0
    skipping = bool(resume_job)

    for job in jobs:
        if skipping:
            if job.job_id != resume_job:
                continue
            skipping = False
            bucket_list = iter_range_buckets(job, range_from, range_to)
            if resume_minute is not None:
                bucket_list = [b for b in bucket_list if b >= resume_minute]
        else:
            bucket_list = iter_range_buckets(job, range_from, range_to)

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

            bucket_end = add_bucket(bucket_start, job.bucket_kind)
            ready, reason = dependency_ready(job, bucket_start, bucket_end, states)
            if not ready:
                # Hourly/daily may wait on 1m — re-check later.
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
            except Exception as exc:
                msg = str(exc)
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
    logger.info(
        "run start jobs=%s max_buckets_per_job=%s sleep_between_buckets=%s safe_until=%s dry_run=%s",
        ",".join(job.job_id for job in jobs),
        args.max_buckets_per_job,
        args.sleep_between_buckets,
        fmt_dt(until),
        args.dry_run,
    )

    for job in jobs:
        processed = 0
        job_until = safe_until_for_job(job, args)
        while processed < args.max_buckets_per_job:
            state = states.get(job.job_id)
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
            bucket_end = add_bucket(bucket_start, job.bucket_kind)

            if bucket_start >= job_until:
                logger.info(
                    "job=%s action=skip reason=safe_lag bucket=%s safe_until=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    fmt_dt(job_until),
                )
                skip_count += 1
                break

            ready, reason = dependency_ready(job, bucket_start, bucket_end, states)
            if not ready:
                logger.warning(
                    "job=%s action=skip reason=dependency bucket=%s detail=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    reason,
                )
                skip_count += 1
                break

            if args.dry_run:
                logger.info(
                    "job=%s action=dry_run bucket=%s dest=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    job.dest_table,
                )
                ok_count += 1
                processed += 1
                states[job.job_id] = JobState(
                    last_bucket=bucket_start,
                    status="dry_run",
                    last_error="",
                )
                continue

            try:
                _, duration_ms, _ = run_bucket(ch, logger, job, bucket_start, args)
                save_state(ch, job.job_id, bucket_start, "ok", "", 0, duration_ms)
                states[job.job_id] = JobState(
                    last_bucket=bucket_start,
                    status="ok",
                    last_error="",
                )
                ok_count += 1
                processed += 1
                if args.sleep_between_buckets > 0:
                    time.sleep(args.sleep_between_buckets)
            except Exception as exc:
                msg = str(exc)
                logger.error(
                    "job=%s bucket=%s status=error err=%s",
                    job.job_id,
                    fmt_dt(bucket_start),
                    msg,
                )
                try:
                    save_state(ch, job.job_id, bucket_start, "error", msg, 0, 0)
                except Exception as save_exc:
                    logger.error(
                        "job=%s failed to persist error state: %s",
                        job.job_id,
                        save_exc,
                    )
                states[job.job_id] = JobState(
                    last_bucket=state.last_bucket if state else None,
                    status="error",
                    last_error=msg,
                )
                fail_count += 1
                break

    elapsed = time.monotonic() - started
    logger.info(
        "run complete ok=%s skipped=%s failed=%s elapsed_s=%.1f",
        ok_count,
        skip_count,
        fail_count,
        elapsed,
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
