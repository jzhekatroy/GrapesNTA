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

Before first run, create state table:

  clickhouse-client ... --multiquery < deploy/clickhouse/traffic_rollup_state.sql

Keep all traffic_*_mv detached while this script is the rollup source.
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
        return (proc.stdout or "").strip()

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
        if len(parts) < 4:
            continue
        job, bucket_raw, status, last_error = parts[0], parts[1], parts[2], parts[3]
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
        "FROM default.flows_raw",
        display="flows_raw lag seconds",
    )
    return int(value or "0")


def bootstrap_bucket(ch: ClickHouseClient, job: RollupJob, days: int) -> datetime:
    col = job.time_column
    table = job.source_table
    if job.bucket_kind == "minute":
        expr = f"toStartOfMinute({col})"
    elif job.bucket_kind == "hour":
        expr = f"toStartOfHour({col})"
    else:
        expr = f"toStartOfDay({col})"
    sql = (
        f"SELECT ifNull(min({expr}), toDateTime('1970-01-01 00:00:00', 'UTC')) "
        f"FROM {table}"
    )
    raw = ch.query(sql, display=f"bootstrap min bucket for {job.job_id}")
    if raw == "1970-01-01 00:00:00":
        return truncate_bucket(utc_now() - timedelta(days=days), job.bucket_kind)
    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    floor = truncate_bucket(utc_now() - timedelta(days=days), job.bucket_kind)
    return dt if dt > floor else floor


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


def build_time_filter(job: RollupJob, start: datetime, end: datetime) -> str:
    start_s = fmt_dt(start)
    end_s = fmt_dt(end)
    col = job.time_filter_column or job.time_column
    if col in ("time_received_ns", "time_flow_start_ns"):
        return (
            f"{col} >= toDateTime64('{start_s}', 9, 'UTC') "
            f"AND {col} < toDateTime64('{end_s}', 9, 'UTC')"
        )
    return (
        f"{col} >= toDateTime('{start_s}', 'UTC') "
        f"AND {col} < toDateTime('{end_s}', 'UTC')"
    )


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

    if args.delete_before_insert and job.pre_delete_sql:
        delete_sql = job.pre_delete_sql.format(bucket_dt=bucket_dt)
        logger.info("job=%s action=delete bucket=%s", job.job_id, fmt_dt(bucket_start))
        ch.execute(delete_sql, display=f"delete bucket for {job.job_id}")

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
) -> datetime:
    if state is None or state.last_bucket is None:
        start = bootstrap_bucket(ch, job, bootstrap_days)
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
        "--bootstrap-days",
        type=int,
        default=int(env("TRAFFIC_ROLLUP_BOOTSTRAP_DAYS", "7") or "7"),
    )
    parser.add_argument(
        "--delete-before-insert",
        action="store_true",
        default=(env("TRAFFIC_ROLLUP_DELETE_BEFORE_INSERT", "0") or "0").lower()
        in ("1", "true", "yes", "on"),
        help="delete target bucket before insert (slower, idempotent rebuild)",
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.clickhouse_client = resolve_clickhouse_client(args.clickhouse_client)
    log_file = None if args.no_log_file else args.log_file
    logger = setup_logging(log_file, args.verbose)

    if not os.path.isfile(args.clickhouse_client):
        logger.error("clickhouse-client not found: %s", args.clickhouse_client)
        return 2

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

    states = load_states(ch)
    until = safe_until(args)
    logger.info(
        "run start jobs=%s max_buckets_per_job=%s safe_until=%s dry_run=%s",
        ",".join(job.job_id for job in jobs),
        args.max_buckets_per_job,
        fmt_dt(until),
        args.dry_run,
    )

    for job in jobs:
        processed = 0
        job_until = safe_until_for_job(job, args)
        while processed < args.max_buckets_per_job:
            state = states.get(job.job_id)
            bucket_start = next_bucket(job, state, ch, args.bootstrap_days)
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


if __name__ == "__main__":
    sys.exit(main())
