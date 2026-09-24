#!/usr/bin/env python3
"""
Прореживание старых суток flows_raw (тёплое хранение).

Последние hot_days полных суток и текущие хранятся точно. В более старых
сутках мелкие потоки источников xdpflowd (bytes < порога) оставляются с
вероятностью 1/rate, а у оставшихся bytes, packets и sampling_rate умножаются
на rate. Суммы трафика сохраняются, число строк падает в десятки раз.
NetFlow и sFlow не трогаются: их потоки и так выборочные или агрегированные.

Проверка на копии суток m61, 24 сентября 2026, 1:64 и порог 100 КБ:
151 ГиБ -> 4.5 ГиБ, мутация 8 минут, расхождение сумм за сутки 0.002%.
Подробности в docs/HOT_COLD_STORAGE_PLAN.md.

Запускается из cron worker каждые 30 минут. За ночь берёт одни сутки,
работает только в окне run_at + 3 часа, настройки читает из
default.app_flow_storage_settings, каждое действие пишет в
default.flow_thinning_log.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from traffic_rollup_async import (  # noqa: E402
    ClickHouseClient,
    env,
    resolve_clickhouse_client,
    setup_logging,
    split_table_name,
    sql_string,
)

SETTINGS_TABLE = "default.app_flow_storage_settings"
LOG_TABLE = "default.flow_thinning_log"
SOURCES_VIEW = "default.net_flow_sources_enabled"

RATES = (4, 16, 64, 256)
MODES = ("off", "dry_run", "on")
MIN_THRESHOLD_BYTES = 1000
WINDOW_HOURS = 3
MUTATION_MAX_AGE = timedelta(hours=3)
# Сводки, не обновлявшиеся дольше, считаются отключёнными и не ждут.
ROLLUP_STALE_AFTER = timedelta(days=1)
# Мутация переписывает часть целиком, пока старая ещё на диске.
DISK_RESERVE = 1.2

# Хеш включает время и размер: sequence_num у xdpflowd всегда 0, и без них все
# потоки одной пары адресов и портов за сутки попадали бы в выборку или мимо
# неё целиком. На копии суток это давало ICMP -7% и ICMPv6 -22%.
KEEP_HASH = (
    "cityHash64(src_addr, dst_addr, src_port, dst_port, proto, "
    "sequence_num, time_received_ns, bytes)"
)


@dataclass(frozen=True)
class Settings:
    mode: str = "off"
    hot_days: int = 1
    xdp_rate: int = 64
    xdp_threshold_bytes: int = 100000
    run_at: str = "04:30"


@dataclass(frozen=True)
class LogRow:
    day: date
    status: str
    mode: str = ""
    source_ids: Tuple[str, ...] = ()
    rate: int = 0
    threshold_bytes: int = 0
    rows_before: int = 0
    bytes_before: int = 0
    eligible_rows: int = 0
    mutation_id: str = ""
    started_at: Optional[datetime] = None
    message: str = ""


@dataclass(frozen=True)
class Partition:
    day: date
    rows: int
    bytes_on_disk: int
    max_part_bytes: int
    disk_name: str


def parse_run_at(value: str) -> Optional[Tuple[int, int]]:
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*", str(value or ""))
    if not m:
        return None
    hh, mm = int(m.group(1)), int(m.group(2))
    if hh > 23 or mm > 59:
        return None
    return hh, mm


def parse_settings(row: Optional[dict]) -> Tuple[Settings, str]:
    """Настройки из строки таблицы. Неверные значения выключают прореживание."""
    base = Settings()
    if not row:
        return base, ""
    try:
        s = Settings(
            mode=str(row.get("mode") or base.mode),
            hot_days=int(row.get("hot_days", base.hot_days)),
            xdp_rate=int(row.get("xdp_rate", base.xdp_rate)),
            xdp_threshold_bytes=int(row.get("xdp_threshold_bytes", base.xdp_threshold_bytes)),
            run_at=str(row.get("run_at") or base.run_at),
        )
    except (TypeError, ValueError) as exc:
        return base, f"настройки не читаются: {exc}"
    problems = []
    if s.mode not in MODES:
        problems.append(f"режим {s.mode!r}")
    if s.hot_days < 1:
        problems.append(f"hot_days={s.hot_days}")
    if s.xdp_rate not in RATES:
        problems.append(f"xdp_rate={s.xdp_rate}")
    if s.xdp_threshold_bytes < MIN_THRESHOLD_BYTES:
        problems.append(f"порог {s.xdp_threshold_bytes}")
    if parse_run_at(s.run_at) is None:
        problems.append(f"run_at={s.run_at!r}")
    if problems:
        return base, "неверные настройки: " + ", ".join(problems)
    return s, ""


def in_window(now_local: datetime, run_at: str, hours: int = WINDOW_HOURS) -> bool:
    hm = parse_run_at(run_at)
    if hm is None:
        return False
    start = now_local.replace(hour=hm[0], minute=hm[1], second=0, microsecond=0)
    # Окно может переходить через полночь: 23:00 + 3 ч.
    for candidate in (start, start - timedelta(days=1)):
        if candidate <= now_local < candidate + timedelta(hours=hours):
            return True
    return False


def ttl_days_from_ddl(ddl: str) -> Optional[int]:
    for pattern in (
        r"TTL\s+.+?\+\s*toIntervalDay\((\d+)\)",
        r"TTL\s+.+?\+\s*INTERVAL\s+(\d+)\s+DAY",
    ):
        m = re.search(pattern, ddl or "", re.IGNORECASE)
        if m:
            return int(m.group(1))
    return None


def taken_statuses(mode: str) -> Tuple[str, ...]:
    # running и done не берутся никогда: второй проход снова умножил бы потоки.
    # dry_run не мешает включению, но в режиме проверки сутки не считаются дважды.
    base = ("running", "done", "skipped")
    return base + ("dry_run",) if mode == "dry_run" else base


def day_candidates(
    partitions: Iterable[date],
    today_utc: date,
    hot_days: int,
    ttl_days: Optional[int],
    latest: Dict[date, LogRow],
    mode: str,
) -> List[date]:
    last_warm = today_utc - timedelta(days=hot_days + 1)
    taken = taken_statuses(mode)
    out = []
    for day in partitions:
        if day > last_warm:
            continue
        # Сутки, которые TTL удалит сегодня, переписывать незачем.
        if ttl_days is not None and day + timedelta(days=ttl_days) <= today_utc:
            continue
        row = latest.get(day)
        if row is not None and row.status in taken:
            continue
        out.append(day)
    return sorted(out)


def bucket_span(job: str) -> Optional[timedelta]:
    if job.endswith("_1m"):
        return timedelta(minutes=1)
    if job.endswith("_1h"):
        return timedelta(hours=1)
    if job.endswith("_1d"):
        return timedelta(days=1)
    return None


def rollups_ready(
    state: Sequence[Tuple[str, datetime, datetime]],
    day: date,
    now_utc: datetime,
) -> Tuple[bool, str]:
    """Все действующие сводки досчитали сутки: их считают по точным данным."""
    day_end = datetime(day.year, day.month, day.day, tzinfo=timezone.utc) + timedelta(days=1)
    active = 0
    behind = []
    for job, last_bucket, updated_at in state:
        span = bucket_span(job)
        if span is None or updated_at < now_utc - ROLLUP_STALE_AFTER:
            continue
        active += 1
        if last_bucket + span < day_end:
            behind.append(job)
    if active == 0:
        return False, "нет действующих сводок в traffic_rollup_state"
    if behind:
        return False, "сводки ещё не досчитали сутки: " + ", ".join(sorted(behind)[:5])
    return True, ""


def source_filter(source_ids: Sequence[str], threshold_bytes: int) -> str:
    ids = ", ".join(sql_string(s) for s in source_ids)
    return (
        f"source_id IN ({ids}) AND sampling_rate = 1 "
        f"AND bytes < {int(threshold_bytes)}"
    )


def thinning_sql(
    table: str,
    day: date,
    source_ids: Sequence[str],
    rate: int,
    threshold_bytes: int,
) -> str:
    if rate not in RATES:
        raise ValueError(f"rate {rate} not in {RATES}")
    if not source_ids:
        raise ValueError("no sources")
    part = sql_string(day.isoformat())
    cond = source_filter(source_ids, threshold_bytes)
    r = int(rate)
    # UPDATE и DELETE одной мутацией: оставленные строки получают
    # sampling_rate = rate и под условие DELETE уже не попадают.
    return (
        f"ALTER TABLE {table} "
        f"UPDATE bytes = bytes * {r}, packets = packets * {r}, "
        f"sampling_rate = sampling_rate * {r} "
        f"IN PARTITION {part} WHERE {cond} AND {KEEP_HASH} % {r} = 0, "
        f"DELETE IN PARTITION {part} WHERE {cond} AND {KEEP_HASH} % {r} != 0 "
        "SETTINGS mutations_sync = 0"
    )


def estimate_after(rows_before: int, bytes_before: int, eligible: int, rate: int) -> Tuple[int, int]:
    rows_after = rows_before - eligible + eligible // max(1, rate)
    if rows_before <= 0:
        return rows_after, 0
    return rows_after, int(bytes_before * rows_after / rows_before)


class Thinner:
    def __init__(self, ch: ClickHouseClient, logger: logging.Logger, table: str) -> None:
        self.ch = ch
        self.log = logger
        self.table = table
        self.db, self.name = split_table_name(table)

    # --- ClickHouse helpers -------------------------------------------------

    def rows(self, sql: str, display: str) -> List[dict]:
        out = self.ch.query(sql + " FORMAT JSONEachRow", display=display)
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def table_exists(self, full_name: str) -> bool:
        db, name = split_table_name(full_name)
        raw = self.ch.query(
            "SELECT count() FROM system.tables "
            f"WHERE database = {sql_string(db)} AND name = {sql_string(name)}",
            display=f"exists {full_name}",
        )
        return int(raw or "0") > 0

    def load_settings(self) -> Tuple[Settings, str]:
        rows = self.rows(
            "SELECT mode, hot_days, xdp_rate, xdp_threshold_bytes, run_at "
            f"FROM {SETTINGS_TABLE} FINAL WHERE settings_id = 'global' LIMIT 1",
            "load flow storage settings",
        )
        return parse_settings(rows[0] if rows else None)

    def load_latest_log(self) -> Dict[date, LogRow]:
        rows = self.rows(
            "SELECT day, status, mode, source_ids, rate, threshold_bytes, "
            "rows_before, bytes_before, eligible_rows, mutation_id, "
            "toString(started_at) AS started_at, message "
            f"FROM {LOG_TABLE} ORDER BY day, updated_at DESC LIMIT 1 BY day",
            "load thinning log",
        )
        out = {}
        for r in rows:
            day = date.fromisoformat(r["day"])
            out[day] = LogRow(
                day=day,
                status=r["status"],
                mode=r["mode"],
                source_ids=tuple(r["source_ids"]),
                rate=int(r["rate"]),
                threshold_bytes=int(r["threshold_bytes"]),
                rows_before=int(r["rows_before"]),
                bytes_before=int(r["bytes_before"]),
                eligible_rows=int(r["eligible_rows"]),
                mutation_id=r["mutation_id"],
                started_at=datetime.strptime(r["started_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc),
                message=r["message"],
            )
        return out

    def write_log(self, row: LogRow, **extra) -> None:
        values = {
            "day": row.day.isoformat(),
            "source_ids": list(row.source_ids),
            "rate": row.rate,
            "threshold_bytes": row.threshold_bytes,
            "mode": row.mode,
            "status": row.status,
            "rows_before": row.rows_before,
            "bytes_before": row.bytes_before,
            "eligible_rows": row.eligible_rows,
            "mutation_id": row.mutation_id,
            "message": row.message[:1000],
        }
        if row.started_at is not None:
            values["started_at"] = row.started_at.strftime("%Y-%m-%d %H:%M:%S")
        values.update(extra)
        self.ch.execute(
            f"INSERT INTO {LOG_TABLE} FORMAT JSONEachRow\n{json.dumps(values, ensure_ascii=False)}",
            display=f"log {row.day} {row.status}",
        )
        self.log.info("day=%s status=%s %s", row.day, row.status, row.message)

    def xdp_sources(self) -> List[str]:
        rows = self.rows(
            f"SELECT source_id FROM {SOURCES_VIEW} WHERE source_type = 'xdp' ORDER BY source_id",
            "xdp sources",
        )
        return [r["source_id"] for r in rows]

    def partitions(self) -> List[Partition]:
        rows = self.rows(
            "SELECT partition, sum(rows) AS rows, sum(bytes_on_disk) AS bytes, "
            "max(bytes_on_disk) AS max_part, argMax(disk_name, bytes_on_disk) AS disk "
            "FROM system.parts "
            f"WHERE active AND database = {sql_string(self.db)} AND table = {sql_string(self.name)} "
            "GROUP BY partition ORDER BY partition",
            "flows partitions",
        )
        out = []
        for r in rows:
            try:
                day = date.fromisoformat(str(r["partition"]).strip("'"))
            except ValueError:
                continue
            out.append(Partition(day, int(r["rows"]), int(r["bytes"]), int(r["max_part"]), r["disk"]))
        return out

    def ttl_days(self) -> Optional[int]:
        rows = self.rows(
            "SELECT engine_full FROM system.tables "
            f"WHERE database = {sql_string(self.db)} AND name = {sql_string(self.name)}",
            "flows ttl",
        )
        return ttl_days_from_ddl(rows[0]["engine_full"]) if rows else None

    def rollup_state(self) -> List[Tuple[str, datetime, datetime]]:
        rows = self.rows(
            "SELECT job, toString(last_bucket) AS last_bucket, toString(updated_at) AS updated_at "
            "FROM default.traffic_rollup_state FINAL",
            "rollup state",
        )
        fmt = "%Y-%m-%d %H:%M:%S"
        return [
            (
                r["job"],
                datetime.strptime(r["last_bucket"], fmt).replace(tzinfo=timezone.utc),
                datetime.strptime(r["updated_at"], fmt).replace(tzinfo=timezone.utc),
            )
            for r in rows
        ]

    def pending_mutations(self) -> int:
        raw = self.ch.query(
            "SELECT count() FROM system.mutations "
            f"WHERE database = {sql_string(self.db)} AND table = {sql_string(self.name)} AND is_done = 0",
            display="pending flows mutations",
        )
        return int(raw or "0")

    def free_bytes(self, disk_name: str) -> Optional[int]:
        rows = self.rows(
            f"SELECT free_space FROM system.disks WHERE name = {sql_string(disk_name)}",
            "disk free",
        )
        return int(rows[0]["free_space"]) if rows else None

    def count(self, where: str, display: str) -> int:
        return int(self.ch.query(f"SELECT count() FROM {self.table} WHERE {where}", display=display) or "0")

    # --- steps --------------------------------------------------------------

    def finish_running(self, row: LogRow, now_utc: datetime) -> bool:
        """Дописывает журнал по запущенной мутации. True, пока она ещё идёт."""
        if not row.mutation_id and self.pending_mutations() > 0:
            self.log.info("day=%s mutation id unknown and flows_raw still has a mutation", row.day)
            return True
        found = self.rows(
            "SELECT is_done, latest_fail_reason FROM system.mutations "
            f"WHERE database = {sql_string(self.db)} AND table = {sql_string(self.name)} "
            f"AND mutation_id = {sql_string(row.mutation_id)}",
            "mutation status",
        ) if row.mutation_id else []
        done = not found or int(found[0]["is_done"]) == 1
        if done:
            part = sql_string(row.day.isoformat())
            parts = self.rows(
                "SELECT sum(rows) AS rows, sum(bytes_on_disk) AS bytes FROM system.parts "
                f"WHERE active AND database = {sql_string(self.db)} AND table = {sql_string(self.name)} "
                f"AND partition = {part}",
                "partition after",
            )
            rows_after = int(parts[0]["rows"]) if parts else 0
            bytes_after = int(parts[0]["bytes"]) if parts else 0
            took = (now_utc - row.started_at) if row.started_at else None
            msg = "готово"
            if took is not None:
                msg += f", не дольше {int(took.total_seconds() // 60)} мин"
            self.write_log(
                replace(row, status="done", message=msg),
                rows_after=rows_after,
                bytes_after=bytes_after,
                finished_at=now_utc.strftime("%Y-%m-%d %H:%M:%S"),
            )
            return False
        started = row.started_at or now_utc
        if now_utc - started > MUTATION_MAX_AGE:
            self.ch.execute(
                "KILL MUTATION WHERE "
                f"database = {sql_string(self.db)} AND table = {sql_string(self.name)} "
                f"AND mutation_id = {sql_string(row.mutation_id)}",
                display="kill thinning mutation",
            )
            reason = (found[0].get("latest_fail_reason") or "").strip()
            msg = "не успела за 3 ч и остановлена, повтор следующей ночью"
            if reason:
                msg += f": {reason}"
            self.write_log(
                replace(row, status="failed", message=msg),
                finished_at=now_utc.strftime("%Y-%m-%d %H:%M:%S"),
            )
            return False
        self.log.info("day=%s mutation=%s still running", row.day, row.mutation_id)
        return True

    def find_mutation_id(self, day: date, since: datetime) -> str:
        rows = self.rows(
            "SELECT mutation_id FROM system.mutations "
            f"WHERE database = {sql_string(self.db)} AND table = {sql_string(self.name)} "
            f"AND create_time >= toDateTime({sql_string((since - timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S'))}, 'UTC') "
            f"AND position(command, {sql_string(day.isoformat())}) > 0 "
            "AND position(command, 'cityHash64') > 0 "
            "ORDER BY create_time DESC LIMIT 1",
            "find mutation id",
        )
        return rows[0]["mutation_id"] if rows else ""

    def waiting(self, day: date, s: Settings, latest: Dict[date, LogRow], reason: str) -> int:
        prev = latest.get(day)
        if prev is None or prev.status != "waiting" or prev.message != reason:
            self.write_log(LogRow(day=day, status="waiting", mode=s.mode, rate=s.xdp_rate,
                                  threshold_bytes=s.xdp_threshold_bytes, message=reason))
        else:
            self.log.info("day=%s waiting: %s", day, reason)
        return 0

    def run(self, now_utc: datetime, now_local: datetime) -> int:
        if not self.table_exists(SETTINGS_TABLE):
            self.log.info("no %s, nothing to do", SETTINGS_TABLE)
            return 0
        if not self.table_exists(LOG_TABLE):
            self.log.error("no %s, apply deploy/schema/10_flows first", LOG_TABLE)
            return 1

        settings, problem = self.load_settings()
        latest = self.load_latest_log()

        # Незавершённая мутация дописывается в любое время и в любом режиме.
        for row in latest.values():
            if row.status == "running" and self.finish_running(row, now_utc):
                return 0

        if problem:
            self.log.error("%s; thinning is off", problem)
            return 1
        if settings.mode == "off":
            self.log.info("mode=off")
            return 0
        if not in_window(now_local, settings.run_at):
            self.log.info("outside window %s + %sh", settings.run_at, WINDOW_HOURS)
            return 0

        sources = self.xdp_sources()
        if not sources:
            self.log.info("no enabled xdp sources")
            return 0

        today_utc = now_utc.date()
        parts = {p.day: p for p in self.partitions()}
        days = day_candidates(parts, today_utc, settings.hot_days, self.ttl_days(), latest, settings.mode)
        if not days:
            self.log.info("no days to thin")
            return 0
        day = days[0]
        part = parts[day]

        ok, reason = rollups_ready(self.rollup_state(), day, now_utc)
        if not ok:
            return self.waiting(day, settings, latest, reason)
        if self.pending_mutations() > 0:
            return self.waiting(day, settings, latest, "по flows_raw идёт другая мутация")
        free = self.free_bytes(part.disk_name)
        need = int(part.max_part_bytes * DISK_RESERVE)
        if free is not None and free < need:
            return self.waiting(day, settings, latest, f"мало места: свободно {free} Б, нужно {need} Б")

        # Счёт по двум колонкам за сутки идёт десятки секунд; даём запас.
        self.ch.timeout_s = max(self.ch.timeout_s or 0, 900)
        day_sql = f"date = {sql_string(day.isoformat())}"
        ids = ", ".join(sql_string(x) for x in sources)
        base = LogRow(
            day=day, status="", mode=settings.mode, source_ids=tuple(sources),
            rate=settings.xdp_rate, threshold_bytes=settings.xdp_threshold_bytes,
            rows_before=part.rows, bytes_before=part.bytes_on_disk, started_at=now_utc,
        )
        if self.count(f"{day_sql} AND source_id IN ({ids})", "xdp rows") == 0:
            self.write_log(replace(base, status="skipped", message="нет потоков xdpflowd"))
            return 0
        eligible = self.count(
            f"{day_sql} AND {source_filter(sources, settings.xdp_threshold_bytes)}",
            "eligible rows",
        )
        base = replace(base, eligible_rows=eligible)
        if eligible == 0:
            self.write_log(replace(base, status="skipped",
                                     message="нечего прореживать: все потоки уже прорежены или крупные"))
            return 0

        if settings.mode == "dry_run":
            rows_after, bytes_after = estimate_after(part.rows, part.bytes_on_disk, eligible, settings.xdp_rate)
            self.write_log(
                replace(base, status="dry_run", message="проверка: данные не изменены, объём после — оценка"),
                rows_after=rows_after,
                bytes_after=bytes_after,
                finished_at=now_utc.strftime("%Y-%m-%d %H:%M:%S"),
            )
            return 0

        sql = thinning_sql(self.table, day, sources, settings.xdp_rate, settings.xdp_threshold_bytes)
        try:
            self.ch.execute(sql, display=f"thin {day}")
        except RuntimeError as exc:
            self.write_log(replace(base, status="failed", message=str(exc)[:1000]),
                           finished_at=now_utc.strftime("%Y-%m-%d %H:%M:%S"))
            return 1
        mutation_id = self.find_mutation_id(day, now_utc)
        self.write_log(replace(base, status="running", mutation_id=mutation_id,
                                 message="мутация запущена"))
        return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--clickhouse-client", default=env("TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"))
    p.add_argument("--host", default=env("TRAFFIC_ROLLUP_CH_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(env("TRAFFIC_ROLLUP_CH_PORT", "9000")))
    p.add_argument("--user", default=env("TRAFFIC_ROLLUP_CH_USER", "default"))
    p.add_argument("--password", default=env("TRAFFIC_ROLLUP_CH_PASSWORD", ""))
    p.add_argument("--database", default=env("TRAFFIC_ROLLUP_CH_DATABASE", "default"))
    p.add_argument("--table", default=env("FLOW_THINNING_TABLE", "default.flows_raw"))
    p.add_argument("--query-timeout-sec", type=int, default=int(env("TRAFFIC_ROLLUP_QUERY_TIMEOUT_SEC", "180")))
    p.add_argument("--log-file", default=env("FLOW_THINNING_LOG_FILE"))
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    args.clickhouse_client = resolve_clickhouse_client(args.clickhouse_client)
    logger = setup_logging(args.log_file, args.verbose)
    ch = ClickHouseClient(args)
    try:
        return Thinner(ch, logger, args.table).run(datetime.now(timezone.utc).replace(microsecond=0), datetime.now())
    except RuntimeError as exc:
        logger.error("flow thinning failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
