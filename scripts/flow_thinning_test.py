#!/usr/bin/env python3
import json
import logging
import unittest
from datetime import date, datetime, timedelta, timezone

from flow_thinning import (
    LogRow,
    Settings,
    Thinner,
    day_candidates,
    in_window,
    parse_settings,
    rollups_ready,
    thinning_sql,
    ttl_days_from_ddl,
)

UTC = timezone.utc


class SettingsParsing(unittest.TestCase):
    def test_missing_row_is_off(self):
        s, problem = parse_settings(None)
        self.assertEqual(s.mode, "off")
        self.assertEqual(problem, "")

    def test_json_row_with_quoted_ints(self):
        s, problem = parse_settings({
            "mode": "on", "hot_days": 2, "xdp_rate": 16,
            "xdp_threshold_bytes": "50000", "run_at": "02:00",
        })
        self.assertEqual(problem, "")
        self.assertEqual((s.mode, s.hot_days, s.xdp_rate, s.xdp_threshold_bytes), ("on", 2, 16, 50000))

    def test_bad_values_turn_it_off(self):
        for row in (
            {"mode": "on", "xdp_rate": 10},
            {"mode": "on", "hot_days": 0},
            {"mode": "on", "xdp_threshold_bytes": 10},
            {"mode": "on", "run_at": "25:00"},
            {"mode": "always"},
        ):
            s, problem = parse_settings(row)
            self.assertEqual(s.mode, "off", row)
            self.assertTrue(problem, row)

    def test_legacy_dry_run_is_off(self):
        s, problem = parse_settings({
            "mode": "dry_run", "hot_days": 1, "xdp_rate": 64,
            "xdp_threshold_bytes": 100000, "run_at": "04:30",
        })
        self.assertEqual(problem, "")
        self.assertEqual(s.mode, "off")


class Window(unittest.TestCase):
    def test_inside_and_outside(self):
        self.assertTrue(in_window(datetime(2026, 9, 24, 4, 30), "04:30"))
        self.assertTrue(in_window(datetime(2026, 9, 24, 7, 29), "04:30"))
        self.assertFalse(in_window(datetime(2026, 9, 24, 7, 30), "04:30"))
        self.assertFalse(in_window(datetime(2026, 9, 24, 4, 0), "04:30"))

    def test_window_past_midnight(self):
        self.assertTrue(in_window(datetime(2026, 9, 24, 1, 0), "23:00"))
        self.assertTrue(in_window(datetime(2026, 9, 24, 23, 10), "23:00"))
        self.assertFalse(in_window(datetime(2026, 9, 24, 2, 0), "23:00"))


class Days(unittest.TestCase):
    today = date(2026, 9, 24)
    parts = [date(2026, 9, d) for d in range(18, 25)]

    def test_ttl_from_ddl(self):
        self.assertEqual(ttl_days_from_ddl("MergeTree PARTITION BY date TTL date + toIntervalDay(4) SETTINGS"), 4)
        self.assertEqual(ttl_days_from_ddl("TTL time_received_ns + INTERVAL 10 DAY"), 10)
        self.assertIsNone(ttl_days_from_ddl("MergeTree ORDER BY x"))

    def test_hot_days_kept_and_oldest_first(self):
        got = day_candidates(self.parts, self.today, 1, None, {})
        self.assertEqual(got[0], date(2026, 9, 18))
        self.assertEqual(got[-1], date(2026, 9, 22))

    def test_day_expiring_today_is_skipped(self):
        got = day_candidates(self.parts, self.today, 1, 4, {})
        self.assertEqual(got, [date(2026, 9, 21), date(2026, 9, 22)])

    def test_done_and_running_are_never_retaken(self):
        latest = {
            date(2026, 9, 21): LogRow(day=date(2026, 9, 21), status="done"),
            date(2026, 9, 22): LogRow(day=date(2026, 9, 22), status="running"),
        }
        got = day_candidates(self.parts, self.today, 1, 4, latest)
        self.assertEqual(got, [])

    def test_failed_and_waiting_are_retried(self):
        latest = {
            date(2026, 9, 21): LogRow(day=date(2026, 9, 21), status="failed"),
            date(2026, 9, 22): LogRow(day=date(2026, 9, 22), status="waiting"),
        }
        got = day_candidates(self.parts, self.today, 1, 4, latest)
        self.assertEqual(got, [date(2026, 9, 21), date(2026, 9, 22)])

    def test_old_dry_run_log_does_not_block(self):
        latest = {date(2026, 9, 22): LogRow(day=date(2026, 9, 22), status="dry_run")}
        self.assertEqual(day_candidates(self.parts, self.today, 1, 4, latest),
                         [date(2026, 9, 21), date(2026, 9, 22)])


class Rollups(unittest.TestCase):
    now = datetime(2026, 9, 24, 2, 0, tzinfo=UTC)

    def test_ready_when_every_active_job_passed_the_day(self):
        state = [
            ("traffic_dashboard_1m", datetime(2026, 9, 24, 1, 50, tzinfo=UTC), self.now),
            ("traffic_dashboard_1h", datetime(2026, 9, 24, 0, 0, tzinfo=UTC), self.now),
            ("traffic_dashboard_1d", datetime(2026, 9, 22, tzinfo=UTC), self.now),
        ]
        self.assertEqual(rollups_ready(state, date(2026, 9, 22), self.now), (True, ""))

    def test_day_job_not_done_blocks(self):
        state = [("traffic_client_1d", datetime(2026, 9, 21, tzinfo=UTC), self.now)]
        ok, reason = rollups_ready(state, date(2026, 9, 22), self.now)
        self.assertFalse(ok)
        self.assertIn("traffic_client_1d", reason)

    def test_stale_job_is_ignored(self):
        state = [
            ("traffic_talker_1h", datetime(2026, 7, 21, 5, tzinfo=UTC), datetime(2026, 7, 21, 6, tzinfo=UTC)),
            ("traffic_dashboard_1d", datetime(2026, 9, 22, tzinfo=UTC), self.now),
        ]
        self.assertTrue(rollups_ready(state, date(2026, 9, 22), self.now)[0])

    def test_no_state_blocks(self):
        self.assertFalse(rollups_ready([], date(2026, 9, 22), self.now)[0])


class Sql(unittest.TestCase):
    def test_thinning_sql_shape(self):
        sql = thinning_sql("default.flows_raw", date(2026, 9, 23), ["netflow"], 64, 100000)
        self.assertIn("IN PARTITION '2026-09-23'", sql)
        self.assertIn("source_id IN ('netflow') AND sampling_rate = 1 AND bytes < 100000", sql)
        self.assertIn("time_received_ns, bytes)", sql)
        self.assertIn("% 64 = 0", sql)
        self.assertIn("% 64 != 0", sql)
        self.assertIn("sampling_rate = sampling_rate * 64", sql)
        self.assertLess(sql.index(" UPDATE "), sql.index(" DELETE "))

    def test_bad_rate_or_no_sources(self):
        with self.assertRaises(ValueError):
            thinning_sql("t", date(2026, 9, 23), ["x"], 10, 1000)
        with self.assertRaises(ValueError):
            thinning_sql("t", date(2026, 9, 23), [], 64, 1000)

    def test_source_id_is_quoted(self):
        sql = thinning_sql("t", date(2026, 9, 23), ["a'b"], 64, 1000)
        self.assertIn("'a\\'b'", sql)

class FakeClickHouse:
    """Отвечает по подписи запроса (display) и запоминает изменяющие запросы."""

    def __init__(self, answers):
        self.answers = answers
        self.executed = []
        self.timeout_s = 180

    def query(self, sql, *, display=None):
        if sql.startswith(("INSERT", "ALTER", "KILL")):
            self.executed.append(sql)
            return ""
        answer = self.answers.get(display)
        if answer is None:
            for key, value in self.answers.items():
                if display and display.startswith(key):
                    answer = value
                    break
        if answer is None:
            raise AssertionError(f"unexpected query {display}: {sql}")
        if isinstance(answer, list):
            return "\n".join(json.dumps(r) for r in answer)
        return str(answer)

    def execute(self, sql, *, display=None):
        self.query(sql, display=display)

    def logged(self):
        out = []
        for sql in self.executed:
            if sql.startswith("INSERT"):
                out.append(json.loads(sql.split("FORMAT JSONEachRow", 1)[1]))
        return out


NOW = datetime(2026, 9, 24, 2, 0, tzinfo=UTC)
LOCAL = datetime(2026, 9, 24, 5, 0)


def base_answers(mode="on", log_rows=None):
    return {
        "exists default.app_flow_storage_settings": 1,
        "exists default.flow_thinning_log": 1,
        "load flow storage settings": [{
            "mode": mode, "hot_days": 1, "xdp_rate": 64,
            "xdp_threshold_bytes": "100000", "run_at": "04:30",
        }],
        "load thinning log": log_rows or [],
        "xdp sources": [{"source_id": "netflow"}],
        "flows partitions": [
            {"partition": "2026-09-22", "rows": "5000", "bytes": "150000", "max_part": "40000", "disk": "default"},
            {"partition": "2026-09-23", "rows": "5000", "bytes": "150000", "max_part": "40000", "disk": "default"},
            {"partition": "2026-09-24", "rows": "900", "bytes": "30000", "max_part": "9000", "disk": "default"},
        ],
        "flows ttl": [{"engine_full": "MergeTree TTL date + toIntervalDay(10)"}],
        "rollup state": [{"job": "traffic_dashboard_1d", "last_bucket": "2026-09-23 00:00:00",
                          "updated_at": "2026-09-24 01:00:00"}],
        "pending flows mutations": 0,
        "disk free": [{"free_space": "10000000"}],
        "xdp rows": 4000,
        "eligible rows": 3200,
        "find mutation id": [{"mutation_id": "mutation_7.txt"}],
    }


def log_row(day, status, **kw):
    row = {
        "day": day, "status": status, "mode": "on", "source_ids": ["netflow"], "rate": 64,
        "threshold_bytes": "100000", "rows_before": "5000", "bytes_before": "150000",
        "eligible_rows": "3200", "mutation_id": "", "started_at": "2026-09-24 01:40:00", "message": "",
    }
    row.update(kw)
    return row


class Run(unittest.TestCase):
    def thinner(self, ch):
        logger = logging.getLogger("flow_thinning_test")
        logger.addHandler(logging.NullHandler())
        logger.propagate = False
        return Thinner(ch, logger, "default.flows_raw")

    def alters(self, ch):
        return [s for s in ch.executed if s.startswith("ALTER")]

    def test_on_starts_one_mutation_for_oldest_day(self):
        ch = FakeClickHouse(base_answers())
        self.assertEqual(self.thinner(ch).run(NOW, LOCAL), 0)
        alters = self.alters(ch)
        self.assertEqual(len(alters), 1)
        self.assertIn("IN PARTITION '2026-09-22'", alters[0])
        logged = ch.logged()
        self.assertEqual(logged[-1]["status"], "running")
        self.assertEqual(logged[-1]["mutation_id"], "mutation_7.txt")

    def test_legacy_dry_run_setting_is_off(self):
        ch = FakeClickHouse(base_answers(mode="dry_run"))
        self.assertEqual(self.thinner(ch).run(NOW, LOCAL), 0)
        self.assertEqual(self.alters(ch), [])
        self.assertEqual(ch.logged(), [])

    def test_off_and_outside_window_do_nothing(self):
        ch = FakeClickHouse(base_answers(mode="off"))
        self.thinner(ch).run(NOW, LOCAL)
        self.assertEqual(ch.executed, [])
        ch = FakeClickHouse(base_answers())
        self.thinner(ch).run(NOW, datetime(2026, 9, 24, 12, 0))
        self.assertEqual(ch.executed, [])

    def test_running_mutation_blocks_new_work(self):
        answers = base_answers(log_rows=[log_row("2026-09-22", "running", mutation_id="mutation_7.txt")])
        answers["mutation status"] = [{"is_done": 0, "latest_fail_reason": ""}]
        ch = FakeClickHouse(answers)
        self.thinner(ch).run(NOW, LOCAL)
        self.assertEqual(ch.executed, [])

    def test_finished_mutation_is_recorded_and_day_not_retaken(self):
        answers = base_answers(log_rows=[log_row("2026-09-22", "running", mutation_id="mutation_7.txt")])
        answers["mutation status"] = [{"is_done": 1, "latest_fail_reason": ""}]
        answers["partition after"] = [{"rows": "300", "bytes": "5000"}]
        # 23-е ещё в горячих сутках, других кандидатов нет.
        ch = FakeClickHouse(answers)
        self.thinner(ch).run(NOW, LOCAL)
        self.assertEqual(self.alters(ch), [])
        done = ch.logged()[0]
        self.assertEqual((done["status"], done["rows_after"], done["bytes_after"]), ("done", 300, 5000))

    def test_stuck_mutation_is_killed(self):
        answers = base_answers(log_rows=[log_row("2026-09-22", "running", mutation_id="mutation_7.txt",
                                                 started_at="2026-09-23 22:00:00")])
        answers["mutation status"] = [{"is_done": 0, "latest_fail_reason": ""}]
        ch = FakeClickHouse(answers)
        self.thinner(ch).run(NOW, LOCAL)
        self.assertTrue(any(s.startswith("KILL MUTATION") for s in ch.executed))
        self.assertEqual(ch.logged()[0]["status"], "failed")

    def test_other_mutation_makes_it_wait(self):
        answers = base_answers()
        answers["pending flows mutations"] = 1
        ch = FakeClickHouse(answers)
        self.thinner(ch).run(NOW, LOCAL)
        self.assertEqual(self.alters(ch), [])
        self.assertEqual(ch.logged()[-1]["status"], "waiting")

    def test_same_wait_reason_is_not_logged_twice(self):
        answers = base_answers(log_rows=[log_row("2026-09-22", "waiting", message="по flows_raw идёт другая мутация")])
        answers["pending flows mutations"] = 1
        ch = FakeClickHouse(answers)
        self.thinner(ch).run(NOW, LOCAL)
        self.assertEqual(ch.executed, [])

    def test_rollups_behind_makes_it_wait(self):
        answers = base_answers()
        answers["rollup state"] = [{"job": "traffic_dashboard_1d", "last_bucket": "2026-09-21 00:00:00",
                                    "updated_at": "2026-09-24 01:00:00"}]
        ch = FakeClickHouse(answers)
        self.thinner(ch).run(NOW, LOCAL)
        self.assertEqual(self.alters(ch), [])
        self.assertEqual(ch.logged()[-1]["status"], "waiting")

    def test_day_without_xdp_is_skipped(self):
        answers = base_answers()
        answers["xdp rows"] = 0
        ch = FakeClickHouse(answers)
        self.thinner(ch).run(NOW, LOCAL)
        self.assertEqual(self.alters(ch), [])
        self.assertEqual(ch.logged()[-1]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
