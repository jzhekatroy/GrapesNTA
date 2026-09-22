#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
import unittest

import argparse

from traffic_rollup_async import (
    CATCHUP_LAG_BUCKETS,
    JobState,
    catchup_window_buckets,
    complete_raw_until,
    defer_until,
    flows_raw_enabled_max_minute,
    is_epoch_timestamp,
    is_retryable_queue_error,
    lag_buckets,
    mark_deferred,
    raw_max_received,
    recent_five_minute_filter,
    truncate_bucket,
)
from traffic_rollup_jobs import sorted_jobs


class CatchupGates(unittest.TestCase):
    def test_epoch_timestamp(self):
        self.assertTrue(is_epoch_timestamp(""))
        self.assertTrue(is_epoch_timestamp("1970-01-01 00:00:00"))
        self.assertFalse(is_epoch_timestamp("2026-09-05 21:00:52"))

    def test_complete_raw_until_clamps_to_landed_data(self):
        live = datetime(2026, 9, 7, 8, 5, tzinfo=timezone.utc)
        raw = datetime(2026, 9, 5, 21, 0, tzinfo=timezone.utc)
        got = complete_raw_until(raw, 5, live)
        self.assertEqual(got, datetime(2026, 9, 5, 20, 55, tzinfo=timezone.utc))

    def test_complete_raw_until_does_not_pass_live(self):
        live = datetime(2026, 9, 7, 8, 5, tzinfo=timezone.utc)
        raw = datetime(2026, 9, 7, 8, 10, tzinfo=timezone.utc)
        got = complete_raw_until(raw, 5, live)
        self.assertEqual(got, live)

    def test_complete_raw_until_empty_raw_keeps_live(self):
        live = datetime(2026, 9, 7, 8, 5, tzinfo=timezone.utc)
        self.assertEqual(complete_raw_until(None, 5, live), live)

    def test_draining_holds_back_further_than_the_safety_lag(self):
        # While a spool replays, run_live adds 15 minutes to the safety lag so
        # the minutes the drain may still fill are not rolled undercounted.
        live = datetime(2026, 9, 7, 9, 0, tzinfo=timezone.utc)
        raw = datetime(2026, 9, 7, 8, 55, tzinfo=timezone.utc)
        self.assertEqual(
            complete_raw_until(raw, 5 + 15, live),
            datetime(2026, 9, 7, 8, 35, tzinfo=timezone.utc),
        )

    def test_truncate_minute(self):
        dt = datetime(2026, 9, 5, 21, 0, 52, tzinfo=timezone.utc)
        self.assertEqual(
            truncate_bucket(dt - timedelta(minutes=5), "minute"),
            datetime(2026, 9, 5, 20, 55, tzinfo=timezone.utc),
        )


class PassOneWindow(unittest.TestCase):
    """The fair pass sizes its window from state, without querying ClickHouse."""

    def _args(self, clamp):
        return argparse.Namespace(safety_lag_minutes=5, _until_clamp=clamp)

    def _minute_job(self):
        job = next(j for j in sorted_jobs() if j.job_id == "traffic_dashboard_1m")
        self.assertEqual(job.bucket_kind, "minute")
        return job

    def _state(self, last_bucket):
        return JobState(last_bucket=last_bucket, status="ok", last_error="")

    def test_caught_up_job_stays_on_one_bucket(self):
        job = self._minute_job()
        until = datetime(2026, 9, 5, 20, 55, tzinfo=timezone.utc)
        states = {job.job_id: self._state(until - timedelta(minutes=1))}
        self.assertLessEqual(
            lag_buckets(job, states, self._args(until)), CATCHUP_LAG_BUCKETS
        )

    def test_job_behind_an_outage_asks_for_a_range(self):
        job = self._minute_job()
        until = datetime(2026, 9, 5, 20, 55, tzinfo=timezone.utc)
        states = {job.job_id: self._state(datetime(2026, 9, 5, 15, 54, tzinfo=timezone.utc))}
        self.assertEqual(lag_buckets(job, states, self._args(until)), 300)

    def test_missing_state_is_not_a_lag(self):
        job = self._minute_job()
        until = datetime(2026, 9, 5, 20, 55, tzinfo=timezone.utc)
        self.assertEqual(lag_buckets(job, {}, self._args(until)), 0)


class CatchupWindow(unittest.TestCase):
    def test_minute_budget_stays_a_quarter_hour(self):
        self.assertEqual(catchup_window_buckets("minute", 15), 15)

    def test_hour_budget_is_one_hour_not_fifteen(self):
        self.assertEqual(catchup_window_buckets("hour", 15), 1)

    def test_two_hours_only_when_the_budget_covers_them(self):
        self.assertEqual(catchup_window_buckets("hour", 120), 2)
        self.assertEqual(catchup_window_buckets("hour", 24 * 60), 2)

    def test_day_budget_is_one_day(self):
        self.assertEqual(catchup_window_buckets("day", 15), 1)


class RetryableTimeout(unittest.TestCase):
    def test_server_timeout_is_retryable(self):
        msg = "curl: (22) The requested URL returned error: 500 Code: 159. DB::Exception: Timeout exceeded"
        self.assertTrue(is_retryable_queue_error(msg))

    def test_hard_error_is_not_retryable(self):
        self.assertFalse(is_retryable_queue_error("Code: 47. Unknown expression identifier"))

    def test_defer_marker_holds_for_five_minutes(self):
        now = datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
        note = mark_deferred("Timeout exceeded", now)
        state = JobState(last_bucket=now, status="deferred", last_error=note)
        self.assertEqual(
            defer_until(state),
            datetime(2026, 9, 22, 10, 5, tzinfo=timezone.utc),
        )
        self.assertIsNone(defer_until(JobState(last_bucket=now, status="error", last_error=note)))


class RecordingClickHouse:
    """Отдаёт заранее заданные ответы и запоминает запросы."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.queries = []

    def query(self, sql, display=None):
        self.queries.append(sql)
        return self.answers.pop(0) if self.answers else ""


class FreshnessProbeWindow(unittest.TestCase):
    def test_recent_filter_sits_on_the_sort_key(self):
        sql = recent_five_minute_filter(30)
        self.assertIn("toStartOfFiveMinutes(time_received_ns) >=", sql)
        self.assertIn("INTERVAL 30 MINUTE", sql)

    def test_recent_filter_never_narrower_than_one_granule(self):
        self.assertIn("INTERVAL 5 MINUTE", recent_five_minute_filter(1))

    def test_live_collector_answers_from_the_narrow_window(self):
        ch = RecordingClickHouse(["2026-09-22 14:46:25"])
        got = raw_max_received(ch)
        self.assertEqual(got, datetime(2026, 9, 22, 14, 46, 25, tzinfo=timezone.utc))
        self.assertEqual(len(ch.queries), 1)
        self.assertIn("toStartOfFiveMinutes", ch.queries[0])

    def test_silent_collector_falls_back_to_the_wide_scan(self):
        ch = RecordingClickHouse(["1970-01-01 00:00:00", "2026-09-20 03:11:00"])
        got = raw_max_received(ch)
        self.assertEqual(got, datetime(2026, 9, 20, 3, 11, tzinfo=timezone.utc))
        self.assertEqual(len(ch.queries), 2)
        self.assertNotIn("toStartOfFiveMinutes", ch.queries[1])

    def test_empty_table_stays_none(self):
        ch = RecordingClickHouse(["", ""])
        self.assertIsNone(raw_max_received(ch))
        self.assertEqual(len(ch.queries), 2)

    def test_enabled_sources_probe_uses_the_same_window(self):
        ch = RecordingClickHouse(["2026-09-22 14:46:00"])
        got = flows_raw_enabled_max_minute(ch)
        self.assertEqual(got, datetime(2026, 9, 22, 14, 46, tzinfo=timezone.utc))
        self.assertEqual(len(ch.queries), 1)
        self.assertIn("toStartOfFiveMinutes", ch.queries[0])
        self.assertIn("net_flow_sources_enabled", ch.queries[0])

    def test_enabled_sources_probe_falls_back(self):
        ch = RecordingClickHouse(["1970-01-01 00:00:00", "2026-09-20 03:11:00"])
        got = flows_raw_enabled_max_minute(ch)
        self.assertEqual(got, datetime(2026, 9, 20, 3, 11, tzinfo=timezone.utc))
        self.assertEqual(len(ch.queries), 2)
        self.assertIn("net_flow_sources_enabled", ch.queries[1])


if __name__ == "__main__":
    unittest.main()
