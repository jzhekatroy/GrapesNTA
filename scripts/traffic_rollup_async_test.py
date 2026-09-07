#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
import unittest

import argparse

from traffic_rollup_async import (
    CATCHUP_LAG_BUCKETS,
    JobState,
    complete_raw_until,
    is_epoch_timestamp,
    lag_buckets,
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


if __name__ == "__main__":
    unittest.main()
