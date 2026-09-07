#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
import unittest

from traffic_rollup_async import (
    complete_raw_until,
    is_epoch_timestamp,
    truncate_bucket,
)


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


if __name__ == "__main__":
    unittest.main()
