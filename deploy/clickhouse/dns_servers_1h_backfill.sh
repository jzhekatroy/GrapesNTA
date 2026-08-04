#!/usr/bin/env bash
# Backfill default.dns_servers_1h from raw dns_log, one day at a time.
#
# The rollup itself is created by dns_servers_1h.sql and fills going forward
# from its materialized view. This script is only for the history that already
# sat in dns_log before the MV existed.
#
# It walks days from newest to oldest, so an interrupted run still leaves the
# most useful part done. Each day is a separate INSERT: the log holds billions
# of rows and a single statement over the whole window would scan all of them.
# Re-running a day would double-count it, so days already present are skipped.
#
# Usage:
#   CH="clickhouse-client --host ... --port ... --user ... --password ..." \
#   DAYS=7 ./dns_servers_1h_backfill.sh
#
# Env:
#   CH        clickhouse-client invocation (required)
#   DAYS      how many days back to cover, default 7 (dns_log keeps 30)
#   THREADS   max_threads per INSERT, default 4 — keep the scan off the
#             collector's back while it runs
#   FORCE=1   re-insert days that already have rows (only after deleting them)

set -euo pipefail

CH=${CH:?set CH to your clickhouse-client invocation}
DAYS=${DAYS:-7}
THREADS=${THREADS:-4}
FORCE=${FORCE:-0}

for ((d = 1; d <= DAYS; d++)); do
    day=$($CH -q "SELECT toString(toDate(now()) - $d)")

    existing=$($CH -q "
        SELECT count()
        FROM default.dns_servers_1h
        WHERE hour >= toDateTime('$day 00:00:00', 'UTC')
          AND hour <  toDateTime('$day 00:00:00', 'UTC') + INTERVAL 1 DAY
    ")

    if [[ "$existing" != "0" && "$FORCE" != "1" ]]; then
        echo "$day: skip, already has $existing rows"
        continue
    fi

    echo "$day: backfilling..."
    started=$(date +%s)

    $CH -q "
        INSERT INTO default.dns_servers_1h
        SELECT
            toStartOfHour(toDateTime(ts)) AS hour,
            source_id,
            server_ip,
            countIf(is_response = 0) AS queries,
            countIf(is_response = 1) AS responses,
            countIf(is_response = 1 AND rcode = 3) AS nxdomain,
            countIf(is_response = 1 AND rcode = 2) AS servfail
        FROM default.dns_log
        WHERE ts >= toDateTime('$day 00:00:00', 'UTC')
          AND ts <  toDateTime('$day 00:00:00', 'UTC') + INTERVAL 1 DAY
        GROUP BY hour, source_id, server_ip
        SETTINGS max_threads = $THREADS
    "

    echo "$day: done in $(( $(date +%s) - started ))s"
done
