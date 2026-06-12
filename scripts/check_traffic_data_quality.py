#!/usr/bin/env python3
"""
Traffic data quality checks for GrapesNTA ClickHouse rollups.

The script is intentionally read-only. It checks:
  - rollup freshness and rollup_state lag/errors;
  - source filtering (every source must be registered; sources with
    include_in_total=0 polluting the rollups FAIL unless allowed);
  - classifier output in raw and rollups: no unknown direction, no unknown
    scope, local ASN enrichment present;
  - country resolution: flags '??' IP country (geo dict) and '??' AS country
    where the ASN is known (registry cc gap);
  - raw vs aggregate consistency by direction.

Exit codes: 0 = OK, 1 = WARN only, 2 = FAIL.

Typical usage on a collector:

  set -a
  source /etc/grapesnta/traffic-rollups.env
  set +a
  python3 scripts/check_traffic_data_quality.py --local-asn 34665
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple


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


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


@dataclass
class CheckResult:
    status: str
    name: str
    detail: str


class ClickHouse:
    def __init__(self, args: argparse.Namespace) -> None:
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

    def query_tsv(self, sql: str) -> List[Tuple[str, ...]]:
        proc = subprocess.run(
            self.base + ["--query", sql + "\nFORMAT TabSeparated"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"clickhouse query failed: {err}\nquery: {sql[:800]}")
        out = (proc.stdout or "").rstrip("\n")
        if out == "":
            return []
        return [tuple(line.split("\t")) for line in out.splitlines()]


def one_int(ch: ClickHouse, sql: str) -> int:
    rows = ch.query_tsv(sql)
    if not rows or not rows[0] or rows[0][0] == "":
        return 0
    return int(float(rows[0][0]))


def one_row(ch: ClickHouse, sql: str) -> Tuple[str, ...]:
    rows = ch.query_tsv(sql)
    if not rows:
        return tuple()
    return rows[0]


def add(results: List[CheckResult], status: str, name: str, detail: str) -> None:
    results.append(CheckResult(status=status, name=name, detail=detail))


def check_rollup_state(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    rows = ch.query_tsv(
        """
SELECT
    job,
    toString(last_bucket),
    dateDiff('minute', last_bucket, now()) AS lag_min,
    status,
    left(last_error, 160) AS err
FROM default.traffic_rollup_state FINAL
ORDER BY job
"""
    )
    if not rows:
        add(results, "FAIL", "rollup_state", "default.traffic_rollup_state FINAL is empty")
        return

    expected_1m = {
        "traffic_dashboard_1m",
        "traffic_protocol_1m",
        "traffic_direction_1m",
        "traffic_role_1m",
        "traffic_entity_1m",
        "traffic_vlan_1m",
        "traffic_country_1m",
        "traffic_service_1m",
        "traffic_unknown_port_1m",
        "traffic_talker_1m",
        "traffic_pair_1m",
    }
    allowed_skipped = {
        "traffic_dashboard_1h",
        "traffic_dashboard_1d",
        "traffic_pair_1h",
    }
    seen = set()
    for job, last_bucket, lag_s, status, err in rows:
        seen.add(job)
        lag = int(lag_s)
        if err:
            add(results, "FAIL", f"rollup_state.{job}", f"last_error={err}")
            continue
        if job in expected_1m:
            if lag > args.max_rollup_lag_minutes:
                add(results, "FAIL", f"rollup_state.{job}", f"lag_min={lag} last_bucket={last_bucket} status={status}")
            elif status not in ("ok", "skipped_backfill"):
                add(results, "WARN", f"rollup_state.{job}", f"lag_min={lag} status={status}")
            else:
                add(results, "OK", f"rollup_state.{job}", f"lag_min={lag} status={status}")
        elif job in allowed_skipped and status == "skipped_backfill":
            add(results, "OK", f"rollup_state.{job}", f"intentionally skipped; last_bucket={last_bucket}")
        elif status == "ok":
            add(results, "OK", f"rollup_state.{job}", f"lag_min={lag}")
        else:
            add(results, "WARN", f"rollup_state.{job}", f"lag_min={lag} status={status}")

    missing = sorted(expected_1m - seen)
    if missing:
        add(results, "FAIL", "rollup_state.missing_jobs", ",".join(missing))


def check_raw_classifier(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    row = one_row(
        ch,
        f"""
SELECT
    count() AS flows,
    round(sum(bytes) / 1e9, 1) AS gb,
    countIf(direction IN ('', 'unknown', 'unclassified')) AS unknown_flows,
    round(sumIf(bytes, direction IN ('', 'unknown', 'unclassified')) / 1e9, 1) AS unknown_gb,
    round(sumIf(bytes, direction = 'out' AND src_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit') AND src_asn = 0) / 1e9, 1) AS out_local_src_asn_zero_gb,
    round(sumIf(bytes, direction = 'in' AND dst_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit') AND dst_asn = 0) / 1e9, 1) AS in_local_dst_asn_zero_gb
FROM default.flows_raw
WHERE source_id = {sql_string(args.source_id)}
  AND time_received_ns >= now64(9) - INTERVAL {args.raw_window_minutes} MINUTE
"""
    )
    if not row:
        add(results, "FAIL", "raw_classifier", "no rows")
        return
    flows, gb, unknown_flows, unknown_gb, out_zero_gb, in_zero_gb = row
    if int(flows) == 0:
        add(results, "FAIL", "raw_classifier", f"no {args.source_id} rows in {args.raw_window_minutes}m")
        return
    if float(unknown_gb) > args.max_unknown_gb:
        add(results, "FAIL", "raw_classifier.unknown_direction", f"unknown_gb={unknown_gb} unknown_flows={unknown_flows}")
    else:
        add(results, "OK", "raw_classifier.unknown_direction", f"unknown_gb={unknown_gb} total_gb={gb}")
    if float(out_zero_gb) > args.max_local_asn_zero_gb:
        add(results, "FAIL", "raw_classifier.out_local_src_asn", f"zero_gb={out_zero_gb}")
    else:
        add(results, "OK", "raw_classifier.out_local_src_asn", f"zero_gb={out_zero_gb}")
    if float(in_zero_gb) > args.max_local_asn_zero_gb:
        add(results, "FAIL", "raw_classifier.in_local_dst_asn", f"zero_gb={in_zero_gb}")
    else:
        add(results, "OK", "raw_classifier.in_local_dst_asn", f"zero_gb={in_zero_gb}")


def check_table_freshness(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    tables = [
        "traffic_dashboard_1m",
        "traffic_direction_1m",
        "traffic_role_1m",
        "traffic_entity_1m",
        "traffic_vlan_1m",
        "traffic_country_1m",
        "traffic_protocol_1m",
        "traffic_service_1m",
        "traffic_unknown_port_1m",
        "traffic_talker_1m",
        "traffic_pair_1m",
    ]
    for table in tables:
        row = one_row(
            ch,
            f"""
SELECT
    toString(max(minute)) AS max_bucket,
    dateDiff('minute', max(minute), now()) AS lag_min,
    count() AS rows
FROM default.{table}
""",
        )
        if not row:
            add(results, "FAIL", f"freshness.{table}", "query returned no row")
            continue
        max_bucket, lag_s, rows_s = row
        rows_count = int(rows_s)
        if rows_count == 0:
            if table == "traffic_vlan_1m":
                add(results, "OK", f"freshness.{table}", "empty; no VLAN config/traffic")
            else:
                add(results, "FAIL", f"freshness.{table}", "empty")
            continue
        lag = int(lag_s)
        if lag > args.max_rollup_lag_minutes:
            add(results, "FAIL", f"freshness.{table}", f"lag_min={lag} max_bucket={max_bucket} rows={rows_count}")
        else:
            add(results, "OK", f"freshness.{table}", f"lag_min={lag} rows={rows_count}")


def check_sources(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    rows = ch.query_tsv(
        """
SELECT
    table_name,
    source_id,
    ifNull(toString(include_in_total), 'NULL') AS include_in_total,
    rows,
    gb
FROM
(
    SELECT 'traffic_talker_1m' AS table_name, t.source_id, s.include_in_total, count() AS rows, round(sum(t.bytes)/1e9, 1) AS gb
    FROM default.traffic_talker_1m AS t
    LEFT JOIN default.net_flow_sources_enabled AS s ON t.source_id = s.source_id
    WHERE t.minute >= now() - INTERVAL 30 MINUTE
    GROUP BY t.source_id, s.include_in_total

    UNION ALL

    SELECT 'traffic_pair_1m', p.source_id, s.include_in_total, count(), round(sum(p.bytes)/1e9, 1)
    FROM default.traffic_pair_1m AS p
    LEFT JOIN default.net_flow_sources_enabled AS s ON p.source_id = s.source_id
    WHERE p.minute >= now() - INTERVAL 30 MINUTE
    GROUP BY p.source_id, s.include_in_total

    UNION ALL

    SELECT 'traffic_dashboard_1m', d.source_id, s.include_in_total, count(), round(sum(d.total_bytes)/1e9, 1)
    FROM default.traffic_dashboard_1m AS d
    LEFT JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
    WHERE d.minute >= now() - INTERVAL 30 MINUTE
    GROUP BY d.source_id, s.include_in_total
)
ORDER BY table_name, gb DESC
"""
    )
    excluded_status = "WARN" if args.allow_excluded_sources else "FAIL"
    for table_name, source_id, include_in_total, rows_s, gb_s in rows:
        if include_in_total == "NULL":
            add(results, "FAIL", f"sources.{table_name}.{source_id}", f"missing from net_flow_sources_enabled rows={rows_s} gb={gb_s}")
        elif include_in_total == "1":
            add(results, "OK", f"sources.{table_name}.{source_id}", f"include_in_total=1 rows={rows_s} gb={gb_s}")
        else:
            add(
                results,
                excluded_status,
                f"sources.{table_name}.{source_id}",
                f"excluded source present (include_in_total=0) rows={rows_s} gb={gb_s}; "
                f"stop its writer and purge, or pass --allow-excluded-sources",
            )


def check_talker_quality(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    rows = ch.query_tsv(
        f"""
WITH (SELECT max(minute) FROM default.traffic_talker_1m WHERE source_id={sql_string(args.source_id)}) AS ts_to
SELECT
    endpoint_side,
    direction,
    endpoint_scope,
    count() AS rows,
    countIf(endpoint_ip = '') AS empty_ip,
    round(sumIf(bytes, endpoint_scope IN ('local', 'customer') AND endpoint_asn = 0) / 1e9, 1) AS local_asn_zero_gb,
    round(sumIf(bytes, endpoint_scope = 'remote' AND endpoint_asn = 0) / 1e9, 1) AS remote_asn_zero_gb,
    round(sumIf(bytes, endpoint_ip_country = '??') / 1e9, 1) AS ip_country_unknown_gb,
    round(sumIf(bytes, endpoint_as_country = '??' AND endpoint_asn != 0) / 1e9, 1) AS as_country_unknown_known_asn_gb,
    round(sum(bytes) / 1e9, 1) AS gb
FROM default.traffic_talker_1m
WHERE source_id={sql_string(args.source_id)}
  AND minute >= ts_to - INTERVAL {args.quality_window_minutes} MINUTE
  AND minute <= ts_to
GROUP BY endpoint_side, direction, endpoint_scope
ORDER BY gb DESC
"""
    )
    if not rows:
        add(results, "FAIL", "talker_quality", "no rows in quality window")
        return
    for (
        side,
        direction,
        scope,
        rows_s,
        empty_ip_s,
        local_zero_s,
        remote_zero_s,
        ip_cc_unknown_s,
        as_cc_unknown_s,
        gb_s,
    ) in rows:
        name = f"talker_quality.{direction}.{side}.{scope}"
        if direction in ("", "unknown", "unclassified") and float(gb_s) > args.max_unknown_direction_gb:
            add(results, "FAIL", name, f"unknown_direction gb={gb_s} rows={rows_s}")
        elif scope in ("", "unknown") and float(gb_s) > args.max_unknown_scope_gb:
            add(results, "FAIL", name, f"unknown_scope gb={gb_s} rows={rows_s}")
        elif int(empty_ip_s) > 0:
            add(results, "FAIL", name, f"empty_ip_rows={empty_ip_s} rows={rows_s}")
        elif float(local_zero_s) > args.max_local_asn_zero_gb:
            add(results, "FAIL", name, f"local_asn_zero_gb={local_zero_s} gb={gb_s}")
        elif float(remote_zero_s) > args.max_remote_asn_zero_gb:
            add(results, "FAIL", name, f"remote_asn_zero_gb={remote_zero_s} gb={gb_s} (fallback IP->ASN coverage)")
        elif float(as_cc_unknown_s) > args.max_as_country_unknown_gb:
            add(results, "WARN", name, f"as_country_unknown_for_known_asn_gb={as_cc_unknown_s} gb={gb_s} (asn_registry cc gap)")
        elif float(ip_cc_unknown_s) > args.max_ip_country_unknown_gb:
            add(results, "WARN", name, f"ip_country_unknown_gb={ip_cc_unknown_s} gb={gb_s} (geo dict / private IPs)")
        elif float(remote_zero_s) > 0:
            add(results, "WARN", name, f"remote_asn_zero_gb={remote_zero_s} gb={gb_s} (BGP coverage)")
        else:
            add(results, "OK", name, f"gb={gb_s} rows={rows_s}")


def check_pair_quality(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    rows = ch.query_tsv(
        f"""
WITH (SELECT max(minute) FROM default.traffic_pair_1m WHERE source_id={sql_string(args.source_id)}) AS ts_to
SELECT
    direction,
    src_scope,
    dst_scope,
    count() AS rows,
    countIf(src_ip = '' OR dst_ip = '') AS empty_ip_rows,
    round(sumIf(bytes, src_scope IN ('local', 'customer') AND src_asn = 0) / 1e9, 1) AS src_local_asn_zero_gb,
    round(sumIf(bytes, dst_scope IN ('local', 'customer') AND dst_asn = 0) / 1e9, 1) AS dst_local_asn_zero_gb,
    round(sumIf(bytes, src_scope = 'remote' AND src_asn = 0) / 1e9, 1) AS src_remote_asn_zero_gb,
    round(sumIf(bytes, dst_scope = 'remote' AND dst_asn = 0) / 1e9, 1) AS dst_remote_asn_zero_gb,
    round(sumIf(bytes, src_ip_country = '??' OR dst_ip_country = '??') / 1e9, 1) AS ip_country_unknown_gb,
    round(sumIf(bytes, (src_as_country = '??' AND src_asn != 0) OR (dst_as_country = '??' AND dst_asn != 0)) / 1e9, 1) AS as_country_unknown_known_asn_gb,
    round(sum(bytes) / 1e9, 1) AS gb
FROM default.traffic_pair_1m
WHERE source_id={sql_string(args.source_id)}
  AND minute >= ts_to - INTERVAL {args.quality_window_minutes} MINUTE
  AND minute <= ts_to
GROUP BY direction, src_scope, dst_scope
ORDER BY gb DESC
"""
    )
    if not rows:
        add(results, "FAIL", "pair_quality", "no rows in quality window")
        return
    for (
        direction,
        src_scope,
        dst_scope,
        rows_s,
        empty_ip_s,
        src_local_zero_s,
        dst_local_zero_s,
        src_remote_zero_s,
        dst_remote_zero_s,
        ip_cc_unknown_s,
        as_cc_unknown_s,
        gb_s,
    ) in rows:
        name = f"pair_quality.{direction}.{src_scope}_to_{dst_scope}"
        if direction in ("", "unknown", "unclassified") and float(gb_s) > args.max_unknown_direction_gb:
            add(results, "FAIL", name, f"unknown_direction gb={gb_s} rows={rows_s}")
        elif (src_scope in ("", "unknown") or dst_scope in ("", "unknown")) and float(gb_s) > args.max_unknown_scope_gb:
            add(results, "FAIL", name, f"unknown_scope gb={gb_s} rows={rows_s}")
        elif int(empty_ip_s) > 0:
            add(results, "FAIL", name, f"empty_ip_rows={empty_ip_s} rows={rows_s}")
        elif float(src_local_zero_s) > args.max_local_asn_zero_gb or float(dst_local_zero_s) > args.max_local_asn_zero_gb:
            add(
                results,
                "FAIL",
                name,
                f"src_local_asn_zero_gb={src_local_zero_s} dst_local_asn_zero_gb={dst_local_zero_s} gb={gb_s}",
            )
        elif float(src_remote_zero_s) > args.max_remote_asn_zero_gb or float(dst_remote_zero_s) > args.max_remote_asn_zero_gb:
            add(
                results,
                "FAIL",
                name,
                f"remote_asn_zero_gb src={src_remote_zero_s} dst={dst_remote_zero_s} gb={gb_s} (fallback IP->ASN coverage)",
            )
        elif float(as_cc_unknown_s) > args.max_as_country_unknown_gb:
            add(results, "WARN", name, f"as_country_unknown_for_known_asn_gb={as_cc_unknown_s} gb={gb_s} (asn_registry cc gap)")
        elif float(ip_cc_unknown_s) > args.max_ip_country_unknown_gb:
            add(results, "WARN", name, f"ip_country_unknown_gb={ip_cc_unknown_s} gb={gb_s} (geo dict / private IPs)")
        elif float(src_remote_zero_s) > 0 or float(dst_remote_zero_s) > 0:
            add(
                results,
                "WARN",
                name,
                f"remote_asn_zero_gb src={src_remote_zero_s} dst={dst_remote_zero_s} gb={gb_s} (BGP coverage)",
            )
        else:
            add(results, "OK", name, f"gb={gb_s} rows={rows_s}")


def check_direction_rollup(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    row = one_row(
        ch,
        f"""
WITH (SELECT max(minute) FROM default.traffic_direction_1m WHERE source_id = {sql_string(args.source_id)}) AS ts_to
SELECT
    round(sum(bytes) / 1e9, 1) AS total_gb,
    round(sumIf(bytes, direction IN ('', 'unknown', 'unclassified')) / 1e9, 1) AS unknown_gb
FROM default.traffic_direction_1m
WHERE source_id = {sql_string(args.source_id)}
  AND minute >= ts_to - INTERVAL {args.quality_window_minutes} MINUTE
  AND minute <= ts_to
""",
    )
    if not row or row[0] == "":
        add(results, "FAIL", "direction_rollup", "no rows in quality window")
        return
    total_gb, unknown_gb = row
    if float(unknown_gb) > args.max_unknown_direction_gb:
        add(results, "FAIL", "direction_rollup.unknown_direction", f"unknown_gb={unknown_gb} total_gb={total_gb}")
    else:
        add(results, "OK", "direction_rollup.unknown_direction", f"unknown_gb={unknown_gb} total_gb={total_gb}")


def check_country_rollup(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    row = one_row(
        ch,
        f"""
WITH (SELECT max(minute) FROM default.traffic_country_1m WHERE source_id = {sql_string(args.source_id)}) AS ts_to
SELECT
    round(sum(bytes) / 1e9, 1) AS total_gb,
    round(sumIf(bytes, country_code = '??') / 1e9, 1) AS unknown_gb,
    round(100 * sumIf(bytes, country_code = '??') / nullIf(sum(bytes), 0), 1) AS unknown_pct
FROM default.traffic_country_1m
WHERE source_id = {sql_string(args.source_id)}
  AND country_basis = 'ip'
  AND minute >= ts_to - INTERVAL {args.quality_window_minutes} MINUTE
  AND minute <= ts_to
""",
    )
    if not row or row[0] == "":
        add(results, "WARN", "country_rollup", "no rows in quality window or no country_code column")
        return
    total_gb, unknown_gb, unknown_pct = row
    pct = float(unknown_pct) if unknown_pct not in ("", "\\N") else 0.0
    if pct > args.max_country_unknown_pct:
        add(results, "WARN", "country_rollup.unknown_country", f"unknown_gb={unknown_gb} ({unknown_pct}%) total_gb={total_gb}")
    else:
        add(results, "OK", "country_rollup.unknown_country", f"unknown_gb={unknown_gb} ({unknown_pct}%) total_gb={total_gb}")


def check_raw_vs_direction_agg(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    rows = ch.query_tsv(
        f"""
WITH
    (SELECT max(minute) FROM default.traffic_direction_1m WHERE source_id = {sql_string(args.source_id)}) AS ts_to,
    ts_to - INTERVAL {args.compare_window_minutes} MINUTE AS ts_from
SELECT
    direction,
    round(sumIf(gb, src = 'raw'), 1) AS raw_gb,
    round(sumIf(gb, src = 'agg'), 1) AS agg_gb,
    round(abs(raw_gb - agg_gb), 1) AS diff_gb
FROM
(
    SELECT 'raw' AS src, direction, sum(bytes) / 1e9 AS gb
    FROM default.flows_raw
    WHERE source_id = {sql_string(args.source_id)}
      AND time_received_ns >= ts_from
      AND time_received_ns < ts_to
    GROUP BY direction

    UNION ALL

    SELECT 'agg' AS src, direction, sum(bytes) / 1e9 AS gb
    FROM default.traffic_direction_1m AS d
    INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
    WHERE s.include_in_total = 1
      AND d.minute >= ts_from
      AND d.minute < ts_to
    GROUP BY direction
)
GROUP BY direction
ORDER BY direction
"""
    )
    if not rows:
        add(results, "FAIL", "raw_vs_direction_agg", "no rows")
        return
    for direction, raw_gb_s, agg_gb_s, diff_gb_s in rows:
        diff = float(diff_gb_s)
        if diff > args.max_raw_agg_diff_gb:
            add(results, "FAIL", f"raw_vs_direction_agg.{direction}", f"raw_gb={raw_gb_s} agg_gb={agg_gb_s} diff_gb={diff_gb_s}")
        else:
            add(results, "OK", f"raw_vs_direction_agg.{direction}", f"raw_gb={raw_gb_s} agg_gb={agg_gb_s} diff_gb={diff_gb_s}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Check GrapesNTA traffic data quality in ClickHouse")
    default_client = env("TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client")
    p.add_argument("--clickhouse-client", default=resolve_clickhouse_client(default_client))
    p.add_argument("--host", default=env("TRAFFIC_ROLLUP_CH_HOST", "localhost"))
    p.add_argument("--port", type=int, default=int(env("TRAFFIC_ROLLUP_CH_PORT", "9000") or 9000))
    p.add_argument("--user", default=env("TRAFFIC_ROLLUP_CH_USER", "default"))
    p.add_argument("--password", default=env("TRAFFIC_ROLLUP_CH_PASSWORD"))
    p.add_argument("--database", default=env("TRAFFIC_ROLLUP_CH_DATABASE", "default"))
    p.add_argument("--source-id", default="netflow", help="production flow source_id to validate")
    p.add_argument("--local-asn", type=int, default=0, help="expected local ASN; informational for operators")
    p.add_argument("--raw-window-minutes", type=int, default=5)
    p.add_argument("--quality-window-minutes", type=int, default=10)
    p.add_argument("--compare-window-minutes", type=int, default=10)
    p.add_argument("--max-rollup-lag-minutes", type=int, default=25)
    p.add_argument("--max-unknown-gb", type=float, default=0.1, help="max GB of raw flows with unknown direction")
    p.add_argument("--max-unknown-direction-gb", type=float, default=0.1, help="max GB in rollups with empty/unknown direction")
    p.add_argument("--max-unknown-scope-gb", type=float, default=0.1, help="max GB in talker/pair with empty/unknown scope")
    p.add_argument("--max-local-asn-zero-gb", type=float, default=0.1)
    p.add_argument("--max-remote-asn-zero-gb", type=float, default=10.0, help="FAIL above this GB of remote traffic with ASN=0")
    p.add_argument("--max-ip-country-unknown-gb", type=float, default=5.0, help="WARN above this GB of '??' IP country (private/bogon expected small)")
    p.add_argument("--max-as-country-unknown-gb", type=float, default=5.0, help="WARN above this GB of '??' AS country where ASN is known")
    p.add_argument("--max-country-unknown-pct", type=float, default=5.0, help="WARN above this %% of bytes with '??' IP country in traffic_country_1m")
    p.add_argument("--max-raw-agg-diff-gb", type=float, default=1.0)
    p.add_argument(
        "--allow-excluded-sources",
        action="store_true",
        help="downgrade 'excluded source present (include_in_total=0)' from FAIL to WARN",
    )
    p.add_argument("--warn-only", action="store_true", help="exit 0 when WARN exists but no FAIL")
    return p.parse_args()


def print_results(results: Sequence[CheckResult]) -> None:
    order = {"FAIL": 0, "WARN": 1, "OK": 2}
    for result in sorted(results, key=lambda r: (order.get(r.status, 9), r.name)):
        print(f"{result.status}\t{result.name}\t{result.detail}")


def main() -> int:
    args = parse_args()
    if args.local_asn:
        print(f"INFO\tconfig\tlocal_asn={args.local_asn} source_id={args.source_id}")
    ch = ClickHouse(args)
    results: List[CheckResult] = []

    checks = [
        ("rollup_state", lambda: check_rollup_state(ch, args, results)),
        ("raw_classifier", lambda: check_raw_classifier(ch, args, results)),
        ("table_freshness", lambda: check_table_freshness(ch, args, results)),
        ("sources", lambda: check_sources(ch, args, results)),
        ("direction_rollup", lambda: check_direction_rollup(ch, args, results)),
        ("country_rollup", lambda: check_country_rollup(ch, args, results)),
        ("talker_quality", lambda: check_talker_quality(ch, args, results)),
        ("pair_quality", lambda: check_pair_quality(ch, args, results)),
        ("raw_vs_direction_agg", lambda: check_raw_vs_direction_agg(ch, args, results)),
    ]
    for name, fn in checks:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - CLI health check should report all failures.
            add(results, "FAIL", name, str(exc))

    print_results(results)
    if any(r.status == "FAIL" for r in results):
        return 2
    if any(r.status == "WARN" for r in results) and not args.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
