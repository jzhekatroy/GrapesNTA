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
  - raw vs aggregate consistency by direction;
  - pipeline throughput: rates on collector/xdpflowd/flows_raw/rollups and
    percent deviation between stages (optional live window via --coverage-window-sec).

Exit codes: 0 = OK, 1 = WARN only, 2 = FAIL.

Typical usage on a collector (env is auto-loaded from /etc/grapesnta/traffic-rollups.env):

  python3 scripts/check_traffic_data_quality.py

Or with explicit env:

  set -a
  source /etc/grapesnta/traffic-rollups.env
  set +a
  python3 scripts/check_traffic_data_quality.py --local-asn 34665
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Roles that must have origin_asn; system private prefixes (internal) may legitimately have asn=0.
LOCAL_ORIGIN_ROLES = ("provider_public", "customer_allocated", "customer_transit")
LOCAL_ORIGIN_ROLES_SQL = ", ".join(f"'{role}'" for role in LOCAL_ORIGIN_ROLES)

# traffic_pair_1m has no network_role; exclude RFC1918/CGNAT/link-local/loopback by-CIDR instead.
PRIVATE_IP_EXCLUDE_SRC_SQL = """
NOT (
    isIPAddressInRange(src_ip, '10.0.0.0/8') OR
    isIPAddressInRange(src_ip, '172.16.0.0/12') OR
    isIPAddressInRange(src_ip, '192.168.0.0/16') OR
    isIPAddressInRange(src_ip, '100.64.0.0/10') OR
    isIPAddressInRange(src_ip, '127.0.0.0/8') OR
    isIPAddressInRange(src_ip, '169.254.0.0/16') OR
    isIPAddressInRange(src_ip, 'fc00::/7') OR
    isIPAddressInRange(src_ip, 'fe80::/10') OR
    isIPAddressInRange(src_ip, '::1/128')
)
""".strip()
PRIVATE_IP_EXCLUDE_DST_SQL = PRIVATE_IP_EXCLUDE_SRC_SQL.replace("src_ip", "dst_ip")

DEFAULT_ENV_FILES = (
    "/etc/grapesnta/traffic-rollups.env",
    "/etc/grapesnta/traffic-talkers-rollups.env",
)

MINUTE_ROLLUP_JOBS = {
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

HOURLY_ROLLUP_JOBS = {
    "traffic_dashboard_1h",
    "traffic_talker_1h",
    "traffic_pair_1h",
}

DAILY_ROLLUP_JOBS = {
    "traffic_dashboard_1d",
}


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def load_env_file(path: str, *, override: bool = False) -> bool:
    """Load KEY=VALUE pairs from a systemd-style env file into os.environ."""
    if not os.path.isfile(path):
        return False
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if not key:
                continue
            if override or env(key) is None:
                os.environ[key] = value
    return True


def bootstrap_env(explicit_files: Sequence[str]) -> List[str]:
    """Load rollup env files unless TRAFFIC_ROLLUP_CH_HOST is already set."""
    loaded: List[str] = []
    if env("TRAFFIC_ROLLUP_CH_HOST"):
        return loaded
    paths = list(explicit_files) if explicit_files else list(DEFAULT_ENV_FILES)
    for path in paths:
        if load_env_file(path):
            loaded.append(path)
    return loaded


def rollup_job_kind(job: str) -> str:
    if job in MINUTE_ROLLUP_JOBS or job.endswith("_1m"):
        return "1m"
    if job in HOURLY_ROLLUP_JOBS or job.endswith("_1h"):
        return "1h"
    if job in DAILY_ROLLUP_JOBS or job.endswith("_1d"):
        return "1d"
    return "other"


def max_lag_for_job(job: str, args: argparse.Namespace) -> int:
    kind = rollup_job_kind(job)
    if kind == "1m":
        return args.max_rollup_lag_minutes
    if kind == "1h":
        return args.max_hourly_lag_minutes
    if kind == "1d":
        return args.max_daily_lag_minutes
    return args.max_rollup_lag_minutes


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


def pct_ratio(numerator: float, denominator: float) -> Optional[float]:
    if denominator <= 0:
        return None
    return 100.0 * numerator / denominator


def pct_deviation(ratio_pct: Optional[float]) -> Optional[float]:
    if ratio_pct is None:
        return None
    return ratio_pct - 100.0


def format_ratio_pct(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}%"


def format_deviation_pct(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value:+.2f}%" if value > 0 else f"{value:.2f}%"


def format_rate(packets: int, bytes_: int, window_sec: int) -> str:
    if window_sec <= 0:
        return "pps=0 gbps=0"
    pps = packets / window_sec
    gbps = (bytes_ * 8) / window_sec / 1e9
    return f"pps={pps:,.0f} gbps={gbps:.2f}"


def read_int_file(path: str) -> int:
    try:
        return int(Path(path).read_text().strip())
    except OSError:
        return 0


def load_env_value(path: str, key: str) -> Optional[str]:
    if not os.path.isfile(path):
        return None
    prefix = key + "="
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or not line.startswith(prefix):
                continue
            value = line[len(prefix) :].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            return value
    return None


def resolve_mirror_iface(args: argparse.Namespace) -> str:
    if args.iface:
        return args.iface
    for path in (args.xdp_env_file, "/etc/xdpflowd/xdpflowd.env"):
        value = load_env_value(path, "XDPFLOWD_IFACE")
        if value:
            return value
    return "ens1np0"


def read_sysfs_rx(iface: str) -> Tuple[int, int]:
    base = f"/sys/class/net/{iface}/statistics"
    return read_int_file(f"{base}/rx_packets"), read_int_file(f"{base}/rx_bytes")


def read_nic_wire_pkts(iface: str) -> int:
    proc = subprocess.run(
        ["ethtool", "-S", iface],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return 0
    total = 0
    for line in (proc.stdout or "").splitlines():
        m = re.match(r"^\s*rx(\d+)_xdp_drop:\s*(\d+)", line)
        if m:
            total += int(m.group(2))
            continue
        m = re.match(r"^\s*rx(\d+)_xdp_packets:\s*(\d+)", line)
        if m:
            total += int(m.group(2))
    if total > 0:
        return total
    for line in (proc.stdout or "").splitlines():
        m = re.match(r"^\s*rx_xdp_drop:\s*(\d+)", line)
        if m:
            return int(m.group(1))
    return 0


def parse_xdp_stats_line(line: str) -> Dict[str, int]:
    keys = (
        "total_packets",
        "parse_errors",
        "map_full",
        "non_ip_pass",
        "accounted_packets",
        "vlan_tag_seen",
    )
    out: Dict[str, int] = {}
    for key in keys:
        m = re.search(rf"{key}=(\d+)", line)
        if m:
            out[key] = int(m.group(1))
    return out


def read_xdp_stats(unit: str) -> Dict[str, int]:
    proc = subprocess.run(
        ["journalctl", "-u", unit, "--since", "2 minutes ago", "--no-pager", "-o", "cat"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return {}
    for line in reversed((proc.stdout or "").splitlines()):
        if "msg=stats" in line and "total_packets=" in line:
            return parse_xdp_stats_line(line)
    return {}


def utc_now_sql() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def query_ch_window_totals(
    ch: ClickHouse, args: argparse.Namespace, t0: str, t1: str
) -> Tuple[int, int]:
    row = one_row(
        ch,
        f"""
SELECT sum(packets), sum(bytes)
FROM default.flows_raw
WHERE source_id = {sql_string(args.source_id)}
  AND time_received_ns >= toDateTime64({sql_string(t0)}, 9, 'UTC')
  AND time_received_ns <  toDateTime64({sql_string(t1)}, 9, 'UTC')
""",
    )
    if not row:
        return 0, 0
    return int(float(row[0] or 0)), int(float(row[1] or 0))


def query_stage_rates(
    ch: ClickHouse, args: argparse.Namespace, window_minutes: int
) -> Tuple[str, str, List[Tuple[str, int, int]]]:
    """Return (ts_from, ts_to, stage totals) on a closed-minute window aligned to rollups."""
    source = sql_string(args.source_id)
    anchor = one_row(
        ch,
        f"""
SELECT
    toString(least(
        (SELECT max(minute) FROM default.traffic_dashboard_1m WHERE source_id = {source}),
        (SELECT max(minute) FROM default.traffic_direction_1m WHERE source_id = {source}),
        (SELECT max(minute) FROM default.traffic_pair_1m WHERE source_id = {source})
    )) AS ts_to,
    toString(
        least(
            (SELECT max(minute) FROM default.traffic_dashboard_1m WHERE source_id = {source}),
            (SELECT max(minute) FROM default.traffic_direction_1m WHERE source_id = {source}),
            (SELECT max(minute) FROM default.traffic_pair_1m WHERE source_id = {source})
        ) - INTERVAL {window_minutes} MINUTE
    ) AS ts_from
""",
    )
    if not anchor or not anchor[0] or anchor[0].startswith("1970-"):
        return "", "", []
    ts_to, ts_from = anchor[0], anchor[1]
    rows = ch.query_tsv(
        f"""
SELECT stage, packets, bytes
FROM
(
    SELECT
        'flows_raw' AS stage,
        sum(packets) AS packets,
        sum(bytes) AS bytes
    FROM default.flows_raw
    WHERE source_id = {source}
      AND time_received_ns >= toDateTime({sql_string(ts_from)})
      AND time_received_ns <  toDateTime({sql_string(ts_to)})

    UNION ALL

    SELECT
        'dashboard_1m' AS stage,
        sum(total_packets) AS packets,
        sum(total_bytes) AS bytes
    FROM default.traffic_dashboard_1m
    WHERE source_id = {source}
      AND minute >= toDateTime({sql_string(ts_from)})
      AND minute <  toDateTime({sql_string(ts_to)})

    UNION ALL

    SELECT
        'direction_1m' AS stage,
        sum(packets) AS packets,
        sum(bytes) AS bytes
    FROM default.traffic_direction_1m
    WHERE source_id = {source}
      AND minute >= toDateTime({sql_string(ts_from)})
      AND minute <  toDateTime({sql_string(ts_to)})

    UNION ALL

    SELECT
        'pair_1m' AS stage,
        sum(packets) AS packets,
        sum(bytes) AS bytes
    FROM default.traffic_pair_1m
    WHERE source_id = {source}
      AND minute >= toDateTime({sql_string(ts_from)})
      AND minute <  toDateTime({sql_string(ts_to)})
)
ORDER BY bytes DESC
"""
    )
    out: List[Tuple[str, int, int]] = []
    for stage, packets_s, bytes_s in rows:
        out.append((stage, int(float(packets_s or 0)), int(float(bytes_s or 0))))
    return ts_from, ts_to, out


def check_pipeline_coverage(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    window_sec = args.coverage_window_sec
    if window_sec <= 0:
        return

    iface = resolve_mirror_iface(args)
    print(
        f"INFO\tcoverage\tmeasuring pipeline for {window_sec}s on iface={iface} "
        f"source_id={args.source_id}"
    )

    xdp0 = read_xdp_stats(args.xdp_unit)
    wire0 = read_nic_wire_pkts(iface)
    sysfs0 = read_sysfs_rx(iface)
    t0 = utc_now_sql()

    time.sleep(window_sec)

    xdp1 = read_xdp_stats(args.xdp_unit)
    wire1 = read_nic_wire_pkts(iface)
    sysfs1 = read_sysfs_rx(iface)
    t1 = utc_now_sql()

    if not xdp0 or not xdp1:
        add(
            results,
            "WARN",
            "coverage.xdpflowd",
            f"cannot read msg=stats from journalctl -u {args.xdp_unit}; run as root on collector host",
        )
    else:
        d_total = xdp1.get("total_packets", 0) - xdp0.get("total_packets", 0)
        d_accounted = xdp1.get("accounted_packets", 0) - xdp0.get("accounted_packets", 0)
        d_parse = xdp1.get("parse_errors", 0) - xdp0.get("parse_errors", 0)
        d_map_full = xdp1.get("map_full", 0) - xdp0.get("map_full", 0)
        d_non_ip = xdp1.get("non_ip_pass", 0) - xdp0.get("non_ip_pass", 0)
        identity = d_accounted + d_parse + d_map_full + d_non_ip

        add(
            results,
            "OK",
            "coverage.xdpflowd.total",
            f"window_sec={window_sec} packets={d_total} {format_rate(d_total, 0, window_sec)}",
        )
        add(
            results,
            "OK",
            "coverage.xdpflowd.accounted",
            f"window_sec={window_sec} packets={d_accounted} {format_rate(d_accounted, 0, window_sec)}",
        )
        if d_map_full > 0:
            add(
                results,
                "FAIL",
                "coverage.xdpflowd.map_full",
                f"map_full_delta={d_map_full} over {window_sec}s — packets lost before export",
            )
        else:
            add(results, "OK", "coverage.xdpflowd.map_full", f"map_full_delta=0 window_sec={window_sec}")

        if d_total > 0 and identity != d_total:
            diff = abs(d_total - identity)
            diff_pct = 100.0 * diff / d_total
            if diff <= args.max_identity_packet_diff or diff_pct <= args.max_identity_packet_pct:
                add(
                    results,
                    "OK",
                    "coverage.xdpflowd.identity",
                    f"accounted+loss={identity} total={d_total} diff={d_total - identity} "
                    f"(within noise ≤{args.max_identity_packet_diff} pkts / {args.max_identity_packet_pct}%)",
                )
            else:
                add(
                    results,
                    "FAIL",
                    "coverage.xdpflowd.identity",
                    f"accounted+parse+map_full+non_ip={identity} != total={d_total} diff={d_total - identity}",
                )
        elif d_total > 0:
            add(results, "OK", "coverage.xdpflowd.identity", f"accounted+loss={identity} total={d_total}")

    ch_pkts, ch_bytes = query_ch_window_totals(ch, args, t0, t1)
    add(
        results,
        "OK" if ch_pkts > 0 else "FAIL",
        "coverage.clickhouse.flows_raw",
        f"window_sec={window_sec} packets={ch_pkts} bytes={ch_bytes} {format_rate(ch_pkts, ch_bytes, window_sec)}",
    )

    if xdp0 and xdp1:
        d_total = xdp1.get("total_packets", 0) - xdp0.get("total_packets", 0)
        d_accounted = xdp1.get("accounted_packets", 0) - xdp0.get("accounted_packets", 0)
        if d_accounted > 0:
            ratio = pct_ratio(ch_pkts, d_accounted)
            dev = pct_deviation(ratio)
            status = "OK"
            if ratio is not None and abs(dev or 0) > args.max_coverage_deviation_pct:
                status = "WARN"
            add(
                results,
                status,
                "coverage.ratio.ch_vs_accounted",
                f"ch_pkts={ch_pkts} accounted_pkts={d_accounted} ratio={format_ratio_pct(ratio)} "
                f"deviation={format_deviation_pct(dev)} threshold=±{args.max_coverage_deviation_pct}%",
            )
        if d_total > 0:
            ratio = pct_ratio(ch_pkts, d_total)
            dev = pct_deviation(ratio)
            add(
                results,
                "OK",
                "coverage.ratio.ch_vs_total",
                f"ch_pkts={ch_pkts} total_pkts={d_total} ratio={format_ratio_pct(ratio)} deviation={format_deviation_pct(dev)}",
            )
            acc_ratio = pct_ratio(d_accounted, d_total)
            acc_dev = pct_deviation(acc_ratio)
            add(
                results,
                "OK",
                "coverage.ratio.accounted_vs_total",
                f"accounted_pkts={d_accounted} total_pkts={d_total} ratio={format_ratio_pct(acc_ratio)} "
                f"deviation={format_deviation_pct(acc_dev)}",
            )

    d_wire = wire1 - wire0
    if d_wire > 0:
        add(
            results,
            "OK",
            "coverage.wire.ethtool",
            f"window_sec={window_sec} packets={d_wire} source=ethtool_xdp counters",
        )
        if xdp0 and xdp1:
            d_total = xdp1.get("total_packets", 0) - xdp0.get("total_packets", 0)
            ratio = pct_ratio(d_total, d_wire)
            dev = pct_deviation(ratio)
            status = "OK"
            if ratio is not None and abs(dev or 0) > args.max_coverage_deviation_pct:
                status = "WARN"
            add(
                results,
                status,
                "coverage.ratio.xdp_vs_wire",
                f"xdp_total={d_total} wire_pkts={d_wire} ratio={format_ratio_pct(ratio)} "
                f"deviation={format_deviation_pct(dev)} threshold=±{args.max_coverage_deviation_pct}%",
            )
    else:
        d_sysfs_pkts = sysfs1[0] - sysfs0[0]
        d_sysfs_bytes = sysfs1[1] - sysfs0[1]
        if d_sysfs_pkts > 0:
            add(
                results,
                "WARN",
                "coverage.wire.sysfs",
                f"window_sec={window_sec} rx_packets={d_sysfs_pkts} {format_rate(d_sysfs_pkts, d_sysfs_bytes, window_sec)} "
                f"(sysfs may undercount while XDP is attached)",
            )
        else:
            add(
                results,
                "WARN",
                "coverage.wire",
                f"no ethtool xdp_* counters and sysfs delta=0 on {iface}; use xdp_vs_ch ratios only",
            )


def check_stage_rate_consistency(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    ts_from, ts_to, stages = query_stage_rates(ch, args, args.compare_window_minutes)
    if not stages:
        add(results, "FAIL", "coverage.stages", f"no CH stage data in closed {args.compare_window_minutes}m window")
        return

    ref_pkts = 0
    ref_bytes = 0
    for stage, packets, bytes_ in stages:
        if stage == "flows_raw":
            ref_pkts, ref_bytes = packets, bytes_

    if ref_bytes <= 0:
        add(results, "FAIL", "coverage.stages.flows_raw", f"no flows_raw bytes in [{ts_from}, {ts_to})")
        return

    window_sec = args.compare_window_minutes * 60
    add(
        results,
        "OK",
        "coverage.stages.flows_raw",
        f"window=[{ts_from}, {ts_to}) packets={ref_pkts} bytes={ref_bytes} "
        f"{format_rate(ref_pkts, ref_bytes, window_sec)}",
    )

    for stage, packets, bytes_ in stages:
        if stage == "flows_raw":
            continue
        pkt_ratio = pct_ratio(packets, ref_pkts)
        byte_ratio = pct_ratio(bytes_, ref_bytes)
        pkt_dev = pct_deviation(pkt_ratio)
        byte_dev = pct_deviation(byte_ratio)
        status = "OK"
        if byte_ratio is not None and abs(byte_dev or 0) > args.max_stage_deviation_pct:
            status = "WARN"
        add(
            results,
            status,
            f"coverage.stages.{stage}",
            f"packets={packets} bytes={bytes_} {format_rate(packets, bytes_, window_sec)} "
            f"bytes_of_raw={format_ratio_pct(byte_ratio)} bytes_dev={format_deviation_pct(byte_dev)} "
            f"pkts_of_raw={format_ratio_pct(pkt_ratio)} threshold=±{args.max_stage_deviation_pct}%",
        )


def is_meaningful_bucket(ts: str) -> bool:
    """ClickHouse max() on empty tables returns epoch; treat as no data."""
    if not ts:
        return False
    return not ts.startswith("1970-")


def format_table_lag_bit(table_key: str, table_rows: dict) -> str:
    if table_key not in table_rows:
        return ""
    table_mx, table_lag = table_rows[table_key]
    if is_meaningful_bucket(table_mx):
        return f" table_max={table_mx} table_lag_min={table_lag}"
    return " table=empty"


def check_lag_summary(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    """Human-friendly lag view: state cursor + table max bucket side by side."""
    state_rows = ch.query_tsv(
        """
SELECT
    job,
    dateDiff('minute', last_bucket, now()) AS lag_min,
    status,
    left(last_error, 120) AS err,
    toString(last_bucket) AS last_bucket_s
FROM default.traffic_rollup_state FINAL
WHERE job LIKE 'traffic_%'
ORDER BY job
"""
    )
    if not state_rows:
        add(results, "FAIL", "lag.summary", "traffic_rollup_state is empty")
        return

    table_lag_sql = """
SELECT 'dashboard_1m' AS t, toString(max(minute)) AS mx, dateDiff('minute', max(minute), now()) AS lag
FROM default.traffic_dashboard_1m
UNION ALL SELECT 'talker_1m', toString(max(minute)), dateDiff('minute', max(minute), now())
FROM default.traffic_talker_1m WHERE source_id = {source_id}
UNION ALL SELECT 'pair_1m', toString(max(minute)), dateDiff('minute', max(minute), now())
FROM default.traffic_pair_1m WHERE source_id = {source_id}
UNION ALL SELECT 'dashboard_1h', toString(max(hour)), dateDiff('minute', max(hour), now())
FROM default.traffic_dashboard_1h
UNION ALL SELECT 'talker_1h', toString(max(hour)), dateDiff('minute', max(hour), now())
FROM default.traffic_talker_1h WHERE source_id = {source_id}
UNION ALL SELECT 'pair_1h', toString(max(hour)), dateDiff('minute', max(hour), now())
FROM default.traffic_pair_1h WHERE source_id = {source_id}
UNION ALL SELECT 'dashboard_1d', toString(max(day)), dateDiff('minute', max(day), now())
FROM default.traffic_dashboard_1d
""".format(source_id=sql_string(args.source_id))
    table_rows = {t: (mx, int(lag)) for t, mx, lag in ch.query_tsv(table_lag_sql)}

    for job, lag_s, status, err, last_bucket in state_rows:
        lag = int(lag_s)
        kind = rollup_job_kind(job)
        max_lag = max_lag_for_job(job, args)
        table_key = job.replace("traffic_", "")
        table_bit = format_table_lag_bit(table_key, table_rows)
        table_empty = table_key in table_rows and "table=empty" in table_bit
        if err:
            add(results, "FAIL", f"lag.{kind}.{job}", f"lag_min={lag} last_bucket={last_bucket} err={err}{table_bit}")
            continue
        if lag > max_lag:
            add(
                results,
                "FAIL",
                f"lag.{kind}.{job}",
                f"lag_min={lag} > max={max_lag} last_bucket={last_bucket} status={status}{table_bit}",
            )
        elif table_empty and kind == "1d":
            add(
                results,
                "WARN",
                f"lag.{kind}.{job}",
                f"lag_min={lag} last_bucket={last_bucket} state ok but table has no rows{table_bit}",
            )
        elif kind == "1h":
            add(
                results,
                "OK",
                f"lag.{kind}.{job}",
                f"lag_min={lag} last_bucket={last_bucket} (hourly; waits for closed hour){table_bit}",
            )
        elif kind == "1d":
            add(
                results,
                "OK",
                f"lag.{kind}.{job}",
                f"lag_min={lag} last_bucket={last_bucket} (daily; waits for closed day){table_bit}",
            )
        else:
            add(
                results,
                "OK",
                f"lag.{kind}.{job}",
                f"lag_min={lag} last_bucket={last_bucket} status={status}{table_bit}",
            )


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

    expected_1m = MINUTE_ROLLUP_JOBS
    allowed_skipped = HOURLY_ROLLUP_JOBS | DAILY_ROLLUP_JOBS
    seen = set()
    for job, last_bucket, lag_s, status, err in rows:
        seen.add(job)
        lag = int(lag_s)
        max_lag = max_lag_for_job(job, args)
        if err:
            add(results, "FAIL", f"rollup_state.{job}", f"last_error={err}")
            continue
        if job in expected_1m:
            if lag > max_lag:
                add(results, "FAIL", f"rollup_state.{job}", f"lag_min={lag} last_bucket={last_bucket} status={status}")
            elif status not in ("ok", "skipped_backfill"):
                add(results, "WARN", f"rollup_state.{job}", f"lag_min={lag} status={status}")
            else:
                add(results, "OK", f"rollup_state.{job}", f"lag_min={lag} status={status}")
        elif job in allowed_skipped and status == "skipped_backfill":
            add(results, "OK", f"rollup_state.{job}", f"intentionally skipped; last_bucket={last_bucket}")
        elif status == "ok":
            if lag > max_lag:
                add(results, "FAIL", f"rollup_state.{job}", f"lag_min={lag} last_bucket={last_bucket}")
            else:
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
    round(sumIf(bytes, direction = 'out' AND src_role IN ({LOCAL_ORIGIN_ROLES_SQL}) AND src_asn = 0) / 1e9, 1) AS out_local_src_asn_zero_gb,
    round(sumIf(bytes, direction = 'in' AND dst_role IN ({LOCAL_ORIGIN_ROLES_SQL}) AND dst_asn = 0) / 1e9, 1) AS in_local_dst_asn_zero_gb
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
    round(sumIf(bytes, endpoint_scope IN ('local', 'customer') AND endpoint_network_role IN ({LOCAL_ORIGIN_ROLES_SQL}) AND endpoint_asn = 0) / 1e9, 1) AS local_asn_zero_gb,
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
    round(sumIf(bytes, src_scope IN ('local', 'customer') AND src_asn = 0 AND {PRIVATE_IP_EXCLUDE_SRC_SQL}) / 1e9, 1) AS src_local_asn_zero_gb,
    round(sumIf(bytes, dst_scope IN ('local', 'customer') AND dst_asn = 0 AND {PRIVATE_IP_EXCLUDE_DST_SQL}) / 1e9, 1) AS dst_local_asn_zero_gb,
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
    p.add_argument(
        "--env-file",
        action="append",
        default=[],
        metavar="PATH",
        help="env file to load when TRAFFIC_ROLLUP_CH_* are unset (default: /etc/grapesnta/traffic-rollups.env)",
    )
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
    p.add_argument("--max-rollup-lag-minutes", type=int, default=25, help="FAIL if *_1m rollup lag exceeds this")
    p.add_argument(
        "--max-hourly-lag-minutes",
        type=int,
        default=180,
        help="FAIL if *_1h rollup lag exceeds this (closed hour + safety; ~120 is normal)",
    )
    p.add_argument(
        "--max-daily-lag-minutes",
        type=int,
        default=2880,
        help="FAIL if *_1d rollup lag exceeds this (daily job runs once per closed day; up to ~48h is normal)",
    )
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
        "--coverage-window-sec",
        type=int,
        default=60,
        help="live pipeline measurement window: xdpflowd vs flows_raw (0=skip sleep measurement)",
    )
    p.add_argument(
        "--skip-coverage",
        action="store_true",
        help="skip live pipeline measurement and stage rate checks",
    )
    p.add_argument("--iface", default="", help="mirror NIC for wire counters (default: XDPFLOWD_IFACE from env)")
    p.add_argument("--xdp-unit", default="xdpflowd", help="systemd unit for xdpflowd stats")
    p.add_argument("--xdp-env-file", default="/etc/xdpflowd/xdpflowd.env", help="env file with XDPFLOWD_IFACE")
    p.add_argument(
        "--max-coverage-deviation-pct",
        type=float,
        default=5.0,
        help="WARN if CH/accounted or xdp/wire ratio deviates more than this from 100%%",
    )
    p.add_argument(
        "--max-stage-deviation-pct",
        type=float,
        default=3.0,
        help="WARN if rollup stage bytes deviate more than this from flows_raw",
    )
    p.add_argument(
        "--max-identity-packet-diff",
        type=int,
        default=1000,
        help="treat xdpflowd identity mismatch as noise below this packet delta",
    )
    p.add_argument(
        "--max-identity-packet-pct",
        type=float,
        default=0.01,
        help="treat xdpflowd identity mismatch as noise below this %% of total_packets",
    )
    p.add_argument(
        "--allow-excluded-sources",
        action="store_true",
        help="downgrade 'excluded source present (include_in_total=0)' from FAIL to WARN",
    )
    p.add_argument("--warn-only", action="store_true", help="exit 0 when WARN exists but no FAIL")
    return p.parse_args()


def print_results(results: Sequence[CheckResult]) -> None:
    order = {"FAIL": 0, "WARN": 1, "OK": 2}

    def sort_key(r: CheckResult) -> Tuple[int, int, str]:
        if r.name.startswith("lag."):
            section = 0
        elif r.name.startswith("coverage."):
            section = 1
        else:
            section = 2
        return (section, order.get(r.status, 9), r.name)

    for result in sorted(results, key=sort_key):
        print(f"{result.status}\t{result.name}\t{result.detail}")


def main() -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", action="append", default=[])
    pre_args, _ = pre.parse_known_args()
    loaded_env = bootstrap_env(pre_args.env_file)

    args = parse_args()
    if loaded_env:
        print(f"INFO\tconfig\tenv={' '.join(loaded_env)} host={args.host} port={args.port} user={args.user}")
    else:
        print(f"INFO\tconfig\thost={args.host} port={args.port} user={args.user} database={args.database}")
    if args.local_asn:
        print(f"INFO\tconfig\tlocal_asn={args.local_asn} source_id={args.source_id}")
    ch = ClickHouse(args)
    results: List[CheckResult] = []

    checks = [
        ("lag_summary", lambda: check_lag_summary(ch, args, results)),
    ]
    if not args.skip_coverage:
        checks.append(("stage_rate_consistency", lambda: check_stage_rate_consistency(ch, args, results)))
        if args.coverage_window_sec > 0:
            checks.append(("pipeline_coverage", lambda: check_pipeline_coverage(ch, args, results)))
    checks.extend([
        ("rollup_state", lambda: check_rollup_state(ch, args, results)),
        ("raw_classifier", lambda: check_raw_classifier(ch, args, results)),
        ("table_freshness", lambda: check_table_freshness(ch, args, results)),
        ("sources", lambda: check_sources(ch, args, results)),
        ("direction_rollup", lambda: check_direction_rollup(ch, args, results)),
        ("country_rollup", lambda: check_country_rollup(ch, args, results)),
        ("talker_quality", lambda: check_talker_quality(ch, args, results)),
        ("pair_quality", lambda: check_pair_quality(ch, args, results)),
        ("raw_vs_direction_agg", lambda: check_raw_vs_direction_agg(ch, args, results)),
    ])
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
