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
  - pipeline throughput: live rates on the local collector (xdpflowd or
    flowcollectord) vs ClickHouse flows_raw and rollup stages;
  - sFlow-specific sanity: bytes/packets ≈ frame length, sampling_rate bounds,
    parse-error ratio, optional volume vs --expected-max-gbps.

Exit codes: 0 = OK, 1 = WARN only, 2 = FAIL.

Typical usage (env auto-loaded from /etc/grapesnta/traffic-rollups.env):

  # XDP mirror collector (m61): auto-detects xdpflowd + XDPFLOWD_SOURCE_ID
  python3 scripts/check_traffic_data_quality.py

  # sFlow collector (netflow-test): auto-detects flowcollectord + sflow-default
  python3 scripts/check_traffic_data_quality.py --collector sflow --expected-max-gbps 15

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
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlparse

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


def no_asn_expected_sql(col: str) -> str:
    """Ranges that legitimately have no origin ASN (multicast / reserved / broadcast).

    IPTV/streaming multicast (224.0.0.0/4) and reserved space (240.0.0.0/4,
    including 255.255.255.255 broadcast) plus IPv6 multicast (ff00::/8) are never
    advertised in BGP or iptoasn, so dst/src ASN=0 there is expected, not a gap.
    """
    return (
        f"(isIPAddressInRange({col}, '224.0.0.0/4') OR "
        f"isIPAddressInRange({col}, '240.0.0.0/4') OR "
        f"isIPAddressInRange({col}, 'ff00::/8'))"
    )

DEFAULT_ENV_FILES = (
    "/etc/grapesnta/traffic-rollups.env",
    "/etc/grapesnta/traffic-talkers-rollups.env",
    "/etc/flowcollectord/flowcollectord.env",
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


def apply_clickhouse_dsn_defaults(args: argparse.Namespace) -> bool:
    """Use collector DSN when rollup env vars are absent on a collector-only host."""
    dsn = env("FC_CH_DSN") or env("XDP_CH_DSN") or env("DNS_CH_DSN") or env("BMP_CH_DSN")
    if not dsn:
        return False
    parsed = urlparse(dsn)
    if parsed.scheme not in ("clickhouse", "clickhouses") or not parsed.hostname:
        return False

    if args.host == "localhost" and env("TRAFFIC_ROLLUP_CH_HOST") is None:
        args.host = parsed.hostname
    if args.port == 9000 and env("TRAFFIC_ROLLUP_CH_PORT") is None:
        args.port = parsed.port or (9440 if parsed.scheme == "clickhouses" else 9000)
    if args.user == "default" and env("TRAFFIC_ROLLUP_CH_USER") is None and parsed.username:
        args.user = unquote(parsed.username)
    if (args.password is None or args.password == "") and env("TRAFFIC_ROLLUP_CH_PASSWORD") is None and parsed.password:
        args.password = unquote(parsed.password)
    if args.database == "default" and env("TRAFFIC_ROLLUP_CH_DATABASE") is None:
        database = parsed.path.lstrip("/")
        if database:
            args.database = database
    return True


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


@dataclass
class SFlowCaptureSummary:
    datagrams: int = 0
    flow_samples: int = 0
    counter_samples: int = 0
    raw_records: int = 0
    parsed_records: int = 0
    parse_errors: int = 0
    sampled_frame_bytes: int = 0
    extrapolated_packets: int = 0
    extrapolated_bytes: int = 0
    min_sampling_rate: int = 0
    max_sampling_rate: int = 0

    def add_record(self, frame_length: int, sampling_rate: int) -> None:
        rate = sampling_rate if sampling_rate > 0 else 1
        self.parsed_records += 1
        self.sampled_frame_bytes += frame_length
        self.extrapolated_packets += rate
        self.extrapolated_bytes += frame_length * rate
        if self.min_sampling_rate == 0 or rate < self.min_sampling_rate:
            self.min_sampling_rate = rate
        if rate > self.max_sampling_rate:
            self.max_sampling_rate = rate


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


def resolve_sflow_iface(args: argparse.Namespace) -> str:
    if args.sflow_iface:
        return args.sflow_iface
    return args.sflow_iface_default


def systemctl_is_active(unit: str) -> bool:
    proc = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def detect_collector_mode(args: argparse.Namespace) -> str:
    if args.collector != "auto":
        return args.collector
    has_xdp = systemctl_is_active(args.xdp_unit)
    has_sflow = systemctl_is_active(args.flow_unit)
    if has_sflow and not has_xdp:
        return "sflow"
    if has_xdp and not has_sflow:
        return "xdp"
    if has_sflow and has_xdp:
        return "both"
    return "xdp"


def resolve_source_id(args: argparse.Namespace, mode: str) -> str:
    if args.source_id:
        return args.source_id
    if mode in ("sflow", "both"):
        value = load_env_value(args.flow_env_file, "FC_SFLOW_SOURCE_ID")
        if value:
            return value
    value = load_env_value(args.xdp_env_file, "XDPFLOWD_SOURCE_ID")
    if value:
        return value
    if mode == "sflow":
        return "sflow-default"
    return "netflow"


def parse_journal_kv_line(line: str, keys: Sequence[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for key in keys:
        match = re.search(rf"{key}=(\d+)", line)
        if match:
            out[key] = int(match.group(1))
    return out


def read_flowcollectord_stats(unit: str) -> Dict[str, int]:
    proc = subprocess.run(
        ["journalctl", "-u", unit, "--since", "2 minutes ago", "--no-pager", "-o", "cat"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return {}
    out: Dict[str, int] = {}
    for line in reversed((proc.stdout or "").splitlines()):
        if "msg=sflow " in line and "datagrams=" in line:
            out.update(
                parse_journal_kv_line(
                    line,
                    (
                        "datagrams",
                        "flow_samples",
                        "records_parsed",
                        "counter_skipped",
                        "parse_errors",
                        "unknown_samples",
                        "udp_queue_drops",
                    ),
                )
            )
        if "clickhouse spool pipeline" in line and "records_acked=" in line:
            out.update(
                parse_journal_kv_line(
                    line,
                    ("records_spooled", "records_acked", "insert_errs", "batches_ok"),
                )
            )
        if out.get("records_parsed") and out.get("records_acked"):
            return out
    return out


def read_udp_snmp() -> Dict[str, int]:
    """Read aggregate UDP counters from /proc/net/snmp."""
    try:
        lines = Path("/proc/net/snmp").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    header: Optional[List[str]] = None
    for line in lines:
        if not line.startswith("Udp:"):
            continue
        fields = line.split()
        if header is None:
            header = fields[1:]
            continue
        values = fields[1:]
        if header and len(header) == len(values):
            return {k: int(v) for k, v in zip(header, values)}
    return {}


def read_udp_socket_stats(port: int, unit: str = "") -> Dict[str, int]:
    """Read per-socket UDP queue drops for listeners on port (ss skmem d= field)."""
    if not shutil.which("ss"):
        return {}
    proc = subprocess.run(
        ["ss", "-uanpm"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return {}

    out = {"sockets": 0, "drops": 0, "recv_q": 0}
    lines = (proc.stdout or "").splitlines()
    port_pat = re.compile(rf"(?<!\d):{port}(?:\s|$)")
    unit_needle = unit.strip()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if "UNCONN" not in line or not port_pat.search(line):
            idx += 1
            continue
        if unit_needle and unit_needle not in line:
            idx += 1
            continue

        out["sockets"] += 1
        parts = line.split()
        if len(parts) >= 2:
            try:
                out["recv_q"] += int(parts[1])
            except ValueError:
                pass
        if idx + 1 < len(lines) and "skmem:" in lines[idx + 1]:
            match = re.search(r",d(\d+)", lines[idx + 1])
            if match:
                out["drops"] += int(match.group(1))
            idx += 1
        idx += 1
    return out


def be_u32(buf: bytes, offset: int) -> int:
    return struct.unpack_from(">I", buf, offset)[0]


def be_u16(buf: bytes, offset: int) -> int:
    return struct.unpack_from(">H", buf, offset)[0]


def parse_sampled_ethernet_header(buf: bytes) -> bool:
    if len(buf) < 14:
        return False
    off = 12
    etype = be_u16(buf, off)
    off += 2
    while etype in (0x8100, 0x88A8):
        if len(buf) < off + 4:
            return False
        off += 2
        etype = be_u16(buf, off)
        off += 2
    if etype == 0x0800:
        if len(buf) < off + 20:
            return False
        ihl = (buf[off] & 0x0F) * 4
        return ihl >= 20 and len(buf) >= off + ihl
    if etype == 0x86DD:
        return len(buf) >= off + 40
    return False


def parse_sflow_payload(payload: bytes, summary: SFlowCaptureSummary) -> None:
    summary.datagrams += 1
    if len(payload) < 28:
        summary.parse_errors += 1
        return
    if be_u32(payload, 0) != 5:
        summary.parse_errors += 1
        return

    agent_type = be_u32(payload, 4)
    off = 8
    if agent_type == 1:
        if len(payload) < off + 4:
            summary.parse_errors += 1
            return
        off += 4
    elif agent_type == 2:
        if len(payload) < off + 16:
            summary.parse_errors += 1
            return
        off += 16
    else:
        summary.parse_errors += 1
        return

    if len(payload) < off + 16:
        summary.parse_errors += 1
        return
    off += 12  # sub_agent_id, datagram_sequence, uptime
    samples = be_u32(payload, off)
    off += 4
    if samples > 4096:
        summary.parse_errors += 1
        return

    for _ in range(samples):
        if len(payload) < off + 8:
            summary.parse_errors += 1
            return
        sample_type = be_u32(payload, off)
        sample_len = be_u32(payload, off + 4)
        off += 8
        if len(payload) < off + sample_len:
            summary.parse_errors += 1
            return
        sample = payload[off : off + sample_len]
        off += sample_len

        sample_format = sample_type & 0xFFF
        if sample_format in (1, 3):
            summary.flow_samples += 1
            parse_sflow_flow_sample(sample, sample_format == 3, summary)
        elif sample_format in (2, 4):
            summary.counter_samples += 1


def parse_sflow_flow_sample(sample: bytes, expanded: bool, summary: SFlowCaptureSummary) -> None:
    min_len = 44 if expanded else 32
    if len(sample) < min_len:
        summary.parse_errors += 1
        return
    if expanded:
        sampling_rate = be_u32(sample, 12)
        records = be_u32(sample, 40)
        off = 44
    else:
        sampling_rate = be_u32(sample, 8)
        records = be_u32(sample, 28)
        off = 32
    if sampling_rate == 0:
        sampling_rate = 1
    if records > 4096:
        summary.parse_errors += 1
        return

    for _ in range(records):
        if len(sample) < off + 8:
            summary.parse_errors += 1
            return
        record_type = be_u32(sample, off)
        record_len = be_u32(sample, off + 4)
        off += 8
        if len(sample) < off + record_len:
            summary.parse_errors += 1
            return
        record = sample[off : off + record_len]
        off += record_len
        if record_type & 0xFFF != 1:
            continue
        summary.raw_records += 1
        parse_sflow_raw_header_record(record, sampling_rate, summary)


def parse_sflow_raw_header_record(record: bytes, sampling_rate: int, summary: SFlowCaptureSummary) -> None:
    if len(record) < 16:
        summary.parse_errors += 1
        return
    header_protocol = be_u32(record, 0)
    if header_protocol != 1:  # sampled_header_protocol=ethernet
        summary.parse_errors += 1
        return
    frame_length = be_u32(record, 4)
    header_length = be_u32(record, 12)
    if header_length == 0 or len(record) < 16 + header_length:
        summary.parse_errors += 1
        return
    if not parse_sampled_ethernet_header(record[16 : 16 + header_length]):
        summary.parse_errors += 1
        return
    summary.add_record(frame_length, sampling_rate)


def iter_pcap_packets(path: str) -> Tuple[int, List[bytes]]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        return 0, []
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("unsupported capture format (expected classic pcap from tcpdump -w)")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    off = 24
    packets: List[bytes] = []
    while len(data) >= off + 16:
        _sec, _usec, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if incl_len < 0 or len(data) < off + incl_len:
            break
        packets.append(data[off : off + incl_len])
        off += incl_len
    return linktype, packets


def udp_payload_from_packet(packet: bytes, linktype: int, udp_port: int) -> Optional[bytes]:
    off = 0
    if linktype == 1:  # LINKTYPE_ETHERNET
        if len(packet) < 14:
            return None
        off = 12
        etype = be_u16(packet, off)
        off += 2
        while etype in (0x8100, 0x88A8):
            if len(packet) < off + 4:
                return None
            off += 2
            etype = be_u16(packet, off)
            off += 2
        if etype != 0x0800:
            return None
    elif linktype == 276:  # LINKTYPE_LINUX_SLL2
        if len(packet) < 20:
            return None
        if be_u16(packet, 0) != 0x0800:
            return None
        off = 20
    elif linktype == 113:  # LINKTYPE_LINUX_SLL
        if len(packet) < 16:
            return None
        if be_u16(packet, 14) != 0x0800:
            return None
        off = 16
    else:
        return None

    if len(packet) < off + 20:
        return None
    ihl = (packet[off] & 0x0F) * 4
    if ihl < 20 or len(packet) < off + ihl:
        return None
    proto = packet[off + 9]
    if proto != 17:
        return None
    total_len = be_u16(packet, off + 2)
    ip_end = min(len(packet), off + total_len) if total_len > 0 else len(packet)
    udp_off = off + ihl
    if ip_end < udp_off + 8:
        return None
    src_port = be_u16(packet, udp_off)
    dst_port = be_u16(packet, udp_off + 2)
    if src_port != udp_port and dst_port != udp_port:
        return None
    udp_len = be_u16(packet, udp_off + 4)
    payload_end = min(ip_end, udp_off + udp_len) if udp_len >= 8 else ip_end
    return packet[udp_off + 8 : payload_end]


def capture_sflow_pcap(args: argparse.Namespace) -> Tuple[str, str, str]:
    capture_file = tempfile.NamedTemporaryFile(prefix="grapesnta_sflow_", suffix=".pcap", delete=False)
    capture_file.close()
    cmd = [
        args.tcpdump,
        "-i",
        resolve_sflow_iface(args),
        "-s",
        "0",
        "-U",
        "-w",
        capture_file.name,
        f"udp port {args.sflow_port}",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(args.sflow_capture_warmup_sec)
    t0 = utc_now_sql()
    time.sleep(args.sflow_capture_sec)
    t1 = utc_now_sql()
    proc.terminate()
    try:
        _stdout, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        _stdout, stderr = proc.communicate(timeout=5)
    if proc.returncode not in (0, -15, 143):
        raise RuntimeError(f"tcpdump failed rc={proc.returncode}: {(stderr or '').strip()}")
    return capture_file.name, t0, t1


def summarize_sflow_pcap(path: str, udp_port: int) -> SFlowCaptureSummary:
    linktype, packets = iter_pcap_packets(path)
    summary = SFlowCaptureSummary()
    for packet in packets:
        payload = udp_payload_from_packet(packet, linktype, udp_port)
        if payload:
            parse_sflow_payload(payload, summary)
    return summary


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
  AND time_received_ns >= toDateTime({sql_string(t0)}, 'UTC')
  AND time_received_ns <  toDateTime({sql_string(t1)}, 'UTC')
""",
    )
    if not row:
        return 0, 0
    return int(float(row[0] or 0)), int(float(row[1] or 0))


def query_ch_window_rowcount(
    ch: ClickHouse, args: argparse.Namespace, t0: str, t1: str
) -> int:
    return one_int(
        ch,
        f"""
SELECT count()
FROM default.flows_raw
WHERE source_id = {sql_string(args.source_id)}
  AND time_received_ns >= toDateTime({sql_string(t0)}, 'UTC')
  AND time_received_ns <  toDateTime({sql_string(t1)}, 'UTC')
""",
    )


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
    mode = detect_collector_mode(args)
    if mode in ("xdp", "both"):
        check_xdp_pipeline_coverage(ch, args, results)
    if mode in ("sflow", "both"):
        check_sflow_pipeline_coverage(ch, args, results)


def check_xdp_pipeline_coverage(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
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


def check_sflow_pipeline_coverage(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    window_sec = args.coverage_window_sec
    if window_sec <= 0:
        return

    iface = resolve_sflow_iface(args)
    print(
        f"INFO\tcoverage\tmeasuring sFlow pipeline for {window_sec}s "
        f"iface={iface} source_id={args.source_id} unit={args.flow_unit}"
    )

    fc0 = read_flowcollectord_stats(args.flow_unit)
    sysfs0 = read_sysfs_rx(iface)
    t0 = utc_now_sql()

    time.sleep(window_sec)

    fc1 = read_flowcollectord_stats(args.flow_unit)
    sysfs1 = read_sysfs_rx(iface)
    t1 = utc_now_sql()

    if not fc0 or not fc1:
        add(
            results,
            "WARN",
            "coverage.flowcollectord",
            f"cannot read sflow/spool metrics from journalctl -u {args.flow_unit}; run as root on sFlow host",
        )
        return

    d_datagrams = fc1.get("datagrams", 0) - fc0.get("datagrams", 0)
    d_samples = fc1.get("flow_samples", 0) - fc0.get("flow_samples", 0)
    d_parsed = fc1.get("records_parsed", 0) - fc0.get("records_parsed", 0)
    d_parse_err = fc1.get("parse_errors", 0) - fc0.get("parse_errors", 0)
    d_queue_drops = fc1.get("udp_queue_drops", 0) - fc0.get("udp_queue_drops", 0)
    d_acked = fc1.get("records_acked", 0) - fc0.get("records_acked", 0)
    d_insert_err = fc1.get("insert_errs", 0) - fc0.get("insert_errs", 0)

    add(
        results,
        "OK" if d_datagrams > 0 else "FAIL",
        "coverage.flowcollectord.datagrams",
        f"window_sec={window_sec} datagrams={d_datagrams} flow_samples={d_samples} "
        f"records_parsed={d_parsed} parse_errors_delta={d_parse_err} udp_queue_drops_delta={d_queue_drops}",
    )
    add(
        results,
        "OK" if d_acked > 0 else "FAIL",
        "coverage.flowcollectord.acked",
        f"window_sec={window_sec} records_acked={d_acked} insert_errs_delta={d_insert_err}",
    )

    if d_samples > 0:
        parse_pct = 100.0 * d_parse_err / d_samples
        status = "OK"
        if parse_pct > args.max_sflow_parse_error_pct:
            status = "WARN"
        add(
            results,
            status,
            "coverage.flowcollectord.parse_error_rate",
            f"parse_errors/samples={parse_pct:.1f}% threshold={args.max_sflow_parse_error_pct}% "
            f"(non-fatal: counter samples / non-Ethernet headers)",
        )

    ch_rows = query_ch_window_rowcount(ch, args, t0, t1)
    ch_pkts, ch_bytes = query_ch_window_totals(ch, args, t0, t1)
    add(
        results,
        "OK" if ch_bytes > 0 else "FAIL",
        "coverage.clickhouse.flows_raw",
        f"window_sec={window_sec} rows={ch_rows} packets={ch_pkts} bytes={ch_bytes} "
        f"{format_rate(ch_pkts, ch_bytes, window_sec)}",
    )

    if d_parsed > 0:
        row_ratio = pct_ratio(ch_rows, d_parsed)
        row_dev = pct_deviation(row_ratio)
        status = "OK"
        if row_ratio is not None and abs(row_dev or 0) > args.max_coverage_deviation_pct:
            status = "WARN"
        add(
            results,
            status,
            "coverage.ratio.ch_rows_vs_parsed",
            f"ch_rows={ch_rows} parsed_delta={d_parsed} ratio={format_ratio_pct(row_ratio)} "
            f"deviation={format_deviation_pct(row_dev)} threshold=±{args.max_coverage_deviation_pct}%",
        )

    if d_acked > 0:
        ack_ratio = pct_ratio(ch_rows, d_acked)
        ack_dev = pct_deviation(ack_ratio)
        status = "OK"
        if ack_ratio is not None and abs(ack_dev or 0) > args.max_coverage_deviation_pct:
            status = "WARN"
        add(
            results,
            status,
            "coverage.ratio.ch_rows_vs_acked",
            f"ch_rows={ch_rows} acked_delta={d_acked} ratio={format_ratio_pct(ack_ratio)} "
            f"deviation={format_deviation_pct(ack_dev)} threshold=±{args.max_coverage_deviation_pct}%",
        )

    d_sysfs_pkts = sysfs1[0] - sysfs0[0]
    d_sysfs_bytes = sysfs1[1] - sysfs0[1]
    if d_sysfs_bytes > 0:
        add(
            results,
            "OK",
            "coverage.wire.sysfs",
            f"window_sec={window_sec} iface={iface} rx_bytes={d_sysfs_bytes} "
            f"{format_rate(d_sysfs_pkts, d_sysfs_bytes, window_sec)} "
            f"(all traffic on NIC, not sFlow-only)",
        )
        if ch_bytes > 0:
            byte_ratio = pct_ratio(ch_bytes, d_sysfs_bytes)
            add(
                results,
                "OK",
                "coverage.ratio.ch_bytes_vs_nic_rx",
                f"ch_bytes={ch_bytes} nic_rx_bytes={d_sysfs_bytes} ratio={format_ratio_pct(byte_ratio)} "
                f"(sFlow extrapolates sampled frames; expect >>100% if many agents)",
            )


def check_sflow_capture_vs_db(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    if not is_sflow_source(args.source_id) or args.sflow_capture_sec <= 0:
        return
    mode = detect_collector_mode(args)
    if mode not in ("sflow", "both"):
        return
    if not shutil.which(args.tcpdump) and not os.path.isfile(args.tcpdump):
        add(results, "WARN", "sflow_capture", f"tcpdump not found: {args.tcpdump}")
        return

    print(
        f"INFO\tsflow_capture\tcapturing {args.sflow_capture_sec}s on "
        f"iface={resolve_sflow_iface(args)} udp/{args.sflow_port}"
    )
    pcap_path = ""
    fc0 = read_flowcollectord_stats(args.flow_unit)
    udp0 = read_udp_snmp()
    sock0 = read_udp_socket_stats(args.sflow_port, args.flow_unit)
    try:
        pcap_path, t0, t1 = capture_sflow_pcap(args)
        summary = summarize_sflow_pcap(pcap_path, args.sflow_port)
    except Exception as exc:  # noqa: BLE001 - health check should report and continue.
        add(results, "WARN", "sflow_capture", str(exc))
        return
    finally:
        if pcap_path and not args.keep_sflow_capture:
            try:
                os.unlink(pcap_path)
            except OSError:
                pass

    if summary.datagrams == 0:
        add(results, "FAIL", "sflow_capture.datagrams", "captured 0 sFlow datagrams")
        return

    add(
        results,
        "OK" if summary.parsed_records > 0 else "FAIL",
        "sflow_capture.parsed",
        f"datagrams={summary.datagrams} flow_samples={summary.flow_samples} "
        f"counter_samples={summary.counter_samples} raw_records={summary.raw_records} "
        f"parsed_records={summary.parsed_records} parse_errors={summary.parse_errors}",
    )
    add(
        results,
        "OK",
        "sflow_capture.scaled_total",
        f"window_sec={args.sflow_capture_sec} packets={summary.extrapolated_packets} "
        f"bytes={summary.extrapolated_bytes} sampled_frame_bytes={summary.sampled_frame_bytes} "
        f"{format_rate(summary.extrapolated_packets, summary.extrapolated_bytes, args.sflow_capture_sec)} "
        f"sampling_rate_min={summary.min_sampling_rate} sampling_rate_max={summary.max_sampling_rate}",
    )

    if args.sflow_db_settle_sec > 0:
        time.sleep(args.sflow_db_settle_sec)
    fc1 = read_flowcollectord_stats(args.flow_unit)
    udp1 = read_udp_snmp()
    sock1 = read_udp_socket_stats(args.sflow_port, args.flow_unit)
    ch_rows = query_ch_window_rowcount(ch, args, t0, t1)
    ch_packets, ch_bytes = query_ch_window_totals(ch, args, t0, t1)

    if fc0 and fc1:
        fc_datagrams = fc1.get("datagrams", 0) - fc0.get("datagrams", 0)
        fc_parsed = fc1.get("records_parsed", 0) - fc0.get("records_parsed", 0)
        fc_acked = fc1.get("records_acked", 0) - fc0.get("records_acked", 0)
        dgram_ratio = pct_ratio(fc_datagrams, summary.datagrams)
        parsed_ratio = pct_ratio(fc_parsed, summary.parsed_records)
        status = "OK"
        if parsed_ratio is not None and abs((pct_deviation(parsed_ratio) or 0)) > args.max_sflow_capture_db_deviation_pct:
            status = "WARN"
        add(
            results,
            status,
            "sflow_capture.flowcollectord_compare",
            f"capture_datagrams={summary.datagrams} collector_datagrams_delta={fc_datagrams} "
            f"datagrams_ratio={format_ratio_pct(dgram_ratio)} capture_rows={summary.parsed_records} "
            f"collector_parsed_delta={fc_parsed} parsed_ratio={format_ratio_pct(parsed_ratio)} "
            f"collector_acked_delta={fc_acked}",
        )

    socket_drops_delta = 0
    socket_count = 0
    if sock0 or sock1:
        socket_drops_delta = sock1.get("drops", 0) - sock0.get("drops", 0)
        socket_count = max(sock0.get("sockets", 0), sock1.get("sockets", 0))
        recv_q = sock1.get("recv_q", 0)
        if socket_count == 0:
            add(
                results,
                "WARN",
                "sflow_capture.udp_socket",
                f"port={args.sflow_port} unit={args.flow_unit}: no UDP listeners found via ss",
            )
        else:
            add(
                results,
                "OK" if socket_drops_delta == 0 else "FAIL",
                "sflow_capture.udp_socket",
                f"port={args.sflow_port} sockets={socket_count} recv_q={recv_q} "
                f"drops_delta={socket_drops_delta}",
            )

    if udp0 and udp1:
        in_err = udp1.get("InErrors", 0) - udp0.get("InErrors", 0)
        rcvbuf_err = udp1.get("RcvbufErrors", 0) - udp0.get("RcvbufErrors", 0)
        in_datagrams = udp1.get("InDatagrams", 0) - udp0.get("InDatagrams", 0)
        # /proc/net/snmp UDP counters are host-wide, not per sFlow socket. Do not
        # FAIL when the collector socket itself shows no drops.
        if in_err == 0 and rcvbuf_err == 0:
            snmp_status = "OK"
        elif socket_count > 0 and socket_drops_delta == 0:
            snmp_status = "OK"
        else:
            snmp_status = "WARN"
        suffix = ""
        if snmp_status == "OK" and (in_err > 0 or rcvbuf_err > 0):
            suffix = " (host-wide; sFlow socket drops=0)"
        add(
            results,
            snmp_status,
            "sflow_capture.udp_kernel",
            f"InDatagrams_delta={in_datagrams} InErrors_delta={in_err} "
            f"RcvbufErrors_delta={rcvbuf_err}{suffix}",
        )

    row_ratio = pct_ratio(ch_rows, summary.parsed_records)
    pkt_ratio = pct_ratio(ch_packets, summary.extrapolated_packets)
    byte_ratio = pct_ratio(ch_bytes, summary.extrapolated_bytes)
    row_dev = pct_deviation(row_ratio)
    pkt_dev = pct_deviation(pkt_ratio)
    byte_dev = pct_deviation(byte_ratio)

    status = "OK"
    max_dev = max(abs(row_dev or 0), abs(pkt_dev or 0), abs(byte_dev or 0))
    if max_dev > args.max_sflow_capture_db_deviation_pct:
        status = "FAIL"
    add(
        results,
        status,
        "sflow_capture.db_compare",
        f"window=[{t0},{t1}) capture_rows={summary.parsed_records} ch_rows={ch_rows} "
        f"rows_ratio={format_ratio_pct(row_ratio)} capture_packets={summary.extrapolated_packets} "
        f"ch_packets={ch_packets} packets_ratio={format_ratio_pct(pkt_ratio)} "
        f"capture_bytes={summary.extrapolated_bytes} ch_bytes={ch_bytes} "
        f"bytes_ratio={format_ratio_pct(byte_ratio)} threshold=±{args.max_sflow_capture_db_deviation_pct}%",
    )

    avg_frame = (
        summary.extrapolated_bytes / summary.extrapolated_packets
        if summary.extrapolated_packets > 0
        else 0
    )
    if avg_frame > args.max_sflow_frame_bytes:
        add(
            results,
            "FAIL",
            "sflow_capture.avg_frame",
            f"bytes/packets={avg_frame:.0f} > {args.max_sflow_frame_bytes}",
        )
    else:
        add(
            results,
            "OK",
            "sflow_capture.avg_frame",
            f"bytes/packets={avg_frame:.0f} (derived directly from captured sFlow records)",
        )


def is_sflow_source(source_id: str) -> bool:
    return source_id == "sflow-default" or source_id.startswith("sflow-") or source_id.endswith("-sflow")


def check_sflow_sampling_sanity(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    if not is_sflow_source(args.source_id):
        return

    row = one_row(
        ch,
        f"""
SELECT
    round(sum(bytes) / nullIf(sum(packets), 0), 0) AS avg_bytes_per_packet,
    round(sum(bytes) / 1e12, 3) AS tb,
    sum(packets) AS total_packets,
    max(sampling_rate) AS max_sampling_rate,
    round(quantile(0.5)(sampling_rate), 0) AS p50_sampling_rate
FROM default.flows_raw
WHERE source_id = {sql_string(args.source_id)}
  AND time_received_ns >= now() - INTERVAL {args.quality_window_minutes} MINUTE
""",
    )
    if not row or row[0] == "":
        add(results, "FAIL", "sflow_sampling", f"no {args.source_id} rows in last {args.quality_window_minutes}m")
        return

    avg_bpp, tb, total_pkts, max_rate, p50_rate = row
    avg_bpp_f = float(avg_bpp or 0)
    tb_f = float(tb or 0)
    max_rate_i = int(float(max_rate or 0))
    p50_rate_i = int(float(p50_rate or 0))
    pkts_sum = int(float(total_pkts or 0))

    window_sec = args.quality_window_minutes * 60
    bytes_sum = int(avg_bpp_f * pkts_sum) if pkts_sum > 0 else 0
    row_bytes = one_row(
        ch,
        f"""
SELECT sum(bytes)
FROM default.flows_raw
WHERE source_id = {sql_string(args.source_id)}
  AND time_received_ns >= now() - INTERVAL {args.quality_window_minutes} MINUTE
""",
    )
    if row_bytes and row_bytes[0]:
        bytes_sum = int(float(row_bytes[0]))

    add(
        results,
        "OK",
        "sflow_sampling.volume",
        f"window={args.quality_window_minutes}m tb={tb_f} "
        f"{format_rate(pkts_sum, bytes_sum, window_sec)} rows_implied_frame={avg_bpp_f}B",
    )

    if avg_bpp_f <= 0:
        add(results, "FAIL", "sflow_sampling.avg_frame", "bytes/packets=0")
    elif avg_bpp_f > args.max_sflow_frame_bytes:
        add(
            results,
            "FAIL",
            "sflow_sampling.avg_frame",
            f"bytes/packets={avg_bpp_f:.0f} > {args.max_sflow_frame_bytes} "
            f"(expected Ethernet frame size; pre-scale may be wrong)",
        )
    elif avg_bpp_f > args.warn_sflow_frame_bytes:
        add(
            results,
            "WARN",
            "sflow_sampling.avg_frame",
            f"bytes/packets={avg_bpp_f:.0f} warn_above={args.warn_sflow_frame_bytes}",
        )
    else:
        add(
            results,
            "OK",
            "sflow_sampling.avg_frame",
            f"bytes/packets={avg_bpp_f:.0f} (≈ mean frame length after sampling_rate pre-scale)",
        )

    if max_rate_i > args.max_sflow_sampling_rate:
        add(
            results,
            "FAIL",
            "sflow_sampling.max_rate",
            f"max_sampling_rate={max_rate_i} > {args.max_sflow_sampling_rate}",
        )
    else:
        add(
            results,
            "OK",
            "sflow_sampling.max_rate",
            f"max_sampling_rate={max_rate_i} p50_sampling_rate={p50_rate_i}",
        )


def check_sflow_volume_summary(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    if not is_sflow_source(args.source_id):
        return

    minutes = int(args.volume_window_hours * 60)
    row = one_row(
        ch,
        f"""
SELECT
    round(sum(bytes) / 1e12, 3) AS tb,
    round(sum(bytes) * 8 / 1e9 / {minutes * 60}, 2) AS avg_gbps,
    count() AS rows
FROM default.flows_raw
WHERE source_id = {sql_string(args.source_id)}
  AND time_received_ns >= now() - INTERVAL {minutes} MINUTE
""",
    )
    if not row or row[0] == "":
        add(results, "FAIL", "sflow_volume", f"no rows in last {args.volume_window_hours}h")
        return

    tb, avg_gbps, rows = row
    tb_f = float(tb or 0)
    gbps_f = float(avg_gbps or 0)
    detail = f"window={args.volume_window_hours}h tb={tb_f} avg_gbps={gbps_f} rows={rows}"
    if args.expected_max_gbps > 0 and gbps_f > args.expected_max_gbps * (1 + args.max_volume_overshoot_pct / 100):
        add(
            results,
            "FAIL",
            "sflow_volume.rate",
            f"{detail} exceeds expected_max_gbps={args.expected_max_gbps} "
            f"by >{args.max_volume_overshoot_pct}%",
        )
    else:
        status = "OK"
        if args.expected_max_gbps > 0:
            detail += f" expected_max_gbps={args.expected_max_gbps}"
        add(results, status, "sflow_volume.rate", detail)


def check_cross_source_rate(ch: ClickHouse, args: argparse.Namespace, results: List[CheckResult]) -> None:
    if not args.compare_source_id:
        return
    minutes = args.compare_window_minutes
    row = one_row(
        ch,
        f"""
SELECT
    round(sumIf(bytes, source_id = {sql_string(args.source_id)}) / 1e9, 1) AS primary_gb,
    round(sumIf(bytes, source_id = {sql_string(args.compare_source_id)}) / 1e9, 1) AS compare_gb
FROM default.flows_raw
WHERE source_id IN ({sql_string(args.source_id)}, {sql_string(args.compare_source_id)})
  AND time_received_ns >= now() - INTERVAL {minutes} MINUTE
""",
    )
    if not row or row[0] == "":
        add(results, "WARN", "cross_source", "no overlapping window rows")
        return
    primary_gb = float(row[0] or 0)
    compare_gb = float(row[1] or 0)
    ratio = pct_ratio(primary_gb, compare_gb)
    add(
        results,
        "OK",
        "cross_source.bytes",
        f"window={minutes}m {args.source_id}_gb={primary_gb} {args.compare_source_id}_gb={compare_gb} "
        f"ratio={format_ratio_pct(ratio)}",
    )
    if compare_gb > 0 and ratio is not None:
        if ratio > 100 * args.max_cross_source_ratio or ratio < 100 / args.max_cross_source_ratio:
            add(
                results,
                "WARN",
                "cross_source.ratio",
                f"{args.source_id} vs {args.compare_source_id} ratio={format_ratio_pct(ratio)} "
                f"outside 1/{args.max_cross_source_ratio}..{args.max_cross_source_ratio}x "
                f"(overlap or scaling mismatch if same traffic)",
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
    round(sumIf(bytes, endpoint_scope = 'remote' AND endpoint_asn = 0 AND NOT {no_asn_expected_sql('endpoint_ip')}) / 1e9, 1) AS remote_asn_zero_gb,
    round(sumIf(bytes, endpoint_scope = 'remote' AND endpoint_asn = 0 AND {no_asn_expected_sql('endpoint_ip')}) / 1e9, 1) AS remote_no_asn_expected_gb,
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
        remote_no_asn_expected_s,
        ip_cc_unknown_s,
        as_cc_unknown_s,
        gb_s,
    ) in rows:
        name = f"talker_quality.{direction}.{side}.{scope}"
        no_asn_note = (
            f" (+{remote_no_asn_expected_s} gb multicast/reserved, no ASN expected)"
            if float(remote_no_asn_expected_s) > 0
            else ""
        )
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
            add(results, "WARN", name, f"remote_asn_zero_gb={remote_zero_s} gb={gb_s} (BGP coverage){no_asn_note}")
        else:
            add(results, "OK", name, f"gb={gb_s} rows={rows_s}{no_asn_note}")


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
    round(sumIf(bytes, src_scope = 'remote' AND src_asn = 0 AND NOT {no_asn_expected_sql('src_ip')}) / 1e9, 1) AS src_remote_asn_zero_gb,
    round(sumIf(bytes, dst_scope = 'remote' AND dst_asn = 0 AND NOT {no_asn_expected_sql('dst_ip')}) / 1e9, 1) AS dst_remote_asn_zero_gb,
    round(sumIf(bytes, (src_scope = 'remote' AND src_asn = 0 AND {no_asn_expected_sql('src_ip')}) OR (dst_scope = 'remote' AND dst_asn = 0 AND {no_asn_expected_sql('dst_ip')})) / 1e9, 1) AS remote_no_asn_expected_gb,
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
        remote_no_asn_expected_s,
        ip_cc_unknown_s,
        as_cc_unknown_s,
        gb_s,
    ) in rows:
        name = f"pair_quality.{direction}.{src_scope}_to_{dst_scope}"
        no_asn_note = (
            f" (+{remote_no_asn_expected_s} gb multicast/reserved, no ASN expected)"
            if float(remote_no_asn_expected_s) > 0
            else ""
        )
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
                f"remote_asn_zero_gb src={src_remote_zero_s} dst={dst_remote_zero_s} gb={gb_s} (BGP coverage){no_asn_note}",
            )
        else:
            add(results, "OK", name, f"gb={gb_s} rows={rows_s}{no_asn_note}")


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
    WHERE d.source_id = {sql_string(args.source_id)}
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
    p.add_argument("--source-id", default="", help="flow source_id (default: auto from collector env)")
    p.add_argument(
        "--collector",
        choices=("auto", "xdp", "sflow", "both"),
        default="auto",
        help="local collector type for live coverage (auto=systemd detect)",
    )
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
    p.add_argument("--flow-unit", default="flowcollectord", help="systemd unit for flowcollectord stats")
    p.add_argument(
        "--flow-env-file",
        default="/etc/flowcollectord/flowcollectord.env",
        help="env file with FC_SFLOW_SOURCE_ID",
    )
    p.add_argument(
        "--sflow-iface",
        default="",
        help="NIC receiving sFlow UDP (for optional sysfs rx reference)",
    )
    p.add_argument(
        "--sflow-iface-default",
        default="ens18",
        help="default sFlow NIC when --sflow-iface unset",
    )
    p.add_argument(
        "--compare-source-id",
        default="",
        help="optional second source_id to compare byte volume (overlap check)",
    )
    p.add_argument(
        "--max-cross-source-ratio",
        type=float,
        default=3.0,
        help="WARN if primary/compare byte ratio outside 1/N..N",
    )
    p.add_argument(
        "--expected-max-gbps",
        type=float,
        default=0.0,
        help="FAIL if sFlow avg gbps in volume window exceeds this (0=disable)",
    )
    p.add_argument(
        "--volume-window-hours",
        type=float,
        default=1.0,
        help="window for sflow_volume.rate summary",
    )
    p.add_argument(
        "--max-volume-overshoot-pct",
        type=float,
        default=20.0,
        help="allowed overshoot above --expected-max-gbps before FAIL",
    )
    p.add_argument(
        "--max-sflow-frame-bytes",
        type=int,
        default=65535,
        help="FAIL if mean bytes/packets exceeds this (bad pre-scale)",
    )
    p.add_argument(
        "--warn-sflow-frame-bytes",
        type=int,
        default=16384,
        help="WARN if mean bytes/packets exceeds this",
    )
    p.add_argument(
        "--max-sflow-sampling-rate",
        type=int,
        default=1_000_000,
        help="FAIL if max sampling_rate in window exceeds this",
    )
    p.add_argument(
        "--max-sflow-parse-error-pct",
        type=float,
        default=60.0,
        help="WARN if flowcollectord parse_errors/samples exceeds this in live window",
    )
    p.add_argument("--tcpdump", default="tcpdump", help="tcpdump binary for live sFlow pcap verification")
    p.add_argument("--sflow-port", type=int, default=6343, help="sFlow UDP port to capture")
    p.add_argument(
        "--sflow-capture-sec",
        type=int,
        default=15,
        help="capture live sFlow datagrams for independent parser-vs-DB check (0=disable)",
    )
    p.add_argument(
        "--sflow-capture-warmup-sec",
        type=float,
        default=0.5,
        help="seconds to let tcpdump attach before starting DB comparison window",
    )
    p.add_argument(
        "--sflow-db-settle-sec",
        type=float,
        default=3.0,
        help="seconds to wait after capture before querying ClickHouse",
    )
    p.add_argument(
        "--max-sflow-capture-db-deviation-pct",
        type=float,
        default=5.0,
        help="FAIL if pcap parser and flows_raw differ more than this in the capture window",
    )
    p.add_argument(
        "--keep-sflow-capture",
        action="store_true",
        help="keep temporary pcap file after sFlow capture parser check",
    )
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
    used_collector_dsn = apply_clickhouse_dsn_defaults(args)
    collector_mode = detect_collector_mode(args)
    args.source_id = resolve_source_id(args, collector_mode)
    if loaded_env:
        print(f"INFO\tconfig\tenv={' '.join(loaded_env)} host={args.host} port={args.port} user={args.user}")
    else:
        print(f"INFO\tconfig\thost={args.host} port={args.port} user={args.user} database={args.database}")
    if used_collector_dsn:
        print("INFO\tconfig\tclickhouse_dsn=collector_env")
    print(
        f"INFO\tconfig\tcollector={collector_mode} source_id={args.source_id} "
        f"xdp_unit={args.xdp_unit} flow_unit={args.flow_unit}"
    )
    if args.local_asn:
        print(f"INFO\tconfig\tlocal_asn={args.local_asn}")
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
        ("sflow_capture", lambda: check_sflow_capture_vs_db(ch, args, results)),
        ("sflow_sampling", lambda: check_sflow_sampling_sanity(ch, args, results)),
        ("sflow_volume", lambda: check_sflow_volume_summary(ch, args, results)),
        ("cross_source", lambda: check_cross_source_rate(ch, args, results)),
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
