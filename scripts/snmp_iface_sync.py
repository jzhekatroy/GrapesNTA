#!/usr/bin/env python3
"""Discover sFlow exporters and maintain their SNMP v2c interface catalog."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


SYS_NAME = ".1.3.6.1.2.1.1.5.0"
IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = ".1.3.6.1.2.1.31.1.1.1.18"
IF_DESCR = ".1.3.6.1.2.1.2.2.1.2"
IF_HIGH_SPEED = ".1.3.6.1.2.1.31.1.1.1.15"
IF_SPEED = ".1.3.6.1.2.1.2.2.1.5"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def fmt_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value: str) -> datetime:
    text = str(value or "").strip()
    if (
        not text
        or text.startswith("1970-01-01")
        or text.startswith("0000-00-00")
        or text.startswith("0001-01-01")
    ):
        return EPOCH
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return EPOCH


def resolve_binary(configured: str, fallback: str) -> str:
    if os.path.isfile(configured):
        return configured
    return shutil.which(fallback) or configured


def normalize_sampler_hex(raw: str) -> Optional[str]:
    """Decode GrapesNTA FixedString(16), including its IPv4-first encoding."""
    try:
        packed = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(packed) != 16 or packed == bytes(16):
        return None
    if packed[4:] == bytes(12):
        return str(ipaddress.IPv4Address(packed[:4]))
    try:
        address = ipaddress.IPv6Address(packed)
    except ipaddress.AddressValueError:
        return None
    return str(address.ipv4_mapped or address)


def decode_sflow_ifindex(raw: int) -> Optional[int]:
    """Decode the RFC 3176 interface field; only ifIndex format zero is valid."""
    value = int(raw)
    if value <= 0 or value > 0xFFFFFFFF or value >> 30 != 0:
        return None
    index = value & 0x3FFFFFFF
    return index or None


def clean_snmp_value(value: str) -> str:
    value = value.strip()
    if value.lower().startswith(("nosuch", "no such")):
        return ""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def parse_uint(value: str) -> int:
    match = re.search(r"\d+", value)
    return int(match.group(0)) if match else 0


@dataclass
class Settings:
    community: str
    port: int
    timeout_ms: int
    retries: int
    lookback_hours: int
    refresh_seconds: int
    full_walk_seconds: int
    enabled: bool
    auto_enable_new_agents: bool


@dataclass
class Agent:
    switch_ip: str
    display_name: str
    source_ids: List[str]
    snmp_enabled: int
    community_override: str
    port_override: int
    timeout_ms_override: int
    retries_override: int
    first_seen_at: datetime
    last_seen_at: datetime
    last_poll_at: datetime
    last_full_walk_at: datetime
    last_poll_status: str
    last_poll_error: str
    is_new: int


class ClickHouseClient:
    def __init__(self, args: argparse.Namespace) -> None:
        self.base = [
            args.clickhouse_client,
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--user",
            args.user,
            "--database",
            args.database,
        ]
        if args.password:
            self.base += ["--password", args.password]

    def query(self, sql: str, display: str) -> str:
        proc = subprocess.run(
            self.base + ["--query", sql],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            error = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"{display} failed: {error}")
        return (proc.stdout or "").rstrip("\n")

    def json_rows(self, sql: str, display: str) -> List[Dict[str, Any]]:
        output = self.query(f"{sql}\nFORMAT JSONEachRow", display)
        return [json.loads(line) for line in output.splitlines() if line.strip()]

    def insert_json(self, table: str, rows: Sequence[Dict[str, Any]]) -> None:
        if not rows:
            return
        payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
        proc = subprocess.run(
            self.base + ["--query", f"INSERT INTO {table} FORMAT JSONEachRow"],
            input=payload,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            error = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"insert into {table} failed: {error}")


def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("snmp_iface_sync")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(handler)
    return logger


def load_settings(ch: ClickHouseClient) -> Settings:
    rows = ch.json_rows(
        """
        SELECT community, port, timeout_ms, retries, discover_lookback_hours,
               refresh_interval_sec, full_walk_interval_sec, enabled,
               auto_enable_new_agents
        FROM default.net_snmp_settings_current
        WHERE settings_id = 'global'
        LIMIT 1
        """,
        "load global SNMP settings",
    )
    if not rows:
        raise RuntimeError(
            "global SNMP settings missing; apply deploy/clickhouse/net_snmp_interfaces.sql"
        )
    row = rows[0]
    return Settings(
        community=str(row["community"]),
        port=int(row["port"]),
        timeout_ms=int(row["timeout_ms"]),
        retries=int(row["retries"]),
        lookback_hours=int(row["discover_lookback_hours"]),
        refresh_seconds=int(row["refresh_interval_sec"]),
        full_walk_seconds=int(row["full_walk_interval_sec"]),
        enabled=bool(row["enabled"]),
        auto_enable_new_agents=bool(int(row.get("auto_enable_new_agents") or 0)),
    )


def load_agents(ch: ClickHouseClient) -> Dict[str, Agent]:
    rows = ch.json_rows(
        """
        SELECT switch_ip, display_name, source_ids, snmp_enabled,
               community_override, port_override, timeout_ms_override,
               retries_override, first_seen_at, last_seen_at,
               last_poll_at, last_full_walk_at, last_poll_status,
               last_poll_error, is_new
        FROM default.net_snmp_agents_current
        """,
        "load SNMP agents",
    )
    result: Dict[str, Agent] = {}
    for row in rows:
        agent = Agent(
            switch_ip=str(row["switch_ip"]),
            display_name=str(row["display_name"]),
            source_ids=sorted(str(item) for item in row["source_ids"]),
            snmp_enabled=int(row["snmp_enabled"]),
            community_override=str(row["community_override"]),
            port_override=int(row["port_override"]),
            timeout_ms_override=int(row["timeout_ms_override"]),
            retries_override=int(row["retries_override"]),
            first_seen_at=parse_dt(str(row["first_seen_at"])),
            last_seen_at=parse_dt(str(row["last_seen_at"])),
            last_poll_at=parse_dt(str(row["last_poll_at"])),
            last_full_walk_at=parse_dt(str(row["last_full_walk_at"])),
            last_poll_status=str(row["last_poll_status"]),
            last_poll_error=str(row["last_poll_error"]),
            is_new=int(row["is_new"]),
        )
        result[agent.switch_ip] = agent
    return result


def agent_row(agent: Agent, now: datetime) -> Dict[str, Any]:
    return {
        "switch_ip": agent.switch_ip,
        "display_name": agent.display_name,
        "source_ids": sorted(set(agent.source_ids)),
        "snmp_enabled": agent.snmp_enabled,
        "community_override": agent.community_override,
        "port_override": agent.port_override,
        "timeout_ms_override": agent.timeout_ms_override,
        "retries_override": agent.retries_override,
        "first_seen_at": fmt_dt(agent.first_seen_at),
        "last_seen_at": fmt_dt(agent.last_seen_at),
        "last_poll_at": fmt_dt(agent.last_poll_at),
        "last_full_walk_at": fmt_dt(agent.last_full_walk_at),
        "last_poll_status": agent.last_poll_status,
        "last_poll_error": agent.last_poll_error[:1000],
        "is_new": agent.is_new,
        "updated_at": fmt_dt(now),
    }


def discover(
    ch: ClickHouseClient,
    agents: Dict[str, Agent],
    lookback_hours: int,
    now: datetime,
    auto_enable_new_agents: bool = False,
) -> Dict[str, Set[int]]:
    rows = ch.json_rows(
        f"""
        SELECT
            hex(sampler_address) AS sampler_hex,
            groupUniqArray(source_id) AS source_ids,
            groupUniqArray(in_if) AS in_values,
            groupUniqArray(out_if) AS out_values,
            max(toDateTime(time_received_ns, 'UTC')) AS last_seen_at
        FROM default.flows_raw
        PREWHERE time_received_ns >= now64(9) - INTERVAL {lookback_hours:d} HOUR
        WHERE sampler_address != unhex('00000000000000000000000000000000')
          AND (in_if != 0 OR out_if != 0)
        GROUP BY sampler_hex
        """,
        "discover sFlow agents",
    )
    live_indices: Dict[str, Set[int]] = {}
    writes: List[Dict[str, Any]] = []
    for row in rows:
        switch_ip = normalize_sampler_hex(str(row["sampler_hex"]))
        if not switch_ip:
            continue
        indices = {
            decoded
            for raw in list(row["in_values"]) + list(row["out_values"])
            for decoded in [decode_sflow_ifindex(int(raw))]
            if decoded is not None
        }
        if not indices:
            continue
        live_indices[switch_ip] = indices
        seen_at = parse_dt(str(row["last_seen_at"]))
        source_ids = sorted(str(item) for item in row["source_ids"] if str(item))
        agent = agents.get(switch_ip)
        if agent is None:
            agent = Agent(
                switch_ip=switch_ip,
                display_name="",
                source_ids=source_ids,
                snmp_enabled=1 if auto_enable_new_agents else 0,
                community_override="",
                port_override=0,
                timeout_ms_override=0,
                retries_override=0,
                first_seen_at=seen_at,
                last_seen_at=seen_at,
                last_poll_at=EPOCH,
                last_full_walk_at=EPOCH,
                last_poll_status="never",
                last_poll_error="",
                is_new=1,
            )
            agents[switch_ip] = agent
        else:
            agent.source_ids = sorted(set(agent.source_ids).union(source_ids))
            agent.last_seen_at = max(agent.last_seen_at, seen_at)
        writes.append(agent_row(agent, now))
    ch.insert_json("default.net_snmp_agents", writes)
    return live_indices


class SnmpError(RuntimeError):
    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


def classify_snmp_error(text: str) -> str:
    lowered = text.lower()
    if "timeout" in lowered or "no response" in lowered:
        return "timeout"
    if "authorization" in lowered or "authentication" in lowered:
        return "auth_error"
    return "error"


def redact_secret(text: str, secret: str) -> str:
    return text.replace(secret, "***") if secret else text


def snmp_base(
    binary: str,
    agent: Agent,
    settings: Settings,
    community: str,
) -> List[str]:
    timeout_ms = agent.timeout_ms_override or settings.timeout_ms
    retries = agent.retries_override or settings.retries
    port = agent.port_override or settings.port
    target = f"udp6:[{agent.switch_ip}]:{port}" if ":" in agent.switch_ip else (
        f"{agent.switch_ip}:{port}"
    )
    return [
        binary,
        "-v2c",
        "-c",
        community,
        "-t",
        f"{max(timeout_ms, 100) / 1000.0:.3f}",
        "-r",
        str(retries),
        target,
    ]


def run_snmp_get(
    binary: str,
    agent: Agent,
    settings: Settings,
    community: str,
    oids: Sequence[str],
) -> List[str]:
    proc = subprocess.run(
        snmp_base(binary, agent, settings, community) + ["-Oqv"] + list(oids),
        capture_output=True,
        text=True,
        check=False,
        timeout=max(
            10,
            ((agent.timeout_ms_override or settings.timeout_ms) / 1000 + 1) * 3,
        ),
    )
    if proc.returncode:
        message = redact_secret(
            (proc.stderr or proc.stdout or "SNMP request failed").strip(), community
        )
        raise SnmpError(classify_snmp_error(message), message[:1000])
    values = [clean_snmp_value(line) for line in proc.stdout.splitlines()]
    if len(values) != len(oids):
        raise SnmpError("error", "SNMP response did not match requested OID count")
    return values


def walk_if_names(
    binary: str,
    agent: Agent,
    settings: Settings,
    community: str,
) -> Dict[int, str]:
    proc = subprocess.run(
        snmp_base(binary, agent, settings, community) + ["-On", IF_NAME],
        capture_output=True,
        text=True,
        check=False,
        timeout=max(
            30,
            ((agent.timeout_ms_override or settings.timeout_ms) / 1000 + 1) * 20,
        ),
    )
    if proc.returncode:
        message = redact_secret(
            (proc.stderr or proc.stdout or "SNMP walk failed").strip(), community
        )
        raise SnmpError(classify_snmp_error(message), message[:1000])
    result: Dict[int, str] = {}
    pattern = re.compile(r"^\.(?:\d+\.)+(\d+)\s+=\s+(?:\S+:\s+)?(.*)$")
    for line in proc.stdout.splitlines():
        match = pattern.match(line.strip())
        if match:
            result[int(match.group(1))] = clean_snmp_value(match.group(2))
    return result


def chunks(values: Iterable[int], size: int) -> Iterable[List[int]]:
    batch: List[int] = []
    for value in values:
        batch.append(value)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def poll_agent(
    ch: ClickHouseClient,
    snmpget: str,
    snmpwalk: str,
    agent: Agent,
    settings: Settings,
    live_indices: Set[int],
    full_walk_due: bool,
    max_interfaces: int,
    now: datetime,
) -> Tuple[int, bool]:
    community = agent.community_override or settings.community
    if not community:
        raise SnmpError("config_error", "SNMP community is not configured")

    agent.display_name = run_snmp_get(
        snmpget, agent, settings, community, [SYS_NAME]
    )[0]
    walked_names: Dict[int, str] = {}
    if full_walk_due:
        walked_names = walk_if_names(snmpwalk, agent, settings, community)

    indices = sorted(set(live_indices).union(walked_names))[:max_interfaces]
    interface_rows: List[Dict[str, Any]] = []
    for batch in chunks(indices, 25):
        oids = [
            oid
            for index in batch
            for oid in [
                f"{IF_NAME}.{index}",
                f"{IF_ALIAS}.{index}",
                f"{IF_DESCR}.{index}",
                f"{IF_HIGH_SPEED}.{index}",
                f"{IF_SPEED}.{index}",
            ]
        ]
        values = run_snmp_get(snmpget, agent, settings, community, oids)
        for position, index in enumerate(batch):
            offset = position * 5
            if_values = values[offset : offset + 5]
            high_speed = parse_uint(if_values[3])
            speed_bps = parse_uint(if_values[4])
            if high_speed:
                speed_bps = high_speed * 1_000_000
            interface_rows.append(
                {
                    "switch_ip": agent.switch_ip,
                    "if_index": index,
                    "if_name": if_values[0] or walked_names.get(index, ""),
                    "if_alias": if_values[1],
                    "if_descr": if_values[2],
                    "if_high_speed_mbps": high_speed,
                    "if_speed_bps": speed_bps,
                    "updated_at": fmt_dt(now),
                }
            )
    ch.insert_json("default.net_interfaces", interface_rows)
    return len(interface_rows), full_walk_due


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover sFlow agents and refresh SNMP v2c interfaces"
    )
    parser.add_argument(
        "--clickhouse-client",
        default=env("SNMP_SYNC_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"),
    )
    parser.add_argument("--host", default=env("SNMP_SYNC_CH_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port", type=int, default=int(env("SNMP_SYNC_CH_PORT", "6124") or "6124")
    )
    parser.add_argument("--user", default=env("SNMP_SYNC_CH_USER", "develop"))
    parser.add_argument("--password", default=env("SNMP_SYNC_CH_PASSWORD"))
    parser.add_argument("--database", default=env("SNMP_SYNC_CH_DATABASE", "default"))
    parser.add_argument("--snmpget", default=env("SNMP_SYNC_SNMPGET", "/usr/bin/snmpget"))
    parser.add_argument(
        "--snmpwalk", default=env("SNMP_SYNC_SNMPWALK", "/usr/bin/snmpwalk")
    )
    parser.add_argument(
        "--max-agents",
        type=int,
        default=int(env("SNMP_SYNC_MAX_AGENTS", "25") or "25"),
    )
    parser.add_argument(
        "--max-interfaces",
        type=int,
        default=int(env("SNMP_SYNC_MAX_INTERFACES", "4096") or "4096"),
    )
    parser.add_argument("--discover-only", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger = setup_logging(args.verbose)
    args.clickhouse_client = resolve_binary(args.clickhouse_client, "clickhouse-client")
    args.snmpget = resolve_binary(args.snmpget, "snmpget")
    args.snmpwalk = resolve_binary(args.snmpwalk, "snmpwalk")
    if not os.path.isfile(args.clickhouse_client):
        logger.error("clickhouse-client not found: %s", args.clickhouse_client)
        return 2

    ch = ClickHouseClient(args)
    try:
        settings = load_settings(ch)
        agents = load_agents(ch)
        now = utc_now()
        live_indices = discover(
            ch,
            agents,
            settings.lookback_hours,
            now,
            settings.auto_enable_new_agents,
        )
        logger.info(
            "discovery complete agents_seen=%s agents_known=%s",
            len(live_indices),
            len(agents),
        )
        if args.discover_only or not settings.enabled:
            return 0
        if not os.path.isfile(args.snmpget) or not os.path.isfile(args.snmpwalk):
            logger.error("net-snmp tools not found (snmpget=%s snmpwalk=%s)", args.snmpget, args.snmpwalk)
            return 2

        due = [
            agent
            for agent in agents.values()
            if agent.snmp_enabled
            and (
                agent.last_poll_at == EPOCH
                or now - agent.last_poll_at
                >= timedelta(seconds=settings.refresh_seconds)
            )
        ]
        due.sort(key=lambda item: (item.last_poll_at, item.switch_ip))
        failures = 0
        for agent in due[: args.max_agents]:
            full_walk_due = (
                agent.last_full_walk_at == EPOCH
                or now - agent.last_full_walk_at
                >= timedelta(seconds=settings.full_walk_seconds)
            )
            try:
                count, walked = poll_agent(
                    ch,
                    args.snmpget,
                    args.snmpwalk,
                    agent,
                    settings,
                    live_indices.get(agent.switch_ip, set()),
                    full_walk_due,
                    args.max_interfaces,
                    now,
                )
                agent.last_poll_status = "ok"
                agent.last_poll_error = ""
                if walked:
                    agent.last_full_walk_at = now
                logger.info(
                    "switch_ip=%s status=ok interfaces=%s full_walk=%s",
                    agent.switch_ip,
                    count,
                    int(walked),
                )
            except (SnmpError, subprocess.TimeoutExpired) as exc:
                failures += 1
                agent.last_poll_status = (
                    exc.status if isinstance(exc, SnmpError) else "timeout"
                )
                agent.last_poll_error = str(exc)[:1000]
                logger.warning(
                    "switch_ip=%s status=%s error=%s",
                    agent.switch_ip,
                    agent.last_poll_status,
                    agent.last_poll_error,
                )
            agent.last_poll_at = now
            ch.insert_json("default.net_snmp_agents", [agent_row(agent, now)])
        logger.info("poll complete due=%s attempted=%s failed=%s", len(due), min(len(due), args.max_agents), failures)
        # Per-agent failures are expected operational states (timeout/auth/etc.)
        # and are persisted for the UI. Keep the timer healthy so other agents
        # continue to be discovered and retried.
        return 0
    except Exception as exc:
        logger.error("sync failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
