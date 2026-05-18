#!/usr/bin/env python3
"""
Seed local operators and their customer prefixes into ClickHouse.

This is intentionally a simple INSERT-based helper for the MVP. Operators can
later edit the same rows through MoonShine.
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import BinaryIO, Optional, Sequence


OPERATORS = [
    ("pin", "ПИН", ["188.143.128.0/17"]),
    ("arbital", "Арбиталь", ["94.26.128.0/18"]),
    ("iconet", "Айконет", ["91.196.252.0/22", "176.116.240.0/20"]),
    ("metrobit", "Метробит", ["176.123.128.0/19", "91.203.152.0/22", "45.159.200.0/22"]),
    ("veroline", "Веролайн", ["91.151.176.0/20"]),
    ("master-it", "Мастер АйТи", ["91.244.160.0/21"]),
]


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def clickhouse_base_args(args: argparse.Namespace) -> list[str]:
    cmd = [args.clickhouse_client]
    cmd += ["--host", args.host]
    cmd += ["--port", str(args.port)]
    cmd += ["--user", args.user]
    if args.password:
        cmd += ["--password", args.password]
    cmd += ["--database", args.database]
    return cmd


def ch_run_query(
    base: Sequence[str],
    query: str,
    *,
    stdin: Optional[BinaryIO] = None,
) -> None:
    proc = subprocess.run(
        list(base) + ["--query", query],
        stdin=stdin,
        capture_output=True,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"clickhouse-client failed (exit {proc.returncode})\nstderr: {stderr}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed default local operators and prefixes.")
    port_s = env("LOCALOPERATORS_CH_PORT")
    default_port = int(port_s) if port_s and port_s.isdigit() else 9000
    parser.add_argument("--clickhouse-client", default=env("LOCALOPERATORS_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"))
    parser.add_argument("--host", default=env("LOCALOPERATORS_CH_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--user", default=env("LOCALOPERATORS_CH_USER", "default"))
    parser.add_argument("--password", default=env("LOCALOPERATORS_CH_PASSWORD"))
    parser.add_argument("--database", default=env("LOCALOPERATORS_CH_DATABASE", "default"))
    parser.add_argument("--operators-table", default=env("LOCALOPERATORS_TABLE", "default.local_operators"))
    parser.add_argument("--networks-table", default=env("LOCALOPERATORS_NETWORKS_TABLE", "default.local_networks"))
    parser.add_argument("--source", default=env("LOCALOPERATORS_SOURCE", "manual_seed"))
    parser.add_argument("--keep-tsv", action="store_true")
    args = parser.parse_args()

    if not os.path.isfile(args.clickhouse_client):
        raise FileNotFoundError(f"clickhouse-client not found: {args.clickhouse_client}")

    base = clickhouse_base_args(args)
    updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    fd_ops, ops_path = tempfile.mkstemp(prefix="local_operators_", suffix=".tsv", text=True)
    fd_nets, nets_path = tempfile.mkstemp(prefix="local_networks_", suffix=".tsv", text=True)
    os.close(fd_ops)
    os.close(fd_nets)
    try:
        with open(ops_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            for operator_id, name, _prefixes in OPERATORS:
                writer.writerow([operator_id, name, args.source, 1, updated_at])

        with open(nets_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            for operator_id, name, prefixes in OPERATORS:
                for prefix in prefixes:
                    family = 6 if ":" in prefix else 4
                    writer.writerow([prefix, family, operator_id, "customer", name, args.source, 1, updated_at])

        with open(ops_path, "rb") as f:
            ch_run_query(
                base,
                f"INSERT INTO {args.operators_table} (operator_id, name, source, enabled, updated_at) FORMAT TabSeparated",
                stdin=f,
            )
        with open(nets_path, "rb") as f:
            ch_run_query(
                base,
                f"INSERT INTO {args.networks_table} (prefix, family, operator_id, kind, name, source, enabled, updated_at) FORMAT TabSeparated",
                stdin=f,
            )

        print(f"seeded operators={len(OPERATORS)} prefixes={sum(len(p) for _, _, p in OPERATORS)}", file=sys.stderr)
        return 0
    finally:
        if not args.keep_tsv:
            for path in (ops_path, nets_path):
                try:
                    os.remove(path)
                except OSError:
                    pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)
