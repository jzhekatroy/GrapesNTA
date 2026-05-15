#!/usr/bin/env python3
"""
Load local network prefixes from BGP origin ASN into ClickHouse.

The loader:
  - reads active prefixes from bgp_prefix_origin_current for one origin ASN;
  - collapses overlapping/more-specific prefixes into a minimal list;
  - writes them to default.local_networks as enabled config rows;
  - disables no-longer-present rows from the same source;
  - creates/replaces and reloads default.local_networks_dict (IP_TRIE).

Requires: Python 3.7+ (stdlib only) and clickhouse-client on PATH.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import BinaryIO, Iterable, List, Optional, Sequence, Tuple


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def clickhouse_base_args(args: argparse.Namespace) -> List[str]:
    cmd = [args.clickhouse_client]
    cmd += ["--host", args.host]
    cmd += ["--port", str(args.port)]
    cmd += ["--user", args.user]
    if args.password is not None and args.password != "":
        cmd += ["--password", args.password]
    cmd += ["--database", args.database]
    return cmd


def ch_run_query(
    base: Sequence[str],
    query: str,
    *,
    stdin: Optional[BinaryIO] = None,
    capture: bool = False,
    display_query: Optional[str] = None,
) -> Optional[str]:
    proc = subprocess.run(
        list(base) + ["--query", query],
        stdin=stdin,
        capture_output=True,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        shown_query = display_query if display_query is not None else query
        raise RuntimeError(
            f"clickhouse-client failed (exit {proc.returncode})\n"
            f"query: {shown_query[:500]}{'...' if len(shown_query) > 500 else ''}\n"
            f"stderr: {stderr}"
        )
    if capture:
        return proc.stdout.decode("utf-8", errors="replace")
    return None


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def build_dictionary_query(args: argparse.Namespace, password: str) -> str:
    return f"""
CREATE DICTIONARY {args.dictionary}
(
    prefix String,
    name String,
    source String,
    updated_at DateTime
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(
    HOST {sql_string(args.dictionary_source_host)}
    PORT {args.dictionary_source_port}
    USER {sql_string(args.dictionary_source_user)}
    PASSWORD {sql_string(password)}
    DB {sql_string(args.dictionary_source_database)}
    TABLE {sql_string(args.dictionary_source_table)}
    CONNECT_TIMEOUT {args.dictionary_source_connect_timeout}
    SEND_RECEIVE_TIMEOUT {args.dictionary_source_receive_timeout}
))
LAYOUT(IP_TRIE)
LIFETIME(0)
"""


def ch_create_or_replace_dictionary(base: Sequence[str], args: argparse.Namespace) -> None:
    password = args.dictionary_source_password or ""
    query = build_dictionary_query(args, password)
    redacted = build_dictionary_query(args, "***")
    # Target ClickHouse 24.11 accepts CREATE DICTIONARY but rejects
    # DROP DICTIONARY; dictionaries can be dropped through DROP TABLE.
    ch_run_query(base, f"DROP TABLE IF EXISTS {args.dictionary}")
    ch_run_query(base, query, display_query=redacted)


def fetch_origin_prefixes(base: Sequence[str], args: argparse.Namespace) -> List[ipaddress._BaseNetwork]:
    query = f"""
SELECT prefix
FROM {args.origin_table}
WHERE origin_asn = {args.asn}
  AND family IN ({args.families})
FORMAT TabSeparatedRaw
"""
    out = ch_run_query(base, query, capture=True) or ""
    networks: List[ipaddress._BaseNetwork] = []
    for line in out.splitlines():
        prefix = line.strip()
        if not prefix:
            continue
        try:
            networks.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            print(f"skip invalid prefix from ClickHouse: {prefix}", file=sys.stderr)
    return networks


def collapse_networks(networks: Iterable[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    ipv4 = [n for n in networks if n.version == 4]
    ipv6 = [n for n in networks if n.version == 6]
    collapsed: List[ipaddress._BaseNetwork] = []
    collapsed.extend(sorted(ipaddress.collapse_addresses(ipv4)))
    collapsed.extend(sorted(ipaddress.collapse_addresses(ipv6)))
    return collapsed


def fetch_existing_source_prefixes(base: Sequence[str], args: argparse.Namespace) -> List[Tuple[str, int]]:
    query = f"""
SELECT prefix, family
FROM {args.table} FINAL
WHERE source = {sql_string(args.source)}
  AND enabled = 1
FORMAT TabSeparatedRaw
"""
    out = ch_run_query(base, query, capture=True) or ""
    rows: List[Tuple[str, int]] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        try:
            rows.append((parts[0], int(parts[1])))
        except ValueError:
            continue
    return rows


def write_rows_tsv(
    path: str,
    *,
    enabled_networks: Sequence[ipaddress._BaseNetwork],
    disabled_rows: Sequence[Tuple[str, int]],
    name: str,
    source: str,
    updated_at: str,
) -> int:
    count = 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        for prefix, family in disabled_rows:
            writer.writerow([prefix, family, name, source, 0, updated_at])
            count += 1
        for network in enabled_networks:
            writer.writerow([str(network), network.version, name, source, 1, updated_at])
            count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Load local_networks from BGP origin ASN.")
    port_s = env("LOCALNETWORKS_CH_PORT")
    default_port = int(port_s) if port_s and port_s.isdigit() else 9000
    parser.add_argument(
        "--clickhouse-client",
        default=env("LOCALNETWORKS_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"),
    )
    parser.add_argument("--host", default=env("LOCALNETWORKS_CH_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--user", default=env("LOCALNETWORKS_CH_USER", "default"))
    parser.add_argument("--password", default=env("LOCALNETWORKS_CH_PASSWORD"))
    parser.add_argument("--database", default=env("LOCALNETWORKS_CH_DATABASE", "default"))

    parser.add_argument("--asn", type=int, default=int(env("LOCALNETWORKS_ASN", "0") or 0))
    parser.add_argument("--name", default=env("LOCALNETWORKS_NAME", ""))
    parser.add_argument("--source", default=env("LOCALNETWORKS_SOURCE", "bgp_origin_local_asn"))
    parser.add_argument(
        "--families",
        default=env("LOCALNETWORKS_FAMILIES", "4,6"),
        help="Comma-separated IP families to load, e.g. 4 or 4,6",
    )
    parser.add_argument(
        "--origin-table",
        default=env("LOCALNETWORKS_ORIGIN_TABLE", "default.bgp_prefix_origin_current"),
    )
    parser.add_argument("--table", default=env("LOCALNETWORKS_TABLE", "default.local_networks"))
    parser.add_argument(
        "--enabled-view",
        default=env("LOCALNETWORKS_ENABLED_VIEW", "default.local_networks_enabled"),
    )
    parser.add_argument(
        "--dictionary",
        default=env("LOCALNETWORKS_DICT", "default.local_networks_dict"),
    )

    parser.add_argument(
        "--dictionary-source-host",
        default=env("LOCALNETWORKS_DICT_SOURCE_HOST", env("LOCALNETWORKS_CH_HOST", "localhost")),
    )
    dict_port_s = env("LOCALNETWORKS_DICT_SOURCE_PORT", env("LOCALNETWORKS_CH_PORT"))
    dict_default_port = int(dict_port_s) if dict_port_s and dict_port_s.isdigit() else default_port
    parser.add_argument("--dictionary-source-port", type=int, default=dict_default_port)
    parser.add_argument(
        "--dictionary-source-user",
        default=env("LOCALNETWORKS_DICT_SOURCE_USER", env("LOCALNETWORKS_CH_USER", "default")),
    )
    parser.add_argument(
        "--dictionary-source-password",
        default=env("LOCALNETWORKS_DICT_SOURCE_PASSWORD", env("LOCALNETWORKS_CH_PASSWORD")),
    )
    parser.add_argument(
        "--dictionary-source-database",
        default=env("LOCALNETWORKS_DICT_SOURCE_DATABASE", env("LOCALNETWORKS_CH_DATABASE", "default")),
    )
    parser.add_argument(
        "--dictionary-source-table",
        default=env("LOCALNETWORKS_DICT_SOURCE_TABLE", "local_networks_enabled"),
    )
    parser.add_argument(
        "--dictionary-source-connect-timeout",
        type=int,
        default=int(env("LOCALNETWORKS_DICT_SOURCE_CONNECT_TIMEOUT", "10") or 10),
    )
    parser.add_argument(
        "--dictionary-source-receive-timeout",
        type=int,
        default=int(env("LOCALNETWORKS_DICT_SOURCE_RECEIVE_TIMEOUT", "30") or 30),
    )
    parser.add_argument("--skip-dictionary-create", action="store_true")
    parser.add_argument("--keep-tsv", action="store_true")
    args = parser.parse_args()

    if args.asn <= 0:
        raise RuntimeError("LOCALNETWORKS_ASN/--asn must be set to a positive ASN")
    families = [f.strip() for f in args.families.split(",") if f.strip()]
    if not families or any(f not in ("4", "6") for f in families):
        raise RuntimeError("--families must be a comma-separated list containing only 4 and/or 6")
    args.families = ",".join(families)
    if not args.name:
        args.name = f"AS{args.asn}"

    if not os.path.isfile(args.clickhouse_client):
        raise FileNotFoundError(f"clickhouse-client not found: {args.clickhouse_client}")

    base = clickhouse_base_args(args)

    # Ensure table/view exist even when the DDL file was not applied manually.
    ch_run_query(base, f"""
CREATE TABLE IF NOT EXISTS {args.table}
(
    prefix     String,
    family     UInt8,
    name       String,
    source     LowCardinality(String),
    enabled    UInt8,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192
""")
    ch_run_query(base, f"""
DROP TABLE IF EXISTS {args.enabled_view}
""")
    ch_run_query(base, f"""
CREATE VIEW {args.enabled_view} AS
SELECT
    prefix,
    name,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        prefix,
        argMax(name, updated_at) AS name,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM {args.table}
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1
""")

    raw_networks = fetch_origin_prefixes(base, args)
    if not raw_networks:
        raise RuntimeError(f"no prefixes found in {args.origin_table} for AS{args.asn}")
    collapsed = collapse_networks(raw_networks)
    new_keys = {(str(n), n.version) for n in collapsed}
    old_keys = set(fetch_existing_source_prefixes(base, args))
    disabled = sorted(old_keys - new_keys)

    updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    fd, tmp_path = tempfile.mkstemp(prefix="local_networks_", suffix=".tsv", text=True)
    os.close(fd)
    try:
        rows = write_rows_tsv(
            tmp_path,
            enabled_networks=collapsed,
            disabled_rows=disabled,
            name=args.name,
            source=args.source,
            updated_at=updated_at,
        )
        print(
            f"prefixes: raw={len(raw_networks)} collapsed={len(collapsed)} "
            f"disable_old={len(disabled)} rows_to_insert={rows}",
            file=sys.stderr,
        )

        insert_q = f"""
INSERT INTO {args.table}
(prefix, family, name, source, enabled, updated_at)
FORMAT TabSeparated
"""
        with open(tmp_path, "rb") as tsv:
            ch_run_query(base, insert_q, stdin=tsv)

        if not args.skip_dictionary_create:
            ch_create_or_replace_dictionary(base, args)
        ch_run_query(base, f"SYSTEM RELOAD DICTIONARY {args.dictionary}")

        print("load_local_networks_from_asn: done", file=sys.stderr)
        return 0
    finally:
        if not args.keep_tsv and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)
