#!/usr/bin/env python3
"""
Rebuild BGP prefix -> origin ASN lookup from bmp_route_events.

The output table is default.bgp_prefix_origin_current and the generated
dictionary is default.bgp_origin_asn_dict (IP_TRIE). This lets traffic queries
map flow IPs to BGP origin ASN quickly:

    flows_raw.dst_addr -> bgp_origin_asn_dict -> origin_asn -> asn_registry_enriched

Requires: Python 3.7+ (stdlib only) and clickhouse-client on PATH.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import BinaryIO, List, Optional, Sequence, Tuple


def env(s: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(s)
    if v is None or v == "":
        return default
    return v


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
    display_query: Optional[str] = None,
) -> str:
    proc = subprocess.run(
        list(base) + ["--query", query],
        stdin=stdin,
        capture_output=True,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        shown_query = display_query if display_query is not None else query
        msg = (
            f"clickhouse-client failed (exit {proc.returncode})\n"
            f"query: {shown_query[:500]}{'...' if len(shown_query) > 500 else ''}\n"
            f"stderr: {err}"
        )
        raise RuntimeError(msg)
    return proc.stdout.decode("utf-8", errors="replace")


def ch_run_scalar(base: Sequence[str], query: str) -> str:
    return ch_run_query(base, query + " FORMAT TabSeparated").strip()


def ch_run_int(base: Sequence[str], query: str) -> int:
    out = ch_run_scalar(base, query)
    if out == "":
        return 0
    return int(out.splitlines()[0].split("\t")[0])


def ch_run_tsv_row(base: Sequence[str], query: str) -> Tuple[str, ...]:
    out = ch_run_scalar(base, query)
    if out == "":
        return tuple()
    return tuple(out.splitlines()[0].split("\t"))


def log_info(message: str) -> None:
    print(f"rebuild_bgp_origin_asn: {message}", file=sys.stderr)


def ch_swap_tables(
    base: Sequence[str],
    table: str,
    staging: str,
    dictionary: Optional[str] = None,
) -> None:
    # EXCHANGE TABLES is atomic and keeps both table names, so a dictionary whose
    # SOURCE references `table` stays valid. This is the primary swap path.
    q = f"EXCHANGE TABLES {table} AND {staging}"
    try:
        ch_run_query(base, q)
        return
    except RuntimeError as exc:
        log_info(f"EXCHANGE TABLES failed, falling back to RENAME: {exc}")
    if "." not in table or "." not in staging:
        raise RuntimeError(
            "EXCHANGE TABLES failed; for RENAME fallback use qualified names "
            "like default.bgp_prefix_origin_current"
        )
    # RENAME fallback drops the current table name, which a dependent dictionary
    # blocks (Code 630). Best-effort drop the dictionary first; the caller
    # recreates it right after the swap. Ignore drop failures (e.g. restricted
    # endpoints that reject DROP DICTIONARY) so the fallback can still proceed.
    if dictionary:
        ch_drop_dictionary(base, dictionary)
    db = table.split(".", 1)[0]
    tmp = f"{db}._bgp_origin_swap_{os.getpid()}"
    q2 = (
        f"RENAME TABLE {table} TO {tmp}, "
        f"{staging} TO {table}, "
        f"{tmp} TO {staging}"
    )
    ch_run_query(base, q2)


def ch_drop_dictionary(base: Sequence[str], dictionary: str) -> None:
    try:
        ch_run_query(base, f"DROP DICTIONARY IF EXISTS {dictionary}")
        return
    except RuntimeError as exc1:
        try:
            # Some ClickHouse endpoints expose dictionaries as Dictionary-engine
            # tables and reject DROP DICTIONARY in their SQL parser.
            ch_run_query(base, f"DROP TABLE IF EXISTS {dictionary}")
            return
        except RuntimeError as exc2:
            log_info(
                f"drop dictionary {dictionary} failed (ignored): "
                f"drop_dictionary={exc1}; drop_table={exc2}"
            )


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def build_dictionary_query(args: argparse.Namespace, password: str) -> str:
    return f"""
CREATE OR REPLACE DICTIONARY {args.dictionary}
(
    prefix String,
    origin_asn UInt32,
    peer_asn UInt32,
    active_paths UInt32,
    source String,
    snapshot_ts DateTime
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
    redacted_query = build_dictionary_query(args, "***")
    ch_run_query(base, query, display_query=redacted_query)


def build_rebuild_query(args: argparse.Namespace, family: int) -> str:
    # MVP aggregation: latest event per prefix, one IP family at a time.
    #
    # Splitting IPv4 and IPv6 halves the aggregation cardinality per query and
    # keeps memory predictable on the shared ClickHouse. External group-by spill
    # is enabled and max_memory_usage is capped to stay below the server-wide
    # overcommit tracker limit.
    return f"""
INSERT INTO {args.staging_table}
SELECT
    if(
        family = 4,
        concat(IPv4NumToString(reinterpretAsUInt32(reverse(substring(prefix_bin, 1, 4)))), '/', toString(prefix_len)),
        concat(IPv6NumToString(prefix_bin), '/', toString(prefix_len))
    ) AS prefix,
    family,
    last_origin_asn AS origin_asn,
    last_peer_asn AS peer_asn,
    toUInt32(1) AS active_paths,
    last_ts,
    'bmp_route_events' AS source,
    now() AS snapshot_ts
FROM
(
    SELECT
        family,
        prefix AS prefix_bin,
        prefix_len,
        argMax(event_type, ts) AS last_event,
        argMax(origin_asn, ts) AS last_origin_asn,
        argMax(peer_asn, ts) AS last_peer_asn,
        max(ts) AS last_ts
    FROM {args.route_events_table}
    WHERE ts >= now() - INTERVAL {args.lookback_days} DAY
      AND family = {family}
      AND prefix_len > 0
    GROUP BY
        family,
        prefix,
        prefix_len
)
WHERE last_event = 'announce' AND last_origin_asn != 0
SETTINGS
    max_memory_usage = {args.max_memory_usage},
    max_bytes_before_external_group_by = {args.max_bytes_before_external_group_by},
    max_threads = {args.max_threads},
    group_by_two_level_threshold_bytes = 50000000
"""


def main() -> int:
    p = argparse.ArgumentParser(description="Rebuild BGP origin ASN IP_TRIE lookup.")
    _port_s = env("BGPORIGIN_CH_PORT")
    _default_port = int(_port_s) if _port_s and _port_s.isdigit() else 9000
    p.add_argument(
        "--clickhouse-client",
        default=env("BGPORIGIN_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"),
    )
    p.add_argument("--host", default=env("BGPORIGIN_CH_HOST", "localhost"))
    p.add_argument("--port", type=int, default=_default_port)
    p.add_argument("--user", default=env("BGPORIGIN_CH_USER", "default"))
    p.add_argument(
        "--password",
        default=env("BGPORIGIN_CH_PASSWORD"),
        help="If omitted, empty password (or set env BGPORIGIN_CH_PASSWORD)",
    )
    p.add_argument("--database", default=env("BGPORIGIN_CH_DATABASE", "default"))
    p.add_argument(
        "--route-events-table",
        default=env("BGPORIGIN_ROUTE_EVENTS_TABLE", "default.bmp_route_events"),
    )
    p.add_argument(
        "--table",
        default=env("BGPORIGIN_CH_TABLE", "default.bgp_prefix_origin_current"),
    )
    p.add_argument(
        "--staging-table",
        default=env("BGPORIGIN_CH_STAGING", "default.bgp_prefix_origin_current_staging"),
    )
    p.add_argument(
        "--dictionary",
        default=env("BGPORIGIN_CH_DICT", "default.bgp_origin_asn_dict"),
    )
    p.add_argument(
        "--lookback-days",
        type=int,
        default=int(env("BGPORIGIN_LOOKBACK_DAYS", "1") or 1),
        help="Route event lookback window used to infer current active prefixes",
    )
    p.add_argument(
        "--min-prefixes",
        type=int,
        default=int(env("BGPORIGIN_MIN_PREFIXES", "0") or 0),
        help="Fail before swap if staging has fewer rows than this count",
    )
    p.add_argument(
        "--max-prefix-drop-pct",
        type=float,
        default=float(env("BGPORIGIN_MAX_PREFIX_DROP_PCT", "50") or 50),
        help="Fail before swap if staging row count drops by more than this percent versus the current table",
    )
    p.add_argument(
        "--max-memory-usage",
        type=int,
        default=int(env("BGPORIGIN_MAX_MEMORY_USAGE", str(4 * 1024 * 1024 * 1024)) or 4 * 1024 * 1024 * 1024),
        help="Per-query max_memory_usage (bytes). Stay well below ClickHouse server total limit.",
    )
    p.add_argument(
        "--max-bytes-before-external-group-by",
        type=int,
        default=int(env("BGPORIGIN_MAX_BYTES_BEFORE_EXTERNAL_GROUP_BY", str(1024 * 1024 * 1024)) or 1024 * 1024 * 1024),
        help="Aggregation spill threshold (bytes). Should be lower than --max-memory-usage.",
    )
    p.add_argument(
        "--max-threads",
        type=int,
        default=int(env("BGPORIGIN_MAX_THREADS", "2") or 2),
        help="Per-query thread limit. Lower values reduce memory pressure.",
    )
    p.add_argument(
        "--dictionary-source-host",
        default=env("BGPORIGIN_DICT_SOURCE_HOST", env("BGPORIGIN_CH_HOST", "localhost")),
        help="Host used by ClickHouse itself to read bgp_prefix_origin_current for the dictionary",
    )
    _dict_port_s = env("BGPORIGIN_DICT_SOURCE_PORT", env("BGPORIGIN_CH_PORT"))
    _dict_default_port = int(_dict_port_s) if _dict_port_s and _dict_port_s.isdigit() else _default_port
    p.add_argument(
        "--dictionary-source-port",
        type=int,
        default=_dict_default_port,
        help="Port used by ClickHouse itself to read bgp_prefix_origin_current for the dictionary",
    )
    p.add_argument(
        "--dictionary-source-user",
        default=env("BGPORIGIN_DICT_SOURCE_USER", env("BGPORIGIN_CH_USER", "default")),
    )
    p.add_argument(
        "--dictionary-source-password",
        default=env("BGPORIGIN_DICT_SOURCE_PASSWORD", env("BGPORIGIN_CH_PASSWORD")),
    )
    p.add_argument(
        "--dictionary-source-database",
        default=env("BGPORIGIN_DICT_SOURCE_DATABASE", env("BGPORIGIN_CH_DATABASE", "default")),
    )
    p.add_argument(
        "--dictionary-source-table",
        default=env("BGPORIGIN_DICT_SOURCE_TABLE", "bgp_prefix_origin_current"),
    )
    p.add_argument(
        "--dictionary-source-connect-timeout",
        type=int,
        default=int(env("BGPORIGIN_DICT_SOURCE_CONNECT_TIMEOUT", "10") or 10),
    )
    p.add_argument(
        "--dictionary-source-receive-timeout",
        type=int,
        default=int(env("BGPORIGIN_DICT_SOURCE_RECEIVE_TIMEOUT", "30") or 30),
    )
    p.add_argument(
        "--skip-dictionary-create",
        action="store_true",
        help="Only reload an already-created dictionary",
    )
    args = p.parse_args()

    if args.lookback_days < 1:
        raise RuntimeError("--lookback-days must be >= 1")
    if args.min_prefixes < 0:
        raise RuntimeError("--min-prefixes must be >= 0")
    if args.max_prefix_drop_pct < 0 or args.max_prefix_drop_pct > 100:
        raise RuntimeError("--max-prefix-drop-pct must be between 0 and 100")
    if not os.path.isfile(args.clickhouse_client):
        raise FileNotFoundError(f"clickhouse-client not found: {args.clickhouse_client}")

    base = clickhouse_base_args(args)

    log_info(
        "starting "
        f"route_events_table={args.route_events_table} "
        f"target_table={args.table} "
        f"lookback_days={args.lookback_days} "
        f"min_prefixes={args.min_prefixes} "
        f"max_prefix_drop_pct={args.max_prefix_drop_pct:g}"
    )

    source = ch_run_tsv_row(
        base,
        f"""
SELECT
    count(),
    countIf(event_type = 'announce'),
    countIf(event_type = 'withdraw'),
    toString(min(ts)),
    toString(max(ts))
FROM {args.route_events_table}
WHERE ts >= now() - INTERVAL {args.lookback_days} DAY
""",
    )
    if len(source) == 5:
        log_info(
            "source_window "
            f"events={source[0]} announces={source[1]} withdraws={source[2]} "
            f"first_ts={source[3]} last_ts={source[4]}"
        )

    existing_rows = ch_run_int(base, f"SELECT count() FROM {args.table}")
    log_info(f"current_table rows={existing_rows}")

    ch_run_query(base, f"TRUNCATE TABLE IF EXISTS {args.staging_table}")
    for family in (4, 6):
        log_info(f"rebuilding family={family}")
        ch_run_query(base, build_rebuild_query(args, family))

    rows = ch_run_int(base, f"SELECT count() FROM {args.staging_table}")
    staging = ch_run_tsv_row(
        base,
        f"""
SELECT
    count(),
    uniqExact(origin_asn),
    toString(min(last_ts)),
    toString(max(last_ts)),
    toString(max(snapshot_ts))
FROM {args.staging_table}
""",
    )
    if len(staging) == 5:
        log_info(
            "staging "
            f"rows={staging[0]} origin_asns={staging[1]} "
            f"oldest_event={staging[2]} newest_event={staging[3]} "
            f"snapshot_ts={staging[4]}"
        )

    if rows == 0:
        raise RuntimeError("validation failed: bgp_prefix_origin_current staging is empty")
    if args.min_prefixes > 0 and rows < args.min_prefixes:
        raise RuntimeError(
            "validation failed: staging row count below minimum "
            f"rows={rows} min_prefixes={args.min_prefixes}"
        )
    if existing_rows > 0 and rows < existing_rows:
        drop_pct = (existing_rows - rows) * 100.0 / existing_rows
        if drop_pct > args.max_prefix_drop_pct:
            raise RuntimeError(
                "validation failed: staging row count dropped too much "
                f"current_rows={existing_rows} staging_rows={rows} "
                f"drop_pct={drop_pct:.2f} max_prefix_drop_pct={args.max_prefix_drop_pct:g}"
            )

    swap_dictionary = None if args.skip_dictionary_create else args.dictionary
    ch_swap_tables(base, args.table, args.staging_table, swap_dictionary)
    log_info(f"swapped target_table={args.table} rows={rows}")

    if not args.skip_dictionary_create:
        ch_create_or_replace_dictionary(base, args)

    ch_run_query(base, f"SYSTEM RELOAD DICTIONARY {args.dictionary}")
    log_info(f"done rows={rows}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError) as e:
        print(e, file=sys.stderr)
        raise SystemExit(1)
