#!/usr/bin/env python3
"""
Load RIR delegated-extended statistics into ClickHouse.

The loader refreshes:
  - geo_prefix_country: country-only IP prefixes for IP_TRIE lookup.
  - asn_registry: ASN allocation country/RIR/status metadata for BGP reports.

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
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import BinaryIO, Iterator, List, Optional, Sequence, Tuple

DEFAULT_SOURCES: List[Tuple[str, str]] = [
    (
        "ripencc",
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    ),
    (
        "apnic",
        "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
    ),
    ("arin", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
    (
        "afrinic",
        "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    ),
    (
        "lacnic",
        "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    ),
]


def env(s: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(s)
    if v is None or v == "":
        return default
    return v


def cache_path(cache_dir: str, rir: str) -> str:
    return os.path.join(
        cache_dir, f"delegated-{rir}-extended-latest.txt"
    )


def download_file(url: str, dest: str, timeout: float) -> int:
    tmp = dest + ".tmp"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GrapesNTA-load_rir_geo/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", None)
            if code is None:
                code = resp.getcode()
            if code != 200:
                raise RuntimeError(f"{url}: HTTP {code}")
            data = resp.read()
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, dest)
        return len(data)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def is_alpha2(cc: str) -> bool:
    if len(cc) != 2:
        return False
    return cc.isalpha()


def prefix_status_ok(status: str) -> bool:
    s = status.strip().lower()
    if not s:
        return True
    if s in ("allocated", "assigned", "available", "legacy"):
        return True
    return "allocated" in s or "assigned" in s


def asn_status_ok(status: str) -> bool:
    s = status.strip().lower()
    if not s:
        return True
    if s in ("allocated", "assigned", "legacy"):
        return True
    return "allocated" in s or "assigned" in s


def parse_alloc_date(date_str: str) -> str:
    """Return YYYY-MM-DD for ClickHouse Date, or 1970-01-01 if unknown."""
    s = date_str.strip()
    if len(s) != 8 or not s.isdigit():
        return "1970-01-01"
    y, m, d = int(s[0:4]), int(s[4:6]), int(s[6:8])
    if y == 0 and m == 0 and d == 0:
        return "1970-01-01"
    return f"{y:04d}-{m:02d}-{d:02d}"


def parse_delegated_lines(
    path: str,
    rir_hint: str,
    snapshot: str,
    source_tag: str = "rir_delegated",
) -> Iterator[Tuple[str, int, str, str, str, str, str, str]]:
    """Yield TabSeparated row fields (8 columns)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rec = line.split("|")
            if len(rec) < 6:
                continue
            registry, cc, rec_type, start, val_str, date_str = rec[:6]
            status = rec[6] if len(rec) > 6 else ""

            if cc == "*" or not is_alpha2(cc):
                continue
            if status.strip().lower() == "summary":
                continue
            if not prefix_status_ok(status):
                continue

            rir = registry.strip().lower() or rir_hint.lower()
            alloc = parse_alloc_date(date_str)
            cc_u = cc.upper()

            if rec_type == "ipv4":
                try:
                    n = int(val_str, 10)
                except ValueError:
                    continue
                if n <= 0:
                    continue
                try:
                    first = ipaddress.IPv4Address(start)
                except ValueError:
                    continue
                last_int = int(first) + n - 1
                if last_int > 2**32 - 1:
                    continue
                last = ipaddress.IPv4Address(last_int)
                for net in ipaddress.summarize_address_range(first, last):
                    yield (
                        str(net),
                        4,
                        cc_u,
                        rir,
                        status,
                        alloc,
                        source_tag,
                        snapshot,
                    )
            elif rec_type == "ipv6":
                try:
                    pfx_len = int(val_str, 10)
                except ValueError:
                    continue
                if pfx_len <= 0 or pfx_len > 128:
                    continue
                try:
                    net = ipaddress.ip_network(f"{start}/{pfx_len}", strict=False)
                except ValueError:
                    continue
                yield (
                    str(net),
                    6,
                    cc_u,
                    rir,
                    status,
                    alloc,
                    source_tag,
                    snapshot,
                )


def parse_delegated_asn_lines(
    path: str,
    rir_hint: str,
    snapshot: str,
    source_tag: str = "rir_delegated",
) -> Iterator[Tuple[int, str, str, str, str, str, str]]:
    """Yield TabSeparated ASN rows (7 columns).

    RIR delegated ASN records use:
      registry|cc|asn|start|value|date|status

    where start is the first ASN and value is the count in the allocation.
    ClickHouse reports join by exact origin_asn, so ranges are expanded into one
    row per ASN. The global ASN table is small enough for this to be practical.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rec = line.split("|")
            if len(rec) < 6:
                continue
            registry, cc, rec_type, start, val_str, date_str = rec[:6]
            status = rec[6] if len(rec) > 6 else ""

            if rec_type != "asn":
                continue
            if cc == "*" or not is_alpha2(cc):
                continue
            if status.strip().lower() == "summary":
                continue
            if not asn_status_ok(status):
                continue

            try:
                first = int(start, 10)
                count = int(val_str, 10)
            except ValueError:
                continue
            if first <= 0 or count <= 0:
                continue
            last = first + count - 1
            if last > 2**32 - 1:
                continue

            rir = registry.strip().lower() or rir_hint.lower()
            alloc = parse_alloc_date(date_str)
            cc_u = cc.upper()

            for asn in range(first, last + 1):
                yield (
                    asn,
                    cc_u,
                    rir,
                    status,
                    alloc,
                    source_tag,
                    snapshot,
                )


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
) -> None:
    proc = subprocess.run(
        list(base) + ["--query", query],
        stdin=stdin,
        capture_output=True,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        # Never echo full argv (may contain password on some setups).
        shown_query = display_query if display_query is not None else query
        msg = (
            f"clickhouse-client failed (exit {proc.returncode})\n"
            f"query: {shown_query[:500]}{'...' if len(shown_query) > 500 else ''}\n"
            f"stderr: {err}"
        )
        raise RuntimeError(msg)


def ch_swap_tables(base: Sequence[str], table: str, staging: str) -> None:
    q = f"EXCHANGE TABLES {table} AND {staging}"
    try:
        ch_run_query(base, q)
        return
    except RuntimeError:
        pass
    # Fallback: atomic triple RENAME (same database).
    if "." not in table or "." not in staging:
        raise RuntimeError(
            "EXCHANGE TABLES failed; for RENAME fallback use qualified names "
            "like default.geo_prefix_country"
        )
    db = table.split(".", 1)[0]
    tmp = f"{db}._rir_loader_swap_{os.getpid()}"
    q2 = (
        f"RENAME TABLE {table} TO {tmp}, "
        f"{staging} TO {table}, "
        f"{tmp} TO {staging}"
    )
    ch_run_query(base, q2)


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def build_dictionary_query(args: argparse.Namespace, password: str) -> str:
    return f"""
CREATE OR REPLACE DICTIONARY {args.dictionary}
(
    prefix String,
    cc String,
    rir String,
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


@dataclass
class RunStats:
    rows: int = 0
    countries: set = field(default_factory=set)
    ru: int = 0


def write_tsvs_and_stats(
    cache_dir: str,
    sources: Sequence[Tuple[str, str]],
    snapshot: str,
    skip_download: bool,
    http_timeout: float,
    prefix_tsv_path: str,
    asn_tsv_path: str,
) -> Tuple[RunStats, RunStats]:
    os.makedirs(cache_dir, mode=0o755, exist_ok=True)
    prefix_stats = RunStats()
    asn_stats = RunStats()
    with open(prefix_tsv_path, "w", encoding="utf-8", newline="") as prefix_out, open(
        asn_tsv_path, "w", encoding="utf-8", newline=""
    ) as asn_out:
        prefix_w = csv.writer(prefix_out, delimiter="\t", lineterminator="\n")
        asn_w = csv.writer(asn_out, delimiter="\t", lineterminator="\n")
        for rir, url in sources:
            path = cache_path(cache_dir, rir)
            if not skip_download:
                n = download_file(url, path, http_timeout)
                print(f"downloaded {rir}: {n} bytes -> {path}", file=sys.stderr)
            elif not os.path.isfile(path):
                raise FileNotFoundError(f"cache missing (use download): {path}")
            for row in parse_delegated_lines(path, rir, snapshot):
                prefix_w.writerow(row)
                prefix_stats.rows += 1
                prefix_stats.countries.add(row[2])
                if row[2] == "RU":
                    prefix_stats.ru += 1
            for row in parse_delegated_asn_lines(path, rir, snapshot):
                asn_w.writerow(row)
                asn_stats.rows += 1
                asn_stats.countries.add(row[1])
                if row[1] == "RU":
                    asn_stats.ru += 1
    return prefix_stats, asn_stats


def validate_stats(stats: RunStats, min_countries: int, require_ru: bool, label: str) -> None:
    if stats.rows == 0:
        raise RuntimeError(f"validation failed: no {label} rows parsed")
    if require_ru and stats.ru == 0:
        raise RuntimeError(
            f"validation failed: no RU {label} rows (unexpected for full RIR data); "
            "use --no-ru-check if intentional"
        )
    if len(stats.countries) < min_countries:
        raise RuntimeError(
            f"validation failed: only {len(stats.countries)} distinct countries in {label} "
            f"(want >= {min_countries})"
        )


def main() -> int:
    p = argparse.ArgumentParser(description="Load RIR delegated data into ClickHouse.")
    _port_s = env("GEOLOADERD_CH_PORT")
    _default_port = int(_port_s) if _port_s and _port_s.isdigit() else 9000
    p.add_argument(
        "--clickhouse-client",
        default=env("GEOLOADERD_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client"),
    )
    p.add_argument("--host", default=env("GEOLOADERD_CH_HOST", "localhost"))
    p.add_argument("--port", type=int, default=_default_port)
    p.add_argument("--user", default=env("GEOLOADERD_CH_USER", "default"))
    p.add_argument(
        "--password",
        default=env("GEOLOADERD_CH_PASSWORD"),
        help="If omitted, empty password (or set env GEOLOADERD_CH_PASSWORD)",
    )
    p.add_argument("--database", default=env("GEOLOADERD_CH_DATABASE", "default"))
    p.add_argument(
        "--table",
        default=env("GEOLOADERD_CH_TABLE", "default.geo_prefix_country"),
    )
    p.add_argument(
        "--staging-table",
        default=env("GEOLOADERD_CH_STAGING", "default.geo_prefix_country_staging"),
    )
    p.add_argument(
        "--asn-table",
        default=env("GEOLOADERD_CH_ASN_TABLE", "default.asn_registry"),
    )
    p.add_argument(
        "--asn-staging-table",
        default=env("GEOLOADERD_CH_ASN_STAGING", "default.asn_registry_staging"),
    )
    p.add_argument(
        "--dictionary",
        default=env("GEOLOADERD_CH_DICT", "default.geo_country_dict"),
    )
    p.add_argument(
        "--dictionary-source-host",
        default=env("GEOLOADERD_DICT_SOURCE_HOST", env("GEOLOADERD_CH_HOST", "localhost")),
        help="Host used by ClickHouse itself to read geo_prefix_country for the dictionary",
    )
    _dict_port_s = env("GEOLOADERD_DICT_SOURCE_PORT", env("GEOLOADERD_CH_PORT"))
    _dict_default_port = int(_dict_port_s) if _dict_port_s and _dict_port_s.isdigit() else _default_port
    p.add_argument(
        "--dictionary-source-port",
        type=int,
        default=_dict_default_port,
        help="Port used by ClickHouse itself to read geo_prefix_country for the dictionary",
    )
    p.add_argument(
        "--dictionary-source-user",
        default=env("GEOLOADERD_DICT_SOURCE_USER", env("GEOLOADERD_CH_USER", "default")),
    )
    p.add_argument(
        "--dictionary-source-password",
        default=env("GEOLOADERD_DICT_SOURCE_PASSWORD", env("GEOLOADERD_CH_PASSWORD")),
    )
    p.add_argument(
        "--dictionary-source-database",
        default=env("GEOLOADERD_DICT_SOURCE_DATABASE", env("GEOLOADERD_CH_DATABASE", "default")),
    )
    p.add_argument(
        "--dictionary-source-table",
        default=env("GEOLOADERD_DICT_SOURCE_TABLE", "geo_prefix_country"),
    )
    p.add_argument(
        "--dictionary-source-connect-timeout",
        type=int,
        default=int(env("GEOLOADERD_DICT_SOURCE_CONNECT_TIMEOUT", "10") or 10),
    )
    p.add_argument(
        "--dictionary-source-receive-timeout",
        type=int,
        default=int(env("GEOLOADERD_DICT_SOURCE_RECEIVE_TIMEOUT", "30") or 30),
    )
    p.add_argument(
        "--skip-dictionary-create",
        action="store_true",
        help="Only reload an already-created dictionary",
    )
    p.add_argument(
        "--cache-dir",
        default=env("GEOLOADERD_CACHE_DIR", "/var/lib/geoloaderd/cache"),
    )
    p.add_argument("--skip-download", action="store_true")
    p.add_argument("--keep-tsv", action="store_true", help="Do not delete temp TSV")
    p.add_argument("--http-timeout", type=float, default=120.0)
    p.add_argument("--min-countries", type=int, default=8)
    p.add_argument(
        "--no-ru-check",
        action="store_true",
        help="Do not require RU prefixes (for subset testing)",
    )
    args = p.parse_args()

    snapshot = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    tmp_tsv = None
    tmp_asn_tsv = None
    try:
        fd, tmp_tsv = tempfile.mkstemp(prefix="rir_geo_", suffix=".tsv", text=True)
        os.close(fd)
        fd, tmp_asn_tsv = tempfile.mkstemp(prefix="rir_asn_", suffix=".tsv", text=True)
        os.close(fd)
        prefix_stats, asn_stats = write_tsvs_and_stats(
            args.cache_dir,
            DEFAULT_SOURCES,
            snapshot,
            args.skip_download,
            args.http_timeout,
            tmp_tsv,
            tmp_asn_tsv,
        )
        validate_stats(
            prefix_stats,
            args.min_countries,
            require_ru=not args.no_ru_check,
            label="prefix",
        )
        validate_stats(
            asn_stats,
            args.min_countries,
            require_ru=not args.no_ru_check,
            label="ASN",
        )
        print(
            "validation ok: "
            f"prefix_rows={prefix_stats.rows} prefix_countries={len(prefix_stats.countries)} prefix_ru={prefix_stats.ru} "
            f"asn_rows={asn_stats.rows} asn_countries={len(asn_stats.countries)} asn_ru={asn_stats.ru}",
            file=sys.stderr,
        )

        if not os.path.isfile(args.clickhouse_client):
            raise FileNotFoundError(f"clickhouse-client not found: {args.clickhouse_client}")

        base = clickhouse_base_args(args)

        stg = args.staging_table
        ch_run_query(base, f"TRUNCATE TABLE IF EXISTS {stg}")
        insert_q = f"INSERT INTO {stg} FORMAT TabSeparated"
        with open(tmp_tsv, "rb") as tsv_bin:
            ch_run_query(base, insert_q, stdin=tsv_bin)

        ch_swap_tables(base, args.table, stg)

        asn_stg = args.asn_staging_table
        ch_run_query(base, f"TRUNCATE TABLE IF EXISTS {asn_stg}")
        asn_insert_q = f"INSERT INTO {asn_stg} FORMAT TabSeparated"
        with open(tmp_asn_tsv, "rb") as asn_tsv_bin:
            ch_run_query(base, asn_insert_q, stdin=asn_tsv_bin)

        ch_swap_tables(base, args.asn_table, asn_stg)

        if not args.skip_dictionary_create:
            ch_create_or_replace_dictionary(base, args)

        ch_run_query(base, f"SYSTEM RELOAD DICTIONARY {args.dictionary}")

        print("load_rir_geo: done", file=sys.stderr)
        return 0
    finally:
        if tmp_tsv and os.path.isfile(tmp_tsv) and not args.keep_tsv:
            try:
                os.remove(tmp_tsv)
            except OSError:
                pass
        if tmp_asn_tsv and os.path.isfile(tmp_asn_tsv) and not args.keep_tsv:
            try:
                os.remove(tmp_asn_tsv)
            except OSError:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError, urllib.error.URLError) as e:
        print(e, file=sys.stderr)
        raise SystemExit(1)
