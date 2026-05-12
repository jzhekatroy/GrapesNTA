#!/usr/bin/env python3
"""
Load RIR delegated-extended statistics into ClickHouse (country-only prefixes).

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
) -> None:
    proc = subprocess.run(
        list(base) + ["--query", query],
        stdin=stdin,
        capture_output=True,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        # Never echo full argv (may contain password on some setups).
        msg = (
            f"clickhouse-client failed (exit {proc.returncode})\n"
            f"query: {query[:500]}{'...' if len(query) > 500 else ''}\n"
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
    tmp = f"{db}._geo_country_swap_{os.getpid()}"
    q2 = (
        f"RENAME TABLE {table} TO {tmp}, "
        f"{staging} TO {table}, "
        f"{tmp} TO {staging}"
    )
    ch_run_query(base, q2)


@dataclass
class RunStats:
    rows: int = 0
    countries: set = field(default_factory=set)
    ru: int = 0


def write_tsv_and_stats(
    cache_dir: str,
    sources: Sequence[Tuple[str, str]],
    snapshot: str,
    skip_download: bool,
    http_timeout: float,
    tsv_path: str,
) -> RunStats:
    os.makedirs(cache_dir, mode=0o755, exist_ok=True)
    stats = RunStats()
    with open(tsv_path, "w", encoding="utf-8", newline="") as out:
        w = csv.writer(out, delimiter="\t", lineterminator="\n")
        for rir, url in sources:
            path = cache_path(cache_dir, rir)
            if not skip_download:
                n = download_file(url, path, http_timeout)
                print(f"downloaded {rir}: {n} bytes -> {path}", file=sys.stderr)
            elif not os.path.isfile(path):
                raise FileNotFoundError(f"cache missing (use download): {path}")
            for row in parse_delegated_lines(path, rir, snapshot):
                w.writerow(row)
                stats.rows += 1
                stats.countries.add(row[2])
                if row[2] == "RU":
                    stats.ru += 1
    return stats


def validate_stats(stats: RunStats, min_countries: int, require_ru: bool) -> None:
    if stats.rows == 0:
        raise RuntimeError("validation failed: no prefix rows parsed")
    if require_ru and stats.ru == 0:
        raise RuntimeError(
            "validation failed: no RU prefixes (unexpected for full RIR data); "
            "use --no-ru-check if intentional"
        )
    if len(stats.countries) < min_countries:
        raise RuntimeError(
            f"validation failed: only {len(stats.countries)} distinct countries "
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
        "--dictionary",
        default=env("GEOLOADERD_CH_DICT", "default.geo_country_dict"),
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
    try:
        fd, tmp_tsv = tempfile.mkstemp(prefix="rir_geo_", suffix=".tsv", text=True)
        os.close(fd)
        stats = write_tsv_and_stats(
            args.cache_dir,
            DEFAULT_SOURCES,
            snapshot,
            args.skip_download,
            args.http_timeout,
            tmp_tsv,
        )
        validate_stats(
            stats,
            args.min_countries,
            require_ru=not args.no_ru_check,
        )
        print(
            f"validation ok: rows={stats.rows} countries={len(stats.countries)} ru={stats.ru}",
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

        ch_run_query(base, f"SYSTEM RELOAD DICTIONARY {args.dictionary}")

        print("load_rir_geo: done", file=sys.stderr)
        return 0
    finally:
        if tmp_tsv and os.path.isfile(tmp_tsv) and not args.keep_tsv:
            try:
                os.remove(tmp_tsv)
            except OSError:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError, urllib.error.URLError) as e:
        print(e, file=sys.stderr)
        raise SystemExit(1)
