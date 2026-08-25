#!/usr/bin/env python3
"""
Load IP->ASN fallback prefixes into ClickHouse.

Source format: https://iptoasn.com/data/ip2asn-combined.tsv.gz
Columns:
  range_start, range_end, as_number, country_code, as_description

The loader converts IP ranges to CIDR prefixes and refreshes
default.ip_asn_prefixes_current through a staging table. It is intended as a
fallback for remote ASN enrichment when BMP/BGP does not provide full-view
coverage.

Requires Python 3.7+ (stdlib only) and clickhouse-client.
"""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Iterator, List, Optional, Sequence, Tuple


DEFAULT_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
SOURCE_TAG = "iptoasn"


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


def clickhouse_base_args(args: argparse.Namespace) -> List[str]:
    cmd = [args.clickhouse_client]
    cmd += ["--host", args.host]
    cmd += ["--port", str(args.port)]
    cmd += ["--user", args.user]
    if args.password:
        cmd += ["--password", args.password]
    cmd += ["--database", args.database]
    return cmd


def ch_run(
    base: Sequence[str],
    query: str,
    *,
    input_path: Optional[str] = None,
    extra_args: Optional[Sequence[str]] = None,
) -> None:
    stdin = None
    try:
        if input_path:
            stdin = open(input_path, "rb")
        proc = subprocess.run(
            list(base) + list(extra_args or []) + ["--query", query],
            stdin=stdin,
            capture_output=True,
            text=True,
        )
    finally:
        if stdin is not None:
            stdin.close()
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"clickhouse-client failed: {err}\nquery: {query[:800]}")


def swap_tables(base: Sequence[str], staging_table: str, current_table: str) -> None:
    """Swap staging/current, supporting old ClickHouse without EXCHANGE TABLES."""
    try:
        ch_run(base, f"EXCHANGE TABLES {staging_table} AND {current_table}")
        return
    except RuntimeError as exc:
        print(f"EXCHANGE TABLES failed, falling back to RENAME TABLE: {exc}", file=sys.stderr)

    if "." in current_table:
        db, table = current_table.rsplit(".", 1)
        tmp_table = f"{db}.{table}_swap_old"
    else:
        tmp_table = f"{current_table}_swap_old"

    ch_run(base, f"DROP TABLE IF EXISTS {tmp_table}")
    ch_run(
        base,
        f"RENAME TABLE {current_table} TO {tmp_table}, "
        f"{staging_table} TO {current_table}, "
        f"{tmp_table} TO {staging_table}",
    )


def download(url: str, path: str, timeout: float, retries: int = 3) -> int:
    last_err: Optional[BaseException] = None
    attempts = max(int(retries), 1)
    for attempt in range(1, attempts + 1):
        tmp = path + ".tmp"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "GrapesNTA-iptoasn-loader/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
                if code != 200:
                    raise RuntimeError(f"{url}: HTTP {code}")
                written = 0
                with open(tmp, "wb") as f:
                    while True:
                        chunk = resp.read(1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        written += len(chunk)
            os.replace(tmp, path)
            tmp = ""
            return written
        except (TimeoutError, OSError, urllib.error.URLError, RuntimeError) as exc:
            last_err = exc
            print(f"download attempt {attempt}/{attempts} failed: {exc}", file=sys.stderr)
            if attempt < attempts:
                time.sleep(min(30, 5 * attempt))
        finally:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
    assert last_err is not None
    raise last_err


def iter_prefix_rows(gz_path: str, snapshot_ts: str) -> Iterator[Tuple[str, int, int, str, str, str, str]]:
    with gzip.open(gz_path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            start_s, end_s, asn_s, cc_s, as_name = parts[:5]
            try:
                asn = int(asn_s)
            except ValueError:
                continue
            if asn <= 0:
                continue
            try:
                start_ip = ipaddress.ip_address(start_s)
                end_ip = ipaddress.ip_address(end_s)
            except ValueError:
                continue
            if start_ip.version != end_ip.version:
                continue
            family = 4 if start_ip.version == 4 else 6
            cc = cc_s.strip().upper()
            if len(cc) != 2 or not cc.isalpha():
                cc = "??"
            clean_name = (
                as_name.replace("\\", "\\\\")
                .replace("\t", " ")
                .replace("\r", " ")
                .replace("\n", " ")
                .strip()
            )
            for net in ipaddress.summarize_address_range(start_ip, end_ip):
                yield (str(net), family, asn, cc, clean_name, SOURCE_TAG, snapshot_ts)


def write_tsv(rows: Iterator[Tuple[str, int, int, str, str, str, str]], path: str) -> int:
    count = 0
    with open(path, "w", encoding="utf-8", newline="") as out:
        for prefix, family, asn, cc, as_name, source, snapshot_ts in rows:
            out.write(
                f"{prefix}\t{family}\t{asn}\t{cc}\t{as_name}\t{source}\t{snapshot_ts}\n"
            )
            count += 1
    return count


def parse_args() -> argparse.Namespace:
    default_client = env("IPTOASN_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client")
    p = argparse.ArgumentParser(description="Load IP->ASN fallback prefixes into ClickHouse")
    p.add_argument("--clickhouse-client", default=resolve_clickhouse_client(default_client))
    p.add_argument("--host", default=env("IPTOASN_CH_HOST", env("GEOLOADERD_CH_HOST", "localhost")))
    p.add_argument("--port", type=int, default=int(env("IPTOASN_CH_PORT", env("GEOLOADERD_CH_PORT", "9000")) or 9000))
    p.add_argument("--user", default=env("IPTOASN_CH_USER", env("GEOLOADERD_CH_USER", "default")))
    p.add_argument("--password", default=env("IPTOASN_CH_PASSWORD", env("GEOLOADERD_CH_PASSWORD")))
    p.add_argument("--database", default=env("IPTOASN_CH_DATABASE", env("GEOLOADERD_CH_DATABASE", "default")))
    p.add_argument("--url", default=env("IPTOASN_URL", DEFAULT_URL))
    p.add_argument("--cache-dir", default=env("IPTOASN_CACHE_DIR", "/var/lib/iptoasn-loader/cache"))
    p.add_argument("--current-table", default=env("IPTOASN_CH_TABLE", "default.ip_asn_prefixes_current"))
    p.add_argument("--staging-table", default=env("IPTOASN_CH_STAGING", "default.ip_asn_prefixes_staging"))
    p.add_argument("--timeout", type=float, default=float(env("IPTOASN_TIMEOUT", "600") or 600))
    p.add_argument("--min-rows", type=int, default=int(env("IPTOASN_MIN_ROWS", "100000") or 100000))
    p.add_argument("--skip-download", action="store_true", default=env("IPTOASN_SKIP_DOWNLOAD") == "1")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    os.makedirs(args.cache_dir, exist_ok=True)
    gz_path = os.path.join(args.cache_dir, "ip2asn-combined.tsv.gz")

    if not args.skip_download or not os.path.exists(gz_path):
        size = download(args.url, gz_path, args.timeout)
        print(f"downloaded {size} bytes from {args.url}", file=sys.stderr)

    snapshot_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with tempfile.TemporaryDirectory(prefix="iptoasn-loader-") as tmpdir:
        tsv_path = os.path.join(tmpdir, "ip_asn_prefixes.tsv")
        rows = write_tsv(iter_prefix_rows(gz_path, snapshot_ts), tsv_path)
        if rows < args.min_rows:
            raise RuntimeError(f"too few prefixes parsed: {rows} < {args.min_rows}")
        print(f"parsed prefixes={rows}", file=sys.stderr)

        base = clickhouse_base_args(args)
        ch_run(base, f"TRUNCATE TABLE {args.staging_table}")
        insert_query = (
            f"INSERT INTO {args.staging_table} "
            "(prefix, family, origin_asn, cc, as_name, source, snapshot_ts) "
            "FORMAT TabSeparated"
        )
        ch_run(base, insert_query, input_path=tsv_path)
        swap_tables(base, args.staging_table, args.current_table)
        ch_run(base, f"TRUNCATE TABLE {args.staging_table}")

    print(f"loaded {rows} prefixes into {args.current_table}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
