#!/usr/bin/env python3
"""
Load ASN organization names into ClickHouse default.asn_names.

Data flow:
  1. Read distinct ASN list from --source-table (default: default.asn_registry,
     which is populated by scripts/load_rir_geo.py).
  2. Query Team Cymru bulk whois (whois.cymru.com:43, no auth) in chunks for
     "AS NAME" + country/registry metadata.
  3. INSERT into --target-table (default: default.asn_names). The target is a
     ReplacingMergeTree by `updated_at`, so periodic reruns simply override
     stale rows without staging/swap.

Requires: Python 3.7+ (stdlib only) and clickhouse-client on PATH.
"""

from __future__ import annotations

import argparse
import csv
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import BinaryIO, Iterator, List, Optional, Sequence, Tuple


DEFAULT_CYMRU_HOST = "whois.cymru.com"
DEFAULT_CYMRU_PORT = 43
SOURCE_TAG = "team_cymru"


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
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
    capture: bool = False,
    display_query: Optional[str] = None,
) -> Optional[str]:
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
    if capture:
        return proc.stdout.decode("utf-8", errors="replace")
    return None


def _is_retryable_error(stderr: str) -> bool:
    """True for transient ClickHouse errors that we should back off and retry.

    Code 241 is MEMORY_LIMIT_EXCEEDED — typical when the server is briefly
    overcommitted by other workloads (RIB dumps from bmpgrapes, periodic
    rebuilds, etc.). Code 252 is TOO_MANY_PARTS, similarly transient.
    """
    if not stderr:
        return False
    return (
        "Code: 241" in stderr
        or "MEMORY_LIMIT_EXCEEDED" in stderr
        or "Code: 252" in stderr
        or "TOO_MANY_PARTS" in stderr
        or "Code: 49" in stderr  # LOGICAL_ERROR sometimes wraps transient races
    )


def ch_run_query_retry(
    base: Sequence[str],
    query: str,
    *,
    input_bytes: Optional[bytes] = None,
    attempts: int = 5,
    delay: float = 30.0,
    label: str = "query",
    display_query: Optional[str] = None,
) -> None:
    """Run a query with retries on transient memory/overcommit errors.

    input_bytes is preferred over stdin file handles because retries become
    trivial: we keep the bytes in memory and resend on each attempt.
    """
    last_stderr = ""
    last_rc = 0
    for attempt in range(1, attempts + 1):
        proc = subprocess.run(
            list(base) + ["--query", query],
            input=input_bytes,
            capture_output=True,
        )
        if proc.returncode == 0:
            return
        last_rc = proc.returncode
        last_stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        if attempt < attempts and _is_retryable_error(last_stderr):
            wait = delay * attempt  # linear backoff is fine for slow memory recovery
            head = last_stderr.splitlines()[0] if last_stderr else ""
            print(
                f"{label}: retryable error attempt {attempt}/{attempts}, "
                f"sleeping {wait:.0f}s ({head[:160]})",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(wait)
            continue
        break
    shown_query = display_query if display_query is not None else query
    raise RuntimeError(
        f"clickhouse-client failed (exit {last_rc}) after {attempts} attempts\n"
        f"label: {label}\n"
        f"query: {shown_query[:500]}{'...' if len(shown_query) > 500 else ''}\n"
        f"stderr: {last_stderr}"
    )


def insert_tsv_in_batches(
    base: Sequence[str],
    target_table: str,
    tsv_path: str,
    *,
    batch_size: int,
    attempts: int,
    delay: float,
    progress: bool = False,
) -> int:
    """INSERT a TSV file into ClickHouse in fixed-row batches with retries.

    Splitting keeps each attempt's working set small so that an overcommitted
    server can usually accept it on the next try. SETTINGS on the INSERT cap
    the per-query memory budget and limit insert-thread fan-out.
    """
    insert_q = (
        f"INSERT INTO {target_table} (asn, name, org_id, source, updated_at) "
        f"SETTINGS max_memory_usage = 1073741824, "
        f"max_insert_threads = 1, "
        f"max_threads = 2 "
        f"FORMAT TabSeparated"
    )
    with open(tsv_path, "rb") as src:
        data = src.read()
    lines = data.splitlines(keepends=True)
    total = len(lines)
    if total == 0:
        raise RuntimeError("nothing to insert: empty TSV")
    inserted = 0
    n_batches = (total + batch_size - 1) // batch_size
    for bi, i in enumerate(range(0, total, batch_size), start=1):
        chunk = b"".join(lines[i : i + batch_size])
        if progress:
            print(
                f"insert batch {bi}/{n_batches} rows={min(batch_size, total - i)} "
                f"bytes={len(chunk)} ...",
                file=sys.stderr,
                flush=True,
            )
        ch_run_query_retry(
            base,
            insert_q,
            input_bytes=chunk,
            attempts=attempts,
            delay=delay,
            label=f"INSERT batch {bi}/{n_batches}",
        )
        inserted += min(batch_size, total - i)
    return inserted


def fetch_asn_list(base: Sequence[str], args: argparse.Namespace) -> List[int]:
    """Return distinct ASN list from --source-table, sorted ascending."""
    where = "asn > 0"
    if args.source_filter:
        where = f"{where} AND ({args.source_filter})"
    query = (
        f"SELECT DISTINCT asn FROM {args.source_table} "
        f"WHERE {where} ORDER BY asn FORMAT TabSeparated"
    )
    out = ch_run_query(base, query, capture=True) or ""
    asns: List[int] = []
    for line in out.splitlines():
        s = line.strip()
        if not s or not s.isdigit():
            continue
        asns.append(int(s))
    return asns


def _recv_until_eof(sock: socket.socket) -> bytes:
    buf = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def cymru_lookup_chunk(
    asns: Sequence[int],
    host: str,
    port: int,
    timeout: float,
) -> Iterator[Tuple[int, str, str, str]]:
    """Query Team Cymru bulk whois for one chunk of ASNs.

    Yields (asn, name, cc, registry). Lines that cannot be parsed (e.g. the
    banner line "Bulk mode; ...") are skipped.
    """
    payload = bytearray()
    payload.extend(b"begin\n")
    payload.extend(b"verbose\n")
    for asn in asns:
        payload.extend(f"AS{int(asn)}\n".encode("ascii"))
    payload.extend(b"end\n")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(bytes(payload))
        data = _recv_until_eof(sock)

    text = data.decode("utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Verbose mode reply columns:
        #   AS | CC | Registry | Allocated | AS Name
        # The banner ("Bulk mode; ...") and any error lines have no '|' or fewer columns.
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        asn_s, cc, registry, _allocated, as_name = parts[:5]
        if not asn_s.isdigit():
            continue
        asn = int(asn_s)
        if asn <= 0:
            continue
        name = as_name
        # Cymru appends ", <CC>" to AS Name; strip it for a cleaner display.
        if cc and name.endswith(", " + cc):
            name = name[: -(2 + len(cc))]
        name = name.strip()
        if name in ("", "NA"):
            continue
        yield asn, name, cc.upper() if len(cc) == 2 and cc.isalpha() else "", registry.lower()


def write_tsv(
    asns: Sequence[int],
    tsv_path: str,
    args: argparse.Namespace,
    snapshot: str,
) -> int:
    rows = 0
    seen: set = set()
    with open(tsv_path, "w", encoding="utf-8", newline="") as out:
        w = csv.writer(out, delimiter="\t", lineterminator="\n")
        for i in range(0, len(asns), args.chunk_size):
            sub = asns[i : i + args.chunk_size]
            if args.progress:
                print(
                    f"cymru chunk {i // args.chunk_size + 1}/"
                    f"{(len(asns) + args.chunk_size - 1) // args.chunk_size} "
                    f"size={len(sub)} ...",
                    file=sys.stderr,
                    flush=True,
                )
            for asn, name, _cc, _rir in cymru_lookup_chunk(
                sub, args.cymru_host, args.cymru_port, args.cymru_timeout
            ):
                if asn in seen:
                    continue
                seen.add(asn)
                w.writerow([asn, name, "", SOURCE_TAG, snapshot])
                rows += 1
    return rows


def _resolve_connection_defaults() -> dict:
    """Resolve ClickHouse connection defaults as a single coherent tuple.

    A connection is {host, port, user, password, database}. Mixing fields across
    env-prefixes is a footgun (e.g. ASNNAMES_CH_USER=default with the
    GEOLOADERD_CH_PASSWORD of another user). So we pick exactly one prefix:
      * If ANY ASNNAMES_CH_* is defined, use the ASNNAMES_CH_* set as-is (empty
        means empty — never silently fall back to geoloaderd).
      * Otherwise fall back to GEOLOADERD_CH_* (compat with shared env files).
      * Otherwise built-in defaults (localhost:9000, user=default, empty pw).
    """
    prefixes = ("ASNNAMES_CH_", "GEOLOADERD_CH_")
    chosen = None
    for pref in prefixes:
        if any(f"{pref}{k}" in os.environ for k in ("HOST", "PORT", "USER", "PASSWORD", "DATABASE")):
            chosen = pref
            break
    if chosen is None:
        return {
            "host": "localhost",
            "port": 9000,
            "user": "default",
            "password": None,
            "database": "default",
        }
    host = os.environ.get(f"{chosen}HOST", "").strip() or "localhost"
    port_s = os.environ.get(f"{chosen}PORT", "").strip()
    port = int(port_s) if port_s.isdigit() else 9000
    user = os.environ.get(f"{chosen}USER", "").strip() or "default"
    # Empty string is a valid (=empty) password; convert to None so we omit
    # --password from the clickhouse-client invocation.
    pw_raw = os.environ.get(f"{chosen}PASSWORD")
    password = pw_raw if pw_raw not in (None, "") else None
    database = os.environ.get(f"{chosen}DATABASE", "").strip() or "default"
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Load ASN names from Team Cymru into ClickHouse.")
    conn = _resolve_connection_defaults()
    p.add_argument(
        "--clickhouse-client",
        default=env("ASNNAMES_CLICKHOUSE_CLIENT", env("GEOLOADERD_CLICKHOUSE_CLIENT", "/usr/bin/clickhouse-client")),
    )
    p.add_argument("--host", default=conn["host"])
    p.add_argument("--port", type=int, default=conn["port"])
    p.add_argument("--user", default=conn["user"])
    p.add_argument(
        "--password",
        default=conn["password"],
        help="If omitted, empty password (or set env ASNNAMES_CH_PASSWORD)",
    )
    p.add_argument("--database", default=conn["database"])

    p.add_argument(
        "--source-table",
        default=env("ASNNAMES_SOURCE_TABLE", "default.asn_registry"),
        help="Table with ASN column to enrich (default: default.asn_registry)",
    )
    p.add_argument(
        "--source-filter",
        default=env("ASNNAMES_SOURCE_FILTER", ""),
        help="Optional SQL predicate appended to the SELECT (without WHERE)",
    )
    p.add_argument(
        "--target-table",
        default=env("ASNNAMES_CH_TABLE", "default.asn_names"),
    )

    p.add_argument(
        "--cymru-host",
        default=env("ASNNAMES_CYMRU_HOST", DEFAULT_CYMRU_HOST),
    )
    p.add_argument(
        "--cymru-port",
        type=int,
        default=int(env("ASNNAMES_CYMRU_PORT", str(DEFAULT_CYMRU_PORT)) or DEFAULT_CYMRU_PORT),
    )
    p.add_argument(
        "--cymru-timeout",
        type=float,
        default=float(env("ASNNAMES_CYMRU_TIMEOUT", "120") or 120),
    )
    p.add_argument(
        "--chunk-size",
        type=int,
        default=int(env("ASNNAMES_CHUNK_SIZE", "5000") or 5000),
        help="ASN per bulk-whois session (Team Cymru handles a few thousand per connection)",
    )
    p.add_argument(
        "--min-rows",
        type=int,
        default=int(env("ASNNAMES_MIN_ROWS", "1000") or 1000),
        help="Refuse to insert if fewer rows parsed (likely connectivity issue)",
    )
    p.add_argument(
        "--max-asns",
        type=int,
        default=int(env("ASNNAMES_MAX_ASNS", "0") or 0),
        help="If > 0, only resolve the first N ASN from the source list (debug)",
    )
    p.add_argument(
        "--insert-batch-size",
        type=int,
        default=int(env("ASNNAMES_INSERT_BATCH_SIZE", "10000") or 10000),
        help="Rows per INSERT batch (smaller = friendlier to a memory-pressured server)",
    )
    p.add_argument(
        "--retry-attempts",
        type=int,
        default=int(env("ASNNAMES_RETRY_ATTEMPTS", "6") or 6),
        help="Attempts per INSERT batch on transient errors (memory/overcommit)",
    )
    p.add_argument(
        "--retry-delay",
        type=float,
        default=float(env("ASNNAMES_RETRY_DELAY", "30") or 30),
        help="Seconds to wait between retries (multiplied by attempt number)",
    )
    p.add_argument(
        "--skip-optimize",
        action="store_true",
        default=bool(env("ASNNAMES_SKIP_OPTIMIZE")),
        help="Do not run OPTIMIZE TABLE FINAL after insert",
    )
    p.add_argument("--keep-tsv", action="store_true")
    p.add_argument("--progress", action="store_true", default=bool(env("ASNNAMES_PROGRESS")))
    args = p.parse_args()

    if not os.path.isfile(args.clickhouse_client):
        raise FileNotFoundError(f"clickhouse-client not found: {args.clickhouse_client}")

    base = clickhouse_base_args(args)

    asns = fetch_asn_list(base, args)
    if not asns:
        raise RuntimeError(
            f"no ASN found in {args.source_table}; run load_rir_geo.py first"
        )
    if args.max_asns > 0:
        asns = asns[: args.max_asns]
    print(f"asns to lookup: {len(asns)}", file=sys.stderr)

    snapshot = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    tmp_tsv = None
    try:
        fd, tmp_tsv = tempfile.mkstemp(prefix="asn_names_", suffix=".tsv", text=True)
        os.close(fd)
        rows = write_tsv(asns, tmp_tsv, args, snapshot)
        print(f"parsed rows: {rows}", file=sys.stderr)
        if rows < args.min_rows:
            raise RuntimeError(
                f"too few rows parsed ({rows} < {args.min_rows}); Cymru likely unreachable or empty reply"
            )

        inserted = insert_tsv_in_batches(
            base,
            args.target_table,
            tmp_tsv,
            batch_size=args.insert_batch_size,
            attempts=args.retry_attempts,
            delay=args.retry_delay,
            progress=args.progress,
        )
        print(f"inserted rows: {inserted}", file=sys.stderr)

        # ReplacingMergeTree deduplicates lazily during merges; nudge it so that
        # asn_registry_enriched returns fresh names without waiting for a merge.
        # On a memory-pressured server this is best-effort: if it fails we keep
        # the inserted rows and let background merges catch up.
        if not args.skip_optimize:
            try:
                ch_run_query_retry(
                    base,
                    f"OPTIMIZE TABLE {args.target_table} FINAL",
                    attempts=args.retry_attempts,
                    delay=args.retry_delay,
                    label="OPTIMIZE FINAL",
                )
            except RuntimeError as e:
                print(f"OPTIMIZE warning: {e}", file=sys.stderr)

        print("load_asn_names: done", file=sys.stderr)
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
    except (FileNotFoundError, RuntimeError, OSError) as e:
        print(e, file=sys.stderr)
        raise SystemExit(1)
