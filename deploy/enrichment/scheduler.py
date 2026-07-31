#!/usr/bin/env python3
"""Minimal job scheduler for grapes-enrichment (replaces supercronic)."""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

JOBS = [
    # (name, script, interval_sec, lock_path)
    ("bgp-origin", "/app/bin/cron-bgp-origin.sh", 300, "/tmp/bgp-origin.lock"),
    ("geoloaderd", "/app/bin/cron-geoloaderd.sh", 86400, "/tmp/enrichment-heavy.lock"),
    ("asn-names", "/app/bin/cron-asn-names.sh", 604800, "/tmp/asn-names.lock"),
    # Shares the heavy lock with geoloaderd: both download large external files.
    ("iptoasn", "/app/bin/cron-iptoasn.sh", 86400, "/tmp/enrichment-heavy.lock"),
    # 5 min: discover is a flows_raw scan; SNMP poll itself is gated by
    # refresh_interval_sec (default 1800) inside snmp_iface_sync.py.
    ("snmp-iface-sync", "/app/bin/cron-snmp-iface-sync.sh", 300, "/tmp/snmp-iface-sync.lock"),
]


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{ts} {msg}", flush=True)


def run_locked(name: str, script: str, lock_path: str) -> None:
    # Skip bgp while heavy RIR lock is held.
    if name == "bgp-origin":
        try:
            heavy = open("/tmp/enrichment-heavy.lock", "a+", encoding="utf-8")
            try:
                fcntl.flock(heavy.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(heavy.fileno(), fcntl.LOCK_UN)
            except BlockingIOError:
                log(f"{name}: skip (geoloaderd heavy lock held)")
                heavy.close()
                _report_skipped(name, "geoloaderd heavy lock held")
                return
            heavy.close()
        except OSError as e:
            log(f"{name}: heavy-lock check failed: {e}")

    lockf = open(lock_path, "a+", encoding="utf-8")
    try:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log(f"{name}: skip (already running)")
        lockf.close()
        _report_skipped(name, "already running")
        return

    log(f"{name}: start {script}")
    try:
        proc = subprocess.run([script], check=False)
        log(f"{name}: exit={proc.returncode}")
    finally:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)
        lockf.close()


def _report_skipped(name: str, reason: str) -> None:
    try:
        subprocess.run(
            [
                "python3",
                "/app/bin/report_job_status.py",
                "--job",
                name,
                "--status",
                "skipped",
                "--exit-code",
                "0",
                "--message",
                reason,
            ],
            check=False,
        )
    except OSError as e:
        log(f"{name}: skip-status report failed: {e}")


def _ensure_reporter_http_env() -> None:
    """report_job_status.py reads CLICKHOUSE_HTTP_*; map from job client envs."""
    host = (
        os.environ.get("CLICKHOUSE_HTTP_HOST")
        or os.environ.get("GEOLOADERD_CH_HOST")
        or os.environ.get("BGPORIGIN_CH_HOST")
        or "127.0.0.1"
    )
    user = (
        os.environ.get("CLICKHOUSE_HTTP_USER")
        or os.environ.get("GEOLOADERD_CH_USER")
        or os.environ.get("BGPORIGIN_CH_USER")
        or "default"
    )
    password = (
        os.environ.get("CLICKHOUSE_HTTP_PASSWORD")
        or os.environ.get("GEOLOADERD_CH_PASSWORD")
        or os.environ.get("BGPORIGIN_CH_PASSWORD")
        or ""
    )
    os.environ.setdefault("CLICKHOUSE_HTTP_HOST", host)
    os.environ.setdefault("CLICKHOUSE_HTTP_PORT", os.environ.get("CLICKHOUSE_HTTP_PORT", "8123"))
    os.environ.setdefault("CLICKHOUSE_HTTP_USER", user)
    os.environ.setdefault("CLICKHOUSE_HTTP_PASSWORD", password)


def _seed_deferred_job_status() -> None:
    """Heavy jobs wait a full interval after start; seed status so Diagnostics
    does not show neverRan until the first real run (day/week)."""
    _ensure_reporter_http_env()
    for name, _script, interval, _lock in JOBS:
        if name not in ("geoloaderd", "asn-names", "iptoasn"):
            continue
        try:
            rc = subprocess.run(
                [
                    "python3",
                    "/app/bin/report_job_status.py",
                    "--job",
                    name,
                    "--status",
                    "idle",
                    "--exit-code",
                    "0",
                    "--message",
                    f"awaiting first scheduled run (interval={interval}s)",
                ],
                check=False,
            ).returncode
            if rc == 0:
                log(f"{name}: seeded idle status (deferred first run)")
            else:
                log(f"{name}: seed status failed exit={rc}")
        except OSError as e:
            log(f"{name}: seed status failed: {e}")


def main() -> int:
    if os.path.isfile("/app/.env"):
        # Best-effort load for interactive debugging; docker env_file already injects vars.
        with open("/app/.env", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v)

    last_run = {name: 0.0 for name, *_ in JOBS}
    # Run bgp-origin soon after start; delay heavy jobs a bit.
    last_run["bgp-origin"] = time.time() - 240
    last_run["geoloaderd"] = time.time()  # wait ~1 day unless forced
    last_run["asn-names"] = time.time()
    last_run["iptoasn"] = time.time()
    last_run["snmp-iface-sync"] = 0.0  # run on first tick

    log("grapes-enrichment scheduler started")
    _seed_deferred_job_status()
    while True:
        now = time.time()
        for name, script, interval, lock_path in JOBS:
            if now - last_run[name] >= interval:
                last_run[name] = now
                run_locked(name, script, lock_path)
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
