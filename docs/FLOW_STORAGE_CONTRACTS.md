# Flow storage contracts (production)

This document freezes **what we keep stable** while changing the NetFlow hot path
(`ipt_NETFLOW` / `xdpflowd`): **local `nfcapd` archive**, **`default.flows_raw`**, and
how we validate `xdpflowd` delivery (direct or spool-backed).

## Local archive contract: `nfcapd` / `nfdump`

- **Transport**: NetFlow **v9** over **UDP**.
- **Typical capture on prod hosts**: `127.0.0.1:9996` (and sometimes additional
  ports, e.g. `2055` for parallel collectors).
- **On-disk format**: **nfdump binary** as produced by `nfcapd` (not a replay
  source for ClickHouse; local forensics / `nfdump` tooling).
- **Scripts**: `NF_DSTS` / the third argument to `prod_ab_swap.sh` must keep
  `127.0.0.1:9996` when local capture must continue during XDP tests, e.g.:
  `NF_DSTS=127.0.0.1:9996` or include it in a comma-separated list.

**Quick checks**

```bash
# Listener (example)
ss -lunp | grep 9996 || true

# Latest rotated file (path varies by install; often under /storage/nfdump)
ls -lt /storage/nfdump | head

# Read a few flows from a capture file
nfdump -r /path/to/nfcapd.file -c 5
```

## Database contract: `default.flows_raw` (ClickHouse)

- **Table**: production-shaped MergeTree storage — see
  [`docs/CLICKHOUSE_FLOWS_RAW.md`](CLICKHOUSE_FLOWS_RAW.md) and
  [`docs/CLICKHOUSE_SCHEMA.md`](CLICKHOUSE_SCHEMA.md).
- **Direct insert from `xdpflowd`**: `INSERT` column order and types must match
  this table (including `sampler_address FixedString(16)` and IPv4-in-first-4-bytes
  layout for `src_addr` / `dst_addr`).

**Quick checks**

```bash
clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" --password "$CH_PASS" --query "
SELECT count() AS rows, sum(packets) AS packets, sum(bytes) AS bytes,
       min(time_received_ns), max(time_received_ns)
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 10 MINUTE
FORMAT PrettyCompact
"
```

## `xdpflowd` delivery checks (direct or spool)

After a test run, inspect `xdpflowd` logs:

```bash
grep -E 'clickhouse|spool pipeline|queue_drops|insert_errs|final flush|shutdown|ERROR|WARN' /path/to/xdpflowd.log
```

- **Direct sink** (`-ch-spool-mode off`): expect `records_queued == records_written`
  after close, `insert_errs=0`, `queue_drops=0` when the system keeps up.
- **Spool pipeline** (`-ch-spool-mode on|required`): expect `records_spooled` and
  `records_acked` to match after graceful shutdown and ClickHouse catch-up; watch
  `insert_errs` / retry storms under overload.

## Durable spool (internal queue only)

- Spool files under `-ch-spool-dir` are **not** a user-facing archive format; they
  hold gob-encoded `FlowRow` batches for at-least-once delivery to ClickHouse.
- Do **not** point spool at the multi-terabyte `nfdump` volume without sizing;
  use a dedicated fast path (e.g. `var` /NVMe) and retention / `max-bytes` caps.

## Heavy servers (`netflow`-class)

For very large BPF flow maps, use either:

- `xdpflowd -heavy-export` (shorter `-nf-active` / `-nf-idle` / `-nf-scan`), or
- `XDP_HEAVY_SERVER=1` with `prod_ab_swap.sh` / `prod_phase3_drop.sh` (see script headers).

Goal: avoid multi-million-flow **final flush** hitting watchdog shutdown.

For production-style configuration, prefer a reviewed YAML file; see
[`XDPFLOWD_CONFIG.md`](XDPFLOWD_CONFIG.md).
