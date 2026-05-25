# Operations Monitoring and Error Logging

This document defines the first monitoring contract for GrapesNTA services. For now the source of truth is the systemd journal: services keep regular metrics at `INFO`, and emit `ERROR` only when the collector is degraded or data can be lost/stale.

## Log Levels

- `INFO`: normal service lifecycle and periodic counters. These lines are useful for dashboards and manual checks, but should not page by themselves.
- `WARN`: transient problem or automatic back-pressure/retry. Investigate if repeated, but it can recover without data loss.
- `ERROR`: alert-worthy degradation. The service is still running, but collection, parsing, or ClickHouse delivery is unhealthy.

Recommended first alert filter:

```bash
sudo journalctl -u xdpflowd -u dnsflowd -u bmpgrapes --since "10 minutes ago" --no-pager | grep 'level=ERROR'
```

Per-service filters:

```bash
sudo journalctl -u xdpflowd --since "10 minutes ago" --no-pager | grep 'xdpflowd health degraded'
sudo journalctl -u dnsflowd --since "10 minutes ago" --no-pager | grep 'dnsflowd health degraded'
sudo journalctl -u bmpgrapes --since "10 minutes ago" --no-pager | grep 'bmpgrapes health degraded'
```

## xdpflowd

`xdpflowd` writes one `ERROR` line:

```text
level=ERROR msg="xdpflowd health degraded"
```

Alert fields:

- `map_full_delta`: BPF flow map was full during the health interval. Flow aggregation may be dropping new keys. Increase map capacity, shorten export windows, or reduce churn.
- `insert_errs_delta`: ClickHouse inserts failed. Check ClickHouse reachability, authentication, table schema, and server load.
- `queue_drops_delta`: direct ClickHouse queue dropped rows. Use spool mode for production or increase queue/batch capacity.
- `writer_lag_rows`: rows queued/spooled but not acked by ClickHouse. If growing, ClickHouse delivery is slower than capture.
- `lag_segments`: durable spool segment lag. A non-zero value is acceptable during bursts; sustained growth means ClickHouse is behind.
- `drainer_progress_age`: spool drainer has not acknowledged progress while lag exists. Check ClickHouse and spool corruption/retry logs.
- `netflow_send_errs_delta`: NetFlow socket sends failed. Check local nfcapd/goflow2 target and network path.

Default env thresholds:

```env
XDP_HEALTH_INTERVAL=1m
XDP_HEALTH_SPOOL_LAG_SEGMENTS=10
XDP_HEALTH_WRITER_LAG_ROWS=100000
XDP_HEALTH_DRAINER_AGE=2m
```

First checks:

```bash
sudo journalctl -u xdpflowd --since "10 minutes ago" --no-pager | grep -E 'health degraded|clickhouse spool pipeline|stats|netflow'
sudo systemctl status xdpflowd --no-pager
du -sh /var/lib/xdpflowd/ch-spool 2>/dev/null || true
```

## dnsflowd

`dnsflowd` writes one `ERROR` line:

```text
level=ERROR msg="dnsflowd health degraded"
```

Alert fields (split sinks):

- `answers_queue_drops_delta`: **critical** — `dns_answers` rows dropped; Flow Explorer DNS names will be missing/stale.
- `raw_queue_drops_delta`: raw `dns_log` loss (audit/debug); answers may still be OK.
- `answers_insert_errs_delta`: `dns_answers` INSERT failures.
- `raw_insert_errs_delta` / `insert_errs_delta`: `dns_log` INSERT failures.
- `answers_writer_lag_rows`: answers queue backlog (primary lag signal).
- `raw_writer_lag_rows`: raw queue backlog.
- `raw_shed_active`, `raw_shed_due_answers_lag_total`, `raw_policy`: automatic raw
  pause to protect `dns_answers` (best-effort raw).
- `answers_dedup_suppressed`, `answers_dedup_emitted`: in-process dedup volume.
- `answers_queue_depth_batches`, `raw_queue_depth_batches`: per-queue depth.
- Legacy: `queue_drops_delta`, `writer_lag_rows` (answers-focused aggregate).

Default env thresholds:

```env
DNS_HEALTH_INTERVAL=1m
DNS_HEALTH_LAG_THRESHOLD=100000
```

Recommended production capacity:

```env
DNS_CH_RAW_ENABLED=1
DNS_CH_ANSWERS_ENABLED=1
DNS_CH_RAW_BATCH_SIZE=20000
DNS_CH_ANSWERS_BATCH_SIZE=20000
DNS_CH_RAW_QUEUE_SIZE=65536
DNS_CH_ANSWERS_QUEUE_SIZE=262144
DNS_CH_RAW_WRITERS=1
DNS_CH_ANSWERS_WRITERS=2
DNS_CAPTURE_BATCH_SIZE=1000
DNS_CAPTURE_FLUSH_INTERVAL=100ms
```

UI-first overload:

```env
DNS_CH_RAW_ENABLED=0
DNS_CH_ANSWERS_ENABLED=1
DNS_CH_ANSWERS_WRITERS=4
```

First checks:

```bash
sudo journalctl -u dnsflowd --since "10 minutes ago" --no-pager | grep -E 'health degraded|dnsflowd clickhouse|answers queue full|raw queue full|insert_errs'
sudo systemctl status dnsflowd --no-pager
```

Then confirm freshness in ClickHouse:

```sql
SELECT toString(max(ts)) AS max_ts, count() AS total_rows FROM default.dns_log FORMAT PrettyCompact;
SELECT toString(max(ts)) AS max_ts, count() AS total_rows FROM default.dns_answers FORMAT PrettyCompact;
```

## bmpgrapes

`bmpgrapes` writes one `ERROR` line:

```text
level=ERROR msg="bmpgrapes health degraded"
```

Alert fields:

- `insert_errs_delta`: writes to `bmp_route_events` or `bmp_peers` failed.
- `queue_drops_delta`: rows were dropped. This only happens in `BMP_CH_QUEUE_MODE=drop`; production should prefer `block`.
- `queue_blocks_delta`: rows hit full queue in `block` mode and BMP TCP back-pressure was applied. This avoids loss, but sustained values mean ClickHouse cannot keep up.
- `events_lag_rows`, `peers_lag_rows`: queued rows not yet written.
- `bgp_parse_errs_delta`, `bgp_parse_error_pct`: parser rejected BGP UPDATE payloads. A high ratio can mean unsupported message shape or corrupted/mirrored data.
- `sessions_open`: active BMP TCP sessions. If `BMP_HEALTH_REQUIRE_ACTIVE_PEER=true`, zero sessions is `ERROR`.

Default env thresholds:

```env
BMP_HEALTH_INTERVAL=1m
BMP_HEALTH_WRITER_LAG_ROWS=100000
BMP_HEALTH_QUEUE_BLOCKS=100000
BMP_HEALTH_BGP_PARSE_ERROR_PCT=5
BMP_HEALTH_REQUIRE_ACTIVE_PEER=false
```

First checks:

```bash
sudo journalctl -u bmpgrapes --since "10 minutes ago" --no-pager | grep -E 'health degraded|bmpgrapes clickhouse|peer up|peer down|session'
sudo systemctl status bmpgrapes --no-pager
```

## bgp-origin-refresh

`bgp-origin-refresh.service` is a `oneshot` systemd job that rebuilds the
current `prefix -> origin ASN` lookup from `default.bmp_route_events`.
`bgp-origin-refresh.timer` should run it every 5 minutes.

This service does not talk to routers and does not read from `bmpgrapes`
directly. It reads ClickHouse event history and atomically swaps
`default.bgp_prefix_origin_current` when the rebuilt snapshot passes validation.

Expected success log:

```text
rebuild_bgp_origin_asn: starting ...
rebuild_bgp_origin_asn: source_window events=... announces=... withdraws=...
rebuild_bgp_origin_asn: current_table rows=...
rebuild_bgp_origin_asn: staging rows=... origin_asns=...
rebuild_bgp_origin_asn: swapped target_table=default.bgp_prefix_origin_current rows=...
rebuild_bgp_origin_asn: done rows=...
```

Failure conditions:

- authentication or ClickHouse connectivity errors;
- memory/query failures during the rebuild;
- empty staging table;
- `BGPORIGIN_MIN_PREFIXES` guard failure;
- `BGPORIGIN_MAX_PREFIX_DROP_PCT` guard failure.

First checks:

```bash
sudo systemctl status bgp-origin-refresh.timer --no-pager
sudo systemctl status bgp-origin-refresh.service --no-pager
sudo systemctl list-timers | grep bgp
sudo journalctl -u bgp-origin-refresh.service --since "1 hour ago" --no-pager
```

Freshness query:

```sql
SELECT
    count() AS prefixes,
    uniqExact(origin_asn) AS origin_asns,
    toString(max(snapshot_ts)) AS snapshot_ts,
    toString(min(last_ts)) AS oldest_event_used,
    toString(max(last_ts)) AS newest_event_used
FROM default.bgp_prefix_origin_current;
```

## Alerting Policy

Initial policy for log-based alerting:

- Page immediately on any `level=ERROR msg="xdpflowd health degraded"` where `map_full_delta`, `queue_drops_delta`, or `insert_errs_delta` is non-zero.
- Page immediately on any `level=ERROR msg="dnsflowd health degraded"` where `answers_queue_drops_delta`, `answers_insert_errs_delta`, or `answers_writer_lag_rows` exceeds threshold.
- Warn on `raw_queue_drops_delta` or `raw_insert_errs_delta` (audit loss, UI may still work).
- Page on `bmpgrapes health degraded` if `insert_errs_delta` or `queue_drops_delta` is non-zero.
- Page if `bgp-origin-refresh.service` fails, the timer is missing/inactive, or `bgp_prefix_origin_current.snapshot_ts` is stale.
- Create warning alerts for sustained lag/back-pressure over 5-10 minutes: `writer_lag_rows`, `lag_segments`, `drainer_progress_age`, `queue_blocks_delta`.

## Future UI Status

The future UI can derive component states from the same fields:

- `OK`: no recent `ERROR`, freshness queries are current.
- `DEGRADED`: lag/back-pressure exists, but no drops.
- `DATA_LOSS_RISK`: queue drops, BPF map full, or insert errors.
- `STALE`: no fresh rows in ClickHouse or no required BMP peer session.

Until that exists, the journal `ERROR` contract above is the operational interface.
