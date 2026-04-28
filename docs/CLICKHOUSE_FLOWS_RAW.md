# ClickHouse flow ingest: `default.flows_raw` and direct `xdpflowd` insert

## Production table (`default.flows_raw`)

This is the actual production DDL observed on `sel` via `SHOW CREATE TABLE default.flows_raw`:

```sql
CREATE TABLE default.flows_raw
(
    `date` Date,
    `time_inserted_ns` DateTime64(9),
    `time_received_ns` DateTime64(9),
    `time_flow_start_ns` DateTime64(9),
    `sequence_num` UInt32,
    `sampling_rate` UInt64,
    `sampler_address` FixedString(16),
    `src_addr` FixedString(16),
    `dst_addr` FixedString(16),
    `src_as` UInt32,
    `dst_as` UInt32,
    `etype` UInt32,
    `proto` UInt32,
    `src_port` UInt32,
    `dst_port` UInt32,
    `bytes` UInt64,
    `packets` UInt64
)
ENGINE = MergeTree
PARTITION BY date
ORDER BY time_received_ns
TTL date + toIntervalDay(5)
SETTINGS index_granularity = 8192;
```

Phase scripts (`prod_phase3_drop.sh`) currently compare:

| Usage | Column | Notes |
|-------|--------|-------|
| Time window | `time_received_ns` | `DateTime64(9)` |
| Aggregates | `packets` | `UInt64` |
| Aggregates | `bytes` | `UInt64` |

The live table is fed by the existing NetFlow → collector pipeline:

```text
ipt_NETFLOW / xdpflowd
  -> NetFlow v9 UDP
  -> local collector
  -> ClickHouse default.flows_raw
```

## Recommended staging table for direct inserts

For the first direct-ingest test, create a staging table with the **same shape** as `default.flows_raw`.
This keeps A/B validation honest and makes a later production switch a table-name/config change rather than a schema rewrite.

```sql
CREATE TABLE IF NOT EXISTS default.flows_raw_xdp_direct
(
    `date` Date,
    `time_inserted_ns` DateTime64(9),
    `time_received_ns` DateTime64(9),
    `time_flow_start_ns` DateTime64(9),
    `sequence_num` UInt32,
    `sampling_rate` UInt64,
    `sampler_address` FixedString(16),
    `src_addr` FixedString(16),
    `dst_addr` FixedString(16),
    `src_as` UInt32,
    `dst_as` UInt32,
    `etype` UInt32,
    `proto` UInt32,
    `src_port` UInt32,
    `dst_port` UInt32,
    `bytes` UInt64,
    `packets` UInt64
)
ENGINE = MergeTree
PARTITION BY date
ORDER BY time_received_ns
TTL date + toIntervalDay(5)
SETTINGS index_granularity = 8192;
```

## Field mapping (BPF → `flows_raw` shape)

| Column | Source / value |
|----------------|--------|
| `date` | `toDate(time_received_ns)` |
| `time_inserted_ns` | Wall time at ClickHouse insert (`now64(9)` equivalent from `xdpflowd`) |
| `time_received_ns` | Wall time when `xdpflowd` exports the row |
| `time_flow_start_ns` | `ExporterStart + (FirstSeenNs - BpfStartNs)` |
| `sequence_num` | `0` for direct staging until a downstream consumer requires exporter sequence semantics |
| `sampling_rate` | `1` (no sampling in current XDP path) |
| `sampler_address` | 16-byte exporter/source address; use zero bytes until real exporter IP is required |
| `src_addr` / `dst_addr` | 16 raw bytes from `FlowKey`; IPv4 stored in the first 4 bytes with the rest zeroed to match current BPF key layout |
| `src_as` / `dst_as` | `0` (not enriched by `xdpflowd`) |
| `etype` | `0x0800` for IPv4, `0x86DD` for IPv6 |
| `proto` | `FlowKey.Proto` |
| `src_port` / `dst_port` | Host-endian ports from BPF key (`keyPortHost`) |
| `bytes` / `packets` | `FlowValue.Bytes` / `FlowValue.Packets` |

## A/B vs legacy NetFlow→ClickHouse path

1. Create the staging table on ClickHouse using the production-shaped DDL above.
2. Run `xdpflowd` with **both** the existing NetFlow destinations (`-nf-dst …`) **and** direct insert:
   ```bash
   ./bin/xdpflowd ... \
     -nf-dst '127.0.0.1:9996,127.0.0.1:9999' \
     -ch-dsn 'clickhouse://USER:PASS@HOST:9000/default' \
     -ch-table default.flows_raw_xdp_direct
   ```
   Or via `prod_ab_swap.sh` / `prod_phase3_drop.sh`:
   ```bash
   export XDP_CH_DSN='clickhouse://USER:PASS@HOST:9000/default'
   export XDP_CH_TABLE='default.flows_raw_xdp_direct'
   ```

   Use the **native** TCP port (often `9000`), not the HTTP client port.

3. Compare **legacy DB path** (`default.flows_raw` from collector) vs **staging** (`default.flows_raw_xdp_direct`) using `sum(packets)` / `sum(bytes)` over the same wall-clock windows (`time_received_ns`).
4. Exact equality is not expected (flow timeouts differ slightly, bounded CH queue may drop under overload); large systematic gaps need investigation.
5. After validation, either point direct insert at `default.flows_raw` or keep a direct table and wire downstream reads/materialized views to it. Keep the NetFlow port used for local capture unchanged.

## Rollback / safety

Direct ClickHouse insert is disabled by default. The original path remains:

```text
xdpflowd -nf-dst 127.0.0.1:9996,127.0.0.1:9999
```

Operational rollback:

1. Remove or comment `XDP_CH_TABLE` / `XDP_CH_DSN` in `/root/.grapesnta-clickhouse.env`.
2. Restart the test or daemon. `xdpflowd` will continue exporting NetFlow only.
3. If staging data should be removed:

   ```sql
   DROP TABLE IF EXISTS default.flows_raw_xdp_direct;
   ```

This does not touch `default.flows_raw` or the local NetFlow capture port.
