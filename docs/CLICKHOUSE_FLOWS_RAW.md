# ClickHouse flow ingest: `default.flows_raw` and direct `xdpflowd` insert

## Production table (`default.flows_raw`)

Phase scripts (`prod_phase3_drop.sh`) assume:

| Usage | Column | Notes |
|-------|--------|-------|
| Time window | `time_received_ns` | `DateTime64(9)` |
| Aggregates | `packets` | `UInt64` |
| Aggregates | `bytes` | `UInt64` |

The live table is fed by the existing NetFlow → collector pipeline; exact DDL may include many more columns managed by that stack.

## Recommended staging table for direct inserts

Use a dedicated MergeTree table so `xdpflowd` can INSERT without altering Kafka-backed or managed schemas:

```sql
CREATE TABLE IF NOT EXISTS default.flows_raw_xdp_direct (
    time_received_ns   DateTime64(9),
    flow_first_seen_ns DateTime64(9),
    flow_last_seen_ns  DateTime64(9),
    src_ip             IPv6,
    dst_ip             IPv6,
    src_port           UInt16,
    dst_port           UInt16,
    protocol           UInt8,
    ip_version         UInt8,
    packets            UInt64,
    bytes              UInt64,
    tcp_flags          UInt8,
    vlan_id            UInt16,
    ingress_ifindex    UInt32,
    rx_queue           UInt32,
    src_tos            UInt8,
    ttl_min            UInt8,
    ttl_max            UInt8,
    pkt_len_min        UInt16,
    pkt_len_max        UInt16,
    ip_frag_count      UInt32,
    tcp_syn_count      UInt32,
    tcp_rst_count      UInt32,
    tcp_fin_count      UInt32,
    exporter_source_id UInt32,
    ingest_kind        LowCardinality(String) DEFAULT 'xdpflowd_direct'
)
ENGINE = MergeTree
PARTITION BY toDate(time_received_ns)
ORDER BY (time_received_ns, src_ip, dst_ip, dst_port);
```

## Field mapping (BPF / NetFlow → staging)

| Staging column | Source |
|----------------|--------|
| `time_received_ns` | Wall time when `xdpflowd` exported the row (receive time analogue). |
| `flow_first_seen_ns` | `ExporterStart + (FirstSeenNs - BpfStartNs)` |
| `flow_last_seen_ns` | `ExporterStart + (LastSeenNs - BpfStartNs)` |
| `src_ip` / `dst_ip` | IPv4 mapped to IPv6 (`::ffff:x.x.x.x`) or full IPv6 from flow key |
| `src_port` / `dst_port` | Host-endian ports from BPF key (`keyPortHost`) |
| `packets`, `bytes`, TCP/TTL/VLAN… | `FlowValue` / `FlowKey` |

## A/B vs legacy NetFlow→ClickHouse path

1. Create the staging table on ClickHouse (SQL above).
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
5. After validation, you can stop mirroring to the collector port that only fed ClickHouse and keep the port used for local capture unchanged.
