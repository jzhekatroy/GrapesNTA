# ClickHouse enrichment (future layer)

**Status**: planned — **not** part of the current `default.flows_raw` contract.

After `xdpflowd` reliably delivers base flow rows (directly or via durable spool)
into `default.flows_raw`, enrichment can add reversibly:

| Signal | Notes |
|--------|--------|
| `sampler_address` | Already exposed via `-ch-sampler-addr` for exporter identity. |
| NetFlow `source_id` | Available as `-nf-source-id`; currently mapped to `sequence_num=0` in many paths — extend only with consumer agreement. |
| Exporter hostname | Inject in a batch job or sidecar, not required in BPF. |
| `src_as` / `dst_as`, geo, labels | Via MaxMind / internal dictionaries / MV to an **enriched** table or column set. |

## Principles

1. **Do not break** the base `default.flows_raw` schema without an explicit migration.
2. Prefer **new table + MV** or a dedicated `flows_enriched` layer for AS/geo so
   backfills do not rewrite history.
3. **nfcapd / nfdump** archives remain the local binary corpus; enrichment is
   orthogonal to that format.

See also: [`FLOW_STORAGE_CONTRACTS.md`](FLOW_STORAGE_CONTRACTS.md),
[`CLICKHOUSE_FLOWS_RAW.md`](CLICKHOUSE_FLOWS_RAW.md).
