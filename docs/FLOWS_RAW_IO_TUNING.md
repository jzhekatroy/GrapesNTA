# `flows_raw` I/O tuning

Production `flows_raw` volume is high enough that ClickHouse background merges
can dominate disk I/O. The safe tuning order is:

1. Reduce rollup mutations. Async rollups should skip existing buckets unless a
   manual rebuild explicitly passes `--delete-before-insert`.
2. Limit large `flows_raw` merges with table settings during incidents.
3. Apply storage codecs and remove legacy duplicate columns.
4. Reduce ClickHouse background merge concurrency when server/container access
   is available.

## Applied storage changes

`deploy/clickhouse/migrate_flows_raw_storage_tuning.sql` records the production
storage migration:

- `time_*`, ports, counters, ASN, VLAN, and protocol columns use explicit codecs.
- legacy duplicate `src_as` / `dst_as` columns are removed; writers use
  `src_asn` / `dst_asn`.

On large existing tables these ALTERs can create mutations that rewrite old
parts. Monitor and stop unexpected rewrite work:

```sql
SELECT mutation_id, is_done, command
FROM system.mutations
WHERE database = 'default' AND table = 'flows_raw'
ORDER BY create_time DESC;

KILL MUTATION
WHERE database = 'default'
  AND table = 'flows_raw'
  AND mutation_id = '...';
```

## Measuring compression

Use `system.part_log` for fresh parts after a known timestamp:

```sql
SELECT
    event_type,
    round(sum(size_in_bytes) / sum(rows), 1) AS bytes_per_row,
    sum(rows) AS total_rows,
    round(sum(size_in_bytes) / 1024 / 1024 / 1024, 2) AS gb
FROM system.part_log
WHERE database = 'default'
  AND table = 'flows_raw'
  AND event_time > 'YYYY-MM-DD HH:MM:SS'
  AND event_type IN ('NewPart', 'MergeParts')
GROUP BY event_type
ORDER BY event_type;
```

Use `system.parts_columns` to find remaining heavy columns on fresh active
parts:

```sql
SELECT
    column,
    round(sum(column_data_compressed_bytes) / 1024 / 1024, 1) AS comp_mb,
    round(sum(column_data_uncompressed_bytes) / sum(column_data_compressed_bytes), 2) AS ratio
FROM system.parts_columns
WHERE database = 'default'
  AND table = 'flows_raw'
  AND active
  AND partition = 'YYYY-MM-DD'
  AND modification_time > now() - INTERVAL 5 MINUTE
GROUP BY column
ORDER BY comp_mb DESC
LIMIT 20;
```

## Deferred high-impact changes

`time_flow_start_ns DateTime64(9)` remains the largest poorly-compressed column.
Reducing time precision to milliseconds (`DateTime64(3)`) is likely the next
large storage win, but it rewrites the table and should wait for a maintenance
window and calmer merge concurrency.

Candidate maintenance-window ALTER:

```sql
ALTER TABLE default.flows_raw
    MODIFY COLUMN time_flow_start_ns DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    MODIFY COLUMN time_received_ns DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    MODIFY COLUMN time_inserted_ns DateTime64(3) CODEC(DoubleDelta, ZSTD(1));
```

The column names retain `_ns` for compatibility; the stored precision would be
milliseconds after this ALTER.
