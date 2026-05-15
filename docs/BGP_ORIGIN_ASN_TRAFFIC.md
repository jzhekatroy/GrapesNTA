# BGP Origin ASN Traffic Enrichment

This adds a fast `IP -> origin_asn` lookup built from `bmpgrapes` route events.
It is used to answer traffic questions such as:

```text
Which ASN / organization receives the most traffic?
```

## Data Flow

```text
bmp_route_events
  -> rebuild_bgp_origin_asn.py
  -> bgp_prefix_origin_current
  -> bgp_origin_asn_dict (IP_TRIE)

flows_raw.dst_addr
  -> bgp_origin_asn_dict
  -> origin_asn
  -> asn_registry_enriched
  -> name / country / RIR
```

## Tables And Dictionary

DDL: [`deploy/clickhouse/bgp_origin_asn.sql`](../deploy/clickhouse/bgp_origin_asn.sql)

- `default.bgp_prefix_origin_current` - current active prefix -> origin ASN.
- `default.bgp_prefix_origin_current_staging` - staging table used by refresh.
- `default.bgp_origin_asn_dict` - `IP_TRIE` dictionary created by the refresh script.

The refresh script reads the latest event per `(router, peer, prefix)`. A
withdraw only removes that peer's active path; another peer's active announce can
keep the prefix in the dictionary.

## One-Time Setup

```bash
clickhouse-client \
  --host 95.215.1.30 --port 6124 \
  --user develop --password 'PASSWORD' \
  --database default \
  --multiquery < deploy/clickhouse/bgp_origin_asn.sql
```

Create `/etc/bgp-origin-refresh/bgp-origin-refresh.env`:

```bash
sudo install -d /etc/bgp-origin-refresh
sudo install -m 0600 deploy/systemd/bgp-origin-refresh.env.example /etc/bgp-origin-refresh/bgp-origin-refresh.env
sudo editor /etc/bgp-origin-refresh/bgp-origin-refresh.env
```

Important: `BGPORIGIN_CH_*` is how the loader connects to ClickHouse. 
`BGPORIGIN_DICT_SOURCE_*` is how ClickHouse itself reads
`bgp_prefix_origin_current` for the dictionary. In the current deployment this
usually means:

```bash
BGPORIGIN_CH_HOST=95.215.1.30
BGPORIGIN_CH_PORT=6124

BGPORIGIN_DICT_SOURCE_HOST=127.0.0.1
BGPORIGIN_DICT_SOURCE_PORT=9000
```

because `127.0.0.1:9000` is evaluated from the ClickHouse server/container, not
from the loader host.

## Manual Refresh

```bash
set -a
source /etc/bgp-origin-refresh/bgp-origin-refresh.env
set +a

sudo -E /usr/bin/python3 scripts/rebuild_bgp_origin_asn.py
```

Expected output:

```text
rebuild_bgp_origin_asn: done rows=...
```

## Validate

```sql
SELECT count(), uniqExact(origin_asn)
FROM default.bgp_prefix_origin_current;

SELECT
    name,
    status,
    last_exception
FROM system.dictionaries
WHERE database = 'default' AND name = 'bgp_origin_asn_dict'
FORMAT Vertical;

SELECT dictGetUInt32(
    'default.bgp_origin_asn_dict',
    'origin_asn',
    tuple(toIPv4('8.8.8.8'))
);
```

## Top Destination ASN By Traffic

IPv4 destination traffic. Aggregate to top ASN first, then join names; joining
`asn_registry_enriched` before aggregation applies the JOIN to every raw flow
and can be killed by ClickHouse OvercommitTracker during `JoiningTransform`.

```sql
WITH topn AS
(
    SELECT
        asn,
        sum(bytes)   AS bytes_total,
        sum(packets) AS packets_total,
        count()      AS flows
    FROM
    (
        SELECT
            dictGetUInt32(
                'default.bgp_origin_asn_dict',
                'origin_asn',
                tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
            ) AS asn,
            bytes,
            packets
        FROM default.flows_raw
        WHERE time_received_ns >= now() - INTERVAL 15 MINUTE
          AND etype = 0x0800
    )
    WHERE asn != 0
    GROUP BY asn
    ORDER BY bytes_total DESC
    LIMIT 20
)
SELECT
    t.asn,
    e.name AS as_name,
    e.cc   AS country,
    e.rir  AS rir,
    formatReadableSize(t.bytes_total) AS traffic,
    t.bytes_total,
    t.packets_total,
    t.flows
FROM topn AS t
LEFT JOIN default.asn_registry_enriched AS e ON e.asn = t.asn
ORDER BY t.bytes_total DESC
SETTINGS
    max_memory_usage = 4000000000,
    max_bytes_before_external_group_by = 2000000000,
    max_threads = 4,
    join_algorithm = 'parallel_hash';
```

For source ASN, replace `dst_addr` with `src_addr`. For longer windows, prefer
a minute aggregate table (for example `traffic_asn_1m`) instead of repeatedly
scanning `flows_raw`.

## systemd

```bash
sudo ln -sfn /root/GrapesNTA /opt/GrapesNTA
sudo install -m 0644 deploy/systemd/bgp-origin-refresh.service /etc/systemd/system/bgp-origin-refresh.service
sudo install -m 0644 deploy/systemd/bgp-origin-refresh.timer /etc/systemd/system/bgp-origin-refresh.timer
sudo systemctl daemon-reload
sudo systemctl enable --now bgp-origin-refresh.timer
sudo systemctl start bgp-origin-refresh.service
journalctl -u bgp-origin-refresh.service -f
```
