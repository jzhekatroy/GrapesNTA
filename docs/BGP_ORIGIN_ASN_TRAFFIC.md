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

IPv4 destination traffic:

```sql
SELECT
    asn,
    any(a.name) AS as_name,
    any(a.cc) AS country,
    any(a.rir) AS rir,
    formatReadableSize(sum(bytes)) AS traffic,
    sum(bytes) AS bytes_total,
    sum(packets) AS packets_total,
    count() AS flows
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
    WHERE time_received_ns >= now() - INTERVAL 1 HOUR
      AND etype = 0x0800
) AS f
LEFT JOIN default.asn_registry_enriched AS a ON f.asn = a.asn
WHERE asn != 0
GROUP BY asn
ORDER BY bytes_total DESC
LIMIT 20;
```

For source ASN, replace `dst_addr` with `src_addr`.

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
