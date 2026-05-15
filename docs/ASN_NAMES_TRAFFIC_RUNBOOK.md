# ASN Names And Traffic Runbook

This runbook documents the ASN name enrichment and Top ASN traffic flow added
on 2026-05-15.

## Goal

Traffic records in `default.flows_raw` contain IP addresses, not organization
names. BMP route events give us the current `prefix -> origin_asn` view, and
RIR delegated files give us ASN allocation metadata. The remaining missing
piece was human-readable ASN names.

The resulting data path is:

```text
RIR delegated files
  -> scripts/load_rir_geo.py
  -> default.asn_registry

Team Cymru bulk whois
  -> scripts/load_asn_names.py
  -> default.asn_names

BMP route events
  -> scripts/rebuild_bgp_origin_asn.py
  -> default.bgp_origin_asn_dict

flows_raw.dst_addr / src_addr
  -> bgp_origin_asn_dict
  -> origin_asn
  -> asn_registry_enriched
  -> ASN name / country / RIR
```

## Implemented Pieces

- `scripts/load_asn_names.py` reads distinct ASN from `default.asn_registry`,
  queries Team Cymru bulk whois (`whois.cymru.com:43`) in chunks, and writes
  names into `default.asn_names`.
- `deploy/systemd/asn-names-loader.service` runs the loader as a one-shot unit.
- `deploy/systemd/asn-names-loader.timer` runs it weekly with a randomized
  delay.
- `deploy/systemd/asn-names-loader.env.example` documents connection, Cymru,
  retry and insert-batch settings.
- `docs/geoip_country.md` documents how ASN registry, ASN names and
  `asn_registry_enriched` fit together.
- `docs/BGP_ORIGIN_ASN_TRAFFIC.md` contains traffic queries that use
  `bgp_origin_asn_dict`.

## Tables

- `default.asn_registry` - ASN allocation metadata from RIR delegated files:
  ASN, country, RIR, allocation date and status.
- `default.asn_names` - human-readable ASN names. It is a
  `ReplacingMergeTree(updated_at)`, so new runs can overwrite stale names
  without truncating the table.
- `default.asn_registry_enriched` - view joining `asn_registry` with latest
  names from `asn_names`; falls back to `AS<asn>` when no name is known.
- `default.bgp_prefix_origin_current` - current active BGP prefix to origin ASN
  mapping rebuilt from BMP events.
- `default.bgp_origin_asn_dict` - `IP_TRIE` dictionary used for fast
  `IP -> origin_asn` lookup in traffic queries.

## ASN Names Loader

Install/update on the server:

```bash
cd /root/GrapesNTA && git pull --ff-only origin feature/dnsflowd-mvp

sudo mkdir -p /etc/asn-names-loader
sudo cp deploy/systemd/asn-names-loader.env.example /etc/asn-names-loader/asn-names-loader.env
sudo chmod 0600 /etc/asn-names-loader/asn-names-loader.env

sudo install -m 0644 deploy/systemd/asn-names-loader.service /etc/systemd/system/asn-names-loader.service
sudo install -m 0644 deploy/systemd/asn-names-loader.timer /etc/systemd/system/asn-names-loader.timer
sudo systemctl daemon-reload
sudo systemctl enable --now asn-names-loader.timer
```

Run manually with progress:

```bash
sudo sed -i 's/^# ASNNAMES_PROGRESS=1/ASNNAMES_PROGRESS=1/' /etc/asn-names-loader/asn-names-loader.env
sudo systemctl start asn-names-loader.service
journalctl -u asn-names-loader -f --since "1 minute ago"
```

`journalctl -f` follows the log and keeps waiting after the service finishes.
When the log shows `load_asn_names: done` and `Deactivated successfully`, the
run is complete and `Ctrl+C` is safe.

## Connection Resolution

The loader resolves ClickHouse connection settings as one coherent tuple:

1. `ASNNAMES_CH_*` from `/etc/asn-names-loader/asn-names-loader.env`;
2. `GEOLOADERD_CH_*` from `/etc/geoloaderd/geoloaderd.env`;
3. built-in defaults: `localhost:9000`, user `default`, empty password.

Do not set only one of `ASNNAMES_CH_USER` / `ASNNAMES_CH_PASSWORD`. If
overriding the connection, uncomment and set all five values together:

```bash
ASNNAMES_CH_HOST=...
ASNNAMES_CH_PORT=...
ASNNAMES_CH_USER=...
ASNNAMES_CH_PASSWORD=...
ASNNAMES_CH_DATABASE=default
```

On the current deployment the local ClickHouse `default` user has a password
and `develop` is configured for the external endpoint. Leaving `ASNNAMES_CH_*`
commented lets systemd inherit the working `GEOLOADERD_CH_*` tuple.

## Memory Pressure Handling

The first full run parsed about 116k ASN names. A single large INSERT was
stopped by ClickHouse OvercommitTracker with Code 241
`MEMORY_LIMIT_EXCEEDED` while the server was globally memory-pressured.

The loader now:

- splits INSERTs into `ASNNAMES_INSERT_BATCH_SIZE` batches (default `10000`);
- retries transient errors (`MEMORY_LIMIT_EXCEEDED`, `TOO_MANY_PARTS`) using
  `ASNNAMES_RETRY_ATTEMPTS` and `ASNNAMES_RETRY_DELAY`;
- caps each INSERT with `SETTINGS max_memory_usage`, `max_insert_threads = 1`
  and `max_threads = 2`;
- treats `OPTIMIZE TABLE ... FINAL` as best-effort and allows disabling it with
  `ASNNAMES_SKIP_OPTIMIZE=1`.

Expected successful log shape:

```text
asns to lookup: 121267
cymru chunk 1/25 size=5000 ...
...
parsed rows: 116295
insert batch 1/12 rows=10000 bytes=...
...
INSERT batch 5/12: retryable error attempt 1/6, sleeping 30s (...)
...
inserted rows: 116295
load_asn_names: done
asn-names-loader.service: Deactivated successfully.
```

## Validation

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
SELECT
    count(),
    uniqExact(asn),
    toString(max(updated_at)) AS last_update
FROM default.asn_names FINAL
"

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
SELECT asn, name
FROM default.asn_registry_enriched
WHERE asn IN (13335, 15169, 16509, 13238, 50509, 44050, 2519, 138421, 23969)
ORDER BY asn
"
```

## Top Destination ASN By Traffic

Important: aggregate to top ASN first, then join names. Joining
`asn_registry_enriched` before aggregation applies the join to every raw flow
and can be killed by ClickHouse OvercommitTracker at `JoiningTransform`.

This query uses a 15-minute window by default. Increase the window only after
confirming the server is not memory-pressured.

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
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
    join_algorithm = 'parallel_hash'
FORMAT PrettyCompactMonoBlock
"
```

For source ASN, replace `dst_addr` with `src_addr`.

## Example Result

The first successful top-20 destination ASN query showed:

- `AS50509 TRANSROUTE` dominating the selected window with about `1002 GiB`;
- `AS44068 ARBITAL-AS` around `142 GiB`;
- `AS34665 PINDC-AS` around `59 GiB`;
- well-known external ASNs such as Amazon, Hetzner, Google, OVH and Apple now
  displayed with names.

Interpretation notes:

- ASN country is allocation/registration country from RIR data, not necessarily
  traffic geolocation. Use `geo_country_dict` for heatmaps by IP country.
- Low flow count with high traffic usually means long-lived or high-throughput
  flows. Dashboard tables should show bytes, packets and flows together.

## Next Step For Dashboard

The raw-query approach is useful for diagnostics, but web dashboards should not
scan `flows_raw` every time. The next planned table is a minute aggregate such
as `default.traffic_asn_1m` with:

```text
minute, direction, asn, bytes, packets, flows_count
```

Then Laravel/MoonShine can render Top ASN charts from minute aggregates instead
of scanning raw flow rows.
