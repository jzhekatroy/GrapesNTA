# Local Networks And Traffic Direction

This document describes how GrapesNTA decides whether traffic is inbound,
outbound, internal or transit.

## Why This Exists

`flows_raw` contains raw flow rows with `src_addr`, `dst_addr`, bytes and
packets. To build an `In/Out bps` chart we need to know which prefixes are
ours:

```text
src external, dst local     -> in
src local, dst external     -> out
src local, dst local        -> internal
src external, dst external  -> transit
```

Without local prefixes, the UI can still show total traffic, but honest
In/Out requires `local_networks`.

## Architecture Decision: No Dictionary

Earlier drafts of this design assumed an `IP_TRIE` dictionary
`default.local_networks_dict` plugged into `traffic_1m_mv` via `dictHas`.
The deployment turned out to make that impossible without server-side help:

- ClickHouse 24.11 is **remote** and reached only through a SQL proxy
  (`95.215.1.30:6124`). Local host `netflow-test` has no `clickhouse-server`
  installed, no `/etc/clickhouse-server`, just `clickhouse-client 18.16.1`
  and a Docker port-forward to the proxy.
- Through that proxy the existing dictionaries (`bgp_origin_asn_dict`,
  `geo_country_dict`) are visible and `LOADED`, but every variant of
  `CREATE DICTIONARY` / `DROP DICTIONARY` / `CREATE OR REPLACE DICTIONARY`
  is rejected as a syntax error.
- We don't have shell access to the ClickHouse host, so we can't drop an
  XML config into `/etc/clickhouse-server/dictionaries.d/` ourselves.

So the current MVP is **dictionary-less**:

- `default.local_networks` and `default.local_networks_enabled` are still
  loaded by `scripts/load_local_networks_from_asn.py`.
- `default.traffic_1m_mv` writes `direction = 'unknown'` and is therefore
  immune to the dictionary problem.
- `in / out / internal / transit` is computed in API queries by
  JOIN-ing `flows_raw` with `default.local_networks_enabled` and using
  `isIPAddressInRange`. Short windows (1 h default) make this affordable.

The XML template `deploy/clickhouse/local_networks_dict.xml` is kept in the
repo. As soon as someone with shell access to the ClickHouse host installs it
into `/etc/clickhouse-server/dictionaries.d/`, the `traffic_1m_mv` template
at the bottom of `deploy/clickhouse/traffic_1m_mv.sql` can be applied and the
on-the-fly logic switched off.

## Current Local ASN

For the current deployment, `195.2.241.1` resolves through
`bgp_origin_asn_dict` to:

```text
AS34665 PINDC-AS
```

So the first local-network source is all active prefixes in
`default.bgp_prefix_origin_current` where `origin_asn = 34665`, collapsed into
a minimal non-overlapping set.

Observed first load:

```text
raw BGP prefixes: 404
collapsed local_networks: 84
  IPv4: 75
  IPv6: 9
```

## Data Model

DDL: [`deploy/clickhouse/local_networks.sql`](../deploy/clickhouse/local_networks.sql)

- `default.local_networks` - editable local prefix config
  (`ReplacingMergeTree(updated_at)`).
- `default.local_networks_enabled` - deduplicated view of currently enabled
  prefixes, exposing `family, prefix, name, source, updated_at`.

The table is intentionally editable. MoonShine can later manage it directly:

```text
prefix, family, name, source, enabled, updated_at
```

Examples:

```text
195.2.240.0/23   4   PINDC-AS AS34665   bgp_origin_as34665   1
2a07:a300::/29   6   PINDC-AS AS34665   bgp_origin_as34665   1
```

## Loader From ASN

The loader reads active BGP prefixes for one ASN, collapses them using
Python's `ipaddress.collapse_addresses()`, writes them into `local_networks`,
and disables old rows from the same source that disappeared.

Dictionary creation and `SYSTEM RELOAD DICTIONARY` are **off by default**.
They can be enabled with `--with-dictionary` (or `LOCALNETWORKS_WITH_DICTIONARY=1`)
after the dictionary has been installed on the CH host.

Script:

```text
scripts/load_local_networks_from_asn.py
```

Systemd:

```text
deploy/systemd/local-networks-loader.env.example
deploy/systemd/local-networks-loader.service
deploy/systemd/local-networks-loader.timer
```

Install/update:

```bash
cd /root/GrapesNTA && git pull --ff-only origin feature/dnsflowd-mvp

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' \
  --multiquery < deploy/clickhouse/local_networks.sql

sudo mkdir -p /etc/local-networks-loader
sudo cp deploy/systemd/local-networks-loader.env.example \
  /etc/local-networks-loader/local-networks-loader.env
sudo chmod 0600 /etc/local-networks-loader/local-networks-loader.env
sudo editor /etc/local-networks-loader/local-networks-loader.env

sudo install -m 0644 deploy/systemd/local-networks-loader.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/local-networks-loader.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now local-networks-loader.timer
```

Manual run:

```bash
sudo systemctl start local-networks-loader.service
journalctl -u local-networks-loader -n 80 --no-pager
```

Expected log on the first run:

```text
prefixes: raw=404 collapsed=84 disable_old=0 rows_to_insert=84
skipping dictionary management (use --with-dictionary or
LOCALNETWORKS_WITH_DICTIONARY=1 to enable). Direction is computed on the fly
from default.local_networks_enabled.
load_local_networks_from_asn: done
```

## Verifying The Data

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
SELECT family, count() AS prefixes
FROM default.local_networks_enabled
GROUP BY family
ORDER BY family
FORMAT PrettyCompactMonoBlock
"
```

Expected (after the first AS34665 load):

```text
family   prefixes
4        75
6        9
```

## Direction On The Fly: SQL Recipe

The dashboard uses this query as the source for `Traffic In/Out, bps`. It
runs on the **raw** `flows_raw` table for short windows (default 1 hour) and
computes direction by matching both endpoints against
`default.local_networks_enabled`.

```sql
WITH
    (SELECT groupArray(prefix) FROM default.local_networks_enabled WHERE family = 4) AS local_v4,
    (SELECT groupArray(prefix) FROM default.local_networks_enabled WHERE family = 6) AS local_v6
SELECT
    minute,
    multiIf(
        src_is_local AND dst_is_local, 'internal',
        src_is_local AND NOT dst_is_local, 'out',
        NOT src_is_local AND dst_is_local, 'in',
        'transit'
    ) AS direction,
    sum(bytes) * 8 / 60 AS bps,
    sum(packets) / 60   AS pps,
    count()             AS flows
FROM
(
    SELECT
        toStartOfMinute(time_received_ns) AS minute,
        bytes,
        packets,
        multiIf(
            etype = 0x0800,
                arrayExists(
                    p -> isIPAddressInRange(
                        IPv4NumToString(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4))))),
                        p
                    ),
                    local_v4
                ),
            etype = 0x86DD,
                arrayExists(
                    p -> isIPAddressInRange(
                        IPv6NumToString(reinterpretAsIPv6(src_addr)),
                        p
                    ),
                    local_v6
                ),
            0
        ) AS src_is_local,
        multiIf(
            etype = 0x0800,
                arrayExists(
                    p -> isIPAddressInRange(
                        IPv4NumToString(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4))))),
                        p
                    ),
                    local_v4
                ),
            etype = 0x86DD,
                arrayExists(
                    p -> isIPAddressInRange(
                        IPv6NumToString(reinterpretAsIPv6(dst_addr)),
                        p
                    ),
                    local_v6
                ),
            0
        ) AS dst_is_local
    FROM default.flows_raw
    WHERE time_received_ns >= now() - INTERVAL 1 HOUR
)
GROUP BY minute, direction
ORDER BY minute
SETTINGS
    max_memory_usage = 4000000000,
    max_bytes_before_external_group_by = 2000000000,
    max_threads = 4;
```

Notes:

- The two `WITH (SELECT ...) AS name` scalar subqueries each evaluate to a
  single array of prefixes (75 IPv4 and 9 IPv6 for AS34665) and are computed
  once per query, not per row. Avoid the `WITH name AS (SELECT ...)` CTE
  form here — the proxy in front of the production ClickHouse rejects it
  with a parser error.
- For the empty-`local_networks` case all four checks evaluate to 0, so every
  row ends up as `'transit'`. The UI rule below converts that into
  outbound/total until real local prefixes are loaded.
- For longer windows (24 h, 7 d) prefer one of:
  - the same query with a larger `WHERE time_received_ns >= now() - INTERVAL 1 DAY`
    and a coarser bucket, e.g. `toStartOfFiveMinute`;
  - a future direction-aware `traffic_1m_mv` once the dictionary is available.

## UI Rule

For the first `Traffic In/Out, bps` dashboard:

```text
in_bps  = bps where direction = 'in'
out_bps = bps where direction IN ('out', 'transit', 'unknown')
```

This preserves the MVP rule: when local networks are not configured or do not
match a flow, traffic is shown as outbound/total rather than disappearing
from the chart.

## Future: Switch Back To dictHas

When someone with shell access to the ClickHouse host can install the XML
dictionary:

```bash
sudo install -m 0640 -o root -g clickhouse \
  /root/GrapesNTA/deploy/clickhouse/local_networks_dict.xml \
  /etc/clickhouse-server/dictionaries.d/local_networks_dict.xml

# adjust the develop password in the file to match the other dictionaries
sudo editor /etc/clickhouse-server/dictionaries.d/local_networks_dict.xml

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
SYSTEM RELOAD DICTIONARY default.local_networks_dict
"

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
SELECT name, status, source, last_exception
FROM system.dictionaries
WHERE name = 'local_networks_dict'
FORMAT PrettyCompactMonoBlock
"
```

Then redeploy `traffic_1m_mv` using the commented template at the bottom of
`deploy/clickhouse/traffic_1m_mv.sql`, set `LOCALNETWORKS_WITH_DICTIONARY=1`
in the loader environment file and the API can switch from the on-the-fly
query above to a plain aggregate on `traffic_1m`.
