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

## Current Architecture: Collector Classifier

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

So the current MVP is **dictionary-less** and **collector-classified**:

- `default.local_networks` and `default.local_networks_enabled` are still
  loaded by `scripts/load_local_networks_from_asn.py`.
- `default.local_asns` and `default.local_networks` define IP/ASN endpoint
  ownership (`local`, `customer`, `remote`).
- `default.vlan_map` defines VLAN attachment context (`customer`, `uplink`,
  `core`, ... plus `internal`/`external` boundary). VLAN no longer decides IP
  ownership directly.
- `xdpflowd` reads BGP/local/VLAN data into memory and writes `src_asn`,
  `dst_asn`, attachment fields, endpoint fields, `direction`, labels and
  operators directly into `flows_raw`.
- `traffic_1m_mv`, `traffic_direction_1m_mv`, `traffic_uplink_1m_mv` and
  `traffic_customer_1m_mv` only aggregate precomputed fields.

Direction now comes from endpoint scope:

```text
local/customer -> remote          = out
remote -> local/customer          = in
local/customer -> local/customer  = internal
remote -> remote                  = transit
```

Endpoint scope is decided by `local ASN > local prefix > fallback remote`.
VLAN fills only `src_attachment_*` / `dst_attachment_*`. If no local ASN or
local prefix is configured, `xdpflowd` uses the MVP fallback and writes
`direction = 'out'`.

The XML template `deploy/clickhouse/local_networks_dict.xml` is kept in the
repo for future server-side experiments, but dashboard direction must not rely
on raw-table dictionary lookups.

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
- `default.local_asns` - editable list of ASNs considered local for dashboard
  direction. The loader inserts the source ASN automatically, and MoonShine can
  enable additional downstream/customer ASNs.
- `default.local_asns_enabled` - deduplicated view of currently enabled local
  ASNs, exposing `asn, name, source, updated_at`.

The table is intentionally editable. MoonShine can later manage it directly:

```text
prefix, family, name, source, enabled, updated_at
```

Examples:

```text
195.2.240.0/23   4   PINDC-AS AS34665   bgp_origin_as34665   1
2a07:a300::/29   6   PINDC-AS AS34665   bgp_origin_as34665   1
```

```text
34665   PINDC-AS AS34665   bgp_origin_as34665   1
50509   TRANSROUTE         manual_customer_asn   1
44068   ARBITAL-AS         manual_customer_asn   1
```

## Loader From ASN

The loader reads active BGP prefixes for one ASN, collapses them using
Python's `ipaddress.collapse_addresses()`, writes them into `local_networks`,
disables old rows from the same source that disappeared, and writes the same
ASN into `local_asns` as enabled.

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
local_asn: AS34665 enabled in default.local_asns
skipping dictionary management (use --with-dictionary or
LOCALNETWORKS_WITH_DICTIONARY=1 to enable). Direction is computed on the fly
from local_asns_enabled and local_networks_enabled.
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

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
SELECT asn, name, source
FROM default.local_asns_enabled
ORDER BY asn
FORMAT PrettyCompactMonoBlock
"
```

## Deprecated: Direction On The Fly SQL Recipe

The dashboard must not use this raw-flow query in production. It is useful only
for diagnostics and short manual checks. A 15-minute raw query can already hit
memory limits on the production flow volume.

For the Laravel dashboard, use
[`docs/LARAVEL_MOONSHINE_TRAFFIC_IN_OUT.md`](LARAVEL_MOONSHINE_TRAFFIC_IN_OUT.md)
and read chart series from `default.traffic_chart_1m` (fallback:
`default.traffic_direction_1m`).

The raw diagnostic query computes direction with a hybrid approach:

- **IPv4** flows use `dictGetUInt32('default.bgp_origin_asn_dict', 'origin_asn', ip)`.
  An IPv4 is local when its BGP origin ASN is present in
  `default.local_asns_enabled`. This is O(1) per row and reuses the
  already-loaded BGP dictionary.
- **IPv6** flows use `arrayExists` against the small IPv6 prefix list from
  `default.local_networks_enabled` (9 prefixes for AS34665, IPv6 traffic is
  usually a small fraction of total volume).

This avoids the OOM we hit when matching all flows against 75 IPv4 prefixes
with `isIPAddressInRange` on every row.

```sql
WITH
    (SELECT groupArray(asn) FROM default.local_asns_enabled) AS local_asns,
    length(local_asns) AS local_asns_count,
    (SELECT groupArray(prefix) FROM default.local_networks_enabled WHERE family = 6) AS local_v6
SELECT
    minute,
    multiIf(
        local_asns_count = 0, 'out',
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
                has(
                    local_asns,
                    dictGetUInt32(
                        'default.bgp_origin_asn_dict', 'origin_asn',
                        tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))
                    )
                ),
            etype = 0x86DD,
                arrayExists(p -> isIPAddressInRange(IPv6NumToString(src_addr), p), local_v6),
            0
        ) AS src_is_local,
        multiIf(
            etype = 0x0800,
                has(
                    local_asns,
                    dictGetUInt32(
                        'default.bgp_origin_asn_dict', 'origin_asn',
                        tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
                    )
                ),
            etype = 0x86DD,
                arrayExists(p -> isIPAddressInRange(IPv6NumToString(dst_addr), p), local_v6),
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

- `WITH (SELECT ...) AS name` is a scalar-subquery CTE and is computed once
  per query. Avoid the `WITH name AS (SELECT ...)` CTE form here — the
  proxy in front of the production ClickHouse rejects it with a parser
  error.
- `local_asns` comes from `default.local_asns_enabled`, so adding customer or
  downstream ASNs in MoonShine changes dashboard direction without code
  changes.
- When `local_asns_enabled` is empty, `local_asns_count = 0` forces every row
  to `out`, preserving the MVP fallback rule.
- `dictGetUInt32` returns 0 when an IP has no BGP origin in the dictionary
  (unrouted / IXP prefixes, RFC1918, link-local). Those flows then end up
  as `'transit'`, which is the desired MVP behaviour.
- For IPv4 prefixes that are NOT covered by our BGP origin (e.g. private
  RFC1918 addresses you want to count as local), add them to
  `default.local_networks` for IPv4 too and switch the IPv4 branch to a
  `dictHas` lookup once `default.local_networks_dict` is installed.
- For dashboards, prefer `default.traffic_direction_1m` and related
  collector-built aggregates.

## Deprecated: ASN Pair Aggregate

DDL:

```text
deploy/clickhouse/traffic_asn_pair_1m.sql
```

Apply:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' \
  --multiquery < deploy/clickhouse/traffic_asn_pair_1m.sql
```

Objects:

```text
default.traffic_asn_pair_1m
default.traffic_asn_pair_1m_mv
```

Schema:

```text
minute, src_asn, dst_asn, bytes, packets, flows_count
```

This table is intentionally not direction-specific. Direction is derived while
reading:

```text
src_asn local, dst_asn external -> out
src_asn external, dst_asn local -> in
src_asn local, dst_asn local    -> internal
otherwise                       -> transit
```

This lets operators change `local_asns_enabled` without rebuilding history.
The trade-off is that this MVP aggregate only covers IPv4 ASN-based direction.
Operators without ASNs need prefix-based classification through
`local_networks_dict` or collector-side prefix matching.

## UI Rule

For the first `Traffic In/Out, bps` dashboard:

```text
in_bps  = bps where direction = 'in'
out_bps = bps where direction = 'out'
transit_bps = bps where direction = 'transit'   # optional third line
```

If `local_asns_enabled` is empty, the API should return all traffic as
`out_bps`/total to preserve the MVP rule: an unconfigured dashboard should not
look empty. Once at least one local ASN is configured, `transit` should be kept
separate instead of silently folding it into `out`, because real data showed a
large amount of true transit/customer traffic through `AS50509 TRANSROUTE`.

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
