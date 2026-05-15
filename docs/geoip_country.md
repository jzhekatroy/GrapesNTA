# Country geolocation from RIR delegated data

This adds **country-only** IP lookup and **ASN allocation metadata** using public
RIR `delegated-*-extended-latest` statistics. It does **not** provide city
accuracy and RIR delegated files do **not** include human-readable ASN
organization names.

IP country is resolved at query time via `dictGet*` (or pre-aggregated tables
you build yourself). It is **not** written into `flows_raw`.

ASN allocation metadata is loaded into `default.asn_registry` and can be joined
with BGP `origin_asn`. Optional names live in `default.asn_names`, so daily RIR
refreshes do not overwrite manual or separately loaded organization names.

## Components

| Path | Purpose |
|------|---------|
| [deploy/clickhouse/geo_country.sql](deploy/clickhouse/geo_country.sql) | `geo_prefix_country`, `asn_registry`, `asn_names` + staging table DDL |
| [scripts/load_rir_geo.py](scripts/load_rir_geo.py) | Downloads RIR files, parses prefixes and ASN allocations, loads staging, swaps tables, creates/updates `geo_country_dict`, reloads dictionary |
| [deploy/systemd/geoloaderd.*](deploy/systemd/) | `systemd` oneshot + daily timer |

## One-time ClickHouse setup

On the ClickHouse server (or via client):

```bash
clickhouse-client --multiquery < deploy/clickhouse/geo_country.sql
```

This creates the tables only. The loader creates/updates `default.geo_country_dict`
because dictionary source credentials often differ from the credentials used by
the remote loader. ASN names are kept in `default.asn_names`; RIR refresh only
updates allocation metadata in `default.asn_registry`.

Confirm:

```sql
SHOW TABLES FROM default LIKE 'geo_prefix_country%';
SHOW TABLES FROM default LIKE 'asn_%';
```

## Dependencies

- **Python 3.7+** (stdlib only; no pip / venv required)
- **`clickhouse-client`** installed where the loader runs (same host as the unit or with network access to ClickHouse native port)
- Outbound **HTTPS** to RIR mirrors (unless `--skip-download` and a populated cache)

## Manual run

```bash
sudo mkdir -p /var/lib/geoloaderd/cache
python3 scripts/load_rir_geo.py \
  --host 127.0.0.1 --port 9000 --user default --password '' \
  --database default \
  --cache-dir /var/lib/geoloaderd/cache
```

Environment variables (optional; same names as used by systemd):

| Variable | Meaning |
|----------|---------|
| `GEOLOADERD_CLICKHOUSE_CLIENT` | Path to `clickhouse-client` (default `/usr/bin/clickhouse-client`) |
| `GEOLOADERD_CH_HOST` | ClickHouse host |
| `GEOLOADERD_CH_PORT` | Native port (default `9000`) |
| `GEOLOADERD_CH_USER` | User |
| `GEOLOADERD_CH_PASSWORD` | Password (omit or empty for none) |
| `GEOLOADERD_CH_DATABASE` | Database (`--database`) |
| `GEOLOADERD_CACHE_DIR` | RIR file cache |
| `GEOLOADERD_CH_TABLE` | Live prefix table (default `default.geo_prefix_country`) |
| `GEOLOADERD_CH_STAGING` | Staging table |
| `GEOLOADERD_CH_ASN_TABLE` | Live ASN allocation table (default `default.asn_registry`) |
| `GEOLOADERD_CH_ASN_STAGING` | ASN staging table |
| `GEOLOADERD_CH_DICT` | Dictionary to reload |
| `GEOLOADERD_DICT_SOURCE_HOST` | Host used by the ClickHouse server itself to read `geo_prefix_country` |
| `GEOLOADERD_DICT_SOURCE_PORT` | Port used by the ClickHouse server itself |
| `GEOLOADERD_DICT_SOURCE_USER` | User used by dictionary source reads |
| `GEOLOADERD_DICT_SOURCE_PASSWORD` | Password used by dictionary source reads |
| `GEOLOADERD_DICT_SOURCE_DATABASE` | Source database |
| `GEOLOADERD_DICT_SOURCE_TABLE` | Source table name without database (`geo_prefix_country`) |

CLI flags (see `python3 scripts/load_rir_geo.py --help`):

| Flag | Default | Meaning |
|------|---------|---------|
| `--clickhouse-client` | `/usr/bin/clickhouse-client` | `clickhouse-client` binary |
| `--host` | `localhost` | Server host |
| `--port` | `9000` | Native protocol port |
| `--user` | `default` | User |
| `--password` | env / empty | Password |
| `--database` | `default` | Database |
| `--table` | `default.geo_prefix_country` | Live table |
| `--staging-table` | `default.geo_prefix_country_staging` | Staging |
| `--asn-table` | `default.asn_registry` | Live ASN allocation table |
| `--asn-staging-table` | `default.asn_registry_staging` | ASN staging |
| `--dictionary` | `default.geo_country_dict` | Dictionary |
| `--dictionary-source-host` | `GEOLOADERD_DICT_SOURCE_HOST` or `--host` | Dictionary source host, from ClickHouse server perspective |
| `--dictionary-source-port` | `GEOLOADERD_DICT_SOURCE_PORT` or `--port` | Dictionary source port |
| `--dictionary-source-user` | `GEOLOADERD_DICT_SOURCE_USER` or `--user` | Dictionary source user |
| `--dictionary-source-password` | env / empty | Dictionary source password |
| `--dictionary-source-database` | `default` | Dictionary source database |
| `--dictionary-source-table` | `geo_prefix_country` | Dictionary source table |
| `--skip-dictionary-create` | off | Reload an already-created dictionary without recreating it |
| `--cache-dir` | `/var/lib/geoloaderd/cache` | Cache directory |
| `--skip-download` | off | Use existing cache only |
| `--keep-tsv` | off | Keep temporary TSV on disk |
| `--http-timeout` | `120` | Per-URL download timeout (seconds) |
| `--min-countries` | `8` | Validation: minimum distinct ISO codes |
| `--no-ru-check` | off | Allow runs without `RU` rows (subset tests) |

The loader **refuses** to proceed if validation fails (e.g. no rows, too few countries, or no `RU` prefixes when using the full default RIR sources).

Table swap uses `EXCHANGE TABLES` when supported; otherwise it falls back to a three-step `RENAME TABLE` sequence. Errors from `clickhouse-client` print the failing query text **without** echoing the password.

## How the dictionary connection works

There are two separate ClickHouse connections:

```text
loader host -> GEOLOADERD_CH_HOST:GEOLOADERD_CH_PORT -> INSERT / EXCHANGE / CREATE DICTIONARY
ClickHouse server -> GEOLOADERD_DICT_SOURCE_HOST:GEOLOADERD_DICT_SOURCE_PORT -> read geo_prefix_country for IP_TRIE
```

If the loader connects through an external address or proxy, for example
`95.215.1.30:6124`, do **not** blindly reuse that address for the dictionary
source. During `dictGetString(...)`, the ClickHouse server opens the dictionary
source connection itself. In many deployments the correct source is the
ClickHouse server's internal endpoint, for example:

```bash
GEOLOADERD_CH_HOST=95.215.1.30
GEOLOADERD_CH_PORT=6124
GEOLOADERD_CH_USER=develop
GEOLOADERD_CH_PASSWORD=plain-password-not-url-encoded

GEOLOADERD_DICT_SOURCE_HOST=127.0.0.1
GEOLOADERD_DICT_SOURCE_PORT=9000
GEOLOADERD_DICT_SOURCE_USER=develop
GEOLOADERD_DICT_SOURCE_PASSWORD=plain-password-not-url-encoded
```

If `dictGetString(...)` returns `ALL_CONNECTION_TRIES_FAILED`, the dictionary
source host/port is not reachable from the ClickHouse server. If it returns
`AUTHENTICATION_FAILED`, the dictionary source user/password is wrong for that
internal endpoint.

## systemd deployment

1. Copy [deploy/systemd/geoloaderd.env.example](deploy/systemd/geoloaderd.env.example) to `/etc/geoloaderd/geoloaderd.env` and set `GEOLOADERD_CH_HOST`, credentials, and paths.
2. Install script and systemd files (adjust `/opt/GrapesNTA` if needed):

   ```bash
   sudo install -d /opt/GrapesNTA/scripts
   sudo install -m 0755 scripts/load_rir_geo.py /opt/GrapesNTA/scripts/load_rir_geo.py
   sudo install -m 0644 deploy/systemd/geoloaderd.service /etc/systemd/system/geoloaderd.service
   sudo install -m 0644 deploy/systemd/geoloaderd.timer /etc/systemd/system/geoloaderd.timer
   ```

3. Enable the timer:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now geoloaderd.timer
   sudo systemctl start geoloaderd.service   # optional immediate run
   journalctl -u geoloaderd.service -f
   ```

The service runs:

`ExecStart=/usr/bin/python3 /opt/GrapesNTA/scripts/load_rir_geo.py`

with environment from `/etc/geoloaderd/geoloaderd.env`.

## Full deployment runbook

1. Fetch the branch:

   ```bash
   cd /root/GrapesNTA
   git fetch origin
   git checkout feature/dnsflowd-mvp
   git pull --ff-only
   ```

2. Create `/etc/geoloaderd/geoloaderd.env`:

   ```bash
   sudo install -d /etc/geoloaderd
   sudo install -m 0600 deploy/systemd/geoloaderd.env.example /etc/geoloaderd/geoloaderd.env
   sudo editor /etc/geoloaderd/geoloaderd.env
   ```

   Use the externally reachable ClickHouse endpoint for `GEOLOADERD_CH_*`.
   Use the endpoint reachable from the ClickHouse server itself for
   `GEOLOADERD_DICT_SOURCE_*`.

3. Create tables:

   ```bash
   set -a
   source /etc/geoloaderd/geoloaderd.env
   set +a

   clickhouse-client \
     --host "$GEOLOADERD_CH_HOST" \
     --port "$GEOLOADERD_CH_PORT" \
     --user "$GEOLOADERD_CH_USER" \
     --password "$GEOLOADERD_CH_PASSWORD" \
     --database "$GEOLOADERD_CH_DATABASE" \
     --multiquery < deploy/clickhouse/geo_country.sql
   ```

4. Load data and create/reload dictionary:

   ```bash
   sudo mkdir -p /var/lib/geoloaderd/cache

   set -a
   source /etc/geoloaderd/geoloaderd.env
   set +a

   sudo -E /usr/bin/python3 scripts/load_rir_geo.py
   ```

5. Validate:

   ```bash
   clickhouse-client \
     --host "$GEOLOADERD_CH_HOST" \
     --port "$GEOLOADERD_CH_PORT" \
     --user "$GEOLOADERD_CH_USER" \
     --password "$GEOLOADERD_CH_PASSWORD" \
     --database "$GEOLOADERD_CH_DATABASE" \
     --query "SELECT count(), uniqExact(cc) FROM default.geo_prefix_country"

   clickhouse-client \
     --host "$GEOLOADERD_CH_HOST" \
     --port "$GEOLOADERD_CH_PORT" \
     --user "$GEOLOADERD_CH_USER" \
     --password "$GEOLOADERD_CH_PASSWORD" \
     --database "$GEOLOADERD_CH_DATABASE" \
     --query "SELECT count(), uniqExact(cc), min(asn), max(asn) FROM default.asn_registry"

   clickhouse-client \
     --host "$GEOLOADERD_CH_HOST" \
     --port "$GEOLOADERD_CH_PORT" \
     --user "$GEOLOADERD_CH_USER" \
     --password "$GEOLOADERD_CH_PASSWORD" \
     --database "$GEOLOADERD_CH_DATABASE" \
     --query "SELECT dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4('8.8.8.8')))"
   ```

   `8.8.8.8` should normally return `US`.

6. Enable daily refresh:

   ```bash
   sudo ln -sfn /root/GrapesNTA /opt/GrapesNTA
   sudo install -m 0644 deploy/systemd/geoloaderd.service /etc/systemd/system/geoloaderd.service
   sudo install -m 0644 deploy/systemd/geoloaderd.timer /etc/systemd/system/geoloaderd.timer
   sudo systemctl daemon-reload
   sudo systemctl enable --now geoloaderd.timer
   sudo systemctl start geoloaderd.service
   journalctl -u geoloaderd.service -f
   ```

## Validation queries

```sql
SELECT count(), uniqExact(cc) FROM default.geo_prefix_country;
SELECT count(), uniqExact(cc), min(asn), max(asn) FROM default.asn_registry;

SELECT cc, count()
FROM default.geo_prefix_country
GROUP BY cc
ORDER BY count() DESC
LIMIT 20;

SELECT dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4('8.8.8.8')));
SELECT dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4('77.88.8.8')));
```

## ASN Registry For BGP

RIR delegated files include ASN allocation country/RIR/status, but not company
names. The loader refreshes:

- `default.asn_registry` - authoritative daily allocation data from RIR FTP;
- `default.asn_names` - optional editable/enrichment table with human-readable names;
- `default.asn_registry_enriched` - view that joins both and falls back to `AS<asn>`
  when no name is known.

Manual name example:

```sql
INSERT INTO default.asn_names (asn, name, source)
VALUES
    (16509, 'Amazon.com, Inc.', 'manual'),
    (13335, 'Cloudflare, Inc.', 'manual'),
    (15169, 'Google LLC', 'manual');
```

### Automated ASN Names Loader (Team Cymru)

For bulk population there is `scripts/load_asn_names.py`. It reads the distinct
ASN list from `default.asn_registry`, queries Team Cymru bulk whois
(`whois.cymru.com:43`, public, no auth) in chunks and inserts the parsed names
into `default.asn_names` with `source = 'team_cymru'`. Manual rows
(`source = 'manual'`) stay authoritative if their `updated_at` is more recent —
`asn_registry_enriched` picks the latest name per ASN via `argMax(name, updated_at)`.

Layout:

| File | Purpose |
|---|---|
| [scripts/load_asn_names.py](../scripts/load_asn_names.py) | The loader (Python stdlib only) |
| [deploy/systemd/asn-names-loader.service](../deploy/systemd/asn-names-loader.service) | One-shot unit |
| [deploy/systemd/asn-names-loader.timer](../deploy/systemd/asn-names-loader.timer) | Weekly run, random 2h jitter |
| [deploy/systemd/asn-names-loader.env.example](../deploy/systemd/asn-names-loader.env.example) | Env template |

Install:

```bash
sudo mkdir -p /etc/asn-names-loader
sudo cp /opt/GrapesNTA/deploy/systemd/asn-names-loader.env.example \
    /etc/asn-names-loader/asn-names-loader.env
sudo chmod 0600 /etc/asn-names-loader/asn-names-loader.env

sudo install -m 0644 /opt/GrapesNTA/deploy/systemd/asn-names-loader.service \
    /etc/systemd/system/asn-names-loader.service
sudo install -m 0644 /opt/GrapesNTA/deploy/systemd/asn-names-loader.timer \
    /etc/systemd/system/asn-names-loader.timer
sudo systemctl daemon-reload
sudo systemctl enable --now asn-names-loader.timer
```

The systemd unit loads `/etc/asn-names-loader/asn-names-loader.env` first and
then `/etc/geoloaderd/geoloaderd.env`. By default the example keeps all
`ASNNAMES_CH_*` variables commented out — the loader then inherits the full
`{host, port, user, password, database}` tuple from `GEOLOADERD_CH_*`, so on a
host where `geoloaderd` is already configured you do not need to repeat the
ClickHouse credentials. If you want the ASN loader to talk to a different
ClickHouse, uncomment **all five** `ASNNAMES_CH_*` lines together — partial
overrides are rejected at resolution time to avoid silent auth failures
(USER from one source mixed with PASSWORD from another).

Manual one-off run (smoke test on the first 200 ASN):

```bash
ASNNAMES_PROGRESS=1 ASNNAMES_MIN_ROWS=10 \
sudo -E python3 /opt/GrapesNTA/scripts/load_asn_names.py --max-asns 200
```

Verify:

```bash
clickhouse-client --query "
SELECT count(), uniqExact(asn) FROM default.asn_names FINAL;

SELECT asn, name, source, updated_at
FROM default.asn_names FINAL
ORDER BY updated_at DESC
LIMIT 10;

SELECT asn, name, cc, rir
FROM default.asn_registry_enriched
WHERE asn IN (13335, 15169, 16509, 13238)
ORDER BY asn;
"
```

Team Cymru's bulk endpoint is rate-limited but generous; `ASNNAMES_CHUNK_SIZE=5000`
per TCP session is a safe default. If a chunk fails the loader aborts before
inserting, so `default.asn_names` is never partially overwritten — the previous
snapshot stays in place until the next successful run.

Top origin ASN for BMP with country/RIR/name:

```sql
SELECT
    r.origin_asn,
    any(a.name) AS as_name,
    any(a.cc) AS country,
    any(a.rir) AS rir,
    count() AS routes
FROM default.bmp_route_events AS r
LEFT JOIN default.asn_registry_enriched AS a ON r.origin_asn = a.asn
WHERE r.ts >= now() - INTERVAL 30 MINUTE
  AND r.event_type = 'announce'
GROUP BY r.origin_asn
ORDER BY routes DESC
LIMIT 20;
```

## Top Countries By Traffic

Top destination countries for IPv4 traffic during the last hour:

```sql
SELECT
    if(country = '', '??', country) AS country,
    sum(bytes) AS bytes_total,
    formatReadableSize(bytes_total) AS traffic,
    count() AS flows
FROM
(
    SELECT
        dictGetString(
            'default.geo_country_dict',
            'cc',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
        ) AS country,
        bytes
    FROM default.flows_raw
    WHERE time_received_ns >= now() - INTERVAL 1 HOUR
      AND etype = 0x0800
)
GROUP BY country
ORDER BY bytes_total DESC
LIMIT 20;
```

Top source countries for IPv4 traffic during the last hour:

```sql
SELECT
    if(country = '', '??', country) AS country,
    sum(bytes) AS bytes_total,
    formatReadableSize(bytes_total) AS traffic,
    count() AS flows
FROM
(
    SELECT
        dictGetString(
            'default.geo_country_dict',
            'cc',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))
        ) AS country,
        bytes
    FROM default.flows_raw
    WHERE time_received_ns >= now() - INTERVAL 1 HOUR
      AND etype = 0x0800
)
GROUP BY country
ORDER BY bytes_total DESC
LIMIT 20;
```

`??` means the prefix was not found in `geo_country_dict`.

Reload dictionary manually after a manual table change:

```sql
SYSTEM RELOAD DICTIONARY default.geo_country_dict;
```

## Troubleshooting

- `Authentication failed` when running `clickhouse-client --multiquery < deploy/clickhouse/geo_country.sql` usually means the command used the wrong endpoint or credentials. Source `/etc/geoloaderd/geoloaderd.env` and pass `--host`, `--port`, `--user`, `--password`, and `--database` explicitly.
- Use the plain ClickHouse password in `GEOLOADERD_CH_PASSWORD` and `GEOLOADERD_DICT_SOURCE_PASSWORD`. Do not URL-encode characters; for example use `@`, not `%40`.
- If `dictGetString(...)` returns `ALL_CONNECTION_TRIES_FAILED`, the dictionary source endpoint is not reachable from the ClickHouse server. Set `GEOLOADERD_DICT_SOURCE_HOST` / `GEOLOADERD_DICT_SOURCE_PORT` to the ClickHouse-internal endpoint, commonly `127.0.0.1:9000`.
- If `dictGetString(...)` returns `AUTHENTICATION_FAILED`, the dictionary source credentials are wrong for the internal endpoint. They may differ from the remote loader credentials.
- If the loader prints `validation ok` and then fails on `SYSTEM RELOAD DICTIONARY`, table loading succeeded but dictionary creation/reload needs fixing. Re-run with `--skip-download` after correcting the dictionary source settings.

## Example `dictGetString` usage

See **Enriching NetFlow** below for `flows_raw`-specific casts.

## Enriching NetFlow (`flows_raw`)

`default.flows_raw` stores `src_addr` and `dst_addr` as **FixedString(16)** (IPv4 in the first 4 bytes, network byte order; IPv6 uses the full 16 bytes). Use `etype` to distinguish IPv4 (`0x0800`) vs IPv6 (`0x86DD`).

**IPv4** rows:

```sql
SELECT
    dictGetString(
        'default.geo_country_dict',
        'cc',
        tuple(
            toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4))))
        )
    ) AS dst_cc,
    sum(bytes) AS bytes
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 1 HOUR
  AND etype = 0x0800
GROUP BY dst_cc
ORDER BY bytes DESC;
```

**IPv6** rows (if your ClickHouse build supports `reinterpretAsIPv6` on FixedString):

```sql
SELECT
    dictGetString('default.geo_country_dict', 'cc', tuple(reinterpretAsIPv6(dst_addr))) AS dst_cc,
    sum(bytes) AS bytes
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 1 HOUR
  AND etype = 0x86DD
GROUP BY dst_cc
ORDER BY bytes DESC;
```

If `reinterpretAsIPv6` is not available, check `DESCRIBE TABLE default.flows_raw` and use the appropriate cast for your version.

Adjust the time filter column if your table uses `DateTime` instead of `DateTime64` — see `DESCRIBE TABLE default.flows_raw`.

## Limitations

- **Country registration ≠ physical location.** Cloud, VPN, Anycast, and corporate networks can be “wrong” for operational traffic.
- **No city** in this phase. RIR delegated files do not include city.
- **Overlapping prefixes** across RIRs are rare but possible historically; `IP_TRIE` returns one match.
- Loader needs outbound **HTTPS** to RIR mirrors unless `--skip-download` and a populated cache.

## Offline checks

```bash
python3 -m py_compile scripts/load_rir_geo.py
python3 scripts/load_rir_geo.py --help
```
