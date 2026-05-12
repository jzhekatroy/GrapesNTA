# Country geolocation from RIR delegated data

This adds **country-only** IP lookup using public RIR `delegated-*-extended-latest` statistics. It does **not** provide city accuracy. Data is loaded into ClickHouse and exposed as an `IP_TRIE` dictionary for `dictGet*` in queries.

**Country is resolved at query time** via `dictGet*` (or pre-aggregated tables you build yourself). It is **not** written into `flows_raw`.

## Components

| Path | Purpose |
|------|---------|
| [deploy/clickhouse/geo_country.sql](deploy/clickhouse/geo_country.sql) | Tables + `default.geo_country_dict` DDL |
| [scripts/load_rir_geo.py](scripts/load_rir_geo.py) | Downloads RIR files, parses prefixes, loads staging, swaps tables, reloads dictionary (Python stdlib + `clickhouse-client`) |
| [deploy/systemd/geoloaderd.*](deploy/systemd/) | `systemd` oneshot + daily timer |

## One-time ClickHouse setup

On the ClickHouse server (or via client):

```bash
clickhouse-client --multiquery < deploy/clickhouse/geo_country.sql
```

Confirm:

```sql
SHOW TABLES FROM default LIKE 'geo_prefix_country%';
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
| `GEOLOADERD_CH_DICT` | Dictionary to reload |

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
| `--dictionary` | `default.geo_country_dict` | Dictionary |
| `--cache-dir` | `/var/lib/geoloaderd/cache` | Cache directory |
| `--skip-download` | off | Use existing cache only |
| `--keep-tsv` | off | Keep temporary TSV on disk |
| `--http-timeout` | `120` | Per-URL download timeout (seconds) |
| `--min-countries` | `8` | Validation: minimum distinct ISO codes |
| `--no-ru-check` | off | Allow runs without `RU` rows (subset tests) |

The loader **refuses** to proceed if validation fails (e.g. no rows, too few countries, or no `RU` prefixes when using the full default RIR sources).

Table swap uses `EXCHANGE TABLES` when supported; otherwise it falls back to a three-step `RENAME TABLE` sequence. Errors from `clickhouse-client` print the failing query text **without** echoing the password.

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

## Validation queries

```sql
SELECT count(), uniqExact(cc) FROM default.geo_prefix_country;

SELECT cc, count()
FROM default.geo_prefix_country
GROUP BY cc
ORDER BY count() DESC
LIMIT 20;

SELECT dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4('8.8.8.8')));
SELECT dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4('77.88.8.8')));
```

Reload dictionary manually after a manual table change:

```sql
SYSTEM RELOAD DICTIONARY default.geo_country_dict;
```

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
