# Universal ClickHouse schema (GrapesNTA)

Source: production dump `ch-schema-dump-20260720-with-dns` (SHOW CREATE from live CH).

One schema covers collectors and product surfaces:

| Layer | Contents |
|-------|----------|
| `10_flows` | `flows_raw` (XDP + sFlow fields, classifier, MAC/ifIndex, tcp_flags, …) |
| `20_dns` | `dns_log` / answers / rollups (+ MVs as on prod) |
| `30_bmp` | BMP peers/events, BGP updates, origin ASN tables/dict |
| `40_enrichment` | geo / IP→ASN / ASN names |
| `50_net` | locations, sources, L3/L2, SNMP catalog, port services, health |
| `60_traffic` | async rollup targets + `traffic_rollup_state` |
| `70_observations` | observations store + personal rollups |
| `80_rbac` | users / roles / permissions |

## Apply (fresh CH)

`apply.sh` walks `NN_*/*.sql` in filename order. `MANIFEST.txt` is the inventory of those files; keep it in sync when adding SQL.

HTTP (as used on prod admin port):

```bash
export CH_URL='http://127.0.0.1:8123'
export CH_USER='default'
export CH_PASS='...'
./deploy/schema/apply.sh
```

Native client:

```bash
export CH_HOST=127.0.0.1 CH_PORT=9000 CH_USER=default CH_PASS='...'
./deploy/schema/apply.sh
```

Partial:

```bash
./deploy/schema/apply.sh 10_flows 30_bmp 60_traffic
```

Install profiles (sFlow-only / +BMP / +DNS) choose **which daemons to run**, not a different DB shape.

Dictionaries (`*_dict.sql`) get `CH_DICT_HOST/PORT/USER/PASSWORD` via `envsubst` (defaults follow `CH_USER`/`CH_PASS` or `default`/empty).

## Notes

- Statements use `IF NOT EXISTS` for safer re-runs; they do **not** migrate altered columns.
- HTTP apply (`CH_URL`) splits each file into statements (`split_sql.py`) because ClickHouse HTTP accepts one query per request. Native `--multiquery` is unchanged.
- Live stands: `./deploy/deploy.sh schema` (also runs before `ui` / `full`) applies `ensure.list` using `deploy/ui/.env`. Add an idempotent SQL file there when UI starts selecting a new column or view.
- Prod TTL on `flows_raw` is short (6d) — tune per customer after install.
- DNS MVs are included for parity with prod; disable layer `20_dns` MVs later if you prefer async-only.
- Legacy Kafka `flows` / old talkers IP tables are intentionally omitted.
