# deploy/clickhouse — operations, not canonical DDL

Canonical table/view/dictionary DDL lives in [`../schema/`](../schema/).
Fresh installs use:

```bash
./deploy/schema/apply.sh
```

This directory keeps **what you run against an already-live database**:

| What | Why it stays here |
|---|---|
| `apply_dns_tables.sh`, `apply_catalog_tables.sh` | Wrappers around `deploy/schema/apply.sh` |
| `apply_net_snmp_interfaces_dict.sh` | Dictionary SOURCE credentials |
| `migrate_*.sql`, `migrate_*.sh` | One-off ALTERs for existing installs |
| `flows_raw_*.sql` | Column adds for older `flows_raw` |
| `detach_traffic_mvs.sql` | Drop leftover sync MVs |
| `cleanup_old_classification.sql` | One-time drop of pre-analytics objects |
| `register_sel_collector.sql`, `monitor_sel_collector.sql` | SEL collector seed/ops |
| `dns_servers_1h_backfill.sh` | History backfill, not schema |
| `local_networks_dict.xml` | ClickHouse server config snippet |
| `seed_net_client_example.sql` | Example rows, not DDL |

Do not add new `CREATE TABLE` files here. Put them in `deploy/schema/NN_*/`.
