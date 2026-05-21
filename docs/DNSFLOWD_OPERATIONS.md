# dnsflowd Operations

Документ описывает эксплуатацию `dnsflowd`: настройку, проверку полноты записи
DNS и алерты по деградации.

For the current split-sink architecture and metric interpretation, see
[`DNSFLOWD_CURRENT_ARCHITECTURE.md`](DNSFLOWD_CURRENT_ARCHITECTURE.md).

ClickHouse capacity and freshness queries:
[`DNSFLOWD_CH_RUNBOOK.md`](DNSFLOWD_CH_RUNBOOK.md).

## Tables

`dnsflowd` пишет в две таблицы ClickHouse:

- `default.dns_log` - raw DNS log, одна строка на DNS query/response;
- `default.dns_answers` - плоские A/AAAA answers для обогащения flows доменом.

DDL:

```bash
CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
  ./deploy/clickhouse/apply_dns_tables.sh
```

## Recommended Runtime Settings

`dnsflowd` пишет в ClickHouse через **два независимых sink**:

- `dns_log` (raw audit);
- `dns_answers` (плоские A/AAAA для Flow Explorer).

При перегрузке одна общая очередь забивается старым backlog, и UI перестаёт
видеть свежий DNS. Split sink держит `dns_answers` отдельно от `dns_log`.

Production defaults на `netflow`:

```bash
DNS_CH_RAW_ENABLED=1
DNS_CH_ANSWERS_ENABLED=1
DNS_CH_RAW_BATCH_SIZE=20000
DNS_CH_ANSWERS_BATCH_SIZE=20000
DNS_CH_RAW_QUEUE_SIZE=65536
DNS_CH_ANSWERS_QUEUE_SIZE=262144
DNS_CH_RAW_WRITERS=1
DNS_CH_ANSWERS_WRITERS=2
DNS_CAPTURE_BATCH_SIZE=1000
DNS_CAPTURE_FLUSH_INTERVAL=100ms
DNS_CH_FLUSH_INTERVAL=1s
DNS_HEALTH_INTERVAL=1m
DNS_HEALTH_LAG_THRESHOLD=100000
DNS_CH_RAW_AUTO_SHED_ON_ANSWERS_LAG=1
DNS_CH_ANSWERS_LAG_SHED_THRESHOLD=100000
DNS_CH_ANSWERS_LAG_RECOVER_THRESHOLD=50000
DNS_CH_RAW_SHED_RECOVER_COOLDOWN=2m
DNS_CH_ANSWERS_DEDUP_TTL=60s
```

Автоматический raw shed включён по умолчанию: при высоком `answers_writer_lag_rows`
`dnsflowd` сам перестаёт писать `dns_log`, чтобы не убить свежесть `dns_answers`.
Смотреть `raw_shed_active` и `raw_policy` в логах.

UI-first режим при сильной перегрузке (отключить raw, усилить answers writers):

```bash
DNS_CH_RAW_ENABLED=0
DNS_CH_ANSWERS_ENABLED=1
DNS_CH_ANSWERS_WRITERS=4
```

После изменения `/etc/dnsflowd/dnsflowd.env`:

```bash
sudo systemctl restart dnsflowd
sudo journalctl -u dnsflowd -n 30 --no-pager | grep 'sink enabled'
```

Ожидаемо:

```text
raw_enabled=true raw_batch_size=20000 raw_queue_size=65536 raw_writers=1
answers_enabled=true answers_batch_size=20000 answers_queue_size=262144 answers_writers=2
```

## Health Log

`dnsflowd` раз в минуту пишет `ERROR`, если обнаружена деградация:

```text
level=ERROR msg="dnsflowd health degraded"
```

Условия:

- `answers_queue_drops_delta > 0` — критично: Flow Explorer теряет свежий DNS;
- `raw_queue_drops_delta > 0` — деградация raw audit (`dns_log`);
- `answers_insert_errs_delta > 0` — ошибки записи `dns_answers`;
- `raw_insert_errs_delta > 0` / `insert_errs_delta > 0` — ошибки `dns_log`;
- `answers_writer_lag_rows > DNS_HEALTH_LAG_THRESHOLD` — answers writer отстаёт.

Legacy поля в том же логе:

- `queue_drops_delta` = `raw_queue_drops_delta + answers_queue_drops_delta`;
- `writer_lag_rows` = `answers_writer_lag_rows`.

Проверка:

```bash
sudo journalctl -u dnsflowd --since "10 minutes ago" --no-pager \
  | grep 'dnsflowd health degraded'
```

Интерпретация:

- `answers_queue_drops_delta > 0` = UI DNS enrichment incomplete;
- `raw_queue_drops_delta > 0` = raw audit loss, answers may still be OK;
- `answers_writer_lag_rows > 0` без drops = задержка, очередь ещё буферизует;
- `answers_insert_errs_delta > 0` = проблема ClickHouse/сети/схемы для `dns_answers`.

## Manual Freshness Check

Для UI важнее `dns_answers`:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '...' --query "
SELECT
    toString(now('UTC')) AS now_utc,
    toString(max(ts)) AS max_ts,
    dateDiff('second', max(ts), now('UTC')) AS lag_sec,
    count() AS rows
FROM default.dns_answers
FORMAT PrettyCompact
"
```

Success: `lag_sec < 60-120` under normal load.

Raw audit (`dns_log`):

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '...' --query "
SELECT
    toString(max(ts)) AS latest_ts,
    countIf(ts >= now('UTC') - INTERVAL 1 MINUTE) AS rows_1m,
    countIf(is_response = 0 AND ts >= now('UTC') - INTERVAL 1 MINUTE) AS queries_1m,
    countIf(is_response = 1 AND ts >= now('UTC') - INTERVAL 1 MINUTE) AS responses_1m
FROM default.dns_log
FORMAT PrettyCompact
"
```

If `dns_answers.lag_sec` is large while DNS traffic exists, `dnsflowd` is behind or
dropping answers (`answers queue full` in journal).

## Packet Capture Comparison

Use this to estimate write coverage for one minute. `tcpdump` on a busy mirror
is not a perfect ground truth: it can report `dropped by interface`.

```bash
cd /tmp

IFACE=enp5s0d1
DUMP="/tmp/dns_check_$(date -u +%Y%m%d_%H%M%S).pcap"

START_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"
echo "START_UTC=$START_UTC"
echo "DUMP=$DUMP"

timeout 60 tcpdump -i "$IFACE" -s 0 -w "$DUMP" \
  '((ip and udp port 53) or (vlan and ip and udp port 53))'

END_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"
echo "END_UTC=$END_UTC"

echo "PCAP_COUNT:"
tcpdump -nn -r "$DUMP" '((ip and udp port 53) or (vlan and ip and udp port 53))' 2>/dev/null | wc -l
```

Then compare with ClickHouse:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '...' --query "
SELECT
    count() AS rows,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    uniq(query_name) AS unique_names
FROM default.dns_log
WHERE ts >= '$START_UTC'
  AND ts <  '$END_UTC'
FORMAT PrettyCompact
"
```

If `dnsflowd` is catching up, wait 1-2 minutes and repeat the ClickHouse count
for the same interval.

## Find One Packet From Pcap In ClickHouse

Example pcap line:

```text
8.8.8.8.53 > 45.159.201.67.41193: 18801 2/0/0 CNAME webdav.disk.yandex.ru., A 213.180.204.148
```

Search by `txid` and normalized client/server:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '...' --query "
SELECT
    toString(ts) AS ts_text,
    if(is_response = 1, 'response', 'query') AS row_type,
    txid,
    query_name,
    qtype,
    rcode,
    IPv4NumToString(reinterpretAsUInt32(reverse(substring(client_ip, 1, 4)))) AS client_ip,
    client_port,
    IPv4NumToString(reinterpretAsUInt32(reverse(substring(server_ip, 1, 4)))) AS server_ip,
    server_port,
    answer_count,
    raw_size
FROM default.dns_log
WHERE ts >= '$START_UTC'
  AND ts <  '$END_UTC'
  AND txid = 18801
  AND IPv4NumToString(reinterpretAsUInt32(reverse(substring(client_ip, 1, 4)))) = '45.159.201.67'
  AND IPv4NumToString(reinterpretAsUInt32(reverse(substring(server_ip, 1, 4)))) = '8.8.8.8'
ORDER BY ts
FORMAT PrettyCompact
"
```

Do not alias `toString(ts) AS ts` in queries that also filter by `ts`; use
`ts_text` to avoid alias/type confusion.

## UI Status

The UI should treat DNS context as best-effort:

- `OK`: fresh rows, no recent `dnsflowd health degraded` logs;
- `DEGRADED`: recent health error or writer lag, flow rows are valid but DNS
  names can be incomplete;
- `STALE`: `default.dns_log` has no fresh rows;
- `DOWN`: `dnsflowd` service is not active or ClickHouse inserts fail.

Recommended banner:

```text
DNS enrichment is degraded. Some flows may not have DNS names.
```

## Next Reliability Step

Current `dnsflowd` uses an in-memory queue. It can buffer short bursts, but it is
not durable. For guaranteed capture through ClickHouse slowdowns or restarts,
add a disk spool similar to `xdpflowd`.
