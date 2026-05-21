# dnsflowd Operations

Документ описывает эксплуатацию `dnsflowd`: настройку, проверку полноты записи
DNS и алерты по деградации.

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

На высоком DNS-потоке маленькая in-memory queue приводит к `queue full` и потере
строк. Для production на `netflow` используем:

```bash
DNS_CH_BATCH_SIZE=5000
DNS_CH_QUEUE_SIZE=262144
DNS_CH_FLUSH_INTERVAL=1s
DNS_HEALTH_INTERVAL=1m
DNS_HEALTH_LAG_THRESHOLD=100000
```

После изменения `/etc/dnsflowd/dnsflowd.env`:

```bash
sudo systemctl restart dnsflowd
sudo journalctl -u dnsflowd -n 30 --no-pager | grep 'sink enabled'
```

Ожидаемо:

```text
batch_size=5000 flush_interval=1s queue_size=262144
```

## Health Log

`dnsflowd` раз в минуту пишет `ERROR`, если обнаружена деградация:

```text
level=ERROR msg="dnsflowd health degraded"
```

Условия:

- `queue_drops_delta > 0` - строки DNS были потеряны из-за переполнения очереди;
- `insert_errs_delta > 0` - ошибки записи `dns_log`;
- `answers_insert_errs_delta > 0` - ошибки записи `dns_answers`;
- `writer_lag_rows > DNS_HEALTH_LAG_THRESHOLD` - writer отстаёт от очереди.

Проверка:

```bash
sudo journalctl -u dnsflowd --since "10 minutes ago" --no-pager \
  | grep 'dnsflowd health degraded'
```

Интерпретация:

- `queue_drops_delta > 0` = loss, DNS rows уже потеряны;
- `writer_lag_rows > 0` без drops = есть задержка, но очередь пока буферизует;
- `insert_errs_delta > 0` = проблема ClickHouse/сети/схемы.

## Manual Freshness Check

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

If `rows_1m = 0` while DNS traffic exists, `dnsflowd` is stale or writing to the
wrong ClickHouse target.

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
