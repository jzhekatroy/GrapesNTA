# ClickHouse / Kafka / goflow2 — схема flow-пайплайна

Документ описывает, **куда и в каком виде** должны попасть NetFlow-записи от
`xdpflowd`, чтобы downstream (goflow2 → Kafka → ClickHouse) продолжил работать
как с `ipt_NETFLOW`. Используется при планировании **Phase 3 (XDP_DROP)**.

## Общая топология

```
NIC (enp5s0d1, SPAN)
  ↓
[до замены]  ipt_NETFLOW → NFv9 UDP
[после]      xdpflowd    → NFv9 UDP
  ↓                       ↓
127.0.0.1:9996          127.0.0.1:9999
  ↓                       ↓
nfcapd                  docker-proxy → goflow2 (в контейнере)
  ↓                       ↓
локальные .nfcapd       Kafka (topic: ???)
                          ↓
                        ClickHouse  → Kafka-engine table `default.flows`
                          ↓ MaterializedView `default.flows_raw_view`
                          ↓
                        `default.flows_raw` (MergeTree, 30B+ rows, ~700 GiB)
```

> TODO: уточнить имя Kafka-топика и формат (`SELECT create_table_query FROM system.tables WHERE name='flows'`).

## Соединение к CH

```
host:  95.215.1.30
port:  6124 (TCP clickhouse native)
user:  develop
version: 24.11.1
```

## Экспортёры (наблюдение 2026-04-23)

В проде **два** источника NFv9 попадают в `flows_raw`:

| `sampler_address` (hex) | IPv4 | baseline (16:00-16:01) | примечание |
| ----------------------- | ----- | ---------------------- | ---------- |
| `AC130001...`           | `172.19.0.1` | **~820 000 rows/10s = ~82k flows/sec**, ~14 GiB/10s (~11 Gbit/s) | Docker-bridge gateway, **основной** экспортёр, ≈ 94% объёма |
| `AC120001...`           | `172.18.0.1` | ~56 000 rows/10s = ~5.6k flows/sec, ~1.5 GiB/10s | Другой docker-bridge, **вторичный**, ≈ 6% объёма |

`sampler_address` тут **не** `127.0.0.1` — потому что goflow2 слушает внутри контейнера, а UDP-пакеты приходят через `docker-proxy` и видны как пришедшие с bridge-gateway.

> **TODO:** выяснить, что за сеть `172.19.0.0/16` и почему **оттуда** идёт основной поток (возможно удалённый экспортёр с другого сервера, пробрасывается через публичный IP + DNAT → docker network; или второй `ipt_NETFLOW` из другого контейнера).

### Запрос для проверки экспортёров

```sql
SELECT
  hex(sampler_address) AS exporter_hex,
  toStartOfInterval(time_received_ns, toIntervalMinute(10)) AS bucket,
  count() AS rows,
  formatReadableSize(sum(bytes)) AS bytes_hr
FROM default.flows_raw
WHERE time_received_ns > now64(9) - toIntervalHour(6)
GROUP BY exporter_hex, bucket
ORDER BY bucket DESC, rows DESC
LIMIT 100;
```

### Аномалия 2026-04-23 16:11:30 — частичный отказ AC130001

Зафиксирован **резкий спад** потока:

| окно (UTC+3) | AC130001 (rows/10s) | AC120001 (rows/10s) | состояние |
| ------------ | ------------------- | ------------------- | --------- |
| 16:00:00-16:01:00 | ~820 000 | ~56 000 | **NORMAL** |
| 16:11:30 (момент) | резкое падение | без изменений | начало сбоя |
| 16:25:00-16:27:50 | **0** | ~53 000 | **BROKEN** (AC130001 не декодируется) |
| 16:28:00-16:29:50 | всплеск ~1.2M/10s | ~55 000 | после `docker restart kcg-goflow2-1` — временно ожил |
| 16:33:00+ | **0** снова | ~55 000 | опять сломан |

**Признаки:**
- `goflow2` лог забит `level=WARN msg="template error"` с первого же коннекта;
- перезапуск контейнера даёт ~2-минутный burst (пока NFv9-шаблоны от AC130001 свежие), затем снова деградация;
- `softly reset` через `sysctl -w net.netflow.destination=...` на **локальном** `ipt_NETFLOW` (127.0.0.1) ситуацию с AC130001 не исправляет → локальный `ipt_NETFLOW` и AC130001 — это **разные** источники.

**Гипотезы:**
1. Удалённый экспортёр (сервер B) шлёт NFv9 с экзотическими/enterprise-template fields, которые этот goflow2 не умеет декодировать → `template error`.
2. Изменение на удалённом экспортёре в 16:11:30 (обновление, смена шаблонов, перезагрузка).
3. Buffer/queue внутри goflow2 переполняется (`too many receiver messages, muting`) и дропает именно «тяжёлого» отправителя.

**Важно для Phase 3:** наш `xdpflowd` шлёт только стандартные IANA-поля, поэтому `template error` у goflow2 быть не должно. Если после запуска `xdpflowd` в CH появятся записи с `sampler_address` = наш адрес и без дыр — это **подтверждает**, что проблема именно в несовместимости шаблонов, а не в сети / Kafka / CH.

## Таблицы

### `default.flows_raw` (MergeTree) — **целевая**

| колонка              | тип              | назначение                                 |
| -------------------- | ---------------- | ------------------------------------------ |
| `date`               | Date             | партиционирование                          |
| `time_inserted_ns`   | DateTime64(9)    | когда CH записал                           |
| `time_received_ns`   | DateTime64(9)    | когда goflow2 принял NFv9 (UTC, нс)        |
| `time_flow_start_ns` | DateTime64(9)    | первое событие flow (нс)                   |
| `sequence_num`       | UInt32           | sequence exporter'а                        |
| `sampling_rate`      | UInt64           | 1 = нет sampling                           |
| `sampler_address`    | FixedString(16)  | IP экспортера (IPv4-mapped IPv6 если v4)   |
| `src_addr`           | FixedString(16)  | source IP                                  |
| `dst_addr`           | FixedString(16)  | dst IP                                     |
| `src_as`             | UInt32           | BGP AS origin                              |
| `dst_as`             | UInt32           | BGP AS dest                                |
| `etype`              | UInt32           | 0x0800 (IPv4) / 0x86DD (IPv6)              |
| `proto`              | UInt32           | L4 protocol (6=TCP, 17=UDP, 1=ICMP…)       |
| `src_port`           | UInt32           | L4 source port                             |
| `dst_port`           | UInt32           | L4 dest port                               |
| `bytes`              | UInt64           | total bytes в flow                         |
| `packets`            | UInt64           | total packets в flow                       |

**Ключевая колонка времени для сравнения окон — `time_received_ns`**
(`DateTime64(9)`, UTC, наносекунды).

### `default.flows` (Kafka engine) — вход

Та же схема, но `time_received_ns` / `time_flow_start_ns` — `UInt64` вместо
`DateTime64(9)` (MV делает каст).

Поля совпадают с `flows_raw` 1:1, кроме колонок `date` и `time_inserted_ns`
(их MV добавляет сам).

### `default.ddos_raw` + `default.ddos_raw_view` + `default.ddos`

Отдельный pipeline для DDoS-детектора. Мы его **НЕ трогаем**.

### `default.ip_ranges`, `default.vlan_dic`, `dictionaries.protocols`

Справочники. Не трогаем.

## Какие поля NFv9 нам нужно экспортировать из `xdpflowd`

goflow2 заполняет схему из **стандартных IANA полей NFv9**:

| CH колонка           | NFv9 IANA ID | NFv9 field name                  | у нас в xdpflowd |
| -------------------- | ------------ | -------------------------------- | ---------------- |
| `src_addr` (v4)      | 8            | IPV4_SRC_ADDR                    | ✅                |
| `dst_addr` (v4)      | 12           | IPV4_DST_ADDR                    | ✅                |
| `src_addr` (v6)      | 27           | IPV6_SRC_ADDR                    | ✅                |
| `dst_addr` (v6)      | 28           | IPV6_DST_ADDR                    | ✅                |
| `src_port`           | 7            | L4_SRC_PORT                      | ✅                |
| `dst_port`           | 11           | L4_DST_PORT                      | ✅                |
| `proto`              | 4            | PROTOCOL                         | ✅                |
| `bytes`              | 1            | IN_BYTES                         | ✅                |
| `packets`            | 2            | IN_PKTS                          | ✅                |
| `time_flow_start_ns` | 22 / 152     | FIRST_SWITCHED / flowStartMilliseconds | ✅ (msec)         |
| `time_received_ns`   | — (goflow2 сам ставит при приёме) | —             | — (не шлём)      |
| `sampling_rate`      | 34 / 48      | SAMPLING_INTERVAL / SAMPLER_MODE | ✅ (шлём 1)       |
| `sampler_address`    | — (источник UDP) | —                           | — (127.0.0.1)    |
| `etype`              | (выводится goflow2 из v4/v6 шаблона) | —        | — (автомат.)     |
| **`src_as`**         | **16**       | **SRC_AS**                       | ❗ **НЕТ**         |
| **`dst_as`**         | **17**       | **DST_AS**                       | ❗ **НЕТ**         |
| `sequence_num`       | — (заголовок NFv9) | header                     | ✅ (header.seq)   |

### Пробел: `src_as` / `dst_as`

`ipt_NETFLOW` опционально делает BGP AS lookup (`net.netflow.bgplookup` или через
`flowd`). Проверить на проде:

```bash
grep -i bgp /proc/net/stat/ipt_netflow 2>/dev/null
sysctl -a 2>/dev/null | grep -i 'netflow.*bgp\|netflow.*as'
# и посмотреть неcколько записей — действительно ли там ненулевые AS
```

```sql
SELECT
  sum(src_as != 0) AS src_as_nonzero,
  sum(dst_as != 0) AS dst_as_nonzero,
  count()          AS total
FROM default.flows_raw
WHERE time_received_ns > now64(9) - INTERVAL 5 MINUTE;
```

- **Если AS в CH всегда нули** — значит ipt_NETFLOW их не заполняет. Gap не критичен.
- **Если AS заполнены значительно** — xdpflowd должен слать поля 16/17
  (можно всегда 0, goflow2 всё равно их декодирует; но тогда в CH потеряем
  полезный сигнал — нужен BGP lookup, отдельная задача).

## Запросы для сравнения baseline ↔ xdpflowd (Phase 3)

### 1. Baseline за последние N минут ДО swap

```sql
-- подставить :t0 и :t1 как границы окна (DateTime64(9) или now() - INTERVAL)
SELECT
  count()              AS rows,
  countDistinct(src_addr, dst_addr, src_port, dst_port, proto) AS distinct_flows,
  sum(bytes)           AS bytes_sum,
  sum(packets)         AS pkts_sum,
  bytes_sum / 1073741824 AS gib,
  bytes_sum*8 / (dateDiff('second', toDateTime(:t0, 'UTC'), toDateTime(:t1, 'UTC'))) / 1e9
                        AS avg_gbps
FROM default.flows_raw
WHERE time_received_ns BETWEEN :t0 AND :t1;
```

### 2. Окно swap (во время работы xdpflowd) — те же агрегаты

То же самое, другое окно.

### 3. Распределение по протоколам — должно совпадать

```sql
SELECT
  proto,
  count()      AS rows,
  sum(bytes)   AS bytes,
  sum(packets) AS pkts,
  round(sum(bytes)*100.0 / sum(sum(bytes)) OVER (), 2) AS bytes_pct
FROM default.flows_raw
WHERE time_received_ns BETWEEN :t0 AND :t1
GROUP BY proto
ORDER BY bytes DESC
LIMIT 10;
```

Ожидаем то же распределение, что и в `nfdump`:
- TCP ≈ 72%, UDP ≈ 24%, GRE/ESP/ICMP ≈ 4%.

### 4. sampler_address — sanity

```sql
SELECT
  hex(sampler_address) AS sampler_hex,
  count() AS rows,
  formatReadableSize(sum(bytes)) AS bytes_hr
FROM default.flows_raw
WHERE time_received_ns > now64(9) - toIntervalMinute(5)
GROUP BY sampler_hex
ORDER BY rows DESC;
```

До замены ожидаем оба экспортёра (`AC130001...` и `AC120001...`, см. раздел
«Экспортёры»). После Phase 3 в дополнение к ним должна появиться запись с
адресом, с которого шлёт наш `xdpflowd` (обычно `127.0.0.1` →
`00000000000000000000FFFF7F000001` или gateway соответствующего docker-bridge).

> Внимание: **не** использовать `IPv6NumToString(sampler_address)` напрямую —
> в CH 24.11 даёт ошибку. Либо `hex()`, либо `IPv6NumToString(toIPv6(sampler_address))`
> (но без агрегатов внутри агрегатов).

### 5. Дыра или завал (per-10-sec buckets)

```sql
SELECT
  toStartOfInterval(time_received_ns, INTERVAL 10 SECOND) AS t,
  count()      AS rows,
  sum(bytes)   AS bytes,
  sum(packets) AS pkts
FROM default.flows_raw
WHERE time_received_ns > now64(9) - INTERVAL 10 MINUTE
GROUP BY t
ORDER BY t;
```

Если в окне swap идут ровные buckets ≈ как до — данные целы. Если есть дырки
или резко меньшие значения — проблема в формате/шаблоне NFv9.

## Критерии приёмки Phase 3

| Метрика | Требование |
| --- | --- |
| `count()` за swap-окно | ±5% от baseline за равное окно |
| `sum(bytes)` | ±5% от baseline |
| `sum(packets)` | ±5% от baseline |
| распределение `proto` | top-5 совпадают по порядку, разница в % ≤ 2 п.п. |
| `sampler_address` | то же значение, что до |
| дырки в buckets 10s | отсутствуют |
| `softirq` в mpstat | < baseline (33%), цель ≤ 20% |
| `rx_fifo_errors` прирост | практически 0 |

## Риски и обходные пути

| Риск | Как обнаружим | Что делать |
| --- | --- | --- |
| goflow2 не декодирует наш шаблон | bucket в CH = 0 / очень мало | `prod_ab_swap.sh` сам откатит правило через watchdog; проверить goflow2 logs |
| src_as/dst_as у нас нули, а в CH ненулевые | запрос в п. «Gap: src_as/dst_as» | отдельная задача (BGP lookup), не блокер |
| `sampler_address` стал другим | п.4 | проверить, что `xdpflowd` шлёт с `127.0.0.1`, а не внешнего IP |
| Падает xdpflowd | watchdog в `prod_ab_swap.sh` | правило ipt_NETFLOW восстанавливается автоматически |

## TODO (собрать в следующем шаге)

- [ ] `SHOW CREATE TABLE default.flows` — узнать топик Kafka и формат.
- [ ] `SHOW CREATE TABLE default.flows_raw_view` — увидеть как MV мапит поля.
- [ ] Проверить `src_as`/`dst_as` в реальных данных (есть ли сигнал).
- [ ] Запустить 3-минутный Phase 3 drop-run и сверить с запросами выше.
- [ ] Выяснить, кто прячется за `sampler_address` = `172.19.0.1` (удалённый
      сервер? другой контейнер?). Проверить на хосте:
      `sudo docker network ls` и `sudo docker network inspect <net>`,
      `sudo ss -ulnp` / `sudo tcpdump -ni any udp port 9999 -c 20`.
- [ ] Отдельно: расследовать `template error` от AC130001 в goflow2 — что за
      NFv9 template он шлёт, может ли новая версия goflow2 его распарсить.
