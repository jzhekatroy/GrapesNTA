# План реализации: приёмник sFlow v5 (flowcollectord)

Документ-задание для другого агента/разработчика. Цель — добавить приём sFlow v5
и записать потоки в `default.flows_raw` так, чтобы они работали со всеми
существующими агрегатами и дашбордами без изменений SQL.

Это план; код пишется по нему отдельно. Перед реализацией прочитать
`docs/NET_ANALYTICS_MODEL.md` и `docs/CLICKHOUSE_FLOWS_RAW.md`.

---

## 1. Цель и границы

В скоупе:

- Новый демон `flowcollectord` — UDP-приёмник flow-протоколов с парсерами-плагинами.
- Парсер sFlow v5: только **flow samples** → `flows_raw`.
- Переиспользование классификатора и пути доставки в ClickHouse из `xdpflowd`.
- Регистрация источника `sflow-default` в каталоге `net_flow_sources`.

Вне скоупа (MVP):

- Counter samples (счётчики интерфейсов) — пропускаем.
- NetFlow v9 / IPFIX — делаем позже по аналогии (парсер-плагин).
- Изменение схемы `flows_raw` и агрегатов — НЕ требуется.
- Чтение операционной настройки демона из БД — НЕ делаем (см. раздел 8).

---

## 2. Зафиксированные решения

| Тема | Решение |
|------|---------|
| sampling_rate | **Pre-scale**: `bytes = frame_length * rate`, `packets = rate`. Фактический rate пишем в колонку `sampling_rate` справочно. |
| Архитектура | Один бинарь `flowcollectord` с парсерами-плагинами; на каждом хосте включён нужный листенер. |
| Зеркало | XDP остаётся демоном `xdpflowd` (eBPF-захват), общий код переиспользуется. |
| Counter samples | Пропускаем в MVP. |
| include_in_total | sFlow — **отдельная точка наблюдения**, ставим `include_in_total = 1`. |
| Операционная настройка | Локальный env на хосте. БД хранит только каталог/метаданные. |

---

## 3. Развёртывание (3 сервера)

| Сервер | Источник | Демон | Слушает |
|--------|----------|-------|---------|
| mirror | XDP-зеркало (eBPF) | `xdpflowd` | NIC |
| netflow | NetFlow (push UDP) | `flowcollectord` (позже) | UDP :2055 |
| sflow | sFlow v5 (push UDP) | `flowcollectord` | UDP :6343 |

Один бинарь `flowcollectord` разворачивается на серверах netflow/sflow; на каждом
включён ровно один листенер через локальный конфиг. Бинарь умеет все протоколы,
но принимает только то, что включено.

---

## 4. Структура кода

### 4.1. Рефактор: вынести общий код

Сейчас переиспользуемый код лежит в `package main` внутри `cmd/xdpflowd`. Вынести
в общий пакет (xdpflowd продолжает работать через него):

```text
internal/flowingest/
  flow_row.go            FlowRow + INSERT-маппинг (compact + enriched)
  classifier.go          trafficClassifier.classifyPair(...)
  clickhouse_sink.go     батч-INSERT (async)
  clickhouse_spool.go    дисковый спул (durability)
  clickhouse_delivery.go доставка spool|direct
```

**Важная граница рефактора.** Сейчас `clickhouseDelivery.enqueue` принимает
`[]flowKV` (записи BPF-карты) и сам конвертит их в `FlowRow` через
`flowRowsFromKV` (XDP-специфичный код: монотонные часы, ключ карты).

Нужно разделить:

- `flowRowsFromKV` (flowKV → FlowRow) — остаётся в `cmd/xdpflowd`, это специфика XDP.
- Слой доставки/sink/спул — принимает уже готовые `[]FlowRow`.

Предлагаемый интерфейс общего слоя:

```go
// internal/flowingest
type Delivery interface {
    EnqueueRows(rows []FlowRow)
    Close()
    LogMetrics()
    HealthSnapshot() HealthSnapshot
}
```

`xdpflowd` остаётся: `flowKV -> flowRowsFromKV -> Delivery.EnqueueRows`.
`flowcollectord`: `sflow sample -> FlowRow -> Delivery.EnqueueRows`.

Классификатор переиспользуется как есть: `classifyPair(src, dst, ipVersion, srcVLAN, dstVLAN)`.

### 4.2. Новый демон

```text
cmd/flowcollectord/
  main.go            загрузка конфига, запуск листенеров, health, graceful shutdown
  config.go          конфиг листенеров + CH DSN + классификатор
  listener.go        общий UDP-листенер (read loop -> parser -> Delivery)
  sflow_v5.go        парсер датаграммы sFlow v5 -> flow samples
  packet_header.go   разбор raw header: Ethernet/802.1Q/IPv4/IPv6/TCP/UDP
  metrics.go         счётчики: datagrams, samples, parse errors, dropped
  (позже) netflow_v9.go, ipfix.go
```

---

## 5. Парсинг sFlow v5

Спецификация: sFlow v5 (sflow.org). UDP, дефолтный порт 6343.

### 5.1. Заголовок датаграммы

```text
version            uint32 (== 5, иначе drop)
agent_ip_type      uint32 (1 = IPv4, 2 = IPv6)
agent_address      4 или 16 байт   -> SamplerAddress
sub_agent_id       uint32
sequence_number    uint32          -> для метрик/детекта потерь
uptime_ms          uint32
num_samples        uint32
```

Дальше `num_samples` сэмплов.

### 5.2. Сэмпл

```text
sample_type        uint32 (enterprise=0, format): 1=flow, 2=counter,
                                                   3=expanded flow, 4=expanded counter
sample_length      uint32 (байт до следующего сэмпла — использовать для skip)
```

- Тип 1 и 3 (flow / expanded flow) — парсим.
- Тип 2 и 4 (counter) — **пропускаем по `sample_length`**.
- Неизвестный enterprise/format — пропускаем по `sample_length`.

### 5.3. Flow sample (тип 1)

```text
sequence_number    uint32
source_id          uint32 (sFlow internal, НЕ наш source_id)
sampling_rate      uint32          -> rate для pre-scale
sample_pool        uint32
drops              uint32
input_if           uint32
output_if          uint32
num_records        uint32
```

Дальше `num_records` flow-записей. Нужна запно «raw packet header».

### 5.4. Flow record «raw packet header» (format 1)

```text
header_protocol    uint32 (1 = ETHERNET-ISO88023 — обычный случай)
frame_length       uint32  -> исходная длина кадра ДО сэмплирования
stripped           uint32  -> сколько байт отрезано (FCS и т.п.)
header_length      uint32  -> сколько байт заголовка приложено
header_bytes       header_length байт (+ padding до кратности 4)
```

`frame_length` — это длина оригинального кадра, её и берём для объёма (не
header_length). `header_bytes` парсим вручную.

Прочие flow-record форматы (ethernet=2, ipv4=3, ipv6=4, extended switch/router/
gateway) в MVP можно пропускать по длине; при наличии — extended switch даёт VLAN,
extended gateway — src/dst AS. AS берём из классификатора, VLAN — из 802.1Q
заголовка (или extended switch, если приложен).

### 5.5. Разбор raw header (packet_header.go)

Из `header_bytes` (когда `header_protocol = 1`):

1. **Ethernet**: dst MAC(6), src MAC(6), ethertype(2).
2. **802.1Q** (ethertype 0x8100): TPID/TCI — забрать `vlan_id` (12 бит), затем реальный ethertype. Поддержать QinQ (0x88a8) — взять внешний VLAN.
3. **L3**:
   - ethertype 0x0800 → IPv4: ihl, protocol, src/dst (4 байта).
   - ethertype 0x86DD → IPv6: next header, src/dst (16 байт). Учесть extension headers минимально (для портов).
4. **L4**: для TCP(6)/UDP(17) — src_port(2), dst_port(2). Для прочих — порты 0.

Защититься от усечённого header (`header_length` маленькое): если данных не
хватает — заполнить что есть, остальное 0, не падать.

---

## 6. Маппинг sFlow → FlowRow

| FlowRow поле | Источник из sFlow | Примечание |
|--------------|-------------------|------------|
| `SamplerAddress` | agent_address датаграммы | 16-байт layout (IPv4 в первых 4) |
| `SourceID` | конфиг листенера | `sflow-default` |
| `SamplingRate` | flow sample sampling_rate | справочно |
| `SrcAddr` / `DstAddr` | raw header L3 | 16-байт layout |
| `Etype` | 0x0800 / 0x86DD | из ethertype |
| `Proto` | raw header L4 proto | TCP=6/UDP=17/... |
| `SrcPort` / `DstPort` | raw header L4 | 0 если не TCP/UDP |
| `SrcVLAN` | 802.1Q из header | 0 если нет тега |
| `Bytes` | `frame_length * sampling_rate` | **pre-scale** |
| `Packets` | `sampling_rate` | **pre-scale**, 1 сэмпл ~ rate пакетов |
| `TimeReceivedNs` / `Date` | время приёма датаграммы (wall, UTC) | |
| `TimeFlowStartNs` | время приёма (нет точного start в сэмпле) | |
| `Direction`, `Src/DstASN`, scope, role, entity, network_name, attachment | `classifier.classifyPair(SrcAddr, DstAddr, ipVersion, SrcVLAN, 0)` | как в xdpflowd |

Перед вставкой выбирается enriched или compact путь (как в текущем sink:
`rowsHaveEnrichment`). С включённым классификатором — enriched.

Колонки INSERT (enriched) уже реализованы в `clickhouse_sink.go`
(`insertEnrichedBatchRows`) — переиспользуем без изменений.

---

## 7. Конфигурация и env

Конфиг (YAML или env — согласовать со стилем xdpflowd; ниже логическая модель):

```text
listeners:
  - proto: sflow_v5
    listen: 0.0.0.0:6343
    source_id: sflow-default
```

env-файл `deploy/systemd/flowcollectord.env.example`:

```env
REPO_ROOT=/opt/GrapesNTA
FLOWCOLLECTORD_BIN=${REPO_ROOT}/bin/flowcollectord

# Listener (MVP: один протокол на хост)
FC_SFLOW_ENABLED=1
FC_SFLOW_LISTEN=0.0.0.0:6343
FC_SFLOW_SOURCE_ID=sflow-default

# ClickHouse (как у xdpflowd: URL-encode пароль)
FC_CH_DSN=clickhouse://USER:PASS@HOST:9000/default
FC_CH_TABLE=default.flows_raw
FC_CH_BATCH_SIZE=500
FC_CH_FLUSH_INTERVAL=1s
FC_CH_QUEUE_SIZE=64

# Durability spool (как у xdpflowd)
FC_CH_SPOOL_MODE=required
FC_CH_SPOOL_DIR=/var/lib/flowcollectord/ch-spool

# Классификатор (читает те же таблицы, что xdpflowd)
FC_CLASSIFIER=1
FC_CLASSIFIER_REFRESH=60s
FC_CLASSIFIER_BGP_TABLE=default.bgp_prefix_origin_current
FC_CLASSIFIER_L3_PREFIXES_VIEW=default.net_l3_prefixes_enabled
FC_CLASSIFIER_L2_VLANS_VIEW=default.net_l2_vlans_enabled

FC_HEALTH_INTERVAL=1m
```

systemd-юнит `deploy/systemd/flowcollectord.service` — по образцу
`xdpflowd.service` (EnvironmentFile, Restart=on-failure, после network-online).

---

## 8. Граница «настройка в файле vs БД»

Демон НЕ читает операционную настройку из БД.

| Слой | Пример | Где | Кто читает |
|------|--------|-----|-----------|
| Операционная | listen-порт, source_id, CH DSN/пароль, тюнинг, таблицы классификатора | env на хосте | сам демон при старте |
| Каталог/метаданные | display_name, локация, коллектор, include_in_total | БД `net_flow_sources` | UI и SQL дашборда |

Связь — по строке `source_id`. Демон пишет `source_id` в `flows_raw`; строка в
`net_flow_sources` с тем же `source_id` даёт метаданные. За классификатором демон
в БД ходит (как xdpflowd), за своей строкой источника — нет.

---

## 9. Регистрация источника в БД

Применить `deploy/clickhouse/net_flow_sources_sflow.sql` (создан вместе с планом):

```sql
INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
VALUES
    ('sflow-default', 'Default sFlow v5', 'sflow', '', '',
     'sFlow v5 receiver (flowcollectord)', 1, 1, now());
```

`FC_SFLOW_SOURCE_ID` в env должен совпадать с `source_id` в этой строке.

---

## 10. Проверка / приёмка

После запуска на sflow-сервере.

Идут ли строки sFlow:

```sql
SELECT count(), max(time_received_ns) AS last_seen
FROM default.flows_raw
WHERE source_id = 'sflow-default'
  AND time_received_ns >= now() - INTERVAL 5 MINUTE;
```

Адекватность объёмов (после pre-scale) и направлений:

```sql
SELECT direction, count() AS rows, sum(bytes) AS bytes, sum(packets) AS packets
FROM default.flows_raw
WHERE source_id = 'sflow-default'
  AND time_received_ns >= now() - INTERVAL 15 MINUTE
GROUP BY direction
ORDER BY bytes DESC;
```

sampling_rate проставлен:

```sql
SELECT DISTINCT sampling_rate
FROM default.flows_raw
WHERE source_id = 'sflow-default'
  AND time_received_ns >= now() - INTERVAL 15 MINUTE;
```

Источник появился в агрегатах (talkers):

```sql
SELECT endpoint_side, count()
FROM default.traffic_talker_1m
WHERE source_id = 'sflow-default'
  AND minute >= now() - INTERVAL 15 MINUTE
GROUP BY endpoint_side;
```

Критерии приёмки:

- [ ] Строки с `source_id='sflow-default'` появляются в `flows_raw`.
- [ ] `bytes/packets` домножены на `sampling_rate` (pre-scale), `sampling_rate` записан.
- [ ] `direction` и scope считаются (классификатор работает).
- [ ] VLAN из 802.1Q проставляется, где есть тег.
- [ ] Counter samples игнорируются без ошибок парсинга.
- [ ] Источник виден в агрегатах и на дашборде, учитывается в «Всего» (include_in_total=1).
- [ ] Усечённые/битые датаграммы не роняют демон (метрика parse_errors растёт).

---

## 11. Фазы

1. **БД**: применить `net_flow_sources_sflow.sql`. (готово к применению)
2. **Рефактор**: вынести `internal/flowingest`, перевести `xdpflowd` на него, прогнать его тесты.
3. **Парсер sFlow**: `sflow_v5.go` + `packet_header.go` + unit-тесты на реальных датаграммах.
4. **Демон**: `cmd/flowcollectord` (config, listener, health, shutdown) + env + systemd.
5. **Деплой и приёмка**: запуск на sflow-сервере, проверки раздела 10.
6. **NetFlow**: добавить `netflow_v9.go` как второй парсер-плагин по аналогии.

---

## 12. Риски и заметки

- **Усечённый header**: sFlow прикладывает только первые N байт кадра; парсер
  обязан работать на неполных данных и не паниковать.
- **QinQ / двойной VLAN**: брать внешний тег; не падать на стэке тегов.
- **IPv6 extension headers**: для портов пройти минимально; при сложной цепочке —
  порты 0, остальное заполнить.
- **Pre-scale и rate=0**: если `sampling_rate=0` в сэмпле — считать rate=1, чтобы
  не обнулить объём; залогировать аномалию.
- **Потеря сэмплов**: следить за `sequence_number` датаграммы для метрики потерь
  (не критично для агрегатов, но полезно для health).
- **Двойной учёт**: подтверждено, что sFlow — отдельная точка; если позже
  окажется пересечение с XDP — переключить `include_in_total = 0` в БД (без кода).

---

## 13. Ссылки

- `docs/NET_ANALYTICS_MODEL.md` — модель источников, ролей, агрегатов.
- `docs/CLICKHOUSE_FLOWS_RAW.md` — схема `flows_raw`, путь прямого INSERT.
- `cmd/xdpflowd/clickhouse_sink.go` — готовый enriched/compact INSERT (переиспользуем).
- `cmd/xdpflowd/classifier.go` — `classifyPair` (переиспользуем).
- `cmd/xdpflowd/clickhouse_spool.go`, `clickhouse_delivery.go` — durability/доставка.
- `deploy/systemd/xdpflowd.env.example` — образец env и тюнинга.
- `deploy/clickhouse/net_flow_sources.sql` — каталог источников.
