# MVP dashboard data design

> **Deprecated sections:** `local_networks`, `local_asns`, `local_operators`,
> `vlan_map`, `traffic_chart_1m`, `traffic_customer_1m`, `traffic_uplink_1m`,
> `traffic_1m`, `traffic_asn_pair_1m` were replaced by the Network Analytics
> model. See [NET_ANALYTICS_MODEL.md](NET_ANALYTICS_MODEL.md) and
> [NET_ANALYTICS_OPERATIONS.md](NET_ANALYTICS_OPERATIONS.md).

Рабочая схема данных для Laravel + MoonShine поверх ClickHouse. Цель MVP -
быстро рисовать графики/таблицы по traffic, countries, DNS и BMP/BGP без
тяжелых запросов по raw-таблицам на каждый открытый экран.

## Общая схема

```text
xdpflowd       -> flows_raw
dnsgrapesnta   -> dns_log
BMP collector  -> bmp_* tables
        ↓
ClickHouse raw + aggregate tables
        ↓
Laravel API
        ↓
MoonShine dashboards
```

Laravel не должен читать миллионы raw-строк и считать их в PHP. Для UI он
запрашивает уже подготовленные агрегаты: 1 минута, 5 минут, 1 час и т.д.

## Raw tables

### `default.flows_raw`

Сырые flow-записи:

- время;
- src/dst IP;
- src/dst port;
- protocol;
- bytes;
- packets;
- sampler/exporter.

Используется для drill-down, расследований и построения агрегатов.

### `default.dns_log`

Сырые DNS-запросы/ответы:

- client/server IP;
- query name;
- qtype;
- rcode;
- answers;
- raw size.

Используется для DNS-дашборда и расследований.

### `bmp_*`

BMP/BGP-таблицы нужны для маршрутизации:

- peers;
- current routes/RIB;
- route events;
- prefix -> origin ASN;
- next-hop/upstream.

DDL: `deploy/clickhouse/bmp.sql`.

Сервис: `cmd/bmpgrapes` (BMP TCP listener -> ClickHouse). Подробнее в
`docs/BMPGRAPES_MVP.md`. В MVP заполняются `bmp_peers`,
`bmp_route_events` (append-only) и агрегат `bgp_updates_1m` через MV. Поддержка
текущего RIB (`bmp_routes_current`) — следующий шаг после MVP.

## Required dictionaries

### `local_networks`

Справочник наших IP/префиксов. Без него нельзя корректно понять направление:

```text
src external, dst local     -> in
src local, dst external     -> out
src local, dst local        -> internal
src external, dst external  -> transit/unknown
```

DDL и рабочий процесс: `deploy/clickhouse/local_networks.sql` и
`docs/LOCAL_NETWORKS_DIRECTION.md`.

Для текущего MVP локальная сеть автоматически заполняется из BGP origin ASN
через `scripts/load_local_networks_from_asn.py`. В текущей тестовой
конфигурации `195.2.241.1` резолвится в `AS34665 PINDC-AS`, поэтому loader
берет активные префиксы из `bgp_prefix_origin_current WHERE origin_asn = 34665`,
схлопывает more-specific префиксы и пишет их в `default.local_networks` /
`default.local_networks_enabled`.

`IP_TRIE` dictionary `default.local_networks_dict` намеренно НЕ создается:
удалённый ClickHouse 24.11 за SQL-прокси отвергает dictionary DDL. Поэтому
классификация перенесена в `xdpflowd`: collector держит BGP/local/VLAN
справочники в памяти и пишет `src_asn`, `dst_asn`, `direction`,
`src_label`/`dst_label`, `src_operator`/`dst_operator` прямо в `flows_raw`.
Laravel читает агрегаты, а не классифицирует raw-строки.

`default.local_asns` — отдельный редактируемый справочник ASN, которые нужно
считать локальными. Private ASN не считаются локальными автоматически: их нужно
добавлять явно.

`default.vlan_map` — редактируемый справочник VLAN. В MVP используется только
outer VLAN tag, `vlan_id` глобальный. `customer/internal/mgmt/local` считаются
локальной стороной, `uplink/ix/peering` — внешней.

### `geo_prefix_country`

Справочник IP-префикс -> страна. Используется для heatmap и top countries.

### `port_services`

Редактируемый справочник портов/сервисов. DDL: `deploy/clickhouse/port_services.sql`.

Пример:

```text
tcp/22   -> SSH   -> remote_access
tcp/80   -> HTTP  -> web
tcp/443  -> HTTPS -> web
udp/443  -> QUIC  -> web
udp/53   -> DNS   -> dns
udp/5060 -> SIP   -> voip
tcp/5060 -> SIP   -> voip
```

Справочник нужен, чтобы строить отчеты не только по номеру порта, но и по
сервису/категории:

- web;
- dns;
- mail;
- database;
- remote_access;
- vpn;
- voip;
- messaging.

В MVP master-copy можно держать прямо в ClickHouse. Если нужны права, аудит и
удобное редактирование через MoonShine, Laravel может хранить master-copy в
своей БД и синхронизировать ее в ClickHouse.

## Aggregate tables

### `traffic_1m`

Общий график нагрузки:

- total `bps`;
- total `pps`;
- flows/s.

Одна строка = одна минута + `direction`. `traffic_1m_mv` берет готовый
`direction` из `flows_raw`; никакой классификации в ClickHouse здесь нет.

DDL:
- `deploy/clickhouse/traffic_1m_table.sql` — таблица `traffic_1m`
  (`SummingMergeTree`, `CODEC(Delta, ZSTD(1))`, TTL 365 дней). Применяется один
  раз при первом деплое.
- `deploy/clickhouse/traffic_1m_mv.sql` — materialized view `traffic_1m_mv`.
  Передеплоивается при изменении direction-логики.

В MVP `traffic_1m` хранит суммы за минуту:

- bytes;
- packets;
- flows_count.

`bps` и `pps` считаются на API-слое при отдаче графика:

```text
bps = bytes * 8 / bucket_seconds
pps = packets / bucket_seconds
```

Для длинных периодов Laravel выбирает шаг, а ClickHouse группирует данные из
`traffic_1m`:

```text
<= 24h  -> 1m
<= 7d   -> 15m
<= 31d  -> 1h
> 31d   -> 1d
```

То есть физически в MVP достаточно `traffic_1m`. Если месячные/годовые графики
станут тяжелыми, добавляем физические rollup-таблицы `traffic_1h` и
`traffic_1d`.

Для графика `Traffic In/Out, bps` источник данных — `traffic_chart_1m`
(pivot, одна строка на минуту). `traffic_direction_1m` остаётся
нормализованным агрегатом и fallback для debug. `traffic_1m` — legacy total
график.

### `traffic_chart_1m`

Основной агрегат для dashboard chart API. DDL:
`deploy/clickhouse/traffic_chart_1m.sql`.

Поля (на минуту):

- `total_bytes`, `in_bytes`, `out_bytes`, `transit_bytes`, `internal_bytes`,
  `unknown_bytes`;
- те же группы для `packets` и `flows`;
- `bps` / `pps` / `flows_per_sec` считаются в API: `sum(in_bytes) * 8 /
  bucket_seconds`.

Backfill: `deploy/clickhouse/backfill_traffic_chart_1m.sql` из
`traffic_direction_1m`. Validate:
`deploy/clickhouse/traffic_chart_1m_validate.sql`.

### `traffic_direction_1m`

Нормализованный агрегат по `direction` (одна строка = minute + direction). DDL:
`deploy/clickhouse/traffic_direction_1m.sql`.

Поля:

- minute;
- direction;
- bytes;
- packets;
- flows_count.

### `traffic_uplink_1m`

Разрез по uplink/IX label (`Transroute.spb`, `Piterix.msk`, ...). DDL:
`deploy/clickhouse/traffic_uplink_1m.sql`.

### `traffic_customer_1m`

Разрез по `operator_id` (`pin`, `arbital`, `iconet`, ...). DDL:
`deploy/clickhouse/traffic_customer_1m.sql`.

### `traffic_asn_pair_1m` (deprecated)

Старый MVP-агрегат для ASN-only In/Out без сканирования `flows_raw`.
Оставлен для обратной совместимости. Новый API должен использовать
`traffic_direction_1m`. DDL: `deploy/clickhouse/traffic_asn_pair_1m.sql`.

Поля:

- minute;
- src_asn;
- dst_asn;
- bytes;
- packets;
- flows_count.

Направление не пишется в таблицу. Laravel считает его при чтении по
`local_asns_enabled`:

```text
src_asn local, dst_asn external -> out
src_asn external, dst_asn local -> in
src_asn local, dst_asn local    -> internal
otherwise                       -> transit
```

Ограничение: агрегат покрывает только IPv4 ASN-based сценарий и не учитывает
VLAN/префиксы операторов без AS. Новые разработки на него не опираются.

### `traffic_country_1m`

Тепловая карта стран и top countries. DDL:
`deploy/clickhouse/traffic_country_1m.sql`.

Поля:

- minute;
- source_id;
- country_basis (`ip` / `asn`);
- country_side (`src` / `dst`);
- direction;
- country_code (`RU`, `US`, `??` при пустом lookup);
- bytes;
- packets;
- flows_count.

UI выбирает basis (`ip` по умолчанию, `asn` — страна регистрации ASN) и
режим карты: `remote` (in→src, out→dst, transit→src), `src`, `dst`.

Используется для карты за час/сутки/неделю и графика выбранной страны.

### `traffic_talker_1m` / `traffic_pair_1m` / `traffic_talker_1h` / `traffic_pair_1h`

Таблицы top talkers. DDL:

- `deploy/clickhouse/traffic_talkers_1m.sql`;
- `deploy/clickhouse/traffic_talkers_1h.sql`.

`traffic_talker_1m` хранит endpoints по сторонам:

- `endpoint_side = src` — вкладка «Источники»;
- `endpoint_side = dst` — вкладка «Назначения».

`traffic_talker_1h` — часовой rollup для тех же вкладок.

Поля:

- minute;
- source_id;
- endpoint_side;
- direction;
- endpoint_ip;
- endpoint_asn;
- endpoint_as_name;
- endpoint_ip_country;
- endpoint_as_country;
- endpoint_scope;
- endpoint_label;
- endpoint_network_name / endpoint_network_role;
- bytes;
- packets;
- flows_count.

`traffic_pair_1m` хранит пары `src_ip -> dst_ip` с ASN/country атрибутами обеих
сторон для вкладки «Пары». `traffic_pair_1h` — часовой rollup для длинных окон.

Хранение:

- `traffic_talker_1m` / `traffic_pair_1m` — TTL 2 дня, короткие окна;
- `traffic_talker_1h` / `traffic_pair_1h` — TTL 90 дней, 3h/6h/12h/24h+ окна.

Верхний фильтр направления выбирает реальные `direction` rows. Значение UI
«Всего» не хранится как `direction = total`; UI/API суммирует реальные
направления (`in`, `out`, `transit`, `internal`, `unknown`).

### `traffic_service_1m`

Графики и таблицы по сервисам. DDL: `deploy/clickhouse/port_services.sql`.

Поля:

- minute;
- direction;
- transport;
- service_port;
- service_code;
- service_name;
- category;
- bytes;
- packets;
- flows_count.

Для графиков по сервисам агрегат нужен обязательно, иначе top services за сутки
будет каждый раз пересчитываться по огромной `flows_raw`.

В MVP сервисный порт определяется эвристикой:

```text
direction = in   -> service_port = src_port
direction = out  -> service_port = dst_port
otherwise        -> service_port = dst_port
```

Почему так: при исходящем соединении клиент обычно идет на внешний серверный
порт, а при входящем удаленный сервер отвечает с серверного порта. Позже можно
заменить это на более точную нормализацию `client_port/server_port`.

### `dns_1m`

DNS overview:

- QPS;
- responses/s;
- NXDOMAIN rate;
- SERVFAIL rate;
- unique clients;
- unique domains.

### `dns_domain_1m`

Top domains и DNS-аналитика:

- domain;
- qtype;
- queries;
- responses;
- nxdomain;
- servfail.

### `traffic_asn_1m`

Трафик по ASN на базе BMP/BGP:

- ASN;
- direction;
- bytes;
- packets;
- flows_count.

### `traffic_prefix_1m`

Трафик по префиксам:

- prefix;
- origin ASN;
- direction;
- bytes;
- packets;
- flows_count.

## MVP screens

### Overview

- Total in/out bps.
- Total in/out pps.
- Flows/s.
- DNS QPS.
- NXDOMAIN rate.
- Top countries.
- Top services.
- Top ASN.
- BMP/BGP peer status.

### Traffic

- График `bps`.
- График `pps`.
- Top source/destination IP.
- Top conversations.
- Top ports.
- Raw flows with filters.

### Services

- Top services by traffic.
- Top categories by traffic.
- Service traffic over time.
- Top ports inside selected service/category.
- Filters: service, category, transport, direction, time range.

### Countries

- Heatmap.
- Top countries.
- In/out by country.
- Country details over time.

### DNS

- QPS.
- NXDOMAIN/SERVFAIL.
- Top domains.
- Top clients.
- Last DNS queries.

### BMP/BGP

- Peers.
- Routes count.
- Updates/withdrawals.
- Top ASN.
- Top prefixes.
- Route events.

## Missing or edited dictionaries

### If `local_networks` is empty

Сбор данных не должен ломаться, если наши IP/префиксы еще не заданы. В этом
режиме система пишет raw-данные и может показывать общие графики:

- total bps;
- total pps;
- flows/s;
- top IP;
- top ports;
- top services;
- DNS;
- BMP/BGP.

Но честное разделение `in/out` недоступно. Для MVP UI можно считать
`unknown`/`transit` как исходящий/total трафик, чтобы первый график не был
пустым до настройки локальных сетей.

```text
local_networks is empty -> direction = unknown/transit -> UI shows as out/total
```

### If `local_networks` changes

`flows_raw` остается источником истины. Агрегированные таблицы являются
производными данными и могут быть пересчитаны.

Есть два режима:

1. Изменение только на будущее.

```text
local_networks changed
new flows -> new direction rules
old aggregates -> stay as they were
```

Это быстро и безопасно, но старая история может быть неточной.

2. Изменение с пересчетом истории.

```text
local_networks changed
delete aggregate rows for selected period
rebuild aggregates from flows_raw for selected period
```

Это дает корректную историю, но может быть тяжелой операцией.

### If `port_services` changes

Справочник портов влияет на отчеты по сервисам и категориям:

```text
tcp/443 -> HTTPS -> web
udp/53  -> DNS   -> dns
```

После изменения `port_services` новые данные будут классифицироваться по новым
правилам. Старые строки в `traffic_service_1m` уже содержат старые
`service_code`, `service_name` и `category`, поэтому для точной истории тоже
нужен rebuild выбранного периода.

## Aggregate rebuild / backfill

Пересчет старых данных может быть долгим. При потоке порядка `80k flows/sec`
сутки raw-данных дают примерно:

```text
80 000 * 86 400 = 6.9B rows/day
```

Поэтому rebuild нельзя запускать синхронно при открытии графика. Это должна быть
отдельная фоновая задача.

### Backfill job

Минимальная модель задачи:

```text
aggregate_name
period_from
period_to
chunk_size
status: pending / running / done / failed
rows_read
rows_written
started_at
finished_at
error
```

Пересчет выполняется маленькими окнами:

```text
rebuild 2026-05-14 00:00-01:00
rebuild 2026-05-14 01:00-02:00
rebuild 2026-05-14 02:00-03:00
...
```

Так проще контролировать нагрузку на ClickHouse, показывать прогресс и
перезапускать упавшие куски.

### MoonShine action

В админке нужен явный action:

```text
Rebuild aggregates
- last 1 hour
- last 24 hours
- last 7 days
- custom period
```

UI должен предупреждать:

```text
Пересчет может занять долго и нагрузить ClickHouse.
```

### MVP policy

Для MVP:

- новые данные всегда считаются по актуальным справочникам;
- старая история пересчитывается только по явному запросу;
- большие периоды пересчитываются ночью или в фоне с ограничением нагрузки;
- `flows_raw` хранится достаточно долго, чтобы можно было восстановить агрегаты;
- если raw-данные уже удалены TTL, пересчитать этот период невозможно.

## API owner

Laravel формирует API для веба:

```text
GET /api/traffic/timeseries
GET /api/traffic/services
GET /api/countries/heatmap
GET /api/dns/overview
GET /api/bgp/peers
```

MoonShine/веб не ходит напрямую в ClickHouse. Laravel валидирует фильтры,
строит SQL, получает агрегаты и отдает JSON для графиков/таблиц.
