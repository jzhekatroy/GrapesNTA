# ТЗ: настройки Grapes NTA в UI

Документ для junior UI/backend developer. Описывает, какие настройки выносим в
веб-интерфейс (Laravel + MoonShine поверх ClickHouse), как они хранятся и какими
запросами читаются/пишутся.

UI работает напрямую с таблицами и view в ClickHouse (база `default`).
Все справочники — это `ReplacingMergeTree` с полями `enabled` и `updated_at`:

- запись/обновление = `INSERT` новой строки с `updated_at = now()`;
- «удаление» = `INSERT` строки с `enabled = 0` (soft delete);
- актуальное состояние читаем из `*_enabled` view.

---

## 0. Группы настроек

| Группа | Что это | Где хранится | Режим в UI |
|--------|---------|--------------|------------|
| 1. Каталог сети | Локации, коллекторы, источники, объекты, префиксы, VLAN, сервисы | ClickHouse `net_*`, `port_services` | Полный CRUD |
| 2. Фильтры дашборда | Направление, период, источник, режим страны | Не хранится, параметры запроса | Контролы виджетов |
| 3. Статус коллекторов | Живость, лаги, последний flow | Health демонов + `system.*` | Только чтение |
| 4. Хранение данных (TTL) | Сроки хранения таблиц | DDL / `ALTER TABLE` | Только админ |
| 5. Системные параметры хоста | DSN, интерфейс, тюнинг демонов | env-файлы на сервере | НЕ в UI |

Приоритет внедрения для MVP: **Группа 1 → Группа 2 → Группа 3**. Группы 4–5 позже
и только для администратора.

---

## 1. Каталог сети (CRUD)

### 1.1. Иерархия коллекторов

Нужно поддержать несколько локаций, в каждой — один или несколько коллекторов,
а у коллектора — один или несколько источников трафика (`source_id`).

```text
Локация (net_locations)
  └── Коллектор (net_collectors)
        └── Источник трафика (net_flow_sources.source_id)
              └── строки flows_raw / dns_log (поле source_id)
```

Связи:

```text
net_collectors.location_id   -> net_locations.location_id
net_flow_sources.collector_id -> net_collectors.collector_id
flows_raw.source_id           -> net_flow_sources.source_id
```

Важно: в `flows_raw` и агрегатах хранится только `source_id`. Локация и коллектор
не пишутся в каждую строку — они подтягиваются через справочники по `source_id`.

### 1.2. Новая таблица: локации

Создать `default.net_locations`:

```sql
CREATE TABLE IF NOT EXISTS default.net_locations
(
    location_id  String,                       -- 'msk-m9', 'spb-ix'
    display_name String,                        -- 'Москва, ММТС-9'
    city         String DEFAULT '',
    country      LowCardinality(String) DEFAULT '',
    comment      String DEFAULT '',
    enabled      UInt8 DEFAULT 1,
    updated_at   DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY location_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_locations_enabled;

CREATE VIEW default.net_locations_enabled AS
SELECT
    location_id,
    display_name,
    city,
    country,
    comment,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        location_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(city, updated_at) AS city,
        argMax(country, updated_at) AS country,
        argMax(comment, updated_at) AS comment,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_locations
    GROUP BY location_id
)
WHERE enabled_latest = 1;
```

### 1.3. Новая таблица: коллекторы

Создать `default.net_collectors`:

```sql
CREATE TABLE IF NOT EXISTS default.net_collectors
(
    collector_id String,                        -- 'col-msk-1'
    location_id  String DEFAULT '',             -- -> net_locations.location_id
    display_name String,                        -- 'XDP mirror M9 #1'
    hostname     String DEFAULT '',             -- 'netflow' (только справочно)
    comment      String DEFAULT '',
    enabled      UInt8 DEFAULT 1,
    updated_at   DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY collector_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_collectors_enabled;

CREATE VIEW default.net_collectors_enabled AS
SELECT
    collector_id,
    location_id,
    display_name,
    hostname,
    comment,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        collector_id,
        argMax(location_id, updated_at) AS location_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(hostname, updated_at) AS hostname,
        argMax(comment, updated_at) AS comment,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_collectors
    GROUP BY collector_id
)
WHERE enabled_latest = 1;
```

### 1.4. Источники трафика (существует)

Таблица `default.net_flow_sources` уже есть. В ней используем колонку
`collector_id` как ссылку на `net_collectors`. Колонку `location` оставляем для
обратной совместимости, но в UI локацию показываем через коллектор.

| Поле | Тип контрола | Назначение |
|------|--------------|------------|
| `source_id` | text (immutable после создания) | ID точки наблюдения, совпадает с env демона |
| `display_name` | text | Название источника для UI |
| `source_type` | select: `xdp / dns / netflow / ipfix / sflow / manual` | Тип источника |
| `collector_id` | select из `net_collectors_enabled` | К какому коллектору относится |
| `include_in_total` | toggle | Учитывать в KPI «Всего» |
| `description` | textarea | Заметка |
| `enabled` | toggle | Soft delete |

Запись (INSERT новой версии строки):

```sql
INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
VALUES
    ({source_id:String}, {display_name:String}, {source_type:String},
     {collector_id:String}, '', {description:String},
     {include_in_total:UInt8}, 1, now());
```

Чтение списка источников с коллектором и локацией:

```sql
SELECT
    s.source_id,
    s.display_name,
    s.source_type,
    s.include_in_total,
    c.collector_id,
    c.display_name AS collector_name,
    l.location_id,
    l.display_name AS location_name
FROM default.net_flow_sources_enabled AS s
LEFT JOIN default.net_collectors_enabled AS c ON s.collector_id = c.collector_id
LEFT JOIN default.net_locations_enabled  AS l ON c.location_id = l.location_id
ORDER BY l.display_name, c.display_name, s.display_name;
```

Дерево «Локация → Коллекторы → Источники» для UI:

```sql
SELECT
    l.display_name AS location_name,
    c.display_name AS collector_name,
    s.source_id,
    s.display_name AS source_name,
    s.include_in_total
FROM default.net_collectors_enabled AS c
LEFT JOIN default.net_locations_enabled AS l ON c.location_id = l.location_id
LEFT JOIN default.net_flow_sources_enabled AS s ON s.collector_id = c.collector_id
ORDER BY location_name, collector_name, source_name;
```

Важно: привязку «демон → `source_id`» по-прежнему задаёт env на хосте
(`XDPFLOWD_SOURCE_ID`, `DNSFLOWD_SOURCE_ID`). В UI мы только описываем каталог
источников и их метаданные, но не меняем то, какой демон под каким `source_id`
пишет. `source_id` в UI должен совпадать со значением в env демона.

### 1.5. Остальные справочники каталога

Те же правила (ReplacingMergeTree + `*_enabled` view, soft delete).

| Раздел UI | Таблица / view | Ключевые поля |
|-----------|----------------|---------------|
| Объекты сети | `net_entities` / `net_entities_enabled` | `entity_id`, `display_name`, `enabled` |
| IP-префиксы | `net_l3_prefixes` / `net_l3_prefixes_enabled` | `prefix`, `family`, `entity_id`, `role`, `enabled` |
| VLAN/подключения | `net_l2_vlans` / `net_l2_vlans_enabled` | `vlan_id`, `entity_id`, `attachment_type`, `boundary`, `enabled` |
| Сервисы/порты | `port_services` | `transport`, `port`, `service_code`, `service_name`, `category`, `is_enabled` |
| Локальные сети | `local_networks` / `local_networks_enabled` | просмотр + `enabled` |
| Локальные ASN | `local_asns` / `local_asns_enabled` | просмотр + `enabled` |

Допустимые значения `role` (IP-префиксы):

```text
provider_public      наш публичный адресный блок
internal             внутренняя инфраструктура
customer_allocated   выдан клиенту
customer_transit     клиентский префикс, анонсируем за него
remote               внешний (по умолчанию)
```

`role` напрямую влияет на расчёт `direction` в `xdpflowd`. Менять осознанно.

Допустимые значения `attachment_type` (VLAN): `customer`, `uplink`, `ix`,
`peering`, `core`, `internal`, `unknown`. `boundary`: `internal`, `external`,
`unknown`.

---

## 2. Фильтры дашборда

Это не настройки в БД, а параметры запросов виджетов. Хранить в URL/состоянии UI.

| Контрол | Значения | Куда идёт в SQL |
|---------|----------|-----------------|
| Направление | in / out / transit / internal / unknown; «Всего» = все пять | `direction IN (...)` |
| Период | 1h / 3h / 6h / 12h / 24h / 7d | выбор таблицы `*_1m` (<=1h) или `*_1h` (>1h) + `ts_from/ts_to` |
| Источник | один/несколько `source_id` или «по умолчанию» | `source_id IN (...)` + `include_in_total = 1` |
| Топ-N | 20 / 50 / 100 | `LIMIT` |
| Heatmap: режим страны | remote / src / dst | `country_side` логика |
| Heatmap: basis | ip / asn | `country_basis` |

В ClickHouse нет `direction = 'total'`. «Всего» = `direction IN ('in','out','transit','internal','unknown')`.

Подробные шаблоны запросов: `docs/UI_CLICKHOUSE_QUERIES.md`,
`docs/UI_TOP_TALKERS_TZ.md`, `docs/UI_COUNTRY_HEATMAP_TZ.md`.

---

## 3. Статус коллекторов (только чтение)

Отдельный экран «Коллекторы / Состояние». Редактирование запрещено.

Последний flow по источнику (живость источника):

```sql
SELECT
    source_id,
    max(time_received_ns) AS last_seen,
    now() - max(time_received_ns) AS age_seconds
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 1 HOUR
GROUP BY source_id
ORDER BY last_seen DESC;
```

Дополнительно можно показывать (источник — health демонов и `system`-таблицы):

- writer lag / queue drops / spool lag демонов (пороги `*_HEALTH_*` в env);
- активные BMP-пиры (`default.bmp_peers`);
- объём за последний час по источнику (для сверки «молчит/льёт».

UI помечает источник как «нет данных», если `age_seconds` больше порога
(например, 300 секунд).

---

## 4. Хранение данных / TTL (только админ)

Сейчас TTL зашит в DDL. Менять через `ALTER TABLE ... MODIFY TTL`.

| Данные | Таблица | Текущий TTL |
|--------|---------|-------------|
| Сырые потоки | `flows_raw` | 5 дней |
| Top talkers / pairs минутные | `traffic_talker_1m`, `traffic_pair_1m` | 2 дня |
| Top talkers / pairs часовые | `traffic_talker_1h`, `traffic_pair_1h` | 90 дней |
| DNS | `dns_log`, `dns_answers` | 30 дней |
| BMP события | `bmp_route_events` | 365 дней |

Пример изменения:

```sql
ALTER TABLE default.traffic_talker_1h MODIFY TTL hour + INTERVAL 90 DAY;
```

Предупреждение для UI: `MODIFY TTL` на больших таблицах (`flows_raw`,
`traffic_pair_*`) запускает мутацию и может упереться в память сервера. Делать
только из админского раздела, по одной таблице, желательно вне пиковой нагрузки.

---

## 5. Системные параметры хоста (НЕ выносить в UI)

Это env-файлы демонов на серверах (`/etc/xdpflowd/…`, `/etc/dnsflowd/…` и т.д.).
Менять из UI нельзя: требуют рестарта демона и влияют на захват/доставку.

- Подключение к ClickHouse: `*_CH_DSN`, host/port/user/password.
- Захват: `IFACE`, `XDP_MODE`, `XDP_ACTION`, `XDP_DNS_PASSTHROUGH`.
- Привязка `source_id`: `XDPFLOWD_SOURCE_ID`, `DNSFLOWD_SOURCE_ID`.
- Тюнинг: размеры батчей/очередей, writers, `XDP_CH_SPOOL_*`.
- Загрузчики справочников: `BGPORIGIN_*`, `ASNNAMES_*`, `GEOLOADERD_*`,
  `LOCALNETWORKS_*` (расписания и лимиты).

В UI эти значения допустимо показывать только как read-only «информация о
коллекторе», если потребуется, но не редактировать.

---

## 6. Порядок применения новых таблиц

На сервере (тот же ClickHouse, где `flows_raw`):

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' \
  --database default --multiquery < deploy/clickhouse/net_locations.sql

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' \
  --database default --multiquery < deploy/clickhouse/net_collectors.sql
```

Затем заполнить минимум одну локацию и один коллектор, привязать существующие
источники (`xdp-default`, `dns-default`) к коллектору через `collector_id`.

---

## 7. Чеклист

- [ ] Созданы `net_locations` + `net_locations_enabled`.
- [ ] Созданы `net_collectors` + `net_collectors_enabled`.
- [ ] В UI «Источники трафика» поле `collector_id` — select из `net_collectors_enabled`.
- [ ] Дерево «Локация → Коллектор → Источник» строится одним JOIN-запросом.
- [ ] `source_id` в UI совпадает с env демона; UI не меняет привязку демона.
- [ ] CRUD всех справочников — через INSERT новой версии + soft delete `enabled = 0`.
- [ ] Списки читаются из `*_enabled` view, не из базовых таблиц.
- [ ] Фильтры дашборда не пишутся в БД, только в состояние UI.
- [ ] Статус коллекторов — только чтение.
- [ ] TTL и env-параметры недоступны обычному пользователю.
