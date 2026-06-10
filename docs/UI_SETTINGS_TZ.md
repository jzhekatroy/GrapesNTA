# ТЗ: настройки Grapes NTA в UI


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

> Таблицы каталога создаёт deploy-скрипт из git, а не UI. Тебе (UI) не нужно
> выполнять `CREATE TABLE` — таблицы и `*_enabled` view уже существуют. Ты только
> читаешь из view и пишешь `INSERT` новых версий строк. См. раздел 6.

### 1.2. Локации (`net_locations`)

Создаётся скриптом. UI работает с view `net_locations_enabled`. Поля формы:

| Поле | Тип контрола | Назначение |
|------|--------------|------------|
| `location_id` | text (immutable после создания) | ID локации, напр. `msk-m9`, `spb-ix` |
| `display_name` | text | Название, напр. «Москва, ММТС-9» |
| `city` | text | Город (опц.) |
| `country` | text | Код страны (опц.) |
| `comment` | textarea | Заметка |
| `enabled` | toggle | Soft delete |

Запись новой версии:

```sql
INSERT INTO default.net_locations
    (location_id, display_name, city, country, comment, enabled, updated_at)
VALUES
    ({location_id:String}, {display_name:String}, {city:String},
     {country:String}, {comment:String}, 1, now());
```

Чтение списка: `SELECT * FROM default.net_locations_enabled ORDER BY display_name;`

### 1.3. Коллекторы (`net_collectors`)

Создаётся скриптом. UI работает с view `net_collectors_enabled`. Поля формы:

| Поле | Тип контрола | Назначение |
|------|--------------|------------|
| `collector_id` | text (immutable после создания) | ID коллектора, напр. `col-msk-1` |
| `location_id` | select из `net_locations_enabled` | К какой локации относится |
| `display_name` | text | Название, напр. «XDP mirror M9 #1» |
| `hostname` | text | Имя хоста (справочно) |
| `comment` | textarea | Заметка |
| `enabled` | toggle | Soft delete |

Запись новой версии:

```sql
INSERT INTO default.net_collectors
    (collector_id, location_id, display_name, hostname, comment, enabled, updated_at)
VALUES
    ({collector_id:String}, {location_id:String}, {display_name:String},
     {hostname:String}, {comment:String}, 1, now());
```

Чтение списка с локацией:

```sql
SELECT
    c.collector_id,
    c.display_name AS collector_name,
    c.hostname,
    l.location_id,
    l.display_name AS location_name
FROM default.net_collectors_enabled AS c
LEFT JOIN default.net_locations_enabled AS l ON c.location_id = l.location_id
ORDER BY location_name, collector_name;
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
| Сервисы/порты | `port_services` | отдельное ТЗ: `docs/UI_PORT_SERVICES_TZ.md` |
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

Отдельный экран «Коллекторы / Состояние». Редактирование запрещено — это
оперативная картина «кто реально шлёт данные», а не каталог.

### 3.1. Что показываем по строке

Группировка: **Локация → Коллектор → Источник (`source_id`)**. Сворачиваемое
дерево; на верхних уровнях агрегируем метрики дочерних источников.

| Поле | Откуда | Назначение |
|------|--------|------------|
| Имя | каталог (`net_*`) | человекочитаемое название; если нет — `source_id` как есть |
| Протокол | `net_flow_sources.source_type` или `flows_raw` | xdp / sflow / netflow / ipfix / dns |
| Состояние | расчёт по `age` + health | online / lagging / stale / disabled / **unknown** |
| flow/min | `flows_raw` | темп строк |
| bytes/min, pkts/min | `flows_raw` | реальный объём (для sFlow — уже отскейленный) |
| last_seen / age | `flows_raw` | сколько секунд назад был последний flow |
| Источников активно | `flows_raw` vs каталог | сколько `source_id` живы под коллектором |
| sampling_rate | `flows_raw` (sFlow/NetFlow) | напоминание, что объём оценочный |
| Лаг доставки / drops | health демона | «льёт, но не успевает писать в ClickHouse» |

### 3.2. Модель состояния

| Состояние | Условие | Цвет |
|-----------|---------|------|
| `online`   | `age <= 60s` | 🟢 |
| `lagging`  | `60s < age <= 300s` ИЛИ есть spool/writer lag | 🟡 |
| `stale`    | `age > 300s`, но коллектор `enabled=1` в каталоге | 🔴 |
| `disabled` | в каталоге `enabled=0` | ⚪ |
| `unknown`  | `source_id` есть в `flows_raw`, но НЕТ в каталоге | ⚠ |

Пороги (60 / 300 с) — параметр UI, не хранится в БД.

### 3.3. Незнакомые / ненастроенные коллекторы

Источник истины «кто шлёт» — это `flows_raw.source_id`, а не каталог. Поэтому
статус строится `LEFT JOIN` от живых `source_id` к каталогу:

- `source_id` есть в каталоге → показываем имя/локацию/коллектор;
- `source_id` есть только в `flows_raw` → строка `⚠ unknown`, без имени, с CTA
  «Зарегистрировать» (создать запись в `net_flow_sources`).

Скрывать незнакомые НЕЛЬЗЯ: это либо забытая привязка `*_SOURCE_ID` в env, либо
посторонний экспортёр — и то, и другое оператор должен видеть.

### 3.4. Где задаётся имя (env vs БД)

| Что | Где хранится | Кто меняет | Требует рестарт демона |
|-----|--------------|------------|------------------------|
| Привязка `source_id` к демону | env на хосте (`*_SOURCE_ID`) | админ | да |
| `display_name`, `collector_id`, `location_id` | ClickHouse каталог (`net_*`) | оператор в UI | нет |

В текстовом env остаётся только техническая привязка `source_id`. Имя, локация и
группировка по коллекторам редактируются в UI и подтягиваются по `source_id` —
переименование не требует доступа к серверу.

### 3.5. Запрос статуса (живые источники + каталог)

```sql
WITH live AS
(
    SELECT
        source_id,
        max(time_received_ns)                       AS last_seen,
        now() - max(time_received_ns)               AS age_seconds,
        count()                                      AS flows_5m,
        sum(bytes)                                   AS bytes_5m,
        sum(packets)                                 AS pkts_5m,
        anyLast(sampling_rate)                       AS sampling_rate
    FROM default.flows_raw
    WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
    GROUP BY source_id
)
SELECT
    l.display_name                                   AS location_name,
    c.display_name                                   AS collector_name,
    s.display_name                                   AS source_name,
    live.source_id,
    coalesce(s.source_type, '')                      AS protocol,
    live.last_seen,
    live.age_seconds,
    round(live.flows_5m / 5)                         AS flows_per_min,
    round(live.bytes_5m / 300)                       AS bytes_per_sec,
    round(live.pkts_5m  / 300)                        AS pkts_per_sec,
    live.sampling_rate,
    multiIf(
        s.source_id = '',                'unknown',   -- нет в каталоге
        live.age_seconds <= 60,          'online',
        live.age_seconds <= 300,         'lagging',
                                         'stale')      AS state
FROM live
LEFT JOIN default.net_flow_sources_enabled AS s ON live.source_id = s.source_id
LEFT JOIN default.net_collectors_enabled   AS c ON s.collector_id = c.collector_id
LEFT JOIN default.net_locations_enabled    AS l ON c.location_id  = l.location_id
ORDER BY location_name, collector_name, source_name;
```

Здесь `bytes`/`packets`/`sampling_rate` — поля `flows_raw` (для sFlow `bytes`
уже домножен на `sampling_rate` при приёме). Если каких-то колонок в схеме нет,
убрать соответствующие строки.

Дополнительно можно показывать (health демонов и `system`-таблицы):

- writer lag / queue drops / spool lag демонов (пороги `*_HEALTH_*` в env);
- активные BMP-пиры (`default.bmp_peers`);
- объём за последний час по источнику (для сверки «молчит/льёт»).

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

## 6. Откуда берутся таблицы (НЕ задача UI)

UI/джун **не создаёт таблицы руками**. Схему каталога раскатывает deploy-скрипт
из git — он идемпотентный (`CREATE TABLE IF NOT EXISTS`), запускается devops при
развёртывании:

```bash
CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='***' \
  ./deploy/clickhouse/apply_catalog_tables.sh
```

Скрипт применяет в правильном порядке `net_locations.sql` и `net_collectors.sql`
(локации первыми — коллекторы ссылаются на `location_id`) и выводит список
созданных таблиц/view. Источники трафика (`net_flow_sources`) раскатываются своим
шагом — см. `deploy/clickhouse/apply_flow_sources.sql`.

К моменту работы UI таблицы и `*_enabled` view уже существуют. Дальше оператор в
UI заполняет минимум одну локацию и один коллектор и привязывает существующие
источники (`xdp-default`, `dns-default`, `sflow-default`) к коллектору через
`collector_id` — обычными `INSERT` из разделов 1.2–1.4.

---

## 7. Чеклист

- [ ] (devops) Таблицы каталога раскатаны `apply_catalog_tables.sh` — UI их НЕ создаёт.
- [ ] UI читает `net_locations_enabled` / `net_collectors_enabled`, не базовые таблицы.
- [ ] В UI «Источники трафика» поле `collector_id` — select из `net_collectors_enabled`.
- [ ] Дерево «Локация → Коллектор → Источник» строится одним JOIN-запросом.
- [ ] `source_id` в UI совпадает с env демона; UI не меняет привязку демона.
- [ ] CRUD всех справочников — через INSERT новой версии + soft delete `enabled = 0`.
- [ ] Списки читаются из `*_enabled` view, не из базовых таблиц.
- [ ] Фильтры дашборда не пишутся в БД, только в состояние UI.
- [ ] Статус коллекторов — только чтение, строится `LEFT JOIN` от живых `source_id`.
- [ ] Незнакомые `source_id` показываются как `⚠ unknown` с CTA «Зарегистрировать», не скрываются.
- [ ] Состояние считается по `age` (online/lagging/stale/disabled/unknown), пороги — в UI.
- [ ] Имя/локация/коллектор редактируются в UI; в env только привязка `source_id`.
- [ ] TTL и env-параметры недоступны обычному пользователю.
