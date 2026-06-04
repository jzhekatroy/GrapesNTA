# ТЗ: виджет «Топ-говорящие»

Документ для junior UI/backend developer. Нужно сделать таблицу как в референсе:

```text
Топ-говорящие
По исходящему объёму, последний час

[Источники] [Назначения] [Пары] [Все]
```

Верхние фильтры дашборда уже задают:

- период;
- направление трафика;
- источники данных, если есть фильтр по `source_id`.

Внутри виджета вкладки задают только то, **что группировать**:

- `Источники` — группируем source-сторону flow;
- `Назначения` — группируем destination-сторону flow;
- `Пары` — группируем пару `source -> destination`.

---

## 1. Главное правило

```text
Фильтр направления = какие flows берем.
Вкладка = какую сторону этих flows показываем.
```

Пример:

| Направление | Вкладка | Что показывает |
|-------------|---------|----------------|
| `out` | Источники | кто из нашей сети больше всего отправляет наружу |
| `out` | Назначения | куда мы больше всего отправляем наружу |
| `out` | Пары | наш IP -> внешний IP |
| `in` | Источники | кто снаружи больше всего отправляет к нам |
| `in` | Назначения | кто у нас больше всего получает |
| `internal` | Источники | внутренние отправители |
| `internal` | Назначения | внутренние получатели |

---

## 2. Таблицы ClickHouse

Для виджета **не использовать `flows_raw`**.

Используем только агрегаты:

| Период UI | Источники / Назначения | Пары |
|-----------|-------------------------|------|
| до 1 часа включительно | `default.traffic_talker_1m` | `default.traffic_pair_1m` |
| 3h / 6h / 12h / 24h и больше | `default.traffic_talker_1h` | `default.traffic_pair_1h` |

Почему так:

- минутные таблицы очень детальные и хранятся только 2 дня;
- часовые таблицы быстрее для 12h/24h и хранятся 90 дней;
- `traffic_talker_*` хранит endpoints по одной стороне: `src` или `dst`;
- `traffic_pair_*` хранит пары `src_ip -> dst_ip`.

В коде API сделайте простую функцию:

```text
period <= 1h  -> suffix = 1m, time_column = minute
period > 1h   -> suffix = 1h, time_column = hour
```

---

## 3. Направления

В ClickHouse реальные направления:

```text
in
out
transit
internal
unknown
```

В UI может быть пункт **«Всего»**.

Важно: в таблицах **нет** `direction = 'total'`.

Если пользователь выбрал **Всего**, в SQL надо передать все реальные направления:

```sql
AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')
```

Если пользователь выбрал **Исходящий**:

```sql
AND direction IN ('out')
```

Если пользователь выбрал **Входящий**:

```sql
AND direction IN ('in')
```

Если пользователь выбрал несколько направлений, например входящий + исходящий:

```sql
AND direction IN ('in', 'out')
```

---

## 4. Период

В API лучше передавать явные даты:

```text
ts_from
ts_to
```

Пример для последнего часа:

```sql
now() - INTERVAL 1 HOUR AS ts_from,
now() AS ts_to
```

В запросах ниже для простоты стоит последний час. В коде UI/API заменить на параметры.

---

## 5. Источники данных

По умолчанию использовать только источники, включенные в total:

```sql
INNER JOIN default.net_flow_sources_enabled AS s ON t.source_id = s.source_id
WHERE s.include_in_total = 1
```

Если в UI выбран конкретный `source_id`, добавить:

```sql
AND t.source_id IN ('xdp-default')
```

Не суммировать все `source_id` без фильтра: разные источники могут видеть один и тот же трафик.

---

## 6. Формат строки в UI

В основной таблице показываем только короткий набор:

```text
IP / DNS | ASN | GEO | Объём данных
```

Не показываем в основной строке PPS, flow count, scope и прочее — это уходит в раскрытие строки.

### Источники / Назначения

| Колонка UI | Поле |
|------------|------|
| IP / DNS | `endpoint_label` если не пустой, иначе `endpoint_ip`; IP можно второй строкой |
| ASN | `endpoint_as_name`, ниже `AS endpoint_asn` |
| GEO | `endpoint_ip_country` |
| Объём данных | `traffic_gb` / `traffic_tb` |

### Пары

| Колонка UI | Поле |
|------------|------|
| IP / DNS | `src_ip -> dst_ip` |
| ASN | `src_as_name -> dst_as_name`, ниже `AS src_asn -> AS dst_asn` |
| GEO | `src_ip_country -> dst_ip_country` |
| Объём данных | `traffic_gb` / `traffic_tb` |

Progress bar считать на фронте:

```text
bar_width = traffic_gb / traffic_gb первой строки
```

Не считать `share_percent` в SQL для таблицы — это замедляет запросы и не нужно для progress bar.

---

## 6.1. Раскрытие строки

При клике на строку показываем все поля, которые уже вернул запрос.

### Источники / Назначения

```text
IP: endpoint_ip
Label / DNS: endpoint_label
ASN: endpoint_as_name
ASN number: endpoint_asn
IP GEO: endpoint_ip_country
ASN GEO: endpoint_as_country
Scope: endpoint_scope
Network name: endpoint_network_name
Network role: endpoint_network_role
Traffic: traffic_gb
Average speed: avg_gbps
Average PPS: avg_pps
Flows: flow_count
Direction: выбранный фильтр
Side: endpoint_side
Period: ts_from - ts_to
```

### Пары

```text
Source IP: src_ip
Source label: src_label
Source ASN: src_as_name / AS src_asn
Source IP GEO: src_ip_country
Source ASN GEO: src_as_country
Source scope: src_scope

Destination IP: dst_ip
Destination label: dst_label
Destination ASN: dst_as_name / AS dst_asn
Destination IP GEO: dst_ip_country
Destination ASN GEO: dst_as_country
Destination scope: dst_scope

Traffic: traffic_gb
Average speed: avg_gbps
Average PPS: avg_pps
Flows: flow_count
Direction: выбранный фильтр
Period: ts_from - ts_to
```

---

## 7. Вкладка «Источники»

Для периода 12h использовать таблицу:

```text
default.traffic_talker_1h
```

Фильтр:

```sql
endpoint_side = 'src'
```

Пример: **исходящий трафик, 12 часов, источники**.

```sql
WITH
    now() AS ts_to,
    ts_to - INTERVAL 12 HOUR AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    endpoint_ip,
    endpoint_label,
    endpoint_asn,
    endpoint_as_name,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_network_name,
    endpoint_network_role,
    traffic_gb,
    avg_gbps,
    avg_pps,
    flow_count
FROM
(
    SELECT
        t.endpoint_ip,
        t.endpoint_label,
        t.endpoint_asn,
        t.endpoint_as_name,
        t.endpoint_ip_country,
        t.endpoint_as_country,
        t.endpoint_scope,
        t.endpoint_network_name,
        t.endpoint_network_role,
        sum(t.bytes) AS total_bytes,
        round(sum(t.bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
        round((sum(t.bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
        round(sum(t.packets) / window_seconds, 0) AS avg_pps,
        sum(t.flows_count) AS flow_count
    FROM default.traffic_talker_1h AS t
    INNER JOIN default.net_flow_sources_enabled AS s ON t.source_id = s.source_id
    WHERE
        s.include_in_total = 1
        AND t.hour >= ts_from
        AND t.hour < ts_to
        AND t.direction IN ('out')
        AND t.endpoint_side = 'src'
    GROUP BY
        t.endpoint_ip,
        t.endpoint_label,
        t.endpoint_asn,
        t.endpoint_as_name,
        t.endpoint_ip_country,
        t.endpoint_as_country,
        t.endpoint_scope,
        t.endpoint_network_name,
        t.endpoint_network_role
) AS agg
ORDER BY traffic_gb DESC
LIMIT 20;
```

Как читать:

```text
direction = out + endpoint_side = src
= кто из нашей сети больше всего отправляет наружу
```

---

## 8. Вкладка «Назначения»

Для периода 12h использовать ту же часовую таблицу:

```text
default.traffic_talker_1h
```

Фильтр:

```sql
endpoint_side = 'dst'
```

Пример: **исходящий трафик, 12 часов, назначения**.

```sql
WITH
    now() AS ts_to,
    ts_to - INTERVAL 12 HOUR AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    endpoint_ip,
    endpoint_label,
    endpoint_asn,
    endpoint_as_name,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_network_name,
    endpoint_network_role,
    traffic_gb,
    avg_gbps,
    avg_pps,
    flow_count
FROM
(
    SELECT
        t.endpoint_ip,
        t.endpoint_label,
        t.endpoint_asn,
        t.endpoint_as_name,
        t.endpoint_ip_country,
        t.endpoint_as_country,
        t.endpoint_scope,
        t.endpoint_network_name,
        t.endpoint_network_role,
        sum(t.bytes) AS total_bytes,
        round(sum(t.bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
        round((sum(t.bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
        round(sum(t.packets) / window_seconds, 0) AS avg_pps,
        sum(t.flows_count) AS flow_count
    FROM default.traffic_talker_1h AS t
    INNER JOIN default.net_flow_sources_enabled AS s ON t.source_id = s.source_id
    WHERE
        s.include_in_total = 1
        AND t.hour >= ts_from
        AND t.hour < ts_to
        AND t.direction IN ('out')
        AND t.endpoint_side = 'dst'
    GROUP BY
        t.endpoint_ip,
        t.endpoint_label,
        t.endpoint_asn,
        t.endpoint_as_name,
        t.endpoint_ip_country,
        t.endpoint_as_country,
        t.endpoint_scope,
        t.endpoint_network_name,
        t.endpoint_network_role
) AS agg
ORDER BY traffic_gb DESC
LIMIT 20;
```

Как читать:

```text
direction = out + endpoint_side = dst
= куда мы больше всего отправляем наружу
```

---

## 9. Вкладка «Пары»

Для периода 12h использовать часовую таблицу:

```text
default.traffic_pair_1h
```

Пример: **исходящий трафик, 12 часов, пары**.

```sql
WITH
    now() AS ts_to,
    ts_to - INTERVAL 12 HOUR AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    src_ip,
    dst_ip,
    src_asn,
    dst_asn,
    src_as_name,
    dst_as_name,
    src_ip_country,
    dst_ip_country,
    src_as_country,
    dst_as_country,
    src_scope,
    dst_scope,
    src_label,
    dst_label,
    traffic_gb,
    avg_gbps,
    avg_pps,
    flow_count
FROM
(
    SELECT
        p.src_ip,
        p.dst_ip,
        p.src_asn,
        p.dst_asn,
        p.src_as_name,
        p.dst_as_name,
        p.src_ip_country,
        p.dst_ip_country,
        p.src_as_country,
        p.dst_as_country,
        p.src_scope,
        p.dst_scope,
        p.src_label,
        p.dst_label,
        sum(p.bytes) AS total_bytes,
        round(sum(p.bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
        round((sum(p.bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
        round(sum(p.packets) / window_seconds, 0) AS avg_pps,
        sum(p.flows_count) AS flow_count
    FROM default.traffic_pair_1h AS p
    INNER JOIN default.net_flow_sources_enabled AS s ON p.source_id = s.source_id
    WHERE
        s.include_in_total = 1
        AND p.hour >= ts_from
        AND p.hour < ts_to
        AND p.direction IN ('out')
    GROUP BY
        p.src_ip,
        p.dst_ip,
        p.src_asn,
        p.dst_asn,
        p.src_as_name,
        p.dst_as_name,
        p.src_ip_country,
        p.dst_ip_country,
        p.src_as_country,
        p.dst_as_country,
        p.src_scope,
        p.dst_scope,
        p.src_label,
        p.dst_label
) AS agg
ORDER BY traffic_gb DESC
LIMIT 20;
```

Как читать:

```text
direction = out
= наш IP -> внешний IP
```

---

## 10. Как менять запросы под фильтры

### Период

Менять:

```sql
ts_from
ts_to
таблицу
time_column
```

Например последние 24 часа:

```sql
now() AS ts_to,
ts_to - INTERVAL 24 HOUR AS ts_from
```

Выбор таблицы:

```text
до 1h     -> traffic_talker_1m / traffic_pair_1m, колонка времени minute
больше 1h -> traffic_talker_1h / traffic_pair_1h, колонка времени hour
```

### Направление

Менять только массив в:

```sql
AND t.direction IN (...)
```

или для пар:

```sql
AND p.direction IN (...)
```

Примеры:

```sql
-- Входящий
AND t.direction IN ('in')

-- Исходящий
AND t.direction IN ('out')

-- Всего
AND t.direction IN ('in', 'out', 'transit', 'internal', 'unknown')
```

### Вкладка

Для `traffic_talker_1m` / `traffic_talker_1h`:

```sql
-- Источники
AND t.endpoint_side = 'src'

-- Назначения
AND t.endpoint_side = 'dst'
```

Для `Пары` использовать отдельную таблицу:

```text
default.traffic_pair_1m или default.traffic_pair_1h
```

---

## 11. Как подписывать строки в UI

### Источники / Назначения

Основная строка:

```text
endpoint_label или endpoint_ip
```

Если `endpoint_label` пустой, показывать `endpoint_ip`.

Вторая строка:

```text
endpoint_as_name
AS endpoint_asn
```

GEO:

```text
endpoint_ip_country
```

Если `endpoint_ip_country = '??'`, показывать:

```text
Неизвестно
```

### Пары

Основная строка:

```text
src_ip -> dst_ip
```

Вторая строка:

```text
src_as_name -> dst_as_name
```

GEO:

```text
src_ip_country -> dst_ip_country
```

---

## 12. Метрики

Сортировка:

```text
traffic_gb DESC
```

Основная колонка «Объём данных»:

```text
traffic_gb / traffic_tb
```

В раскрытии строки:

```text
avg_gbps
avg_pps
flow_count
```

Progress bar:

```text
traffic_gb / traffic_gb первой строки
```

Для референса проще использовать `traffic_gb / max(traffic_gb)` внутри фронта, чтобы первая строка была 100% ширины.

---

## 13. Чеклист

- [ ] Вкладка `Источники` использует `traffic_talker_1m/1h` + `endpoint_side = 'src'`.
- [ ] Вкладка `Назначения` использует `traffic_talker_1m/1h` + `endpoint_side = 'dst'`.
- [ ] Вкладка `Пары` использует `traffic_pair_1m/1h`.
- [ ] Для 12h/24h используются часовые таблицы `*_1h`.
- [ ] `Всего` не отправляет `direction = 'total'`, а отправляет список реальных направлений.
- [ ] По умолчанию используется `s.include_in_total = 1`.
- [ ] Таблица сортируется по `traffic_gb DESC`.
- [ ] `??` отображается как «Неизвестно».
- [ ] Если label пустой, показывается IP.
- [ ] Для пар показываются обе стороны: source и destination.
- [ ] Основная строка показывает только `IP / DNS`, `ASN`, `GEO`, `Объём данных`.
- [ ] Подробные поля показываются только в раскрытии строки.

