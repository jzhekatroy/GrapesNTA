# ТЗ для UI: справочник сервисов и портов

Документ для junior UI developer.

Нужно сделать экран настройки справочника `port/range -> service`, чтобы оператор мог
добавлять, менять и отключать соответствия портов или диапазонов портов сервисам. Эти соответствия
используются в отчётах по сервисам: `HTTPS`, `DNS`, `SIP`, `MySQL`, категории
`web`, `dns`, `voip`, `database` и т.д.

---

## 1. Зачем это нужно

В сырых flows есть только транспортный протокол и порты:

```text
proto=6, dst_port=443
proto=17, dst_port=53
```

Пользователю в UI нужно видеть не только `tcp/443`, а понятное имя:

```text
tcp/443 -> HTTPS -> web
udp/53  -> DNS   -> dns
udp/443 -> QUIC  -> web
tcp/8000-8999 -> Web Alternate -> web
```

Для этого есть справочник ClickHouse:

- таблица для записи: `default.port_services`;
- view для чтения активных записей: `default.port_services_enabled`;
- техническое view для классификации по одиночным портам:
  `default.port_services_expanded_enabled`;
- DDL: `deploy/clickhouse/port_services.sql`.

UI не создаёт таблицу сам. Таблица создаётся deploy-скриптами.

Схема хранит диапазоны через `port_from` и `port_to`. Для быстрой агрегации есть
expanded view, где диапазон разворачивается в отдельные порты.

Структура `default.port_services`:

```text
transport
port_from
port_to
service_code
service_name
category
description
is_enabled
updated_at
```

Для обратной совместимости одиночный порт хранится как диапазон из одного
значения: `port_from = port_to = 443`.

---

## 2. Что должно быть на экране

Название экрана: **Сервисы / порты**.

Основная таблица:

| Колонка | Откуда | Пример |
|---------|--------|--------|
| Транспорт | `transport` | `tcp` |
| Порт / диапазон | `port_from`, `port_to` | `443` или `8000-8999` |
| Код сервиса | `service_code` | `https` |
| Название | `service_name` | `HTTPS` |
| Категория | `category` | `web` |
| Описание | `description` | `HTTP over TLS` |
| Обновлено | `updated_at` | `2026-06-10 10:00:00` |

Действия:

- добавить сервис;
- редактировать сервис;
- отключить сервис;
- поиск по порту, коду, названию, категории;
- фильтр по `transport`;
- фильтр по `category`.

Удалять физически из ClickHouse не нужно. Кнопка «Удалить» в UI должна означать
«Отключить» (`is_enabled = 0`).

---

## 3. Поля формы

| Поле | Тип / правило | Обязательное | Пример |
|------|---------------|--------------|--------|
| `transport` | select: `tcp`, `udp`, `sctp`, `icmp`, `icmpv6` | да | `tcp` |
| `port_mode` | select: `single`, `range` | да | `range` |
| `port` | число `0..65535`, если `single` | да для `single` | `443` |
| `port_from` | число `0..65535`, если `range` | да для `range` | `8000` |
| `port_to` | число `0..65535`, если `range` | да для `range` | `8999` |
| `service_code` | латиница, цифры, `_`, lowercase | да | `https` |
| `service_name` | строка | да | `HTTPS` |
| `category` | строка/select | да | `web` |
| `description` | строка | нет | `HTTP over TLS` |
| `is_enabled` | boolean | да | `1` |

Модель ключа: `(transport, port_from, port_to)`.

Примеры:

- `tcp/443 = HTTPS`;
- `udp/443 = QUIC`;
- `tcp/8000-8999 = Web Alternate`;
- `udp/10000-20000 = RTP`;
- `tcp/443` и `udp/443` — разные записи, потому что разный `transport`.

Нельзя создавать пересекающиеся активные правила для одного `transport`.
Например, если уже есть `tcp/8000-8999`, нельзя добавить `tcp/8443`, пока не
отключить старое правило или не разбить диапазон на части. Это упрощает
классификацию и убирает неоднозначность.

---

## 4. Как читать список

Для списка активных сервисов использовать только view:

```sql
SELECT
    transport,
    port_from,
    port_to,
    if(port_from = port_to, toString(port_from), concat(toString(port_from), '-', toString(port_to))) AS port_label,
    service_code,
    service_name,
    category,
    description,
    updated_at
FROM default.port_services_enabled
ORDER BY transport, port_from, port_to
FORMAT JSON;
```

Для поиска по строке:

```sql
SELECT
    transport,
    port_from,
    port_to,
    if(port_from = port_to, toString(port_from), concat(toString(port_from), '-', toString(port_to))) AS port_label,
    service_code,
    service_name,
    category,
    description,
    updated_at
FROM default.port_services_enabled
WHERE
    positionCaseInsensitive(service_code, {search:String}) > 0
    OR positionCaseInsensitive(service_name, {search:String}) > 0
    OR positionCaseInsensitive(category, {search:String}) > 0
    OR toString(port_from) = {search:String}
    OR toString(port_to) = {search:String}
ORDER BY transport, port_from, port_to
LIMIT 200
FORMAT JSON;
```

Если поиск пустой, не добавлять блок `WHERE`.

---

## 5. Как сохранять изменения

Таблица `default.port_services` использует `ReplacingMergeTree(updated_at)`.
Поэтому изменения делаются через `INSERT`, а не через `ALTER UPDATE`.

Создание или редактирование:

```sql
INSERT INTO default.port_services
    (transport, port_from, port_to, service_code, service_name, category, description, is_enabled, updated_at)
VALUES
    (
        {transport:String},
        {port_from:UInt16},
        {port_to:UInt16},
        {service_code:String},
        {service_name:String},
        {category:String},
        {description:String},
        1,
        now()
    );
```

Отключение:

```sql
INSERT INTO default.port_services
    (transport, port_from, port_to, service_code, service_name, category, description, is_enabled, updated_at)
VALUES
    (
        {transport:String},
        {port_from:UInt16},
        {port_to:UInt16},
        {service_code:String},
        {service_name:String},
        {category:String},
        {description:String},
        0,
        now()
    );
```

После успешного сохранения UI должен перечитать список из
`default.port_services_enabled`.

Для одиночного порта UI должен отправлять `port_from = port_to = port`.
Например, `tcp/443` сохраняется как `port_from=443`, `port_to=443`.

---

## 6. Как изменения применяются к отчётам

Справочник используется в materialized view `default.traffic_service_1m_mv`.
Для производительности MV не должна делать join по условию
`port BETWEEN port_from AND port_to` на каждом flow.

- `default.port_services_enabled` — показывает правила для UI;
- `default.port_services_expanded_enabled` — техническое view/table для
  агрегации, где диапазоны развёрнуты в отдельные порты;
- `traffic_service_1m_mv` делает быстрый join по равенству
  `transport + port`.

Пример:

```text
tcp/8000-8002 -> Web Alternate
```

в expanded-слое становится:

```text
tcp/8000 -> Web Alternate
tcp/8001 -> Web Alternate
tcp/8002 -> Web Alternate
```

Так мы поддерживаем диапазоны в UI, но не замедляем агрегацию по `flows_raw`.

Практически это значит:

- новые flows после изменения справочника будут классифицироваться по новым
  правилам автоматически;
- уже рассчитанные старые строки в `traffic_service_1m` не изменятся сами;
- для изменения истории нужен отдельный rebuild/backfill агрегата за выбранный
  период;
- UI не должен запускать rebuild синхронно при сохранении записи.

Пример: если оператор поменял `tcp/8443` с `unknown` на `HTTPS Alternate`, новые
данные начнут попадать в сервис `HTTPS Alternate`. История за вчера останется
старой, пока не будет выполнен пересчёт агрегата.

---

## 7. Как это связано с виджетами

Виджеты top services / traffic by service должны читать уже готовый агрегат
`default.traffic_service_1m`, а не джойниться к `flows_raw` каждый раз.

Пример запроса:

```sql
SELECT
    service_code,
    service_name,
    category,
    transport,
    service_port,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows
FROM default.traffic_service_1m
WHERE minute >= {from:DateTime}
  AND minute < {to:DateTime}
  AND source_id IN ({source_ids:Array(String)})
GROUP BY
    service_code,
    service_name,
    category,
    transport,
    service_port
ORDER BY bytes DESC
LIMIT 50
FORMAT JSON;
```

---

## 8. Валидация и проверка пересечений

Перед сохранением проверить:

- `transport` выбран;
- если режим `single`: `port` в диапазоне `0..65535`;
- если режим `range`: `port_from` и `port_to` в диапазоне `0..65535`;
- если режим `range`: `port_from <= port_to`;
- `service_code` не пустой и содержит только `a-z`, `0-9`, `_`;
- `service_name` не пустой;
- `category` не пустая;
- новое правило не пересекается с другим активным правилом того же `transport`.

Проверка пересечений обязательна на backend перед `INSERT`. Проверка только на
frontend недостаточна: два оператора могут сохранить пересекающиеся диапазоны
почти одновременно.

Два диапазона пересекаются, если:

```text
existing.port_from <= new.port_to
AND existing.port_to >= new.port_from
```

Примеры пересечений:

```text
new tcp/8443 пересекается с existing tcp/8000-8999
new udp/15000-16000 пересекается с existing udp/10000-20000
new tcp/80-90 пересекается с existing tcp/90-100
```

Примеры НЕ пересечений:

```text
new tcp/443 НЕ пересекается с existing udp/443, потому что transport разный
new tcp/9000-9999 НЕ пересекается с existing tcp/8000-8999
```

SQL проверки перед созданием новой записи:

```sql
SELECT
    transport,
    port_from,
    port_to,
    if(port_from = port_to, toString(port_from), concat(toString(port_from), '-', toString(port_to))) AS port_label,
    service_code,
    service_name,
    category
FROM default.port_services_enabled
WHERE transport = {transport:String}
  AND port_from <= {port_to:UInt16}
  AND port_to >= {port_from:UInt16}
ORDER BY port_from, port_to
FORMAT JSON;
```

Если запрос вернул хотя бы одну строку, сохранять нельзя. UI должен показать
ошибку:

```text
Диапазон пересекается с существующим правилом: tcp/8000-8999 Web Alternate.
Измените диапазон или отключите старое правило.
```

При редактировании текущей записи есть два варианта:

1. Если оператор меняет только `service_code`, `service_name`, `category` или
   `description`, но не меняет `transport/port_from/port_to`, пересечение с этой
   же записью допустимо. Backend может просто вставить новую версию.
2. Если оператор меняет сам диапазон, сначала проверить пересечения нового
   диапазона с другими активными правилами. Если backend не умеет отличать
   «саму себя», проще сделать это в два шага: отключить старую запись
   (`is_enabled=0`), затем создать новую.

Нельзя автоматически выбирать «более точное» правило, например одиночный порт
поверх широкого диапазона. В MVP пересечения запрещены полностью, чтобы отчёты
были однозначными.

---

## 9. Что не делать

- Не делать `ALTER TABLE ... UPDATE`.
- Не делать физический `DELETE`.
- Не читать напрямую `default.port_services` для обычного списка, там есть
  старые версии записей.
- Не делать join по диапазону прямо из `flows_raw` в пользовательских виджетах.
  Виджеты должны читать готовый `traffic_service_1m`.
- Не пересчитывать `traffic_service_1m` при каждом сохранении справочника.
- Не хранить соответствия портов только в frontend-коде: источник истины —
  ClickHouse.

---

## 10. Deploy-заметка

Для новой БД достаточно применить:

```bash
clickhouse-client --multiquery < deploy/clickhouse/port_services.sql
clickhouse-client --multiquery < deploy/clickhouse/traffic_service_1m.sql
clickhouse-client --multiquery < deploy/clickhouse/traffic_unknown_port_1m.sql
```

Для уже существующей БД, где `port_services` была создана со старым полем
`port`, сначала выполнить миграцию:

```bash
CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
  ./deploy/clickhouse/migrate_port_services_ranges.sh
```

Скрипт сохранит старую таблицу как `port_services_backup_<timestamp>`, перенесёт
все одиночные порты в формат `port_from = port_to` и создаст views
`port_services_enabled` / `port_services_expanded_enabled`.

После миграции нужно пересоздать materialized views:

```bash
clickhouse-client --multiquery < deploy/clickhouse/migrate_port_service_rollups_ranges.sql
```

Этот migration SQL сохраняет уже накопленные таблицы `traffic_service_1m` и
`traffic_unknown_port_1m`, пересоздаёт только materialized views. Исторические
строки останутся классифицированы по старым правилам; для истории нужен
отдельный backfill.
