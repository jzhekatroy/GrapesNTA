# ТЗ: вкладка UI «DNS-запросы»



---

## 1. Что показывает вкладка

Вкладка отвечает на вопросы:

- сколько DNS-запросов идёт сейчас;
- какие домены спрашивают чаще всего;
- какие клиенты генерируют больше всего DNS;
- много ли ошибок `NXDOMAIN` / `SERVFAIL`;
- какие последние DNS-запросы были видны.

Минимальный экран:

```text
DNS-запросы

[Период: 30 минут] [Источник DNS] [QTYPE] [RCODE] [Поиск домена] [Client IP]

1. График DNS activity
   Queries/s | Responses/s | NXDOMAIN/s | SERVFAIL/s

2. Top domains
   Domain | QTYPE | Queries | Responses | NXDOMAIN | SERVFAIL

3. Top clients
   Client IP | Queries | Unique domains | NXDOMAIN | SERVFAIL

4. Last DNS queries
   Time | Client | Server | Query | QTYPE | RCODE | Answers
```

---

## 2. Важные понятия простыми словами

### Queries/s

Сколько DNS-запросов в секунду видит система.

### Responses/s

Сколько DNS-ответов в секунду видит система.

### NXDOMAIN

DNS-сервер ответил: «такого домена не существует».

В таблице это `rcode = 3`.

Рост `NXDOMAIN` может означать:

- мусорные запросы;
- malware / DGA;
- ошибку в приложении;
- DNS abuse / flood.

### SERVFAIL

DNS-сервер ответил: «я не смог обработать запрос».

В таблице это `rcode = 2`.

Рост `SERVFAIL` чаще говорит о проблемах DNS-инфраструктуры:

- upstream DNS не отвечает;
- DNSSEC validation failed;
- перегрузка DNS;
- сетевые проблемы до authoritative DNS.

---

## 3. Есть ли направления in/out/transit/internal

В `dns_log` готового поля `direction` **нет**.

Есть только:

- `is_response = 0` — DNS query;
- `is_response = 1` — DNS response.

Это не то же самое, что `in/out/transit/internal` у traffic flows.

Для MVP во вкладке DNS не показываем направления `in/out/transit/internal`.
Показываем `queries`, `responses`, `client_ip`, `server_ip`.

Позже можно добавить отдельное вычисляемое поле `network_direction`, но для этого
нужно классифицировать `client_ip` и `server_ip` через локальные префиксы.

---

## 4. Таблицы ClickHouse

### 4.1. `default.dns_log`

Одна строка = один DNS query или DNS response.

Основные поля:

| Поле | Что значит |
|------|------------|
| `ts` | время события |
| `source_id` | источник DNS-данных |
| `client_ip` | клиент, который делает DNS-запрос |
| `server_ip` | DNS-сервер |
| `client_port` | порт клиента |
| `server_port` | обычно 53 |
| `is_response` | `0` = query, `1` = response |
| `query_name` | домен |
| `qtype` | тип запроса: `TypeA`, `TypeAAAA`, `TypeTXT`, `TypeALL`, ... |
| `rcode` | код ответа DNS |
| `answers_a` | массив IPv4-ответов |
| `answers_aaaa` | массив IPv6-ответов |
| `answers_cname` | массив CNAME-ответов |
| `raw_size` | размер DNS-пакета |

### 4.2. `default.dns_answers`

Разложенные DNS-ответы.

Одна строка = один `A` или `AAAA` ответ.

Используется для обогащения IP:

```text
answer_ip -> query_name
```

Например, в деталях IP можно показать: «этот IP недавно резолвился из таких
доменов».

---

## 5. Нужны ли агрегаты

Для MVP агрегаты **не нужны**.

Проверка на production data:

```text
dns_log: 16.7 млрд строк за 30 дней

30 минут, график по минутам:  ~0.05s
6 часов, график по 5 минутам: ~0.34s
Top domains за 30 минут:     ~0.17s
Top clients за 30 минут:     ~0.39s
```

Значит UI можно строить напрямую по `default.dns_log`.

Агрегаты добавить позже, если:

- запросы за 24h/7d станут медленнее 1-2 секунд;
- появится много пользователей с автообновлением;
- появятся тяжёлые отчёты по неделям/месяцам.

---

## 6. Общие параметры API

UI передаёт:

```text
period: 30m | 1h | 3h | 6h | 12h | 24h
source_ids: optional array
qtype: optional string
rcode: optional number
domain_search: optional string
client_ip: optional string
limit: default 50
```

В API не передавать произвольный SQL interval от пользователя. Делать whitelist:

```text
30m -> INTERVAL 30 MINUTE
1h  -> INTERVAL 1 HOUR
3h  -> INTERVAL 3 HOUR
6h  -> INTERVAL 6 HOUR
12h -> INTERVAL 12 HOUR
24h -> INTERVAL 24 HOUR
```

Для первого MVP достаточно `30m` и `6h`.

---

## 7. Source filter

DNS-источники лежат в общем справочнике `default.net_flow_sources_enabled`, где
`source_type = 'dns'`.

Список DNS-источников для фильтра:

```sql
SELECT
    source_id,
    display_name,
    collector_id,
    location
FROM default.net_flow_sources_enabled
WHERE source_type = 'dns'
ORDER BY display_name
FORMAT JSON
```

Если пользователь не выбрал source, показываем все DNS-источники:

```sql
AND source_id IN
(
    SELECT source_id
    FROM default.net_flow_sources_enabled
    WHERE source_type = 'dns'
)
```

Если выбрал конкретные:

```sql
AND source_id IN ('dns-netflow', 'dns-default')
```

---

## 8. Helper: IP to string

В `dns_log` IP хранится как `FixedString(16)`.

Для IPv4 в этом проекте используется формат: IPv4 лежит в первых 4 байтах,
остальные 12 байт — нули.

В запросах используем такое выражение:

```sql
if(
    length(client_ip) = 16
    AND substring(client_ip, 5) = unhex('000000000000000000000000'),
    toString(toIPv4(reinterpretAsUInt32(reverse(substring(client_ip, 1, 4))))),
    IPv6NumToString(client_ip)
) AS client
```

Для `server_ip` аналогично заменить `client_ip` на `server_ip`.

---

## 9. Виджет 1: DNS activity chart

Назначение: основной график DNS-активности.

Линии:

- `queries/s`;
- `responses/s`;
- `nxdomain/s`;
- `servfail/s`.

### 30 минут, bucket = 1 minute

```sql
SELECT
    toStartOfMinute(ts) AS bucket,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail,
    round(queries / 60, 2) AS qps,
    round(responses / 60, 2) AS responses_per_sec,
    round(nxdomain / 60, 2) AS nxdomain_per_sec,
    round(servfail / 60, 2) AS servfail_per_sec
FROM default.dns_log
WHERE ts >= now() - INTERVAL 30 MINUTE
  AND source_id IN
  (
      SELECT source_id
      FROM default.net_flow_sources_enabled
      WHERE source_type = 'dns'
  )
GROUP BY bucket
ORDER BY bucket
FORMAT JSON
```

### 6 часов, bucket = 5 minutes

```sql
SELECT
    toStartOfFiveMinutes(ts) AS bucket,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail,
    round(queries / 300, 2) AS qps,
    round(responses / 300, 2) AS responses_per_sec,
    round(nxdomain / 300, 2) AS nxdomain_per_sec,
    round(servfail / 300, 2) AS servfail_per_sec
FROM default.dns_log
WHERE ts >= now() - INTERVAL 6 HOUR
  AND source_id IN
  (
      SELECT source_id
      FROM default.net_flow_sources_enabled
      WHERE source_type = 'dns'
  )
GROUP BY bucket
ORDER BY bucket
FORMAT JSON
```

UI:

- X-axis: `bucket`;
- Y-axis: values per second;
- tooltip: show raw counts and per-second values.

---

## 10. Виджет 2: KPI cards

Карточки сверху:

```text
DNS QPS
Responses/s
NXDOMAIN %
SERVFAIL %
Unique clients
Unique domains
```

Запрос:

```sql
WITH
    1800 AS window_seconds
SELECT
    round(countIf(is_response = 0) / window_seconds, 2) AS qps,
    round(countIf(is_response = 1) / window_seconds, 2) AS responses_per_sec,
    round(countIf(is_response = 1 AND rcode = 3) * 100.0 / nullIf(countIf(is_response = 1), 0), 2) AS nxdomain_percent,
    round(countIf(is_response = 1 AND rcode = 2) * 100.0 / nullIf(countIf(is_response = 1), 0), 2) AS servfail_percent,
    uniqExact(client_ip) AS unique_clients,
    uniqExact(query_name) AS unique_domains
FROM default.dns_log
WHERE ts >= now() - INTERVAL 30 MINUTE
  AND source_id IN
  (
      SELECT source_id
      FROM default.net_flow_sources_enabled
      WHERE source_type = 'dns'
  )
FORMAT JSON
```

Для другого периода поменять `window_seconds`:

```text
30m -> 1800
1h  -> 3600
6h  -> 21600
```

---

## 11. Виджет 3: Top domains

Главная таблица доменов.

Колонки:

```text
Domain | QTYPE | Queries | Responses | NXDOMAIN | SERVFAIL | Error %
```

Запрос:

```sql
SELECT
    query_name,
    qtype,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail,
    round((nxdomain + servfail) * 100.0 / nullIf(responses, 0), 2) AS error_percent
FROM default.dns_log
WHERE ts >= now() - INTERVAL 30 MINUTE
  AND source_id IN
  (
      SELECT source_id
      FROM default.net_flow_sources_enabled
      WHERE source_type = 'dns'
  )
GROUP BY
    query_name,
    qtype
ORDER BY queries DESC
LIMIT 50
FORMAT JSON
```

UI rules:

- если `error_percent > 20`, подсветить строку;
- `query_name` показывать полностью в tooltip;
- длинные домены в таблице обрезать через ellipsis.

---

## 12. Виджет 4: Top clients

Показывает, какие IP генерируют больше всего DNS-запросов.

Колонки:

```text
Client IP | Queries | Unique domains | NXDOMAIN | SERVFAIL | Error %
```

Запрос:

```sql
SELECT
    if(
        length(client_ip) = 16
        AND substring(client_ip, 5) = unhex('000000000000000000000000'),
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(client_ip, 1, 4))))),
        IPv6NumToString(client_ip)
    ) AS client,
    countIf(is_response = 0) AS queries,
    uniqExact(query_name) AS unique_domains,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail,
    round((nxdomain + servfail) * 100.0 / nullIf(countIf(is_response = 1), 0), 2) AS error_percent
FROM default.dns_log
WHERE ts >= now() - INTERVAL 30 MINUTE
  AND source_id IN
  (
      SELECT source_id
      FROM default.net_flow_sources_enabled
      WHERE source_type = 'dns'
  )
GROUP BY client
ORDER BY queries DESC
LIMIT 50
FORMAT JSON
```

UI rules:

- клик по `Client IP` открывает фильтр `client_ip = ...`;
- рядом можно добавить кнопку «искать в Top Talkers»;
- если `unique_domains` очень большое, это может быть скан/бот/DGA.

---

## 13. Виджет 5: Last DNS queries

Показывает последние DNS-события.

Колонки:

```text
Time | Client | Server | Query | QTYPE | RCODE | Answers
```

Запрос:

```sql
SELECT
    toString(ts) AS ts,
    source_id,
    if(
        length(client_ip) = 16
        AND substring(client_ip, 5) = unhex('000000000000000000000000'),
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(client_ip, 1, 4))))),
        IPv6NumToString(client_ip)
    ) AS client,
    if(
        length(server_ip) = 16
        AND substring(server_ip, 5) = unhex('000000000000000000000000'),
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(server_ip, 1, 4))))),
        IPv6NumToString(server_ip)
    ) AS server,
    if(is_response = 1, 'response', 'query') AS event_type,
    query_name,
    qtype,
    rcode,
    answers_cname,
    arrayMap(x -> toString(toIPv4(reinterpretAsUInt32(reverse(substring(x, 1, 4)))))), answers_a) AS answers_a,
    arrayMap(x -> IPv6NumToString(x), answers_aaaa) AS answers_aaaa,
    raw_size
FROM default.dns_log
WHERE ts >= now() - INTERVAL 30 MINUTE
  AND source_id IN
  (
      SELECT source_id
      FROM default.net_flow_sources_enabled
      WHERE source_type = 'dns'
  )
ORDER BY ts DESC
LIMIT 100
FORMAT JSON
```

UI rules:

- `rcode = 0` показывать как `NOERROR`;
- `rcode = 2` показывать как `SERVFAIL`;
- `rcode = 3` показывать как `NXDOMAIN`;
- остальные можно показать как число.

---

## 14. Фильтры

### 14.1. QTYPE

Список доступных типов за период:

```sql
SELECT
    qtype,
    count() AS rows
FROM default.dns_log
WHERE ts >= now() - INTERVAL 30 MINUTE
GROUP BY qtype
ORDER BY rows DESC
LIMIT 50
FORMAT JSON
```

Фильтр в запросах:

```sql
AND qtype = 'TypeA'
```

### 14.2. RCODE

Фильтр:

```sql
AND rcode = 3
```

Подписи:

| rcode | Label |
|-------|-------|
| `0` | `NOERROR` |
| `2` | `SERVFAIL` |
| `3` | `NXDOMAIN` |

### 14.3. Поиск домена

Для MVP:

```sql
AND positionCaseInsensitive(query_name, 'cisco.com') > 0
```

Не запускать поиск без периода. Всегда должен быть `WHERE ts >= ...`.

### 14.4. Client IP

Если API получает `client_ip = '188.143.128.3'`, проще фильтровать в backend:

1. Преобразовать IP в тот же `FixedString(16)` формат.
2. Добавить:

```sql
AND client_ip = {client_ip_fixed}
```

Если пока нет helper-а в backend, можно на первом этапе не делать фильтр по IP.

---

## 15. DNS enrichment для IP details

Дополнительно, не обязательно для первого экрана.

Когда пользователь открыл детали IP, можно показать последние домены, которые
резолвились в этот IP.

Пример для IPv4 `1.2.3.4` нужно в backend преобразовать в `FixedString(16)`.

Запрос:

```sql
SELECT
    query_name,
    answer_type,
    count() AS answers,
    min(ts) AS first_seen,
    max(ts) AS last_seen
FROM default.dns_answers
WHERE ts >= now() - INTERVAL 24 HOUR
  AND answer_ip = {ip_fixed}
GROUP BY
    query_name,
    answer_type
ORDER BY last_seen DESC
LIMIT 50
FORMAT JSON
```

---

## 16. Что НЕ делать в MVP

- Не добавлять DNS в общий bandwidth / pps график.
- Не считать DNS как `in/out/transit/internal`.
- Не строить агрегаты заранее.
- Не делать поиск по домену без ограничения периода.
- Не использовать `dns_log` для подсчёта байтов трафика.

---

## 17. Acceptance criteria

Готово, если:

- есть вкладка `DNS-запросы`;
- график `Queries/s`, `Responses/s`, `NXDOMAIN/s`, `SERVFAIL/s` работает за 30m и 6h;
- есть таблицы `Top domains`, `Top clients`, `Last DNS queries`;
- все запросы используют период;
- данные можно фильтровать по DNS `source_id`;
- DNS не попадает в общий график bandwidth/pps;
- UI не падает на длинных доменах и больших числах.

