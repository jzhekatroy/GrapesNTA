# ТЗ: страница «Исключения из статистики» (Flow Exclusions)

Задача для фронтенд/фулстек-разработчика NTAdmin. Бэкенд коллекторов и схема
ClickHouse уже реализованы, менять их не нужно.

## 1. Что уже сделано (не трогать)

| Слой | Готово |
|------|--------|
| ClickHouse | таблица `default.net_flow_exclusions` + вью `default.net_flow_exclusions_enabled` (`deploy/schema/50_net/35..36`, миграция `deploy/clickhouse/net_flow_exclusions.sql`) |
| xdpflowd | читает вью раз в 60 с, выбрасывает совпавшие потоки **до** ClickHouse и **до** NetFlow v9 |
| flowcollectord | читает ту же вью, выбрасывает совпавшие строки до ClickHouse |
| Health | колонки `flow_rows_excluded`, `flow_packets_excluded`, `flow_bytes_excluded`, `exclusion_rules` в `collector_health_snapshots`; формула полноты в `deploy/ui/app/server/collector-completeness.js` уже учитывает исключённый объём |

Семантика: правило **выбрасывает** трафик. Данные не помечаются и не скрываются
— их физически нет ни в `flows_raw`, ни в роллапах, ни в NetFlow-экспорте.
Изменения действуют только на трафик, наблюдаемый после применения правила;
исторические данные не меняются.

## 2. Что нужно сделать

1. Серверный модуль `deploy/ui/app/server/flow-exclusions.js` (CRUD).
2. Роуты в `deploy/ui/app/server/index.js`.
3. Страница `deploy/ui/app/public/pages/flow-exclusions.jsx`.
4. Регистрация страницы в навигации и RBAC.

Эталон для копирования архитектуры — справочник CIDR:
`server/l3-prefixes.js` + `public/pages/cidr.jsx`. Модель та же:
`ReplacingMergeTree` + вью `_enabled`, запись через INSERT новой версии строки,
«удаление» через `DELETE FROM`, переключатель `enabled` через INSERT с новым
`updated_at`.

## 3. Схема таблицы

```sql
default.net_flow_exclusions
  rule_id      String                 -- ПЕРВИЧНЫЙ КЛЮЧ (ORDER BY rule_id)
  prefix       String   DEFAULT ''    -- CIDR, '' = условие не задано
  family       UInt8    DEFAULT 0     -- 4 | 6, выводится из prefix
  match_side   LowCardinality(String) DEFAULT 'any'  -- src | dst | any
  proto        UInt8    DEFAULT 0     -- 6=TCP, 17=UDP, 1=ICMP, 0 = любой
  port_from    UInt16   DEFAULT 0     -- 0/0 = любой порт
  port_to      UInt16   DEFAULT 0
  port_side    LowCardinality(String) DEFAULT 'any'  -- src | dst | any
  vlan_id      UInt16   DEFAULT 0     -- 0 = любой
  switch_ip    String   DEFAULT ''    -- IP экспортёра (sampler_address)
  if_index     UInt32   DEFAULT 0     -- SNMP ifIndex порта коммутатора
  source_id    LowCardinality(String) DEFAULT ''     -- '' = все коллекторы
  display_name String   DEFAULT ''
  comment      String   DEFAULT ''
  enabled      UInt8
  source       LowCardinality(String) DEFAULT 'manual'  -- UI пишет 'webui'
  updated_at   DateTime DEFAULT now()
ENGINE = ReplacingMergeTree(updated_at) ORDER BY rule_id
```

`rule_id` генерирует UI (например `crypto.randomUUID()`), пользователю он не
показывается — в таблице выводится `display_name`.

## 4. Логика сопоставления (что увидит оператор)

Заполненные поля правила объединяются по **И**. Пустое (нулевое) поле означает
«любой».

- `prefix` + `match_side=any` — совпадение, если префикс содержит **src или dst**.
  `src` / `dst` ограничивают сторону.
- `port_from`/`port_to` — диапазон включительно. Одно значение: заполнить оба
  поля одинаково. `port_side` ограничивает сторону порта.
- `switch_ip` + `if_index` — совпадение, если поток пришёл с этого экспортёра и
  `if_index` равен входному **или** выходному порту.
- `source_id` ограничивает правило одним коллектором.

Правила независимы: поток выбрасывается, если совпало **хотя бы одно**.

### Валидация (обязательна на сервере, желательно и в форме)

Коллектор молча игнорирует некорректные правила, поэтому UI должен не дать их
сохранить:

| Условие | Ошибка |
|---------|--------|
| не заполнено ни одно условие (`prefix`, порт, `proto`, `vlan_id`, `switch_ip`, `source_id`) | «Правило без условий выбросит весь трафик — укажите хотя бы одно условие» |
| `prefix` не парсится как CIDR | «Префикс должен быть в формате CIDR (например 10.0.0.0/8)» |
| `family` не соответствует адресу | «Версия IP не соответствует адресу в префиксе» |
| `if_index` задан, а `switch_ip` пуст | «Укажите IP коммутатора для номера порта» |
| `port_from > port_to` при обоих ненулевых | «Начало диапазона больше конца» |
| `switch_ip` не парсится как IP | «Некорректный IP коммутатора» |

Правило только с `source_id` допустимо (означает «выбросить весь трафик этого
коллектора»), но форма должна показать предупреждение перед сохранением.

## 5. API

Префикс `/api/refs/flow-exclusions`, по образцу `/api/refs/l3-prefixes`.

| Метод | Путь | Тело | Ответ |
|-------|------|------|-------|
| GET | `/api/refs/flow-exclusions` | — | `{ data: [Rule], meta }` |
| POST | `/api/refs/flow-exclusions` | `Rule` без `ruleId` = создание, с `ruleId` = правка | `{ ok: true, ruleId, meta }` |
| POST | `/api/refs/flow-exclusions/toggle` | `{ ruleId, enabled }` | `{ ok: true, enabled, meta }` |
| DELETE | `/api/refs/flow-exclusions` | `{ ruleId }` | `{ ok: true, meta }` |

`Rule` в camelCase:

```json
{
  "ruleId": "6f1c…",
  "prefix": "10.10.0.0/16",
  "family": 4,
  "matchSide": "any",
  "proto": 17,
  "portFrom": 53,
  "portTo": 53,
  "portSide": "dst",
  "vlanId": 0,
  "switchIp": "",
  "ifIndex": 0,
  "sourceId": "",
  "displayName": "Служебный DNS мониторинга",
  "comment": "",
  "enabled": 1,
  "updatedAt": "2026-08-03 05:00:00"
}
```

GET читает **таблицу** (нужны и выключенные правила), берёт последнюю версию:
`row_number() OVER (PARTITION BY rule_id ORDER BY updated_at DESC) = 1`.
Смотри `latestPrefixesCte` в `l3-prefixes.js`.

Добавить в `deploy/ui/app/server/clickhouse.js`:

```js
flowExclusionsTable: env('CLICKHOUSE_FLOW_EXCLUSIONS_TABLE', 'net_flow_exclusions'),
flowExclusionsView:  env('CLICKHOUSE_FLOW_EXCLUSIONS_VIEW',  'net_flow_exclusions_enabled'),
```

плюс `flowExclusionsTableRef()` / `flowExclusionsViewRef()` рядом с
`l3PrefixesTableRef` и экспорт в `module.exports` и в блок конфига,
который отдаётся в диагностику.

## 6. Страница

`id: 'flow-exclusions'`, заголовок «Исключения из статистики», раздел «Модель
сети» (рядом с CIDR / VLAN / Роли портов).

Зарегистрировать в:
- `public/data/app-pages.json`
- `public/components/shell.jsx` (пункт меню + список страниц раздела `netmodel`)
- `public/app.jsx` (`case 'flow-exclusions':`)
- `public/index.html` (подключение `.jsx`)
- `public/data/mock-fixtures.js` (права для ролей)
- права на запись: `AuthAccess.canWritePage('flow-exclusions')`

### Таблица правил

Колонки: Название · Условие · Область · Статус · Обновлено · действия
(вкл/выкл, править, удалить).

«Условие» — человекочитаемая сборка из заполненных полей, например:

- `10.10.0.0/16 (любая сторона)`
- `UDP · порт назначения 53`
- `10.0.0.0/8 (источник) · TCP · порты 30000–30010`
- `коммутатор 192.0.2.7 порт 42`

«Область» — `source_id` или «все коллекторы».

Выключенные правила показывать приглушённо, как в `cidr.jsx`.

### Форма правила

Блоками, все поля необязательные (но хотя бы одно условие обязательно):

1. **Название** (`display_name`) и **комментарий**.
2. **Сеть**: `prefix` + селектор стороны (`any` / `src` / `dst`).
   `family` вычислять из адреса, отдельного поля в форме не делать.
3. **Протокол и порты**: селектор протокола (любой / TCP / UDP / ICMP / номер),
   `port_from`, `port_to`, сторона порта.
4. **Точка наблюдения**: `switch_ip`, `if_index`, `vlan_id`.
   Для `switch_ip`/`if_index` подтягивать подсказки из
   `default.net_interfaces_current` (как на странице «Роли портов»,
   `interface-roles.jsx`).
5. **Коллектор**: селектор `source_id` из `default.net_flow_sources_enabled`,
   пустое значение = все.

Под формой — постоянная плашка:

> Совпавший трафик **удаляется** — он не попадёт ни в статистику, ни в
> NetFlow-экспорт. Уже сохранённые данные не изменятся. Правило начнёт
> действовать в течение минуты.

### Карточки-счётчики сверху

- Всего правил / включено
- Отброшено пакетов и байт за 24 ч

Второй показатель — из `collector_health_snapshots` (счётчики кумулятивные,
сбрасываются при рестарте демона, поэтому берём разницу max−min по окну и
источнику):

```sql
SELECT
  sum(packets) AS packets,
  sum(bytes)   AS bytes
FROM (
  SELECT
    max(flow_packets_excluded) - min(flow_packets_excluded) AS packets,
    max(flow_bytes_excluded)   - min(flow_bytes_excluded)   AS bytes
  FROM default.collector_health_snapshots
  WHERE ts >= now64(3) - INTERVAL 24 HOUR
  GROUP BY source_id
)
```

## 7. Проверка результата

1. Создать правило на тестовую подсеть, включить его.
2. Через минуту в логе демона появится
   `flow exclusions refreshed ... rules=N`.
3. `SELECT count() FROM flows_raw WHERE ... AND time_received_ns > now() - 120`
   по этой подсети даёт 0.
4. `flow_packets_excluded` в `collector_health_snapshots` растёт.
5. Полнота коллектора на странице «Статус коллекторов» остаётся ~100 %
   (исключённый объём учтён в формуле).

## 8. Что вне объёма задачи

- Правила по DNS-именам, ASN, странам — не поддерживаются схемой.
- Ретроспективная чистка `flows_raw` по правилу.
- Импорт/экспорт правил файлом.
