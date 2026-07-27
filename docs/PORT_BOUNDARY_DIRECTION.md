# Разметка портов и направление трафика «по портам»

Направление (`in` / `out` / `internal` / `transit`) сейчас определяется **по сетям**:
коллектор GrapesNTA ищет src и dst IP в справочнике собственных сетей
(`net_l3_prefixes`) и пишет готовое значение в `flows_raw.direction`.

Этот документ описывает вторую модель — **по портам**. Порт один раз размечается,
а направление выводится из разметки входного и выходного интерфейсов flow. Модель
не зависит от полноты справочника сетей, поэтому применима там, где IP разметить
нельзя: точки обмена трафиком, чужие участники, серые адреса.

Подход повторяет Akvorado: интерфейсу присваивается `Boundary`
(`external` / `internal`) и `Connectivity` (`transit`, `pni`, `ix`, `customer`, …),
а направление — это комбинация `InIfBoundary` × `OutIfBoundary`.

## Статус

Реализованы **логика и БД** (эта часть). UI описан отдельно:
[ТЗ интерфейса](UI_NAV_AND_PORTS_TZ.md). Переключение самого пайплайна на
портовую модель (правки коллектора GrapesNTA) — отдельный этап; здесь только
разметка, материализация и отчёты сравнения.

## Логика

### Две независимые характеристики порта

Одно поле «роль» (клиент / аплинк / IX / пиринг) не годится: оно смешивает две
разные вещи и заставляет подстраивать модель под конкретную сеть. Один и тот же
порт «в IX» бывает и нашей стороной, и внешней — зависит от того, чей трафик
считаем. Поэтому характеристик две.

**`boundary` — сторона сети.** Единственное, из чего выводится направление.

| Значение | Смысл |
|---|---|
| `internal` | наша сторона сети |
| `external` | внешняя сторона |
| `unknown` | не размечено |

**`connectivity` — тип стыка.** Описательное поле для фильтров и отчётов, на
направление не влияет: `customer`, `transit`, `pni`, `ppni`, `ix`, `core`,
`cgnat`, `mgmt` или пусто.

Примеры: клиентский порт провайдера — `internal` + `customer`; аплинк —
`external` + `transit`; наш порт в точку обмена — `internal` + `ix`; порт чужого
участника на фабрике IX — `external` + `ix`.

### Откуда берётся значение

Приоритет резолва (`effectiveSqlParts` в `deploy/ui/app/server/net-interface-roles.js`), для
`boundary` и `connectivity` считается независимо:

1. **Ручной override** порта — `net_interface_roles`.
2. **Первое сработавшее правило** по возрастанию `priority` — `net_interface_role_rules`.
   Правила, не задающие это поле, пропускаются: одно правило может назначать
   сторону, другое — тип стыка.
3. Иначе **значение по умолчанию** из настроек (`default_boundary`, по умолчанию
   `unknown`).

Правило состоит из двух необязательных условий, объединяемых через И:

- **текстовый шаблон** — regex (RE2) по `if_descr`, `if_alias` или `if_name` из
  SNMP-каталога; по умолчанию регистронезависимый (шаблон оборачивается в `(?i)`),
  флаг `case_sensitive` это отключает;
- **диапазон скорости порта** — `min_speed_mbps` / `max_speed_mbps`; скорость
  берётся из `if_high_speed_mbps`, а если он нулевой — из `if_speed_bps`.

Хотя бы одно условие должно быть задано. Шаблон валидирует сам ClickHouse (RE2
строже JS-регулярок), а не движок JS.

Текстовые правила работают там, где порты осмысленно подписаны. Если описания
однотипные (`Ethernet1/39` и подобное), автоматика по тексту бесполезна — в этом
случае размечают руками, опираясь на подсказки из трафика (см. ниже).

### Направление из сторон

`portDirectionSql` строит выражение из двух `boundary`:

| Вошёл | Вышел | Направление |
|---|---|---|
| external | internal | `in` |
| internal | external | `out` |
| internal | internal | `internal` |
| external | external | `transit` |
| остальное | | по политике `one_sided` |

**Политика `one_sided`** — что делать, когда сторона одного из портов неизвестна:

- `strict` (по умолчанию) — направление `unknown`, дыры в разметке видны;
- `infer` — классифицировать по известной стороне: вход `external` → `in`,
  вход `internal` → `out`, и симметрично для выхода.

Режим `infer` нужен, когда экспортёр не отдаёт вторую сторону. В sFlow это
частый случай: поле `out_if` в формате 2 означает «несколько выходных
интерфейсов» (флуд, multicast) и в ifIndex не разворачивается. Плата за режим —
транзит между двумя внешними портами при неизвестном выходе будет засчитан как
входящий.

### Значение по умолчанию

`default_boundary` задаёт, чем считается порт, который не покрыт ни ручной
разметкой, ни правилами. У Akvorado это жёстко `internal`; у нас по умолчанию
`unknown` — дыры видны, а не маскируются под внутренний трафик. Установка может
поменять значение, если её топология позволяет безопасное предположение.

### ifIndex из sFlow

В `flows_raw` лежит сырое поле sFlow (`in_if` / `out_if`). Реальный ifIndex несёт
только формат 0 — два старших бита нулевые, значение в младших 30 битах.
Декодирование вынесено в `sflowIfIndexExpr` (`deploy/ui/app/server/queries.js`) и используется
и Explorer'ом, и отчётами разметки.

### Подсказки из трафика

Когда описания портов не помогают, разметить их помогает сам трафик. Главный
признак — **число автономных систем, видимых за портом** (`ingress_asn_count` в
`/api/diagnostics/direction/interfaces`):

- единицы ASN — порт к клиенту или к одному участнику, обычно наша сторона;
- сотни и тысячи ASN — аплинк, магистраль, межкоммутаторный транк, обычно внешняя.

Признак работает одинаково в сети провайдера и на фабрике IX. Отчёт отдаёт
`suggestedBoundary` по порогу (`asn_threshold`, по умолчанию 50 ASN). Это
**подсказка оператору, а не автоматическая разметка**: решение принимает человек.

## Таблицы ClickHouse

DDL: `deploy/schema/50_net/27_net_direction_settings.sql` … `34_net_interface_roles_effective_current.sql`.

Разметка **не хранится в `net_interfaces`** — эту таблицу целиком перезаписывает
SNMP-поллер, и значения затирались бы при каждом опросе.

Во всех вью `*_current` свежая метка времени называется `updated_at_latest` во
вложенном запросе и переименовывается снаружи: ClickHouse не разрешает
`argMax(…, updated_at)` и `max(updated_at) AS updated_at` в одном SELECT.

### `net_direction_settings` — настройки инсталляции

`ReplacingMergeTree(updated_at)`, `ORDER BY settings_id`, одна строка `global`.
Вью `net_direction_settings_current`.

| Колонка | Назначение |
|---|---|
| `direction_mode` | `prefixes` (по сетям) или `ports` (по портам) |
| `default_boundary` | сторона для неразмеченных портов |
| `one_sided` | `strict` / `infer` |
| `updated_by`, `updated_at` | служебные |

`direction_mode` сейчас влияет на отчёты и предпросмотр; пайплайн переключается
на этапе правок коллектора.

### `net_interface_role_rules` — правила автоматики

`ReplacingMergeTree(updated_at)`, `ORDER BY rule_id`.
Актуальный срез — вью `net_interface_role_rules_current` (учитывает `deleted`).

| Колонка | Тип | Назначение |
|---|---|---|
| `rule_id` | String | `ifrule-<ts>-<rand>` |
| `priority` | UInt32 | меньше = выше приоритет (по умолчанию 100) |
| `match_field` | LowCardinality(String) | `descr` / `alias` / `name` |
| `pattern` | String | regex (RE2), может быть пустым |
| `case_sensitive` | UInt8 | 0 = регистронезависимо |
| `min_speed_mbps`, `max_speed_mbps` | UInt32 | 0 = условие не задано |
| `boundary` | LowCardinality(String) | какую сторону назначает, может быть пустым |
| `connectivity` | LowCardinality(String) | какой тип стыка назначает, может быть пустым |
| `comment`, `enabled`, `deleted`, `updated_at` | | служебные |

### `net_interface_roles` — ручные override

`ReplacingMergeTree(updated_at)`, `ORDER BY (switch_ip, if_index)`.
Вью `net_interface_roles_current`.

| Колонка | Тип | Назначение |
|---|---|---|
| `switch_ip` | String | IP коммутатора (как в SNMP-каталоге) |
| `if_index` | UInt32 | декодированный ifIndex |
| `boundary` | LowCardinality(String) | сторона, назначенная руками |
| `connectivity` | LowCardinality(String) | тип стыка |
| `comment`, `updated_by`, `deleted`, `updated_at` | | служебные |

Снятие override пишет строку с `deleted = 1` — порт возвращается под правила.

### `net_interface_roles_effective` — результат резолва

`ReplacingMergeTree(updated_at)`, `ORDER BY (switch_ip, if_index)`.
Вью `net_interface_roles_effective_current`.

| Колонка | Назначение |
|---|---|
| `boundary`, `connectivity` | итоговые значения |
| `boundary_source`, `connectivity_source` | `manual` / `rule` / `default` |
| `boundary_rule_id`, `connectivity_rule_id` | какое правило сработало (пусто для ручных) |

Это плоский срез без regex — его читают отчёты, и его же будет читать коллектор,
чтобы не тянуть правила в горячий путь. Пересчитывается функцией
`materializeEffectiveRoles()` при каждом сохранении правила, override или
настроек, а также вручную через API.

## API

Справочник (`deploy/ui/app/server/net-interface-roles.js`):

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/api/refs/direction-settings` | настройки + словари значений |
| POST | `/api/refs/direction-settings` | сохранить настройки |
| GET | `/api/refs/interface-role-rules` | список правил |
| POST | `/api/refs/interface-role-rules` | создать / изменить правило |
| POST | `/api/refs/interface-role-rules/delete` | удалить правило |
| POST | `/api/refs/interface-role-rules/preview` | какие порты попадут под правило |
| GET | `/api/refs/interface-roles/summary` | сводка покрытия разметкой |
| GET | `/api/refs/interface-roles/:ip` | порты коммутатора с разметкой |
| POST | `/api/refs/interface-roles` | ручная разметка порта (или списка портов) |
| POST | `/api/refs/interface-roles/delete` | снять ручную разметку |
| POST | `/api/refs/interface-roles/rebuild` | пересчитать эффективную разметку |

Диагностика (`deploy/ui/app/server/direction-audit.js`):

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/api/diagnostics/direction/coverage` | заполнены ли `in_if` / `out_if` |
| GET | `/api/diagnostics/direction/compare` | матрица «по портам» × текущий `direction` |
| GET | `/api/diagnostics/direction/interfaces` | порты по объёму, разметка и подсказки |

Параметр `hours` у диагностики — окно по `flows_raw`, по умолчанию 1 час,
максимум 24. Это полный скан сырой таблицы, поэтому окно намеренно короткое.
У `/compare` есть `one_sided` (переопределяет политику для конкретного расчёта),
у `/interfaces` — `limit`, `only_unmarked=1` и `asn_threshold`.

## Порядок внедрения

1. Применить схему: `./deploy/schema/apply.sh 50_net`.
2. Проверить `/api/diagnostics/direction/coverage` — если `in_if` / `out_if`
   приходят редко, портовая модель не применима.
3. Настроить `default_boundary` и `one_sided` под топологию установки.
4. Завести правила (где порты подписаны) и разметить остальное руками, опираясь
   на `/api/diagnostics/direction/interfaces`.
5. Сравнить модели: `/api/diagnostics/direction/compare`. Расхождения — это либо
   неразмеченные порты, либо пробелы в справочнике сетей.
6. Переключение коллектора на портовую модель — отдельный этап в GrapesNTA.
