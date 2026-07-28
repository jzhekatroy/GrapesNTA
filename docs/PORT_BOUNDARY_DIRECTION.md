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

Реализованы логика, БД, UI разметки и **чтение разметки коллектором**:
при `direction_mode = ports` коллектор пишет `flows_raw.direction` по сторонам
входного и выходного порта (см. «Коллектор» ниже). UI описан отдельно:
[ТЗ интерфейса](UI_NAV_AND_PORTS_TZ.md).

Модель строгая: тип стыка (`connectivity`) на направление не влияет и в MVP
интерфейса не показывается, а неизвестная сторона всегда даёт `unknown`.

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
| хотя бы одна сторона неизвестна | | `unknown` |

Режима «угадывать по одной известной стороне» нет: неразмеченный порт или flow
без номера порта дают `unknown`, поэтому дыры в разметке видны, а не маскируются
под входящий трафик. Колонки `one_sided` и `default_boundary` в БД сохранены, но
в них пишутся константы `strict` / `unknown`.

Частый случай — sFlow-поле `out_if` в формате 2 («несколько выходных
интерфейсов»: флуд, multicast). Такой сэмпл в ifIndex не разворачивается и
попадает в `unknown`.

### ifIndex из sFlow

Реальный ifIndex несёт только формат 0: в обычном flow-сэмпле два старших бита
поля — формат, младшие 30 — значение; в expanded-сэмпле формат приходит
отдельным полем. Значение `0x3FFFFFFF` — признак «неизвестен или несколько
интерфейсов».

Коллектор нормализует это при разборе сэмпла (`sflowIfIndex` в
`cmd/flowcollectord/sflow_v5.go`) и пишет в `flows_raw.in_if` / `out_if` либо
чистый ifIndex, либо `0`. Так каждый потребитель — разметка портов в коллекторе,
`scripts/snmp_iface_sync.py` и запросы UI — видит те же номера, что и SNMP.

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

`direction_mode` читает и коллектор: смена режима вступает в силу в течение
одного интервала обновления справочников (`-classifier-refresh`, по умолчанию
минута). Историю никто не пересчитывает — модель применяется к новым flow.

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

Это плоский срез без regex — его читают и отчёты, и коллектор, чтобы не тянуть
правила в горячий путь. Пересчитывается функцией
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

## Коллектор

Разметку читает общий классификатор (`internal/flowingest/classifier.go`) тем же
циклом обновления, что и префиксы: раз в `-classifier-refresh` он забирает
`direction_mode` и все стороны портов в память и подменяет состояние целиком.
Ключ поиска — пара «адрес экспортёра + ifIndex», причём `switch_ip` из каталога
парсится в тот же 16-байтовый вид, что и `sampler_address` во flow, поэтому в
горячем пути остаётся обычный поиск по map.

| Флаг (`flowcollectord` / `xdpflowd`) | ENV `flowcollectord` | Назначение |
|---|---|---|
| `-classifier-direction-settings-view` | `FC_CLASSIFIER_DIRECTION_SETTINGS_VIEW` | откуда читать режим |
| `-classifier-interface-roles-view` | `FC_CLASSIFIER_INTERFACE_ROLES_VIEW` | откуда читать стороны портов |

Пустое значение любого из двух флагов означает «портовая модель выключена»:
коллектор всегда считает направление по сетям. Так же он ведёт себя, если
таблиц нет в БД или их не удалось прочитать — режим никогда не переключается
молча из-за отсутствующего справочника.

**Источники без ifIndex.** ifIndex есть только у sFlow. Зеркальный трафик
(`xdpflowd`) и BMP номеров портов не несут, поэтому в режиме `ports` весь такой
трафик попадает в `unknown`. Это осознанный выбор: смешивать две модели в одной
колонке `direction` нельзя, иначе отчёты становятся неинтерпретируемыми.

**Счётчики.** В строку лога `traffic classifier refreshed` добавлены
`direction_mode`, `port_sides`, `port_switches` и три накопительных счётчика:

| Поле | Смысл |
|---|---|
| `direction_ports_classified` | направление получено по портам |
| `direction_ports_no_ifindex` | `unknown`: во flow нет ifIndex |
| `direction_ports_unmarked` | `unknown`: порт есть, но сторона не размечена |

Последние два — рабочий инструмент при разметке: видно, доразмечать порты или
проблема в источнике, который не отдаёт ifIndex.

## Порядок внедрения

1. Применить схему: `./deploy/schema/apply.sh 50_net`.
2. Проверить `/api/diagnostics/direction/coverage` — если `in_if` / `out_if`
   приходят редко, портовая модель не применима.
3. Обновить коллектор, оставив режим `prefixes`: он начнёт читать разметку, но
   на `direction` это ещё не влияет.
4. Разметить порты в UI («Порты оборудования»), опираясь при необходимости на
   `/api/diagnostics/direction/interfaces`.
5. Сравнить модели: `/api/diagnostics/direction/compare`. Расхождения — это либо
   неразмеченные порты, либо пробелы в справочнике сетей.
6. Переключить `direction_mode` на `ports` и следить за счётчиками выше: рост
   `direction_ports_unmarked` означает недоразмеченные порты.
