# Flow Explorer

Документ фиксирует контракт таблицы "все flow" для Laravel + MoonShine.
Экран читает одну результирующую таблицу из API, но физически данные остаются в
`default.flows_raw`, а изменяемые справочники подключаются на запросе.

## Почему не писать все в одну широкую таблицу

`flows_raw` уже содержит стабильные факты и результат классификации collector-а:
IP, порты, протокол, байты, пакеты, VLAN, direction, kind, label, operator и ASN.

Не стоит дополнительно записывать в каждую flow-строку ASN name, country и service
name:

- ASN names, RIR country и service dictionary меняются после записи flow;
- дублирование раздувает диск и retention;
- исправление справочника должно сразу отражаться в UI без backfill raw-таблицы.

Для API это все равно выглядит как одна таблица: запрос возвращает готовые
колонки `src_as_name`, `dst_as_name`, `src_ip_country`, `service_name` и т.д.

## Источники данных

- `default.flows_raw` - flow facts и collector-side enrichment.
- `default.asn_registry_enriched` - ASN name, allocation country, RIR.
- `default.geo_country_dict` - IP prefix -> country.
- `default.port_services` - editable port/service dictionary.

`default.port_services` создается через `deploy/clickhouse/port_services.sql`.
Базовые сервисы включают `tcp/22 -> SSH` и `udp/tcp 5060 -> SIP`.

## API Defaults

- `from_utc` и `to_utc` обязательны.
- Максимальное окно UI: 200 минут.
- Максимальный `limit`: 1000.
- Default filter: `direction IN ('in', 'out', 'internal', 'transit')`.
- Default sort: `bytes DESC`.
- CSV export в первом MVP не нужен.

## Query

Версия ниже совместима со старым `clickhouse-client`: время возвращается как
`String`, а не `DateTime64`.

```sql
WITH
    toDateTime({from_utc:String}, 'UTC') AS from_ts,
    toDateTime({to_utc:String}, 'UTC') AS to_ts
SELECT
    toString(toDateTime(f.time_received_ns)) AS time_received,
    toString(toDateTime(f.time_flow_start_ns)) AS time_flow_start,

    if(f.etype = 2048,
        IPv4NumToString(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))),
        IPv6NumToString(f.src_addr)) AS src_ip,
    if(f.etype = 2048,
        IPv4NumToString(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))),
        IPv6NumToString(f.dst_addr)) AS dst_ip,

    f.src_port,
    f.dst_port,
    multiIf(f.proto = 6, 'tcp',
            f.proto = 17, 'udp',
            f.proto = 1, 'icmp',
            f.proto = 58, 'icmpv6',
            toString(f.proto)) AS protocol,

    f.src_vlan,
    f.dst_vlan,
    f.bytes,
    f.packets,

    f.direction,
    f.src_kind,
    f.dst_kind,
    f.src_label,
    f.dst_label,
    f.src_operator,
    f.dst_operator,

    f.src_asn,
    f.dst_asn,
    src_as.name AS src_as_name,
    dst_as.name AS dst_as_name,
    src_as.cc AS src_as_country,
    dst_as.cc AS dst_as_country,
    src_as.rir AS src_as_rir,
    dst_as.rir AS dst_as_rir,

    if(f.etype = 2048,
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))))),
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv6(IPv6NumToString(f.src_addr))))
    ) AS src_ip_country,
    if(f.etype = 2048,
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))))),
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv6(IPv6NumToString(f.dst_addr))))
    ) AS dst_ip_country,

    src_svc.service_code AS src_service_code,
    src_svc.service_name AS src_service_name,
    src_svc.category AS src_service_category,
    dst_svc.service_code AS dst_service_code,
    dst_svc.service_name AS dst_service_name,
    dst_svc.category AS dst_service_category,

    multiIf(dst_svc.service_code != '', 'dst',
            src_svc.service_code != '', 'src',
            '') AS service_side,
    multiIf(dst_svc.service_code != '', f.dst_port,
            src_svc.service_code != '', f.src_port,
            toUInt16(0)) AS service_port,
    multiIf(dst_svc.service_code != '', dst_svc.service_code,
            src_svc.service_code != '', src_svc.service_code,
            'unknown') AS service_code,
    multiIf(dst_svc.service_name != '', dst_svc.service_name,
            src_svc.service_name != '', src_svc.service_name,
            'Unknown') AS service_name,
    multiIf(dst_svc.category != '', dst_svc.category,
            src_svc.category != '', src_svc.category,
            'unknown') AS service_category

FROM default.flows_raw AS f
LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
LEFT JOIN default.port_services AS src_svc
    ON src_svc.transport = toLowCardinality(multiIf(f.proto = 6, 'tcp', f.proto = 17, 'udp', f.proto = 1, 'icmp', ''))
   AND src_svc.port = f.src_port
   AND src_svc.is_enabled = 1
LEFT JOIN default.port_services AS dst_svc
    ON dst_svc.transport = toLowCardinality(multiIf(f.proto = 6, 'tcp', f.proto = 17, 'udp', f.proto = 1, 'icmp', ''))
   AND dst_svc.port = f.dst_port
   AND dst_svc.is_enabled = 1

WHERE f.time_received_ns >= from_ts
  AND f.time_received_ns < to_ts
  AND f.direction IN ('in', 'out', 'internal', 'transit')
  /* dynamic filters */

ORDER BY f.bytes DESC
LIMIT {limit:UInt32} OFFSET {offset:UInt32};
```

## ClickHouse Smoke Test Query

Этот запрос можно выполнить напрямую в `clickhouse-client`. Он берет последние
10 минут, скрывает `unknown` по умолчанию, сортирует самые крупные flow сверху и
возвращает 100 строк вместе с протоколом и сервисом (`SSH`, `SIP`, `HTTPS`,
`DNS` и т.д.).

```sql
SELECT
    toString(toDateTime(f.time_received_ns)) AS time_received,
    toString(toDateTime(f.time_flow_start_ns)) AS time_flow_start,

    if(f.etype = 2048,
        IPv4NumToString(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))),
        IPv6NumToString(f.src_addr)
    ) AS src_ip,

    if(f.etype = 2048,
        IPv4NumToString(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))),
        IPv6NumToString(f.dst_addr)
    ) AS dst_ip,

    f.src_port,
    f.dst_port,

    multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        toString(f.proto)
    ) AS protocol,

    f.src_vlan,
    f.dst_vlan,
    f.bytes,
    f.packets,

    f.direction,
    f.src_kind,
    f.dst_kind,
    f.src_label,
    f.dst_label,
    f.src_operator,
    f.dst_operator,

    f.src_asn,
    f.dst_asn,
    src_as.name AS src_as_name,
    dst_as.name AS dst_as_name,
    src_as.cc AS src_as_country,
    dst_as.cc AS dst_as_country,
    src_as.rir AS src_as_rir,
    dst_as.rir AS dst_as_rir,

    if(f.etype = 2048,
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))))),
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv6(IPv6NumToString(f.src_addr))))
    ) AS src_ip_country,

    if(f.etype = 2048,
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))))),
        dictGetString('default.geo_country_dict', 'cc',
            tuple(toIPv6(IPv6NumToString(f.dst_addr))))
    ) AS dst_ip_country,

    src_svc.service_code AS src_service_code,
    src_svc.service_name AS src_service_name,
    src_svc.category AS src_service_category,
    dst_svc.service_code AS dst_service_code,
    dst_svc.service_name AS dst_service_name,
    dst_svc.category AS dst_service_category,

    multiIf(
        dst_svc.service_code != '', 'dst',
        src_svc.service_code != '', 'src',
        ''
    ) AS service_side,

    multiIf(
        dst_svc.service_code != '', f.dst_port,
        src_svc.service_code != '', f.src_port,
        toUInt16(0)
    ) AS service_port,

    multiIf(
        dst_svc.service_code != '', dst_svc.service_code,
        src_svc.service_code != '', src_svc.service_code,
        'unknown'
    ) AS service_code,

    multiIf(
        dst_svc.service_name != '', dst_svc.service_name,
        src_svc.service_name != '', src_svc.service_name,
        'Unknown'
    ) AS service_name,

    multiIf(
        dst_svc.category != '', dst_svc.category,
        src_svc.category != '', src_svc.category,
        'unknown'
    ) AS service_category

FROM default.flows_raw AS f

LEFT JOIN default.asn_registry_enriched AS src_as
    ON src_as.asn = f.src_asn

LEFT JOIN default.asn_registry_enriched AS dst_as
    ON dst_as.asn = f.dst_asn

LEFT JOIN default.port_services AS src_svc
    ON src_svc.transport = toLowCardinality(multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        ''
    ))
   AND src_svc.port = f.src_port
   AND src_svc.is_enabled = 1

LEFT JOIN default.port_services AS dst_svc
    ON dst_svc.transport = toLowCardinality(multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        ''
    ))
   AND dst_svc.port = f.dst_port
   AND dst_svc.is_enabled = 1

WHERE f.time_received_ns >= now('UTC') - INTERVAL 10 MINUTE
  AND f.time_received_ns < now('UTC')
  AND f.direction IN ('in', 'out', 'internal', 'transit')

ORDER BY f.bytes DESC
LIMIT 100 OFFSET 0;
```

Если `default.port_services` еще не создана на ClickHouse, применить:

```bash
clickhouse-client --multiquery < deploy/clickhouse/port_services.sql
```

## Field Dictionary

Ниже описаны поля результирующей таблицы для UI. Физически базовые flow-поля
лежат в `default.flows_raw`; ASN, страна и сервис подтягиваются из справочников
во время запроса.

### Time

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `time_received` | Когда collector получил/export-нул flow в ClickHouse. | `flows_raw.time_received_ns`, приводится к читаемому времени. |
| `time_flow_start` | Когда flow начался по времени первого пакета. | `flows_raw.time_flow_start_ns`, приводится к читаемому времени. |

### Addresses And Ports

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `src_ip` | IP-адрес источника пакетов в flow. | Из `flows_raw.src_addr`; IPv4 форматируется через `IPv4NumToString`, IPv6 через `IPv6NumToString`. |
| `dst_ip` | IP-адрес назначения. | Из `flows_raw.dst_addr`; форматирование аналогично `src_ip`. |
| `src_port` | Порт источника. Для ICMP обычно `0`. | `flows_raw.src_port`. |
| `dst_port` | Порт назначения. Для ICMP может быть `0` или техническое значение из flow key. | `flows_raw.dst_port`. |
| `protocol` | Транспортный протокол: `tcp`, `udp`, `icmp`, `icmpv6` или номер протокола. | Расшифровка `flows_raw.proto`: `6=tcp`, `17=udp`, `1=icmp`, `58=icmpv6`. |

### VLAN

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `src_vlan` | Outer VLAN, с которым packet пришёл на mirror-интерфейс. | `xdpflowd` читает VLAN из Ethernet frame и пишет в `flows_raw.src_vlan`. Если RX VLAN offload снимает тег, будет `0`. |
| `dst_vlan` | VLAN назначения/выхода. | Сейчас `xdpflowd` его не знает и пишет `0`; поле оставлено для будущих exporter-ов/IPFIX. |

Практически для UI сейчас полезно показывать `src_vlan` как `VLAN`. `dst_vlan`
показывать только если значение больше `0`.

### Counters

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `bytes` | Объём flow в байтах. | `flows_raw.bytes`, сумма длин пакетов, увиденных collector-ом. |
| `packets` | Количество пакетов в flow. | `flows_raw.packets`. |

### Direction And Local Classification

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `direction` | Направление относительно нашей сети: `in`, `out`, `internal`, `transit`, `unknown`. | Считает `xdpflowd` до записи в ClickHouse по приоритету `VLAN > local ASN > local prefix`. |
| `src_kind` | Тип источника: например `customer`, `local`, `uplink`, `ix`, `remote`, `unknown`. | Результат classifier-а для `src_ip` + `src_vlan`. |
| `dst_kind` | Тип назначения. | Результат classifier-а для `dst_ip` + `dst_vlan`. |
| `src_label` | Читаемое имя локального/клиентского источника, если источник распознан. | Из `local_networks_enabled`, `local_asns_enabled` или `vlan_map_enabled`. |
| `dst_label` | Читаемое имя локального/клиентского назначения, если назначение распознано. | Аналогично `src_label`, но для destination. |
| `src_operator` | Стабильный `operator_id` источника (`pin`, `iconet`, и т.п.). | Из локальных справочников classifier-а. |
| `dst_operator` | Стабильный `operator_id` назначения. | Из локальных справочников classifier-а. |

Если `direction='unknown'`, то `kind/label/operator/asn` часто будут пустыми
или `0`. В UI `unknown` скрывается по умолчанию, но может включаться отдельным
фильтром для диагностики.

### ASN And Registry

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `src_asn` | Origin ASN для `src_ip`. | `xdpflowd` ищет IP в BGP prefix trie и пишет ASN в `flows_raw.src_asn`. |
| `dst_asn` | Origin ASN для `dst_ip`. | Аналогично `src_asn`. |
| `src_as_name` | Название ASN источника. | `LEFT JOIN default.asn_registry_enriched ON src_asn`. |
| `dst_as_name` | Название ASN назначения. | `LEFT JOIN default.asn_registry_enriched ON dst_asn`. |
| `src_as_country` | Страна регистрации/выделения ASN источника. | Из RIR ASN registry (`asn_registry_enriched.cc`). Это не обязательно фактическая геолокация IP. |
| `dst_as_country` | Страна регистрации/выделения ASN назначения. | Аналогично `src_as_country`. |
| `src_as_rir` | RIR-регистратор ASN источника: `ripencc`, `arin`, `apnic`, и т.п. | Из `asn_registry_enriched.rir`. |
| `dst_as_rir` | RIR-регистратор ASN назначения. | Из `asn_registry_enriched.rir`. |

Если `src_asn` / `dst_asn` равны `0`, то ASN name/country/RIR будут пустыми.

### IP Country

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `src_ip_country` | Страна IP-адреса источника по prefix dictionary. | `dictGetString('default.geo_country_dict', 'cc', src_ip)`. |
| `dst_ip_country` | Страна IP-адреса назначения по prefix dictionary. | `dictGetString('default.geo_country_dict', 'cc', dst_ip)`. |

`src_ip_country` / `dst_ip_country` отличаются от `src_as_country` /
`dst_as_country`: IP-country относится к IP-префиксу, ASN-country относится к
регистрации ASN.

### Port Services

Сервис определяется через `default.port_services` по паре
`protocol + port`. Справочник редактируемый; базово есть `SSH`, `DNS`, `HTTP`,
`HTTPS`, `QUIC`, `SIP` и другие распространённые сервисы.

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `src_service_code` | Код сервиса на source port, например `https`, `ssh`, `sip`. | `LEFT JOIN port_services` по `protocol + src_port`. |
| `dst_service_code` | Код сервиса на destination port. | `LEFT JOIN port_services` по `protocol + dst_port`. |
| `src_service_name` | Читаемое имя source-сервиса, например `HTTPS`. | Из `port_services.service_name`. |
| `dst_service_name` | Читаемое имя destination-сервиса. | Из `port_services.service_name`. |
| `src_service_category` | Категория source-сервиса: `web`, `dns`, `voip`, `remote_access`, и т.п. | Из `port_services.category`. |
| `dst_service_category` | Категория destination-сервиса. | Из `port_services.category`. |

### Chosen Service

Эти поля нужны, чтобы UI мог показать один “главный сервис” в строке flow, не
разбирая отдельно source и destination.

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `service_side` | На какой стороне найден главный сервис: `src`, `dst` или пусто. | Если распознан `dst_service_code`, выбирается `dst`; иначе если есть `src_service_code`, выбирается `src`. |
| `service_port` | Порт выбранного сервиса. | `dst_port`, если service side `dst`; иначе `src_port`; иначе `0`. |
| `service_code` | Код выбранного сервиса. | `dst_service_code`, затем `src_service_code`, иначе `unknown`. |
| `service_name` | Имя выбранного сервиса. | `dst_service_name`, затем `src_service_name`, иначе `Unknown`. |
| `service_category` | Категория выбранного сервиса. | `dst_service_category`, затем `src_service_category`, иначе `unknown`. |

Приоритет `dst` выбран потому, что для обычных клиентских соединений сервис чаще
находится на destination port (`443`, `53`, `22`, `5060`). Для входящих ответов
от сервера сервис может оказаться на source port; тогда `service_side='src'`.

## Dynamic Filters

API добавляет в `WHERE` только whitelisted-фильтры:

- time range: `from_utc`, `to_utc`;
- `direction`;
- `src_ip`, `dst_ip`, `any_ip` через exact IP или CIDR;
- `src_port`, `dst_port`, `any_port`;
- `protocol`;
- `src_asn`, `dst_asn`, `any_asn`;
- `src_ip_country`, `dst_ip_country`, `any_ip_country`;
- `src_vlan`, `dst_vlan`;
- `src_operator`, `dst_operator`, `operator_id`;
- `src_kind`, `dst_kind`;
- `min_bytes`, `min_packets`;
- `service_code`, `service_category`.

Sort whitelist:

- `time_received`;
- `bytes`;
- `packets`;
- `src_port`;
- `dst_port`;
- `direction`;
- `service_name`.

## Notes

`unknown` direction is valid diagnostic data, but hidden by default in the UI.
It can be exposed with an explicit "include unknown" switch.
