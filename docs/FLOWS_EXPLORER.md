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
