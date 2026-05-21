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
- `default.dns_answers` - flattened DNS A/AAAA answers for probable domain
  enrichment.

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
`String`, а не `DateTime64`. DNS enrichment сделан через обычный `LEFT JOIN` +
`argMaxIf`, потому что `ASOF JOIN` в текущей версии ClickHouse требует более
строгого синтаксиса и хуже подходит для совместимого API-запроса.

```sql
WITH
    toDateTime({from_utc:String}, 'UTC') AS from_ts,
    toDateTime({to_utc:String}, 'UTC') AS to_ts,
    1800 AS dns_window_sec
SELECT
    f.time_received,
    f.time_flow_start,
    f.src_ip,
    f.dst_ip,
    f.src_port,
    f.dst_port,
    f.protocol,
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
    f.src_attachment_kind,
    f.dst_attachment_kind,
    f.src_attachment_boundary,
    f.dst_attachment_boundary,
    f.src_attachment_label,
    f.dst_attachment_label,
    f.src_attachment_operator,
    f.dst_attachment_operator,
    f.src_endpoint_scope,
    f.dst_endpoint_scope,
    f.src_endpoint_source,
    f.dst_endpoint_source,
    f.src_network_name,
    f.dst_network_name,
    f.src_network_role,
    f.dst_network_role,
    f.src_asn,
    f.dst_asn,
    f.src_as_name,
    f.dst_as_name,
    f.src_as_country,
    f.dst_as_country,
    f.src_as_rir,
    f.dst_as_rir,
    f.src_ip_country,
    f.dst_ip_country,
    f.src_service_code,
    f.src_service_name,
    f.src_service_category,
    f.dst_service_code,
    f.dst_service_name,
    f.dst_service_category,
    f.service_side,
    f.service_port,
    f.service_code,
    f.service_name,
    f.service_category,

    if(
        countIf(dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
        argMaxIf(dns_fwd.query_name, dns_fwd.ts, dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec),
        argMaxIf(dns_rev.query_name, dns_rev.ts, dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)
    ) AS dns_name,
    if(
        countIf(dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
        'forward',
        if(
            countIf(dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
            'reverse',
            ''
        )
    ) AS dns_match_side,

    if(
        countIf(dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
        toString(maxIf(dns_fwd.ts, dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)),
        if(
            countIf(dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
            toString(maxIf(dns_rev.ts, dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)),
            ''
        )
    ) AS dns_seen_at,

    if(
        countIf((dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)
             OR (dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)) = 0,
        0,
        dateDiff('second',
            if(
                countIf(dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
                maxIf(dns_fwd.ts, dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec),
                maxIf(dns_rev.ts, dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)
            ),
            max(f.flow_ts)
        )
    ) AS dns_age_sec,

    if(
        countIf((dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)
             OR (dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)) = 0,
        '',
        if(
            countIf(dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
            argMaxIf(if(substring(dns_fwd.server_ip, 5, 12) = unhex('000000000000000000000000'),
                IPv4NumToString(reinterpretAsUInt32(reverse(substring(dns_fwd.server_ip, 1, 4)))),
                IPv6NumToString(dns_fwd.server_ip)), dns_fwd.ts, dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec),
            argMaxIf(if(substring(dns_rev.server_ip, 5, 12) = unhex('000000000000000000000000'),
                IPv4NumToString(reinterpretAsUInt32(reverse(substring(dns_rev.server_ip, 1, 4)))),
                IPv6NumToString(dns_rev.server_ip)), dns_rev.ts, dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)
        )
    ) AS dns_server_ip,

    if(
        countIf(dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
        argMaxIf(dns_fwd.answer_type, dns_fwd.ts, dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec),
        argMaxIf(dns_rev.answer_type, dns_rev.ts, dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)
    ) AS dns_answer_type,

    if(
        countIf(dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec) > 0,
        argMaxIf(dns_fwd.ttl, dns_fwd.ts, dns_fwd.query_name != '' AND dateDiff('second', dns_fwd.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec),
        argMaxIf(dns_rev.ttl, dns_rev.ts, dns_rev.query_name != '' AND dateDiff('second', dns_rev.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)
    ) AS dns_ttl

FROM
(
    SELECT
        f.time_received_ns AS flow_ts,
        toString(toDateTime(f.time_received_ns)) AS time_received,
        toString(toDateTime(f.time_flow_start_ns)) AS time_flow_start,
        f.src_addr,
        f.dst_addr,
        if(f.etype = 2048,
            IPv4NumToString(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))),
            IPv6NumToString(f.src_addr)) AS src_ip,
        if(f.etype = 2048,
            IPv4NumToString(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))),
            IPv6NumToString(f.dst_addr)) AS dst_ip,
        f.src_port,
        f.dst_port,
        multiIf(f.proto = 6, 'tcp', f.proto = 17, 'udp', f.proto = 1, 'icmp', f.proto = 58, 'icmpv6', toString(f.proto)) AS protocol,
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
        f.src_attachment_kind,
        f.dst_attachment_kind,
        f.src_attachment_boundary,
        f.dst_attachment_boundary,
        f.src_attachment_label,
        f.dst_attachment_label,
        f.src_attachment_operator,
        f.dst_attachment_operator,
        f.src_endpoint_scope,
        f.dst_endpoint_scope,
        f.src_endpoint_source,
        f.dst_endpoint_source,
        f.src_network_name,
        f.dst_network_name,
        f.src_network_role,
        f.dst_network_role,
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
        multiIf(dst_svc.service_code != '', 'dst', src_svc.service_code != '', 'src', '') AS service_side,
        multiIf(dst_svc.service_code != '', f.dst_port, src_svc.service_code != '', f.src_port, toUInt16(0)) AS service_port,
        multiIf(dst_svc.service_code != '', dst_svc.service_code, src_svc.service_code != '', src_svc.service_code, 'unknown') AS service_code,
        multiIf(dst_svc.service_name != '', dst_svc.service_name, src_svc.service_name != '', src_svc.service_name, 'Unknown') AS service_name,
        multiIf(dst_svc.category != '', dst_svc.category, src_svc.category != '', src_svc.category, 'unknown') AS service_category
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
    LIMIT {limit:UInt32} OFFSET {offset:UInt32}
) AS f
LEFT JOIN
(
    SELECT *
    FROM default.dns_answers
    WHERE ts >= from_ts - INTERVAL 30 MINUTE
      AND ts < to_ts
) AS dns_fwd
    ON f.src_addr = dns_fwd.client_ip
   AND f.dst_addr = dns_fwd.answer_ip
LEFT JOIN
(
    SELECT *
    FROM default.dns_answers
    WHERE ts >= from_ts - INTERVAL 30 MINUTE
      AND ts < to_ts
) AS dns_rev
    ON f.dst_addr = dns_rev.client_ip
   AND f.src_addr = dns_rev.answer_ip
GROUP BY
    f.flow_ts, f.src_addr, f.dst_addr, f.time_received, f.time_flow_start,
    f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol, f.src_vlan,
    f.dst_vlan, f.bytes, f.packets, f.direction, f.src_kind, f.dst_kind,
    f.src_label, f.dst_label, f.src_operator, f.dst_operator,
    f.src_attachment_kind, f.dst_attachment_kind, f.src_attachment_boundary,
    f.dst_attachment_boundary, f.src_attachment_label, f.dst_attachment_label,
    f.src_attachment_operator, f.dst_attachment_operator, f.src_endpoint_scope,
    f.dst_endpoint_scope, f.src_endpoint_source, f.dst_endpoint_source,
    f.src_network_name, f.dst_network_name, f.src_network_role,
    f.dst_network_role, f.src_asn, f.dst_asn, f.src_as_name, f.dst_as_name,
    f.src_as_country, f.dst_as_country, f.src_as_rir, f.dst_as_rir,
    f.src_ip_country, f.dst_ip_country, f.src_service_code,
    f.src_service_name, f.src_service_category, f.dst_service_code,
    f.dst_service_name, f.dst_service_category, f.service_side,
    f.service_port, f.service_code, f.service_name, f.service_category
ORDER BY f.bytes DESC
```

`ON` must use only equality on join keys (`client_ip`, `answer_ip`). Do not put
`dns.ts <= f.flow_ts` into `ON` — ClickHouse rejects mixed left/right columns
unless `allow_experimental_join_condition = 1`. Time filtering belongs in the
`dns_answers` subquery (`ts` window) and in
`argMaxIf(..., dateDiff('second', dns.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec)`.

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
    f.src_attachment_kind,
    f.dst_attachment_kind,
    f.src_attachment_boundary,
    f.dst_attachment_boundary,
    f.src_attachment_label,
    f.dst_attachment_label,
    f.src_attachment_operator,
    f.dst_attachment_operator,
    f.src_endpoint_scope,
    f.dst_endpoint_scope,
    f.src_endpoint_source,
    f.dst_endpoint_source,
    f.src_network_name,
    f.dst_network_name,
    f.src_network_role,
    f.dst_network_role,

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

## ClickHouse DNS Enrichment Smoke Test

Этот запрос можно выполнить напрямую в `clickhouse-client`. Он проверяет, что
`flows_raw` связывается с новой таблицей `dns_answers`: берём свежие flows,
ищем DNS-ответ того же клиента на destination IP и показываем домен + DNS
server IP. Здесь проверяется `forward`-match (`flow.src_addr =
dns.client_ip`, `flow.dst_addr = dns.answer_ip`), которого достаточно для
быстрого smoke test.

```sql
WITH
    now('UTC') - INTERVAL 10 MINUTE AS from_ts,
    now('UTC') AS to_ts,
    1800 AS dns_window_sec
SELECT
    time_received,
    src_ip,
    dst_ip,
    dst_port,
    protocol,
    bytes,
    packets,
    direction,
    argMax(dns.query_name, dns.ts) AS dns_name,
    argMax(
        if(substring(dns.server_ip, 5, 12) = unhex('000000000000000000000000'),
            IPv4NumToString(reinterpretAsUInt32(reverse(substring(dns.server_ip, 1, 4)))),
            IPv6NumToString(dns.server_ip)
        ),
        dns.ts
    ) AS dns_server_ip,
    argMax(dns.answer_type, dns.ts) AS dns_answer_type,
    argMax(dns.ttl, dns.ts) AS dns_ttl,
    toString(max(dns.ts)) AS dns_seen_at,
    dateDiff('second', max(dns.ts), max(flow_ts)) AS dns_age_sec
FROM
(
    SELECT
        time_received_ns AS flow_ts,
        toString(toDateTime(time_received_ns)) AS time_received,
        src_addr,
        dst_addr,
        if(etype = 2048,
            IPv4NumToString(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))),
            IPv6NumToString(src_addr)
        ) AS src_ip,
        if(etype = 2048,
            IPv4NumToString(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))),
            IPv6NumToString(dst_addr)
        ) AS dst_ip,
        dst_port,
        multiIf(proto = 6, 'tcp', proto = 17, 'udp', proto = 1, 'icmp', toString(proto)) AS protocol,
        bytes,
        packets,
        direction
    FROM default.flows_raw
    WHERE time_received_ns >= from_ts
      AND time_received_ns < to_ts
      AND direction IN ('out', 'internal', 'transit')
    ORDER BY bytes DESC
    LIMIT 10000
) AS f
INNER JOIN default.dns_answers AS dns
    ON f.src_addr = dns.client_ip
   AND f.dst_addr = dns.answer_ip
WHERE dns.ts >= from_ts - INTERVAL 30 MINUTE
  AND dns.ts <= f.flow_ts
  AND dateDiff('second', dns.ts, f.flow_ts) BETWEEN 0 AND dns_window_sec
GROUP BY
    time_received,
    src_ip,
    dst_ip,
    dst_port,
    protocol,
    bytes,
    packets,
    direction
ORDER BY bytes DESC
LIMIT 50
FORMAT PrettyCompact;
```

Note: `time_received` may be rendered in the server/session timezone while
`dns_seen_at` comes from `DateTime64(..., 'UTC')`. Trust `dns_age_sec` for the
actual delta.

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
| `direction` | Направление flow относительно нашей сети: `in`, `out`, `internal`, `transit`, `unknown`. | Считает `xdpflowd` до записи в ClickHouse только по `src_endpoint_scope` + `dst_endpoint_scope`. VLAN напрямую не меняет direction. |
| `src_attachment_kind` | Тип подключения, через которое увидели source сторону: `customer`, `uplink`, `core`, `internal`, `mgmt`, `ix`, `peering`, `unknown`. | Из `default.vlan_map_enabled` по `src_vlan`. Это описание VLAN/линка, а не владельца IP. |
| `dst_attachment_kind` | Тип подключения для destination стороны. | Из `default.vlan_map_enabled` по `dst_vlan`. Сейчас `dst_vlan` обычно `0`, поэтому чаще будет `unknown`. |
| `src_attachment_boundary` | Граница подключения: `internal`, `external`, `unknown`. | Из VLAN map. `customer/core/internal/mgmt` обычно `internal`; `uplink/ix/peering/transit` обычно `external`. |
| `dst_attachment_boundary` | Граница destination-подключения. | Аналогично source. |
| `src_attachment_label` | Человекочитаемое имя VLAN/подключения. | Из `vlan_map_enabled.label`, например `Iconnet VLAN 210` или `RETN uplink`. |
| `dst_attachment_label` | Имя destination VLAN/подключения. | Аналогично source. |
| `src_attachment_operator` | Стабильный `operator_id` VLAN/подключения. | Из `vlan_map_enabled.operator_id`. |
| `dst_attachment_operator` | `operator_id` destination VLAN/подключения. | Аналогично source. |
| `src_endpoint_scope` | Чей source IP относительно нас: `local`, `customer`, `remote`, `unknown`. | По IP/ASN: сначала local ASN, потом local prefix, иначе fallback remote. |
| `dst_endpoint_scope` | Чей destination IP относительно нас. | Аналогично source. |
| `src_endpoint_source` | Почему выбран `src_endpoint_scope`: `asn`, `prefix`, `fallback`, `unknown`. | `asn` если ASN есть в `local_asns_enabled`; `prefix` если IP попал в `local_networks_enabled`; `fallback` если локального совпадения нет. |
| `dst_endpoint_source` | Почему выбран `dst_endpoint_scope`. | Аналогично source. |
| `src_network_name` | Имя локального/customer prefix, если source IP попал в prefix-справочник. | Из `local_networks_enabled.name`; иначе пусто. |
| `dst_network_name` | Имя prefix для destination. | Аналогично source. |
| `src_network_role` | Роль prefix: `local`, `customer`, `internal`, `mgmt` или другое значение из справочника. | Из `local_networks_enabled.kind`; иначе пусто. |
| `dst_network_role` | Роль destination prefix. | Аналогично source. |
| `src_kind` / `dst_kind` | Совместимые физические колонки. | Новые записи заполняют их значением `src_endpoint_scope` / `dst_endpoint_scope`. Для UI лучше использовать явные endpoint/attachment поля. |
| `src_label` / `dst_label` | Совместимые физические колонки. | Новые записи заполняют их network/asn label. Для VLAN label используйте `src_attachment_label` / `dst_attachment_label`. |
| `src_operator` / `dst_operator` | Совместимые физические колонки. | Новые записи заполняют их endpoint operator. Для VLAN operator используйте `src_attachment_operator` / `dst_attachment_operator`. |

Классификация теперь разделена на две понятные части.

**Attachment = где увидели пакет**

VLAN отвечает только на вопрос "через какое подключение/линк мы увидели
пакет?". Он не говорит, чей IP. Пример: `src_vlan=444` может означать
`src_attachment_kind='uplink'`, `src_attachment_boundary='external'`.

**Endpoint = чей IP**

IP/ASN отвечает на вопрос "этот адрес наш, клиентский или внешний?". Правила:

| Приоритет | Проверка | Endpoint result |
|-----------|----------|-----------------|
| 1 | Origin ASN IP-адреса есть в `default.local_asns_enabled`. | `endpoint_scope='local'`, `endpoint_source='asn'`. |
| 2 | IP попадает в `default.local_networks_enabled`. | `endpoint_scope='customer'` для role `customer`; `endpoint_scope='local'` для role `local/internal/mgmt`; `endpoint_source='prefix'`. |
| 3 | Локального совпадения нет. | `endpoint_scope='remote'`, `endpoint_source='fallback'`. |
| 4 | Classifier не готов или IP version невалидный. | `endpoint_scope='unknown'`, `endpoint_source='unknown'`, `direction='unknown'`. |

**Direction = куда идёт трафик**

| Source endpoint | Destination endpoint | `direction` |
|-----------------|----------------------|-------------|
| `local` или `customer` | `remote` | `out` |
| `remote` | `local` или `customer` | `in` |
| `local` или `customer` | `local` или `customer` | `internal` |
| `remote` | `remote` | `transit` |
| `unknown` с любой стороны | `unknown` |

Если local ASN/prefix справочники пустые, classifier оставляет fallback
`direction='out'`, чтобы новые инсталляции не теряли график до наполнения
справочников.

**Пример**

```text
src_vlan = 444
src_ip   = 8.8.8.8
dst_ip   = 195.2.240.10

src_attachment_kind     = uplink
src_attachment_boundary = external
src_attachment_label    = RETN uplink

src_endpoint_scope      = remote
src_endpoint_source     = fallback
dst_endpoint_scope      = customer
dst_endpoint_source     = prefix
dst_network_name        = PINDC customer block

direction = in
```

Читается как: "входящий трафик от внешнего IP через uplink в клиентскую сеть".

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

### DNS Enrichment

DNS enrichment строится из `default.dns_answers`. Это вероятная связь: если
клиент получил DNS answer IP, а затем flow этого же клиента пошёл на этот IP,
UI показывает домен и DNS-сервер, который дал ответ.

| Поле | Что значит | Как формируется |
|------|------------|-----------------|
| `dns_name` | Вероятный домен для flow destination/source IP. | `LEFT JOIN dns_answers` + `argMaxIf`: сначала `src_addr -> answer_ip`, затем reverse-match `dst_addr -> answer_ip`. |
| `dns_match_side` | Какая сторона flow совпала с DNS: `forward`, `reverse` или пусто. | `forward`: `flow.src_addr = dns.client_ip` и `flow.dst_addr = dns.answer_ip`; `reverse`: наоборот. |
| `dns_seen_at` | Время DNS-ответа, который использован для enrichment. | `dns_answers.ts`, только если DNS был раньше flow. |
| `dns_age_sec` | Сколько секунд прошло между DNS answer и flow. | `dateDiff('second', dns_answers.ts, flows_raw.time_received_ns)`. |
| `dns_server_ip` | IP DNS-сервера, который дал ответ. | `dns_answers.server_ip`, форматируется как IPv4/IPv6. |
| `dns_answer_type` | Тип DNS answer: `A` или `AAAA`. | `dns_answers.answer_type`. |
| `dns_ttl` | TTL конкретного answer IP. | `dns_answers.ttl`. |

По умолчанию DNS-match ограничен окном `30 минут` (`dns_window_sec = 1800`).
Если DNS старше окна или DNS answer не найден, DNS-поля возвращаются пустыми
или `0`. Для UI это should be treated as "no DNS context".

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
- attachment: `src_attachment_kind`, `dst_attachment_kind`,
  `src_attachment_boundary`, `dst_attachment_boundary`,
  `src_attachment_operator`, `dst_attachment_operator`;
- endpoint: `src_endpoint_scope`, `dst_endpoint_scope`,
  `src_endpoint_source`, `dst_endpoint_source`, `src_network_role`,
  `dst_network_role`;
- compatibility: `src_operator`, `dst_operator`, `operator_id`,
  `src_kind`, `dst_kind`;
- `min_bytes`, `min_packets`;
- `service_code`, `service_category`;
- DNS: `dns_name`, `dns_server_ip`, `has_dns_name`.

Sort whitelist:

- `time_received`;
- `bytes`;
- `packets`;
- `src_port`;
- `dst_port`;
- `direction`;
- `service_name`;
- `dns_name`;
- `dns_age_sec`.

## Notes

`unknown` direction is valid diagnostic data, but hidden by default in the UI.
It can be exposed with an explicit "include unknown" switch.
