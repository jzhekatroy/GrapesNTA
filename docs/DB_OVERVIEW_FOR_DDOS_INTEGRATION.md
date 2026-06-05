# Обзор ClickHouse БД для интеграции DDoS-модуля

Документ для нового разработчика, который будет интегрировать модуль защиты от
DDoS с Grapes NTA. Описание поверхностное: где какие данные лежат, какие поля
важны и для чего таблицы используются.

База по умолчанию: `default`.

## Главное

Для большинства интеграций **не нужно читать `flows_raw` напрямую**. Это самая
большая raw-таблица. Для UI, алертов и быстрых проверок сначала использовать
агрегаты:

| Задача | Рекомендуемая таблица |
|--------|------------------------|
| Общий трафик по направлениям | `traffic_dashboard_1m`, `traffic_dashboard_1h`, `traffic_dashboard_1d` |
| Top источники / назначения | `traffic_talker_1m`, `traffic_talker_1h` |
| Top пары `src -> dst` | `traffic_pair_1m`, `traffic_pair_1h` |
| Top протоколы IP | `traffic_protocol_1m` |
| Top сервисы/порты | `traffic_service_1m`, `traffic_unknown_port_1m` |
| География / страны | `traffic_country_1m` |
| DNS события | `dns_log`, `dns_answers` |
| Справочник наших сетей | `net_l3_prefixes_enabled` |
| Справочник источников данных | `net_flow_sources_enabled` |

## Направления трафика

Поле `direction` уже рассчитано в `xdpflowd` и записано в таблицы.

| Значение | Что значит |
|----------|------------|
| `in` | внешний источник -> наша/клиентская сеть |
| `out` | наша/клиентская сеть -> внешний получатель |
| `internal` | наша/клиентская сеть -> наша/клиентская сеть |
| `transit` | внешний источник -> внешний получатель через нас |
| `unknown` | направление не удалось определить |

В UI может быть режим **«Всего»**, но в ClickHouse нет `direction = 'total'`.
Для «Всего» использовать:

```sql
direction IN ('in', 'out', 'transit', 'internal', 'unknown')
```

## Raw flow

### `flows_raw`

Главная raw-таблица flow-событий. Очень большая, использовать только когда
агрегатов недостаточно.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `time_received_ns` | время получения flow | фильтр периода, построение агрегатов |
| `src_addr`, `dst_addr` | source/destination IP в бинарном виде | raw drill-down, построение IP-агрегатов |
| `src_asn`, `dst_asn` | origin ASN source/destination IP | ASN/GEO enrichment, top talkers |
| `direction` | направление трафика | все dashboard/top таблицы |
| `src_endpoint_scope`, `dst_endpoint_scope` | чей IP: `local`, `customer`, `remote`, `unknown` | классификация DDoS: внешний/наш/клиентский endpoint |
| `src_network_name`, `dst_network_name` | имя сети/префикса, если IP попал в справочник | показывать владельца/сеть назначения |
| `src_network_role`, `dst_network_role` | роль сети: local/customer/internal и т.п. | классификация трафика |
| `src_label`, `dst_label` | человекочитаемая подпись endpoint | UI, drill-down |
| `proto` | IP protocol number | protocol analytics |
| `src_port`, `dst_port` | порты | service/port analytics |
| `bytes`, `packets` | объём flow | все метрики |
| `source_id` | источник наблюдения | фильтр источников, защита от double-count |

## Источники данных

### `net_flow_sources` / `net_flow_sources_enabled`

Справочник источников трафика: XDP, NetFlow, IPFIX, sFlow, DNS и т.п.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `source_id` | ID источника, например `xdp-default` | join/filter во всех агрегатах |
| `display_name` | название для UI | фильтр источников |
| `source_type` | тип источника: `xdp`, `netflow`, `dns`, ... | UI/операционные проверки |
| `include_in_total` | включать ли источник в total | dashboard и DDoS-метрики по умолчанию |
| `enabled` | активен ли источник | soft-delete |

Для default-запросов обычно нужен join:

```sql
INNER JOIN default.net_flow_sources_enabled AS s ON t.source_id = s.source_id
WHERE s.include_in_total = 1
```

## Справочники сети

### `net_entities` / `net_entities_enabled`

Объекты сети: клиент, узел, аплинк, наша инфраструктура и т.п.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `entity_id` | стабильный ID объекта | связь с префиксами/VLAN |
| `display_name` | человекочитаемое имя | UI, отчёты |
| `enabled` | активен ли объект | справочник |

### `net_l3_prefixes` / `net_l3_prefixes_enabled`

IP-префиксы, по которым система понимает, чей это IP и куда идёт трафик.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `prefix` | IP-префикс | классификация endpoint |
| `family` | IPv4/IPv6 | classifier |
| `entity_id` | владелец/объект сети | UI, отчёты |
| `role` | роль: `provider_public`, `internal`, `customer_allocated`, `customer_transit` | расчёт `direction` |
| `display_name` | название префикса | labels/drill-down |
| `enabled` | активен ли префикс | classifier |

### `net_l2_vlans` / `net_l2_vlans_enabled`

L2/VLAN-контекст: где пакет был увиден.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `vlan_id` | VLAN | attachment context |
| `entity_id` | объект сети | UI/аналитика |
| `attachment_type` | `customer`, `uplink`, `ix`, `peering`, `core`, ... | где увидели пакет |
| `boundary` | `internal`, `external`, `unknown` | диагностика direction |
| `display_name` | подпись VLAN/линка | UI |

## Dashboard агрегаты

### `traffic_dashboard_1m`, `traffic_dashboard_1h`, `traffic_dashboard_1d`

Быстрые таблицы для общей картины: total/in/out/transit/internal/unknown.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `minute` / `hour` / `day` | временной bucket | период |
| `source_id` | источник данных | фильтр источника |
| `total_bytes`, `total_packets` | весь трафик | KPI, графики |
| `in_bytes`, `out_bytes` | входящий/исходящий | DDoS baseline, charts |
| `transit_bytes`, `internal_bytes`, `unknown_bytes` | остальные направления | диагностика |

Для DDoS-модуля это быстрый источник baseline по скорости и объёму.

## Top talkers

### `traffic_talker_1m`, `traffic_talker_1h`

Top endpoint-ы. Одна и та же flow-запись попадает в таблицу дважды:
`endpoint_side = 'src'` и `endpoint_side = 'dst'`.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `minute` / `hour` | bucket | период |
| `source_id` | источник данных | фильтр источников |
| `endpoint_side` | `src` или `dst` | вкладки «Источники» / «Назначения» |
| `direction` | направление flow | входящий/исходящий/total |
| `endpoint_ip` | IP endpoint-а | top IP |
| `endpoint_asn`, `endpoint_as_name` | ASN endpoint-а | ASN display/filter |
| `endpoint_ip_country` | страна IP | GEO |
| `endpoint_as_country` | страна ASN | дополнительная справка |
| `endpoint_scope` | `local`, `customer`, `remote`, `unknown` | понять, внешний это IP или наш |
| `endpoint_label` | label/DNS/name | UI |
| `endpoint_network_name`, `endpoint_network_role` | сеть/роль, если IP локальный/клиентский | DDoS target attribution |
| `bytes`, `packets`, `flows_count` | метрики | сортировка/детали |

Использование:

| UI/задача | Фильтр |
|-----------|--------|
| Топ источников входящего DDoS | `direction = 'in' AND endpoint_side = 'src'` |
| Топ целей входящего DDoS | `direction = 'in' AND endpoint_side = 'dst'` |
| Топ наших исходящих отправителей | `direction = 'out' AND endpoint_side = 'src'` |
| Топ внешних назначений исходящего | `direction = 'out' AND endpoint_side = 'dst'` |

По периоду:

| Период | Таблица |
|--------|---------|
| до 1 часа | `traffic_talker_1m` |
| 3h/6h/12h/24h+ | `traffic_talker_1h` |

### `traffic_pair_1m`, `traffic_pair_1h`

Top пары `src_ip -> dst_ip`. Самый детальный и самый тяжёлый top-агрегат.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `minute` / `hour` | bucket | период |
| `source_id` | источник данных | фильтр источников |
| `direction` | направление flow | входящий/исходящий |
| `src_ip`, `dst_ip` | пара IP | вкладка «Пары» |
| `src_asn`, `dst_asn` | ASN обеих сторон | подробности |
| `src_as_name`, `dst_as_name` | названия ASN | UI |
| `src_ip_country`, `dst_ip_country` | GEO обеих сторон | UI |
| `src_scope`, `dst_scope` | чей IP | понять атакующий/цель |
| `src_label`, `dst_label` | подписи | UI |
| `bytes`, `packets`, `flows_count` | метрики | сортировка/детали |

Для DDoS:

| Задача | Фильтр |
|--------|--------|
| Кто атакует какую цель | `direction = 'in'`, group by `src_ip -> dst_ip` |
| Какие наши IP создают исходящий трафик | `direction = 'out'`, group by `src_ip -> dst_ip` |

## Протоколы и сервисы

### `traffic_protocol_1m`

Агрегат по IP protocol number.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `minute` | bucket | период |
| `source_id` | источник данных | фильтр |
| `proto` | IP protocol number: TCP=6, UDP=17, ICMP=1, GRE=47 и т.п. | L3/L4 профиль атаки |
| `direction` | направление | фильтр |
| `bytes`, `packets`, `flows_count` | метрики | графики/алерты |

### `traffic_service_1m`

Агрегат по сервису, определённому через `port_services`.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `minute` | bucket | период |
| `source_id` | источник данных | фильтр |
| `direction` | направление | фильтр |
| `proto`, `transport` | протокол | TCP/UDP/ICMP и т.п. |
| `service_side` | порт найден на `src` или `dst` | диагностика |
| `service_port` | порт сервиса | top ports/services |
| `service_code`, `service_name`, `category` | описание сервиса | UI |
| `bytes`, `packets`, `flows_count` | метрики | DDoS profile |

### `traffic_unknown_port_1m`

Top портов, которые не попали в `port_services`. Используется для drill-down
среза «Other».

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `transport` | TCP/UDP/other | профиль неизвестного трафика |
| `port_side` | `src`/`dst` | где найден порт |
| `port` | порт | top unknown ports |
| `bytes`, `packets`, `flows_count` | метрики | анализ аномалий |

## География и ASN

### `traffic_country_1m`

Агрегат по странам для heatmap/top countries.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `minute` | bucket | период |
| `source_id` | источник данных | фильтр |
| `country_basis` | `ip` или `asn` | страна IP-префикса или страна ASN |
| `country_side` | `src` или `dst` | какую сторону flow смотреть |
| `direction` | направление | фильтр |
| `country_code` | ISO код страны, `??` если неизвестно | heatmap |
| `bytes`, `packets`, `flows_count` | метрики | top countries |

Для DDoS чаще всего использовать `country_basis = 'ip'`.

### `geo_prefix_country`, `geo_country_dict`

Справочник IP prefix -> country. `geo_country_dict` используется через
`dictGetString(...)`.

### `asn_registry`, `asn_registry_enriched`, `asn_names`

ASN registry и названия ASN.

| Таблица | Назначение |
|---------|------------|
| `asn_registry` | ASN -> country/RIR из RIR delegated files |
| `asn_names` | ручные/обогащённые названия ASN |
| `asn_registry_enriched` | view: ASN + name + country |

## DNS

### `dns_log`

Raw DNS события.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `ts` | время | период |
| `source_id` | источник DNS данных | фильтр |
| `client_ip` | клиент | top DNS clients |
| `qname` | домен | DDoS/DNS abuse analytics |
| `qtype` | тип запроса | профиль DNS |
| `rcode` | код ответа | NXDOMAIN/SERVFAIL |

### `dns_answers`

Ответы DNS.

| Поле | Назначение | Где используется |
|------|------------|------------------|
| `ts` | время | период |
| `qname` | домен | связь с запросом |
| `answer` | ответ | IP/domain mapping |
| `answer_type` | тип ответа | A/AAAA/CNAME и т.п. |

## BGP / BMP

### `bgp_prefix_origin_current`

Текущий BGP origin ASN по префиксам. Используется `xdpflowd` для определения
`src_asn` / `dst_asn`.

| Поле | Назначение |
|------|------------|
| `prefix` | BGP prefix |
| `origin_asn` | origin ASN |
| `updated_at` | время обновления |

### `bmp_*`

BMP/BGP raw/служебные таблицы. Для DDoS-интеграции обычно нужны только как
источник ASN/prefix enrichment, напрямую читать их не обязательно.

## Рекомендации для DDoS-модуля

### Быстро определить возможную входящую атаку

1. Смотреть `traffic_dashboard_1m` / `traffic_dashboard_1h` по `in_bytes`,
   `in_packets`.
2. При всплеске взять top источники:
   `traffic_talker_1m/1h` с `direction = 'in' AND endpoint_side = 'src'`.
3. Взять top целей:
   `traffic_talker_1m/1h` с `direction = 'in' AND endpoint_side = 'dst'`.
4. Для конкретных связок:
   `traffic_pair_1m/1h` с `direction = 'in'`.
5. Для профиля атаки:
   `traffic_protocol_1m`, `traffic_service_1m`, `traffic_unknown_port_1m`.

### Что считать внешним источником

Для входящего DDoS:

```sql
direction = 'in'
endpoint_side = 'src'
endpoint_scope = 'remote'
```

`endpoint_scope` уже есть в `traffic_talker_*`.

### Что считать целью

Для входящего DDoS:

```sql
direction = 'in'
endpoint_side = 'dst'
```

Цель можно дополнительно читать через:

- `endpoint_ip`;
- `endpoint_label`;
- `endpoint_network_name`;
- `endpoint_network_role`;
- `endpoint_scope`.

## Важные оговорки

- `flows_raw` огромная. Не строить UI/алерты по ней без крайней необходимости.
- Всегда учитывать `source_id` и `include_in_total`, чтобы не double-count-ить
  трафик с разных источников.
- В ClickHouse нет `direction = 'total'`; total — это сумма реальных направлений.
- `traffic_pair_*` имеет высокую кардинальность. Для длинных периодов использовать
  только `traffic_pair_1h`.
- `IP country` и `ASN country` — разные вещи. Для географии атаки обычно
  использовать IP-country.

