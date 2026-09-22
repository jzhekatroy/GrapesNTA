-- Сырые потоки.
--
-- Раскладка подчинена тому, как таблицу читают. Почти каждый запрос разбора
-- трафика — это «окно по времени плюс фильтр по коммутатору и порту», поэтому
-- ключ сортировки начинается с пятиминутного отрезка времени, затем идут адрес
-- экспортёра и номера портов. За счёт этого, во-первых, работает отсечение
-- гранул по таким фильтрам, во-вторых, одинаковые значения ложатся подряд и
-- сжимаются в десятки раз: при сортировке только по времени номер порта был
-- размазан по всему файлу и сжимался всего вдвое.
--
-- Последним в ключе стоит само time_received_ns. Индекс по нему не строится
-- (см. PRIMARY KEY), но внутри каждой группы время снова идёт по возрастанию,
-- и DoubleDelta на колонке времени работает так же хорошо, как раньше. Без
-- этого пересортировка раздула бы колонку времени примерно втрое.
--
-- Время хранится с точностью до секунды. Экспортёры доли секунды не отдают,
-- обнаружение атак работает минутными окнами, а хранение долей секунды после
-- пересортировки обходится втрое дороже.
--
-- Сжатие LZ4, а не ZSTD: узкое место на разборе трафика процессорное, и время
-- распаковки важнее лишних процентов места.
CREATE TABLE IF NOT EXISTS default.flows_raw
(
    `date` Date,
    `time_inserted_ns` DateTime CODEC(DoubleDelta, LZ4),
    `time_received_ns` DateTime CODEC(DoubleDelta, LZ4),
    `time_flow_start_ns` DateTime CODEC(DoubleDelta, LZ4),
    `sequence_num` UInt32,
    `sampling_rate` UInt64,
    `sampler_address` FixedString(16),
    `src_addr` FixedString(16),
    `dst_addr` FixedString(16),
    `etype` UInt32,
    `proto` UInt32 CODEC(T64, LZ4),
    `src_port` UInt32 CODEC(T64, LZ4),
    `dst_port` UInt32 CODEC(T64, LZ4),
    `src_vlan` UInt16 CODEC(T64, LZ4),
    `dst_vlan` UInt16 CODEC(T64, LZ4),
    `vlan_id` UInt32,
    `bytes` UInt64 CODEC(T64, LZ4),
    `packets` UInt64 CODEC(T64, LZ4),
    `src_asn` UInt32 DEFAULT 0 CODEC(T64, LZ4),
    `dst_asn` UInt32 DEFAULT 0 CODEC(T64, LZ4),
    `src_as_path` Array(UInt32) DEFAULT [],
    `dst_as_path` Array(UInt32) DEFAULT [],
    `direction` LowCardinality(String) DEFAULT 'unknown',
    `src_kind` LowCardinality(String) DEFAULT 'unknown',
    `dst_kind` LowCardinality(String) DEFAULT 'unknown',
    `src_label` LowCardinality(String) DEFAULT '',
    `dst_label` LowCardinality(String) DEFAULT '',
    `src_operator` LowCardinality(String) DEFAULT '',
    `dst_operator` LowCardinality(String) DEFAULT '',
    `src_attachment_kind` LowCardinality(String) DEFAULT 'unknown',
    `dst_attachment_kind` LowCardinality(String) DEFAULT 'unknown',
    `src_attachment_boundary` LowCardinality(String) DEFAULT 'unknown',
    `dst_attachment_boundary` LowCardinality(String) DEFAULT 'unknown',
    `src_attachment_label` LowCardinality(String) DEFAULT '',
    `dst_attachment_label` LowCardinality(String) DEFAULT '',
    `src_attachment_operator` LowCardinality(String) DEFAULT '',
    `dst_attachment_operator` LowCardinality(String) DEFAULT '',
    `src_endpoint_scope` LowCardinality(String) DEFAULT 'unknown',
    `dst_endpoint_scope` LowCardinality(String) DEFAULT 'unknown',
    `src_endpoint_source` LowCardinality(String) DEFAULT 'unknown',
    `dst_endpoint_source` LowCardinality(String) DEFAULT 'unknown',
    `src_network_name` String DEFAULT '',
    `dst_network_name` String DEFAULT '',
    `src_network_role` LowCardinality(String) DEFAULT '',
    `dst_network_role` LowCardinality(String) DEFAULT '',
    `src_role` LowCardinality(String) DEFAULT '',
    `dst_role` LowCardinality(String) DEFAULT '',
    `src_entity` LowCardinality(String) DEFAULT '',
    `dst_entity` LowCardinality(String) DEFAULT '',
    `src_client` LowCardinality(String) DEFAULT '',
    `dst_client` LowCardinality(String) DEFAULT '',
    `source_id` LowCardinality(String) DEFAULT 'xdp-default',
    `src_mac` FixedString(6) DEFAULT '',
    `dst_mac` FixedString(6) DEFAULT '',
    `in_if` UInt32 DEFAULT 0,
    `out_if` UInt32 DEFAULT 0,
    `tcp_flags` UInt8 DEFAULT 0,
    `ip_ttl` UInt8 DEFAULT 0,
    `ip_tos` UInt8 DEFAULT 0,
    INDEX idx_obs_src_vlan src_vlan TYPE set(0) GRANULARITY 4,
    INDEX idx_obs_dst_vlan dst_vlan TYPE set(0) GRANULARITY 4,
    INDEX idx_obs_src_port src_port TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_obs_dst_port dst_port TYPE bloom_filter(0.01) GRANULARITY 4,
    -- Cabinet lookups are "this client on either side", i.e. an OR over both
    -- columns. Per-column indexes cannot decide such an OR on their own, so both
    -- columns live in one set index that evaluates the whole expression.
    INDEX idx_client (src_client, dst_client) TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY date
-- Разреженный индекс строится только по первым четырём колонкам: добавлять в
-- него само время смысла нет, оно уже задано пятиминутным отрезком, а размер
-- индекса вырос бы заметно.
PRIMARY KEY (toStartOfFiveMinutes(time_received_ns), sampler_address, in_if, out_if)
ORDER BY (toStartOfFiveMinutes(time_received_ns), sampler_address, in_if, out_if, time_received_ns)
TTL date + toIntervalDay(4)
SETTINGS index_granularity = 8192, max_bytes_to_merge_at_max_space_in_pool = 8589934592;
