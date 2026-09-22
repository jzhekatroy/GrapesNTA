-- Перевести default.flows_raw на ZSTD(3).
--
-- Меняется только упаковка колонок. Строки, типы и ключ сортировки те же.
-- Старая таблица flows_v1 не трогается: она доживает свой TTL.
--
-- После команды новые записи пишутся уже в ZSTD. Уже лежащие куски ClickHouse
-- переписывает фоновой мутацией, для этого нужно свободное место примерно
-- размером с саму flows_raw. Повторный запуск безопасен: если адреса уже в ZSTD,
-- скрипт-обёртка ничего не делает.
--
-- Не класть в ensure.list: это разовая перепись данных, её нельзя запускать
-- из обычного deploy.sh.

ALTER TABLE default.flows_raw
    MODIFY COLUMN `date` Date CODEC(ZSTD(3)),
    MODIFY COLUMN `time_inserted_ns` DateTime CODEC(DoubleDelta, ZSTD(3)),
    MODIFY COLUMN `time_received_ns` DateTime CODEC(DoubleDelta, ZSTD(3)),
    MODIFY COLUMN `time_flow_start_ns` DateTime CODEC(DoubleDelta, ZSTD(3)),
    MODIFY COLUMN `sequence_num` UInt32 CODEC(ZSTD(3)),
    MODIFY COLUMN `sampling_rate` UInt64 CODEC(ZSTD(3)),
    MODIFY COLUMN `sampler_address` FixedString(16) CODEC(ZSTD(3)),
    MODIFY COLUMN `src_addr` FixedString(16) CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_addr` FixedString(16) CODEC(ZSTD(3)),
    MODIFY COLUMN `etype` UInt32 CODEC(ZSTD(3)),
    MODIFY COLUMN `proto` UInt32 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `src_port` UInt32 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `dst_port` UInt32 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `src_vlan` UInt16 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `dst_vlan` UInt16 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `vlan_id` UInt32 CODEC(ZSTD(3)),
    MODIFY COLUMN `bytes` UInt64 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `packets` UInt64 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `src_asn` UInt32 DEFAULT 0 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `dst_asn` UInt32 DEFAULT 0 CODEC(T64, ZSTD(3)),
    MODIFY COLUMN `src_as_path` Array(UInt32) DEFAULT [] CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_as_path` Array(UInt32) DEFAULT [] CODEC(ZSTD(3)),
    MODIFY COLUMN `direction` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_kind` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_kind` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_label` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_label` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_operator` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_operator` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_attachment_kind` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_attachment_kind` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_attachment_boundary` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_attachment_boundary` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_attachment_label` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_attachment_label` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_attachment_operator` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_attachment_operator` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_endpoint_scope` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_endpoint_scope` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_endpoint_source` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_endpoint_source` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_network_name` String DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_network_name` String DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_network_role` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_network_role` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_role` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_role` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_entity` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_entity` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_client` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_client` LowCardinality(String) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `source_id` LowCardinality(String) DEFAULT 'xdp-default' CODEC(ZSTD(3)),
    MODIFY COLUMN `src_mac` FixedString(6) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `dst_mac` FixedString(6) DEFAULT '' CODEC(ZSTD(3)),
    MODIFY COLUMN `in_if` UInt32 DEFAULT 0 CODEC(ZSTD(3)),
    MODIFY COLUMN `out_if` UInt32 DEFAULT 0 CODEC(ZSTD(3)),
    MODIFY COLUMN `tcp_flags` UInt8 DEFAULT 0 CODEC(ZSTD(3)),
    MODIFY COLUMN `ip_ttl` UInt8 DEFAULT 0 CODEC(ZSTD(3)),
    MODIFY COLUMN `ip_tos` UInt8 DEFAULT 0 CODEC(ZSTD(3));
