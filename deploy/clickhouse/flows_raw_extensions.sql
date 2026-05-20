-- Enrichment columns written by xdpflowd classifier.
--
-- Apply before starting xdpflowd with XDP_CLASSIFIER=1. Existing rows keep
-- DEFAULT values and remain readable.

ALTER TABLE default.flows_raw
ADD COLUMN IF NOT EXISTS src_asn UInt32 DEFAULT 0,
ADD COLUMN IF NOT EXISTS dst_asn UInt32 DEFAULT 0,
ADD COLUMN IF NOT EXISTS direction LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS src_kind LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS dst_kind LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS src_label LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS dst_label LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS src_operator LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS dst_operator LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS src_attachment_kind LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS dst_attachment_kind LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS src_attachment_boundary LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS dst_attachment_boundary LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS src_attachment_label LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS dst_attachment_label LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS src_attachment_operator LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS dst_attachment_operator LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS src_endpoint_scope LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS dst_endpoint_scope LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS src_endpoint_source LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS dst_endpoint_source LowCardinality(String) DEFAULT 'unknown',
ADD COLUMN IF NOT EXISTS src_network_name String DEFAULT '',
ADD COLUMN IF NOT EXISTS dst_network_name String DEFAULT '',
ADD COLUMN IF NOT EXISTS src_network_role LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS dst_network_role LowCardinality(String) DEFAULT '',
ADD COLUMN IF NOT EXISTS src_vlan UInt16 DEFAULT 0,
ADD COLUMN IF NOT EXISTS dst_vlan UInt16 DEFAULT 0;
