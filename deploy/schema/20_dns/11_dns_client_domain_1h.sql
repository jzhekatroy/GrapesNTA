-- Per-client DNS vitrine for the cabinet.
--
-- The key is the registrable domain, not the queried name: a single video
-- session asks rr3---sn-x.googlevideo.com and dozens of siblings, and a client
-- reading "which sites did my network use" wants youtube.com. The whole log
-- produces about 1.9 million distinct names per hour against far fewer
-- registrable domains, so this also decides whether the table is affordable.
--
-- Two names cannot come from the public suffix list and are therefore safe
-- sentinels: 'other' is the folded tail past the per-client top, and 'unknown'
-- is a name the suffix list could not reduce.
--
-- client_id leads the sort key because every query is "one client over a
-- period". Retention is longer than the 30 day raw log on purpose: outliving
-- the log is the entire reason a vitrine exists.
CREATE TABLE IF NOT EXISTS default.dns_client_domain_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `domain` String,
    `queries` UInt64,
    `responses` UInt64,
    `nxdomain` UInt64,
    `servfail` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (client_id, hour, source_id, domain)
TTL hour + toIntervalDay(180)
SETTINGS index_granularity = 8192;
