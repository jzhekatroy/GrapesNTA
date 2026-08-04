-- Known DNS resolvers: a display-level catalog for the DNS page.
--
-- Apply on an existing installation:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_dns_resolvers.sql
--
-- This is NOT net_flow_exclusions. Nothing here drops traffic: an operator's
-- own recursive resolver aggregates every subscriber, so its queries are the
-- data you need in order to find the abuser behind it. The catalog only lets
-- the UI label such an address and fold it out of the top, where it would
-- otherwise sit in first place forever and hide the interesting rows.
--
-- role:
--   resolver  — the operator's own recursive resolver (millions of queries is normal)
--   client    — a subscriber's resolver (same, but it belongs to a client)
--   public    — a well-known public resolver, seen as a destination

CREATE TABLE IF NOT EXISTS default.net_dns_resolvers
(
    resolver_id  String,
    prefix       String,
    family       UInt8 DEFAULT 0,
    role         LowCardinality(String) DEFAULT 'resolver',
    display_name String DEFAULT '',
    comment      String DEFAULT '',
    enabled      UInt8,
    source       LowCardinality(String) DEFAULT 'manual',
    updated_at   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY resolver_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_dns_resolvers_enabled;

CREATE VIEW default.net_dns_resolvers_enabled AS
SELECT
    resolver_id,
    prefix,
    family,
    role,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        resolver_id,
        argMax(prefix, updated_at) AS prefix,
        argMax(family, updated_at) AS family,
        argMax(role, updated_at) AS role,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_dns_resolvers
    GROUP BY resolver_id
)
WHERE enabled_latest = 1;

-- Seed the public resolvers, which are the same everywhere. The operator's own
-- and its clients' resolvers are site-specific and get added from the UI.
INSERT INTO default.net_dns_resolvers
    (resolver_id, prefix, family, role, display_name, comment, enabled, source)
SELECT
    resolver_id, prefix, family, role, display_name, comment, enabled, source
FROM
(
    SELECT 'public-google-8888'   AS resolver_id, '8.8.8.8/32'        AS prefix, 4 AS family, 'public' AS role, 'Google Public DNS'     AS display_name, '' AS comment, 1 AS enabled, 'seed' AS source
    UNION ALL SELECT 'public-google-8844',   '8.8.4.4/32',        4, 'public', 'Google Public DNS',   '', 1, 'seed'
    UNION ALL SELECT 'public-cloudflare-1',  '1.1.1.1/32',        4, 'public', 'Cloudflare DNS',      '', 1, 'seed'
    UNION ALL SELECT 'public-cloudflare-2',  '1.0.0.1/32',        4, 'public', 'Cloudflare DNS',      '', 1, 'seed'
    UNION ALL SELECT 'public-quad9-1',       '9.9.9.9/32',        4, 'public', 'Quad9',               '', 1, 'seed'
    UNION ALL SELECT 'public-quad9-2',       '149.112.112.112/32',4, 'public', 'Quad9',               '', 1, 'seed'
    UNION ALL SELECT 'public-yandex-1',      '77.88.8.8/32',      4, 'public', 'Yandex DNS',          '', 1, 'seed'
    UNION ALL SELECT 'public-yandex-2',      '77.88.8.1/32',      4, 'public', 'Yandex DNS',          '', 1, 'seed'
    UNION ALL SELECT 'public-opendns-1',     '208.67.222.222/32', 4, 'public', 'OpenDNS',             '', 1, 'seed'
    UNION ALL SELECT 'public-opendns-2',     '208.67.220.220/32', 4, 'public', 'OpenDNS',             '', 1, 'seed'
    UNION ALL SELECT 'public-adguard-1',     '94.140.14.14/32',   4, 'public', 'AdGuard DNS',         '', 1, 'seed'
    UNION ALL SELECT 'public-google-v6-8888','2001:4860:4860::8888/128', 6, 'public', 'Google Public DNS', '', 1, 'seed'
    UNION ALL SELECT 'public-cloudflare-v6', '2606:4700:4700::1111/128', 6, 'public', 'Cloudflare DNS',    '', 1, 'seed'
) AS seed
WHERE resolver_id NOT IN (SELECT resolver_id FROM default.net_dns_resolvers);
