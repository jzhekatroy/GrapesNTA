CREATE OR REPLACE VIEW default.bgp_prefix_origin_dict_src AS
SELECT
    prefix,
    any(origin_asn) AS origin_asn,
    any(peer_asn) AS peer_asn,
    max(active_paths) AS active_paths,
    any(source) AS source,
    max(snapshot_ts) AS snapshot_ts
FROM default.bgp_prefix_origin_current
GROUP BY prefix;

CREATE DICTIONARY IF NOT EXISTS default.bgp_origin_asn_dict
(
    `prefix` String,
    `origin_asn` UInt32,
    `peer_asn` UInt32,
    `active_paths` UInt32,
    `source` String,
    `snapshot_ts` DateTime
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(HOST '${CH_DICT_HOST}' PORT ${CH_DICT_PORT} USER '${CH_DICT_USER}' PASSWORD '${CH_DICT_PASSWORD}' DB 'default' TABLE 'bgp_prefix_origin_dict_src' CONNECT_TIMEOUT 10 SEND_RECEIVE_TIMEOUT 30))
LIFETIME(MIN 0 MAX 0)
LAYOUT(IP_TRIE);
