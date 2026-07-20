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
SOURCE(CLICKHOUSE(HOST '${CH_DICT_HOST}' PORT ${CH_DICT_PORT} USER '${CH_DICT_USER}' PASSWORD '${CH_DICT_PASSWORD}' DB 'default' TABLE 'bgp_prefix_origin_current' CONNECT_TIMEOUT 10 SEND_RECEIVE_TIMEOUT 30))
LIFETIME(MIN 0 MAX 0)
LAYOUT(IP_TRIE);
