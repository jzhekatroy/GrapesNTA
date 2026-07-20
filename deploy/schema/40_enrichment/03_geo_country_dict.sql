CREATE DICTIONARY IF NOT EXISTS default.geo_country_dict
(
    `prefix` String,
    `cc` String,
    `rir` String,
    `source` String,
    `snapshot_ts` DateTime
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(HOST '${CH_DICT_HOST}' PORT ${CH_DICT_PORT} USER '${CH_DICT_USER}' PASSWORD '${CH_DICT_PASSWORD}' DB 'default' TABLE 'geo_prefix_country' CONNECT_TIMEOUT 10 SEND_RECEIVE_TIMEOUT 30))
LIFETIME(MIN 0 MAX 0)
LAYOUT(IP_TRIE);
