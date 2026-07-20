CREATE DICTIONARY IF NOT EXISTS default.net_interfaces_dict
(
    `switch_ip` String,
    `if_index` UInt32,
    `if_name` String DEFAULT '',
    `if_alias` String DEFAULT '',
    `if_descr` String DEFAULT '',
    `if_high_speed_mbps` UInt32 DEFAULT 0,
    `if_speed_bps` UInt64 DEFAULT 0
)
PRIMARY KEY switch_ip, if_index
SOURCE(CLICKHOUSE(HOST '${CH_DICT_HOST}' PORT ${CH_DICT_PORT} USER '${CH_DICT_USER}' PASSWORD '${CH_DICT_PASSWORD}' DB 'default' TABLE 'net_interfaces_current'))
LIFETIME(MIN 60 MAX 120)
LAYOUT(COMPLEX_KEY_HASHED());
