-- Apply over the local native ClickHouse port, not via an external HTTP proxy.
-- Example:
--   docker exec -i ch clickhouse-client --multiquery < deploy/clickhouse/net_snmp_interfaces_dict.sql

DROP TABLE IF EXISTS default.net_interfaces_dict;

CREATE DICTIONARY default.net_interfaces_dict
(
    switch_ip          String,
    if_index           UInt32,
    if_name            String DEFAULT '',
    if_alias           String DEFAULT '',
    if_descr           String DEFAULT '',
    if_high_speed_mbps UInt32 DEFAULT 0,
    if_speed_bps       UInt64 DEFAULT 0
)
PRIMARY KEY switch_ip, if_index
SOURCE(CLICKHOUSE(
    HOST '127.0.0.1'
    PORT 9000
    USER 'default'
    PASSWORD ''
    DB 'default'
    TABLE 'net_interfaces_current'
))
LIFETIME(MIN 60 MAX 120)
LAYOUT(COMPLEX_KEY_HASHED());
