-- Optional ClickHouse dictionary for SNMP interface enrichment.
-- Apply over the local native ClickHouse port, not via an external HTTP proxy:
--   docker exec -i kcg-main-db-1 clickhouse-client --multiquery < deploy/clickhouse/net_snmp_interfaces_dict.sql
--
-- IMPORTANT:
--   Replace SOURCE USER/PASSWORD with a real account that can SELECT
--   from default.net_interfaces_current. Empty-password `default` fails on
--   hardened installs.
--   After CREATE, grant dictGet to any role that uses dictGet():
--     GRANT dictGet ON default.net_interfaces_dict TO ui_read;
--
-- NTAdmin Explorer does not require this dictionary: it JOINs
-- net_interfaces_current directly under the ui_read role.

DROP DICTIONARY IF EXISTS default.net_interfaces_dict;

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
    USER '${CH_DICT_USER}'
    PASSWORD '${CH_DICT_PASSWORD}'
    DB 'default'
    TABLE 'net_interfaces_current'
))
LIFETIME(MIN 60 MAX 120)
LAYOUT(COMPLEX_KEY_HASHED());
