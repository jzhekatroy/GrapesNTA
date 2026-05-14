-- Editable service dictionary and service-level traffic aggregates.
--
-- Apply after default.flows_raw exists. The port_services table is intentionally
-- small and human-editable from Laravel/MoonShine; seed rows below are just a
-- practical MVP baseline, not a full IANA registry dump.

CREATE TABLE IF NOT EXISTS default.port_services
(
    transport     LowCardinality(String), -- tcp / udp / sctp / icmp
    port          UInt16,
    service_code  LowCardinality(String), -- ssh / https / dns / smtp
    service_name  String,
    category      LowCardinality(String), -- web / dns / mail / remote_access / ...
    description   String DEFAULT '',
    is_enabled    UInt8 DEFAULT 1,
    updated_at    DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (transport, port)
SETTINGS index_granularity = 8192;

INSERT INTO default.port_services
    (transport, port, service_code, service_name, category, description)
VALUES
    ('tcp', 20, 'ftp_data', 'FTP Data', 'file_transfer', 'FTP data channel'),
    ('tcp', 21, 'ftp', 'FTP', 'file_transfer', 'File Transfer Protocol'),
    ('tcp', 22, 'ssh', 'SSH', 'remote_access', 'Secure Shell'),
    ('tcp', 23, 'telnet', 'Telnet', 'remote_access', 'Telnet'),
    ('tcp', 25, 'smtp', 'SMTP', 'mail', 'Simple Mail Transfer Protocol'),
    ('udp', 53, 'dns', 'DNS', 'dns', 'Domain Name System'),
    ('tcp', 53, 'dns', 'DNS', 'dns', 'Domain Name System over TCP'),
    ('udp', 67, 'dhcp_server', 'DHCP Server', 'network', 'DHCP server'),
    ('udp', 68, 'dhcp_client', 'DHCP Client', 'network', 'DHCP client'),
    ('tcp', 80, 'http', 'HTTP', 'web', 'Hypertext Transfer Protocol'),
    ('udp', 123, 'ntp', 'NTP', 'time', 'Network Time Protocol'),
    ('tcp', 110, 'pop3', 'POP3', 'mail', 'Post Office Protocol v3'),
    ('udp', 161, 'snmp', 'SNMP', 'network_management', 'Simple Network Management Protocol'),
    ('udp', 162, 'snmptrap', 'SNMP Trap', 'network_management', 'SNMP traps'),
    ('tcp', 143, 'imap', 'IMAP', 'mail', 'Internet Message Access Protocol'),
    ('tcp', 389, 'ldap', 'LDAP', 'directory', 'Lightweight Directory Access Protocol'),
    ('udp', 500, 'ike', 'IKE', 'vpn', 'IPsec Internet Key Exchange'),
    ('tcp', 443, 'https', 'HTTPS', 'web', 'HTTP over TLS'),
    ('udp', 443, 'quic', 'QUIC/HTTP3', 'web', 'QUIC and HTTP/3'),
    ('tcp', 465, 'smtps', 'SMTPS', 'mail', 'SMTP over TLS'),
    ('tcp', 587, 'submission', 'Mail Submission', 'mail', 'SMTP message submission'),
    ('udp', 514, 'syslog', 'Syslog', 'logging', 'Syslog'),
    ('tcp', 636, 'ldaps', 'LDAPS', 'directory', 'LDAP over TLS'),
    ('tcp', 993, 'imaps', 'IMAPS', 'mail', 'IMAP over TLS'),
    ('tcp', 995, 'pop3s', 'POP3S', 'mail', 'POP3 over TLS'),
    ('tcp', 1433, 'mssql', 'MSSQL', 'database', 'Microsoft SQL Server'),
    ('tcp', 1521, 'oracle', 'Oracle DB', 'database', 'Oracle database listener'),
    ('tcp', 1723, 'pptp', 'PPTP', 'vpn', 'Point-to-Point Tunneling Protocol'),
    ('udp', 1812, 'radius_auth', 'RADIUS Auth', 'aaa', 'RADIUS authentication'),
    ('udp', 1813, 'radius_acct', 'RADIUS Accounting', 'aaa', 'RADIUS accounting'),
    ('tcp', 2049, 'nfs', 'NFS', 'file_transfer', 'Network File System'),
    ('udp', 2049, 'nfs', 'NFS', 'file_transfer', 'Network File System'),
    ('tcp', 3306, 'mysql', 'MySQL', 'database', 'MySQL database'),
    ('tcp', 3389, 'rdp', 'RDP', 'remote_access', 'Remote Desktop Protocol'),
    ('tcp', 5432, 'postgresql', 'PostgreSQL', 'database', 'PostgreSQL database'),
    ('tcp', 5672, 'amqp', 'AMQP', 'messaging', 'Advanced Message Queuing Protocol'),
    ('tcp', 5900, 'vnc', 'VNC', 'remote_access', 'Virtual Network Computing'),
    ('tcp', 6379, 'redis', 'Redis', 'database', 'Redis'),
    ('tcp', 8080, 'http_alt', 'HTTP Alternate', 'web', 'Common alternate HTTP port'),
    ('tcp', 8443, 'https_alt', 'HTTPS Alternate', 'web', 'Common alternate HTTPS port'),
    ('tcp', 9092, 'kafka', 'Kafka', 'messaging', 'Apache Kafka'),
    ('tcp', 9200, 'elasticsearch', 'Elasticsearch', 'search', 'Elasticsearch HTTP API'),
    ('tcp', 27017, 'mongodb', 'MongoDB', 'database', 'MongoDB database');

CREATE TABLE IF NOT EXISTS default.traffic_service_1m
(
    minute        DateTime('UTC'),
    direction     LowCardinality(String), -- in / out / internal / transit / unknown
    transport     LowCardinality(String), -- tcp / udp / icmp / other
    service_port  UInt16,
    service_code  LowCardinality(String),
    service_name  String,
    category      LowCardinality(String),
    bytes         UInt64,
    packets       UInt64,
    flows_count   UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction, transport, category, service_code, service_port)
TTL minute + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- Template MV for service aggregates.
--
-- This needs the final direction expression from local_networks and should be
-- enabled after the local network dictionary is defined. Keep it here as the
-- contract for the aggregate table.
--
-- CREATE MATERIALIZED VIEW default.traffic_service_1m_mv
-- TO default.traffic_service_1m
-- AS
-- SELECT
--     toStartOfMinute(time_received_ns) AS minute,
--     direction_expr AS direction,
--     multiIf(proto = 6, 'tcp', proto = 17, 'udp', proto = 1, 'icmp', 'other') AS transport,
--     if(direction = 'in', toUInt16(src_port), toUInt16(dst_port)) AS service_port,
--     ifNull(ps.service_code, 'unknown') AS service_code,
--     ifNull(ps.service_name, 'Unknown') AS service_name,
--     ifNull(ps.category, 'unknown') AS category,
--     sum(bytes) AS bytes,
--     sum(packets) AS packets,
--     count() AS flows_count
-- FROM default.flows_raw AS f
-- LEFT JOIN default.port_services AS ps
--     ON ps.transport = transport
--    AND ps.port = service_port
--    AND ps.is_enabled = 1
-- GROUP BY
--     minute, direction, transport, service_port,
--     service_code, service_name, category;
