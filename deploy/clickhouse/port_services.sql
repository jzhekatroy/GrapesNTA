-- Editable service dictionary.
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
    ('udp', 5060, 'sip', 'SIP', 'voip', 'Session Initiation Protocol'),
    ('tcp', 5060, 'sip', 'SIP', 'voip', 'Session Initiation Protocol over TCP'),
    ('tcp', 5672, 'amqp', 'AMQP', 'messaging', 'Advanced Message Queuing Protocol'),
    ('tcp', 5900, 'vnc', 'VNC', 'remote_access', 'Virtual Network Computing'),
    ('tcp', 6379, 'redis', 'Redis', 'database', 'Redis'),
    ('tcp', 8080, 'http_alt', 'HTTP Alternate', 'web', 'Common alternate HTTP port'),
    ('tcp', 8443, 'https_alt', 'HTTPS Alternate', 'web', 'Common alternate HTTPS port'),
    ('tcp', 9092, 'kafka', 'Kafka', 'messaging', 'Apache Kafka'),
    ('tcp', 9200, 'elasticsearch', 'Elasticsearch', 'search', 'Elasticsearch HTTP API'),
    ('tcp', 27017, 'mongodb', 'MongoDB', 'database', 'MongoDB database');

DROP VIEW IF EXISTS default.port_services_enabled;

CREATE VIEW default.port_services_enabled AS
SELECT
    transport,
    port,
    service_code,
    service_name,
    category,
    description,
    updated_at
FROM
(
    SELECT
        transport,
        port,
        argMax(service_code, updated_at) AS service_code,
        argMax(service_name, updated_at) AS service_name,
        argMax(category, updated_at) AS category,
        argMax(description, updated_at) AS description,
        argMax(is_enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at
    FROM default.port_services
    GROUP BY
        transport,
        port
)
WHERE enabled_latest = 1;
