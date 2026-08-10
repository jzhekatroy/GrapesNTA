-- Example: create a debug client bound by prefixes.
-- Edit CLIENT_ID / PREFIX / FAMILY before running.
--
-- Disable later:
--   INSERT INTO default.net_clients (client_id, display_name, comment, bind_mode, enabled, updated_at)
--   VALUES ('client:demo', 'Demo', '', 'prefixes', 0, now());

INSERT INTO default.net_clients
    (client_id, display_name, comment, bind_mode, enabled, updated_at)
VALUES
    ('client:demo', 'Demo client', 'manual seed for collector debug', 'prefixes', 1, now());

-- IPv4 example — replace with a real customer prefix that has traffic.
INSERT INTO default.net_client_prefixes
    (client_id, prefix, family, enabled, updated_at)
VALUES
    ('client:demo', '203.0.113.0/24', 4, 1, now());

-- Port-bound client example (use instead of prefixes, not together):
-- INSERT INTO default.net_clients
--     (client_id, display_name, comment, bind_mode, enabled, updated_at)
-- VALUES
--     ('client:port-demo', 'Port demo', '', 'ports', 1, now());
-- INSERT INTO default.net_client_ports
--     (client_id, switch_ip, if_index, comment, enabled, updated_at)
-- VALUES
--     ('client:port-demo', '192.0.2.1', 12, 'sFlow ifIndex 12', 1, now());

SELECT * FROM default.net_clients_enabled FORMAT Vertical;
SELECT * FROM default.net_client_prefixes_enabled FORMAT Vertical;
