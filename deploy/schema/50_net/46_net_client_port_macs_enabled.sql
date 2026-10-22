CREATE OR REPLACE VIEW default.net_client_port_macs_enabled
(
    `client_id` LowCardinality(String),
    `switch_ip` String,
    `if_index` UInt32,
    `mac` String,
    `updated_at` DateTime
)
AS SELECT
    client_id,
    switch_ip,
    if_index,
    mac,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        switch_ip,
        if_index,
        mac,
        argMax(client_id, updated_at) AS client_id,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_client_port_macs
    GROUP BY switch_ip, if_index, mac
)
WHERE enabled_latest = 1
  AND client_id IN (
    SELECT client_id FROM default.net_clients_enabled WHERE bind_mode = 'ports'
  );
