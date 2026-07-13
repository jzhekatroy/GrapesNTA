-- Remove legacy IP-based top talkers / pair aggregates.
-- Apply after traffic_asn_1m.sql and traffic_asn_1h.sql are deployed and
-- traffic-talkers-rollups.service is switched to ASN jobs.
--
-- Safe to re-run: DROP IF EXISTS is idempotent.

DROP TABLE IF EXISTS default.traffic_talker_1m_mv;
DROP TABLE IF EXISTS default.traffic_pair_1m_mv;
DROP TABLE IF EXISTS default.traffic_talker_1h_mv;
DROP TABLE IF EXISTS default.traffic_pair_1h_mv;

DROP TABLE IF EXISTS default.traffic_talker_1m;
DROP TABLE IF EXISTS default.traffic_pair_1m;
DROP TABLE IF EXISTS default.traffic_talker_1h;
DROP TABLE IF EXISTS default.traffic_pair_1h;

-- Remove stale rollup watermarks for retired IP jobs.
ALTER TABLE default.traffic_rollup_state
    DELETE WHERE job IN (
        'traffic_talker_1m',
        'traffic_talker_1h',
        'traffic_pair_1m',
        'traffic_pair_1h'
    );
