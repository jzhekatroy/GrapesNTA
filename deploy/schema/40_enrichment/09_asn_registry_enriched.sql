CREATE VIEW IF NOT EXISTS default.asn_registry_enriched AS
SELECT
    r.asn,
    if(ifNull(n.name, '') = '', concat('AS', toString(r.asn)), n.name) AS name,
    r.cc,
    r.rir,
    r.status,
    r.alloc_date,
    r.source,
    r.snapshot_ts
FROM default.asn_registry AS r
LEFT JOIN
(
    SELECT
        asn,
        argMax(name, updated_at) AS name
    FROM default.asn_names
    GROUP BY asn
) AS n ON r.asn = n.asn;
