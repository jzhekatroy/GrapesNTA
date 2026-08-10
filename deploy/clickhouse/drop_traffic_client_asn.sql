-- Drop the client ASN vitrine.
--
-- Remote ASN tops needed their own pass over flows_raw plus a join with
-- asn_registry_enriched, while countries carry the same product value for the
-- cabinet at a fraction of the cost. ASN detail is still reachable through
-- raw-flow analysis over the flows_raw retention window.
--
-- Run after the rollup runner no longer lists traffic_client_asn_1h/_1d in its
-- --jobs argument, otherwise the next tick recreates rows in a missing table
-- and fails the job.
--
-- Safe to re-run.

DROP TABLE IF EXISTS default.traffic_client_asn_1h SYNC;
DROP TABLE IF EXISTS default.traffic_client_asn_1d SYNC;
