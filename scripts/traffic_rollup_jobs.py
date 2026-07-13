"""Rollup job definitions mirroring deploy/clickhouse/traffic_*_mv SELECT bodies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence


@dataclass(frozen=True)
class RollupJob:
    job_id: str
    dest_table: str
    bucket_kind: str  # minute | hour | day
    time_column: str
    source_table: str
    priority: int
    depends_on: Sequence[str]
    select_sql: str
    pre_delete_sql: Optional[str] = None
    time_filter_column: Optional[str] = None
    # When set, restrict the scan with an extra guard on the indexed
    # time_received_ns column widened by this many minutes on each side.
    # Used by flow-start-bucketed jobs (time_column=time_flow_start_ns) so the
    # query still groups by flow start but only reads the relevant slice of
    # flows_raw (which is ordered by time_received_ns). The guard must exceed
    # the collector active timeout (-nf-active, default 120s) so no long flow
    # is dropped: received_ns is always >= flow_start_ns and at most one active
    # timeout later.
    received_guard_minutes: Optional[int] = None


def _minute_filter(col: str, start_expr: str, end_expr: str) -> str:
    return (
        f"{col} >= {start_expr} "
        f"AND {col} < {end_expr}"
    )


def _hour_from_minute_filter(start_expr: str, end_expr: str) -> str:
    return (
        f"minute >= {start_expr} "
        f"AND minute < {end_expr}"
    )


JOBS: List[RollupJob] = [
    RollupJob(
        job_id="traffic_dashboard_1m",
        dest_table="default.traffic_dashboard_1m",
        bucket_kind="minute",
        # Bucket by export/receive time so UI volume/bps matches what the
        # collector actually delivered in that minute. Flow-start bucketing
        # pushed long active-timeout flows outside the selected UI window and
        # made charts depend on XDP_NF_ACTIVE.
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=10,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    source_id,
    sum(bytes) AS total_bytes,
    sumIf(bytes, direction = 'in') AS in_bytes,
    sumIf(bytes, direction = 'out') AS out_bytes,
    sumIf(bytes, direction = 'transit') AS transit_bytes,
    sumIf(bytes, direction = 'internal') AS internal_bytes,
    sumIf(bytes, direction = 'unknown') AS unknown_bytes,
    sum(packets) AS total_packets,
    sumIf(packets, direction = 'in') AS in_packets,
    sumIf(packets, direction = 'out') AS out_packets,
    sumIf(packets, direction = 'transit') AS transit_packets,
    sumIf(packets, direction = 'internal') AS internal_packets,
    sumIf(packets, direction = 'unknown') AS unknown_packets,
    sum(coalesce(sampling_rate, 1)) AS total_flows,
    sumIf(coalesce(sampling_rate, 1), direction = 'in') AS in_flows,
    sumIf(coalesce(sampling_rate, 1), direction = 'out') AS out_flows,
    sumIf(coalesce(sampling_rate, 1), direction = 'transit') AS transit_flows,
    sumIf(coalesce(sampling_rate, 1), direction = 'internal') AS internal_flows,
    sumIf(coalesce(sampling_rate, 1), direction = 'unknown') AS unknown_flows
FROM default.flows_raw
WHERE {time_filter}
GROUP BY minute, source_id
""",
        pre_delete_sql="ALTER TABLE default.traffic_dashboard_1m DELETE WHERE minute = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_protocol_1m",
        dest_table="default.traffic_protocol_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=20,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    source_id,
    proto,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(coalesce(sampling_rate, 1)) AS flows_count
FROM default.flows_raw
WHERE {time_filter}
GROUP BY minute, source_id, proto, direction
""",
        pre_delete_sql="ALTER TABLE default.traffic_protocol_1m DELETE WHERE minute = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_direction_1m",
        dest_table="default.traffic_direction_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=30,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    source_id,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(coalesce(sampling_rate, 1)) AS flows_count
FROM default.flows_raw
WHERE {time_filter}
GROUP BY minute, source_id, direction
""",
        pre_delete_sql="ALTER TABLE default.traffic_direction_1m DELETE WHERE minute = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_role_1m",
        dest_table="default.traffic_role_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=40,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    source_id,
    direction,
    multiIf(
        direction = 'out', src_role,
        direction = 'in', dst_role,
        src_role != '', src_role,
        dst_role
    ) AS role,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(coalesce(sampling_rate, 1)) AS flows_count
FROM default.flows_raw
WHERE {time_filter}
  AND direction IN ('in', 'out', 'internal', 'transit', 'unknown')
  AND (src_role != '' OR dst_role != '')
GROUP BY minute, source_id, direction, role
""",
        pre_delete_sql="ALTER TABLE default.traffic_role_1m DELETE WHERE minute = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_entity_1m",
        dest_table="default.traffic_entity_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=50,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    source_id,
    direction,
    multiIf(
        direction = 'out', src_entity,
        direction = 'in', dst_entity,
        src_entity != '', src_entity,
        dst_entity
    ) AS entity_id,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(coalesce(sampling_rate, 1)) AS flows_count
FROM default.flows_raw
WHERE {time_filter}
  AND direction IN ('in', 'out', 'internal')
  AND (src_entity != '' OR dst_entity != '')
GROUP BY minute, source_id, direction, entity_id
""",
        pre_delete_sql="ALTER TABLE default.traffic_entity_1m DELETE WHERE minute = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_vlan_1m",
        dest_table="default.traffic_vlan_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=60,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    source_id,
    direction,
    multiIf(
        direction = 'out', src_attachment_kind,
        direction = 'in', dst_attachment_kind,
        src_attachment_kind != 'unknown', src_attachment_kind,
        dst_attachment_kind
    ) AS attachment_type,
    multiIf(
        direction = 'out', src_vlan,
        direction = 'in', dst_vlan,
        src_vlan != 0, src_vlan,
        dst_vlan
    ) AS vlan_id,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(coalesce(sampling_rate, 1)) AS flows_count
FROM default.flows_raw
WHERE {time_filter}
  AND direction IN ('in', 'out', 'internal', 'transit')
  AND (
      src_attachment_kind != 'unknown'
      OR dst_attachment_kind != 'unknown'
      OR src_vlan != 0
      OR dst_vlan != 0
  )
GROUP BY minute, source_id, direction, attachment_type, vlan_id
""",
        pre_delete_sql="ALTER TABLE default.traffic_vlan_1m DELETE WHERE minute = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_country_1m",
        dest_table="default.traffic_country_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=70,
        depends_on=(),
        select_sql="""
SELECT
    minute,
    source_id,
    country_basis,
    country_side,
    direction,
    if(length(trimBoth(country_raw)) = 0, '??', trimBoth(country_raw)) AS country_code,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_weight) AS flows_count
FROM
(
    SELECT
        toStartOfMinute(f.time_received_ns) AS minute,
        f.source_id,
        f.direction,
        f.bytes AS bytes,
        f.packets AS packets,
        coalesce(f.sampling_rate, 1) AS flow_weight,
        row.1 AS country_basis,
        row.2 AS country_side,
        row.3 AS country_raw
    FROM default.flows_raw AS f
    LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
    LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
    ARRAY JOIN arrayZip(
        ['ip', 'ip', 'asn', 'asn'],
        ['src', 'dst', 'src', 'dst'],
        [
            if(
                f.etype = 2048,
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))))
                ),
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv6(IPv6NumToString(f.src_addr)))
                )
            ),
            if(
                f.etype = 2048,
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))))
                ),
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv6(IPv6NumToString(f.dst_addr)))
                )
            ),
            if(f.src_asn = 0, '', toString(src_as.cc)),
            if(f.dst_asn = 0, '', toString(dst_as.cc))
        ]
    ) AS row
    WHERE {time_filter}
) AS expanded
GROUP BY
    minute,
    source_id,
    country_basis,
    country_side,
    direction,
    country_code
""",
        pre_delete_sql="ALTER TABLE default.traffic_country_1m DELETE WHERE minute = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_service_1m",
        dest_table="default.traffic_service_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=80,
        depends_on=(),
        select_sql="""
WITH
    multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    ) AS transport,
    dst_svc.service_code != '' AS has_dst_service,
    src_svc.service_code != '' AS has_src_service,
    multiIf(has_dst_service, 'dst', has_src_service, 'src', 'unknown') AS service_side,
    multiIf(has_dst_service, toUInt16(f.dst_port), has_src_service, toUInt16(f.src_port), toUInt16(0)) AS service_port,
    multiIf(has_dst_service, dst_svc.service_code, has_src_service, src_svc.service_code, 'unknown') AS service_code,
    multiIf(has_dst_service, dst_svc.service_name, has_src_service, src_svc.service_name, 'Unknown') AS service_name,
    multiIf(has_dst_service, dst_svc.category, has_src_service, src_svc.category, 'unknown') AS category
SELECT
    toStartOfMinute(f.time_received_ns) AS minute,
    f.source_id,
    f.direction,
    f.proto,
    transport,
    service_side,
    service_port,
    service_code,
    service_name,
    category,
    sum(f.bytes) AS bytes,
    sum(f.packets) AS packets,
    sum(coalesce(f.sampling_rate, 1)) AS flows_count
FROM default.flows_raw AS f
LEFT JOIN default.port_services_expanded_enabled AS dst_svc
    ON dst_svc.transport = transport
   AND dst_svc.port = toUInt16(f.dst_port)
LEFT JOIN default.port_services_expanded_enabled AS src_svc
    ON src_svc.transport = transport
   AND src_svc.port = toUInt16(f.src_port)
WHERE {time_filter}
GROUP BY
    minute,
    f.source_id,
    f.direction,
    f.proto,
    transport,
    service_side,
    service_port,
    service_code,
    service_name,
    category
""",
        pre_delete_sql="ALTER TABLE default.traffic_service_1m DELETE WHERE minute = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_unknown_port_1m",
        dest_table="default.traffic_unknown_port_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=90,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(f.time_received_ns) AS minute,
    f.source_id,
    f.direction,
    f.proto,
    multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    ) AS transport,
    multiIf(f.dst_port > 0, 'dst', f.src_port > 0, 'src', 'unknown') AS port_side,
    multiIf(f.dst_port > 0, toUInt16(f.dst_port), f.src_port > 0, toUInt16(f.src_port), toUInt16(0)) AS port,
    sum(f.bytes) AS bytes,
    sum(f.packets) AS packets,
    sum(coalesce(f.sampling_rate, 1)) AS flows_count
FROM default.flows_raw AS f
LEFT JOIN default.port_services_expanded_enabled AS dst_svc
    ON dst_svc.transport = multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    )
   AND dst_svc.port = toUInt16(f.dst_port)
LEFT JOIN default.port_services_expanded_enabled AS src_svc
    ON src_svc.transport = multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    )
   AND src_svc.port = toUInt16(f.src_port)
WHERE {time_filter}
  AND dst_svc.service_code = ''
  AND src_svc.service_code = ''
GROUP BY
    minute,
    f.source_id,
    f.direction,
    f.proto,
    transport,
    port_side,
    port
""",
        pre_delete_sql="ALTER TABLE default.traffic_unknown_port_1m DELETE WHERE minute = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_asn_1m",
        dest_table="default.traffic_asn_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=100,
        depends_on=(),
        select_sql="""
SELECT
    minute,
    source_id,
    endpoint_side,
    direction,
    endpoint_asn,
    any(endpoint_as_name) AS endpoint_as_name,
    any(endpoint_as_country) AS endpoint_as_country,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_weight) AS flows_count
FROM
(
    SELECT
        toStartOfMinute(f.time_received_ns) AS minute,
        f.source_id,
        f.direction,
        f.bytes AS bytes,
        f.packets AS packets,
        coalesce(f.sampling_rate, 1) AS flow_weight,
        tupleElement(row, 1) AS endpoint_side,
        tupleElement(row, 2) AS endpoint_asn,
        tupleElement(row, 3) AS endpoint_as_name,
        if(length(trimBoth(tupleElement(row, 4))) = 0, '??', trimBoth(tupleElement(row, 4))) AS endpoint_as_country
    FROM default.flows_raw AS f
    LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
    LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
    ARRAY JOIN arrayZip(
        ['src', 'dst'],
        [f.src_asn, f.dst_asn],
        [
            multiIf(f.src_asn = 0, '', src_as.asn != 0 AND src_as.name != '', src_as.name, concat('AS', toString(f.src_asn))),
            multiIf(f.dst_asn = 0, '', dst_as.asn != 0 AND dst_as.name != '', dst_as.name, concat('AS', toString(f.dst_asn)))
        ],
        [
            if(f.src_asn = 0 OR src_as.asn = 0, '', toString(src_as.cc)),
            if(f.dst_asn = 0 OR dst_as.asn = 0, '', toString(dst_as.cc))
        ]
    ) AS row
    WHERE {time_filter}
) AS expanded
GROUP BY
    minute,
    source_id,
    endpoint_side,
    direction,
    endpoint_asn
""",
        pre_delete_sql="ALTER TABLE default.traffic_asn_1m DELETE WHERE minute = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_asn_pair_1m",
        dest_table="default.traffic_asn_pair_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=110,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(f.time_received_ns) AS minute,
    f.source_id,
    f.direction,
    f.src_asn,
    f.dst_asn,
    any(multiIf(f.src_asn = 0, '', src_as.asn != 0 AND src_as.name != '', src_as.name, concat('AS', toString(f.src_asn)))) AS src_as_name,
    any(multiIf(f.dst_asn = 0, '', dst_as.asn != 0 AND dst_as.name != '', dst_as.name, concat('AS', toString(f.dst_asn)))) AS dst_as_name,
    any(if(f.src_asn = 0 OR src_as.asn = 0, '??', trimBoth(toString(src_as.cc)))) AS src_as_country,
    any(if(f.dst_asn = 0 OR dst_as.asn = 0, '??', trimBoth(toString(dst_as.cc)))) AS dst_as_country,
    sum(f.bytes) AS bytes,
    sum(f.packets) AS packets,
    sum(coalesce(f.sampling_rate, 1)) AS flows_count
FROM default.flows_raw AS f
LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
WHERE {time_filter}
GROUP BY
    minute,
    f.source_id,
    f.direction,
    f.src_asn,
    f.dst_asn
""",
        pre_delete_sql="ALTER TABLE default.traffic_asn_pair_1m DELETE WHERE minute = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_dashboard_1h",
        dest_table="default.traffic_dashboard_1h",
        bucket_kind="hour",
        time_column="minute",
        source_table="default.traffic_dashboard_1m",
        priority=200,
        depends_on=("traffic_dashboard_1m",),
        # Roll up from the already-computed minute table instead of re-scanning
        # flows_raw. dashboard_1m is the only job that reads flows_raw on the
        # flow-start axis; the hourly view is just a sum of its 60 minute rows,
        # which keeps the flow-start semantics and is effectively free.
        select_sql="""
SELECT
    toStartOfHour(minute) AS hour,
    source_id,
    sum(total_bytes) AS total_bytes,
    sum(in_bytes) AS in_bytes,
    sum(out_bytes) AS out_bytes,
    sum(transit_bytes) AS transit_bytes,
    sum(internal_bytes) AS internal_bytes,
    sum(unknown_bytes) AS unknown_bytes,
    sum(total_packets) AS total_packets,
    sum(in_packets) AS in_packets,
    sum(out_packets) AS out_packets,
    sum(transit_packets) AS transit_packets,
    sum(internal_packets) AS internal_packets,
    sum(unknown_packets) AS unknown_packets,
    sum(total_flows) AS total_flows,
    sum(in_flows) AS in_flows,
    sum(out_flows) AS out_flows,
    sum(transit_flows) AS transit_flows,
    sum(internal_flows) AS internal_flows,
    sum(unknown_flows) AS unknown_flows
FROM default.traffic_dashboard_1m
WHERE {time_filter}
GROUP BY hour, source_id
""",
        pre_delete_sql="ALTER TABLE default.traffic_dashboard_1h DELETE WHERE hour = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_asn_1h",
        dest_table="default.traffic_asn_1h",
        bucket_kind="hour",
        time_column="minute",
        source_table="default.traffic_asn_1m",
        priority=210,
        depends_on=("traffic_asn_1m",),
        # GROUP BY only ORDER BY key columns; as_name is descriptive (any()).
        select_sql="""
SELECT
    toStartOfHour(minute) AS hour,
    source_id,
    endpoint_side,
    direction,
    endpoint_asn,
    any(endpoint_as_name) AS endpoint_as_name,
    any(endpoint_as_country) AS endpoint_as_country,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_asn_1m
WHERE {time_filter}
GROUP BY
    hour,
    source_id,
    endpoint_side,
    direction,
    endpoint_asn
""",
        pre_delete_sql="ALTER TABLE default.traffic_asn_1h DELETE WHERE hour = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_asn_pair_1h",
        dest_table="default.traffic_asn_pair_1h",
        bucket_kind="hour",
        time_column="minute",
        source_table="default.traffic_asn_pair_1m",
        priority=220,
        depends_on=("traffic_asn_pair_1m",),
        # GROUP BY only ORDER BY key columns; names/countries via any().
        select_sql="""
SELECT
    toStartOfHour(minute) AS hour,
    source_id,
    direction,
    src_asn,
    dst_asn,
    any(src_as_name) AS src_as_name,
    any(dst_as_name) AS dst_as_name,
    any(src_as_country) AS src_as_country,
    any(dst_as_country) AS dst_as_country,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_asn_pair_1m
WHERE {time_filter}
GROUP BY
    hour,
    source_id,
    direction,
    src_asn,
    dst_asn
""",
        pre_delete_sql="ALTER TABLE default.traffic_asn_pair_1h DELETE WHERE hour = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_dashboard_1d",
        dest_table="default.traffic_dashboard_1d",
        bucket_kind="day",
        time_column="minute",
        source_table="default.traffic_dashboard_1m",
        priority=300,
        depends_on=("traffic_dashboard_1m",),
        # Roll up from the minute table (1440 rows/day) instead of re-scanning a
        # full day of flows_raw (~1.7B rows). depends_on stays the minute job so
        # the day is only built once all its minutes are done. This also aligns
        # the daily axis with 1m/1h (flow-start); for daily totals the only
        # difference vs the old received axis is flows that cross midnight.
        select_sql="""
SELECT
    toStartOfDay(minute) AS day,
    source_id,
    sum(total_bytes) AS total_bytes,
    sum(in_bytes) AS in_bytes,
    sum(out_bytes) AS out_bytes,
    sum(transit_bytes) AS transit_bytes,
    sum(internal_bytes) AS internal_bytes,
    sum(unknown_bytes) AS unknown_bytes,
    sum(total_packets) AS total_packets,
    sum(in_packets) AS in_packets,
    sum(out_packets) AS out_packets,
    sum(transit_packets) AS transit_packets,
    sum(internal_packets) AS internal_packets,
    sum(unknown_packets) AS unknown_packets,
    sum(total_flows) AS total_flows,
    sum(in_flows) AS in_flows,
    sum(out_flows) AS out_flows,
    sum(transit_flows) AS transit_flows,
    sum(internal_flows) AS internal_flows,
    sum(unknown_flows) AS unknown_flows
FROM default.traffic_dashboard_1m
WHERE {time_filter}
GROUP BY day, source_id
""",
        pre_delete_sql="ALTER TABLE default.traffic_dashboard_1d DELETE WHERE day = {bucket_dt}",
    ),
]


def jobs_by_id() -> dict:
    return {job.job_id: job for job in JOBS}


def sorted_jobs(selected: Optional[Sequence[str]] = None) -> List[RollupJob]:
    wanted = set(selected) if selected else None
    out = [job for job in JOBS if wanted is None or job.job_id in wanted]
    return sorted(out, key=lambda j: (j.priority, j.job_id))
