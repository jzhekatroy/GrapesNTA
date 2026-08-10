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
        time_column="time_flow_start_ns",
        source_table="default.flows_raw",
        priority=10,
        depends_on=(),
        select_sql="""
SELECT
    toStartOfMinute(time_flow_start_ns) AS minute,
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
        received_guard_minutes=15,
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
        direction = 'out' AND src_attachment_kind != 'unknown', src_attachment_kind,
        direction = 'in' AND dst_attachment_kind != 'unknown', dst_attachment_kind,
        src_attachment_kind != 'unknown', src_attachment_kind,
        dst_attachment_kind
    ) AS attachment_type,
    -- Prefer the side implied by direction, but fall back to the other VLAN
    -- when sFlow/XDP only populated one of src_vlan/dst_vlan.
    multiIf(
        direction = 'out' AND src_vlan != 0, src_vlan,
        direction = 'in' AND dst_vlan != 0, dst_vlan,
        src_vlan != 0, src_vlan,
        dst_vlan
    ) AS vlan_id,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(coalesce(sampling_rate, 1)) AS flows_count
FROM default.flows_raw
WHERE {time_filter}
  AND direction IN ('in', 'out', 'internal', 'transit', 'unknown')
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
    # Top Talkers / Pairs: ASN-only (UI reads traffic_asn_*). IP-keyed
    # traffic_talker_* / traffic_pair_* are deprecated and no longer rolled up.
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
        job_id="traffic_client_1m",
        dest_table="default.traffic_client_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=55,
        depends_on=(),
        # Direction is from the client's point of view, not the operator's:
        # src_client -> out, dst_client -> in. A flow with the same client on
        # both sides is skipped (self-traffic). A flow between two different
        # clients produces two rows via ARRAY JOIN.
        #
        # Client rows are a small fraction of flows_raw, so the innermost
        # subquery narrows the scan with PREWHERE on the two client columns
        # before anything else touches the row: only the surviving rows pay for
        # the remaining columns and the ARRAY JOIN expansion.
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    client_id,
    source_id,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM
(
    SELECT
        time_received_ns,
        source_id,
        bytes,
        packets,
        coalesce(sampling_rate, 1) AS flows_count,
        side.1 AS client_id,
        side.2 AS direction
    FROM
    (
        SELECT
            f.time_received_ns AS time_received_ns,
            f.source_id AS source_id,
            f.bytes AS bytes,
            f.packets AS packets,
            f.sampling_rate AS sampling_rate,
            f.src_client AS src_client,
            f.dst_client AS dst_client
        FROM default.flows_raw AS f
        PREWHERE (f.src_client != '') OR (f.dst_client != '')
        WHERE {time_filter}
    ) AS c
    ARRAY JOIN arrayFilter(
        x -> (tupleElement(x, 1) != ''),
        [
            (
                if(src_client != '' AND src_client != dst_client, src_client, ''),
                'out'
            ),
            (
                if(dst_client != '' AND src_client != dst_client, dst_client, ''),
                'in'
            )
        ]
    ) AS side
)
GROUP BY minute, client_id, source_id, direction
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_1m DELETE WHERE minute = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_client_anomaly_1m",
        dest_table="default.traffic_client_anomaly_1m",
        bucket_kind="minute",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=56,
        depends_on=(),
        # Detection profile per client and minute. Shares the client expansion of
        # traffic_client_1m but adds what detection needs and the vitrines lack:
        # transport, connection attempts and the number of distinct peers.
        #
        # This is a second pass over flows_raw rather than extra columns on
        # traffic_client_1m, which would have avoided the pass: keeping the base
        # aggregate untouched avoids rebuilding the table the cabinet already
        # reads through traffic_client_1h, and the pass is cheap because PREWHERE
        # leaves only the client rows.
        #
        # syn_flows counts TCP flows with SYN set and ACK clear, i.e. connection
        # attempts. remote_ips_state is an aggregate state because distinct
        # counts cannot be summed across minutes; read it with uniqCombinedMerge.
        select_sql="""
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    client_id,
    source_id,
    direction,
    transport,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flow_weight) AS flows_count,
    sumIf(flow_weight, is_syn) AS syn_flows,
    uniqCombinedState(remote_addr) AS remote_ips_state
FROM
(
    SELECT
        time_received_ns,
        source_id,
        bytes,
        packets,
        coalesce(sampling_rate, 1) AS flow_weight,
        multiIf(
            proto = 6, 'tcp',
            proto = 17, 'udp',
            proto = 1, 'icmp',
            proto = 58, 'icmpv6',
            proto = 132, 'sctp',
            'other'
        ) AS transport,
        (proto = 6) AND (bitAnd(tcp_flags, 2) = 2) AND (bitAnd(tcp_flags, 16) = 0) AS is_syn,
        side.1 AS client_id,
        side.2 AS direction,
        if(side.2 = 'out', dst_addr, src_addr) AS remote_addr
    FROM
    (
        SELECT
            f.time_received_ns AS time_received_ns,
            f.source_id AS source_id,
            f.bytes AS bytes,
            f.packets AS packets,
            f.sampling_rate AS sampling_rate,
            f.proto AS proto,
            f.tcp_flags AS tcp_flags,
            f.src_addr AS src_addr,
            f.dst_addr AS dst_addr,
            f.src_client AS src_client,
            f.dst_client AS dst_client
        FROM default.flows_raw AS f
        PREWHERE (f.src_client != '') OR (f.dst_client != '')
        WHERE {time_filter}
    ) AS c
    ARRAY JOIN arrayFilter(
        x -> (tupleElement(x, 1) != ''),
        [
            (
                if(src_client != '' AND src_client != dst_client, src_client, ''),
                'out'
            ),
            (
                if(dst_client != '' AND src_client != dst_client, dst_client, ''),
                'in'
            )
        ]
    ) AS side
)
GROUP BY minute, client_id, source_id, direction, transport
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_anomaly_1m DELETE WHERE minute = {bucket_dt}",
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
        job_id="traffic_client_1h",
        dest_table="default.traffic_client_1h",
        bucket_kind="hour",
        time_column="minute",
        source_table="default.traffic_client_1m",
        priority=230,
        depends_on=("traffic_client_1m",),
        select_sql="""
SELECT
    toStartOfHour(minute) AS hour,
    client_id,
    source_id,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_client_1m
WHERE {time_filter}
GROUP BY hour, client_id, source_id, direction
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_1h DELETE WHERE hour = {bucket_dt}",
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
    RollupJob(
        job_id="traffic_client_1d",
        dest_table="default.traffic_client_1d",
        bucket_kind="day",
        time_column="minute",
        source_table="default.traffic_client_1m",
        priority=310,
        depends_on=("traffic_client_1m",),
        select_sql="""
SELECT
    toStartOfDay(minute) AS day,
    client_id,
    source_id,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_client_1m
WHERE {time_filter}
GROUP BY day, client_id, source_id, direction
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_1d DELETE WHERE day = {bucket_dt}",
    ),
    # --- Cabinet showcase vitrines (hour from flows_raw, day from hour) ---
    RollupJob(
        job_id="traffic_client_country_1h",
        dest_table="default.traffic_client_country_1h",
        bucket_kind="hour",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=240,
        depends_on=(),
        select_sql="""
SELECT
    hour,
    client_id,
    source_id,
    direction,
    if(length(trimBoth(remote_cc)) = 0, '??', trimBoth(remote_cc)) AS country_code,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM
(
    SELECT
        toStartOfHour(time_received_ns) AS hour,
        side.1 AS client_id,
        source_id,
        side.2 AS direction,
        multiIf(
            side.2 = 'out' AND etype = 2048,
            dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))),
            side.2 = 'out',
            dictGetString('default.geo_country_dict', 'cc', tuple(toIPv6(IPv6NumToString(dst_addr)))),
            etype = 2048,
            dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))),
            dictGetString('default.geo_country_dict', 'cc', tuple(toIPv6(IPv6NumToString(src_addr))))
        ) AS remote_cc,
        bytes,
        packets,
        coalesce(sampling_rate, 1) AS flows_count
    FROM
    (
        SELECT
            f.time_received_ns AS time_received_ns,
            f.source_id AS source_id,
            f.etype AS etype,
            f.src_addr AS src_addr,
            f.dst_addr AS dst_addr,
            f.bytes AS bytes,
            f.packets AS packets,
            f.sampling_rate AS sampling_rate,
            f.src_client AS src_client,
            f.dst_client AS dst_client
        FROM default.flows_raw AS f
        PREWHERE (f.src_client != '') OR (f.dst_client != '')
        WHERE {time_filter}
    ) AS c
    ARRAY JOIN arrayFilter(
        x -> (tupleElement(x, 1) != ''),
        [
            (if(src_client != '' AND src_client != dst_client, src_client, ''), 'out'),
            (if(dst_client != '' AND src_client != dst_client, dst_client, ''), 'in')
        ]
    ) AS side
)
GROUP BY hour, client_id, source_id, direction, country_code
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_country_1h DELETE WHERE hour = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_client_service_1h",
        dest_table="default.traffic_client_service_1h",
        bucket_kind="hour",
        time_column="time_received_ns",
        source_table="default.flows_raw",
        priority=242,
        depends_on=(),
        # Narrow flows_raw down to client rows in PREWHERE first, expand the
        # sides, and only then probe the port/service table, so the two joins run
        # over the client subset instead of the whole hour of raw flows.
        #
        # A port the dictionary does not know keeps service_code='port' and the
        # port itself instead of vanishing into 'other': on a real client 78% of
        # outbound bytes sat on one stable port the dictionary only covers for a
        # different transport, which would have made the cabinet answer "which
        # services do you use" with "Other".
        #
        # Missing ports become 65535 before least(), so ICMP (no ports at all)
        # lands above the ephemeral cut-off and collapses to 'other' without a
        # special case.
        #
        # "Lower port wins" is only a guess at which side is the server, and it
        # guesses wrong whenever a peer dials in from a port below the client's
        # service port: a client serving 12545/tcp got its traffic smeared over
        # ~1700 peer ports in one hour, one row each. So the per-port detail is
        # ranked by bytes inside the bucket and everything past the top 20 is
        # folded back into 'other'. A real service port carries the volume and
        # survives; a peer's ephemeral port carries a sliver and merges away.
        # Folding rather than dropping the tail keeps the totals equal to the
        # base client aggregate, so shares in the cabinet still add up to 100%.
        #
        # port_owner is read from the client's side. The kept port comes from the
        # source when lo_src <= lo_dst, and the client is the source exactly when
        # direction is 'out', so the two agreeing means the port is the client's
        # own.
        select_sql="""
SELECT
    hour,
    client_id,
    source_id,
    direction,
    transport,
    if(fold_tail, 'other', service_code) AS service_code,
    if(fold_tail, 'Other', service_name) AS service_name,
    if(fold_tail, 'other', category) AS category,
    if(fold_tail, toUInt16(0), service_port) AS service_port,
    if(fold_tail, '', port_owner) AS port_owner,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM
(
    SELECT
        *,
        (service_code = 'port') AND (
            row_number() OVER (
                PARTITION BY hour, client_id, source_id, direction, transport
                ORDER BY bytes DESC
            ) > 20
        ) AS fold_tail
    FROM
    (
WITH
    dst_svc.service_code != '' AS has_dst_service,
    src_svc.service_code != '' AS has_src_service,
    if(e.src_port = 0, 65535, e.src_port) AS lo_src,
    if(e.dst_port = 0, 65535, e.dst_port) AS lo_dst,
    least(lo_src, lo_dst) AS svc_port_raw,
    (NOT has_dst_service) AND (NOT has_src_service) AND (svc_port_raw < 32768) AS keep_port
SELECT
    e.hour AS hour,
    e.client_id AS client_id,
    e.source_id AS source_id,
    e.direction AS direction,
    e.transport AS transport,
    multiIf(
        has_dst_service, dst_svc.service_code,
        has_src_service, src_svc.service_code,
        keep_port, 'port',
        'other'
    ) AS service_code,
    multiIf(
        has_dst_service, dst_svc.service_name,
        has_src_service, src_svc.service_name,
        keep_port, concat(e.transport, '/', toString(svc_port_raw)),
        'Other'
    ) AS service_name,
    multiIf(
        has_dst_service, dst_svc.category,
        has_src_service, src_svc.category,
        keep_port, 'unclassified',
        'other'
    ) AS category,
    if(keep_port, toUInt16(svc_port_raw), toUInt16(0)) AS service_port,
    multiIf(
        NOT keep_port, '',
        (e.direction = 'out') = (lo_src <= lo_dst), 'local',
        'remote'
    ) AS port_owner,
    sum(e.bytes) AS bytes,
    sum(e.packets) AS packets,
    sum(e.flows_count) AS flows_count
FROM
(
    SELECT
        toStartOfHour(time_received_ns) AS hour,
        side.1 AS client_id,
        source_id,
        side.2 AS direction,
        multiIf(
            proto = 6, 'tcp',
            proto = 17, 'udp',
            proto = 1, 'icmp',
            proto = 58, 'icmpv6',
            proto = 132, 'sctp',
            'other'
        ) AS transport,
        toUInt16(src_port) AS src_port,
        toUInt16(dst_port) AS dst_port,
        bytes,
        packets,
        coalesce(sampling_rate, 1) AS flows_count
    FROM
    (
        SELECT
            f.time_received_ns AS time_received_ns,
            f.source_id AS source_id,
            f.proto AS proto,
            f.src_port AS src_port,
            f.dst_port AS dst_port,
            f.bytes AS bytes,
            f.packets AS packets,
            f.sampling_rate AS sampling_rate,
            f.src_client AS src_client,
            f.dst_client AS dst_client
        FROM default.flows_raw AS f
        PREWHERE (f.src_client != '') OR (f.dst_client != '')
        WHERE {time_filter}
    ) AS c
    ARRAY JOIN arrayFilter(
        x -> (tupleElement(x, 1) != ''),
        [
            (if(src_client != '' AND src_client != dst_client, src_client, ''), 'out'),
            (if(dst_client != '' AND src_client != dst_client, dst_client, ''), 'in')
        ]
    ) AS side
) AS e
LEFT JOIN default.port_services_expanded_enabled AS dst_svc
    ON dst_svc.transport = e.transport
   AND dst_svc.port = e.dst_port
LEFT JOIN default.port_services_expanded_enabled AS src_svc
    ON src_svc.transport = e.transport
   AND src_svc.port = e.src_port
GROUP BY
    hour,
    client_id,
    source_id,
    direction,
    transport,
    service_code,
    service_name,
    category,
    service_port,
    port_owner
    ) AS detail
) AS ranked
GROUP BY
    hour,
    client_id,
    source_id,
    direction,
    transport,
    service_code,
    service_name,
    category,
    service_port,
    port_owner
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_service_1h DELETE WHERE hour = {bucket_dt}",
        time_filter_column="f.time_received_ns",
    ),
    RollupJob(
        job_id="traffic_client_country_1d",
        dest_table="default.traffic_client_country_1d",
        bucket_kind="day",
        time_column="hour",
        source_table="default.traffic_client_country_1h",
        priority=320,
        depends_on=("traffic_client_country_1h",),
        select_sql="""
SELECT
    toStartOfDay(hour) AS day,
    client_id,
    source_id,
    direction,
    country_code,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_client_country_1h
WHERE {time_filter}
GROUP BY day, client_id, source_id, direction, country_code
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_country_1d DELETE WHERE day = {bucket_dt}",
    ),
    RollupJob(
        job_id="traffic_client_service_1d",
        dest_table="default.traffic_client_service_1d",
        bucket_kind="day",
        time_column="hour",
        source_table="default.traffic_client_service_1h",
        priority=322,
        depends_on=("traffic_client_service_1h",),
        select_sql="""
SELECT
    toStartOfDay(hour) AS day,
    client_id,
    source_id,
    direction,
    transport,
    service_code,
    service_name,
    category,
    service_port,
    port_owner,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_client_service_1h
WHERE {time_filter}
GROUP BY day, client_id, source_id, direction, transport, service_code, service_name, category, service_port, port_owner
""",
        pre_delete_sql="ALTER TABLE default.traffic_client_service_1d DELETE WHERE day = {bucket_dt}",
    ),
]


def jobs_by_id() -> dict:
    return {job.job_id: job for job in JOBS}


def sorted_jobs(selected: Optional[Sequence[str]] = None) -> List[RollupJob]:
    wanted = set(selected) if selected else None
    out = [job for job in JOBS if wanted is None or job.job_id in wanted]
    return sorted(out, key=lambda j: (j.priority, j.job_id))
