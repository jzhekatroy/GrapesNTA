const {
  col,
  config,
  tableRef,
  flowsRawTableRef,
  flowCol,
  dashboardTableRef,
  dashboardHourTableRef,
  dashboardDayTableRef,
  protocolTableRef,
  serviceTableRef,
  unknownPortTableRef,
  countryTableRef,
  talkerTableRef,
  talkerHourTableRef,
  pairTableRef,
  pairHourTableRef,
  vlanTableRef,
  sourcesTableRef,
  collectorsViewRef,
  locationsViewRef,
  portServicesExpandedViewRef,
  asnNamesTableRef,
  ipAsnPrefixesTableRef,
  asnRegistryEnrichedTableRef,
  escapeSqlString,
  parseDataDatetimeSql,
} = require('./clickhouse');
const { protocolChartColor } = require('./protocol-colors');
const { getVlanNameMap, vlanLabel } = require('./net-l2-vlans');

const DIRECTION_IDS = {
  total: 'total',
  in: 'incoming',
  out: 'outgoing',
  transit: 'transit',
  internal: 'internal',
  unknown: 'unclassified',
};

const DIRECTIONS_SQL = "['total', 'in', 'out', 'transit', 'internal', 'unknown']";

function parseCollectorScope(value) {
  const v = String(value ?? '').trim();
  if (!v) return null;
  if (v.startsWith('loc:')) {
    const locationId = v.slice(4).trim();
    return locationId ? { type: 'location', locationId } : null;
  }
  return { type: 'collector', collectorId: v };
}

function parseCollectorScopes(value) {
  if (!value) return [];
  const parts = Array.isArray(value)
    ? value
    : String(value).split(',').map((part) => part.trim()).filter(Boolean);
  const scopes = [];
  const seen = new Set();
  for (const part of parts) {
    const scope = parseCollectorScope(part);
    if (!scope) continue;
    const key = scope.type === 'location'
      ? `loc:${scope.locationId}`
      : `col:${scope.collectorId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    scopes.push(scope);
  }
  return scopes;
}

function isParsedCollectorScope(value) {
  return value && typeof value === 'object'
    && (value.type === 'collector' || value.type === 'location');
}

function normalizeCollectorScopes(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    if (value.length && isParsedCollectorScope(value[0])) return value;
    return parseCollectorScopes(value);
  }
  if (isParsedCollectorScope(value)) return [value];
  return parseCollectorScopes(value);
}

function scopeCol(alias, name) {
  return alias ? `${alias}.${name}` : name;
}

function sourcesScopeSql(scopes, alias = 's') {
  const base = `${scopeCol(alias, 'include_in_total')} = 1`;
  const list = normalizeCollectorScopes(scopes);
  if (!list.length) return base;

  const collectorsView = collectorsViewRef();
  const orParts = [];
  const collectorIds = [];
  const locationIds = [];
  let hasNoneLocation = false;

  for (const scope of list) {
    if (scope.type === 'collector') collectorIds.push(scope.collectorId);
    else if (scope.locationId === '__none__') hasNoneLocation = true;
    else locationIds.push(scope.locationId);
  }

  if (collectorIds.length) {
    orParts.push(`${scopeCol(alias, 'collector_id')} IN {collector_ids:Array(String)}`);
  }
  if (locationIds.length) {
    orParts.push(`${scopeCol(alias, 'collector_id')} IN (
      SELECT collector_id FROM ${collectorsView} WHERE location_id IN {location_ids:Array(String)}
    )`);
  }
  if (hasNoneLocation) {
    orParts.push(`${scopeCol(alias, 'collector_id')} IN (
      SELECT collector_id FROM ${collectorsView}
      WHERE location_id = '' OR location_id IS NULL
    )`);
  }

  return `${base} AND (${orParts.join(' OR ')})`;
}

function mergeCollectorParams(params, scopes) {
  const list = normalizeCollectorScopes(scopes);
  if (!list.length) return params;

  const collectorIds = [];
  const locationIds = [];
  for (const scope of list) {
    if (scope.type === 'collector') collectorIds.push(scope.collectorId);
    else if (scope.locationId !== '__none__') locationIds.push(scope.locationId);
  }

  const next = { ...params };
  if (collectorIds.length) next.collector_ids = [...new Set(collectorIds)];
  if (locationIds.length) next.location_ids = [...new Set(locationIds)];
  return next;
}

function appendFlowsRawCollectorFilter(collectorId, params, whereClauses, flowAlias = 'f') {
  const collectorScope = parseCollectorScopes(collectorId);
  const sourceIdCol = flowCol('sourceId');
  if (!collectorScope.length || !sourceIdCol) return params;

  const sourceScope = sourcesScopeSql(collectorScope, 's');
  whereClauses.push(`${flowAlias}.${sourceIdCol} IN (
    SELECT source_id FROM ${sourcesTableRef()} AS s
    WHERE ${sourceScope}
  )`);
  return mergeCollectorParams(params, collectorScope);
}
const DIRECTION_BYTES_SQL = '[total_bytes, in_bytes, out_bytes, transit_bytes, internal_bytes, unknown_bytes]';
const DIRECTION_PACKETS_SQL = '[total_packets, in_packets, out_packets, transit_packets, internal_packets, unknown_packets]';

const SHORT_RANGE_INTERVALS = {
  '30m': 'INTERVAL 30 MINUTE',
  '1h': 'INTERVAL 1 HOUR',
  '3h': 'INTERVAL 3 HOUR',
  '6h': 'INTERVAL 6 HOUR',
  '12h': 'INTERVAL 12 HOUR',
  '24h': 'INTERVAL 24 HOUR',
};

const MEDIUM_RANGE_INTERVALS = {
  '2d': 'INTERVAL 2 DAY',
  '7d': 'INTERVAL 7 DAY',
  '14d': 'INTERVAL 14 DAY',
};

const EXTENDED_RANGE_INTERVALS = {
  '30d': 'INTERVAL 30 DAY',
  '60d': 'INTERVAL 60 DAY',
  '90d': 'INTERVAL 90 DAY',
};

const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const THIRTY_DAYS_MS = 30 * ONE_DAY_MS;
const FIVE_MINUTE_BUCKET_SECONDS = 300;

const FIVE_MINUTE_ALIGN_CTE = `
    toStartOfInterval(raw_ts_from + INTERVAL 5 MINUTE - INTERVAL 1 SECOND, INTERVAL 5 MINUTE) AS ts_from,
    toStartOfInterval(raw_ts_to, INTERVAL 5 MINUTE) AS ts_to,`;

const DIRECTION_DAY_COLS = [
  { dir: 'total', bytes: 'total_bytes', packets: 'total_packets' },
  { dir: 'in', bytes: 'in_bytes', packets: 'in_packets' },
  { dir: 'out', bytes: 'out_bytes', packets: 'out_packets' },
  { dir: 'transit', bytes: 'transit_bytes', packets: 'transit_packets' },
  { dir: 'internal', bytes: 'internal_bytes', packets: 'internal_packets' },
  { dir: 'unknown', bytes: 'unknown_bytes', packets: 'unknown_packets' },
];

const PROTO_LABELS = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
  58: 'ICMPv6',
};

function protoLabel(proto) {
  const n = Number(proto);
  return PROTO_LABELS[n] || (Number.isFinite(n) ? `Proto ${n}` : String(proto));
}

/** L4 transport key for port_services join (lowercase). */
function flowTransportSql(protoExpr) {
  return `multiIf(
    ${protoExpr} = 6, 'tcp',
    ${protoExpr} = 17, 'udp',
    ${protoExpr} = 132, 'sctp',
    ${protoExpr} = 1, 'icmp',
    ${protoExpr} = 58, 'icmpv6',
    ''
  )`;
}

const CHART_DIRECTIONS = {
  total: 'total',
  incoming: 'in',
  outgoing: 'out',
  transit: 'transit',
  internal: 'internal',
  unclassified: 'unknown',
};

const CHART_SQL_DIRECTIONS = ['total', 'in', 'out', 'transit', 'internal', 'unknown'];
const CHART_SQL_DIRECTION_SET = new Set(CHART_SQL_DIRECTIONS);

const CHART_LINE_META = [
  { sql: 'in', id: 'incoming', label: 'Входящий', color: '#51D16D' },
  { sql: 'out', id: 'outgoing', label: 'Исходящий', color: '#6972F0' },
  { sql: 'transit', id: 'transit', label: 'Транзит', color: '#F0B400' },
  { sql: 'internal', id: 'internal', label: 'Внутренний', color: '#A4ADFF' },
  { sql: 'unknown', id: 'unclassified', label: 'Неразмеченный', color: '#7F7F9D' },
  { sql: 'total', id: 'total', label: 'Всего', color: '#7E92F8' },
];

const CHART_LINE_DRAW_ORDER = ['incoming', 'outgoing', 'transit', 'internal', 'unclassified', 'total'];

const BUCKET_SECONDS = 300;

/**
 * Drop the trailing bucket that is still open or only partially rolled up.
 * Strict `<` also drops the newest wall-clock-closed bucket on purpose: the 1m
 * rollup trails ~6 minutes (its own safety margin plus cron cadence), so that
 * bucket usually holds 3–4 of its 5 minutes while the divisor stays the full
 * bucket, and the last point would dip by 20–40% instead of being absent.
 */
function closedChartBucketSql(bucketColumn, bucketSeconds, boundaryExpr = 'ts_to') {
  return `${bucketColumn} + toIntervalSecond(${bucketSeconds}) < ${boundaryExpr}`;
}

function shiftedNowSql() {
  return 'now() - INTERVAL 30 SECOND';
}

function anchoredNowSql(anchor) {
  if (anchor) return parseDataDatetimeSql('anchor');
  return shiftedNowSql();
}

function normalizeChartDirections(directions) {
  if (directions === undefined) {
    return [...CHART_SQL_DIRECTIONS];
  }
  const list = directions
    .map((d) => String(d).trim())
    .filter((d) => CHART_SQL_DIRECTION_SET.has(d));
  return [...new Set(list)];
}

function parseChartDirectionsQuery(raw) {
  if (raw === undefined) return undefined;
  if (raw === '') return [];
  return normalizeChartDirections(String(raw).split(','));
}

function chartDirectionsInSql(directions) {
  return normalizeChartDirections(directions)
    .map((d) => `'${d}'`)
    .join(', ');
}

function normalizeChBucketString(bucket) {
  if (bucket == null || bucket === '') return '';
  const s = String(bucket).trim();
  const m = s.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  if (m) return `${m[1]} ${m[2]}`;
  return s.slice(0, 19).replace('T', ' ');
}

function mapBandwidthChartRows(rows, range, directions) {
  const dirs = normalizeChartDirections(directions);
  const lines = CHART_LINE_DRAW_ORDER
    .map((id) => CHART_LINE_META.find((m) => m.id === id))
    .filter((m) => m && dirs.includes(m.sql))
    .map((m) => ({ key: m.id, label: m.label, color: m.color }));

  const buckets = new Map();
  for (const r of rows) {
    const bk = normalizeChBucketString(r.bucket);
    if (!bk) continue;
    if (!buckets.has(bk)) {
      buckets.set(bk, {
        bucket: bk,
        bucketMs: Number(r.bucket_ts) * 1000,
        t: formatSeriesBucketLabel(bk, range),
      });
    }
    const pt = buckets.get(bk);
    const id = DIRECTION_IDS[r.direction];
    if (id) {
      pt[id] = (Number(r.gbps) || 0) * 1e9;
      pt[`${id}_pps`] = Number(r.pps) || 0;
    }
  }

  const points = [...buckets.values()]
    .sort((a, b) => a.bucketMs - b.bucketMs)
    .map(({ bucket, bucketMs, ...pt }) => ({ ...pt, bucket, bucketMs }));

  return { points, lines };
}

function resolveBandwidthSeriesWindow({ range = '1h', from, to } = {}) {
  if (range === 'custom') {
    if (!from || !to) throw new Error('Для своего периода нужны параметры from и to');
    return {
      cteHead: `
    ${parseDataDatetimeSql('to')} AS raw_ts_to,
    ${parseDataDatetimeSql('from')} AS raw_ts_from,
    toStartOfInterval(raw_ts_from + INTERVAL 5 MINUTE - INTERVAL 1 SECOND, INTERVAL 5 MINUTE) AS ts_from,
    toStartOfInterval(raw_ts_to, INTERVAL 5 MINUTE) AS ts_to,`,
      params: { from, to },
    };
  }

  const interval = EXTENDED_RANGE_INTERVALS[range]
    || MEDIUM_RANGE_INTERVALS[range]
    || SHORT_RANGE_INTERVALS[range];
  if (!interval) throw new Error(`Неизвестный период: ${range}`);

  return {
    cteHead: `
    ${shiftedNowSql()} AS raw_ts_to,
    raw_ts_to - ${interval} AS raw_ts_from,
    toStartOfInterval(raw_ts_from + INTERVAL 5 MINUTE - INTERVAL 1 SECOND, INTERVAL 5 MINUTE) AS ts_from,
    toStartOfInterval(raw_ts_to, INTERVAL 5 MINUTE) AS ts_to,`,
    params: {},
  };
}

function buildBandwidthSeriesUnions(dashboardTable, sourcesTable, collectorScope) {
  const scope = sourcesScopeSql(collectorScope);
  return DIRECTION_DAY_COLS.map((d, i) => `
    ${i ? 'UNION ALL' : ''}
    SELECT
      toStartOfInterval(minute, INTERVAL 5 MINUTE) AS bucket,
      minute,
      '${d.dir}' AS direction,
      ${d.bytes} AS bucket_bytes,
      ${d.packets} AS bucket_packets
    FROM ${dashboardTable} AS m
    INNER JOIN ${sourcesTable} AS s ON m.source_id = s.source_id
    WHERE ${scope} AND minute >= ts_from AND minute < ts_to
  `).join('');
}

function formatSeriesBucketLabel(bucket, range) {
  const normalized = normalizeChBucketString(bucket);
  const m = normalized.match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})/);
  if (!m) return '—';
  const longRange = range === 'custom'
    || MEDIUM_RANGE_INTERVALS[range]
    || EXTENDED_RANGE_INTERVALS[range];
  if (longRange) return `${m[3]}.${m[2]} ${m[4]}:${m[5]}`;
  return `${m[4]}:${m[5]}`;
}

/** Traffic time series: gbps + pps per 5-minute bucket, all directions. */
function trafficBandwidthSeries({ range = '1h', from, to, directions, collectorId } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const dirs = normalizeChartDirections(directions);
  if (!dirs.length) {
    return {
      sql: 'SELECT 1 AS _empty WHERE 0',
      params: {},
      map() {
        return { points: [], lines: [] };
      },
    };
  }
  const dirsSql = dirs.map((d) => `'${d}'`).join(', ');
  const windowSpec = resolveBandwidthSeriesWindow({ range, from, to });
  const dashboardTable = dashboardTableRef();
  const sourcesTable = sourcesTableRef();

  return {
    sql: `
      WITH
        ${windowSpec.cteHead}
        ${BUCKET_SECONDS} AS bucket_seconds
      SELECT
        bucket,
        toUnixTimestamp(bucket) AS bucket_ts,
        direction,
        round(sum(bucket_bytes) * 8 / bucket_seconds / 1e9, 3) AS gbps,
        round(sum(bucket_packets) / bucket_seconds, 0) AS pps,
        round(sum(bucket_bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
        sum(bucket_packets) AS total_packets
      FROM
      (
        ${buildBandwidthSeriesUnions(dashboardTable, sourcesTable, collectorScope)}
      )
      WHERE direction IN (${dirsSql})
        AND ${closedChartBucketSql('bucket', BUCKET_SECONDS)}
      GROUP BY
        bucket,
        direction
      ORDER BY
        bucket ASC,
        indexOf(${DIRECTIONS_SQL}, direction)
    `,
    params: mergeCollectorParams({ ...windowSpec.params }, collectorScope),
    map(rows) {
      return mapBandwidthChartRows(rows, range, directions);
    },
  };
}

const DONUT_MIN_PERCENT = 0.01;
const DONUT_LEGEND_LIMIT = 80;
const CATEGORY_TREND_TOP_N = 5;

const PROTOCOL_FLOW_DIRECTIONS = ['in', 'out', 'transit', 'internal', 'unknown'];
const PROTOCOL_FLOW_DIRECTION_SET = new Set(PROTOCOL_FLOW_DIRECTIONS);

const PROTOCOL_MULTIIF_SQL = `
        multiIf(
          proto = 1, 'ICMP',
          proto = 2, 'IGMP',
          proto = 4, 'IPv4-in-IP',
          proto = 6, 'TCP',
          proto = 17, 'UDP',
          proto = 41, 'IPv6-in-IP',
          proto = 47, 'GRE',
          proto = 50, 'ESP',
          proto = 51, 'AH',
          proto = 58, 'ICMPv6',
          proto = 89, 'OSPF',
          proto = 132, 'SCTP',
          concat('IP-', toString(proto))
        )`;

function normalizeProtocolDirections(directions) {
  const list = (directions || PROTOCOL_FLOW_DIRECTIONS)
    .map((d) => String(d).trim())
    .filter((d) => PROTOCOL_FLOW_DIRECTION_SET.has(d));
  return list.length ? [...new Set(list)] : PROTOCOL_FLOW_DIRECTIONS;
}

function protocolDirectionsInSql(directions) {
  return normalizeProtocolDirections(directions)
    .map((d) => `'${d}'`)
    .join(', ');
}

function resolveServiceWindowMode({ range = '24h', from, to } = {}) {
  if (range === 'custom') {
    const durationMs = customRangeDurationMs(from, to);
    if (durationMs <= ONE_DAY_MS) return 'minute';
    if (durationMs < THIRTY_DAYS_MS) return 'hybrid';
    return 'daily';
  }
  if (EXTENDED_RANGE_INTERVALS[range]) return 'daily';
  if (MEDIUM_RANGE_INTERVALS[range]) return 'hybrid';
  return 'minute';
}

function categoryBucketFromWindowMode(mode) {
  switch (mode) {
    case 'daily':
      return { bucketExpr: 'toStartOfHour(minute)', bucketSeconds: 3600 };
    case 'hybrid':
      return { bucketExpr: 'minute', bucketSeconds: 60 };
    default:
      return { bucketExpr: 'toStartOfInterval(minute, INTERVAL 5 MINUTE)', bucketSeconds: 300 };
  }
}

function mapCategoryTrendRows(rows, range, { labelForKey, colorForKey }) {
  const buckets = new Map();
  const totals = new Map();
  const labels = new Map();

  for (const r of rows) {
    const bk = normalizeChBucketString(r.bucket);
    if (!bk) continue;
    const key = String(r.category_key ?? r.service_code ?? r.protocol ?? '');
    if (!key) continue;
    const label = String(r.category_label || labelForKey(key) || key);
    labels.set(key, label);
    if (!buckets.has(bk)) {
      buckets.set(bk, {
        bucket: bk,
        bucketMs: Number(r.bucket_ts) * 1000,
        t: formatSeriesBucketLabel(bk, range),
      });
    }
    const pt = buckets.get(bk);
    const bps = (Number(r.gbps) || 0) * 1e9;
    pt[key] = (pt[key] || 0) + bps;
    totals.set(key, (totals.get(key) || 0) + bps);
  }

  const lines = [...totals.entries()]
    .sort((a, b) => {
      if (a[0] === 'other') return 1;
      if (b[0] === 'other') return -1;
      return b[1] - a[1];
    })
    .map(([key], idx) => ({
      key,
      label: labels.get(key) || labelForKey(key) || key,
      color: colorForKey(key, idx),
    }));

  const points = [...buckets.values()]
    .sort((a, b) => a.bucketMs - b.bucketMs)
    .map(({ bucket, bucketMs, t, ...rest }) => ({ bucket, bucketMs, t, ...rest }));

  return { points, lines };
}

function resolveServiceWindow({ range = '24h', from, to } = {}) {
  if (range === 'custom') {
    if (!from || !to) throw new Error('Для своего периода нужны параметры from и to');
    const durationMs = customRangeDurationMs(from, to);
    if (durationMs <= ONE_DAY_MS) {
      return {
        cteHead: `
    ${parseDataDatetimeSql('to')} AS raw_ts_to,
    ${parseDataDatetimeSql('from')} AS raw_ts_from,
    ${FIVE_MINUTE_ALIGN_CTE}`,
        params: { from, to },
      };
    }
    if (durationMs < THIRTY_DAYS_MS) {
      return {
        cteHead: `
    toStartOfMinute(${parseDataDatetimeSql('to')}) AS ts_to,
    toStartOfMinute(${parseDataDatetimeSql('from')}) AS ts_from,`,
        params: { from, to },
      };
    }
    return {
      cteHead: `
    toStartOfHour(${parseDataDatetimeSql('to')}) AS ts_to,
    toStartOfHour(${parseDataDatetimeSql('from')}) AS ts_from,`,
      params: { from, to },
    };
  }

  if (EXTENDED_RANGE_INTERVALS[range]) {
    return {
      cteHead: `
    toStartOfHour(${shiftedNowSql()}) AS ts_to,
    ts_to - ${EXTENDED_RANGE_INTERVALS[range]} AS ts_from,`,
      params: {},
    };
  }

  if (MEDIUM_RANGE_INTERVALS[range]) {
    return {
      cteHead: `
    toStartOfMinute(${shiftedNowSql()}) AS ts_to,
    ts_to - ${MEDIUM_RANGE_INTERVALS[range]} AS ts_from,`,
      params: {},
    };
  }

  const interval = SHORT_RANGE_INTERVALS[range];
  if (!interval) throw new Error(`Неизвестный период: ${range}`);
  return {
    cteHead: `
    ${shiftedNowSql()} AS raw_ts_to,
    raw_ts_to - ${interval} AS raw_ts_from,
    ${FIVE_MINUTE_ALIGN_CTE}`,
    params: {},
  };
}

/** L7 service distribution by bytes from traffic_service_1m. */
function serviceDistribution({ range = '24h', from, to, directions, collectorId } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveServiceWindow({ range, from, to });
  const serviceTable = serviceTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = protocolDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope, 'src');
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN (${dirsSql})`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead},
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        s.service_code,
        s.service_name,
        s.category,
        round(s.slice_bytes * 100 / nullIf(t.total_bytes, 0), 3) AS percent,
        round(s.slice_bytes * 8 / window_seconds / 1e9, 3) AS avg_gbps,
        round(s.slice_packets / window_seconds, 0) AS avg_pps,
        round(s.slice_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
        s.slice_packets AS packets,
        s.slice_flows AS flows
      FROM
      (
        SELECT
          if(t.service_code = 'unknown', 'other', t.service_code) AS service_code,
          if(t.service_code = 'unknown', 'Other', argMax(t.service_name, t.bytes)) AS service_name,
          if(t.service_code = 'unknown', 'unknown', argMax(t.category, t.bytes)) AS category,
          sum(t.bytes) AS slice_bytes,
          sum(t.packets) AS slice_packets,
          sum(t.flows_count) AS slice_flows
        FROM ${serviceTable} AS t
        INNER JOIN ${sourcesTable} AS src
          ON t.source_id = src.source_id
        WHERE
          ${filter}
        GROUP BY t.service_code
      ) AS s
      CROSS JOIN
      (
        SELECT sum(t.bytes) AS total_bytes
        FROM ${serviceTable} AS t
        INNER JOIN ${sourcesTable} AS src
          ON t.source_id = src.source_id
        WHERE
          ${filter}
      ) AS t
      WHERE s.slice_bytes > 0
      ORDER BY
        if(s.service_code = 'other', 1, 0),
        traffic_gb DESC
      LIMIT ${DONUT_LEGEND_LIMIT}
    `,
    params: mergeCollectorParams(windowSpec.params, collectorScope),
    map(rows) {
      let colorIdx = 0;
      return rows.map((r) => {
        const isOther = String(r.service_code) === 'other';
        return {
          label: r.service_name || r.service_code,
          value: Math.round((Number(r.percent) || 0) * 1000) / 1000,
          color: isOther ? protocolChartColor(19) : protocolChartColor(colorIdx++),
          trafficGb: Number(r.traffic_gb) || 0,
          packets: Number(r.packets) || 0,
          flows: Number(r.flows) || 0,
          serviceCode: r.service_code,
          category: r.category,
          avgGbps: Number(r.avg_gbps) || 0,
          avgPps: Number(r.avg_pps) || 0,
        };
      });
    },
  };
}

const OTHER_PORTS_TOP_N = 20;

/** Top ports inside «Other» services from traffic_unknown_port_1m. */
function otherPortsTop20({ range = '24h', from, to, directions, collectorId } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveServiceWindow({ range, from, to });
  const portTable = unknownPortTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = protocolDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope);
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN (${dirsSql})
        AND port > 0`;
  const totalFilter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN (${dirsSql})`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead},
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        p.transport,
        p.port,
        p.port_side,
        round(p.port_bytes * 100 / nullIf(t.other_bytes, 0), 3) AS percent_within_other,
        round(p.port_bytes * 8 / window_seconds / 1e9, 3) AS avg_gbps,
        round(p.port_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
        p.port_packets AS packets,
        p.port_flows AS flows
      FROM
      (
        SELECT
          u.transport,
          u.port,
          u.port_side,
          sum(u.bytes) AS port_bytes,
          sum(u.packets) AS port_packets,
          sum(u.flows_count) AS port_flows
        FROM ${portTable} AS u
        INNER JOIN ${sourcesTable} AS s
          ON u.source_id = s.source_id
        WHERE
          ${filter}
        GROUP BY u.transport, u.port, u.port_side
      ) AS p
      CROSS JOIN
      (
        SELECT sum(u.bytes) AS other_bytes
        FROM ${portTable} AS u
        INNER JOIN ${sourcesTable} AS s
          ON u.source_id = s.source_id
        WHERE
          ${totalFilter}
      ) AS t
      WHERE p.port_bytes > 0
      ORDER BY traffic_gb DESC
      LIMIT ${OTHER_PORTS_TOP_N}
    `,
    params: mergeCollectorParams(windowSpec.params, collectorScope),
    map(rows) {
      return rows.map((r) => ({
        transport: r.transport,
        port: Number(r.port) || 0,
        portSide: r.port_side,
        percent: Math.round((Number(r.percent_within_other) || 0) * 1000) / 1000,
        avgGbps: Number(r.avg_gbps) || 0,
        trafficGb: Number(r.traffic_gb) || 0,
        packets: Number(r.packets) || 0,
        flows: Number(r.flows) || 0,
      }));
    },
  };
}

/** L4 protocol distribution by bytes from traffic_protocol_1m. */
function protocolDistribution({ range = '24h', from, to, directions, collectorId } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveTrafficWindow({ range, from, to });
  const protocolTable = protocolTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = protocolDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope);
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN (${dirsSql})`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead}
      SELECT
        p.protocol,
        round(p.proto_bytes * 100 / nullIf(t.total_bytes, 0), 3) AS percent,
        round(p.proto_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
        p.proto_packets AS packets
      FROM
      (
        SELECT
          ${PROTOCOL_MULTIIF_SQL} AS protocol,
          sum(bytes) AS proto_bytes,
          sum(packets) AS proto_packets
        FROM ${protocolTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
        GROUP BY proto
      ) AS p
      CROSS JOIN
      (
        SELECT sum(bytes) AS total_bytes
        FROM ${protocolTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
      ) AS t
      WHERE p.proto_bytes > 0
      ORDER BY
        if(lowerUTF8(p.protocol) = 'other', 1, 0),
        traffic_gb DESC
      LIMIT ${DONUT_LEGEND_LIMIT}
    `,
    params: mergeCollectorParams(windowSpec.params, collectorScope),
    map(rows) {
      let colorIdx = 0;
      return rows.map((r) => {
        const isOther = String(r.protocol).toLowerCase() === 'other';
        return {
          label: r.protocol,
          protocol: r.protocol,
          value: Math.round((Number(r.percent) || 0) * 1000) / 1000,
          color: isOther ? protocolChartColor(19) : protocolChartColor(colorIdx++),
          trafficGb: Number(r.traffic_gb) || 0,
          packets: Number(r.packets) || 0,
        };
      });
    },
  };
}

/** L4 protocol trend: top categories + Other per time bucket. */
function protocolDistributionTimeseries({ range = '24h', from, to, directions, collectorId } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveTrafficWindow({ range, from, to });
  const { bucketExpr, bucketSeconds } = categoryBucketFromWindowMode(windowSpec.mode);
  const protocolTable = protocolTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = protocolDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope);
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN (${dirsSql})`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead},
        ${bucketSeconds} AS bucket_seconds,
        top_protos AS (
          SELECT
            proto
          FROM ${protocolTable} AS p
          INNER JOIN ${sourcesTable} AS s
            ON p.source_id = s.source_id
          WHERE
            ${filter}
          GROUP BY proto
          ORDER BY sum(bytes) DESC
          LIMIT ${CATEGORY_TREND_TOP_N}
        )
      SELECT
        bucket,
        toUnixTimestamp(bucket) AS bucket_ts,
        category_key,
        round(sum(slice_bytes) * 8 / bucket_seconds / 1e9, 3) AS gbps
      FROM
      (
        SELECT
          ${bucketExpr} AS bucket,
          if(p.proto IN (SELECT proto FROM top_protos), toString(p.proto), 'other') AS category_key,
          sum(p.bytes) AS slice_bytes
        FROM ${protocolTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
        GROUP BY
          bucket,
          category_key
      )
      WHERE ${closedChartBucketSql('bucket', 'bucket_seconds')}
      GROUP BY
        bucket,
        category_key
      ORDER BY
        bucket ASC,
        if(category_key = 'other', 1, 0),
        category_key
    `,
    params: mergeCollectorParams(windowSpec.params, collectorScope),
    map(rows) {
      let colorIdx = 0;
      return mapCategoryTrendRows(rows, range, {
        labelForKey(key) {
          if (key === 'other') return 'Other';
          const n = Number(key);
          return Number.isFinite(n) ? protoLabel(n) : key;
        },
        colorForKey(key) {
          if (key === 'other') return protocolChartColor(19);
          return protocolChartColor(colorIdx++);
        },
      });
    },
  };
}

/** L7 service trend: top categories + Other per time bucket. */
function serviceDistributionTimeseries({ range = '24h', from, to, directions, collectorId } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveServiceWindow({ range, from, to });
  const mode = resolveServiceWindowMode({ range, from, to });
  const { bucketExpr, bucketSeconds } = categoryBucketFromWindowMode(mode);
  const serviceTable = serviceTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = protocolDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope, 'src');
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN (${dirsSql})`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead},
        ${bucketSeconds} AS bucket_seconds,
        top_services AS (
          SELECT
            if(t.service_code = 'unknown', 'other', t.service_code) AS service_code,
            if(t.service_code = 'unknown', 'Other', argMax(t.service_name, t.bytes)) AS service_name,
            sum(t.bytes) AS total_bytes
          FROM ${serviceTable} AS t
          INNER JOIN ${sourcesTable} AS src
            ON t.source_id = src.source_id
          WHERE
            ${filter}
          GROUP BY t.service_code
          ORDER BY total_bytes DESC
          LIMIT ${CATEGORY_TREND_TOP_N}
        )
      SELECT
        bucket,
        toUnixTimestamp(bucket) AS bucket_ts,
        category_key,
        if(
          category_key = 'other',
          'Other',
          coalesce(ts.service_name, category_key)
        ) AS category_label,
        round(sum(slice_bytes) * 8 / bucket_seconds / 1e9, 3) AS gbps
      FROM
      (
        SELECT
          ${bucketExpr} AS bucket,
          multiIf(
            t.service_code = 'unknown', 'other',
            t.service_code IN (SELECT service_code FROM top_services), if(t.service_code = 'unknown', 'other', t.service_code),
            'other'
          ) AS category_key,
          sum(t.bytes) AS slice_bytes
        FROM ${serviceTable} AS t
        INNER JOIN ${sourcesTable} AS src
          ON t.source_id = src.source_id
        WHERE
          ${filter}
        GROUP BY
          bucket,
          category_key
      ) AS slices
      LEFT JOIN top_services AS ts
        ON slices.category_key = ts.service_code
      WHERE ${closedChartBucketSql('bucket', 'bucket_seconds')}
      GROUP BY
        bucket,
        category_key,
        category_label
      ORDER BY
        bucket ASC,
        if(category_key = 'other', 1, 0),
        category_key
    `,
    params: mergeCollectorParams(windowSpec.params, collectorScope),
    map(rows) {
      let colorIdx = 0;
      return mapCategoryTrendRows(rows, range, {
        labelForKey(key) {
          if (key === 'other') return 'Other';
          return key;
        },
        colorForKey(key) {
          if (key === 'other') return protocolChartColor(19);
          return protocolChartColor(colorIdx++);
        },
      });
    },
  };
}

// Keep in sync with PROTOCOL_FLOW_DIRECTIONS: when most traffic is still
// unclassified (empty L3 catalog or unfinished port marking), dropping
// `unknown` makes the VLAN widgets look empty even though traffic_vlan_1m is full.
const VLAN_FLOW_DIRECTIONS = ['in', 'out', 'transit', 'internal', 'unknown'];
const VLAN_FLOW_DIRECTION_SET = new Set(VLAN_FLOW_DIRECTIONS);
const VLAN_ATTACHMENT_SET = new Set([
  'unknown', 'customer', 'uplink', 'core', 'peering', 'ix', 'internal', 'transit', 'management',
]);
const VLAN_BOUNDARY_SET = new Set(['internal', 'external', 'unknown']);

function normalizeVlanDirections(directions) {
  const list = (directions || VLAN_FLOW_DIRECTIONS)
    .map((d) => String(d).trim())
    .filter((d) => VLAN_FLOW_DIRECTION_SET.has(d));
  return list.length ? [...new Set(list)] : VLAN_FLOW_DIRECTIONS;
}

function vlanDirectionsInSql(directions) {
  return normalizeVlanDirections(directions).map((d) => `'${d}'`).join(', ');
}

function vlanAttachmentFilterSql(attachmentType, params) {
  const v = String(attachmentType || '').trim();
  if (!v || v === 'all' || !VLAN_ATTACHMENT_SET.has(v)) return '';
  params.vlan_attachment = v;
  return `\n        AND attachment_type = {vlan_attachment:String}`;
}

/** Top VLANs by traffic from traffic_vlan_1m (donut). */
function vlanDistribution({ range = '24h', from, to, directions, collectorId, attachmentType } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveTrafficWindow({ range, from, to });
  const vlanTable = vlanTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = vlanDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope);
  const params = mergeCollectorParams(windowSpec.params, collectorScope);
  const attachmentSql = vlanAttachmentFilterSql(attachmentType, params);
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND vlan_id != 0
        AND direction IN (${dirsSql})${attachmentSql}`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead}
      SELECT
        v.vlan_id AS vlan_id,
        round(v.vlan_bytes * 100 / nullIf(t.total_bytes, 0), 3) AS percent,
        round(v.vlan_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
        v.vlan_packets AS packets,
        v.vlan_flows AS flows
      FROM
      (
        SELECT
          vlan_id,
          sum(bytes) AS vlan_bytes,
          sum(packets) AS vlan_packets,
          sum(flows_count) AS vlan_flows
        FROM ${vlanTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
        GROUP BY vlan_id
      ) AS v
      CROSS JOIN
      (
        SELECT sum(bytes) AS total_bytes
        FROM ${vlanTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
      ) AS t
      WHERE v.vlan_bytes > 0
      ORDER BY traffic_gb DESC
      LIMIT ${DONUT_LEGEND_LIMIT}
    `,
    params,
    async map(rows) {
      const nameMap = await getVlanNameMap();
      let colorIdx = 0;
      return rows.map((r) => {
        const vlanId = Number(r.vlan_id) || 0;
        return {
          vlanId,
          label: vlanLabel(vlanId, nameMap),
          value: Math.round((Number(r.percent) || 0) * 1000) / 1000,
          color: protocolChartColor(colorIdx++),
          trafficGb: Number(r.traffic_gb) || 0,
          packets: Number(r.packets) || 0,
          flows: Number(r.flows) || 0,
        };
      });
    },
  };
}

/** VLAN trend: top-N VLANs + Other per time bucket from traffic_vlan_1m. */
function vlanDistributionTimeseries({ range = '24h', from, to, directions, collectorId, attachmentType } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveTrafficWindow({ range, from, to });
  const { bucketExpr, bucketSeconds } = categoryBucketFromWindowMode(windowSpec.mode);
  const vlanTable = vlanTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = vlanDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope);
  const params = mergeCollectorParams(windowSpec.params, collectorScope);
  const attachmentSql = vlanAttachmentFilterSql(attachmentType, params);
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND vlan_id != 0
        AND direction IN (${dirsSql})${attachmentSql}`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead},
        ${bucketSeconds} AS bucket_seconds,
        top_vlans AS (
          SELECT
            vlan_id
          FROM ${vlanTable} AS p
          INNER JOIN ${sourcesTable} AS s
            ON p.source_id = s.source_id
          WHERE
            ${filter}
          GROUP BY vlan_id
          ORDER BY sum(bytes) DESC
          LIMIT ${CATEGORY_TREND_TOP_N}
        )
      SELECT
        bucket,
        toUnixTimestamp(bucket) AS bucket_ts,
        category_key,
        round(sum(slice_bytes) * 8 / bucket_seconds / 1e9, 3) AS gbps
      FROM
      (
        SELECT
          ${bucketExpr} AS bucket,
          if(p.vlan_id IN (SELECT vlan_id FROM top_vlans), toString(p.vlan_id), 'other') AS category_key,
          sum(p.bytes) AS slice_bytes
        FROM ${vlanTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
        GROUP BY
          bucket,
          category_key
      )
      WHERE ${closedChartBucketSql('bucket', 'bucket_seconds')}
      GROUP BY
        bucket,
        category_key
      ORDER BY
        bucket ASC,
        if(category_key = 'other', 1, 0),
        category_key
    `,
    params,
    async map(rows) {
      const nameMap = await getVlanNameMap();
      let colorIdx = 0;
      return mapCategoryTrendRows(rows, range, {
        labelForKey(key) {
          if (key === 'other') return 'Other';
          const n = Number(key);
          return Number.isFinite(n) ? vlanLabel(n, nameMap) : key;
        },
        colorForKey(key) {
          if (key === 'other') return protocolChartColor(19);
          return protocolChartColor(colorIdx++);
        },
      });
    },
  };
}

/** VLAN table for the dedicated page: traffic + share + attachment/boundary. */
function vlanTopTable({ range = '24h', from, to, directions, collectorId, attachmentType, limit = 50 } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveTrafficWindow({ range, from, to });
  const vlanTable = vlanTableRef();
  const sourcesTable = sourcesTableRef();
  const dirsSql = vlanDirectionsInSql(directions);
  const scope = sourcesScopeSql(collectorScope);
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 500);
  const windowSeconds = explorerWindowSeconds({ range, from, to });
  const params = { ...mergeCollectorParams(windowSpec.params, collectorScope), limit: lim };
  const attachmentSql = vlanAttachmentFilterSql(attachmentType, params);
  const filter = `
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND vlan_id != 0
        AND direction IN (${dirsSql})${attachmentSql}`;
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');

  return {
    sql: `
      WITH
        ${cteHead},
        ${windowSeconds} AS window_seconds
      SELECT
        v.vlan_id AS vlan_id,
        v.vlan_bytes AS bytes,
        round(v.vlan_bytes * 8 / window_seconds, 0) AS avg_bps,
        v.vlan_packets AS packets,
        v.vlan_flows AS flows,
        round(v.vlan_bytes * 100 / nullIf(t.total_bytes, 0), 3) AS percent
      FROM
      (
        SELECT
          vlan_id,
          sum(bytes) AS vlan_bytes,
          sum(packets) AS vlan_packets,
          sum(flows_count) AS vlan_flows
        FROM ${vlanTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
        GROUP BY vlan_id
      ) AS v
      CROSS JOIN
      (
        SELECT sum(bytes) AS total_bytes
        FROM ${vlanTable} AS p
        INNER JOIN ${sourcesTable} AS s
          ON p.source_id = s.source_id
        WHERE
          ${filter}
      ) AS t
      WHERE v.vlan_bytes > 0
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `,
    params,
    meta: { windowSeconds },
    async map(rows) {
      const nameMap = await getVlanNameMap();
      let colorIdx = 0;
      return rows.map((r) => {
        const vlanId = Number(r.vlan_id) || 0;
        const info = nameMap.get(vlanId) || {};
        return {
          vlanId,
          label: vlanLabel(vlanId, nameMap),
          displayName: info.displayName || '',
          attachmentType: info.attachmentType || 'unknown',
          boundary: info.boundary || 'unknown',
          entityId: info.entityId || '',
          bytes: Number(r.bytes) || 0,
          avgBps: Number(r.avg_bps) || 0,
          packets: Number(r.packets) || 0,
          flows: Number(r.flows) || 0,
          pct: Number(r.percent) || 0,
          color: protocolChartColor(colorIdx++),
        };
      });
    },
  };
}

const TOP_TALKERS_GROUP_SET = new Set(['src', 'dst', 'pair']);

function normalizeTopTalkersGroup(group) {
  const v = String(group || 'src').trim().toLowerCase();
  return TOP_TALKERS_GROUP_SET.has(v) ? v : 'src';
}

function formatAsn(asn) {
  const n = Number(asn);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n === 0) return 'AS0';
  return `AS${n}`;
}

const TALKERS_MINUTE_RANGES = new Set(['30m', '1h']);
const ONE_HOUR_MS = 60 * 60 * 1000;

function resolveTalkersGranularity({ range = '1h', from, to } = {}) {
  let useMinute = TALKERS_MINUTE_RANGES.has(range);
  if (range === 'custom' && from && to) {
    const fromD = new Date(from);
    const toD = new Date(to);
    if (!Number.isNaN(fromD.getTime()) && !Number.isNaN(toD.getTime()) && toD > fromD) {
      useMinute = (toD.getTime() - fromD.getTime()) <= ONE_HOUR_MS;
    }
  }
  if (useMinute) {
    return {
      granularity: '1m',
      timeColumn: 'minute',
      talkerTable: talkerTableRef(),
      pairTable: pairTableRef(),
    };
  }
  return {
    granularity: '1h',
    timeColumn: 'hour',
    talkerTable: talkerHourTableRef(),
    pairTable: pairHourTableRef(),
  };
}

function trafficTbFromGb(trafficGb) {
  const gb = Number(trafficGb) || 0;
  return gb >= 1000 ? Math.round((gb / 1000) * 1000) / 1000 : 0;
}

function mapStringArray(val) {
  if (!val) return [];
  return Array.isArray(val) ? val.map((v) => String(v)) : [String(val)];
}

function mapTalkerRow(r, endpointSide) {
  const trafficGb = Number(r.traffic_gb) || 0;
  const asCountry = String(r.endpoint_as_country || '').trim();
  return {
    group: endpointSide,
    // ASN aggregates — no per-IP fields.
    ip: '',
    label: '',
    asName: r.endpoint_as_name || '',
    asn: r.endpoint_asn,
    asnLabel: formatAsn(r.endpoint_asn),
    countryCode: asCountry,
    asCountry,
    endpointScope: '',
    endpointNetworkName: '',
    endpointNetworkRole: '',
    endpointSide,
    sourceIds: mapStringArray(r.source_ids),
    directions: mapStringArray(r.directions),
    totalBytes: Number(r.total_bytes) || 0,
    trafficGb,
    trafficTb: trafficTbFromGb(trafficGb),
    avgGbps: Number(r.avg_gbps) || 0,
    avgPps: Number(r.avg_pps) || 0,
    flowCount: Number(r.flow_count) || 0,
  };
}

function mapPairRow(r) {
  const trafficGb = Number(r.traffic_gb) || 0;
  const srcAsCountry = String(r.src_as_country || '').trim();
  const dstAsCountry = String(r.dst_as_country || '').trim();
  return {
    group: 'pair',
    srcIp: '',
    dstIp: '',
    srcLabel: '',
    dstLabel: '',
    srcAsn: r.src_asn,
    dstAsn: r.dst_asn,
    srcAsName: r.src_as_name || '',
    dstAsName: r.dst_as_name || '',
    srcCountry: srcAsCountry,
    dstCountry: dstAsCountry,
    srcAsCountry,
    dstAsCountry,
    srcScope: '',
    dstScope: '',
    sourceIds: mapStringArray(r.source_ids),
    directions: mapStringArray(r.directions),
    totalBytes: Number(r.total_bytes) || 0,
    trafficGb,
    trafficTb: trafficTbFromGb(trafficGb),
    avgGbps: Number(r.avg_gbps) || 0,
    avgPps: Number(r.avg_pps) || 0,
    flowCount: Number(r.flow_count) || 0,
  };
}

const TOP_TALKERS_SOURCE_IDS_LIMIT = 16;
const TOP_TALKERS_DIRECTIONS_LIMIT = 8;

const TOP_TALKERS_QUERY_SETTINGS = '';

function topTalkersSourceIdsFilter(alias, ids) {
  return ids.length ? `AND ${alias}.source_id IN {source_ids:Array(String)}` : '';
}

function topTalkersEnabledSourcesCte(sourcesTable, scope) {
  return `
    enabled_sources AS (
      SELECT source_id
      FROM ${sourcesTable} AS s
      WHERE ${scope}
    )`;
}

function topTalkersTrafficSelect(prefix) {
  return `
        ${prefix}.total_bytes,
        round(${prefix}.total_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
        round((${prefix}.total_bytes * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
        round(${prefix}.total_packets / window_seconds, 0) AS avg_pps,
        ${prefix}.flow_count`;
}

function asnDisplayNameSql(nameExpr, registryNameExpr, asnExpr) {
  return `coalesce(
            nullIf(${nameExpr}, ''),
            nullIf(${registryNameExpr}, concat('AS', toString(${asnExpr}))),
            nullIf(${registryNameExpr}, ''),
            ''
          )`;
}

/** Top ASN talkers/pairs from traffic_asn_* and traffic_asn_pair_*. */
function topTalkersDashboard({
  range = '1h',
  from,
  to,
  directions,
  group = 'src',
  limit = 20,
  offset = 0,
  sourceIds,
  collectorId,
} = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveServiceWindow({ range, from, to });
  const gran = resolveTalkersGranularity({ range, from, to });
  const sourcesTable = sourcesTableRef();
  const dirsSql = protocolDirectionsInSql(directions);
  const side = normalizeTopTalkersGroup(group);
  const ids = normalizeSourceIds(sourceIds);
  const scope = sourcesScopeSql(collectorScope);
  const sourceFilter = topTalkersSourceIdsFilter('t', ids);
  const pairSourceFilter = topTalkersSourceIdsFilter('p', ids);
  const enabledSourcesCte = topTalkersEnabledSourcesCte(sourcesTable, scope);
  const asnNames = asnNamesTableRef();
  const asnRegistry = asnRegistryEnrichedTableRef();
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');
  const timeCol = gran.timeColumn;
  const lim = Math.min(Math.max(Number(limit) || 20, 1), 100);
  const off = Math.min(Math.max(Number(offset) || 0, 0), 10000);
  const params = mergeCollectorParams({ ...windowSpec.params, limit: lim, row_offset: off }, collectorScope);
  if (ids.length) params.source_ids = ids;
  const queryMeta = {
    granularity: gran.granularity,
    timeColumn: gran.timeColumn,
    group: side,
    range,
    from,
    to,
    directions: normalizeProtocolDirections(directions),
  };

  if (side === 'pair') {
    const pairTable = gran.pairTable;
    return {
      sql: `
      WITH
        ${cteHead},
        dateDiff('second', ts_from, ts_to) AS window_seconds,
        ${enabledSourcesCte},
        ranked_pairs AS (
          SELECT
            p.src_asn,
            p.dst_asn,
            argMax(p.src_as_name, p.bytes) AS src_as_name,
            argMax(p.dst_as_name, p.bytes) AS dst_as_name,
            argMax(p.src_as_country, p.bytes) AS src_as_country,
            argMax(p.dst_as_country, p.bytes) AS dst_as_country,
            groupUniqArray(${TOP_TALKERS_SOURCE_IDS_LIMIT})(p.source_id) AS source_ids,
            groupUniqArray(${TOP_TALKERS_DIRECTIONS_LIMIT})(p.direction) AS directions,
            sum(p.bytes) AS total_bytes,
            sum(p.packets) AS total_packets,
            sum(p.flows_count) AS flow_count
          FROM ${pairTable} AS p
          PREWHERE
            p.${timeCol} >= ts_from
            AND p.${timeCol} < ts_to
          WHERE
            p.direction IN (${dirsSql})
            AND p.source_id IN (SELECT source_id FROM enabled_sources)
            ${pairSourceFilter}
          GROUP BY
            p.src_asn,
            p.dst_asn
          ORDER BY total_bytes DESC
          LIMIT {limit:UInt32} OFFSET {row_offset:UInt32}
        )
      SELECT
        ranked.src_asn AS src_asn,
        ranked.dst_asn AS dst_asn,
        ${asnDisplayNameSql(
          'src_names.name',
          'coalesce(nullIf(src_reg.name, \'\'), ranked.src_as_name)',
          'ranked.src_asn',
        )} AS src_as_name,
        ${asnDisplayNameSql(
          'dst_names.name',
          'coalesce(nullIf(dst_reg.name, \'\'), ranked.dst_as_name)',
          'ranked.dst_asn',
        )} AS dst_as_name,
        ranked.src_as_country AS src_as_country,
        ranked.dst_as_country AS dst_as_country,
        ranked.source_ids AS source_ids,
        ranked.directions AS directions,
        ${topTalkersTrafficSelect('ranked').trim()}
      FROM ranked_pairs AS ranked
      LEFT JOIN ${asnNames} AS src_names ON src_names.asn = ranked.src_asn
      LEFT JOIN ${asnNames} AS dst_names ON dst_names.asn = ranked.dst_asn
      LEFT JOIN ${asnRegistry} AS src_reg ON src_reg.asn = ranked.src_asn
      LEFT JOIN ${asnRegistry} AS dst_reg ON dst_reg.asn = ranked.dst_asn
      ORDER BY ranked.total_bytes DESC
      ${TOP_TALKERS_QUERY_SETTINGS}
    `,
      params,
      meta: queryMeta,
      map(rows) {
        return rows.map(mapPairRow);
      },
    };
  }

  const talkerTable = gran.talkerTable;
  const endpointSide = side === 'dst' ? 'dst' : 'src';
  return {
    sql: `
      WITH
        ${cteHead},
        dateDiff('second', ts_from, ts_to) AS window_seconds,
        ${enabledSourcesCte},
        ranked_asns AS (
          SELECT
            t.endpoint_asn,
            argMax(t.endpoint_as_name, t.bytes) AS endpoint_as_name,
            argMax(t.endpoint_as_country, t.bytes) AS endpoint_as_country,
            groupUniqArray(${TOP_TALKERS_SOURCE_IDS_LIMIT})(t.source_id) AS source_ids,
            groupUniqArray(${TOP_TALKERS_DIRECTIONS_LIMIT})(t.direction) AS directions,
            sum(t.bytes) AS total_bytes,
            sum(t.packets) AS total_packets,
            sum(t.flows_count) AS flow_count
          FROM ${talkerTable} AS t
          PREWHERE
            t.${timeCol} >= ts_from
            AND t.${timeCol} < ts_to
          WHERE
            t.direction IN (${dirsSql})
            AND t.endpoint_side = '${endpointSide}'
            AND t.source_id IN (SELECT source_id FROM enabled_sources)
            ${sourceFilter}
          GROUP BY
            t.endpoint_asn
          ORDER BY total_bytes DESC
          LIMIT {limit:UInt32} OFFSET {row_offset:UInt32}
        )
      SELECT
        ranked.endpoint_asn AS endpoint_asn,
        ${asnDisplayNameSql(
          'endpoint_names.name',
          'coalesce(nullIf(endpoint_reg.name, \'\'), ranked.endpoint_as_name)',
          'ranked.endpoint_asn',
        )} AS endpoint_as_name,
        ranked.endpoint_as_country AS endpoint_as_country,
        ranked.source_ids AS source_ids,
        ranked.directions AS directions,
        ${topTalkersTrafficSelect('ranked').trim()}
      FROM ranked_asns AS ranked
      LEFT JOIN ${asnNames} AS endpoint_names ON endpoint_names.asn = ranked.endpoint_asn
      LEFT JOIN ${asnRegistry} AS endpoint_reg ON endpoint_reg.asn = ranked.endpoint_asn
      ORDER BY ranked.total_bytes DESC
      ${TOP_TALKERS_QUERY_SETTINGS}
    `,
    params,
    meta: queryMeta,
    map(rows) {
      return rows.map((r) => mapTalkerRow(r, endpointSide));
    },
  };
}

function flowIpExpr(ipCol) {
  const etype = flowCol('etype');
  if (!etype) return `IPv6NumToString(${ipCol})`;
  const etypeRef = ipCol.includes('.')
    ? `${ipCol.split('.')[0]}.${etype}`
    : etype;
  return `if(
        ${etypeRef} = 2048,
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(${ipCol}, 1, 4))))),
        IPv6NumToString(${ipCol})
      )`;
}

function flowSamplerIpExpr(samplerCol) {
  // GrapesNTA stores IPv4 exporters in the first 4 bytes of FixedString(16).
  return `if(
        length(${samplerCol}) = 16
          AND substring(${samplerCol}, 5) = unhex('000000000000000000000000'),
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(${samplerCol}, 1, 4))))),
        IPv6NumToString(${samplerCol})
      )`;
}

/**
 * sFlow interface field -> plain ifIndex.
 * Only format 0 (two high bits = 0) carries a single ifIndex in the low 30 bits;
 * other formats (discard reason / multiple interfaces) decode to 0.
 */
function sflowIfIndexExpr(ifColRef) {
  const rawExpr = `toUInt32OrZero(toString(${ifColRef}))`;
  return `if(${rawExpr} > 0 AND bitShiftRight(${rawExpr}, 30) = 0, bitAnd(${rawExpr}, 1073741823), toUInt32(0))`;
}

function flowMacExpr(macCol) {
  if (config.macStorage === 'uint64') {
    return `MACNumToString(${macCol})`;
  }
  return `lower(arrayStringConcat(arrayMap(i -> substring(hex(${macCol}), (i - 1) * 2 + 1, 2), range(1, 7)), ':'))`;
}

function flowColSelect(key, alias, tableAlias) {
  const c = flowCol(key);
  if (!c) return null;
  const ref = tableAlias ? `${tableAlias}.${c}` : c;
  return `${ref} AS ${alias}`;
}

function formatTimeOnly(d) {
  return [
    String(d.getHours()).padStart(2, '0'),
    String(d.getMinutes()).padStart(2, '0'),
    String(d.getSeconds()).padStart(2, '0'),
  ].join(':') + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function formatFlowTimestampParts(hh, mm, ss, frac) {
  const ms = frac ? String(frac).padEnd(3, '0').slice(0, 3) : '000';
  return `${String(hh).padStart(2, '0')}:${mm}:${ss}.${ms}`;
}

/** time_received_ns, DateTime-строка или уже готовое время → HH:MM:SS.mmm (без даты). */
function formatFlowTimestamp(ts) {
  if (ts == null || ts === '') return '—';
  const s = String(ts).trim();
  if (!s) return '—';

  const timeOnly = s.match(/^(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$/);
  if (timeOnly) {
    return formatFlowTimestampParts(timeOnly[1], timeOnly[2], timeOnly[3], timeOnly[4]);
  }

  const dateTime = s.match(/\d{4}-\d{2}-\d{2}[ T](\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?/);
  if (dateTime) {
    return formatFlowTimestampParts(dateTime[1], dateTime[2], dateTime[3], dateTime[4]);
  }

  if (/^\d+$/.test(s)) {
    try {
      const n = BigInt(s);
      const sec = n / 1000000000n;
      const ms = Number((n % 1000000000n) / 1000000n);
      const d = new Date(Number(sec) * 1000 + ms);
      if (!Number.isNaN(d.getTime())) return formatTimeOnly(d);
    } catch {
      /* fall through */
    }
  }

  const num = Number(s);
  if (Number.isFinite(num) && num > 0) {
    let ms;
    if (num > 1e15) ms = Math.floor(num / 1e6);
    else if (num > 1e12) ms = num;
    else ms = num * 1000;
    const d = new Date(ms);
    if (!Number.isNaN(d.getTime())) return formatTimeOnly(d);
  }

  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return formatTimeOnly(d);

  return s;
}

function formatFlowAsn(n) {
  const v = Number(n);
  return Number.isFinite(v) && v > 0 ? `AS${v}` : '—';
}

function formatFlowAsnPair(srcAsn, dstAsn) {
  const src = formatFlowAsn(srcAsn);
  const dst = formatFlowAsn(dstAsn);
  if (src !== '—' && dst !== '—') return `${src} → ${dst}`;
  return dst !== '—' ? dst : src;
}

function cleanCountryCode(value) {
  const s = String(value || '').replace(/\0/g, '').trim();
  return s === '??' ? '' : s;
}

/** ISO country from geo IP dictionary (same logic as explorer). */
function geoCountryExpr(ipExpr, etypeExpr = null) {
  const dict = escapeSqlString(config.geoCountryDict);
  const lookup = (keyExpr) => `dictGetString('${dict}', 'cc', tuple(${keyExpr}))`;
  const ipv4Expr = `toIPv4(reinterpretAsUInt32(reverse(substring(${ipExpr}, 1, 4))))`;
  const isIpv4 = etypeExpr
    ? `${etypeExpr} = 2048`
    : `length(${ipExpr}) = 16 AND substring(${ipExpr}, 5) = unhex('000000000000000000000000')`;
  const country = `upper(if(${isIpv4}, ${lookup(ipv4Expr)}, ${lookup(ipExpr)}))`;
  return `nullIf(nullIf(${country}, ''), '??')`;
}

const RECENT_FLOWS_LOOKBACK_MINUTES = 1;

function protoLabelSql(expr) {
  return `multiIf(
    ${expr} = 1, 'ICMP',
    ${expr} = 6, 'TCP',
    ${expr} = 17, 'UDP',
    ${expr} = 47, 'GRE',
    ${expr} = 50, 'ESP',
    ${expr} = 51, 'AH',
    ${expr} = 58, 'ICMPv6',
    ${expr} = 132, 'SCTP',
    concat('IP-', toString(${expr}))
  )`;
}

function explorerWindowSeconds({ range = '24h', from, to } = {}) {
  if (range === 'custom') {
    return Math.max(1, Math.floor(customRangeDurationMs(from, to) / 1000));
  }
  const secondsByRange = {
    '30m': 30 * 60,
    '1h': 3600,
    '3h': 3 * 3600,
    '6h': 6 * 3600,
    '12h': 12 * 3600,
    '24h': 86400,
    '2d': 2 * 86400,
    '7d': 7 * 86400,
    '14d': 14 * 86400,
    '30d': 30 * 86400,
    '60d': 60 * 86400,
    '90d': 90 * 86400,
  };
  return secondsByRange[range] || 3600;
}

/** Recent flow records from flows_raw (enrichment via fetchRecentFlows). */
function recentFlows(limit = 20, directions, collectorId) {
  const collectorScope = parseCollectorScopes(collectorId);
  const t = col('time');
  const bytes = col('bytes');
  const packets = col('packets');
  const srcIp = col('srcIp');
  const dstIp = col('dstIp');
  const srcPort = col('srcPort');
  const dstPort = col('dstPort');
  const proto = col('proto');
  const srcAsn = col('srcAsn');
  const dstAsn = col('dstAsn');
  const directionCol = flowCol('direction');
  const sourceIdCol = flowCol('sourceId');
  const dirs = normalizeProtocolDirections(directions);
  const dirsSql = protocolDirectionsInSql(dirs);
  const lim = Math.min(Math.max(Number(limit) || 20, 1), 200);
  const perSourceLimit = collectorScope.length ? lim : lim;
  const recentLimitSql = collectorScope.length || !sourceIdCol
    ? 'LIMIT {limit:UInt32}'
    : `LIMIT {per_source_limit:UInt32} BY f.${sourceIdCol}`;
  const recentInnerOrderSql = collectorScope.length || !sourceIdCol
    ? `f.${t} DESC`
    : `f.${sourceIdCol} ASC, f.${t} DESC`;
  const sourceScope = sourcesScopeSql(collectorScope, '');
  const enabledSourcesCte = `
        enabled_sources AS (
          SELECT source_id
          FROM ${sourcesTableRef()}
          WHERE ${sourceScope}
        )`;

  const innerSelectCols = [
    `f.${t} AS ts`,
    flowColSelect('sourceId', 'source_id', 'f'),
    flowColSelect('direction', 'direction', 'f'),
    `${flowIpExpr(`f.${srcIp}`)} AS src_ip`,
    `${flowIpExpr(`f.${dstIp}`)} AS dst_ip`,
    `f.${srcPort} AS src_port`,
    `f.${dstPort} AS dst_port`,
    `f.${proto} AS proto`,
    `f.${srcAsn} AS src_asn`,
    `f.${dstAsn} AS dst_asn`,
    flowColSelect('srcLabel', 'src_label', 'f'),
    flowColSelect('dstLabel', 'dst_label', 'f'),
    flowColSelect('srcEndpointScope', 'src_endpoint_scope', 'f'),
    flowColSelect('dstEndpointScope', 'dst_endpoint_scope', 'f'),
    flowColSelect('srcNetworkName', 'src_network_name', 'f'),
    flowColSelect('dstNetworkName', 'dst_network_name', 'f'),
    flowColSelect('srcVlan', 'src_vlan', 'f'),
    flowColSelect('dstVlan', 'dst_vlan', 'f'),
    flowColSelect('vlanId', 'vlan_id', 'f'),
    `f.${bytes} AS bytes`,
    `f.${packets} AS packets`,
  ].filter(Boolean);

  const prewhereClauses = [
    'f.date >= today()',
    `f.${t} >= now() - INTERVAL ${RECENT_FLOWS_LOOKBACK_MINUTES} MINUTE`,
  ];
  const whereClauses = [];
  if (directionCol) whereClauses.push(`f.${directionCol} IN (${dirsSql})`);
  if (sourceIdCol) {
    whereClauses.push(`f.${sourceIdCol} IN (SELECT source_id FROM enabled_sources)`);
  }
  const innerWhere = whereClauses.length ? `WHERE ${whereClauses.join(' AND ')}` : '';
  const params = mergeCollectorParams({ limit: lim, per_source_limit: perSourceLimit }, collectorScope);

  return {
    sql: `
      WITH
        ${enabledSourcesCte}
      SELECT
        recent.*
      FROM (
        SELECT
          ${innerSelectCols.join(',\n          ')}
        FROM ${flowsRawTableRef()} AS f
        PREWHERE ${prewhereClauses.join(' AND ')}
        ${innerWhere}
        ORDER BY ${recentInnerOrderSql}
        ${recentLimitSql}
      ) AS recent
      ORDER BY recent.ts DESC
      LIMIT {limit:UInt32}
    `,
    params,
    map: mapRecentFlowRows,
  };
}

function flowTransportFromProto(proto) {
  const n = Number(proto);
  if (n === 6) return 'tcp';
  if (n === 17) return 'udp';
  if (n === 132) return 'sctp';
  if (n === 1) return 'icmp';
  if (n === 58) return 'icmpv6';
  return '';
}

function mapRecentFlowRows(rows) {
  return rows.map(mapRecentFlowRow);
}

function mapRecentFlowRow(r, enrich = {}) {
  const srcIpVal = String(r.src_ip || '');
  const dstIpVal = String(r.dst_ip || '');
  const srcPortVal = r.src_port;
  const dstPortVal = r.dst_port;
  const srcAsn = Number(r.src_asn) || 0;
  const dstAsn = Number(r.dst_asn) || 0;
  const transport = flowTransportFromProto(r.proto);
  const portService = enrich.portServices?.get(`${transport}:${dstPortVal}`) || {};
  return {
    ts: formatFlowTimestamp(r.ts),
    src: `${srcIpVal}:${srcPortVal}`,
    dst: `${dstIpVal}:${dstPortVal}`,
    srcIp: srcIpVal,
    dstIp: dstIpVal,
    srcPort: srcPortVal,
    dstPort: dstPortVal,
    srcLabel: String(r.src_label || '').trim(),
    dstLabel: String(r.dst_label || '').trim(),
    proto: protoLabel(r.proto),
    bytes: Number(r.bytes) || 0,
    pkts: Number(r.packets) || 0,
    dur: '—',
    asn: formatFlowAsnPair(srcAsn, dstAsn),
    srcAsn,
    dstAsn,
    srcAsName: enrich.asnNames?.get(srcAsn) || enrich.asnRegistry?.get(srcAsn)?.name || '',
    dstAsName: enrich.asnNames?.get(dstAsn) || enrich.asnRegistry?.get(dstAsn)?.name || '',
    srcCountry: cleanCountryCode(r.src_geo_country) || cleanCountryCode(enrich.asnRegistry?.get(srcAsn)?.cc),
    dstCountry: cleanCountryCode(r.dst_geo_country) || cleanCountryCode(enrich.asnRegistry?.get(dstAsn)?.cc),
    srcVlan: Number(r.src_vlan) || 0,
    dstVlan: Number(r.dst_vlan) || 0,
    vlanId: Number(r.vlan_id) || 0,
    direction: r.direction || '',
    sourceId: r.source_id || '',
    srcScope: r.src_endpoint_scope || '',
    dstScope: r.dst_endpoint_scope || '',
    srcNetworkName: r.src_network_name || '',
    dstNetworkName: r.dst_network_name || '',
    dstServiceCode: String(portService.service_code || ''),
    dstServiceName: String(portService.service_name || ''),
    dstServiceCategory: String(portService.category || ''),
  };
}

async function loadRecentFlowEnrichment(rows, queryFn, { name = 'dashboard/recent-flows' } = {}) {
  const runQuery = queryFn || require('./clickhouse').query;
  if (!rows.length) {
    return { asnNames: new Map(), asnRegistry: new Map(), portServices: new Map() };
  }

  const asns = [...new Set(rows.flatMap((row) => [
    Number(row.src_asn) || 0,
    Number(row.dst_asn) || 0,
  ]).filter((asn) => asn > 0))];

  const portClauses = [];
  const seenPorts = new Set();
  for (const row of rows) {
    const transport = flowTransportFromProto(row.proto);
    const port = Number(row.dst_port);
    if (!transport || !Number.isFinite(port)) continue;
    const key = `${transport}:${port}`;
    if (seenPorts.has(key)) continue;
    seenPorts.add(key);
    portClauses.push(`(ps.transport = '${transport}' AND ps.port = ${port})`);
  }

  const [asnNameResult, asnRegistryResult, portServiceResult] = await Promise.all([
    asns.length
      ? runQuery(
        `SELECT asn, name FROM ${asnNamesTableRef()} WHERE asn IN {asns:Array(UInt32)}`,
        { asns },
        { name: `${name}/asn-names` },
      )
      : { rows: [] },
    asns.length
      ? runQuery(
        `SELECT asn, name, cc FROM ${asnRegistryEnrichedTableRef()} WHERE asn IN {asns:Array(UInt32)}`,
        { asns },
        { name: `${name}/asn-registry` },
      )
      : { rows: [] },
    portClauses.length
      ? runQuery(
        `SELECT ps.transport, ps.port, ps.service_code, ps.service_name, ps.category
         FROM ${portServicesExpandedViewRef()} AS ps
         WHERE ${portClauses.join(' OR ')}`,
        {},
        { name: `${name}/port-services` },
      )
      : { rows: [] },
  ]);

  const asnNames = new Map(asnNameResult.rows.map((row) => [Number(row.asn), String(row.name || '').trim()]));
  const asnRegistry = new Map(asnRegistryResult.rows.map((row) => [Number(row.asn), {
    name: String(row.name || '').trim(),
    cc: cleanCountryCode(row.cc),
  }]));
  const portServices = new Map(portServiceResult.rows.map((row) => [
    `${String(row.transport)}:${Number(row.port)}`,
    {
      service_code: String(row.service_code || ''),
      service_name: String(row.service_name || ''),
      category: String(row.category || ''),
    },
  ]));

  return { asnNames, asnRegistry, portServices };
}

async function fetchRecentFlows(limit = 20, directions, collectorId, { name = 'dashboard/recent-flows', queryFn } = {}) {
  const runQuery = queryFn || require('./clickhouse').query;
  const spec = recentFlows(limit, directions, collectorId);
  const started = Date.now();
  const { rows, elapsedMs } = await runQuery(spec.sql, spec.params || {}, { name });
  const enrich = await loadRecentFlowEnrichment(rows, runQuery, { name });
  return {
    data: rows.map((row) => mapRecentFlowRow(row, enrich)),
    meta: { elapsedMs: Date.now() - started, rows: rows.length, queryMs: elapsedMs },
  };
}

/** Traffic stats by direction (max / avg / volume) from aggregated dashboard table. */
function mapTrafficDirectionRows(rows) {
  const max = {};
  const avg = {};
  const volume = {};

  for (const r of rows) {
    const id = DIRECTION_IDS[r.direction] || r.direction;
    max[id] = { bps: (Number(r.max_gbps) || 0) * 1e9, pps: Number(r.max_pps) || 0 };
    avg[id] = { bps: (Number(r.avg_gbps) || 0) * 1e9, pps: Number(r.avg_pps) || 0 };
    volume[id] = {
      gb: Number(r.total_gb) || 0,
      tb: Number(r.total_tb) || 0,
      packets: Number(r.total_packets) || 0,
    };
  }

  return { max, avg, volume };
}

function customRangeDurationMs(from, to) {
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    throw new Error('Некорректный пользовательский период');
  }
  return end - start;
}

function resolveTrafficWindow({ range = '24h', from, to, bucketSeconds, anchor } = {}) {
  const minuteAlignCte = `
    ${parseDataDatetimeSql('to')} AS raw_ts_to,
    ${parseDataDatetimeSql('from')} AS raw_ts_from,
    toStartOfMinute(raw_ts_from) AS ts_from,
    toStartOfMinute(raw_ts_to) AS ts_to,`;
  const useMinuteAlign = Number(bucketSeconds) > 0 && Number(bucketSeconds) <= 60;
  const nowExpr = anchoredNowSql(anchor);
  const anchorParams = anchor ? { anchor } : {};

  if (range === 'custom') {
    if (!from || !to) throw new Error('Для своего периода нужны параметры from и to');
    const durationMs = customRangeDurationMs(from, to);
    const mode = durationMs >= THIRTY_DAYS_MS ? 'daily' : durationMs > ONE_DAY_MS ? 'hybrid' : 'minute';
    if (mode === 'daily') {
      return {
        mode,
        cteHead: `
    toStartOfHour(${parseDataDatetimeSql('to')}) AS ts_to,
    toStartOfHour(${parseDataDatetimeSql('from')}) AS ts_from,`,
        params: { from, to },
      };
    }
    if (mode === 'hybrid') {
      return {
        mode,
        cteHead: `
    toStartOfMinute(${parseDataDatetimeSql('to')}) AS ts_to,
    toStartOfMinute(${parseDataDatetimeSql('from')}) AS ts_from,`,
        params: { from, to },
      };
    }
    return {
      mode,
      cteHead: useMinuteAlign
        ? minuteAlignCte
        : `
    ${parseDataDatetimeSql('to')} AS raw_ts_to,
    ${parseDataDatetimeSql('from')} AS raw_ts_from,
    ${FIVE_MINUTE_ALIGN_CTE}`,
      params: { from, to },
    };
  }

  if (EXTENDED_RANGE_INTERVALS[range]) {
    return {
      mode: 'daily',
      cteHead: `
    toStartOfHour(${nowExpr}) AS ts_to,
    ts_to - ${EXTENDED_RANGE_INTERVALS[range]} AS ts_from,`,
      params: { ...anchorParams },
    };
  }

  if (MEDIUM_RANGE_INTERVALS[range]) {
    return {
      mode: 'hybrid',
      cteHead: `
    toStartOfMinute(${nowExpr}) AS ts_to,
    ts_to - ${MEDIUM_RANGE_INTERVALS[range]} AS ts_from,`,
      params: { ...anchorParams },
    };
  }

  const interval = SHORT_RANGE_INTERVALS[range];
  if (!interval) throw new Error(`Неизвестный период: ${range}`);
  return {
    mode: 'minute',
    cteHead: `
    ${nowExpr} AS raw_ts_to,
    raw_ts_to - ${interval} AS raw_ts_from,
    ${FIVE_MINUTE_ALIGN_CTE}`,
    params: { ...anchorParams },
  };
}

async function probeTrafficWindowBounds({ range = '24h', from, to, anchor, bucketSeconds } = {}, queryFn) {
  const runQuery = queryFn || require('./clickhouse').query;
  const windowSpec = resolveTrafficWindow({ range, from, to, anchor, bucketSeconds });
  const tz = escapeSqlString(config.dataTimezone || 'UTC');
  const { rows } = await runQuery(`
    WITH
      ${windowSpec.cteHead}
      dateDiff('second', ts_from, ts_to) AS _window_seconds
    SELECT
      formatDateTime(ts_from, '%F %T', '${tz}') AS window_from,
      formatDateTime(ts_to, '%F %T', '${tz}') AS window_to,
      _window_seconds AS window_seconds
  `, windowSpec.params, { name: 'explorer/window-bounds' });
  const row = rows[0] || {};
  return {
    windowFrom: row.window_from || null,
    windowTo: row.window_to || null,
    windowSeconds: Math.max(1, Number(row.window_seconds) || 1),
  };
}

function buildDirectionMinuteBucketUnions(dashboardTable, sourcesTable, collectorScope) {
  const scope = sourcesScopeSql(collectorScope);
  return DIRECTION_DAY_COLS.map((d, i) => `
    ${i ? 'UNION ALL' : ''}
    SELECT
      toStartOfInterval(minute, INTERVAL 5 MINUTE) AS bucket,
      '${d.dir}' AS direction,
      ${d.bytes} AS bucket_bytes,
      ${d.packets} AS bucket_packets
    FROM ${dashboardTable} AS m
    INNER JOIN ${sourcesTable} AS s ON m.source_id = s.source_id
    WHERE ${scope} AND minute >= ts_from AND minute < ts_to
  `).join('');
}

function buildDirectionDayUnions(dashboardDayTable, sourcesTable, collectorScope) {
  const scope = sourcesScopeSql(collectorScope);
  return DIRECTION_DAY_COLS.map((d, i) => `
    ${i ? 'UNION ALL' : ''}
    SELECT '${d.dir}' AS direction, ${d.bytes} AS bytes, ${d.packets} AS packets
    FROM ${dashboardDayTable} AS d
    INNER JOIN ${sourcesTable} AS s ON d.source_id = s.source_id
    WHERE ${scope} AND day >= toStartOfDay(ts_from) AND day < toStartOfDay(ts_to)
  `).join('');
}

function buildDirectionHourPeakUnions(dashboardHourTable, sourcesTable, collectorScope) {
  const scope = sourcesScopeSql(collectorScope);
  return DIRECTION_DAY_COLS.map((d, i) => `
    ${i ? 'UNION ALL' : ''}
    SELECT
      hour,
      '${d.dir}' AS direction,
      sum(${d.bytes}) AS hour_bytes,
      sum(${d.packets}) AS hour_packets
    FROM ${dashboardHourTable} AS h
    INNER JOIN ${sourcesTable} AS s ON h.source_id = s.source_id
    WHERE ${scope} AND hour >= ts_from AND hour < ts_to
    GROUP BY hour
  `).join('');
}

function trafficDirectionStatsDailySql({ cteHead, dashboardDayTable, dashboardHourTable, sourcesTable, collectorScope }) {
  return `
    WITH
      ${cteHead}
      dateDiff('second', ts_from, ts_to) AS window_seconds
    SELECT
      totals.direction,
      peaks.max_gbps,
      totals.avg_gbps,
      peaks.max_pps,
      totals.avg_pps,
      totals.total_gb,
      totals.total_tb,
      totals.total_packets
    FROM
    (
      SELECT
        direction,
        round((sum(bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
        round(sum(packets) / window_seconds, 0) AS avg_pps,
        round(sum(bytes) / 1000 / 1000 / 1000, 3) AS total_gb,
        round(sum(bytes) / 1000 / 1000 / 1000 / 1000, 3) AS total_tb,
        sum(packets) AS total_packets
      FROM
      (
        ${buildDirectionDayUnions(dashboardDayTable, sourcesTable, collectorScope)}
      )
      GROUP BY direction
    ) AS totals
    LEFT JOIN
    (
      SELECT
        direction,
        round(max(hour_bytes * 8 / 3600) / 1e9, 3) AS max_gbps,
        round(max(hour_packets / 3600), 0) AS max_pps
      FROM
      (
        ${buildDirectionHourPeakUnions(dashboardHourTable, sourcesTable, collectorScope)}
      )
      GROUP BY direction
    ) AS peaks
      ON totals.direction = peaks.direction
    ORDER BY indexOf(${DIRECTIONS_SQL}, totals.direction)
  `;
}

function trafficDirectionStatsMinuteSql({ cteHead, dashboardTable, sourcesTable, collectorScope }) {
  return `
    WITH
      ${cteHead}
      dateDiff('second', ts_from, ts_to) AS window_seconds
    SELECT
      direction,
      round(max(bucket_bytes * 8 / ${FIVE_MINUTE_BUCKET_SECONDS}) / 1e9, 3) AS max_gbps,
      round((sum(bucket_bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
      round(max(bucket_packets / ${FIVE_MINUTE_BUCKET_SECONDS}), 0) AS max_pps,
      round(sum(bucket_packets) / window_seconds, 0) AS avg_pps,
      round(sum(bucket_bytes) / 1000 / 1000 / 1000, 3) AS total_gb,
      round(sum(bucket_bytes) / 1000 / 1000 / 1000 / 1000, 3) AS total_tb,
      sum(bucket_packets) AS total_packets
    FROM
    (
      SELECT
        bucket,
        direction,
        sum(bucket_bytes) AS bucket_bytes,
        sum(bucket_packets) AS bucket_packets
      FROM
      (
        ${buildDirectionMinuteBucketUnions(dashboardTable, sourcesTable, collectorScope)}
      )
      GROUP BY
        bucket,
        direction
    )
    GROUP BY direction
    ORDER BY indexOf(${DIRECTIONS_SQL}, direction)
  `;
}

function trafficDirectionStatsHybridSql({ cteHead, dashboardTable, dashboardHourTable, sourcesTable, collectorScope }) {
  const scope = sourcesScopeSql(collectorScope);
  return `
    WITH
      ${cteHead}
      toStartOfHour(ts_from) AS ts_from_hour_floor,
      if(ts_from = ts_from_hour_floor, ts_from_hour_floor, ts_from_hour_floor + INTERVAL 1 HOUR) AS full_hour_from,
      toStartOfHour(ts_to) AS full_hour_to,
      dateDiff('second', ts_from, ts_to) AS window_seconds
    SELECT
      direction,
      round(max(bucket_bytes * 8 / bucket_seconds) / 1e9, 3) AS max_gbps,
      round((sum(bucket_bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
      round(max(bucket_packets / bucket_seconds), 0) AS max_pps,
      round(sum(bucket_packets) / window_seconds, 0) AS avg_pps,
      round(sum(bucket_bytes) / 1000 / 1000 / 1000, 3) AS total_gb,
      round(sum(bucket_bytes) / 1000 / 1000 / 1000 / 1000, 3) AS total_tb,
      sum(bucket_packets) AS total_packets
    FROM
    (
      SELECT
        minute AS bucket,
        direction,
        sum(bytes) AS bucket_bytes,
        sum(packets) AS bucket_packets,
        60 AS bucket_seconds
      FROM ${dashboardTable} AS m
      INNER JOIN ${sourcesTable} AS s
        ON m.source_id = s.source_id
      ARRAY JOIN
        ${DIRECTIONS_SQL} AS direction,
        ${DIRECTION_BYTES_SQL} AS bytes,
        ${DIRECTION_PACKETS_SQL} AS packets
      WHERE
        ${scope}
        AND minute >= ts_from
        AND minute < ts_to
        AND (minute < full_hour_from OR minute >= full_hour_to)
      GROUP BY
        bucket,
        direction
      UNION ALL
      SELECT
        hour AS bucket,
        direction,
        sum(bytes) AS bucket_bytes,
        sum(packets) AS bucket_packets,
        3600 AS bucket_seconds
      FROM ${dashboardHourTable} AS h
      INNER JOIN ${sourcesTable} AS s
        ON h.source_id = s.source_id
      ARRAY JOIN
        ${DIRECTIONS_SQL} AS direction,
        ${DIRECTION_BYTES_SQL} AS bytes,
        ${DIRECTION_PACKETS_SQL} AS packets
      WHERE
        ${scope}
        AND hour >= full_hour_from
        AND hour < full_hour_to
      GROUP BY
        bucket,
        direction
    )
    GROUP BY direction
    ORDER BY indexOf(${DIRECTIONS_SQL}, direction)
  `;
}

function trafficDirectionStats({ range = '24h', from, to, collectorId } = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveTrafficWindow({ range, from, to });
  const tables = {
    dashboardTable: dashboardTableRef(),
    dashboardHourTable: dashboardHourTableRef(),
    dashboardDayTable: dashboardDayTableRef(),
    sourcesTable: sourcesTableRef(),
    collectorScope,
  };

  let sql;
  if (windowSpec.mode === 'daily') {
    sql = trafficDirectionStatsDailySql({ cteHead: windowSpec.cteHead, ...tables });
  } else if (windowSpec.mode === 'hybrid') {
    sql = trafficDirectionStatsHybridSql({ cteHead: windowSpec.cteHead, ...tables });
  } else {
    sql = trafficDirectionStatsMinuteSql({ cteHead: windowSpec.cteHead, ...tables });
  }

  return {
    sql,
    params: mergeCollectorParams(windowSpec.params, collectorScope),
    map: mapTrafficDirectionRows,
  };
}

const COUNTRY_BASIS_SET = new Set(['ip', 'asn']);
const MAP_SIDE_SET = new Set(['remote', 'src', 'dst']);

function normalizeCountryBasis(basis) {
  const v = String(basis || 'ip').trim().toLowerCase();
  return COUNTRY_BASIS_SET.has(v) ? v : 'ip';
}

function normalizeMapSide(mapSide) {
  const v = String(mapSide || 'remote').trim().toLowerCase();
  return MAP_SIDE_SET.has(v) ? v : 'remote';
}

function normalizeSourceIds(sourceIds) {
  if (!sourceIds?.length) return [];
  return [...new Set(
    sourceIds
      .map((id) => String(id).trim())
      .filter(Boolean),
  )];
}

/** Country traffic heatmap from traffic_country_1m. */
function countryHeatmap({
  range = '24h',
  from,
  to,
  directions,
  countryBasis = 'ip',
  mapSide = 'remote',
  sourceIds,
  collectorId,
} = {}) {
  const collectorScope = parseCollectorScopes(collectorId);
  const windowSpec = resolveServiceWindow({ range, from, to });
  const countryTable = countryTableRef();
  const sourcesTable = sourcesTableRef();
  const basis = normalizeCountryBasis(countryBasis);
  const side = normalizeMapSide(mapSide);
  const dirsSql = protocolDirectionsInSql(directions);
  const ids = normalizeSourceIds(sourceIds);
  const scope = sourcesScopeSql(collectorScope);
  const sourceFilter = ids.length
    ? 'AND c.source_id IN {source_ids:Array(String)}'
    : '';
  const cteHead = windowSpec.cteHead.trim().replace(/,\s*$/, '');
  const params = mergeCollectorParams({ ...windowSpec.params, map_side: side }, collectorScope);
  if (ids.length) params.source_ids = ids;

  return {
    sql: `
      WITH
        ${cteHead},
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        agg.country_code,
        agg.country_basis,
        agg.map_side,
        agg.traffic_gb,
        round(100 * agg.traffic_gb / sum(agg.traffic_gb) OVER (), 2) AS share_percent,
        round((agg.total_bytes * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
        round(agg.packet_count / window_seconds, 0) AS avg_pps,
        agg.packet_count,
        agg.flow_count
      FROM
      (
        SELECT
          c.country_code,
          '${basis}' AS country_basis,
          {map_side:String} AS map_side,
          sum(c.bytes) AS total_bytes,
          round(sum(c.bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
          sum(c.packets) AS packet_count,
          sum(c.flows_count) AS flow_count
        FROM ${countryTable} AS c
        INNER JOIN ${sourcesTable} AS s ON c.source_id = s.source_id
        WHERE
          ${scope}
          AND c.minute >= ts_from
          AND c.minute < ts_to
          AND c.country_basis = '${basis}'
          AND c.country_code != '??'
          AND c.direction IN (${dirsSql})
          AND (
            ({map_side:String} = 'src' AND c.country_side = 'src')
            OR ({map_side:String} = 'dst' AND c.country_side = 'dst')
            OR (
              {map_side:String} = 'remote'
              AND (
                (c.direction = 'in' AND c.country_side = 'src')
                OR (c.direction = 'out' AND c.country_side = 'dst')
                OR (c.direction = 'transit' AND c.country_side = 'src')
                OR (c.direction = 'internal' AND c.country_side = 'src')
                OR (c.direction = 'unknown' AND c.country_side = 'src')
              )
            )
          )
          ${sourceFilter}
        GROUP BY c.country_code
      ) AS agg
      ORDER BY traffic_gb DESC
    `,
    params,
    map(rows) {
      return rows.map((r) => ({
        countryCode: String(r.country_code || '').trim(),
        countryBasis: r.country_basis,
        mapSide: r.map_side,
        trafficGb: Number(r.traffic_gb) || 0,
        sharePercent: Number(r.share_percent) || 0,
        avgGbps: Number(r.avg_gbps) || 0,
        avgPps: Number(r.avg_pps) || 0,
        packetCount: Number(r.packet_count) || 0,
        flowCount: Number(r.flow_count) || 0,
      }));
    },
  };
}

/** Enabled collectors for dashboard filter dropdown. */
function dashboardCollectors() {
  const collectorsView = collectorsViewRef();
  const locationsView = locationsViewRef();
  return {
    sql: `
      SELECT
        c.collector_id,
        c.display_name AS collector_name,
        c.location_id,
        coalesce(nullIf(l.display_name, ''), nullIf(c.location_id, '')) AS location_name
      FROM ${collectorsView} AS c
      LEFT JOIN ${locationsView} AS l ON c.location_id = l.location_id
      ORDER BY location_name, collector_name
    `,
    params: {},
    map(rows) {
      return rows.map((r) => {
        const locationIdRaw = String(r.location_id ?? '').trim();
        const locationId = locationIdRaw || null;
        const locationNameRaw = String(r.location_name ?? '').trim();
        return {
          collectorId: String(r.collector_id),
          collectorName: String(r.collector_name || r.collector_id),
          locationId,
          locationName: locationNameRaw || locationId,
        };
      });
    },
  };
}

module.exports = {
  trafficBandwidthSeries,
  trafficDirectionStats,
  protocolDistribution,
  protocolDistributionTimeseries,
  serviceDistribution,
  serviceDistributionTimeseries,
  vlanDistribution,
  vlanDistributionTimeseries,
  vlanTopTable,
  normalizeVlanDirections,
  otherPortsTop20,
  countryHeatmap,
  dashboardCollectors,
  normalizeProtocolDirections,
  normalizeChartDirections,
  parseChartDirectionsQuery,
  topTalkersDashboard,
  resolveTalkersGranularity,
  normalizeTopTalkersGroup,
  recentFlows,
  fetchRecentFlows,
  resolveTrafficWindow,
  probeTrafficWindowBounds,
  anchoredNowSql,
  flowIpExpr,
  flowSamplerIpExpr,
  sflowIfIndexExpr,
  flowMacExpr,
  protoLabelSql,
  flowTransportSql,
  customRangeDurationMs,
  explorerWindowSeconds,
  protoLabel,
  parseCollectorScopes,
  sourcesScopeSql,
  mergeCollectorParams,
  appendFlowsRawCollectorFilter,
  CHART_LINE_META,
};
