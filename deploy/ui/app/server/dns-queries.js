const {
  config,
  dnsLogTableRef,
  dnsActivity5mTableRef,
  dnsDomains1hTableRef,
  dnsClients1hTableRef,
  dnsServers1hTableRef,
  dnsResolversViewRef,
  l3PrefixesViewRef,
  sourcesTableRef,
  collectorsViewRef,
  parseDataDatetimeSql,
} = require('./clickhouse');
const { parseCollectorScopes, mergeCollectorParams } = require('./queries');

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

const PRESET_WINDOW_SECONDS = {
  '30m': 1800,
  '1h': 3600,
  '3h': 10800,
  '6h': 21600,
  '12h': 43200,
  '24h': 86400,
  '2d': 172800,
  '7d': 604800,
  '14d': 1209600,
  '30d': 2592000,
};

const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
const SHORT_RAW_RANGES = new Set(['30m', '1h', '3h', '6h']);
const MINUTE_BUCKET_RANGES = SHORT_RAW_RANGES;

const RCODE_LABELS = {
  0: 'NOERROR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
};

function customRangeDurationMs(from, to) {
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    throw new Error('Некорректный пользовательский период');
  }
  return end - start;
}

function resolveRangeInterval(range) {
  return EXTENDED_RANGE_INTERVALS[range]
    || MEDIUM_RANGE_INTERVALS[range]
    || SHORT_RANGE_INTERVALS[range];
}

function dnsUsesAggregates(range, from, to) {
  if (range === 'custom') {
    return customRangeDurationMs(from, to) > SIX_HOURS_MS;
  }
  return !SHORT_RAW_RANGES.has(range);
}

function dnsBucketMode(range, from, to) {
  if (range === 'custom') {
    return customRangeDurationMs(from, to) <= SIX_HOURS_MS ? '1m' : '5m';
  }
  return MINUTE_BUCKET_RANGES.has(range) ? '1m' : '5m';
}

function dnsBucketSeconds(bucketMode) {
  return bucketMode === '1m' ? 60 : 300;
}

function dnsBucketExpr(bucketMode) {
  return bucketMode === '1m' ? 'toStartOfMinute(ts)' : 'toStartOfFiveMinutes(ts)';
}

function dnsWindowSeconds(range, from, to) {
  if (range === 'custom') {
    return Math.max(1, Math.round(customRangeDurationMs(from, to) / 1000));
  }
  const seconds = PRESET_WINDOW_SECONDS[range];
  if (!seconds) throw new Error(`Неизвестный период: ${range}`);
  return seconds;
}

function normalizeChBucketString(bucket) {
  if (bucket == null || bucket === '') return '';
  const s = String(bucket).trim();
  const m = s.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  if (m) return `${m[1]} ${m[2]}`;
  return s.slice(0, 19).replace('T', ' ');
}

function resolveTimeWindow({ range = '24h', from, to, timeCol = 'ts' } = {}) {
  const bucketMode = dnsBucketMode(range, from, to);
  const windowSeconds = dnsWindowSeconds(range, from, to);

  if (range === 'custom') {
    if (!from || !to) throw new Error('Для своего периода нужны параметры from и to');
    return {
      whereTime: `${timeCol} >= ${parseDataDatetimeSql('from')} AND ${timeCol} <= ${parseDataDatetimeSql('to')}`,
      params: { from, to },
      windowSeconds,
      bucketMode,
    };
  }

  const interval = resolveRangeInterval(range);
  if (!interval) throw new Error(`Неизвестный период: ${range}`);

  return {
    whereTime: `${timeCol} >= now() - ${interval}`,
    params: {},
    windowSeconds,
    bucketMode,
  };
}

function resolveDnsWindow(opts = {}) {
  const window = resolveTimeWindow(opts);
  return {
    whereTs: window.whereTime,
    params: window.params,
    windowSeconds: window.windowSeconds,
    bucketMode: window.bucketMode,
  };
}

function dnsIpExpr(col) {
  return `if(
    length(${col}) = 16
    AND substring(${col}, 5) = unhex('000000000000000000000000'),
    toString(toIPv4(reinterpretAsUInt32(reverse(substring(${col}, 1, 4))))),
    IPv6NumToString(${col})
  )`;
}

function dnsCol(name, alias) {
  return alias ? `${alias}.${name}` : name;
}

function clientIpFilterSql(alias) {
  const col = dnsCol('client_ip', alias);
  return `(
    (positionCaseInsensitive({client_ip:String}, ':') = 0
      AND substring(${col}, 1, 4) = reverse(reinterpretAsString(toIPv4({client_ip:String})))
      AND substring(${col}, 5) = unhex('000000000000000000000000'))
    OR
    (positionCaseInsensitive({client_ip:String}, ':') > 0
      AND ${col} = IPv6StringToNum({client_ip:String}))
  )`;
}

function serverIpFilterSql(alias) {
  const col = dnsCol('server_ip', alias);
  return `(
    (positionCaseInsensitive({server_ip:String}, ':') = 0
      AND substring(${col}, 1, 4) = reverse(reinterpretAsString(toIPv4({server_ip:String})))
      AND substring(${col}, 5) = unhex('000000000000000000000000'))
    OR
    (positionCaseInsensitive({server_ip:String}, ':') > 0
      AND ${col} = IPv6StringToNum({server_ip:String}))
  )`;
}

function dnsResolverLabelSql(prefix = 'r') {
  return `if(${prefix}.display_name != '', ${prefix}.display_name,
    multiIf(${prefix}.role = 'resolver', 'Резолвер', ${prefix}.role = 'client', 'Клиент', ${prefix}.role = 'public', 'Публичный', ${prefix}.role))`;
}

function dnsBadgeCtes(aggregatedName, ipColumn) {
  const resolversView = dnsResolversViewRef();
  const l3View = l3PrefixesViewRef();
  return `
    resolver_badges AS (
      SELECT
        a.${ipColumn} AS ip,
        argMax(r.role, length(r.prefix)) AS resolver_role,
        argMax(${dnsResolverLabelSql('r')}, length(r.prefix)) AS resolver_label
      FROM ${aggregatedName} AS a
      CROSS JOIN ${resolversView} AS r
      WHERE isIPAddressInRange(a.${ipColumn}, r.prefix)
      GROUP BY a.${ipColumn}
    ),
    internal_ips AS (
      SELECT DISTINCT a.${ipColumn} AS ip
      FROM ${aggregatedName} AS a
      CROSS JOIN ${l3View} AS p
      WHERE isIPAddressInRange(a.${ipColumn}, p.prefix)
    )`;
}

function dnsBadgeJoinSql(aggregatedAlias, ipColumn) {
  return `
    LEFT JOIN resolver_badges AS rb ON ${aggregatedAlias}.${ipColumn} = rb.ip
    LEFT JOIN internal_ips AS ii ON ${aggregatedAlias}.${ipColumn} = ii.ip`;
}

function dnsBadgeSelectSql() {
  return `
    rb.resolver_role AS resolver_role,
    rb.resolver_label AS resolver_label,
    ii.ip IS NULL AS is_external`;
}

function dnsRecentBadgeCtes() {
  const resolversView = dnsResolversViewRef();
  const l3View = l3PrefixesViewRef();
  const label = dnsResolverLabelSql('res');
  return `
    client_resolver_badges AS (
      SELECT
        r.client AS ip,
        argMax(res.role, length(res.prefix)) AS resolver_role,
        argMax(${label}, length(res.prefix)) AS resolver_label
      FROM recent_rows AS r
      CROSS JOIN ${resolversView} AS res
      WHERE isIPAddressInRange(r.client, res.prefix)
      GROUP BY r.client
    ),
    server_resolver_badges AS (
      SELECT
        r.server AS ip,
        argMax(res.role, length(res.prefix)) AS resolver_role,
        argMax(${label}, length(res.prefix)) AS resolver_label
      FROM recent_rows AS r
      CROSS JOIN ${resolversView} AS res
      WHERE isIPAddressInRange(r.server, res.prefix)
      GROUP BY r.server
    ),
    client_internal_ips AS (
      SELECT DISTINCT r.client AS ip
      FROM recent_rows AS r
      CROSS JOIN ${l3View} AS p
      WHERE isIPAddressInRange(r.client, p.prefix)
    ),
    server_internal_ips AS (
      SELECT DISTINCT r.server AS ip
      FROM recent_rows AS r
      CROSS JOIN ${l3View} AS p
      WHERE isIPAddressInRange(r.server, p.prefix)
    )`;
}

function mapIpBadgeFields(row, prefix = '') {
  const roleKey = prefix ? `${prefix}_resolver_role` : 'resolver_role';
  const labelKey = prefix ? `${prefix}_resolver_label` : 'resolver_label';
  const externalKey = prefix ? `${prefix}_is_external` : 'is_external';
  return {
    resolverRole: String(row[roleKey] ?? ''),
    resolverLabel: String(row[labelKey] ?? ''),
    isExternal: Number(row[externalKey]) === 1,
  };
}

function hideResolversWhereSql() {
  return `(NOT {hide_resolvers:UInt8} OR coalesce(resolver_role, '') NOT IN ('resolver', 'client'))`;
}

function scopeCol(alias, name) {
  return alias ? `${alias}.${name}` : name;
}

function dnsCollectorScopeSql(scopes, alias = 's') {
  const list = Array.isArray(scopes) ? scopes : parseCollectorScopes(scopes);
  if (!list.length) return '1=0';

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

  if (!orParts.length) return '1=0';
  return `(${orParts.join(' OR ')})`;
}

function resolveCollectorScopes(filters = {}) {
  if (filters.collectorScopes?.length) return filters.collectorScopes;
  if (filters.collectorId) return parseCollectorScopes(filters.collectorId);
  return [];
}

function appendSourceFilter(clauses, params, filterOpts, alias) {
  const sourceIds = filterOpts?.sourceIds;
  const collectorScopes = resolveCollectorScopes(filterOpts);

  if (sourceIds?.length) {
    clauses.push(`${dnsCol('source_id', alias)} IN {source_ids:Array(String)}`);
    params.source_ids = sourceIds;
    return;
  }

  if (collectorScopes.length) {
    const scopeSql = dnsCollectorScopeSql(collectorScopes);
    Object.assign(params, mergeCollectorParams(params, collectorScopes));
    clauses.push(`${dnsCol('source_id', alias)} IN (
      SELECT source_id
      FROM ${sourcesTableRef()} AS s
      WHERE source_type = 'dns'
        AND ${scopeSql}
    )`);
    return;
  }

  clauses.push(`${dnsCol('source_id', alias)} IN (
    SELECT source_id
    FROM ${sourcesTableRef()}
    WHERE source_type = 'dns'
  )`);
}

function buildRawDnsFilters(filters = {}) {
  const {
    range = '24h',
    from,
    to,
    qtype,
    rcode,
    domainSearch,
    clientIp,
    serverIp,
    alias,
  } = filters;
  const window = resolveDnsWindow({ range, from, to });
  const tsCol = dnsCol('ts', alias);
  const clauses = [window.whereTs.replace(/\bts\b/g, tsCol)];
  const params = { ...window.params };

  appendSourceFilter(clauses, params, filters, alias);

  if (qtype) {
    clauses.push(`${dnsCol('qtype', alias)} = {qtype:String}`);
    params.qtype = qtype;
  }

  if (rcode !== undefined && rcode !== null && rcode !== '') {
    clauses.push(`${dnsCol('rcode', alias)} = {rcode:UInt8}`);
    params.rcode = Number(rcode);
  }

  if (domainSearch) {
    clauses.push(`positionCaseInsensitive(${dnsCol('query_name', alias)}, {domain_search:String}) > 0`);
    params.domain_search = domainSearch;
  }

  if (clientIp) {
    clauses.push(clientIpFilterSql(alias));
    params.client_ip = clientIp;
  }

  if (serverIp) {
    clauses.push(serverIpFilterSql(alias));
    params.server_ip = serverIp;
  }

  return {
    whereSql: clauses.join('\n  AND '),
    params,
    windowSeconds: window.windowSeconds,
    bucketMode: window.bucketMode,
  };
}

function buildActivity5mFilters(filters = {}) {
  const {
    range = '24h',
    from,
    to,
    alias,
  } = filters;
  const window = resolveTimeWindow({ range, from, to, timeCol: 'bucket' });
  const bucketCol = dnsCol('bucket', alias);
  const clauses = [window.whereTime.replace(/\bbucket\b/g, bucketCol)];
  const params = { ...window.params };

  appendSourceFilter(clauses, params, filters, alias);

  return {
    whereSql: clauses.join('\n  AND '),
    params,
    windowSeconds: window.windowSeconds,
    bucketMode: '5m',
  };
}

function buildDomains1hFilters(filters = {}) {
  const {
    range = '24h',
    from,
    to,
    qtype,
    domainSearch,
    alias,
  } = filters;
  const window = resolveTimeWindow({ range, from, to, timeCol: 'hour' });
  const hourCol = dnsCol('hour', alias);
  const clauses = [window.whereTime.replace(/\bhour\b/g, hourCol)];
  const params = { ...window.params };

  appendSourceFilter(clauses, params, filters, alias);

  if (qtype) {
    clauses.push(`${dnsCol('qtype', alias)} = {qtype:String}`);
    params.qtype = qtype;
  }

  if (domainSearch) {
    clauses.push(`positionCaseInsensitive(${dnsCol('query_name', alias)}, {domain_search:String}) > 0`);
    params.domain_search = domainSearch;
  }

  return {
    whereSql: clauses.join('\n  AND '),
    params,
    windowSeconds: window.windowSeconds,
  };
}

function buildClients1hFilters(filters = {}) {
  const {
    range = '24h',
    from,
    to,
    clientIp,
    alias,
  } = filters;
  const window = resolveTimeWindow({ range, from, to, timeCol: 'hour' });
  const hourCol = dnsCol('hour', alias);
  const clauses = [window.whereTime.replace(/\bhour\b/g, hourCol)];
  const params = { ...window.params };

  appendSourceFilter(clauses, params, filters, alias);

  if (clientIp) {
    clauses.push(clientIpFilterSql(alias));
    params.client_ip = clientIp;
  }

  return {
    whereSql: clauses.join('\n  AND '),
    params,
    windowSeconds: window.windowSeconds,
  };
}

function buildServers1hFilters(filters = {}) {
  const {
    range = '24h',
    from,
    to,
    serverIp,
    alias,
  } = filters;
  const window = resolveTimeWindow({ range, from, to, timeCol: 'hour' });
  const hourCol = dnsCol('hour', alias);
  const clauses = [window.whereTime.replace(/\bhour\b/g, hourCol)];
  const params = { ...window.params };

  appendSourceFilter(clauses, params, filters, alias);

  if (serverIp) {
    clauses.push(serverIpFilterSql(alias));
    params.server_ip = serverIp;
  }

  return {
    whereSql: clauses.join('\n  AND '),
    params,
    windowSeconds: window.windowSeconds,
  };
}

function resolveRecentWindow(filters = {}) {
  const usesAgg = dnsUsesAggregates(filters.range, filters.from, filters.to);
  const hasNarrowingFilter = Boolean(filters.clientIp || filters.serverIp || filters.domainSearch);

  if (usesAgg && !hasNarrowingFilter) {
    return {
      range: '30m',
      from: undefined,
      to: undefined,
      forced30m: true,
      recentWindow: '30m',
    };
  }

  return {
    range: filters.range,
    from: filters.from,
    to: filters.to,
    forced30m: false,
    recentWindow: filters.range === 'custom' ? 'custom' : filters.range,
  };
}

function dnsMeta(filters, extra = {}) {
  const usesAgg = dnsUsesAggregates(filters.range, filters.from, filters.to);
  const raw = buildRawDnsFilters(filters);
  return {
    range: filters.range,
    from: filters.from,
    to: filters.to,
    windowSeconds: raw.windowSeconds,
    bucketMode: usesAgg ? '5m' : raw.bucketMode,
    dataTier: extra.dataTier || (usesAgg ? 'aggregate' : 'raw'),
    ...extra,
  };
}

function dnsSources() {
  return {
    sql: `
      SELECT
        source_id,
        display_name,
        collector_id,
        location
      FROM ${sourcesTableRef()}
      WHERE source_type = 'dns'
      ORDER BY display_name
    `,
    params: {},
    map(rows) {
      return rows.map((r) => ({
        sourceId: String(r.source_id),
        displayName: String(r.display_name || r.source_id),
        collectorId: r.collector_id != null ? String(r.collector_id) : null,
        location: r.location != null ? String(r.location) : null,
      }));
    },
  };
}

function dnsActivityChart(filters = {}) {
  const usesAgg = dnsUsesAggregates(filters.range, filters.from, filters.to);

  if (!usesAgg) {
    const { whereSql, params, bucketMode } = buildRawDnsFilters(filters);
    const bucket = dnsBucketExpr(bucketMode);
    const bucketSec = dnsBucketSeconds(bucketMode);

    return {
      sql: `
        SELECT
          ${bucket} AS bucket,
          toUnixTimestamp(${bucket}) AS bucket_ts,
          countIf(is_response = 0) AS queries,
          countIf(is_response = 1) AS responses,
          countIf(is_response = 1 AND rcode = 3) AS nxdomain,
          countIf(is_response = 1 AND rcode = 2) AS servfail,
          round(queries / ${bucketSec}, 2) AS qps,
          round(responses / ${bucketSec}, 2) AS responses_per_sec,
          round(nxdomain / ${bucketSec}, 2) AS nxdomain_per_sec,
          round(servfail / ${bucketSec}, 2) AS servfail_per_sec
        FROM ${dnsLogTableRef()}
        WHERE ${whereSql}
        GROUP BY bucket
        ORDER BY bucket
      `,
      params,
      meta: dnsMeta(filters, { dataTable: config.dnsLogTable, dataTier: 'raw' }),
      map(rows) {
        return rows.map((r) => ({
          bucket: normalizeChBucketString(r.bucket),
          bucketMs: Number(r.bucket_ts) * 1000,
          queries: Number(r.queries) || 0,
          responses: Number(r.responses) || 0,
          nxdomain: Number(r.nxdomain) || 0,
          servfail: Number(r.servfail) || 0,
          qps: Number(r.qps) || 0,
          responsesPerSec: Number(r.responses_per_sec) || 0,
          nxdomainPerSec: Number(r.nxdomain_per_sec) || 0,
          servfailPerSec: Number(r.servfail_per_sec) || 0,
        }));
      },
    };
  }

  const { whereSql, params } = buildActivity5mFilters(filters);
  const bucketSec = 300;

  return {
    sql: `
      SELECT
        bucket,
        bucket_ts,
        queries,
        responses,
        nxdomain,
        servfail,
        round(queries / ${bucketSec}, 2) AS qps,
        round(responses / ${bucketSec}, 2) AS responses_per_sec,
        round(nxdomain / ${bucketSec}, 2) AS nxdomain_per_sec,
        round(servfail / ${bucketSec}, 2) AS servfail_per_sec
      FROM (
        SELECT
          bucket,
          toUnixTimestamp(bucket) AS bucket_ts,
          sum(queries) AS queries,
          sum(responses) AS responses,
          sum(nxdomain) AS nxdomain,
          sum(servfail) AS servfail
        FROM ${dnsActivity5mTableRef()}
        WHERE ${whereSql}
        GROUP BY bucket
      )
      ORDER BY bucket
    `,
    params,
    meta: dnsMeta(filters, { dataTable: config.dnsActivity5mTable, dataTier: 'aggregate' }),
    map(rows) {
      return rows.map((r) => ({
        bucket: normalizeChBucketString(r.bucket),
        bucketMs: Number(r.bucket_ts) * 1000,
        queries: Number(r.queries) || 0,
        responses: Number(r.responses) || 0,
        nxdomain: Number(r.nxdomain) || 0,
        servfail: Number(r.servfail) || 0,
        qps: Number(r.qps) || 0,
        responsesPerSec: Number(r.responses_per_sec) || 0,
        nxdomainPerSec: Number(r.nxdomain_per_sec) || 0,
        servfailPerSec: Number(r.servfail_per_sec) || 0,
      }));
    },
  };
}

function dnsTopDomains(filters = {}, limit = 50) {
  const usesAgg = dnsUsesAggregates(filters.range, filters.from, filters.to);
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);

  if (!usesAgg) {
    const { whereSql, params } = buildRawDnsFilters(filters);

    return {
      sql: `
        SELECT
          query_name,
          qtype,
          countIf(is_response = 0) AS queries,
          countIf(is_response = 1) AS responses,
          countIf(is_response = 1 AND rcode = 3) AS nxdomain,
          countIf(is_response = 1 AND rcode = 2) AS servfail,
          round(servfail * 100.0 / nullIf(responses, 0), 2) AS error_percent
        FROM ${dnsLogTableRef()}
        WHERE ${whereSql}
        GROUP BY query_name, qtype
        ORDER BY queries DESC
        LIMIT {limit:UInt32}
      `,
      params: { ...params, limit: lim },
      meta: dnsMeta(filters, { limit: lim, dataTable: config.dnsLogTable, dataTier: 'raw' }),
      map(rows) {
        return rows.map((r) => ({
          queryName: String(r.query_name || ''),
          qtype: String(r.qtype || ''),
          queries: Number(r.queries) || 0,
          responses: Number(r.responses) || 0,
          nxdomain: Number(r.nxdomain) || 0,
          servfail: Number(r.servfail) || 0,
          errorPercent: Number(r.error_percent) || 0,
        }));
      },
    };
  }

  const { whereSql, params } = buildDomains1hFilters(filters);

  return {
    sql: `
      SELECT
        query_name,
        qtype,
        queries,
        responses,
        nxdomain,
        servfail,
        round(servfail * 100.0 / nullIf(responses, 0), 2) AS error_percent
      FROM (
        SELECT
          query_name,
          qtype,
          sum(queries) AS queries,
          sum(responses) AS responses,
          sum(nxdomain) AS nxdomain,
          sum(servfail) AS servfail
        FROM ${dnsDomains1hTableRef()}
        WHERE ${whereSql}
        GROUP BY query_name, qtype
      )
      ORDER BY queries DESC
      LIMIT {limit:UInt32}
    `,
    params: { ...params, limit: lim },
    meta: dnsMeta(filters, { limit: lim, dataTable: config.dnsDomains1hTable, dataTier: 'aggregate' }),
    map(rows) {
      return rows.map((r) => ({
        queryName: String(r.query_name || ''),
        qtype: String(r.qtype || ''),
        queries: Number(r.queries) || 0,
        responses: Number(r.responses) || 0,
        nxdomain: Number(r.nxdomain) || 0,
        servfail: Number(r.servfail) || 0,
        errorPercent: Number(r.error_percent) || 0,
      }));
    },
  };
}

function dnsTopClients(filters = {}, limit = 50) {
  const usesAgg = dnsUsesAggregates(filters.range, filters.from, filters.to);
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const clientExpr = dnsIpExpr('client_ip');
  const hideResolvers = filters.hideResolvers === false ? 0 : 1;

  if (!usesAgg) {
    const { whereSql, params } = buildRawDnsFilters(filters);

    return {
      sql: `
        WITH aggregated AS (
          SELECT
            ${clientExpr} AS client,
            countIf(is_response = 0) AS queries,
            uniqExact(query_name) AS unique_domains,
            countIf(is_response = 1 AND rcode = 3) AS nxdomain,
            countIf(is_response = 1 AND rcode = 2) AS servfail,
            round(servfail * 100.0 / nullIf(countIf(is_response = 1), 0), 2) AS error_percent
          FROM ${dnsLogTableRef()}
          WHERE ${whereSql}
          GROUP BY client
        ),
        ${dnsBadgeCtes('aggregated', 'client')}
        SELECT
          a.client,
          a.queries,
          a.unique_domains,
          a.nxdomain,
          a.servfail,
          a.error_percent,
          ${dnsBadgeSelectSql()}
        FROM aggregated AS a
        ${dnsBadgeJoinSql('a', 'client')}
        WHERE ${hideResolversWhereSql()}
        ORDER BY a.queries DESC
        LIMIT {limit:UInt32}
      `,
      params: { ...params, limit: lim, hide_resolvers: hideResolvers },
      meta: dnsMeta(filters, { limit: lim, dataTable: config.dnsLogTable, dataTier: 'raw' }),
      map(rows) {
        return rows.map((r) => ({
          client: String(r.client || ''),
          queries: Number(r.queries) || 0,
          uniqueDomains: Number(r.unique_domains) || 0,
          nxdomain: Number(r.nxdomain) || 0,
          servfail: Number(r.servfail) || 0,
          errorPercent: Number(r.error_percent) || 0,
          ...mapIpBadgeFields(r),
        }));
      },
    };
  }

  const { whereSql, params } = buildClients1hFilters(filters);

  return {
    sql: `
      WITH aggregated AS (
        SELECT
          client,
          queries,
          unique_domains,
          nxdomain,
          servfail,
          round(servfail * 100.0 / nullIf(responses, 0), 2) AS error_percent
        FROM (
          SELECT
            ${clientExpr} AS client,
            sum(queries) AS queries,
            sum(responses) AS responses,
            uniqCombinedMerge(unique_domains_state) AS unique_domains,
            sum(nxdomain) AS nxdomain,
            sum(servfail) AS servfail
          FROM ${dnsClients1hTableRef()}
          WHERE ${whereSql}
          GROUP BY client
        )
      ),
      ${dnsBadgeCtes('aggregated', 'client')}
      SELECT
        a.client,
        a.queries,
        a.unique_domains,
        a.nxdomain,
        a.servfail,
        a.error_percent,
        ${dnsBadgeSelectSql()}
      FROM aggregated AS a
      ${dnsBadgeJoinSql('a', 'client')}
      WHERE ${hideResolversWhereSql()}
      ORDER BY a.queries DESC
      LIMIT {limit:UInt32}
    `,
    params: { ...params, limit: lim, hide_resolvers: hideResolvers },
    meta: dnsMeta(filters, { limit: lim, dataTable: config.dnsClients1hTable, dataTier: 'aggregate' }),
    map(rows) {
      return rows.map((r) => ({
        client: String(r.client || ''),
        queries: Number(r.queries) || 0,
        uniqueDomains: Number(r.unique_domains) || 0,
        nxdomain: Number(r.nxdomain) || 0,
        servfail: Number(r.servfail) || 0,
        errorPercent: Number(r.error_percent) || 0,
        ...mapIpBadgeFields(r),
      }));
    },
  };
}

function dnsTopServers(filters = {}, limit = 50) {
  const usesAgg = dnsUsesAggregates(filters.range, filters.from, filters.to);
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const serverExpr = dnsIpExpr('server_ip');

  if (!usesAgg) {
    const { whereSql, params } = buildRawDnsFilters(filters);

    return {
      sql: `
        WITH aggregated AS (
          SELECT
            ${serverExpr} AS server,
            countIf(is_response = 0) AS queries,
            countIf(is_response = 1) AS responses,
            countIf(is_response = 1 AND rcode = 3) AS nxdomain,
            countIf(is_response = 1 AND rcode = 2) AS servfail,
            round(servfail * 100.0 / nullIf(responses, 0), 2) AS error_percent
          FROM ${dnsLogTableRef()}
          WHERE ${whereSql}
          GROUP BY server
        ),
        ${dnsBadgeCtes('aggregated', 'server')}
        SELECT
          a.server,
          a.queries,
          a.responses,
          a.nxdomain,
          a.servfail,
          a.error_percent,
          ${dnsBadgeSelectSql()}
        FROM aggregated AS a
        ${dnsBadgeJoinSql('a', 'server')}
        ORDER BY a.queries DESC
        LIMIT {limit:UInt32}
      `,
      params: { ...params, limit: lim },
      meta: dnsMeta(filters, { limit: lim, dataTable: config.dnsLogTable, dataTier: 'raw' }),
      map(rows) {
        return rows.map((r) => ({
          server: String(r.server || ''),
          queries: Number(r.queries) || 0,
          responses: Number(r.responses) || 0,
          nxdomain: Number(r.nxdomain) || 0,
          servfail: Number(r.servfail) || 0,
          errorPercent: Number(r.error_percent) || 0,
          ...mapIpBadgeFields(r),
        }));
      },
    };
  }

  const { whereSql, params } = buildServers1hFilters(filters);

  return {
    sql: `
      WITH aggregated AS (
        SELECT
          server,
          queries,
          responses,
          nxdomain,
          servfail,
          round(servfail * 100.0 / nullIf(responses, 0), 2) AS error_percent
        FROM (
          SELECT
            ${serverExpr} AS server,
            sum(queries) AS queries,
            sum(responses) AS responses,
            sum(nxdomain) AS nxdomain,
            sum(servfail) AS servfail
          FROM ${dnsServers1hTableRef()}
          WHERE ${whereSql}
          GROUP BY server
        )
      ),
      ${dnsBadgeCtes('aggregated', 'server')}
      SELECT
        a.server,
        a.queries,
        a.responses,
        a.nxdomain,
        a.servfail,
        a.error_percent,
        ${dnsBadgeSelectSql()}
      FROM aggregated AS a
      ${dnsBadgeJoinSql('a', 'server')}
      ORDER BY a.queries DESC
      LIMIT {limit:UInt32}
    `,
    params: { ...params, limit: lim },
    meta: dnsMeta(filters, { limit: lim, dataTable: config.dnsServers1hTable, dataTier: 'aggregate' }),
    map(rows) {
      return rows.map((r) => ({
        server: String(r.server || ''),
        queries: Number(r.queries) || 0,
        responses: Number(r.responses) || 0,
        nxdomain: Number(r.nxdomain) || 0,
        servfail: Number(r.servfail) || 0,
        errorPercent: Number(r.error_percent) || 0,
        ...mapIpBadgeFields(r),
      }));
    },
  };
}

function formatRcodeLabel(rcode) {
  const n = Number(rcode);
  return RCODE_LABELS[n] ?? String(rcode);
}

function formatRcodeHumanLabel(rcode) {
  const n = Number(rcode);
  if (n === 0) return 'Успешно';
  if (n === 2) return 'Ошибка DNS-сервера';
  if (n === 3) return 'Домен не найден';
  return 'Другой код';
}

function formatRcodeHumanTitle(rcode) {
  const n = Number(rcode);
  const tech = formatRcodeLabel(rcode);
  if (n === 0) return `Успешно (${tech})`;
  if (n === 2) return `Ошибка DNS-сервера (${tech})`;
  if (n === 3) return `Домен не найден (${tech})`;
  return `${formatRcodeHumanLabel(rcode)} (${tech})`;
}

function dnsRecent(filters = {}, limit = 50) {
  const { whereSql, params } = buildRawDnsFilters({ ...filters, alias: 'd' });
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 500);
  const clientExpr = dnsIpExpr('d.client_ip');
  const serverExpr = dnsIpExpr('d.server_ip');

  return {
    sql: `
      WITH recent_rows AS (
        SELECT
          toString(d.ts) AS event_time,
          d.source_id,
          ${clientExpr} AS client,
          ${serverExpr} AS server,
          if(d.is_response = 1, 'response', 'query') AS event_type,
          d.query_name,
          d.qtype,
          d.rcode,
          d.answers_cname,
          arrayMap(x -> toString(toIPv4(reinterpretAsUInt32(reverse(substring(x, 1, 4))))), d.answers_a) AS answers_a,
          arrayMap(x -> IPv6NumToString(x), d.answers_aaaa) AS answers_aaaa,
          d.raw_size
        FROM ${dnsLogTableRef()} AS d
        WHERE ${whereSql}
        ORDER BY d.ts DESC
        LIMIT {limit:UInt32}
      ),
      ${dnsRecentBadgeCtes()}
      SELECT
        r.event_time,
        r.source_id,
        r.client,
        r.server,
        r.event_type,
        r.query_name,
        r.qtype,
        r.rcode,
        r.answers_cname,
        r.answers_a,
        r.answers_aaaa,
        r.raw_size,
        crb.resolver_role AS client_resolver_role,
        crb.resolver_label AS client_resolver_label,
        ci.ip IS NULL AS client_is_external,
        srb.resolver_role AS server_resolver_role,
        srb.resolver_label AS server_resolver_label,
        si.ip IS NULL AS server_is_external
      FROM recent_rows AS r
      LEFT JOIN client_resolver_badges AS crb ON r.client = crb.ip
      LEFT JOIN client_internal_ips AS ci ON r.client = ci.ip
      LEFT JOIN server_resolver_badges AS srb ON r.server = srb.ip
      LEFT JOIN server_internal_ips AS si ON r.server = si.ip
      ORDER BY r.event_time DESC
    `,
    params: { ...params, limit: lim },
    meta: dnsMeta(filters, {
      limit: lim,
      dataTable: config.dnsLogTable,
      dataTier: 'raw',
    }),
    map(rows) {
      return rows.map((r) => ({
        eventTime: String(r.event_time || ''),
        sourceId: String(r.source_id || ''),
        client: String(r.client || ''),
        server: String(r.server || ''),
        eventType: String(r.event_type || ''),
        queryName: String(r.query_name || ''),
        qtype: String(r.qtype || ''),
        rcode: Number(r.rcode),
        rcodeLabel: formatRcodeHumanLabel(r.rcode),
        rcodeTitle: formatRcodeHumanTitle(r.rcode),
        answersA: Array.isArray(r.answers_a) ? r.answers_a.map(String) : [],
        answersAaaa: Array.isArray(r.answers_aaaa) ? r.answers_aaaa.map(String) : [],
        answersCname: Array.isArray(r.answers_cname) ? r.answers_cname.map(String) : [],
        rawSize: Number(r.raw_size) || 0,
        clientBadges: mapIpBadgeFields(r, 'client'),
        serverBadges: mapIpBadgeFields(r, 'server'),
      }));
    },
  };
}

function dnsQtypes(filters = {}) {
  const usesAgg = dnsUsesAggregates(filters.range, filters.from, filters.to);

  if (!usesAgg) {
    const { whereSql, params } = buildRawDnsFilters(filters);

    return {
      sql: `
        SELECT
          qtype,
          count() AS rows
        FROM ${dnsLogTableRef()}
        WHERE ${whereSql}
        GROUP BY qtype
        ORDER BY rows DESC
        LIMIT 50
      `,
      params,
      meta: dnsMeta(filters, { dataTable: config.dnsLogTable, dataTier: 'raw' }),
      map(rows) {
        return rows.map((r) => ({
          qtype: String(r.qtype || ''),
          rows: Number(r.rows) || 0,
        }));
      },
    };
  }

  const { whereSql, params } = buildDomains1hFilters(filters);

  return {
    sql: `
      SELECT
        qtype,
        sum(queries) AS rows
      FROM ${dnsDomains1hTableRef()}
      WHERE ${whereSql}
      GROUP BY qtype
      ORDER BY rows DESC
      LIMIT 50
    `,
    params,
    meta: dnsMeta(filters, { dataTable: config.dnsDomains1hTable, dataTier: 'aggregate' }),
    map(rows) {
      return rows.map((r) => ({
        qtype: String(r.qtype || ''),
        rows: Number(r.rows) || 0,
      }));
    },
  };
}

function parseCollectorIdValue(raw) {
  if (raw == null || raw === '') return undefined;
  if (Array.isArray(raw)) {
    const parts = raw.map((v) => String(v).trim()).filter(Boolean);
    return parts.length ? parts.join(',') : undefined;
  }
  const v = String(raw).trim();
  return v || undefined;
}

function parseDnsOverviewQuery(query = {}) {
  const range = String(query.range || '24h');
  const from = query.from ? String(query.from) : undefined;
  const to = query.to ? String(query.to) : undefined;
  const sourceIds = query.source_ids
    ? String(query.source_ids).split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;
  const collectorId = parseCollectorIdValue(query.collector_id);
  const collectorScopes = collectorId ? parseCollectorScopes(collectorId) : undefined;
  const hideResolvers = query.hide_resolvers === '0' || query.hide_resolvers === 'false'
    ? false
    : query.hide_resolvers === '1' || query.hide_resolvers === 'true'
      ? true
      : undefined;
  const limit = query.limit !== undefined ? Number(query.limit) : undefined;

  return {
    range,
    from,
    to,
    sourceIds,
    collectorId,
    collectorScopes,
    hideResolvers,
    limit,
  };
}

function parseDnsFiltersQuery(query = {}) {
  const overview = parseDnsOverviewQuery(query);
  const qtype = query.qtype ? String(query.qtype) : undefined;
  const rcode = query.rcode !== undefined && query.rcode !== ''
    ? Number(query.rcode)
    : undefined;
  const domainSearch = query.domain_search ? String(query.domain_search).trim() : undefined;
  const clientIp = query.client_ip ? String(query.client_ip).trim() : undefined;
  const serverIp = query.server_ip ? String(query.server_ip).trim() : undefined;

  return {
    ...overview,
    qtype: qtype || undefined,
    rcode: Number.isFinite(rcode) ? rcode : undefined,
    domainSearch: domainSearch || undefined,
    clientIp: clientIp || undefined,
    serverIp: serverIp || undefined,
  };
}

module.exports = {
  dnsSources,
  dnsActivityChart,
  dnsTopDomains,
  dnsTopClients,
  dnsTopServers,
  dnsRecent,
  dnsQtypes,
  parseDnsFiltersQuery,
  parseDnsOverviewQuery,
  formatRcodeLabel,
  formatRcodeHumanLabel,
  formatRcodeHumanTitle,
  dnsUsesAggregates,
  buildRawDnsFilters,
  buildActivity5mFilters,
  buildDomains1hFilters,
  buildClients1hFilters,
  buildServers1hFilters,
  resolveRecentWindow,
  dnsIpExpr,
  clientIpFilterSql,
  serverIpFilterSql,
  appendSourceFilter,
  resolveDnsWindow,
  dnsBucketExpr,
  dnsBucketSeconds,
  dnsMeta,
  mapIpBadgeFields,
  dnsResolverLabelSql,
};
