const {
  query,
  config,
  col,
  flowCol,
  flowsRawTableRef,
  asnNamesTableRef,
  asnRegistryEnrichedTableRef,
  escapeSqlString,
  parseDataDatetimeSql,
  formatDataDatetimeSql,
} = require('../clickhouse');
const { dnsIpExpr } = require('../dns-queries');
const { flowIpExpr, protoLabel } = require('../queries');

function parseRange(queryParams = {}) {
  const fromRaw = String(queryParams.from || queryParams.range_from || '').trim();
  const toRaw = String(queryParams.to || queryParams.range_to || '').trim();
  const hours = Math.min(Math.max(Number(queryParams.hours) || 24, 1), 24 * 40);

  if (fromRaw && toRaw) {
    return {
      from: fromRaw,
      to: toRaw,
      mode: 'absolute',
    };
  }

  return {
    hours,
    mode: 'relative',
  };
}

function timeFilterSql(column, range) {
  if (range.mode === 'absolute') {
    return {
      sql: `${column} >= ${parseDataDatetimeSql('from')} AND ${column} < ${parseDataDatetimeSql('to')}`,
      params: { from: range.from, to: range.to },
    };
  }
  return {
    sql: `${column} >= now() - INTERVAL {hours:UInt32} HOUR`,
    params: { hours: range.hours },
  };
}

function rowBucketMs(unixSeconds) {
  const ts = Number(unixSeconds);
  return Number.isFinite(ts) && ts > 0 ? ts * 1000 : null;
}

// The hourly vitrines only ever hold closed hours, so the cabinet is behind
// real time by up to an hour plus the rollup lag. Rather than let the UI guess
// that boundary, every hourly endpoint reports the last hour it actually has.
// Asked without a range so an empty range still yields a boundary.
async function lastCompleteHour(table, clientId) {
  const { rows } = await query(
    `SELECT ${formatDataDatetimeSql('max(hour)')} AS data_until FROM default.${table} WHERE client_id = {clientId:String}`,
    { clientId },
    { name: `cabinet/data-until/${table}` },
  );
  const value = rows[0] ? String(rows[0].data_until || '') : '';
  // A client with no rows at all comes back as the epoch rather than as null.
  return value && !value.startsWith('1970') ? value : null;
}

const MINUTE_RETENTION_HOURS = 14 * 24;
const HOUR_RETENTION_HOURS = 180 * 24;
const DAY_RETENTION_HOURS = 730 * 24;
const AUTO_MINUTE_MAX_HOURS = 6;
const AUTO_HOUR_MAX_HOURS = 40 * 24;

function parseGranularity(raw) {
  const value = String(raw || 'auto').trim().toLowerCase();
  if (['auto', 'minute', 'hour', 'day'].includes(value)) return value;
  return 'auto';
}

function rangeSpanHours(range) {
  if (range.mode === 'relative') return Number(range.hours) || 24;
  const fromMs = Date.parse(range.from);
  const toMs = Date.parse(range.to);
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || toMs <= fromMs) return 24;
  return Math.max((toMs - fromMs) / 3600000, 1);
}

function resolveOverviewGranularity(range, requested) {
  const spanHours = rangeSpanHours(range);
  const requestedGranularity = parseGranularity(requested);
  if (requestedGranularity === 'minute') {
    if (spanHours > MINUTE_RETENTION_HOURS) {
      const err = new Error('Минутная детализация доступна не глубже 14 суток');
      err.statusCode = 400;
      throw err;
    }
    return 'minute';
  }
  if (requestedGranularity === 'day') {
    if (spanHours > DAY_RETENTION_HOURS) {
      const err = new Error('Дневная детализация доступна не глубже 730 суток');
      err.statusCode = 400;
      throw err;
    }
    return 'day';
  }
  if (requestedGranularity === 'hour') {
    if (spanHours > HOUR_RETENTION_HOURS) {
      const err = new Error('Часовая детализация доступна не глубже 180 суток');
      err.statusCode = 400;
      throw err;
    }
    return 'hour';
  }
  if (spanHours <= AUTO_MINUTE_MAX_HOURS) return 'minute';
  if (spanHours <= AUTO_HOUR_MAX_HOURS) return 'hour';
  return 'day';
}

function overviewTableForGranularity(granularity) {
  if (granularity === 'minute') return { table: 'traffic_client_1m', bucketColumn: 'minute' };
  if (granularity === 'day') return { table: 'traffic_client_1d', bucketColumn: 'day' };
  return { table: 'traffic_client_1h', bucketColumn: 'hour' };
}

async function lastCompleteBucket(table, bucketColumn, clientId) {
  const { rows } = await query(
    `SELECT ${formatDataDatetimeSql(`max(${bucketColumn})`)} AS data_until FROM default.${table} WHERE client_id = {clientId:String}`,
    { clientId },
    { name: `cabinet/data-until/${table}` },
  );
  const value = rows[0] ? String(rows[0].data_until || '') : '';
  return value && !value.startsWith('1970') ? value : null;
}

async function overviewSeries(clientId, queryParams = {}) {
  const range = parseRange(queryParams);
  const granularity = resolveOverviewGranularity(range, queryParams.granularity);
  const { table, bucketColumn } = overviewTableForGranularity(granularity);
  const filter = timeFilterSql(bucketColumn, range);
  const [{ rows, elapsedMs }, dataUntil] = await Promise.all([query(
    `
      SELECT
        ${formatDataDatetimeSql(bucketColumn)} AS bucket,
        toUnixTimestamp(${bucketColumn}) AS bucket_ts,
        direction,
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows_count) AS flows_count
      FROM default.${table}
      WHERE client_id = {clientId:String}
        AND (${filter.sql})
      GROUP BY ${bucketColumn}, direction
      ORDER BY ${bucketColumn} ASC, direction ASC
    `,
    { clientId, ...filter.params },
    { name: 'cabinet/overview-series' },
  ), lastCompleteBucket(table, bucketColumn, clientId)]);

  const data = rows.map((r) => ({
    bucket: r.bucket,
    hour: r.bucket,
    bucketMs: rowBucketMs(r.bucket_ts),
    direction: String(r.direction),
    bytes: Number(r.bytes) || 0,
    packets: Number(r.packets) || 0,
    flowsCount: Number(r.flows_count) || 0,
  }));

  const totals = data.reduce((acc, row) => {
    if (row.direction === 'in') acc.in += row.bytes;
    if (row.direction === 'out') acc.out += row.bytes;
    return acc;
  }, { in: 0, out: 0 });

  return {
    data,
    meta: {
      elapsedMs,
      rows: rows.length,
      clientId,
      range,
      granularity,
      totals,
      dataUntil,
    },
  };
}

function statsGranularityForRange(range) {
  const spanHours = rangeSpanHours(range);
  if (spanHours <= MINUTE_RETENTION_HOURS) return 'minute';
  if (spanHours <= HOUR_RETENTION_HOURS) return 'hour';
  return 'day';
}

function emptyTrafficStats() {
  return {
    max: {
      in: { bps: 0, pps: 0 },
      out: { bps: 0, pps: 0 },
    },
    avg: {
      in: { bps: 0, pps: 0 },
      out: { bps: 0, pps: 0 },
    },
    volume: {
      in: { gb: 0, tb: 0, packets: 0 },
      out: { gb: 0, tb: 0, packets: 0 },
    },
  };
}

async function overviewStats(clientId, queryParams = {}) {
  const range = parseRange(queryParams);
  const granularity = statsGranularityForRange(range);
  const { table, bucketColumn } = overviewTableForGranularity(granularity);
  const filter = timeFilterSql(bucketColumn, range);
  const bucketSeconds = granularity === 'minute' ? 60 : granularity === 'hour' ? 3600 : 86400;
  const windowSeconds = Math.max(1, rangeSpanHours(range) * 3600);
  const [{ rows, elapsedMs }, dataUntil] = await Promise.all([query(
    `
      SELECT
        direction,
        max(bucket_bytes * 8 / {bucketSeconds:UInt32}) AS max_bps,
        sum(bucket_bytes) * 8 / {windowSeconds:Float64} AS avg_bps,
        max(bucket_packets / {bucketSeconds:UInt32}) AS max_pps,
        sum(bucket_packets) / {windowSeconds:Float64} AS avg_pps,
        sum(bucket_bytes) AS total_bytes,
        sum(bucket_packets) AS total_packets
      FROM
      (
        SELECT
          ${bucketColumn} AS bucket,
          direction,
          sum(bytes) AS bucket_bytes,
          sum(packets) AS bucket_packets
        FROM default.${table}
        WHERE client_id = {clientId:String}
          AND (${filter.sql})
          AND direction IN ('in', 'out')
        GROUP BY bucket, direction
      )
      GROUP BY direction
      ORDER BY direction ASC
    `,
    {
      clientId,
      ...filter.params,
      bucketSeconds,
      windowSeconds,
    },
    { name: 'cabinet/overview-stats' },
  ), lastCompleteBucket(table, bucketColumn, clientId)]);

  const data = emptyTrafficStats();
  for (const row of rows) {
    const direction = String(row.direction);
    if (direction !== 'in' && direction !== 'out') continue;
    const totalBytes = Number(row.total_bytes) || 0;
    data.max[direction] = {
      bps: Number(row.max_bps) || 0,
      pps: Number(row.max_pps) || 0,
    };
    data.avg[direction] = {
      bps: Number(row.avg_bps) || 0,
      pps: Number(row.avg_pps) || 0,
    };
    data.volume[direction] = {
      gb: totalBytes / 1e9,
      tb: totalBytes / 1e12,
      packets: Number(row.total_packets) || 0,
    };
  }

  return {
    data,
    meta: {
      elapsedMs,
      rows: rows.length,
      granularity,
      dataUntil,
    },
  };
}

function geoCountrySql(ipExpr, etypeExpr) {
  const dict = escapeSqlString(config.geoCountryDict);
  const ipv4Expr = `toIPv4(reinterpretAsUInt32(reverse(substring(${ipExpr}, 1, 4))))`;
  const isIpv4 = etypeExpr
    ? `${etypeExpr} = 2048`
    : `length(${ipExpr}) = 16 AND substring(${ipExpr}, 5) = unhex('000000000000000000000000')`;
  return `nullIf(nullIf(upper(if(
    ${isIpv4},
    dictGetString('${dict}', 'cc', tuple(${ipv4Expr})),
    dictGetString('${dict}', 'cc', tuple(${ipExpr}))
  )), ''), '??')`;
}

async function overviewRecentFlows(clientId, queryParams = {}) {
  const limit = Math.min(Math.max(Number(queryParams.limit) || 20, 1), 100);
  const table = flowsRawTableRef();
  const time = col('time');
  const bytes = col('bytes');
  const packets = col('packets');
  const srcIp = col('srcIp');
  const dstIp = col('dstIp');
  const srcPort = col('srcPort');
  const dstPort = col('dstPort');
  const proto = col('proto');
  const srcAsn = col('srcAsn');
  const dstAsn = col('dstAsn');
  const etype = flowCol('etype');
  const srcCountry = geoCountrySql(`f.${srcIp}`, etype ? `f.${etype}` : null);
  const dstCountry = geoCountrySql(`f.${dstIp}`, etype ? `f.${etype}` : null);
  const asnNames = asnNamesTableRef();
  const asnRegistry = asnRegistryEnrichedTableRef();

  const { rows, elapsedMs } = await query(
    `
      SELECT
        recent.*,
        coalesce(nullIf(src_name.name, ''), nullIf(src_registry.name, concat('AS', toString(recent.src_asn))), '') AS src_as_name,
        coalesce(nullIf(dst_name.name, ''), nullIf(dst_registry.name, concat('AS', toString(recent.dst_asn))), '') AS dst_as_name
      FROM
      (
        SELECT
          ${formatDataDatetimeSql(`f.${time}`)} AS ts,
          ${flowIpExpr(`f.${srcIp}`)} AS src_ip,
          ${flowIpExpr(`f.${dstIp}`)} AS dst_ip,
          f.${srcPort} AS src_port,
          f.${dstPort} AS dst_port,
          f.${proto} AS proto,
          f.${bytes} AS bytes,
          f.${packets} AS packets,
          f.${srcAsn} AS src_asn,
          f.${dstAsn} AS dst_asn,
          ${srcCountry} AS src_country,
          ${dstCountry} AS dst_country,
          multiIf(
            f.src_client = {clientId:String} AND f.dst_client = {clientId:String}, 'both',
            f.src_client = {clientId:String}, 'src',
            'dst'
          ) AS client_side
        FROM ${table} AS f
        PREWHERE f.date >= today() - 1
        WHERE (f.src_client = {clientId:String} OR f.dst_client = {clientId:String})
        ORDER BY f.${time} DESC
        LIMIT {limit:UInt32}
      ) AS recent
      LEFT JOIN ${asnNames} AS src_name ON src_name.asn = recent.src_asn AND recent.src_asn > 0
      LEFT JOIN ${asnNames} AS dst_name ON dst_name.asn = recent.dst_asn AND recent.dst_asn > 0
      LEFT JOIN ${asnRegistry} AS src_registry ON src_registry.asn = recent.src_asn AND recent.src_asn > 0
      LEFT JOIN ${asnRegistry} AS dst_registry ON dst_registry.asn = recent.dst_asn AND recent.dst_asn > 0
      ORDER BY recent.ts DESC
    `,
    { clientId, limit },
    { name: 'cabinet/overview-recent-flows' },
  );

  return {
    data: rows.map((row) => ({
      ts: row.ts,
      srcIp: String(row.src_ip || ''),
      dstIp: String(row.dst_ip || ''),
      srcPort: Number(row.src_port) || 0,
      dstPort: Number(row.dst_port) || 0,
      proto: protoLabel(row.proto),
      bytes: Number(row.bytes) || 0,
      pkts: Number(row.packets) || 0,
      srcAsn: Number(row.src_asn) || 0,
      dstAsn: Number(row.dst_asn) || 0,
      srcAsName: String(row.src_as_name || '').trim(),
      dstAsName: String(row.dst_as_name || '').trim(),
      srcCountry: String(row.src_country || '').trim(),
      dstCountry: String(row.dst_country || '').trim(),
      clientSide: String(row.client_side || ''),
    })),
    meta: { elapsedMs, rows: rows.length },
  };
}

function breakdownTablesForRange(range) {
  const spanHours = rangeSpanHours(range);
  if (spanHours > AUTO_HOUR_MAX_HOURS) {
    return {
      country: { table: 'traffic_client_country_1d', bucketColumn: 'day' },
      service: { table: 'traffic_client_service_1d', bucketColumn: 'day' },
    };
  }
  return {
    country: { table: 'traffic_client_country_1h', bucketColumn: 'hour' },
    service: { table: 'traffic_client_service_1h', bucketColumn: 'hour' },
  };
}

async function queryBreakdownTotalBytes(table, bucketColumn, clientId, range, direction) {
  const filter = timeFilterSql(bucketColumn, range);
  const params = { clientId, ...filter.params };
  let directionFilter = '';
  if (direction) {
    params.direction = String(direction);
    directionFilter = 'AND direction = {direction:String}';
  }
  const { rows } = await query(
    `
      SELECT sum(bytes) AS bytes
      FROM default.${table}
      WHERE client_id = {clientId:String}
        AND (${filter.sql})
        ${directionFilter}
    `,
    params,
    { name: `cabinet/overview-total/${table}` },
  );
  return Number(rows[0]?.bytes) || 0;
}

async function overviewCountries(clientId, queryParams = {}) {
  const range = parseRange(queryParams);
  const { table, bucketColumn } = breakdownTablesForRange(range).country;
  const filter = timeFilterSql(bucketColumn, range);
  const direction = String(queryParams.direction || '').trim();
  const limit = Math.min(Math.max(Number(queryParams.limit) || 20, 1), 100);
  const [{ rows, elapsedMs }, dataUntil, totalBytes] = await Promise.all([query(
    `
      SELECT
        country_code,
        direction,
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows_count) AS flows_count
      FROM default.${table}
      WHERE client_id = {clientId:String}
        AND (${filter.sql})
        ${direction ? 'AND direction = {direction:String}' : ''}
      GROUP BY country_code, direction
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `,
    {
      clientId,
      ...filter.params,
      ...(direction ? { direction } : {}),
      limit,
    },
    { name: 'cabinet/overview-countries' },
  ), lastCompleteBucket(table, bucketColumn, clientId),
  queryBreakdownTotalBytes(table, bucketColumn, clientId, range, direction)]);
  return {
    data: rows.map((r) => ({
      countryCode: String(r.country_code),
      direction: String(r.direction),
      bytes: Number(r.bytes) || 0,
      packets: Number(r.packets) || 0,
      flowsCount: Number(r.flows_count) || 0,
    })),
    meta: {
      elapsedMs,
      rows: rows.length,
      clientId,
      range,
      dataUntil,
      totalBytes,
      breakdownGranularity: bucketColumn === 'day' ? 'day' : 'hour',
    },
  };
}

async function overviewServices(clientId, queryParams = {}) {
  const range = parseRange(queryParams);
  const { table, bucketColumn } = breakdownTablesForRange(range).service;
  const filter = timeFilterSql(bucketColumn, range);
  const direction = String(queryParams.direction || '').trim();
  const limit = Math.min(Math.max(Number(queryParams.limit) || 20, 1), 100);
  const [{ rows, elapsedMs }, dataUntil, totalBytes] = await Promise.all([query(
    `
      SELECT
        service_code,
        any(service_name) AS service_name,
        transport,
        category,
        direction,
        service_port,
        port_owner,
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows_count) AS flows_count
      FROM default.${table}
      WHERE client_id = {clientId:String}
        AND (${filter.sql})
        ${direction ? 'AND direction = {direction:String}' : ''}
      GROUP BY service_code, transport, category, direction, service_port, port_owner
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `,
    {
      clientId,
      ...filter.params,
      ...(direction ? { direction } : {}),
      limit,
    },
    { name: 'cabinet/overview-services' },
  ), lastCompleteBucket(table, bucketColumn, clientId),
  queryBreakdownTotalBytes(table, bucketColumn, clientId, range, direction)]);
  return {
    data: rows.map((r) => ({
      serviceCode: String(r.service_code),
      serviceName: String(r.service_name || ''),
      transport: String(r.transport || ''),
      category: String(r.category || ''),
      direction: String(r.direction),
      // Only set when the service dictionary had no name for the traffic:
      // servicePort is the port it ran on and portOwner says whether the client
      // listens on it ('local') or dialled it ('remote').
      servicePort: Number(r.service_port) || 0,
      portOwner: String(r.port_owner || ''),
      bytes: Number(r.bytes) || 0,
      packets: Number(r.packets) || 0,
      flowsCount: Number(r.flows_count) || 0,
    })),
    meta: {
      elapsedMs,
      rows: rows.length,
      clientId,
      range,
      dataUntil,
      totalBytes,
      breakdownGranularity: bucketColumn === 'day' ? 'day' : 'hour',
    },
  };
}

// 'other' is the tail the rollup folded past the client's top domains, and
// 'unknown' a name the public suffix list could not reduce. Neither can be a
// real registrable domain, so the UI can label them without ambiguity.
const FOLDED_DOMAIN = 'other';

// The log stores the name as the resolver sent it, ending in the root dot.
// Nobody types 'ya.ru.' and nobody wants to read it, so the cabinet strips the
// dot on the way out and tolerates it on the way in.
function withoutRootDot(name) {
  const s = String(name || '');
  return s.endsWith('.') ? s.slice(0, -1) : s;
}

// With the root dot in place cutToFirstSignificantSubdomain returns nothing. The
// rollup that fills the vitrine strips it the same way, so the detail filter has
// to match. Kept as a literal rather than trimRight(name, '.'), whose two
// argument form is not in every ClickHouse we run against.
function registrableDomainSql(column) {
  return `cutToFirstSignificantSubdomain(
  if(endsWith(${column}, '.'), substring(${column}, 1, length(${column}) - 1), ${column})
)`;
}

async function dnsDomains(clientId, queryParams = {}) {
  const range = parseRange(queryParams);
  const filter = timeFilterSql('hour', range);
  const sourceId = String(queryParams.sourceId || queryParams.source_id || '').trim();
  const limit = Math.min(Math.max(Number(queryParams.limit) || 20, 1), 100);
  const [{ rows, elapsedMs }, dataUntil] = await Promise.all([query(
    `
      SELECT
        domain,
        sum(queries) AS queries,
        sum(responses) AS responses,
        sum(nxdomain) AS nxdomain,
        sum(servfail) AS servfail
      FROM default.dns_client_domain_1h
      WHERE client_id = {clientId:String}
        AND (${filter.sql})
        ${sourceId ? 'AND source_id = {sourceId:String}' : ''}
      GROUP BY domain
      ORDER BY queries DESC
      LIMIT {limit:UInt32}
    `,
    {
      clientId,
      ...filter.params,
      ...(sourceId ? { sourceId } : {}),
      limit,
    },
    { name: 'cabinet/dns-domains' },
  ), lastCompleteHour('dns_client_domain_1h', clientId)]);
  return {
    data: rows.map((r) => ({
      domain: String(r.domain),
      folded: String(r.domain) === FOLDED_DOMAIN,
      queries: Number(r.queries) || 0,
      responses: Number(r.responses) || 0,
      nxdomain: Number(r.nxdomain) || 0,
      servfail: Number(r.servfail) || 0,
    })),
    // Summing over observation points can double count a query two of them both
    // saw, so a stand with several needs sourceId rather than the total.
    meta: { elapsedMs, rows: rows.length, clientId, range, dataUntil, sourceId: sourceId || null },
  };
}

// The detail list reads the raw log by client_id, never by address: the collector
// tagged each row with whoever owned the address at the time, so a network that
// later moves to another client cannot expose the previous owner's history.
async function dnsQueries(clientId, queryParams = {}) {
  const range = parseRange(queryParams);
  const filter = timeFilterSql('d.ts', range);
  const domain = withoutRootDot(String(queryParams.domain || '').trim());
  const limit = Math.min(Math.max(Number(queryParams.limit) || 100, 1), 1000);
  const { rows, elapsedMs } = await query(
    `
      SELECT
        ${formatDataDatetimeSql('d.ts')} AS ts,
        ${dnsIpExpr('d.client_ip')} AS client_ip,
        ${dnsIpExpr('d.server_ip')} AS server_ip,
        d.query_name,
        d.qtype,
        d.rcode,
        d.is_response,
        d.transport
      FROM default.dns_log AS d
      WHERE d.client_id = {clientId:String}
        AND (${filter.sql})
        ${domain ? `AND ${registrableDomainSql('d.query_name')} = {domain:String}` : ''}
      ORDER BY d.ts DESC
      LIMIT {limit:UInt32}
    `,
    {
      clientId,
      ...filter.params,
      ...(domain ? { domain } : {}),
      limit,
    },
    { name: 'cabinet/dns-queries' },
  );
  return {
    data: rows.map((r) => ({
      ts: r.ts,
      clientIp: String(r.client_ip || ''),
      serverIp: String(r.server_ip || ''),
      queryName: withoutRootDot(r.query_name),
      qtype: String(r.qtype || ''),
      rcode: Number(r.rcode) || 0,
      isResponse: Number(r.is_response) === 1,
      transport: String(r.transport || ''),
    })),
    meta: { elapsedMs, rows: rows.length, clientId, range },
  };
}

module.exports = {
  parseRange,
  parseGranularity,
  resolveOverviewGranularity,
  overviewSeries,
  overviewStats,
  overviewRecentFlows,
  overviewCountries,
  overviewServices,
  dnsDomains,
  dnsQueries,
};
