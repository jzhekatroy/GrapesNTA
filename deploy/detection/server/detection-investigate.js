'use strict';

const { query, flowsRawTableRef, netInterfacesCurrentRef, clientsViewRef, col, flowCol, asnNamesTableRef } = require('./clickhouse');
const { flowIpExpr, flowSamplerIpExpr, sflowIfIndexExpr } = require('./queries');
const { AMPLIFIER_PORTS } = require('./detection-signals');
const {
  formatCh, parseUtc, BASELINE_DAYS, BASELINE_QUARANTINE_MINUTES, EXPORT_LAG, MINUTE,
} = require('./detection-core');
const { tableRef } = require('./detection-schema');

const CHEAP = {
  max_execution_time: 30,
  max_memory_usage: '2000000000',
};

function utcDateTime(param) {
  return `toDateTime({${param}:String}, 'UTC')`;
}

function utcDateTime64(param) {
  return `toDateTime64({${param}:String}, 9, 'UTC')`;
}

function protoLabel(code) {
  const n = Number(code);
  if (n === 17) return 'UDP';
  if (n === 6) return 'TCP';
  if (n === 1) return 'ICMP';
  return n ? String(n) : '';
}

// toIPv4OrZero, not toIPv4: ClickHouse evaluates both if() branches for every
// row, so a single IPv6 flow in the slice made the whole investigate throw
// "Cannot parse IPv4" and the alert arrived with an empty "Куда".
function net24Sql(ipExpr) {
  return `if(
    isIPv4String(${ipExpr}),
    concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4OrZero(${ipExpr}), 24), 1)), '/24'),
    ''
  )`;
}

function emptyInvestigate() {
  return {
    victim: null,
    dest24: [],
    sources: { ipCount: 0, net24Count: 0, top: [] },
    source24: [],
    ampDest24: [],
    l4src: [],
    switchIn: null,
    switchOut: null,
  };
}

function emptyBinding() {
  return { bindMode: '', prefixes: [], ports: [] };
}

function mapShareRow(row, extra = {}, totalBytes = 0) {
  const bytes = Number(row.bytes || 0);
  return {
    ...extra,
    share: totalBytes > 0 ? bytes / totalBytes : Number(row.share || 0),
    gbit: Number(row.gbit || 0),
  };
}

async function loadHourEnvelope({ scope, scopeId, minute }) {
  const minuteTs = parseUtc(minute);
  if (!Number.isFinite(minuteTs) || !scopeId) {
    return { p95: null, p999: null, recentMedian: null };
  }
  const params = {
    scopeId: String(scopeId),
    minute: formatCh(minuteTs),
    days: BASELINE_DAYS,
    quarantine: BASELINE_QUARANTINE_MINUTES,
  };
  // Карантинный час всё равно нужен для медианы, поэтому окно остаётся одно, а
  // квантили и медиана берутся условными агрегатами по разным его половинам.
  const cutoff = `${utcDateTime('minute')} - INTERVAL {quarantine:UInt16} MINUTE`;
  const envelope = (rows) => ({
    p95: Number(rows[0]?.p95 || 0) || null,
    p999: Number(rows[0]?.p999 || 0) || null,
    recentMedian: Number(rows[0]?.recent_median || 0) || null,
  });
  if (scope === 'client') {
    const { rows } = await query(`
      SELECT
        quantileExactIf(0.95)(bytes * 8 / 60, minute < ${cutoff}) AS p95,
        quantileExactIf(0.999)(bytes * 8 / 60, minute < ${cutoff}) AS p999,
        quantileExactIf(0.5)(bytes * 8 / 60, minute >= ${cutoff}) AS recent_median
      FROM default.traffic_client_1m
      WHERE client_id = {scopeId:String}
        AND direction = 'in'
        AND minute >= ${utcDateTime('minute')} - INTERVAL {days:UInt16} DAY
        AND minute < ${utcDateTime('minute')}
        AND toDayOfWeek(minute) = toDayOfWeek(${utcDateTime('minute')})
        AND abs(toInt8(toHour(minute)) - toInt8(toHour(${utcDateTime('minute')}))) <= 1
    `, params, { name: 'detection/hour-envelope-client' });
    return envelope(rows);
  }
  const { rows } = await query(`
    SELECT
      quantileExactIf(0.95)(bps, minute < ${cutoff}) AS p95,
      quantileExactIf(0.999)(bps, minute < ${cutoff}) AS p999,
      quantileExactIf(0.5)(bps, minute >= ${cutoff}) AS recent_median
    FROM ${tableRef()}
    WHERE scope = 'net'
      AND scope_id = {scopeId:String}
      AND proto = 'all'
      AND minute >= ${utcDateTime('minute')} - INTERVAL {days:UInt16} DAY
      AND minute < ${utcDateTime('minute')}
      AND toDayOfWeek(minute) = toDayOfWeek(${utcDateTime('minute')})
      AND abs(toInt8(toHour(minute)) - toInt8(toHour(${utcDateTime('minute')}))) <= 1
  `, params, { name: 'detection/hour-envelope-net' });
  return envelope(rows);
}

async function loadForeignEnvelopes(minute) {
  const minuteTs = parseUtc(minute);
  if (!Number.isFinite(minuteTs)) return new Map();
  try {
    const { rows } = await query(`
      SELECT
        client_id,
        quantileExact(0.95)(foreign_bps) AS p95_bps,
        quantileExact(0.95)(foreign_share) AS p95_share
      FROM (
        SELECT
          client_id,
          hour,
          sumIf(bytes, country_code NOT IN ('RU', '??', '')) * 8 / 3600 AS foreign_bps,
          sumIf(bytes, country_code NOT IN ('RU', '??', '')) / nullIf(sum(bytes), 0) AS foreign_share
        FROM default.traffic_client_country_1h
        WHERE direction = 'in'
          AND hour >= ${utcDateTime('minute')} - INTERVAL {days:UInt16} DAY
          AND hour < toStartOfHour(${utcDateTime('minute')})
          AND toDayOfWeek(hour) = toDayOfWeek(${utcDateTime('minute')})
          AND abs(toInt8(toHour(hour)) - toInt8(toHour(${utcDateTime('minute')}))) <= 1
        GROUP BY client_id, hour
      )
      GROUP BY client_id
    `, {
      minute: formatCh(minuteTs),
      days: BASELINE_DAYS,
    }, { name: 'detection/foreign-envelope' });
    const map = new Map();
    for (const row of rows) {
      map.set(String(row.client_id), {
        bpsP95: Number(row.p95_bps || 0) || null,
        shareP95: Number(row.p95_share || 0) || null,
      });
    }
    return map;
  } catch {
    return new Map();
  }
}

async function loadClientBinding(scopeId) {
  const id = String(scopeId || '');
  if (!id) return emptyBinding();
  const opts = { name: 'detection/client-binding', requestTimeoutMs: 8000 };
  try {
    const { rows } = await query(`
      SELECT bind_mode
      FROM ${clientsViewRef()}
      WHERE client_id = {id:String}
      LIMIT 1
    `, { id }, opts);
    const bindMode = String(rows[0]?.bind_mode || '');
    if (bindMode === 'ports') {
      const { rows: ports } = await query(`
        SELECT switch_ip, if_index, comment
        FROM default.net_client_ports_enabled
        WHERE client_id = {id:String}
        LIMIT 4
      `, { id }, { ...opts, name: 'detection/client-ports' });
      return {
        bindMode,
        prefixes: [],
        ports: ports.map((p) => ({
          switchIp: String(p.switch_ip || ''),
          ifIndex: Number(p.if_index || 0),
          comment: String(p.comment || ''),
        })),
      };
    }
    const { rows: prefixes } = await query(`
      SELECT prefix
      FROM default.net_client_prefixes_enabled
      WHERE client_id = {id:String}
      LIMIT 4
    `, { id }, { ...opts, name: 'detection/client-prefixes' });
    return {
      bindMode: bindMode || 'prefixes',
      prefixes: prefixes.map((p) => String(p.prefix || '')).filter(Boolean),
      ports: [],
    };
  } catch {
    return emptyBinding();
  }
}

function formatClientMarkup(binding) {
  if (!binding) return '';
  if (binding.bindMode === 'ports' && binding.ports?.length) {
    return binding.ports.map((p) => {
      const comment = String(p.comment || '').trim();
      if (comment) return `${p.switchIp} · ${comment}`;
      if (p.switchIp && p.ifIndex) return `${p.switchIp} if ${p.ifIndex}`;
      return p.switchIp || '';
    }).filter(Boolean).join('; ');
  }
  if (binding.prefixes?.length) return binding.prefixes.join(', ');
  return '';
}

function towardPred() {
  const dstIp = flowIpExpr(`f.${col('dstIp')}`);
  return `
    if(
      {scope:String} = 'client',
      f.dst_client = {scopeId:String},
      ${net24Sql(dstIp)} = {scopeId:String}
    )
  `;
}

function minuteBounds(minuteTs) {
  return {
    from: formatCh(minuteTs),
    to: formatCh(minuteTs + MINUTE),
    until: formatCh(minuteTs + EXPORT_LAG + MINUTE),
  };
}

function timeFilterSql() {
  const timeCol = col('time');
  return `
    f.date >= toDate(${utcDateTime64('from')}) - 1
      AND f.date <= toDate(${utcDateTime64('until')})
      AND f.time_flow_start_ns >= ${utcDateTime64('from')}
      AND f.time_flow_start_ns < ${utcDateTime64('to')}
      AND f.${timeCol} >= ${utcDateTime64('from')}
      AND f.${timeCol} < ${utcDateTime64('until')}
  `;
}

function evCte() {
  const srcIp = flowIpExpr(`f.${col('srcIp')}`);
  const dstIp = flowIpExpr(`f.${col('dstIp')}`);
  const protoCol = `f.${col('proto')}`;
  const srcPort = `f.${col('srcPort')}`;
  const dstPort = `f.${col('dstPort')}`;
  const bytes = `f.${col('bytes')}`;
  const srcAsn = col('srcAsn') ? `f.${col('srcAsn')}` : '0';
  const samplerCol = flowCol('samplerAddress') || 'sampler_address';
  const inIfCol = flowCol('inIf') || 'in_if';
  const outIfCol = flowCol('outIf') || 'out_if';
  const switchIp = flowSamplerIpExpr(`f.${samplerCol}`);
  const inIdx = sflowIfIndexExpr(`f.${inIfCol}`);
  const outIdx = sflowIfIndexExpr(`f.${outIfCol}`);
  const prewhere = `
    if({scope:String} = 'client', f.dst_client = {scopeId:String}, 1)
  `;
  return `
    SELECT
      ${srcIp} AS src_ip,
      ${dstIp} AS dst_ip,
      ${net24Sql(srcIp)} AS src24,
      ${net24Sql(dstIp)} AS dst24,
      ${srcPort} AS src_port,
      ${dstPort} AS dst_port,
      ${protoCol} AS proto,
      ${srcAsn} AS src_asn,
      ${bytes} AS bytes,
      ${switchIp} AS switch_ip,
      ${inIdx} AS in_idx,
      ${outIdx} AS out_idx
    FROM ${flowsRawTableRef()} AS f
    PREWHERE ${prewhere}
    WHERE ${timeFilterSql()} AND ${towardPred()}
  `;
}

function mapSwitch(row, total) {
  if (!row) return null;
  const ifIndex = Number(row.if_index || 0);
  const ifName = String(row.if_name || '');
  const ifAlias = String(row.if_alias || '');
  const switchAddr = String(row.switch_ip || '');
  if (!ifIndex && !ifName && !switchAddr) return null;
  const mapped = mapShareRow(row, { switchIp: switchAddr, ifIndex, ifName, ifAlias }, total);
  return {
    switchIp: mapped.switchIp,
    ifIndex: mapped.ifIndex,
    ifName: mapped.ifName,
    ifAlias: mapped.ifAlias,
    share: mapped.share,
    gbit: mapped.gbit,
  };
}

/**
 * One PREWHERE on dst_client (or /24), same minute window as detection.
 * Aggregations run on the already-narrow slice — not 8 full-minute scans.
 */
async function investigateIncident({ scope, scopeId, minute }) {
  const minuteTs = parseUtc(minute);
  if (!Number.isFinite(minuteTs)) return emptyInvestigate();
  const bounds = minuteBounds(minuteTs);
  const params = {
    scope: String(scope || 'client'),
    scopeId: String(scopeId),
    ...bounds,
  };
  const opts = { name: 'detection/investigate', clickhouse_settings: CHEAP, requestTimeoutMs: 35000 };
  const ev = evCte();
  const ifaces = netInterfacesCurrentRef();

  // groupArray lives inside each CTE, not around it: 24.8 inlines WITH
  // and otherwise treats sum(bytes) as nested inside the outer aggregate.
  const { rows } = await query(`
    WITH ev AS (${ev}),
    dest AS (
      SELECT groupArray(tuple(ip, net24, port, proto, byte_sum)) AS rows
      FROM (
        SELECT dst_ip AS ip, dst24 AS net24, dst_port AS port, proto, sum(bytes) AS byte_sum
        FROM ev GROUP BY ip, net24, port, proto ORDER BY byte_sum DESC LIMIT 8
      )
    ),
    dest24 AS (
      SELECT groupArray(tuple(net24, byte_sum, ips)) AS rows
      FROM (
        SELECT dst24 AS net24, sum(bytes) AS byte_sum, uniqExact(dst_ip) AS ips
        FROM ev WHERE dst24 != '' GROUP BY net24 ORDER BY byte_sum DESC LIMIT 8
      )
    ),
    amp_ev AS (
      SELECT dst24, dst_ip, bytes
      FROM ev
      WHERE proto = 17 AND src_port IN (${AMPLIFIER_PORTS.join(', ')})
    ),
    amp_tot AS (
      SELECT sum(bytes) AS byte_sum FROM amp_ev
    ),
    amp_dest24 AS (
      SELECT groupArray(tuple(net24, byte_sum, ips)) AS rows
      FROM (
        SELECT dst24 AS net24, sum(bytes) AS byte_sum, uniqExact(dst_ip) AS ips
        FROM amp_ev WHERE dst24 != '' GROUP BY net24 ORDER BY byte_sum DESC LIMIT 5
      )
    ),
    src24 AS (
      SELECT groupArray(tuple(net24, asn, byte_sum, ips, asn_name)) AS rows
      FROM (
        SELECT
          s.net24 AS net24,
          s.asn AS asn,
          s.byte_sum AS byte_sum,
          s.ips AS ips,
          ifNull(nullIf(n.name, ''), '') AS asn_name
        FROM (
          SELECT src24 AS net24, any(src_asn) AS asn, sum(bytes) AS byte_sum, uniqExact(src_ip) AS ips
          FROM ev WHERE src24 != '' GROUP BY net24 ORDER BY byte_sum DESC LIMIT 8
        ) AS s
        LEFT JOIN ${asnNamesTableRef()} AS n ON n.asn = s.asn
      )
    ),
    srcip AS (
      SELECT groupArray(tuple(ip, net24, asn, byte_sum)) AS rows
      FROM (
        SELECT src_ip AS ip, src24 AS net24, src_asn AS asn, sum(bytes) AS byte_sum
        FROM ev GROUP BY ip, net24, asn ORDER BY byte_sum DESC LIMIT 5
      )
    ),
    l4 AS (
      SELECT groupArray(tuple(port, proto, byte_sum)) AS rows
      FROM (
        SELECT src_port AS port, proto, sum(bytes) AS byte_sum
        FROM ev GROUP BY port, proto ORDER BY byte_sum DESC LIMIT 8
      )
    ),
    sw_in AS (
      SELECT groupArray(tuple(switch_ip, if_index, if_name, if_alias, byte_sum)) AS rows
      FROM (
        SELECT
          s.switch_ip,
          s.if_index,
          ifNull(nullIf(i.if_name, ''), '') AS if_name,
          ifNull(nullIf(i.if_alias, ''), '') AS if_alias,
          s.byte_sum
        FROM (
          SELECT switch_ip, in_idx AS if_index, sum(bytes) AS byte_sum
          FROM ev GROUP BY switch_ip, if_index ORDER BY byte_sum DESC LIMIT 3
        ) AS s
        LEFT JOIN ${ifaces} AS i ON i.switch_ip = s.switch_ip AND i.if_index = s.if_index
      )
    ),
    sw_out AS (
      SELECT groupArray(tuple(switch_ip, if_index, if_name, if_alias, byte_sum)) AS rows
      FROM (
        SELECT
          s.switch_ip,
          s.if_index,
          ifNull(nullIf(i.if_name, ''), '') AS if_name,
          ifNull(nullIf(i.if_alias, ''), '') AS if_alias,
          s.byte_sum
        FROM (
          SELECT switch_ip, out_idx AS if_index, sum(bytes) AS byte_sum
          FROM ev GROUP BY switch_ip, if_index ORDER BY byte_sum DESC LIMIT 3
        ) AS s
        LEFT JOIN ${ifaces} AS i ON i.switch_ip = s.switch_ip AND i.if_index = s.if_index
      )
    ),
    totals AS (
      SELECT
        sum(bytes) AS byte_sum,
        uniqExact(src_ip) AS src_ips,
        uniqExact(src24) AS src_nets,
        uniqExact(dst_ip) AS dst_ips,
        uniqExact(dst24) AS dst_nets
      FROM ev
    )
    SELECT
      (SELECT byte_sum FROM totals) AS bytes,
      (SELECT src_ips FROM totals) AS src_ips,
      (SELECT src_nets FROM totals) AS src_nets,
      (SELECT dst_ips FROM totals) AS dst_ips,
      (SELECT dst_nets FROM totals) AS dst_nets,
      (SELECT rows FROM dest) AS dests,
      (SELECT rows FROM dest24) AS dest24s,
      (SELECT rows FROM amp_dest24) AS amp_dest24s,
      (SELECT byte_sum FROM amp_tot) AS amp_bytes,
      (SELECT rows FROM src24) AS src24s,
      (SELECT rows FROM srcip) AS srcips,
      (SELECT rows FROM l4) AS l4s,
      (SELECT rows FROM sw_in) AS ins,
      (SELECT rows FROM sw_out) AS outs
  `, params, opts);

  const row = rows[0] || {};
  const total = Number(row.bytes || 0);
  const toGbit = (bytes) => (Number(bytes || 0) * 8) / 60 / 1e9;
  const asTuples = (value) => {
    if (!Array.isArray(value)) return [];
    return value.map((item) => (Array.isArray(item) ? item : Object.values(item || {})));
  };
  const dests = asTuples(row.dests);
  const topDest = dests[0];
  const dest24s = asTuples(row.dest24s);
  const src24s = asTuples(row.src24s);
  const srcips = asTuples(row.srcips);
  const l4s = asTuples(row.l4s);
  const ins = asTuples(row.ins);
  const outs = asTuples(row.outs);

  const destTuple = (t) => ({
    ip: String(t[0] || ''),
    net24: String(t[1] || ''),
    port: Number(t[2] || 0),
    proto: Number(t[3] || 0),
    bytes: Number(t[4] || 0),
    gbit: toGbit(t[4]),
  });
  const switchTuple = (t) => ({
    switch_ip: String(t[0] || ''),
    if_index: Number(t[1] || 0),
    if_name: String(t[2] || ''),
    if_alias: String(t[3] || ''),
    bytes: Number(t[4] || 0),
    gbit: toGbit(t[4]),
  });

  return {
    victim: topDest ? {
      ...destTuple(topDest),
      protoLabel: protoLabel(topDest[3]),
      share: total > 0 ? Number(topDest[4] || 0) / total : 0,
    } : null,
    dest24: dest24s.filter((t) => t[0]).map((t) => mapShareRow(
      { bytes: t[1], gbit: toGbit(t[1]) },
      { net24: String(t[0]), ips: Number(t[2] || 0) },
      total,
    )),
    ampDest24: asTuples(row.amp_dest24s).filter((t) => t[0]).map((t) => {
      const bytes = Number(t[1] || 0);
      const ampTotal = Number(row.amp_bytes || 0);
      return {
        net24: String(t[0]),
        ips: Number(t[2] || 0),
        bytes,
        bps: bytes * 8 / 60,
        gbit: toGbit(bytes),
        share: ampTotal > 0 ? bytes / ampTotal : 0,
      };
    }),
    sources: {
      ipCount: Number(row.src_ips || 0),
      net24Count: Number(row.src_nets || 0),
      dstIpCount: Number(row.dst_ips || 0),
      dstNetCount: Number(row.dst_nets || 0),
      top: srcips.map((t) => mapShareRow(
        { bytes: t[3], gbit: toGbit(t[3]) },
        { ip: String(t[0] || ''), net24: String(t[1] || ''), asn: Number(t[2] || 0) || null },
        total,
      )),
    },
    source24: src24s.filter((t) => t[0]).map((t) => mapShareRow(
      { bytes: t[2], gbit: toGbit(t[2]) },
      {
        net24: String(t[0]),
        asn: Number(t[1] || 0) || null,
        ips: Number(t[3] || 0),
        asnName: String(t[4] || ''),
      },
      total,
    )),
    l4src: l4s.map((t) => mapShareRow(
      { bytes: t[2], gbit: toGbit(t[2]) },
      { port: Number(t[0] || 0), proto: Number(t[1] || 0), protoLabel: protoLabel(t[1]) },
      total,
    )),
    switchIn: mapSwitch(ins[0] ? switchTuple(ins[0]) : null, total),
    switchOut: mapSwitch(outs[0] ? switchTuple(outs[0]) : null, total),
  };
}

module.exports = {
  loadHourEnvelope,
  loadForeignEnvelopes,
  loadClientBinding,
  formatClientMarkup,
  investigateIncident,
  emptyInvestigate,
  emptyBinding,
};
