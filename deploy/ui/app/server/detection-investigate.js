'use strict';

const { query, flowsRawTableRef, netInterfacesCurrentRef, clientsViewRef, col, flowCol } = require('./clickhouse');
const { flowIpExpr, flowSamplerIpExpr, sflowIfIndexExpr } = require('./queries');
const { formatCh, parseUtc, BASELINE_DAYS, EXPORT_LAG, MINUTE } = require('./detection-core');
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

function net24Sql(ipExpr) {
  return `if(
    isIPv4String(${ipExpr}),
    concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4(${ipExpr}), 24), 1)), '/24'),
    ''
  )`;
}

function emptyInvestigate() {
  return {
    victim: null,
    dest24: [],
    sources: { ipCount: 0, net24Count: 0, top: [] },
    source24: [],
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
    return { p95: null, p999: null };
  }
  const params = {
    scopeId: String(scopeId),
    minute: formatCh(minuteTs),
    days: BASELINE_DAYS,
  };
  if (scope === 'client') {
    const { rows } = await query(`
      SELECT
        quantileExact(0.95)(bytes * 8 / 60) AS p95,
        quantileExact(0.999)(bytes * 8 / 60) AS p999
      FROM default.traffic_client_1m
      WHERE client_id = {scopeId:String}
        AND direction = 'in'
        AND minute >= ${utcDateTime('minute')} - INTERVAL {days:UInt16} DAY
        AND minute < ${utcDateTime('minute')}
        AND toDayOfWeek(minute) = toDayOfWeek(${utcDateTime('minute')})
        AND abs(toInt8(toHour(minute)) - toInt8(toHour(${utcDateTime('minute')}))) <= 1
    `, params, { name: 'detection/hour-envelope-client' });
    return { p95: Number(rows[0]?.p95 || 0) || null, p999: Number(rows[0]?.p999 || 0) || null };
  }
  const { rows } = await query(`
    SELECT
      quantileExact(0.95)(bps) AS p95,
      quantileExact(0.999)(bps) AS p999
    FROM ${tableRef()}
    WHERE scope = 'net'
      AND scope_id = {scopeId:String}
      AND proto = 'all'
      AND minute >= ${utcDateTime('minute')} - INTERVAL {days:UInt16} DAY
      AND minute < ${utcDateTime('minute')}
      AND toDayOfWeek(minute) = toDayOfWeek(${utcDateTime('minute')})
      AND abs(toInt8(toHour(minute)) - toInt8(toHour(${utcDateTime('minute')}))) <= 1
  `, params, { name: 'detection/hour-envelope-net' });
  return { p95: Number(rows[0]?.p95 || 0) || null, p999: Number(rows[0]?.p999 || 0) || null };
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
      isIPv4String(${dstIp})
        AND concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4(${dstIp}), 24), 1)), '/24') = {scopeId:String}
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

  const { rows } = await query(`
    WITH ev AS (${ev}),
    dest AS (
      SELECT dst_ip AS ip, dst24 AS net24, dst_port AS port, proto, sum(bytes) AS bytes
      FROM ev GROUP BY ip, net24, port, proto ORDER BY bytes DESC LIMIT 8
    ),
    dest24 AS (
      SELECT dst24 AS net24, sum(bytes) AS bytes, uniqExact(dst_ip) AS ips
      FROM ev WHERE dst24 != '' GROUP BY net24 ORDER BY bytes DESC LIMIT 8
    ),
    src24 AS (
      SELECT src24 AS net24, any(src_asn) AS asn, sum(bytes) AS bytes, uniqExact(src_ip) AS ips
      FROM ev WHERE src24 != '' GROUP BY net24 ORDER BY bytes DESC LIMIT 8
    ),
    srcip AS (
      SELECT src_ip AS ip, src24 AS net24, src_asn AS asn, sum(bytes) AS bytes
      FROM ev GROUP BY ip, net24, asn ORDER BY bytes DESC LIMIT 5
    ),
    l4 AS (
      SELECT src_port AS port, proto, sum(bytes) AS bytes
      FROM ev GROUP BY port, proto ORDER BY bytes DESC LIMIT 8
    ),
    sw_in AS (
      SELECT switch_ip, in_idx AS if_index, sum(bytes) AS bytes
      FROM ev GROUP BY switch_ip, if_index ORDER BY bytes DESC LIMIT 3
    ),
    sw_out AS (
      SELECT switch_ip, out_idx AS if_index, sum(bytes) AS bytes
      FROM ev GROUP BY switch_ip, if_index ORDER BY bytes DESC LIMIT 3
    ),
    totals AS (
      SELECT
        sum(bytes) AS bytes,
        uniqExact(src_ip) AS src_ips,
        uniqExact(src24) AS src_nets,
        uniqExact(dst_ip) AS dst_ips,
        uniqExact(dst24) AS dst_nets
      FROM ev
    )
    SELECT
      (SELECT bytes FROM totals) AS bytes,
      (SELECT src_ips FROM totals) AS src_ips,
      (SELECT src_nets FROM totals) AS src_nets,
      (SELECT dst_ips FROM totals) AS dst_ips,
      (SELECT dst_nets FROM totals) AS dst_nets,
      (SELECT groupArray(tuple(ip, net24, port, proto, bytes)) FROM dest) AS dests,
      (SELECT groupArray(tuple(net24, bytes, ips)) FROM dest24) AS dest24s,
      (SELECT groupArray(tuple(net24, asn, bytes, ips)) FROM src24) AS src24s,
      (SELECT groupArray(tuple(ip, net24, asn, bytes)) FROM srcip) AS srcips,
      (SELECT groupArray(tuple(port, proto, bytes)) FROM l4) AS l4s,
      (SELECT groupArray(tuple(
          s.switch_ip,
          s.if_index,
          ifNull(nullIf(i.if_name, ''), ''),
          ifNull(nullIf(i.if_alias, ''), ''),
          s.bytes
        ))
        FROM sw_in AS s
        LEFT JOIN ${ifaces} AS i ON i.switch_ip = s.switch_ip AND i.if_index = s.if_index
      ) AS ins,
      (SELECT groupArray(tuple(
          s.switch_ip,
          s.if_index,
          ifNull(nullIf(i.if_name, ''), ''),
          ifNull(nullIf(i.if_alias, ''), ''),
          s.bytes
        ))
        FROM sw_out AS s
        LEFT JOIN ${ifaces} AS i ON i.switch_ip = s.switch_ip AND i.if_index = s.if_index
      ) AS outs
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
      { net24: String(t[0]), asn: Number(t[1] || 0) || null, ips: Number(t[3] || 0) },
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
  loadClientBinding,
  formatClientMarkup,
  investigateIncident,
  emptyInvestigate,
  emptyBinding,
};
