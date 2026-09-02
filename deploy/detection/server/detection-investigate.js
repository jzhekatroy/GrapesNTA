'use strict';

const { query, flowsRawTableRef, netInterfacesCurrentRef, col, flowCol } = require('./clickhouse');
const { flowIpExpr, flowSamplerIpExpr, sflowIfIndexExpr } = require('./queries');
const { formatCh, parseUtc, BASELINE_DAYS } = require('./detection-core');
const { tableRef } = require('./detection-schema');

const HEAVY = {
  max_execution_time: 120,
  max_memory_usage: '8000000000',
};

function utcDateTime(param) {
  return `toDateTime({${param}:String}, 'UTC')`;
}

function protoLabel(code) {
  const n = Number(code);
  if (n === 17) return 'UDP';
  if (n === 6) return 'TCP';
  if (n === 1) return 'ICMP';
  return n ? String(n) : '';
}

function towardSql() {
  return `
    if(
      {scope:String} = 'client',
      f.dst_client = {scopeId:String},
      isIPv4String(${flowIpExpr(`f.${col('dstIp')}`)})
        AND concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4(${flowIpExpr(`f.${col('dstIp')}`)}), 24), 1)), '/24') = {scopeId:String}
    )
  `;
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

function mapShareRow(row, extra = {}, totalBytes = 0) {
  const bytes = Number(row.bytes || 0);
  return {
    ...extra,
    share: totalBytes > 0 ? bytes / totalBytes : Number(row.share || 0),
    gbit: Number(row.gbit || 0),
  };
}

function totalBytes(rows) {
  return rows.reduce((sum, row) => sum + Number(row.bytes || 0), 0);
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

async function investigateIncident({ scope, scopeId, minute }) {
  const minuteTs = parseUtc(minute);
  if (!Number.isFinite(minuteTs)) return emptyInvestigate();
  const from = formatCh(minuteTs);
  const to = formatCh(minuteTs + 60 * 1000);
  const srcIp = flowIpExpr(`f.${col('srcIp')}`);
  const dstIp = flowIpExpr(`f.${col('dstIp')}`);
  const protoCol = `f.${col('proto')}`;
  const srcPort = `f.${col('srcPort')}`;
  const dstPort = `f.${col('dstPort')}`;
  const bytes = `f.${col('bytes')}`;
  const srcAsn = col('srcAsn') ? `f.${col('srcAsn')}` : '0';
  const toward = towardSql();
  const timeFilter = `
    f.date >= toDate(${utcDateTime('from')})
      AND f.date <= toDate(${utcDateTime('to')})
      AND f.time_received_ns >= ${utcDateTime('from')}
      AND f.time_received_ns < ${utcDateTime('to')}
  `;
  const params = { scope: String(scope || 'client'), scopeId: String(scopeId), from, to };
  const opts = { name: 'detection/investigate', clickhouse_settings: HEAVY, requestTimeoutMs: 120000 };
  const flows = flowsRawTableRef();

  const { rows: destRows } = await query(`
    SELECT
      ${dstIp} AS ip,
      ${net24Sql(dstIp)} AS net24,
      ${dstPort} AS port,
      ${protoCol} AS proto,
      sum(${bytes}) AS bytes,
      sum(${bytes}) * 8 / 60 / 1e9 AS gbit
    FROM ${flows} AS f
    WHERE ${timeFilter} AND ${toward}
    GROUP BY ip, net24, port, proto
    ORDER BY bytes DESC
    LIMIT 8
  `, params, { ...opts, name: 'detection/investigate-dst' });

  const { rows: dest24Rows } = await query(`
    SELECT
      ${net24Sql(dstIp)} AS net24,
      sum(${bytes}) AS bytes,
      sum(${bytes}) * 8 / 60 / 1e9 AS gbit,
      uniqExact(${dstIp}) AS ips
    FROM ${flows} AS f
    WHERE ${timeFilter} AND ${toward}
    GROUP BY net24
    ORDER BY bytes DESC
    LIMIT 8
  `, params, { ...opts, name: 'detection/investigate-dst24' });

  const { rows: src24Rows } = await query(`
    SELECT
      ${net24Sql(srcIp)} AS net24,
      any(${srcAsn}) AS asn,
      sum(${bytes}) AS bytes,
      sum(${bytes}) * 8 / 60 / 1e9 AS gbit,
      uniqExact(${srcIp}) AS ips
    FROM ${flows} AS f
    WHERE ${timeFilter} AND ${toward}
    GROUP BY net24
    ORDER BY bytes DESC
    LIMIT 8
  `, params, { ...opts, name: 'detection/investigate-src24' });

  const { rows: srcIpRows } = await query(`
    SELECT
      ${srcIp} AS ip,
      ${net24Sql(srcIp)} AS net24,
      ${srcAsn} AS asn,
      sum(${bytes}) AS bytes,
      sum(${bytes}) * 8 / 60 / 1e9 AS gbit
    FROM ${flows} AS f
    WHERE ${timeFilter} AND ${toward}
    GROUP BY ip, net24, asn
    ORDER BY bytes DESC
    LIMIT 5
  `, params, { ...opts, name: 'detection/investigate-srcip' });

  const { rows: countRows } = await query(`
    SELECT
      uniqExact(${srcIp}) AS src_ips,
      uniqExact(${net24Sql(srcIp)}) AS src_nets,
      uniqExact(${dstIp}) AS dst_ips,
      uniqExact(${net24Sql(dstIp)}) AS dst_nets,
      sum(${bytes}) AS bytes
    FROM ${flows} AS f
    WHERE ${timeFilter} AND ${toward}
  `, params, { ...opts, name: 'detection/investigate-counts' });

  const { rows: l4Rows } = await query(`
    SELECT
      ${srcPort} AS port,
      ${protoCol} AS proto,
      sum(${bytes}) AS bytes,
      sum(${bytes}) * 8 / 60 / 1e9 AS gbit
    FROM ${flows} AS f
    WHERE ${timeFilter} AND ${toward}
    GROUP BY port, proto
    ORDER BY bytes DESC
    LIMIT 8
  `, params, { ...opts, name: 'detection/investigate-l4src' });

  const samplerCol = flowCol('samplerAddress') || 'sampler_address';
  const inIfCol = flowCol('inIf') || 'in_if';
  const outIfCol = flowCol('outIf') || 'out_if';
  const switchIp = flowSamplerIpExpr(`f.${samplerCol}`);
  const inIdx = sflowIfIndexExpr(`f.${inIfCol}`);
  const outIdx = sflowIfIndexExpr(`f.${outIfCol}`);
  const ifaces = netInterfacesCurrentRef();

  const { rows: inRows } = await query(`
    SELECT
      ${switchIp} AS switch_ip,
      ${inIdx} AS if_index,
      ifNull(nullIf(i.if_name, ''), '') AS if_name,
      ifNull(nullIf(i.if_alias, ''), '') AS if_alias,
      sum(${bytes}) AS bytes,
      sum(${bytes}) * 8 / 60 / 1e9 AS gbit
    FROM ${flows} AS f
    LEFT JOIN ${ifaces} AS i
      ON i.switch_ip = ${switchIp} AND i.if_index = ${inIdx}
    WHERE ${timeFilter} AND ${toward}
    GROUP BY switch_ip, if_index, if_name, if_alias
    ORDER BY gbit DESC
    LIMIT 3
  `, params, { ...opts, name: 'detection/investigate-switch-in' });

  const { rows: outRows } = await query(`
    SELECT
      ${switchIp} AS switch_ip,
      ${outIdx} AS if_index,
      ifNull(nullIf(i.if_name, ''), '') AS if_name,
      ifNull(nullIf(i.if_alias, ''), '') AS if_alias,
      sum(${bytes}) AS bytes,
      sum(${bytes}) * 8 / 60 / 1e9 AS gbit
    FROM ${flows} AS f
    LEFT JOIN ${ifaces} AS i
      ON i.switch_ip = ${switchIp} AND i.if_index = ${outIdx}
    WHERE ${timeFilter} AND ${toward}
    GROUP BY switch_ip, if_index, if_name, if_alias
    ORDER BY gbit DESC
    LIMIT 3
  `, params, { ...opts, name: 'detection/investigate-switch-out' });

  const allTotal = Number(countRows[0]?.bytes || 0) || totalBytes(destRows);
  const destTotal = allTotal;
  const dest24Total = allTotal;
  const src24Total = allTotal;
  const srcIpTotal = allTotal;
  const l4Total = allTotal;
  const inTotal = allTotal;
  const outTotal = allTotal;
  const topDest = destRows[0];
  const counts = countRows[0] || {};
  const mapSwitch = (row, total) => {
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
  };

  return {
    victim: topDest ? {
      ip: String(topDest.ip || ''),
      net24: String(topDest.net24 || ''),
      port: Number(topDest.port || 0),
      proto: Number(topDest.proto || 0),
      protoLabel: protoLabel(topDest.proto),
      share: destTotal > 0 ? Number(topDest.bytes || 0) / destTotal : 0,
      gbit: Number(topDest.gbit || 0),
    } : null,
    dest24: dest24Rows.filter((r) => r.net24).map((r) => mapShareRow(r, {
      net24: String(r.net24),
      ips: Number(r.ips || 0),
    }, dest24Total)),
    sources: {
      ipCount: Number(counts.src_ips || 0),
      net24Count: Number(counts.src_nets || 0),
      dstIpCount: Number(counts.dst_ips || 0),
      dstNetCount: Number(counts.dst_nets || 0),
      top: srcIpRows.map((r) => mapShareRow(r, {
        ip: String(r.ip || ''),
        net24: String(r.net24 || ''),
        asn: Number(r.asn || 0) || null,
      }, srcIpTotal)),
    },
    source24: src24Rows.filter((r) => r.net24).map((r) => mapShareRow(r, {
      net24: String(r.net24),
      asn: Number(r.asn || 0) || null,
      ips: Number(r.ips || 0),
    }, src24Total)),
    l4src: l4Rows.map((r) => mapShareRow(r, {
      port: Number(r.port || 0),
      proto: Number(r.proto || 0),
      protoLabel: protoLabel(r.proto),
    }, l4Total)),
    switchIn: mapSwitch(inRows[0], inTotal),
    switchOut: mapSwitch(outRows[0], outTotal),
  };
}

module.exports = {
  loadHourEnvelope,
  investigateIncident,
  emptyInvestigate,
};
