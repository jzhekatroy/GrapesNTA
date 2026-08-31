'use strict';

const {
  query,
  insertRows,
  col,
  flowCol,
  flowsRawTableRef,
  l3PrefixesViewRef,
  clientsViewRef,
} = require('./clickhouse');
const { flowIpExpr } = require('./queries');
const { TABLE, tableRef, ensureDetectionTables } = require('./detection-schema');
const {
  MINUTE,
  EXPORT_LAG,
  BASELINE_DAYS,
  BASELINE_QUANTILE,
  parseUtc,
  formatCh,
  growthRatio,
  minuteMetrics,
} = require('./detection-core');

const HEAVY = {
  max_execution_time: 900,
  max_memory_usage: '16000000000',
  max_bytes_before_external_group_by: '4000000000',
  max_rows_to_read: '0',
  max_bytes_to_read: '0',
};

function utcDateTime(param) {
  return `toDateTime({${param}:String}, 'UTC')`;
}

function utcDateTime64(param) {
  return `toDateTime64({${param}:String}, 9, 'UTC')`;
}

function dstIpSql() {
  return flowIpExpr(col('dstIp'));
}

function srcIpSql() {
  return flowIpExpr(col('srcIp'));
}

function netFromIpSql(ipExpr) {
  return `if(
    isIPv4String(${ipExpr}),
    concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4(${ipExpr}), 24), 1)), '/24'),
    ''
  )`;
}

function prefixToNetSql(prefixExpr) {
  return `if(
    isIPv4String(splitByChar('/', ${prefixExpr})[1]),
    concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4(splitByChar('/', ${prefixExpr})[1]), 24), 1)), '/24'),
    ''
  )`;
}

async function lastClosedMinute() {
  const { rows } = await query(`
    SELECT max(minute) AS m
    FROM default.traffic_client_1m
    WHERE direction = 'in'
      AND minute <= toStartOfMinute(now('UTC') - INTERVAL 4 MINUTE)
  `, {}, { name: 'detection/last-closed-minute' });
  const ts = parseUtc(rows?.[0]?.m);
  return Number.isFinite(ts) && ts > 0 ? ts : null;
}

async function minuteWritten(minuteTs) {
  const { rows } = await query(`
    SELECT count() AS n
    FROM ${tableRef()}
    WHERE minute = ${utcDateTime('m')}
  `, { m: formatCh(minuteTs) }, { name: 'detection/minute-exists' });
  return Number(rows[0]?.n || 0) > 0;
}

async function loadObjects() {
  const { rows: clients } = await query(`
    SELECT client_id, display_name
    FROM ${clientsViewRef()}
  `, {}, { name: 'detection/objects-clients' });

  let netSql = `
    SELECT DISTINCT ${prefixToNetSql('prefix')} AS net
    FROM ${l3PrefixesViewRef()}
    WHERE family = 4 AND ${prefixToNetSql('prefix')} != ''
  `;
  try {
    await query('SELECT 1 FROM default.net_client_prefixes_enabled LIMIT 1', {}, { name: 'detection/prefixes-probe' });
    netSql = `
      SELECT DISTINCT net FROM (
        SELECT ${prefixToNetSql('prefix')} AS net
        FROM ${l3PrefixesViewRef()}
        WHERE family = 4
        UNION ALL
        SELECT ${prefixToNetSql('prefix')} AS net
        FROM default.net_client_prefixes_enabled
      )
      WHERE net != ''
    `;
  } catch {
    // справочник клиентских префиксов может отсутствовать
  }
  const { rows: nets } = await query(netSql, {}, { name: 'detection/objects-nets' });

  return [
    ...clients.map((r) => ({
      scope: 'client',
      scopeId: String(r.client_id),
      name: String(r.display_name || r.client_id),
    })),
    ...nets.map((r) => ({
      scope: 'net',
      scopeId: String(r.net),
      name: String(r.net),
    })),
  ];
}

function emptyRaw() {
  return {
    bytes: 0,
    packets: 0,
    cvN: 0,
    cvSum: 0,
    cvSumSq: 0,
    synAttempts: 0,
    synAnswered: 0,
    synInFlows: 0,
    synHalfOpen: 0,
    synHalfOpenReply: 0,
  };
}

function mapFlagRow(row) {
  return {
    bytes: Number(row.bytes || 0),
    packets: Number(row.packets || 0),
    cvN: Number(row.cv_n || 0),
    cvSum: Number(row.cv_sum || 0),
    cvSumSq: Number(row.cv_sum_sq || 0),
    synAttempts: Number(row.syn_attempts || 0),
    synAnswered: Number(row.syn_answered || 0),
    synInFlows: Number(row.syn_in_flows || 0),
    synHalfOpen: Number(row.syn_half_open || 0),
    synHalfOpenReply: Number(row.syn_half_open_reply || 0),
  };
}

async function loadClientVolume(minuteTs) {
  const { rows } = await query(`
    SELECT
      client_id AS scope_id,
      sum(bytes) AS bytes,
      sum(packets) AS packets
    FROM default.traffic_client_1m
    WHERE direction = 'in' AND minute = ${utcDateTime('m')}
    GROUP BY client_id
  `, { m: formatCh(minuteTs) }, { name: 'detection/client-volume' });
  return new Map(rows.map((r) => [String(r.scope_id), {
    bytes: Number(r.bytes || 0),
    packets: Number(r.packets || 0),
  }]));
}

async function loadScopeFlags(scope, minuteTs) {
  const timeCol = col('time');
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  const protoCol = col('proto');
  const srcIp = col('srcIp');
  const dstIp = col('dstIp');
  const srcPort = col('srcPort');
  const dstPort = col('dstPort');
  const tcpFlags = flowCol('tcpFlags') || '`tcp_flags`';
  const tcp = `f.${protoCol} = 6`;
  const synSet = `bitAnd(f.${tcpFlags}, 2) > 0`;
  const ackSet = `bitAnd(f.${tcpFlags}, 16) > 0`;
  const inDir = `f.direction = 'in'`;
  const outDir = `f.direction = 'out'`;
  const flowAvg = `f.${bytesCol} / f.${packetsCol}`;
  const sessionKey = `if(${inDir},
    (f.${srcIp}, f.${dstIp}, f.${srcPort}, f.${dstPort}),
    (f.${dstIp}, f.${srcIp}, f.${dstPort}, f.${srcPort})
  )`;
  const from = formatCh(minuteTs);
  const to = formatCh(minuteTs + MINUTE);
  const until = formatCh(minuteTs + EXPORT_LAG + MINUTE);

  let scopeExpr;
  let scopeFilter;
  if (scope === 'client') {
    scopeExpr = `if(${inDir}, f.dst_client, f.src_client)`;
    scopeFilter = `((${inDir} AND f.dst_client != '') OR (${outDir} AND f.src_client != ''))`;
  } else {
    const dstNet = netFromIpSql(dstIpSql());
    const srcNet = netFromIpSql(srcIpSql());
    scopeExpr = `if(${inDir}, ${dstNet}, ${srcNet})`;
    scopeFilter = `((${inDir} AND ${dstNet} != '') OR (${outDir} AND ${srcNet} != ''))`;
  }

  const { rows } = await query(`
    SELECT
      ${scopeExpr} AS scope_id,
      sumIf(f.${bytesCol}, ${inDir}) AS bytes,
      sumIf(f.${packetsCol}, ${inDir}) AS packets,
      countIf(${inDir} AND f.${packetsCol} > 0) AS cv_n,
      sumIf(${flowAvg}, ${inDir} AND f.${packetsCol} > 0) AS cv_sum,
      sumIf(pow(${flowAvg}, 2), ${inDir} AND f.${packetsCol} > 0) AS cv_sum_sq,
      uniqIf(${sessionKey}, ${inDir} AND ${tcp} AND ${synSet}) AS syn_attempts,
      uniqIf(${sessionKey}, ${outDir} AND ${tcp} AND ${synSet} AND ${ackSet}) AS syn_answered,
      countIf(${inDir} AND ${tcp} AND ${synSet}) AS syn_in_flows,
      countIf(${inDir} AND ${tcp} AND f.${tcpFlags} = 2) AS syn_half_open,
      countIf(${outDir} AND ${tcp} AND f.${tcpFlags} = 18) AS syn_half_open_reply
    FROM ${flowsRawTableRef()} AS f
    WHERE f.date >= toDate(${utcDateTime64('from')}) - 1
      AND f.date <= toDate(${utcDateTime64('until')})
      AND f.time_flow_start_ns >= ${utcDateTime64('from')}
      AND f.time_flow_start_ns < ${utcDateTime64('to')}
      AND f.${timeCol} >= ${utcDateTime64('from')}
      AND f.${timeCol} < ${utcDateTime64('until')}
      AND ${scopeFilter}
    GROUP BY scope_id
  `, { from, to, until }, { name: `detection/flags-${scope}`, clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });

  return new Map(rows.map((r) => [String(r.scope_id), mapFlagRow(r)]));
}

let clientBaselineCache = { at: 0, map: new Map() };

async function loadClientBaselines() {
  if (Date.now() - clientBaselineCache.at < 6 * 60 * 60 * 1000 && clientBaselineCache.map.size) {
    return clientBaselineCache.map;
  }
  const q = BASELINE_QUANTILE;
  const days = BASELINE_DAYS;
  const map = new Map();
  const { rows: clients } = await query(`
    SELECT
      client_id AS scope_id,
      quantileExact(${q})(bytes * 8 / 60) AS bps,
      quantileExact(${q})(packets / 60) AS pps
    FROM default.traffic_client_1m
    WHERE direction = 'in'
      AND minute >= now('UTC') - INTERVAL {days:UInt16} DAY
      AND minute < now('UTC')
    GROUP BY client_id
  `, { days }, { name: 'detection/baseline-clients', clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });
  for (const r of clients) {
    map.set(`client|${r.scope_id}`, { bps: Number(r.bps || 0), pps: Number(r.pps || 0) });
  }
  clientBaselineCache = { at: Date.now(), map };
  return map;
}

async function loadNetBaselines(beforeTs) {
  const q = BASELINE_QUANTILE;
  const days = BASELINE_DAYS;
  const map = new Map();
  const { rows: nets } = await query(`
    SELECT
      scope_id,
      quantileExact(${q})(bps) AS bps,
      quantileExact(${q})(pps) AS pps
    FROM ${tableRef()}
    WHERE scope = 'net'
      AND minute >= now('UTC') - INTERVAL {days:UInt16} DAY
      AND minute < ${utcDateTime('before')}
    GROUP BY scope_id
  `, { days, before: formatCh(beforeTs) }, { name: 'detection/baseline-nets' });
  for (const r of nets) {
    map.set(`net|${r.scope_id}`, { bps: Number(r.bps || 0), pps: Number(r.pps || 0) });
  }
  return map;
}

async function loadBaselines(beforeTs) {
  const [clients, nets] = await Promise.all([
    loadClientBaselines(),
    loadNetBaselines(beforeTs),
  ]);
  return new Map([...clients, ...nets]);
}

function toInsertRow(object, raw, baseline) {
  const m = minuteMetrics(raw);
  return {
    minute: raw.minute,
    scope: object.scope,
    scope_id: object.scopeId,
    bytes: m.bytes,
    packets: m.packets,
    bps: m.bps,
    pps: m.pps,
    growth_bps: growthRatio(m.bps, baseline?.bps),
    growth_pps: growthRatio(m.pps, baseline?.pps),
    avg_packet_bytes: m.avgPacketBytes,
    cv_percent: m.cvPercent,
    syn_attempts: m.synAttempts,
    syn_answered: m.synAnswered,
    syn_in_flows: m.synInFlows,
    syn_half_open: m.synHalfOpen,
    syn_half_open_reply: m.synHalfOpenReply,
    answer_pct: m.answerPct,
    half_open_pct: m.halfOpenPct,
    half_open_reply_pct: m.halfOpenReplyPct,
  };
}

async function tick() {
  await ensureDetectionTables();
  const closed = await lastClosedMinute();
  if (!closed) return { skipped: 'no_minute' };
  if (await minuteWritten(closed)) return { skipped: 'done', minute: formatCh(closed) };

  const objects = await loadObjects();
  const [clientVol, clientFlags, netFlags, baselines] = await Promise.all([
    loadClientVolume(closed),
    loadScopeFlags('client', closed),
    loadScopeFlags('net', closed),
    loadBaselines(closed),
  ]);

  const minute = formatCh(closed);
  const rows = objects.map((object) => {
    const flags = (object.scope === 'client' ? clientFlags : netFlags).get(object.scopeId) || emptyRaw();
    const volume = object.scope === 'client' ? (clientVol.get(object.scopeId) || null) : null;
    const raw = {
      ...flags,
      minute,
      bytes: volume ? volume.bytes : flags.bytes,
      packets: volume ? volume.packets : flags.packets,
    };
    return toInsertRow(object, raw, baselines.get(`${object.scope}|${object.scopeId}`));
  });

  const chunk = 5000;
  for (let i = 0; i < rows.length; i += chunk) {
    await insertRows(TABLE, rows.slice(i, i + chunk), { name: 'detection/insert-anomaly' });
  }

  return {
    minute,
    clients: objects.filter((o) => o.scope === 'client').length,
    nets: objects.filter((o) => o.scope === 'net').length,
    rows: rows.length,
  };
}

async function loadLatest() {
  await ensureDetectionTables();
  const { rows: latest } = await query(`
    SELECT max(minute) AS m FROM ${tableRef()}
  `, {}, { name: 'detection/latest-minute' });
  const minuteTs = parseUtc(latest[0]?.m);
  if (!Number.isFinite(minuteTs) || minuteTs <= 0) return { minute: null, items: [] };
  const minute = formatCh(minuteTs);

  const { rows } = await query(`
    SELECT
      a.scope,
      a.scope_id,
      a.bps,
      a.pps,
      a.growth_bps,
      a.growth_pps,
      a.avg_packet_bytes,
      a.cv_percent,
      a.syn_attempts,
      a.syn_answered,
      a.syn_in_flows,
      a.syn_half_open,
      a.syn_half_open_reply,
      a.answer_pct,
      a.half_open_pct,
      a.half_open_reply_pct,
      if(a.scope = 'client', ifNull(c.display_name, a.scope_id), a.scope_id) AS name
    FROM ${tableRef()} AS a FINAL
    LEFT JOIN ${clientsViewRef()} AS c ON a.scope = 'client' AND c.client_id = a.scope_id
    WHERE a.minute = ${utcDateTime('m')}
  `, { m: minute }, { name: 'detection/latest-rows' });

  return {
    minute,
    items: rows.map((r) => ({
      scope: r.scope,
      scopeId: r.scope_id,
      name: r.name,
      bps: Number(r.bps || 0),
      pps: Number(r.pps || 0),
      growthBps: r.growth_bps == null ? null : Number(r.growth_bps),
      growthPps: r.growth_pps == null ? null : Number(r.growth_pps),
      avgPacketBytes: Number(r.avg_packet_bytes || 0),
      cvPercent: r.cv_percent == null ? null : Number(r.cv_percent),
      synAttempts: Number(r.syn_attempts || 0),
      synAnswered: Number(r.syn_answered || 0),
      synInFlows: Number(r.syn_in_flows || 0),
      synHalfOpen: Number(r.syn_half_open || 0),
      synHalfOpenReply: Number(r.syn_half_open_reply || 0),
      answerPct: r.answer_pct == null ? null : Number(r.answer_pct),
      halfOpenPct: r.half_open_pct == null ? null : Number(r.half_open_pct),
      halfOpenReplyPct: r.half_open_reply_pct == null ? null : Number(r.half_open_reply_pct),
    })),
  };
}

module.exports = {
  tick,
  loadLatest,
  lastClosedMinute,
};
