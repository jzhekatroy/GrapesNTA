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
  MIN_BPS,
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

function logDetection(stage, extra) {
  const payload = extra == null ? '' : ` ${JSON.stringify(extra)}`;
  console.log(new Date().toISOString(), `detection ${stage}${payload}`);
}

function flagStats(map) {
  const rows = [...map.values()];
  const withAttempts = rows.filter((r) => r.synAttempts > 0).length;
  const maxAttempts = rows.reduce((m, r) => Math.max(m, r.synAttempts), 0);
  const maxAnswered = rows.reduce((m, r) => Math.max(m, r.synAnswered), 0);
  const top = [...map.entries()]
    .filter(([, r]) => r.synAttempts > 0)
    .sort((a, b) => b[1].synAttempts - a[1].synAttempts)
    .slice(0, 5)
    .map(([id, r]) => ({ id, attempts: r.synAttempts, answered: r.synAnswered, half: r.synHalfOpen }));
  return { scopes: map.size, withAttempts, maxAttempts, maxAnswered, top };
}

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
    udpPortEntropy: null,
    udpPortEntropyOut: null,
    udpPortsPerIp: null,
    udpPortsPerIpOut: null,
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

// На части коллекторов почти всё в direction=unknown. Рукопожатие
// считаем по стороне объекта (dst = к нему, src = от него), не по in/out.
function scopeSides(scope) {
  if (scope === 'client') {
    return { towardId: 'f.dst_client', fromId: 'f.src_client' };
  }
  return { towardId: netFromIpSql(dstIpSql()), fromId: netFromIpSql(srcIpSql()) };
}

function minuteFilterSql() {
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

function minuteBounds(minuteTs) {
  return {
    from: formatCh(minuteTs),
    to: formatCh(minuteTs + MINUTE),
    until: formatCh(minuteTs + EXPORT_LAG + MINUTE),
  };
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
  const tcp = `e.proto = 6`;
  const synSet = `bitAnd(e.tcp_flags, 2) > 0`;
  const ackSet = `bitAnd(e.tcp_flags, 16) > 0`;
  const flowAvg = `e.bytes / e.packets`;
  const { from, to, until } = minuteBounds(minuteTs);
  const { towardId, fromId } = scopeSides(scope);
  const timeFilter = minuteFilterSql();
  const flowCols = `
    f.${bytesCol} AS bytes,
    f.${packetsCol} AS packets,
    f.${protoCol} AS proto,
    f.${tcpFlags} AS tcp_flags
  `;

  logDetection(`flags-${scope} start`, {
    from,
    to,
    until,
    timeCol,
    tcpFlags,
    flows: flowsRawTableRef(),
  });
  const started = Date.now();
  let result;
  try {
    result = await query(`
    SELECT
      e.scope_id AS scope_id,
      sumIf(e.bytes, e.toward) AS bytes,
      sumIf(e.packets, e.toward) AS packets,
      countIf(e.toward AND e.packets > 0) AS cv_n,
      sumIf(${flowAvg}, e.toward AND e.packets > 0) AS cv_sum,
      sumIf(pow(${flowAvg}, 2), e.toward AND e.packets > 0) AS cv_sum_sq,
      uniqIf(e.sess, e.toward AND ${tcp} AND ${synSet}) AS syn_attempts,
      uniqIf(e.sess, NOT e.toward AND ${tcp} AND ${synSet} AND ${ackSet}) AS syn_answered,
      countIf(e.toward AND ${tcp} AND ${synSet}) AS syn_in_flows,
      countIf(e.toward AND ${tcp} AND e.tcp_flags = 2) AS syn_half_open,
      countIf(NOT e.toward AND ${tcp} AND e.tcp_flags = 18) AS syn_half_open_reply
    FROM (
      SELECT
        ${towardId} AS scope_id,
        1 AS toward,
        (f.${srcIp}, f.${dstIp}, f.${srcPort}, f.${dstPort}) AS sess,
        ${flowCols}
      FROM ${flowsRawTableRef()} AS f
      WHERE ${timeFilter}
        AND ${towardId} != ''
      UNION ALL
      SELECT
        ${fromId} AS scope_id,
        0 AS toward,
        (f.${dstIp}, f.${srcIp}, f.${dstPort}, f.${srcPort}) AS sess,
        ${flowCols}
      FROM ${flowsRawTableRef()} AS f
      WHERE ${timeFilter}
        AND ${fromId} != ''
    ) AS e
    GROUP BY e.scope_id
  `, { from, to, until }, { name: `detection/flags-${scope}`, clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });
  } catch (err) {
    logDetection(`flags-${scope} error`, { ms: Date.now() - started, message: err.message, stack: err.stack });
    throw err;
  }
  const map = new Map(result.rows.map((r) => [String(r.scope_id), mapFlagRow(r)]));
  logDetection(`flags-${scope} done`, { ms: Date.now() - started, ...flagStats(map) });
  return map;
}

function nullableNum(value) {
  return value == null ? null : Number(value);
}

// Энтропия Шеннона по dst_port UDP, вес доли — пакеты, а не число flow.
// Рядом: пик портов на один dst_addr — флуд по случайным портам бьёт в один
// хост, и среднее по адресам его размывает на абонентах с несколькими IP.
async function loadUdpPortMetrics(scope, minuteTs) {
  const packetsCol = col('packets');
  const protoCol = col('proto');
  const dstPort = col('dstPort');
  const dstAddr = dstIpSql();
  const { from, to, until } = minuteBounds(minuteTs);
  const { towardId, fromId } = scopeSides(scope);
  const timeFilter = minuteFilterSql();
  const started = Date.now();

  const { rows } = await query(`
    WITH
      ev AS (
        SELECT
          ${towardId} AS scope_id,
          1 AS side,
          f.${dstPort} AS dst_port,
          ${dstAddr} AS dst_ip,
          f.${packetsCol} AS packets
        FROM ${flowsRawTableRef()} AS f
        WHERE ${timeFilter}
          AND f.${protoCol} = 17
          AND ${towardId} != ''
        UNION ALL
        SELECT
          ${fromId} AS scope_id,
          0 AS side,
          f.${dstPort} AS dst_port,
          ${dstAddr} AS dst_ip,
          f.${packetsCol} AS packets
        FROM ${flowsRawTableRef()} AS f
        WHERE ${timeFilter}
          AND f.${protoCol} = 17
          AND ${fromId} != ''
      ),
      per_port AS (
        SELECT
          scope_id,
          side,
          dst_port,
          sum(packets) AS pkts
        FROM ev
        GROUP BY scope_id, side, dst_port
        HAVING pkts > 0
      ),
      shares AS (
        SELECT
          scope_id,
          side,
          pkts / sum(pkts) OVER (PARTITION BY scope_id, side) AS q
        FROM per_port
      ),
      by_side AS (
        SELECT
          scope_id,
          if(countIf(side = 1) > 0, -sumIf(q * log2(q), side = 1) + 0, NULL) AS udp_port_entropy,
          if(countIf(side = 0) > 0, -sumIf(q * log2(q), side = 0) + 0, NULL) AS udp_port_entropy_out
        FROM shares
        GROUP BY scope_id
      ),
      per_ip AS (
        SELECT
          scope_id,
          side,
          dst_ip,
          uniqExact(dst_port) AS ports
        FROM ev
        WHERE dst_ip != ''
        GROUP BY scope_id, side, dst_ip
      ),
      ip_peak AS (
        SELECT
          scope_id,
          if(countIf(side = 1) > 0, maxIf(ports, side = 1), NULL) AS udp_ports_per_ip,
          if(countIf(side = 0) > 0, maxIf(ports, side = 0), NULL) AS udp_ports_per_ip_out
        FROM per_ip
        GROUP BY scope_id
      )
    SELECT
      s.scope_id AS scope_id,
      s.udp_port_entropy,
      s.udp_port_entropy_out,
      p.udp_ports_per_ip,
      p.udp_ports_per_ip_out
    FROM by_side AS s
    LEFT JOIN ip_peak AS p ON s.scope_id = p.scope_id
  `, { from, to, until }, {
    name: `detection/udp-metrics-${scope}`,
    clickhouse_settings: HEAVY,
    requestTimeoutMs: 180000,
  });

  const map = new Map(rows.map((r) => [String(r.scope_id), {
    udpPortEntropy: nullableNum(r.udp_port_entropy),
    udpPortEntropyOut: nullableNum(r.udp_port_entropy_out),
    udpPortsPerIp: nullableNum(r.udp_ports_per_ip),
    udpPortsPerIpOut: nullableNum(r.udp_ports_per_ip_out),
  }]));
  logDetection(`udp-metrics-${scope} done`, {
    ms: Date.now() - started,
    scopes: map.size,
    maxEntropyIn: [...map.values()].reduce((m, r) => Math.max(m, r.udpPortEntropy || 0), 0).toFixed(2),
    maxPortsPerIpIn: [...map.values()].reduce((m, r) => Math.max(m, r.udpPortsPerIp || 0), 0).toFixed(2),
  });
  return map;
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
    udp_port_entropy: m.udpPortEntropy,
    udp_port_entropy_out: m.udpPortEntropyOut,
    udp_ports_per_ip: m.udpPortsPerIp,
    udp_ports_per_ip_out: m.udpPortsPerIpOut,
  };
}

// Порог MIN_BPS может отсечь все объекты сразу — тогда в таблице минуты нет
// и minuteWritten() навсегда вернёт false. Помним её здесь, чтобы не зациклиться.
let lastProcessedMinute = 0;

async function tick() {
  await ensureDetectionTables();
  const closed = await lastClosedMinute();
  if (!closed) {
    logDetection('skip', { reason: 'no_minute' });
    return { skipped: 'no_minute' };
  }
  const minute = formatCh(closed);
  if (closed <= lastProcessedMinute) {
    logDetection('skip', { reason: 'processed', minute });
    return { skipped: 'processed', minute };
  }
  if (await minuteWritten(closed)) {
    const { rows: written } = await query(`
      SELECT
        count() AS n,
        countIf(syn_attempts > 0) AS with_attempts,
        max(syn_attempts) AS max_attempts
      FROM ${tableRef()}
      WHERE minute = ${utcDateTime('m')}
    `, { m: minute }, { name: 'detection/minute-written-stats' });
    const stats = written[0] || {};
    logDetection('skip', {
      reason: 'done',
      minute,
      rows: Number(stats.n || 0),
      withAttempts: Number(stats.with_attempts || 0),
      maxAttempts: Number(stats.max_attempts || 0),
    });
    return { skipped: 'done', minute, ...stats };
  }

  const objects = await loadObjects();
  logDetection('objects', {
    minute,
    clients: objects.filter((o) => o.scope === 'client').length,
    nets: objects.filter((o) => o.scope === 'net').length,
  });
  const [clientVol, clientFlags, netFlags, clientUdp, netUdp, baselines] = await Promise.all([
    loadClientVolume(closed),
    loadScopeFlags('client', closed),
    loadScopeFlags('net', closed),
    loadUdpPortMetrics('client', closed),
    loadUdpPortMetrics('net', closed),
    loadBaselines(closed),
  ]);

  let matchedFlags = 0;
  let insertedAttempts = 0;
  const missed = [];
  const allRows = objects.map((object) => {
    const flagMap = object.scope === 'client' ? clientFlags : netFlags;
    const flags = flagMap.get(object.scopeId);
    if (flags) {
      matchedFlags += 1;
      if (flags.synAttempts > 0) insertedAttempts += 1;
    } else if (missed.length < 8) {
      missed.push(`${object.scope}:${object.scopeId}`);
    }
    const volume = object.scope === 'client' ? (clientVol.get(object.scopeId) || null) : null;
    const udp = (object.scope === 'client' ? clientUdp : netUdp).get(object.scopeId);
    const raw = {
      ...(flags || emptyRaw()),
      ...(udp || {}),
      minute,
      bytes: volume ? volume.bytes : (flags?.bytes || 0),
      packets: volume ? volume.packets : (flags?.packets || 0),
    };
    return toInsertRow(object, raw, baselines.get(`${object.scope}|${object.scopeId}`));
  });

  const rows = allRows.filter((r) => r.bps >= MIN_BPS);

  const chunk = 5000;
  for (let i = 0; i < rows.length; i += chunk) {
    await insertRows(TABLE, rows.slice(i, i + chunk), { name: 'detection/insert-anomaly' });
  }
  lastProcessedMinute = closed;

  const out = {
    minute,
    clients: objects.filter((o) => o.scope === 'client').length,
    nets: objects.filter((o) => o.scope === 'net').length,
    rows: rows.length,
    skippedBelowMinBps: allRows.length - rows.length,
    minBpsMbit: Math.round(MIN_BPS / 1e6),
    flagRows: clientFlags.size + netFlags.size,
    matchedFlags,
    insertedWithAttempts: insertedAttempts,
    maxAttempts: rows.reduce((m, r) => Math.max(m, r.syn_attempts), 0),
    missedSample: missed,
  };
  logDetection('insert', out);
  return out;
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
      a.udp_port_entropy,
      a.udp_port_entropy_out,
      a.udp_ports_per_ip,
      a.udp_ports_per_ip_out,
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
      answerPct: r.answer_pct == null ? null : Math.min(100, Number(r.answer_pct)),
      halfOpenPct: r.half_open_pct == null ? null : Math.min(100, Number(r.half_open_pct)),
      halfOpenReplyPct: r.half_open_reply_pct == null ? null : Math.min(100, Number(r.half_open_reply_pct)),
      udpPortEntropy: nullableNum(r.udp_port_entropy),
      udpPortEntropyOut: nullableNum(r.udp_port_entropy_out),
      udpPortsPerIp: nullableNum(r.udp_ports_per_ip),
      udpPortsPerIpOut: nullableNum(r.udp_ports_per_ip_out),
    })),
  };
}

module.exports = {
  tick,
  loadLatest,
  lastClosedMinute,
};
