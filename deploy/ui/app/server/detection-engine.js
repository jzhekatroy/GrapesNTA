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
const { TABLE, tableRef, ensureDetectionTables, PROTOS } = require('./detection-schema');
const { processDetectionAlerts } = require('./detection-telegram');
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
  const rows = [...map.values()].map((bucket) => bucket.tcp || bucket);
  const withAttempts = rows.filter((r) => r.synAttempts > 0).length;
  const maxAttempts = rows.reduce((m, r) => Math.max(m, r.synAttempts || 0), 0);
  const maxAnswered = rows.reduce((m, r) => Math.max(m, r.synAnswered || 0), 0);
  const top = [...map.entries()]
    .map(([id, bucket]) => ({ id, flags: bucket.tcp || bucket }))
    .filter(({ flags }) => flags.synAttempts > 0)
    .sort((a, b) => b.flags.synAttempts - a.flags.synAttempts)
    .slice(0, 5)
    .map(({ id, flags }) => ({ id, attempts: flags.synAttempts, answered: flags.synAnswered, half: flags.synHalfOpen }));
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
    portEntropy: null,
    portEntropyOut: null,
    portsPerIp: null,
    portsPerIpOut: null,
  };
}

function addFlagVolume(target, extra) {
  return {
    ...target,
    bytes: target.bytes + extra.bytes,
    packets: target.packets + extra.packets,
    cvN: target.cvN + extra.cvN,
    cvSum: target.cvSum + extra.cvSum,
    cvSumSq: target.cvSumSq + extra.cvSumSq,
  };
}

function applyTcpHandshake(target, tcp) {
  return {
    ...target,
    synAttempts: tcp.synAttempts,
    synAnswered: tcp.synAnswered,
    synInFlows: tcp.synInFlows,
    synHalfOpen: tcp.synHalfOpen,
    synHalfOpenReply: tcp.synHalfOpenReply,
  };
}

function emptyProtoBucket() {
  return { all: emptyRaw(), tcp: emptyRaw(), udp: emptyRaw() };
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
      multiIf(e.proto = 6, 'tcp', e.proto = 17, 'udp', 'other') AS proto,
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
    GROUP BY e.scope_id, proto
  `, { from, to, until }, { name: `detection/flags-${scope}`, clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });
  } catch (err) {
    logDetection(`flags-${scope} error`, { ms: Date.now() - started, message: err.message, stack: err.stack });
    throw err;
  }
  const map = new Map();
  for (const row of result.rows) {
    const id = String(row.scope_id);
    const proto = String(row.proto || 'other');
    const flags = mapFlagRow(row);
    const bucket = map.get(id) || emptyProtoBucket();
    if (proto === 'tcp' || proto === 'udp') bucket[proto] = flags;
    bucket.all = addFlagVolume(bucket.all, flags);
    map.set(id, bucket);
  }
  for (const bucket of map.values()) {
    bucket.all = applyTcpHandshake(bucket.all, bucket.tcp);
  }
  logDetection(`flags-${scope} done`, { ms: Date.now() - started, ...flagStats(map) });
  return map;
}

function nullableNum(value) {
  return value == null ? null : Number(value);
}

// Энтропия портов и пик портов на адрес — по TCP, UDP и по обоим вместе.
// Вес энтропии — пакеты. Пик — максимум уникальных dst_port на один dst_addr.
async function loadPortMetrics(scope, minuteTs) {
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
          if(f.${protoCol} = 6, 'tcp', 'udp') AS proto,
          f.${dstPort} AS dst_port,
          ${dstAddr} AS dst_ip,
          f.${packetsCol} AS packets
        FROM ${flowsRawTableRef()} AS f
        WHERE ${timeFilter}
          AND f.${protoCol} IN (6, 17)
          AND ${towardId} != ''
        UNION ALL
        SELECT
          ${fromId} AS scope_id,
          0 AS side,
          if(f.${protoCol} = 6, 'tcp', 'udp') AS proto,
          f.${dstPort} AS dst_port,
          ${dstAddr} AS dst_ip,
          f.${packetsCol} AS packets
        FROM ${flowsRawTableRef()} AS f
        WHERE ${timeFilter}
          AND f.${protoCol} IN (6, 17)
          AND ${fromId} != ''
      ),
      sliced AS (
        SELECT scope_id, side, proto, dst_port, dst_ip, packets FROM ev
        UNION ALL
        SELECT scope_id, side, 'all' AS proto, dst_port, dst_ip, packets FROM ev
      ),
      per_port AS (
        SELECT
          scope_id,
          side,
          proto,
          dst_port,
          sum(packets) AS pkts
        FROM sliced
        GROUP BY scope_id, side, proto, dst_port
        HAVING pkts > 0
      ),
      shares AS (
        SELECT
          scope_id,
          side,
          proto,
          pkts / sum(pkts) OVER (PARTITION BY scope_id, side, proto) AS q
        FROM per_port
      ),
      by_side AS (
        SELECT
          scope_id,
          proto,
          if(countIf(side = 1) > 0, -sumIf(q * log2(q), side = 1) + 0, NULL) AS port_entropy,
          if(countIf(side = 0) > 0, -sumIf(q * log2(q), side = 0) + 0, NULL) AS port_entropy_out
        FROM shares
        GROUP BY scope_id, proto
      ),
      per_ip AS (
        SELECT
          scope_id,
          side,
          proto,
          dst_ip,
          uniqExact(dst_port) AS ports
        FROM sliced
        WHERE dst_ip != ''
        GROUP BY scope_id, side, proto, dst_ip
      ),
      ip_peak AS (
        SELECT
          scope_id,
          proto,
          if(countIf(side = 1) > 0, maxIf(ports, side = 1), NULL) AS ports_per_ip,
          if(countIf(side = 0) > 0, maxIf(ports, side = 0), NULL) AS ports_per_ip_out
        FROM per_ip
        GROUP BY scope_id, proto
      )
    SELECT
      s.scope_id AS scope_id,
      s.proto AS proto,
      s.port_entropy,
      s.port_entropy_out,
      p.ports_per_ip,
      p.ports_per_ip_out
    FROM by_side AS s
    LEFT JOIN ip_peak AS p ON s.scope_id = p.scope_id AND s.proto = p.proto
  `, { from, to, until }, {
    name: `detection/port-metrics-${scope}`,
    clickhouse_settings: HEAVY,
    requestTimeoutMs: 180000,
  });

  const map = new Map();
  for (const r of rows) {
    map.set(`${r.scope_id}|${r.proto}`, {
      portEntropy: nullableNum(r.port_entropy),
      portEntropyOut: nullableNum(r.port_entropy_out),
      portsPerIp: nullableNum(r.ports_per_ip),
      portsPerIpOut: nullableNum(r.ports_per_ip_out),
    });
  }
  logDetection(`port-metrics-${scope} done`, {
    ms: Date.now() - started,
    scopes: new Set(rows.map((r) => r.scope_id)).size,
    maxEntropyIn: [...map.values()].reduce((m, r) => Math.max(m, r.portEntropy || 0), 0).toFixed(2),
    maxPortsPerIpIn: [...map.values()].reduce((m, r) => Math.max(m, r.portsPerIp || 0), 0).toFixed(2),
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
    map.set(`client|${r.scope_id}|all`, { bps: Number(r.bps || 0), pps: Number(r.pps || 0) });
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
      scope,
      scope_id,
      proto,
      quantileExact(${q})(bps) AS bps,
      quantileExact(${q})(pps) AS pps
    FROM ${tableRef()}
    WHERE minute >= now('UTC') - INTERVAL {days:UInt16} DAY
      AND minute < ${utcDateTime('before')}
    GROUP BY scope, scope_id, proto
  `, { days, before: formatCh(beforeTs) }, { name: 'detection/baseline-anomaly' });
  for (const r of nets) {
    map.set(`${r.scope}|${r.scope_id}|${r.proto}`, { bps: Number(r.bps || 0), pps: Number(r.pps || 0) });
  }
  return map;
}

async function loadBaselines(beforeTs) {
  const [clients, anomaly] = await Promise.all([
    loadClientBaselines(),
    loadNetBaselines(beforeTs),
  ]);
  return new Map([...anomaly, ...clients]);
}

function toInsertRow(object, proto, raw, baseline) {
  const m = minuteMetrics(raw);
  const handshake = proto === 'udp'
    ? {
      syn_attempts: 0,
      syn_answered: 0,
      syn_in_flows: 0,
      syn_half_open: 0,
      syn_half_open_reply: 0,
      answer_pct: null,
      half_open_pct: null,
      half_open_reply_pct: null,
    }
    : {
      syn_attempts: m.synAttempts,
      syn_answered: m.synAnswered,
      syn_in_flows: m.synInFlows,
      syn_half_open: m.synHalfOpen,
      syn_half_open_reply: m.synHalfOpenReply,
      answer_pct: m.answerPct,
      half_open_pct: m.halfOpenPct,
      half_open_reply_pct: m.halfOpenReplyPct,
    };
  return {
    minute: raw.minute,
    scope: object.scope,
    scope_id: object.scopeId,
    proto,
    bytes: m.bytes,
    packets: m.packets,
    bps: m.bps,
    pps: m.pps,
    growth_bps: growthRatio(m.bps, baseline?.bps),
    growth_pps: growthRatio(m.pps, baseline?.pps),
    avg_packet_bytes: m.avgPacketBytes,
    cv_percent: m.cvPercent,
    ...handshake,
    port_entropy: m.portEntropy,
    port_entropy_out: m.portEntropyOut,
    ports_per_ip: m.portsPerIp,
    ports_per_ip_out: m.portsPerIpOut,
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
  const [clientVol, clientFlags, netFlags, clientPorts, netPorts, baselines] = await Promise.all([
    loadClientVolume(closed),
    loadScopeFlags('client', closed),
    loadScopeFlags('net', closed),
    loadPortMetrics('client', closed),
    loadPortMetrics('net', closed),
    loadBaselines(closed),
  ]);

  let matchedFlags = 0;
  let insertedAttempts = 0;
  const missed = [];
  const rows = [];
  let skippedBelowMinBps = 0;
  for (const object of objects) {
    const flagMap = object.scope === 'client' ? clientFlags : netFlags;
    const portMap = object.scope === 'client' ? clientPorts : netPorts;
    const bucket = flagMap.get(object.scopeId) || emptyProtoBucket();
    if (flagMap.has(object.scopeId)) {
      matchedFlags += 1;
      if (bucket.tcp.synAttempts > 0) insertedAttempts += 1;
    } else if (missed.length < 8) {
      missed.push(`${object.scope}:${object.scopeId}`);
    }
    const volume = object.scope === 'client' ? (clientVol.get(object.scopeId) || null) : null;
    const allBytes = volume ? volume.bytes : bucket.all.bytes;
    const allPackets = volume ? volume.packets : bucket.all.packets;
    if ((allBytes * 8 / 60) < MIN_BPS) {
      skippedBelowMinBps += 1;
      continue;
    }
    for (const proto of PROTOS) {
      const flags = bucket[proto] || emptyRaw();
      const ports = portMap.get(`${object.scopeId}|${proto}`) || {};
      const raw = {
        ...flags,
        ...ports,
        minute,
        bytes: proto === 'all' ? allBytes : flags.bytes,
        packets: proto === 'all' ? allPackets : flags.packets,
      };
      rows.push(toInsertRow(
        object,
        proto,
        raw,
        baselines.get(`${object.scope}|${object.scopeId}|${proto}`),
      ));
    }
  }

  const chunk = 5000;
  for (let i = 0; i < rows.length; i += chunk) {
    await insertRows(TABLE, rows.slice(i, i + chunk), { name: 'detection/insert-anomaly' });
  }
  lastProcessedMinute = closed;

  const nameByKey = new Map(objects.map((o) => [`${o.scope}|${o.scopeId}`, o.name]));
  let telegram = { sent: 0 };
  try {
    telegram = await processDetectionAlerts({ minute, rows, nameByKey });
    logDetection('telegram', telegram);
  } catch (err) {
    logDetection('telegram error', { message: err.message });
    telegram = { sent: 0, error: err.message };
  }

  const out = {
    minute,
    clients: objects.filter((o) => o.scope === 'client').length,
    nets: objects.filter((o) => o.scope === 'net').length,
    rows: rows.length,
    skippedBelowMinBps,
    minBpsMbit: Math.round(MIN_BPS / 1e6),
    flagRows: clientFlags.size + netFlags.size,
    matchedFlags,
    insertedWithAttempts: insertedAttempts,
    maxAttempts: rows.reduce((m, r) => Math.max(m, r.syn_attempts), 0),
    missedSample: missed,
    telegram,
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
      a.proto,
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
      a.port_entropy,
      a.port_entropy_out,
      a.ports_per_ip,
      a.ports_per_ip_out,
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
      proto: r.proto || 'all',
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
      portEntropy: nullableNum(r.port_entropy),
      portEntropyOut: nullableNum(r.port_entropy_out),
      portsPerIp: nullableNum(r.ports_per_ip),
      portsPerIpOut: nullableNum(r.ports_per_ip_out),
    })),
  };
}

const HISTORY_METRICS = {
  bps: { column: 'bps', units: 'бит/с' },
  pps: { column: 'pps', units: 'п/с' },
  growthBps: { column: 'growth_bps', units: '×' },
  growthPps: { column: 'growth_pps', units: '×' },
  synAttempts: { column: 'syn_attempts', units: '' },
  answerPct: { column: 'answer_pct', units: '%' },
  halfOpenPct: { column: 'half_open_pct', units: '%' },
  halfOpenReplyPct: { column: 'half_open_reply_pct', units: '%' },
  portEntropy: { column: 'port_entropy', units: '' },
  portEntropyOut: { column: 'port_entropy_out', units: '' },
  portsPerIp: { column: 'ports_per_ip', units: '' },
  portsPerIpOut: { column: 'ports_per_ip_out', units: '' },
  avgPacketBytes: { column: 'avg_packet_bytes', units: 'Б' },
  cvPercent: { column: 'cv_percent', units: '%' },
};

const HISTORY_HOURS = 6;
const MAX_HISTORY_HOURS = 16 * 24;

function historyBoundTs(value) {
  const raw = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$/.test(raw)) return null;
  const ts = parseUtc(raw);
  return Number.isFinite(ts) ? ts : null;
}

async function loadHistory({ scope, scopeId, proto, metric, hours, from, to } = {}) {
  const spec = HISTORY_METRICS[metric];
  if (!spec) {
    const err = new Error('Неизвестная метрика');
    err.statusCode = 400;
    throw err;
  }
  if (!['client', 'net'].includes(String(scope || ''))) {
    const err = new Error('Неизвестный объект');
    err.statusCode = 400;
    throw err;
  }
  if (!String(scopeId || '').trim()) {
    const err = new Error('Не указан объект');
    err.statusCode = 400;
    throw err;
  }
  if (proto != null && proto !== '' && !PROTOS.includes(proto)) {
    const err = new Error('Неизвестный протокол');
    err.statusCode = 400;
    throw err;
  }
  const hasCustom = from != null && from !== '' || to != null && to !== '';
  let fromTs = null;
  let toTs = null;
  if (hasCustom) {
    fromTs = historyBoundTs(from);
    toTs = historyBoundTs(to);
    if (fromTs == null || toTs == null || toTs <= fromTs) {
      const err = new Error('Некорректный период');
      err.statusCode = 400;
      throw err;
    }
    if (toTs - fromTs > MAX_HISTORY_HOURS * 3600 * 1000) {
      fromTs = toTs - MAX_HISTORY_HOURS * 3600 * 1000;
    }
  }
  await ensureDetectionTables();
  const protoKey = PROTOS.includes(proto) ? proto : 'all';
  const windowHours = Math.min(MAX_HISTORY_HOURS, Math.max(1, Number(hours) || HISTORY_HOURS));
  const timeSql = hasCustom
    ? `minute >= ${utcDateTime('from')} AND minute < ${utcDateTime('to')}`
    : `minute >= now('UTC') - INTERVAL {hours:UInt16} HOUR`;
  const { rows } = await query(`
    SELECT
      minute,
      ${spec.column} AS value
    FROM ${tableRef()} AS a FINAL
    WHERE scope = {scope:String}
      AND scope_id = {scopeId:String}
      AND proto = {proto:String}
      AND ${timeSql}
    ORDER BY minute
  `, {
    scope,
    scopeId: String(scopeId || ''),
    proto: protoKey,
    hours: windowHours,
    from: hasCustom ? formatCh(fromTs) : undefined,
    to: hasCustom ? formatCh(toTs) : undefined,
  }, { name: 'detection/history' });

  return {
    scope,
    scopeId: String(scopeId || ''),
    proto: protoKey,
    metric,
    units: spec.units,
    hours: hasCustom ? null : windowHours,
    from: hasCustom ? formatCh(fromTs) : null,
    to: hasCustom ? formatCh(toTs) : null,
    points: rows.map((r) => {
      const ts = parseUtc(r.minute);
      const v = r.value == null ? null : Number(r.value);
      return {
        t: formatCh(ts),
        bucket: formatCh(ts),
        bucketMs: ts,
        bps: v,
        v,
      };
    }),
  };
}

module.exports = {
  tick,
  loadLatest,
  loadHistory,
  lastClosedMinute,
  HISTORY_METRICS,
};
