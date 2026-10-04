'use strict';

const {
  query,
  insertRows,
  executeCommand,
  col,
  flowCol,
  flowsRawTableRef,
  l3PrefixesViewRef,
  clientsViewRef,
  asnRegistryEnrichedTableRef,
  config,
  ispPrefixLookupSql,
} = require('./clickhouse');
const { flowIpExpr, primarySourceIdsSql, primaryClientSourceSql } = require('./queries');
const {
  TABLE,
  tableRef,
  NET_MINUTE_TABLE,
  netMinuteTableRef,
  netHourTableRef,
  ensureDetectionTables,
  PROTOS,
} = require('./detection-schema');
const { processDetectionAlerts } = require('./detection-telegram');
const { AMPLIFIER_PORTS, isNetSpikeHit, SYN_SUSTAINED_PPS } = require('./detection-signals');
const { loadForeignEnvelopes } = require('./detection-investigate');
const {
  MINUTE,
  EXPORT_LAG,
  BASELINE_DAYS,
  BASELINE_QUANTILE,
  BASELINE_P95_CAP,
  BASELINE_RECENT_CAP,
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

function flowCountryExpr(ipCol) {
  const etype = flowCol('etype');
  const etypeRef = ipCol.includes('.') ? `${ipCol.split('.')[0]}.${etype}` : etype;
  const dict = config.geoCountryDict || 'default.geo_country_dict';
  return `if(
    ${etypeRef} = 2048,
    dictGetString('${dict}', 'cc', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(${ipCol}, 1, 4)))))),
    dictGetString('${dict}', 'cc', tuple(toIPv6(IPv6NumToString(${ipCol}))))
  )`;
}

// RIR пишет страну того, кому выдан блок, а не того, кто его анонсирует: блоки,
// сданные в аренду российским сетям, числятся за PL, SC, CY. Источник из AS,
// зарегистрированного в России, считаем российским.
function srcCountrySql(ipCol, asnCol) {
  const byPrefix = `trimBoth(${flowCountryExpr(ipCol)})`;
  if (!asnCol) return byPrefix;
  return `if(${asnCol} IN (SELECT asn FROM ${asnRegistryEnrichedTableRef()} WHERE cc = 'RU'), 'RU', ${byPrefix})`;
}

const ASN_REGISTRY_CHECK_MS = 60 * 60 * 1000;
const asnRegistryState = { at: 0, ok: false };

async function asnRegistryAvailable() {
  if (Date.now() - asnRegistryState.at < ASN_REGISTRY_CHECK_MS) return asnRegistryState.ok;
  try {
    const { rows } = await query(`
      SELECT count() AS n
      FROM system.tables
      WHERE database = {db:String} AND name = {table:String}
    `, { db: config.database, table: config.asnRegistryEnrichedTable }, { name: 'detection/asn-registry-check' });
    asnRegistryState.ok = Number(rows[0]?.n) > 0;
  } catch {
    asnRegistryState.ok = false;
  }
  asnRegistryState.at = Date.now();
  return asnRegistryState.ok;
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

const CLOSED_MINUTE_LAG_MS = 4 * 60 * 1000;

// Запас как в lastClosedMinute: toStartOfMinute(now - 4 минуты). Если сводка
// ушла вперёд этого запаса, берём его, а не отказываемся от дешёвой минуты.
function clampClosedMinute(ts, now = Date.now()) {
  if (!Number.isFinite(ts) || ts <= 0) return null;
  const limit = now - CLOSED_MINUTE_LAG_MS;
  const closed = limit - (limit % 60000);
  const minute = Math.min(ts, closed);
  return minute > 0 ? minute : null;
}

// Ключ traffic_client_1m начинается с client_id, поэтому max(minute) читает всю
// таблицу (~550 млн строк на каждый тик). Последнюю записанную минуту знает
// состояние свёртки; строки за неё подтверждаем пробой с LIMIT 1.
async function rolledClientMinute() {
  const { rows } = await query(`
    SELECT toString(argMax(last_bucket, updated_at)) AS m
    FROM default.traffic_rollup_state
    WHERE job = 'traffic_client_1m'
  `, {}, { name: 'detection/client-rollup-state' });
  const minute = clampClosedMinute(parseUtc(rows?.[0]?.m));
  if (!minute) return null;
  const { rows: hit } = await query(`
    SELECT 1 AS ok
    FROM default.traffic_client_1m
    WHERE direction = 'in' AND minute = ${utcDateTime('m')}
    LIMIT 1
  `, { m: formatCh(minute) }, { name: 'detection/client-minute-exists' });
  return hit?.length ? minute : null;
}

async function lastClosedMinute() {
  const rolled = await rolledClientMinute();
  if (rolled) return rolled;
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

function smallerClientId(a, b) {
  const na = Number(a);
  const nb = Number(b);
  if (Number.isFinite(na) && Number.isFinite(nb) && na !== nb) return na < nb;
  return String(a) < String(b);
}

function dedupeClientsByDisplayName(rows) {
  const byName = new Map();
  for (const row of rows || []) {
    const id = String(row.client_id || '').trim();
    if (!id) continue;
    const name = String(row.display_name || '').trim();
    if (!name) {
      byName.set(`__id:${id}`, row);
      continue;
    }
    const prev = byName.get(name);
    if (!prev || smallerClientId(id, String(prev.client_id))) {
      byName.set(name, row);
    }
  }
  return [...byName.values()];
}

const ISP_DICT_CHECK_MS = 10 * 60 * 1000;
const ispDictState = { at: 0, ok: false };

async function ispDictAvailable() {
  if (Date.now() - ispDictState.at < ISP_DICT_CHECK_MS) return ispDictState.ok;
  try {
    const name = String(config.ispPrefixDict || 'default.net_isp_prefix_dict').split('.').pop();
    const { rows } = await query(`
      SELECT count() AS n
      FROM system.dictionaries
      WHERE name = {name:String}
    `, { name }, { name: 'detection/isp-dict-check' });
    ispDictState.ok = Number(rows[0]?.n) > 0;
  } catch {
    ispDictState.ok = false;
  }
  ispDictState.at = Date.now();
  return ispDictState.ok;
}

// Сети /24 из L3. Префиксы провайдера целиком смотрит scope provider, поэтому
// их первую /24 из объектов убираем только когда словарь уже есть: иначе
// выкладка кода раньше схемы оставила бы эти сети без присмотра.
function netObjectsSql({ clientPrefixes = false, excludeProviders = false } = {}) {
  const role = excludeProviders ? ` AND role != 'provider_public'` : '';
  if (!clientPrefixes) {
    return `
      SELECT DISTINCT ${prefixToNetSql('prefix')} AS net
      FROM ${l3PrefixesViewRef()}
      WHERE family = 4 AND ${prefixToNetSql('prefix')} != ''${role}
    `;
  }
  return `
    SELECT DISTINCT net FROM (
      SELECT ${prefixToNetSql('prefix')} AS net
      FROM ${l3PrefixesViewRef()}
      WHERE family = 4${role}
      UNION ALL
      SELECT ${prefixToNetSql('prefix')} AS net
      FROM default.net_client_prefixes_enabled
    )
    WHERE net != ''
  `;
}

async function loadProviders() {
  try {
    const { rows } = await query(`
      SELECT entity_id, max(display_name) AS display_name
      FROM ${l3PrefixesViewRef()}
      WHERE family = 4 AND role = 'provider_public' AND entity_id != ''
      GROUP BY entity_id
    `, {}, { name: 'detection/objects-providers' });
    return rows.map((r) => {
      const id = String(r.entity_id);
      const display = String(r.display_name || '').trim();
      return {
        scope: 'provider',
        scopeId: id,
        name: display || id,
        bindMode: 'prefixes',
      };
    });
  } catch (err) {
    logDetection('providers skipped', { message: err.message });
    return [];
  }
}

async function loadObjects() {
  const { rows: clients } = await query(`
    SELECT client_id, display_name, bind_mode
    FROM ${clientsViewRef()}
  `, {}, { name: 'detection/objects-clients' });

  const ispOk = await ispDictAvailable();
  let clientPrefixes = false;
  try {
    await query('SELECT 1 FROM default.net_client_prefixes_enabled LIMIT 1', {}, { name: 'detection/prefixes-probe' });
    clientPrefixes = true;
  } catch {
    // справочник клиентских префиксов может отсутствовать
  }
  const { rows: nets } = await query(
    netObjectsSql({ clientPrefixes, excludeProviders: ispOk }),
    {},
    { name: 'detection/objects-nets' },
  );
  const providers = ispOk ? await loadProviders() : [];

  return [
    ...dedupeClientsByDisplayName(clients).map((r) => ({
      scope: 'client',
      scopeId: String(r.client_id),
      name: String(r.display_name || r.client_id),
      bindMode: String(r.bind_mode || ''),
    })),
    ...nets.map((r) => ({
      scope: 'net',
      scopeId: String(r.net),
      name: String(r.net),
    })),
    ...providers,
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
    synOnlyBytes: 0,
    synOnlyPackets: 0,
    synOnlyRows: 0,
    synOnlyTargets: 0,
    ackOnlyBytes: 0,
    ackOnlyPackets: 0,
    ackOnlyRows: 0,
    rstBytes: 0,
    rstPackets: 0,
    rstRows: 0,
    establishedBytes: 0,
    establishedPackets: 0,
    establishedRows: 0,
    dataBytes: 0,
    dataPackets: 0,
    dataRows: 0,
    samplingRate: 1,
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
    synOnlyBytes: tcp.synOnlyBytes,
    synOnlyPackets: tcp.synOnlyPackets,
    synOnlyRows: tcp.synOnlyRows,
    synOnlyTargets: tcp.synOnlyTargets,
    ackOnlyBytes: tcp.ackOnlyBytes,
    ackOnlyPackets: tcp.ackOnlyPackets,
    ackOnlyRows: tcp.ackOnlyRows,
    rstBytes: tcp.rstBytes,
    rstPackets: tcp.rstPackets,
    rstRows: tcp.rstRows,
    establishedBytes: tcp.establishedBytes,
    establishedPackets: tcp.establishedPackets,
    establishedRows: tcp.establishedRows,
    dataBytes: tcp.dataBytes,
    dataPackets: tcp.dataPackets,
    dataRows: tcp.dataRows,
    samplingRate: tcp.samplingRate || 1,
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
    synOnlyBytes: Number(row.syn_only_bytes || 0),
    synOnlyPackets: Number(row.syn_only_packets || 0),
    synOnlyRows: Number(row.syn_only_rows || 0),
    synOnlyTargets: Number(row.syn_only_targets || 0),
    ackOnlyBytes: Number(row.ack_only_bytes || 0),
    ackOnlyPackets: Number(row.ack_only_packets || 0),
    ackOnlyRows: Number(row.ack_only_rows || 0),
    rstBytes: Number(row.rst_bytes || 0),
    rstPackets: Number(row.rst_packets || 0),
    rstRows: Number(row.rst_rows || 0),
    establishedBytes: Number(row.established_bytes || 0),
    establishedPackets: Number(row.established_packets || 0),
    establishedRows: Number(row.established_rows || 0),
    dataBytes: Number(row.data_bytes || 0),
    dataPackets: Number(row.data_packets || 0),
    dataRows: Number(row.data_rows || 0),
    samplingRate: Number(row.sampling_rate || 0) || 1,
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
      AND ${primaryClientSourceSql()}
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
  if (scope === 'provider') {
    return {
      towardId: ispPrefixLookupSql(`f.${col('dstIp')}`),
      fromId: ispPrefixLookupSql(`f.${col('srcIp')}`),
    };
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
      AND ${primarySourceIdsSql('f')}
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
  // Как tcp_flags: колонка уже в flows_raw. Env не обязателен — иначе на nta
  // минутка писала sampling_rate=1 при сырье 65536, и порог падал до 2000 п/с.
  const samplingRateCol = flowCol('samplingRate') || '`sampling_rate`';
  const tcp = `e.proto = 6`;
  const synSet = `bitAnd(e.tcp_flags, 2) > 0`;
  const ackSet = `bitAnd(e.tcp_flags, 16) > 0`;
  const synOnly = `${tcp} AND ${synSet} AND NOT ${ackSet}`;
  const ackOnly = `${tcp} AND ${ackSet} AND NOT ${synSet} AND bitAnd(e.tcp_flags, 8) = 0 AND bitAnd(e.tcp_flags, 1) = 0 AND bitAnd(e.tcp_flags, 4) = 0`;
  const rstOnly = `${tcp} AND bitAnd(e.tcp_flags, 4) > 0 AND bitAnd(e.tcp_flags, 8) = 0`;
  const established = `${tcp} AND ${synSet} AND ${ackSet}`;
  const dataPkts = `${tcp} AND bitAnd(e.tcp_flags, 8) > 0`;
  const flowAvg = `e.bytes / e.packets`;
  const { from, to, until } = minuteBounds(minuteTs);
  const { towardId, fromId } = scopeSides(scope);
  const timeFilter = minuteFilterSql();
  const flowCols = `
    f.${bytesCol} AS bytes,
    f.${packetsCol} AS packets,
    f.${protoCol} AS proto,
    f.${tcpFlags} AS tcp_flags,
    ${samplingRateCol ? `ifNull(toUInt64(f.${samplingRateCol}), 1)` : 'toUInt64(1)'} AS sampling_rate
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
      countIf(NOT e.toward AND ${tcp} AND e.tcp_flags = 18) AS syn_half_open_reply,
      sumIf(e.bytes, e.toward AND ${synOnly}) AS syn_only_bytes,
      sumIf(e.packets, e.toward AND ${synOnly}) AS syn_only_packets,
      countIf(e.toward AND ${synOnly}) AS syn_only_rows,
      uniqExactIf((tupleElement(e.sess, 2), tupleElement(e.sess, 4)), e.toward AND ${synOnly}) AS syn_only_targets,
      sumIf(e.bytes, e.toward AND ${ackOnly}) AS ack_only_bytes,
      sumIf(e.packets, e.toward AND ${ackOnly}) AS ack_only_packets,
      countIf(e.toward AND ${ackOnly}) AS ack_only_rows,
      sumIf(e.bytes, e.toward AND ${rstOnly}) AS rst_bytes,
      sumIf(e.packets, e.toward AND ${rstOnly}) AS rst_packets,
      countIf(e.toward AND ${rstOnly}) AS rst_rows,
      sumIf(e.bytes, e.toward AND ${established}) AS established_bytes,
      sumIf(e.packets, e.toward AND ${established}) AS established_packets,
      countIf(e.toward AND ${established}) AS established_rows,
      sumIf(e.bytes, e.toward AND ${dataPkts}) AS data_bytes,
      sumIf(e.packets, e.toward AND ${dataPkts}) AS data_packets,
      countIf(e.toward AND ${dataPkts}) AS data_rows,
      -- Доминирующий по пакетам rate, а не min: на nta в flows_raw пять разных
      -- частот (500…65536), и min отдавал минуте 500 у объекта, чей трафик
      -- почти весь приходит через sFlow 1:32768.
      toUInt64(ifNull(topKWeightedIf(1)(e.sampling_rate, e.packets, e.toward AND e.sampling_rate > 0)[1], 1)) AS sampling_rate
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
  const bytesCol = col('bytes');
  const protoCol = col('proto');
  const srcPort = col('srcPort');
  const dstPort = col('dstPort');
  const srcAddrCol = col('srcIp');
  const dstAddr = dstIpSql();
  const srcAddr = srcIpSql();
  const srcAsnCol = col('srcAsn');
  const srcCountry = srcCountrySql(
    `f.${srcAddrCol}`,
    srcAsnCol && await asnRegistryAvailable() ? `f.${srcAsnCol}` : '',
  );
  const ampPorts = AMPLIFIER_PORTS.join(', ');
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
          f.${srcPort} AS src_port,
          ${srcAddr} AS src_ip,
          f.${packetsCol} AS packets,
          f.${bytesCol} AS bytes,
          ${srcCountry} AS src_cc
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
          f.${srcPort} AS src_port,
          ${srcAddr} AS src_ip,
          f.${packetsCol} AS packets,
          f.${bytesCol} AS bytes,
          ${srcCountry} AS src_cc
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
      ),
      amp AS (
        SELECT
          scope_id,
          proto,
          sumIf(bytes, side = 1 AND src_port IN (${ampPorts})) AS amp_bytes,
          sumIf(packets, side = 1 AND src_port IN (${ampPorts})) AS amp_packets,
          uniqExactIf(src_ip, side = 1 AND src_port IN (${ampPorts})) AS amp_srcs
        FROM ev
        WHERE proto = 'udp'
        GROUP BY scope_id, proto
      ),
      geo_cc AS (
        SELECT
          scope_id,
          if(src_cc = '', '??', src_cc) AS cc,
          sum(bytes) AS bytes
        FROM ev
        WHERE side = 1
        GROUP BY scope_id, cc
      ),
      geo_tot AS (
        SELECT scope_id, sum(bytes) AS total FROM geo_cc GROUP BY scope_id
      ),
      geo_top AS (
        SELECT
          g.scope_id AS scope_id,
          arrayStringConcat(
            arrayMap(
              t -> concat(tupleElement(t, 1), ':', toString(round(tupleElement(t, 2), 2))),
              arraySlice(
                arrayReverseSort(t -> tupleElement(t, 2), groupArray((g.cc, g.bytes / nullIf(t.total, 0)))),
                1, 5
              )
            ),
            ','
          ) AS top_countries
        FROM geo_cc AS g
        INNER JOIN geo_tot AS t ON t.scope_id = g.scope_id
        GROUP BY g.scope_id
      ),
      geo AS (
        SELECT
          scope_id,
          sumIf(bytes, side = 1 AND src_cc NOT IN ('', 'RU', '??')) AS foreign_bytes,
          uniqExactIf(src_ip, side = 1 AND src_cc NOT IN ('', 'RU', '??')) AS foreign_srcs
        FROM ev
        GROUP BY scope_id
      )
    SELECT
      s.scope_id AS scope_id,
      s.proto AS proto,
      s.port_entropy,
      s.port_entropy_out,
      p.ports_per_ip,
      p.ports_per_ip_out,
      if(s.proto = 'udp', a.amp_bytes, 0) AS amp_bytes,
      if(s.proto = 'udp', a.amp_packets, 0) AS amp_packets,
      if(s.proto = 'udp', a.amp_srcs, 0) AS amp_srcs,
      if(s.proto = 'all', g.foreign_bytes, 0) AS foreign_bytes,
      if(s.proto = 'all', g.foreign_srcs, 0) AS foreign_srcs,
      if(s.proto = 'all', gt.top_countries, '') AS top_countries
    FROM by_side AS s
    LEFT JOIN ip_peak AS p ON s.scope_id = p.scope_id AND s.proto = p.proto
    LEFT JOIN amp AS a ON s.scope_id = a.scope_id AND s.proto = a.proto
    LEFT JOIN geo AS g ON s.scope_id = g.scope_id
    LEFT JOIN geo_top AS gt ON s.scope_id = gt.scope_id
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
      ampBytes: Number(r.amp_bytes || 0),
      ampPackets: Number(r.amp_packets || 0),
      ampSrcs: Number(r.amp_srcs || 0),
      foreignBytes: Number(r.foreign_bytes || 0),
      foreignSrcs: Number(r.foreign_srcs || 0),
      topCountries: String(r.top_countries || ''),
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

// Сети /24 внутри клиентов на портах. У клиента на IX за портом тысячи адресов,
// и удар в один сервер тонет в общем объёме, поэтому каждую /24 за портом
// сравниваем с её собственной нормой. Клиенты с разметкой по IP уже разложены
// на сети в scope 'net', их не трогаем.
const HOUR = 60 * MINUTE;
const NET_USUAL_FLOOR_BPS = 20e6;
const NET_USUAL_FLOOR_PPS = 5000;
// У нового провайдера нет p999. Пол в 1 Гбит/с даёт рост в первый день,
// когда удар уже десятки гигабит. Если норма уже есть, пол не подставляем.
const PROVIDER_BASELINE_FLOOR_BPS = 1e9;
// Пока сводок меньше суток, норма сети — это случайный час, а не её обычный
// уровень, и признак молчит.
const NET_COVERAGE_MIN_HOURS = 24;
const NET_RECENT_MINUTES = 60;
const NET_LIST_MAX = 3;
const NET_NORM_YOUNG_CACHE_MS = 10 * MINUTE;
const NET_NORM_YOUNG_HOURS = 48;

function portClientIds(objects) {
  return (objects || [])
    .filter((o) => o.scope === 'client' && o.bindMode === 'ports')
    .map((o) => o.scopeId);
}

function clientNetMinuteSql() {
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  const protoCol = col('proto');
  return `
    SELECT
      f.dst_client AS client_id,
      ${netFromIpSql(dstIpSql())} AS net,
      sum(f.${bytesCol}) AS bytes,
      sum(f.${packetsCol}) AS packets,
      sumIf(f.${bytesCol}, f.${protoCol} = 17) AS udp_bytes,
      sumIf(f.${bytesCol}, f.${protoCol} = 6) AS tcp_bytes
    FROM ${flowsRawTableRef()} AS f
    WHERE ${minuteFilterSql()}
      AND f.dst_client IN {clients:Array(String)}
    GROUP BY client_id, net
    HAVING net != '' AND bytes * 8 / 60 >= {minBps:Float64}
  `;
}

async function loadClientNets(minuteTs, clients) {
  if (!clients.length) return [];
  const started = Date.now();
  const { rows } = await query(clientNetMinuteSql(), {
    ...minuteBounds(minuteTs),
    clients,
    minBps: MIN_BPS,
  }, { name: 'detection/client-nets', clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });
  logDetection('client-nets done', { ms: Date.now() - started, clients: clients.length, nets: rows.length });
  return rows;
}

// Сводка часа считается прямо по сырью: так же заполняются прошлые дни, когда
// минутной таблицы сетей ещё не было.
function clientNetHourSql() {
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  return `
    INSERT INTO ${netHourTableRef()} (hour, client_id, net, minutes, bps_max, bps_p95, pps_max, pps_p95)
    SELECT
      toDateTime({hour:String}, 'UTC') AS hour,
      client_id,
      net,
      toUInt16(count()) AS minutes,
      max(bps) AS bps_max,
      quantileExact(0.95)(bps) AS bps_p95,
      max(pps) AS pps_max,
      quantileExact(0.95)(pps) AS pps_p95
    FROM (
      SELECT
        f.dst_client AS client_id,
        ${netFromIpSql(dstIpSql())} AS net,
        toStartOfMinute(f.time_flow_start_ns) AS m,
        sum(f.${bytesCol}) * 8 / 60 AS bps,
        sum(f.${packetsCol}) / 60 AS pps
      FROM ${flowsRawTableRef()} AS f
      WHERE ${minuteFilterSql()}
        AND f.dst_client IN {clients:Array(String)}
      GROUP BY client_id, net, m
    )
    WHERE net != ''
    GROUP BY client_id, net
    HAVING bps_max >= {minBps:Float64}
    SETTINGS max_execution_time = 600, max_bytes_before_external_group_by = 4000000000
  `;
}

function providerIdSql() {
  return ispPrefixLookupSql(`f.${col('dstIp')}`);
}

function providerNetMinuteSql() {
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  const protoCol = col('proto');
  const id = providerIdSql();
  return `
    SELECT
      ${id} AS client_id,
      ${netFromIpSql(dstIpSql())} AS net,
      sum(f.${bytesCol}) AS bytes,
      sum(f.${packetsCol}) AS packets,
      sumIf(f.${bytesCol}, f.${protoCol} = 17) AS udp_bytes,
      sumIf(f.${bytesCol}, f.${protoCol} = 6) AS tcp_bytes
    FROM ${flowsRawTableRef()} AS f
    WHERE ${minuteFilterSql()}
      AND ${id} != ''
    GROUP BY client_id, net
    HAVING net != '' AND bytes * 8 / 60 >= {minBps:Float64}
  `;
}

function providerNetHourSql() {
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  const id = providerIdSql();
  return `
    INSERT INTO ${netHourTableRef()} (hour, client_id, net, minutes, bps_max, bps_p95, pps_max, pps_p95)
    SELECT
      toDateTime({hour:String}, 'UTC') AS hour,
      client_id,
      net,
      toUInt16(count()) AS minutes,
      max(bps) AS bps_max,
      quantileExact(0.95)(bps) AS bps_p95,
      max(pps) AS pps_max,
      quantileExact(0.95)(pps) AS pps_p95
    FROM (
      SELECT
        ${id} AS client_id,
        ${netFromIpSql(dstIpSql())} AS net,
        toStartOfMinute(f.time_flow_start_ns) AS m,
        sum(f.${bytesCol}) * 8 / 60 AS bps,
        sum(f.${packetsCol}) / 60 AS pps
      FROM ${flowsRawTableRef()} AS f
      WHERE ${minuteFilterSql()}
        AND ${id} != ''
      GROUP BY client_id, net, m
    )
    WHERE net != ''
    GROUP BY client_id, net
    HAVING bps_max >= {minBps:Float64}
    SETTINGS max_execution_time = 600, max_bytes_before_external_group_by = 4000000000
  `;
}

async function loadProviderNets(minuteTs) {
  const started = Date.now();
  const { rows } = await query(providerNetMinuteSql(), {
    ...minuteBounds(minuteTs),
    minBps: MIN_BPS,
  }, { name: 'detection/provider-nets', clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });
  logDetection('provider-nets done', { ms: Date.now() - started, nets: rows.length });
  return rows;
}

function hourBounds(hourTs) {
  return {
    hour: formatCh(hourTs),
    from: formatCh(hourTs),
    to: formatCh(hourTs + HOUR),
    until: formatCh(hourTs + HOUR + EXPORT_LAG + MINUTE),
  };
}

function floorHour(ts) {
  return ts - (ts % HOUR);
}

// Свежий час ищем сверху вниз: после выкладки сначала заполняются последние
// сутки, и признак включается через минуты, а не через сутки.
function nextMissingHour(lastHourTs, oldestHourTs, done) {
  for (let ts = lastHourTs; ts >= oldestHourTs; ts -= HOUR) {
    if (!done.has(ts)) return ts;
  }
  return null;
}

// Часы клиентов и провайдеров учитываются раздельно: провайдер появился позже,
// и его прошлые часы нужно досчитать, хотя у клиентов они уже есть.
const netHourState = { done: new Set(), providerDone: new Set(), loaded: false, providersKey: '', rawFromTs: null };
let lastPortClients = [];
let lastProviderIds = [];

async function loadNetHourState(providers = []) {
  const days = BASELINE_DAYS;
  const { rows } = await query(`
    SELECT toString(hour) AS h, max(client_id IN {providers:Array(String)}) AS is_provider,
           min(client_id IN {providers:Array(String)}) AS only_provider
    FROM ${netHourTableRef()}
    WHERE hour >= now('UTC') - INTERVAL {days:UInt16} DAY
    GROUP BY hour
  `, { days, providers }, { name: 'detection/net-hours-done' });
  const { rows: raw } = await query(`
    SELECT toString(min(f.date)) AS d
    FROM ${flowsRawTableRef()} AS f
  `, {}, { name: 'detection/net-raw-from' });
  netHourState.done = new Set(rows
    .filter((r) => Number(r.only_provider) !== 1)
    .map((r) => parseUtc(r.h))
    .filter(Number.isFinite));
  netHourState.providerDone = new Set(rows
    .filter((r) => Number(r.is_provider) === 1)
    .map((r) => parseUtc(r.h))
    .filter(Number.isFinite));
  const rawFrom = parseUtc(`${raw?.[0]?.d || ''} 00:00:00`);
  netHourState.rawFromTs = Number.isFinite(rawFrom) && rawFrom > 0 ? rawFrom : null;
  netHourState.providersKey = providers.join(',');
  netHourState.loaded = true;
}

async function maintainNetHours(closedTs, clients = lastPortClients, providers = lastProviderIds) {
  if ((!clients.length && !providers.length) || !closedTs) return null;
  if (!netHourState.loaded || netHourState.providersKey !== providers.join(',')) {
    await loadNetHourState(providers);
  }
  const lastHour = floorHour(closedTs) - HOUR;
  // Первый день сырья обычно обрезан TTL посередине — его часы занизили бы норму.
  const rawEdge = netHourState.rawFromTs ? netHourState.rawFromTs + 24 * HOUR : 0;
  const oldest = Math.max(lastHour - BASELINE_DAYS * 24 * HOUR, rawEdge);
  const started = Date.now();
  const out = {};
  const clientHour = clients.length ? nextMissingHour(lastHour, oldest, netHourState.done) : null;
  if (clientHour != null) {
    await executeCommand(clientNetHourSql(), {
      ...hourBounds(clientHour),
      clients,
      minBps: MIN_BPS,
    }, { name: 'detection/net-hour-summary' });
    netHourState.done.add(clientHour);
    out.hour = formatCh(clientHour);
  }
  const providerHour = providers.length ? nextMissingHour(lastHour, oldest, netHourState.providerDone) : null;
  if (providerHour != null) {
    await executeCommand(providerNetHourSql(), {
      ...hourBounds(providerHour),
      minBps: MIN_BPS,
    }, { name: 'detection/provider-net-hour' });
    netHourState.providerDone.add(providerHour);
    out.providerHour = formatCh(providerHour);
    // Норма сетей кешируется на часы; провайдер досчитывается позже клиентов,
    // поэтому кеш сбрасываем на каждые сутки его новых сводок.
    if (netHourState.providerDone.size % NET_COVERAGE_MIN_HOURS === 0) netNormCache.at = 0;
  }
  if (clientHour == null && providerHour == null) return null;
  out.ms = Date.now() - started;
  logDetection('net-hour', out);
  return out;
}

function providerNetHours() {
  return netHourState.providerDone.size;
}

async function maintainNetHoursSafe(closedTs) {
  try {
    return await maintainNetHours(closedTs);
  } catch (err) {
    logDetection('net-hour error', { message: err.message });
    return null;
  }
}

let netNormCache = { at: 0, map: new Map(), hours: 0 };

function netNormCacheTtl(hours) {
  return hours >= NET_NORM_YOUNG_HOURS ? BASELINE_CACHE_MS : NET_NORM_YOUNG_CACHE_MS;
}

async function loadNetNorms(beforeTs, now = Date.now()) {
  if (netNormCache.at > 0 && now - netNormCache.at < netNormCacheTtl(netNormCache.hours)) {
    return netNormCache;
  }
  const params = { days: BASELINE_DAYS, before: formatCh(beforeTs) };
  const window = `
    hour >= ${utcDateTime('before')} - INTERVAL {days:UInt16} DAY
    AND hour <= ${utcDateTime('before')} - INTERVAL 120 MINUTE
  `;
  const [{ rows }, { rows: cover }] = await Promise.all([
    query(`
      SELECT
        client_id,
        net,
        quantileExact(0.99)(bps_max) AS bps_peak,
        quantileExact(0.95)(bps_p95) AS bps_typ,
        quantileExact(0.99)(pps_max) AS pps_peak,
        quantileExact(0.95)(pps_p95) AS pps_typ
      FROM ${netHourTableRef()}
      WHERE ${window}
      GROUP BY client_id, net
    `, params, { name: 'detection/net-norms', clickhouse_settings: HEAVY, requestTimeoutMs: 180000 }),
    query(`
      SELECT uniqExact(hour) AS hours
      FROM ${netHourTableRef()}
      WHERE ${window}
    `, params, { name: 'detection/net-norm-hours' }),
  ]);
  const map = new Map();
  for (const r of rows) {
    map.set(`${r.client_id}|${r.net}`, {
      bpsPeak: Number(r.bps_peak || 0),
      bpsTyp: Number(r.bps_typ || 0),
      ppsPeak: Number(r.pps_peak || 0),
      ppsTyp: Number(r.pps_typ || 0),
    });
  }
  netNormCache = { at: now, map, hours: Number(cover?.[0]?.hours || 0) };
  logDetection('net-norms', { nets: map.size, hours: netNormCache.hours });
  return netNormCache;
}

async function loadNetRecent(beforeTs) {
  const { rows } = await query(`
    SELECT
      client_id,
      net,
      median(bytes) * 8 / 60 AS bps,
      median(packets) / 60 AS pps
    FROM ${netMinuteTableRef()}
    WHERE minute >= ${utcDateTime('from')} AND minute < ${utcDateTime('before')}
    GROUP BY client_id, net
  `, {
    from: formatCh(beforeTs - NET_RECENT_MINUTES * MINUTE),
    before: formatCh(beforeTs),
  }, { name: 'detection/net-recent' });
  return new Map(rows.map((r) => [`${r.client_id}|${r.net}`, {
    bps: Number(r.bps || 0),
    pps: Number(r.pps || 0),
  }]));
}

// Та же логика, что у нормы клиента: пик за две недели, но не выше p95×4,
// чтобы прошлая атака не стала нормой, и не ниже медианы последнего часа ×1.6,
// чтобы растущая сеть не читалась атакой.
function netUsual(peak, typ, recent, floor) {
  const p = Number(peak) || 0;
  const t = Number(typ) || 0;
  const history = p > 0 && t > 0 ? Math.min(p, t * BASELINE_P95_CAP) : p;
  const local = (Number(recent) || 0) * BASELINE_RECENT_CAP;
  return Math.max(history, local, floor);
}

function netFieldsFor(item) {
  return {
    net_top: item.net,
    net_bps: item.bps,
    net_pps: item.pps,
    net_usual_bps: item.usualBps,
    net_usual_pps: item.usualPps,
    net_growth_bps: item.growthBps,
    net_growth_pps: item.growthPps,
    net_udp_bps: item.udpBps,
    net_tcp_bps: item.tcpBps,
  };
}

function netItemGrowth(item) {
  return Math.max(Number(item.growthBps) || 0, Number(item.growthPps) || 0);
}

// На клиента — одна самая выросшая горячая сеть и короткий список остальных.
function summarizeClientNets(rows, { norms = new Map(), recent = new Map(), mature = false } = {}) {
  const byClient = new Map();
  for (const r of rows || []) {
    const clientId = String(r.client_id);
    const net = String(r.net);
    const key = `${clientId}|${net}`;
    const norm = norms.get(key);
    const rec = recent.get(key);
    const bps = Number(r.bytes || 0) * 8 / 60;
    const pps = Number(r.packets || 0) / 60;
    const usualBps = netUsual(norm?.bpsPeak, norm?.bpsTyp, rec?.bps, NET_USUAL_FLOOR_BPS);
    const usualPps = netUsual(norm?.ppsPeak, norm?.ppsTyp, rec?.pps, NET_USUAL_FLOOR_PPS);
    const item = {
      net,
      bps,
      pps,
      usualBps,
      usualPps,
      growthBps: mature ? bps / usualBps : null,
      growthPps: mature ? pps / usualPps : null,
      udpBps: Number(r.udp_bytes || 0) * 8 / 60,
      tcpBps: Number(r.tcp_bytes || 0) * 8 / 60,
    };
    if (!isNetSpikeHit(netFieldsFor(item))) continue;
    const list = byClient.get(clientId) || [];
    list.push(item);
    byClient.set(clientId, list);
  }
  const out = new Map();
  for (const [clientId, list] of byClient) {
    list.sort((a, b) => netItemGrowth(b) - netItemGrowth(a) || b.bps - a.bps);
    out.set(clientId, {
      ...netFieldsFor(list[0]),
      net_list: list.slice(0, NET_LIST_MAX)
        .map((item) => `${item.net}:${Math.round(item.bps)}:${netItemGrowth(item).toFixed(1)}`)
        .join(','),
    });
  }
  return out;
}

async function loadClientNetState(minuteTs, clients) {
  if (!clients.length) return { rows: [], fields: new Map() };
  try {
    const [rows, norms, recent] = await Promise.all([
      loadClientNets(minuteTs, clients),
      loadNetNorms(minuteTs),
      loadNetRecent(minuteTs),
    ]);
    const mature = norms.hours >= NET_COVERAGE_MIN_HOURS;
    const fields = summarizeClientNets(rows, { norms: norms.map, recent, mature });
    logDetection('client-nets', { nets: rows.length, hot: fields.size, mature, hours: norms.hours });
    return { rows, fields };
  } catch (err) {
    // Сети — добавка к детекции клиента: их сбой не должен ронять минуту.
    logDetection('client-nets error', { message: err.message });
    return { rows: [], fields: new Map() };
  }
}

async function loadProviderNetState(minuteTs, providers) {
  if (!providers.length) return { rows: [], fields: new Map() };
  try {
    const [rows, norms, recent] = await Promise.all([
      loadProviderNets(minuteTs),
      loadNetNorms(minuteTs),
      loadNetRecent(minuteTs),
    ]);
    // Сутки своих сводок, а не общей таблицы: иначе обычная занятая /24
    // провайдера без нормы читалась бы ударом.
    const hours = providerNetHours();
    const mature = hours >= NET_COVERAGE_MIN_HOURS;
    const fields = summarizeClientNets(rows, { norms: norms.map, recent, mature });
    logDetection('provider-nets', { nets: rows.length, hot: fields.size, mature, hours });
    return { rows, fields };
  } catch (err) {
    logDetection('provider-nets error', { message: err.message });
    return { rows: [], fields: new Map() };
  }
}

function emptyScopeMap(scope, minuteTs, loader) {
  if (scope !== 'provider') return loader(scope, minuteTs);
  return loader(scope, minuteTs).catch((err) => {
    logDetection(`provider ${loader.name || 'query'} skipped`, { message: err.message });
    return new Map();
  });
}

async function insertClientNetRows(minute, rows) {
  if (!rows.length) return;
  const values = rows.map((r) => ({
    minute,
    client_id: String(r.client_id),
    net: String(r.net),
    bytes: Number(r.bytes || 0),
    packets: Number(r.packets || 0),
    udp_bytes: Number(r.udp_bytes || 0),
    tcp_bytes: Number(r.tcp_bytes || 0),
  }));
  try {
    const chunk = 10000;
    for (let i = 0; i < values.length; i += chunk) {
      await insertRows(NET_MINUTE_TABLE, values.slice(i, i + chunk), { name: 'detection/insert-net-minute' });
    }
  } catch (err) {
    logDetection('insert-net-minute error', { message: err.message });
  }
}

const BASELINE_CACHE_MS = 6 * 60 * 60 * 1000;

function isBaselineCacheFresh(cache, now = Date.now(), ttlMs = BASELINE_CACHE_MS) {
  return Boolean(cache?.map?.size) && (now - Number(cache.at || 0)) < ttlMs;
}

let clientBaselineCache = { at: 0, map: new Map() };
let netBaselineCache = { at: 0, map: new Map() };
let hourSignalCache = { at: 0, map: new Map() };

function mskHourKey(scope, scopeId, minuteValue) {
  const ts = typeof minuteValue === 'number' ? minuteValue : parseUtc(minuteValue);
  const d = new Date(ts + 3 * 60 * 60 * 1000);
  const weekend = d.getUTCDay() === 0 || d.getUTCDay() === 6 ? 1 : 0;
  return `${scope}|${scopeId}|${d.getUTCHours()}|${weekend}`;
}

function isHourSignalCacheFresh(now = Date.now()) {
  // Пустая карта тоже норма: на зеркале почти нет трафика усилителей и SYN.
  // Иначе запрос нормы часа повторялся бы каждую минуту.
  return hourSignalCache.at > 0 && (now - hourSignalCache.at) < BASELINE_CACHE_MS;
}

// Норма часа для отражения (UDP с портов усилителей) и голого SYN: p95 за
// тот же час по Москве, будни и выходные отдельно.
async function loadHourSignalBaselines() {
  if (isHourSignalCacheFresh()) return hourSignalCache.map;
  const days = BASELINE_DAYS;
  const { rows } = await query(`
    SELECT
      scope,
      scope_id,
      toHour(toTimeZone(minute, 'Europe/Moscow')) AS h,
      toUInt8(toDayOfWeek(toTimeZone(minute, 'Europe/Moscow')) >= 6) AS we,
      countIf(proto = 'udp') AS n_udp,
      quantileExactIf(0.95)(amp_bytes * 8 / 60, proto = 'udp') AS amp_p95,
      countIf(proto = 'all') AS n_all,
      countIf(proto = 'all' AND syn_only_packets / 60 < ${SYN_SUSTAINED_PPS}) AS n_syn_quiet,
      quantileExactIf(0.95)(syn_only_packets / 60, proto = 'all' AND syn_only_packets / 60 < ${SYN_SUSTAINED_PPS}) AS syn_p95
    FROM ${tableRef()}
    WHERE proto IN ('udp', 'all')
      AND minute >= now('UTC') - INTERVAL {days:UInt16} DAY
      AND minute < now('UTC') - INTERVAL 60 MINUTE
    GROUP BY scope, scope_id, h, we
    HAVING n_udp >= 60 OR n_all >= 60
  `, { days }, { name: 'detection/hour-signal-baseline', clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });
  const map = new Map();
  for (const r of rows) {
    const ampBps = Number(r.n_udp) >= 60 ? Number(r.amp_p95) || 0 : 0;
    // Минуты от миллиона SYN/с в норму не входят: иначе долгий флуд сам становится
    // «обычным» уровнем часа и алерт гаснет при смене часа. Если спокойных минут
    // мало, нормы нет — решает абсолютный пол.
    const synPps = Number(r.n_all) >= 60 && Number(r.n_syn_quiet) >= 30 ? Number(r.syn_p95) || 0 : 0;
    if (!(ampBps > 0) && !(synPps > 0)) continue;
    map.set(`${r.scope}|${r.scope_id}|${Number(r.h)}|${Number(r.we) ? 1 : 0}`, {
      ampBps: ampBps > 0 ? ampBps : null,
      synPps: synPps > 0 ? synPps : null,
    });
  }
  hourSignalCache = { at: Date.now(), map };
  return map;
}

async function loadClientBaselines() {
  if (isBaselineCacheFresh(clientBaselineCache)) return clientBaselineCache.map;
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
      AND ${primaryClientSourceSql()}
    GROUP BY client_id
  `, { days }, { name: 'detection/baseline-clients', clickhouse_settings: HEAVY, requestTimeoutMs: 180000 });
  for (const r of clients) {
    map.set(`client|${r.scope_id}|all`, { bps: Number(r.bps || 0), pps: Number(r.pps || 0) });
  }
  clientBaselineCache = { at: Date.now(), map };
  return map;
}

async function loadNetBaselines(beforeTs) {
  if (isBaselineCacheFresh(netBaselineCache)) return netBaselineCache.map;
  const q = BASELINE_QUANTILE;
  const days = BASELINE_DAYS;
  const map = new Map();
  const { rows: nets } = await query(`
    SELECT
      scope,
      scope_id,
      proto,
      quantileExact(${q})(bps) AS bps_p999,
      quantileExact(0.95)(bps) AS bps_p95,
      quantileExact(${q})(pps) AS pps_p999,
      quantileExact(0.95)(pps) AS pps_p95,
      quantileExact(0.95)(amp_bytes * 8 / 60) AS amp_bps_p95
    FROM ${tableRef()}
    WHERE minute >= now('UTC') - INTERVAL {days:UInt16} DAY
      AND minute < ${utcDateTime('before')}
    GROUP BY scope, scope_id, proto
  `, { days, before: formatCh(beforeTs) }, { name: 'detection/baseline-anomaly' });
  for (const r of nets) {
    const usePeak = String(r.proto) === 'all';
    map.set(`${r.scope}|${r.scope_id}|${r.proto}`, {
      bps: Number((usePeak ? r.bps_p999 : r.bps_p95) || 0),
      pps: Number((usePeak ? r.pps_p999 : r.pps_p95) || 0),
      ampBps: Number(r.amp_bps_p95 || 0) || null,
    });
  }
  netBaselineCache = { at: Date.now(), map };
  return map;
}

async function loadBaselines(beforeTs) {
  const [clients, anomaly] = await Promise.all([
    loadClientBaselines(),
    loadNetBaselines(beforeTs),
  ]);
  const map = new Map(anomaly);
  for (const [key, value] of clients) {
    map.set(key, { ...(map.get(key) || {}), ...value });
  }
  return map;
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
      syn_only_bytes: 0,
      syn_only_packets: 0,
      syn_only_rows: 0,
      syn_only_targets: 0,
      ack_only_bytes: 0,
      ack_only_packets: 0,
      ack_only_rows: 0,
      rst_bytes: 0,
      rst_packets: 0,
      rst_rows: 0,
      established_bytes: 0,
      established_packets: 0,
      established_rows: 0,
      data_bytes: 0,
      data_packets: 0,
      data_rows: 0,
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
      syn_only_bytes: m.synOnlyBytes,
      syn_only_packets: m.synOnlyPackets,
      syn_only_rows: m.synOnlyRows,
      syn_only_targets: m.synOnlyTargets,
      ack_only_bytes: m.ackOnlyBytes,
      ack_only_packets: m.ackOnlyPackets,
      ack_only_rows: m.ackOnlyRows,
      rst_bytes: m.rstBytes,
      rst_packets: m.rstPackets,
      rst_rows: m.rstRows,
      established_bytes: m.establishedBytes,
      established_packets: m.establishedPackets,
      established_rows: m.establishedRows,
      data_bytes: m.dataBytes,
      data_packets: m.dataPackets,
      data_rows: m.dataRows,
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
    amp_bytes: m.ampBytes,
    amp_packets: m.ampPackets,
    amp_srcs: m.ampSrcs,
    growth_amp: proto === 'udp' ? growthRatio(m.ampBytes * 8 / 60, baseline?.ampHourBps) : null,
    growth_syn: proto !== 'udp' ? growthRatio(m.synOnlyPackets / 60, baseline?.synHourPps) : null,
    foreign_bytes: m.foreignBytes,
    foreign_srcs: m.foreignSrcs,
    top_countries: m.topCountries,
    growth_foreign_bps: proto === 'all' ? growthRatio(m.foreignBytes * 8 / 60, baseline?.foreignBps) : null,
    growth_foreign_share: proto === 'all' ? growthRatio(
      m.bytes > 0 ? m.foreignBytes / m.bytes : 0,
      baseline?.foreignShare,
    ) : null,
    sampling_rate: m.samplingRate || 1,
  };
}

// Порог MIN_BPS может отсечь все объекты сразу — тогда в таблице минуты нет
// и minuteWritten() навсегда вернёт false. Помним её здесь, чтобы не зациклиться.
let lastProcessedMinute = 0;

const MINUTE_MS = 60 * 1000;
const CATCHUP_MAX_MINUTES = 10;

// Под нагрузкой свёртка закрывает минуты пачками (ШПД 04.10: 15:42–15:46 UTC
// одним заходом), и последняя закрытая минута перескакивает через остальные.
// Без догона серия для алерта не набирается. Догоняем не дальше окна: минуты
// старше дали бы в Telegram алерты о прошлом. После перезапуска воркера, когда
// за окно ничего не записано, берём только последнюю минуту.
function pendingMinutes(closedTs, lastDoneTs, max = CATCHUP_MAX_MINUTES) {
  if (!Number.isFinite(closedTs) || closedTs <= 0) return [];
  if (!Number.isFinite(lastDoneTs) || lastDoneTs <= 0 || lastDoneTs >= closedTs) return [closedTs];
  const windowFrom = closedTs - (max - 1) * MINUTE_MS;
  const out = [];
  for (let ts = Math.max(lastDoneTs + MINUTE_MS, windowFrom); ts <= closedTs; ts += MINUTE_MS) out.push(ts);
  return out;
}

async function lastWrittenMinute(closedTs, max = CATCHUP_MAX_MINUTES) {
  const { rows } = await query(`
    SELECT toString(max(minute)) AS m, count() AS n
    FROM ${tableRef()}
    WHERE minute >= ${utcDateTime('from')}
      AND minute <= ${utcDateTime('to')}
  `, {
    from: formatCh(closedTs - max * MINUTE_MS),
    to: formatCh(closedTs),
  }, { name: 'detection/last-written-minute' });
  if (!Number(rows[0]?.n)) return null;
  const ts = parseUtc(rows[0]?.m);
  return Number.isFinite(ts) && ts > 0 ? ts : null;
}

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
    const netHour = await maintainNetHoursSafe(closed);
    return { skipped: 'processed', minute, ...(netHour ? { netHour } : {}) };
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
    const netHour = await maintainNetHoursSafe(closed);
    return { skipped: 'done', minute, ...stats, ...(netHour ? { netHour } : {}) };
  }

  const written = await lastWrittenMinute(closed);
  const minutes = pendingMinutes(closed, Math.max(written || 0, lastProcessedMinute));
  if (minutes.length > 1) {
    logDetection('catch-up', { from: formatCh(minutes[0]), to: minute, minutes: minutes.length });
  }
  const objects = await loadObjects();
  let out = null;
  for (const ts of minutes) {
    out = await processMinute(ts, objects);
  }
  if (minutes.length > 1) out.caughtUp = minutes.slice(0, -1).map(formatCh);
  return out;
}

async function processMinute(closed, objects) {
  const minute = formatCh(closed);
  const portClients = portClientIds(objects);
  const providerIds = objects.filter((o) => o.scope === 'provider').map((o) => o.scopeId);
  lastPortClients = portClients;
  lastProviderIds = providerIds;
  logDetection('objects', {
    minute,
    clients: objects.filter((o) => o.scope === 'client').length,
    portClients: portClients.length,
    providers: providerIds.length,
    nets: objects.filter((o) => o.scope === 'net').length,
  });
  const [
    clientVol,
    clientFlags,
    netFlags,
    providerFlags,
    clientPorts,
    netPorts,
    providerPorts,
    baselines,
    foreignEnvelopes,
    hourSignals,
    clientNets,
    providerNets,
  ] = await Promise.all([
    loadClientVolume(closed),
    loadScopeFlags('client', closed),
    loadScopeFlags('net', closed),
    providerIds.length ? emptyScopeMap('provider', closed, loadScopeFlags) : new Map(),
    loadPortMetrics('client', closed),
    loadPortMetrics('net', closed),
    providerIds.length ? emptyScopeMap('provider', closed, loadPortMetrics) : new Map(),
    loadBaselines(closed),
    loadForeignEnvelopes(closed),
    loadHourSignalBaselines(),
    loadClientNetState(closed, portClients),
    loadProviderNetState(closed, providerIds),
  ]);
  for (const [clientId, env] of foreignEnvelopes) {
    const key = `client|${clientId}|all`;
    baselines.set(key, {
      ...(baselines.get(key) || {}),
      foreignBps: env.bpsP95,
      foreignShare: env.shareP95,
    });
  }

  let matchedFlags = 0;
  let insertedAttempts = 0;
  const missed = [];
  const rows = [];
  let skippedBelowMinBps = 0;
  for (const object of objects) {
    const flagMap = object.scope === 'client' ? clientFlags
      : object.scope === 'provider' ? providerFlags
        : netFlags;
    const portMap = object.scope === 'client' ? clientPorts
      : object.scope === 'provider' ? providerPorts
        : netPorts;
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
      const base = baselines.get(`${object.scope}|${object.scopeId}|${proto}`) || null;
      const hour = hourSignals.get(mskHourKey(object.scope, object.scopeId, minute)) || null;
      const ampHourBps = proto === 'udp' ? hour?.ampBps ?? null : null;
      const synHourPps = proto !== 'udp' ? hour?.synPps ?? null : null;
      let baseline = base || ampHourBps || synHourPps ? { ...(base || {}), ampHourBps, synHourPps } : null;
      if (object.scope === 'provider' && proto === 'all' && !(Number(base?.bps) > 0)) {
        baseline = { ...(baseline || {}), bps: PROVIDER_BASELINE_FLOOR_BPS };
      }
      const row = toInsertRow(object, proto, raw, baseline);
      const netState = object.scope === 'provider' ? providerNets : clientNets;
      const netFields = proto === 'all' && (object.scope === 'client' || object.scope === 'provider')
        ? netState.fields.get(object.scopeId)
        : null;
      rows.push(netFields ? { ...row, ...netFields } : row);
    }
  }

  const chunk = 5000;
  for (let i = 0; i < rows.length; i += chunk) {
    await insertRows(TABLE, rows.slice(i, i + chunk), { name: 'detection/insert-anomaly' });
  }
  await insertClientNetRows(minute, [...clientNets.rows, ...providerNets.rows]);
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
    providers: providerIds.length,
    nets: objects.filter((o) => o.scope === 'net').length,
    rows: rows.length,
    skippedBelowMinBps,
    minBpsMbit: Math.round(MIN_BPS / 1e6),
    flagRows: clientFlags.size + netFlags.size + providerFlags.size,
    clientNets: clientNets.rows.length,
    clientNetsHot: clientNets.fields.size,
    providerNets: providerNets.rows.length,
    providerNetsHot: providerNets.fields.size,
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
      a.syn_only_bytes,
      a.syn_only_packets,
      a.syn_only_rows,
      a.syn_only_targets,
      a.ack_only_bytes,
      a.ack_only_packets,
      a.ack_only_rows,
      a.rst_bytes,
      a.rst_packets,
      a.rst_rows,
      a.established_bytes,
      a.established_packets,
      a.established_rows,
      a.data_bytes,
      a.data_packets,
      a.data_rows,
      a.sampling_rate,
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
      synOnlyBytes: Number(r.syn_only_bytes || 0),
      synOnlyPackets: Number(r.syn_only_packets || 0),
      synOnlyRows: Number(r.syn_only_rows || 0),
      synOnlyTargets: Number(r.syn_only_targets || 0),
      ackOnlyBytes: Number(r.ack_only_bytes || 0),
      ackOnlyPackets: Number(r.ack_only_packets || 0),
      ackOnlyRows: Number(r.ack_only_rows || 0),
      rstBytes: Number(r.rst_bytes || 0),
      rstPackets: Number(r.rst_packets || 0),
      rstRows: Number(r.rst_rows || 0),
      establishedBytes: Number(r.established_bytes || 0),
      establishedPackets: Number(r.established_packets || 0),
      establishedRows: Number(r.established_rows || 0),
      dataBytes: Number(r.data_bytes || 0),
      dataPackets: Number(r.data_packets || 0),
      dataRows: Number(r.data_rows || 0),
      samplingRate: Number(r.sampling_rate || 0) || 1,
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
  clampClosedMinute,
  pendingMinutes,
  CATCHUP_MAX_MINUTES,
  HISTORY_METRICS,
  BASELINE_CACHE_MS,
  isBaselineCacheFresh,
  dedupeClientsByDisplayName,
  portClientIds,
  clientNetMinuteSql,
  clientNetHourSql,
  providerNetMinuteSql,
  providerNetHourSql,
  netObjectsSql,
  PROVIDER_BASELINE_FLOOR_BPS,
  hourBounds,
  minuteBounds,
  loadScopeFlags,
  nextMissingHour,
  netUsual,
  summarizeClientNets,
  srcCountrySql,
};
