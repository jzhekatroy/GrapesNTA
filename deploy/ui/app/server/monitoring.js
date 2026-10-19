'use strict';

const { query, config, ping } = require('./clickhouse');
const { tableRef } = require('./detection-schema');
const { parseUtc, formatCh, MINUTE } = require('./detection-core');
const { loadHistory } = require('./detection-engine');
const { fetchCollectorOverview } = require('./collector-overview');
const { getWorkerDiagnostics } = require('./diagnostics-worker');
const { getEnrichmentDiagnostics } = require('./diagnostics-enrichment');
const { getSnmpDiagnostics } = require('./diagnostics-snmp');

// Минута закрывается не раньше чем через 4 минуты и подписана своим началом:
// на ШПД обычное отставание 6,5–7,2 минуты, поэтому тревога только после 10.
const DETECTION_STALE_MS = 10 * MINUTE;
const HISTORY_LEAD_MS = 30 * MINUTE;

const COMPONENTS = [
  { id: 'collectors', title: 'Коллекторы' },
  { id: 'detection', title: 'Детекция' },
  { id: 'worker', title: 'Worker' },
  { id: 'clickhouse', title: 'ClickHouse' },
  { id: 'enrichment', title: 'Обогащение' },
  { id: 'snmp', title: 'SNMP' },
];

const COMPONENT_LINK = {
  collectors: { link: '#collectors', diagnosticsTab: null },
  detection: { link: '#diagnostics', diagnosticsTab: 'detection' },
  worker: { link: '#diagnostics', diagnosticsTab: 'worker' },
  clickhouse: { link: null, diagnosticsTab: null },
  enrichment: { link: '#diagnostics', diagnosticsTab: 'enrichment' },
  snmp: { link: '#snmp', diagnosticsTab: null },
};

const CODE_TITLE = {
  detection_stale: 'Детекция отстала',
  detection_empty: 'Детекция пустая',
  clickhouse_down: 'ClickHouse не отвечает',
  worker_offline: 'Worker не отвечает',
  worker_tick_error: 'Ошибка tick worker',
  obs_live_without_materialize: 'Наблюдение без подготовки данных',
  obs_materialize_error: 'Ошибка materialize',
  obs_queued_stuck: 'Наблюдение зависло в очереди',
  obs_lagging: 'Наблюдение отстаёт',
  obs_cursor_stale: 'Курсор наблюдения устарел',
  obs_no_rollup_rows: 'Нет строк rollup',
  obs_last_tick_error: 'Ошибка tick наблюдения',
  traffic_state_read_failed: 'Не прочитано состояние traffic rollup',
  traffic_job_failed: 'Traffic rollup упал',
  traffic_job_deferred: 'Traffic rollup отложен',
  traffic_job_stale: 'Traffic rollup устарел',
  obs_quota: 'Слишком много materialize',
  enrichment_job_error: 'Ошибка обогащения',
  enrichment_job_stuck: 'Обогащение зависло',
  enrichment_never_ran: 'Обогащение не запускалось',
  enrichment_stale: 'Обогащение устарело',
  enrichment_empty_table: 'Пустая таблица обогащения',
  enrichment_status_read_failed: 'Не прочитан статус обогащения',
  snmp_settings_missing: 'Нет настроек SNMP',
  snmp_disabled: 'SNMP выключен',
  snmp_no_community: 'Не задан SNMP community',
  snmp_agents_read_failed: 'Не прочитаны SNMP-агенты',
  snmp_status_read_failed: 'Не прочитан статус SNMP',
  snmp_never_ran: 'SNMP не запускался',
  snmp_job_error: 'Ошибка SNMP',
  snmp_job_stuck: 'SNMP завис',
  snmp_stale: 'SNMP устарел',
  snmp_all_timeout: 'SNMP не отвечает',
  snmp_all_timeout_cached: 'SNMP не отвечает',
  snmp_many_timeouts: 'Много таймаутов SNMP',
  snmp_auth_errors: 'Ошибки community SNMP',
  snmp_queue_pending: 'Очередь SNMP',
  snmp_interfaces_read_failed: 'Не прочитаны интерфейсы SNMP',
};

function redact(text) {
  return String(text || '')
    .replace(/\/\/([^/\s@]*)@/g, '//')
    .replace(/(password|passwd|pwd|token|community)(\s*[:=]\s*)\S+/gi, '$1$2***');
}

function cleanText(text, max = 500) {
  const value = redact(text).replace(/\s+/g, ' ').trim();
  if (!value) return '';
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function shortPublicError(err) {
  return cleanText(err?.message || err || 'ошибка проверки', 180) || 'ошибка проверки';
}

function problemId(component, code, objectId) {
  const object = String(objectId || '').replace(/[:\s]+/g, '_');
  return object ? `${component}:${code}:${object}` : `${component}:${code}`;
}

function sinceFromAge(now, ageSec) {
  const age = Number(ageSec);
  if (!Number.isFinite(age) || age < 0) return null;
  return new Date(now - age * 1000).toISOString();
}

function latestIso(values) {
  let best = null;
  let bestTs = -Infinity;
  for (const value of values) {
    const ts = Date.parse(value);
    if (Number.isFinite(ts) && ts > bestTs) {
      bestTs = ts;
      best = new Date(ts).toISOString();
    }
  }
  return best;
}

function minuteOf(lastMinutes, sourceId) {
  if (!lastMinutes) return null;
  const value = lastMinutes instanceof Map ? lastMinutes.get(sourceId) : lastMinutes[sourceId];
  return value || null;
}

function componentTitle(id) {
  return COMPONENTS.find((item) => item.id === id)?.title || id;
}

function minsFromMessage(message) {
  const text = String(message || '');
  const paren = text.match(/\((\d+)\s*мин\)/);
  if (paren) return Number(paren[1]);
  const ago = text.match(/(\d+)\s*мин\s+назад/);
  if (ago) return Number(ago[1]);
  const running = text.match(/уже\s+(\d+)\s*мин/);
  if (running) return Number(running[1]);
  return null;
}

function quotedNameFromMessage(message) {
  const match = String(message || '').match(/«([^»]+)»/);
  return match ? match[1] : null;
}

function deriveI18nParams(component, item, objectId, message) {
  const params = {};
  const object = objectId ? String(objectId) : '';
  if (object) {
    params.objectId = object;
    params.label = object;
    params.job = object;
  }
  if (item && typeof item === 'object') {
    if (item.job) params.job = String(item.job);
    if (item.observationId) params.observationId = String(item.observationId);
    if (item.collectorId) params.collectorId = String(item.collectorId);
    if (item.sourceId) params.sourceId = String(item.sourceId);
    if (item.heartbeatAgeSec != null) params.heartbeatAgeSec = item.heartbeatAgeSec;
    if (item.lagSeconds != null) params.lagSeconds = item.lagSeconds;
    if (item.bucketLagSec != null) params.bucketLagSec = item.bucketLagSec;
    if (item.updateAgeSec != null) params.updateAgeSec = item.updateAgeSec;
    if (item.exitCode != null) params.exitCode = item.exitCode;
  }
  const mins = minsFromMessage(message);
  if (mins != null) params.mins = mins;
  const quoted = quotedNameFromMessage(message);
  if (quoted) params.name = quoted;
  if (component) params.component = component;
  params.detail = cleanText(message, 500);
  return params;
}

function makeProblem(component, code, { level, title, message, since, objectId, i18nParams }) {
  const link = COMPONENT_LINK[component] || { link: null, diagnosticsTab: null };
  const object = objectId ? String(objectId) : '';
  return {
    id: problemId(component, code, objectId),
    component,
    code,
    objectId: object,
    level,
    title: cleanText(title, 120),
    message: cleanText(message),
    since: since || null,
    link: link.link,
    diagnosticsTab: link.diagnosticsTab,
    i18nParams: i18nParams || undefined,
  };
}

function checkFailed(component, error) {
  const message = shortPublicError(error);
  return makeProblem(component, 'check_failed', {
    level: 'critical',
    title: `Не удалось проверить ${componentTitle(component)}`,
    message,
    objectId: '',
    i18nParams: deriveI18nParams(component, null, '', message),
  });
}

function workerSince(item, now) {
  if (item.code === 'worker_offline') return sinceFromAge(now, item.heartbeatAgeSec);
  if (item.code === 'obs_lagging') return sinceFromAge(now, item.lagSeconds);
  if (item.code === 'traffic_job_deferred') return sinceFromAge(now, item.bucketLagSec);
  if (item.code === 'traffic_job_stale') {
    const age = item.updateAgeSec != null && item.bucketLagSec != null
      ? Math.max(Number(item.updateAgeSec), Number(item.bucketLagSec))
      : (item.updateAgeSec ?? item.bucketLagSec);
    return sinceFromAge(now, age);
  }
  return null;
}

function enrichmentSince(item, jobs) {
  const job = (jobs || []).find((row) => row.id === item.job);
  if (!job) return null;
  if (item.code === 'enrichment_job_stuck') return job.startedAt || null;
  if (item.code === 'enrichment_stale' || item.code === 'enrichment_job_error') return job.finishedAt || null;
  return null;
}

function snmpSince(item, job) {
  if (!job) return null;
  if (item.code === 'snmp_stale' || item.code === 'snmp_job_error') return job.finishedAt || null;
  if (item.code === 'snmp_job_stuck') return job.startedAt || null;
  return null;
}

function mapExisting(component, item, now, since) {
  const objectId = item.observationId || item.job || item.sourceId || item.collectorId || '';
  const message = item.message || '';
  return makeProblem(component, item.code || 'unknown', {
    level: item.level === 'critical' ? 'critical' : 'warning',
    title: CODE_TITLE[item.code] || message,
    message,
    since,
    objectId,
    i18nParams: deriveI18nParams(component, item, objectId, message),
  });
}

function collectorProblems(collectors, lastMinutes) {
  const problems = [];
  for (const collector of collectors || []) {
    const sources = Array.isArray(collector.sources) ? collector.sources : [];
    if (!sources.length || collector.state === 'empty') continue;
    const name = collector.displayName || collector.collectorId || 'Коллектор';
    if (collector.state === 'offline') {
      problems.push(makeProblem('collectors', 'collector_offline', {
        level: 'critical',
        title: `${name} не шлёт данные`,
        message: 'Ни один источник коллектора не виден в окне живых потоков (5 минут).',
        since: latestIso(sources.map((source) => minuteOf(lastMinutes, source.sourceId))),
        objectId: collector.collectorId,
        i18nParams: { name, collector: name },
      }));
      continue;
    }
    if (collector.state !== 'online') continue;
    for (const source of sources) {
      if (source.isLive) continue;
      const sourceName = source.sourceName || source.sourceId || 'Источник';
      problems.push(makeProblem('collectors', 'source_silent', {
        level: 'warning',
        title: `${sourceName} молчит`,
        message: `Источник коллектора ${name} не виден в окне живых потоков (5 минут).`,
        since: minuteOf(lastMinutes, source.sourceId),
        objectId: source.sourceId,
        i18nParams: { source: sourceName, collector: name },
      }));
    }
  }
  return problems;
}

function detectionProblems(minute, now) {
  if (!minute || !Number.isFinite(minute.ts)) {
    return [makeProblem('detection', 'detection_empty', {
      level: 'critical',
      title: CODE_TITLE.detection_empty,
      message: 'За последние сутки детекция не записала ни одной минуты.',
      i18nParams: {},
    })];
  }
  const lagMs = now - minute.ts;
  if (lagMs <= DETECTION_STALE_MS) return [];
  const lagMin = Math.max(1, Math.round(lagMs / MINUTE));
  return [makeProblem('detection', 'detection_stale', {
    level: 'critical',
    title: CODE_TITLE.detection_stale,
    message: `Новых минут детекции нет уже ${lagMin} мин.`,
    since: minute.iso,
    i18nParams: { lagMin, mins: lagMin },
  })];
}

function clickhouseProblems(pingOk, error) {
  if (pingOk) return [];
  const message = cleanText(error, 180) || 'ClickHouse не отвечает';
  return [makeProblem('clickhouse', 'clickhouse_down', {
    level: 'critical',
    title: CODE_TITLE.clickhouse_down,
    message,
    i18nParams: { detail: message },
  })];
}

function statusOf(problems) {
  if (problems.some((item) => item.level === 'critical')) return 'critical';
  if (problems.some((item) => item.level === 'warning')) return 'warning';
  return 'ok';
}

function detectionMeta(minute, now, readable) {
  if (!readable) {
    return {
      detectionMinute: null,
      detectionMinuteIso: null,
      detectionLagSec: null,
      detectionStale: true,
      detectionEmpty: false,
    };
  }
  if (!minute || !Number.isFinite(minute.ts)) {
    return {
      detectionMinute: null,
      detectionMinuteIso: null,
      detectionLagSec: null,
      detectionStale: true,
      detectionEmpty: true,
    };
  }
  const lagMs = Math.max(0, now - minute.ts);
  return {
    detectionMinute: minute.wall,
    detectionMinuteIso: minute.iso,
    detectionLagSec: Math.floor(lagMs / 1000),
    detectionStale: lagMs > DETECTION_STALE_MS,
    detectionEmpty: false,
  };
}

function buildMonitoringView({
  now = Date.now(),
  collectors = { ok: true, collectors: [] },
  lastMinutes = new Map(),
  detection = { ok: true, minute: null },
  clickhouse = { ok: true, pingOk: true },
  worker = { ok: true, problems: [] },
  enrichment = { ok: true, problems: [], jobs: [] },
  snmp = { ok: true, problems: [], job: null },
} = {}) {
  const byComponent = {
    collectors: collectors.ok
      ? collectorProblems(collectors.collectors, lastMinutes)
      : [checkFailed('collectors', collectors.error)],
    detection: detection.ok
      ? detectionProblems(detection.minute, now)
      : [checkFailed('detection', detection.error)],
    worker: worker.ok
      ? (worker.problems || []).map((item) => mapExisting('worker', item, now, workerSince(item, now)))
      : [checkFailed('worker', worker.error)],
    clickhouse: clickhouse.ok
      ? clickhouseProblems(clickhouse.pingOk, clickhouse.error)
      : [checkFailed('clickhouse', clickhouse.error)],
    enrichment: enrichment.ok
      ? (enrichment.problems || []).map((item) => mapExisting(
        'enrichment',
        item,
        now,
        enrichmentSince(item, enrichment.jobs),
      ))
      : [checkFailed('enrichment', enrichment.error)],
    snmp: snmp.ok
      ? (snmp.problems || []).map((item) => mapExisting('snmp', item, now, snmpSince(item, snmp.job)))
      : [checkFailed('snmp', snmp.error)],
  };

  const problems = COMPONENTS.flatMap((item) => byComponent[item.id] || []);
  problems.sort((a, b) => {
    const componentDelta = COMPONENTS.findIndex((item) => item.id === a.component)
      - COMPONENTS.findIndex((item) => item.id === b.component);
    if (componentDelta) return componentDelta;
    const levelDelta = (a.level === 'critical' ? 0 : 1) - (b.level === 'critical' ? 0 : 1);
    return levelDelta || a.id.localeCompare(b.id);
  });

  return {
    meta: {
      checkedAt: new Date(now).toISOString(),
      ...detectionMeta(detection.minute, now, detection.ok),
    },
    components: COMPONENTS.map((item) => ({
      id: item.id,
      title: item.title,
      status: statusOf(byComponent[item.id] || []),
    })),
    problems,
  };
}

function silentSourceIds(collectors) {
  const ids = [];
  for (const collector of collectors || []) {
    if (!collector || collector.state === 'empty') continue;
    for (const source of collector.sources || []) {
      if (collector.state === 'offline' || !source.isLive) ids.push(String(source.sourceId || ''));
    }
  }
  return [...new Set(ids.filter(Boolean))];
}

async function loadSourceLastMinutes(sourceIds) {
  if (!sourceIds.length) return new Map();
  const { rows } = await query(`
    SELECT source_id, max(minute) AS last_minute
    FROM ${config.database}.traffic_direction_1m
    WHERE minute >= now('UTC') - INTERVAL 1 DAY
      AND source_id IN {ids:Array(String)}
    GROUP BY source_id
  `, { ids: sourceIds }, { name: 'monitoring/source-last-minute' });
  const map = new Map();
  for (const row of rows) {
    const ts = parseUtc(row.last_minute);
    if (Number.isFinite(ts)) map.set(String(row.source_id), new Date(ts).toISOString());
  }
  return map;
}

async function readDetectionMinute() {
  const { rows } = await query(
    `SELECT max(minute) AS last_minute FROM ${tableRef()} WHERE minute >= now('UTC') - INTERVAL 1 DAY`,
    {},
    { name: 'monitoring/detection-minute' },
  );
  const ts = parseUtc(rows[0]?.last_minute);
  if (!Number.isFinite(ts) || ts < Date.UTC(2020, 0, 1)) return null;
  return {
    wall: formatCh(ts),
    iso: new Date(ts).toISOString(),
    ts,
  };
}

async function settle(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, error: err };
  }
}

async function getMonitoringProblems(now = Date.now()) {
  const [overview, detection, health, worker, enrichment, snmp] = await Promise.all([
    settle(() => fetchCollectorOverview()),
    settle(() => readDetectionMinute()),
    settle(() => ping()),
    settle(() => getWorkerDiagnostics()),
    settle(() => getEnrichmentDiagnostics()),
    settle(() => getSnmpDiagnostics()),
  ]);

  const collectors = overview.ok ? (overview.value?.data?.collectors || []) : [];
  let lastMinutes = new Map();
  if (overview.ok) {
    try {
      lastMinutes = await loadSourceLastMinutes(silentSourceIds(collectors));
    } catch {
      lastMinutes = new Map();
    }
  }

  return buildMonitoringView({
    now,
    collectors: overview.ok
      ? { ok: true, collectors }
      : { ok: false, error: overview.error },
    lastMinutes,
    detection: detection.ok
      ? { ok: true, minute: detection.value }
      : { ok: false, error: detection.error },
    clickhouse: health.ok
      ? { ok: true, pingOk: health.value?.ok === true, error: health.value?.error }
      : { ok: false, error: health.error },
    worker: worker.ok
      ? { ok: true, problems: worker.value?.problems || [] }
      : { ok: false, error: worker.error },
    enrichment: enrichment.ok
      ? { ok: true, problems: enrichment.value?.problems || [], jobs: enrichment.value?.jobs || [] }
      : { ok: false, error: enrichment.error },
    snmp: snmp.ok
      ? { ok: true, problems: snmp.value?.problems || [], job: snmp.value?.job || null }
      : { ok: false, error: snmp.error },
  });
}

function attackHistoryWindow(event, now = Date.now()) {
  const start = parseUtc(event?.startMinute) || parseUtc(event?.alertMinute);
  const anchor = Number.isFinite(start) ? start : now - 2 * 60 * MINUTE;
  const fromTs = anchor - HISTORY_LEAD_MS;
  const endMinute = event?.status === 'peak' ? event?.alertMinute : event?.normalizeMinute;
  const endTs = event?.status !== 'active' ? parseUtc(endMinute) : NaN;
  const lastTs = Number.isFinite(endTs) ? Math.min(now, endTs + HISTORY_LEAD_MS) : now;
  const toTs = Math.max(lastTs, fromTs + MINUTE);
  return { from: formatCh(fromTs), to: formatCh(toTs) };
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function mergeAttackHistoryPoints(bpsPoints, growthPoints) {
  const byT = new Map();
  for (const point of bpsPoints || []) {
    byT.set(point.t, {
      t: point.t,
      bucketMs: point.bucketMs,
      bps: finiteNumber(point.v ?? point.bps),
      growthBps: null,
      baselineBps: null,
    });
  }
  for (const point of growthPoints || []) {
    const row = byT.get(point.t) || {
      t: point.t,
      bucketMs: point.bucketMs,
      bps: null,
      growthBps: null,
      baselineBps: null,
    };
    const growth = finiteNumber(point.v ?? point.bps);
    row.growthBps = growth;
    if (row.bps > 0 && growth > 0) row.baselineBps = row.bps / growth;
    byT.set(point.t, row);
  }
  return [...byT.values()].sort((a, b) => (a.bucketMs || 0) - (b.bucketMs || 0));
}

function attackSliceMinute(event) {
  const minute = event?.live?.lastHotMinute || event?.focusMinute || event?.alertMinute;
  return Number.isFinite(parseUtc(minute)) ? minute : null;
}

async function loadAttackHistory(event, now = Date.now()) {
  const requested = attackHistoryWindow(event, now);
  const queryArgs = {
    scope: event.scope,
    scopeId: event.scopeId,
    proto: 'all',
    from: requested.from,
    to: requested.to,
  };
  const [bps, growth] = await Promise.all([
    loadHistory({ ...queryArgs, metric: 'bps' }),
    loadHistory({ ...queryArgs, metric: 'growthBps' }),
  ]);
  return {
    eventId: event.id,
    scope: event.scope,
    scopeId: event.scopeId,
    from: bps.from || requested.from,
    to: bps.to || requested.to,
    alertMinute: event.alertMinute || null,
    points: mergeAttackHistoryPoints(bps.points, growth.points),
  };
}

module.exports = {
  DETECTION_STALE_MS,
  COMPONENTS,
  buildMonitoringView,
  getMonitoringProblems,
  attackHistoryWindow,
  mergeAttackHistoryPoints,
  attackSliceMinute,
  loadAttackHistory,
  shortPublicError,
  silentSourceIds,
  loadSourceLastMinutes,
};
