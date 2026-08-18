'use strict';

const fs = require('fs');
const path = require('path');
const { query, executeCommand, parseDataDatetimeSql } = require('./clickhouse');
const {
  explorerTimeseries,
  explorerSchema,
  explorerFlows,
  explorerResultSeries,
  parseExplorerAsnNumber,
  asnExplorerDisplayLabel,
  lookupAsnDisplayNames,
  explorerEntityDisplayLabel,
  lookupEntityDisplayNames,
  buildSummaryFromFlowRows: summaryFromExplorerFlowRows,
} = require('./explorer');
const {
  normalizeExplorerThresholds,
  explorerThresholdsActive,
  describeThresholds,
} = require('./explorer-thresholds');
const { protocolChartColor } = require('./protocol-colors');
const { tcpFlagsMaskToLabel } = require('./tcp-flags');
const { getMergedDiagnosticsPayload } = require('./analytics-diagnostics');
const {
  ensureObservationsStore,
  loadAllObservations,
  loadObservationById,
  upsertObservation,
  softDeleteObservation,
  loadRunsForObservation,
  loadRunById,
  insertRun,
  lastSuccessfulRunAt: storeLastSuccessfulRunAt,
} = require('./observations-store');
const {
  normalizeSchedule,
  reportWindowForPeriod,
  isScheduleDue,
  DEFAULT_TIMEZONE,
} = require('./observation-schedule');
const { getSmtpSettings, sendSmtpMail } = require('./smtp-settings');
const { renderChartPng } = require('./report-chart-png');

const ARTIFACTS_DIR = path.join(__dirname, 'data', 'observation_runs');
const CHART_IMAGE_FILE = 'chart.png';
const CHART_IMAGE_CID = 'observation-chart';

/** Строк в таблице топа (просмотр и top-*.csv отчёта); «Прочие» добавляется сверх. */
const TOP_ROWS_LIMIT = 100;
/** Линий на графике — больше не читается; остаток уходит в «Прочие». */
const CHART_SERIES_LIMIT = 10;

/** 0 / unset = no hard limit. Positive OBSERVATION_MAX_MATERIALIZE re-enables a cap. */
const MAX_MATERIALIZE = (() => {
  if (process.env.OBSERVATION_MAX_MATERIALIZE == null || process.env.OBSERVATION_MAX_MATERIALIZE === '') {
    return 0;
  }
  const n = Number(process.env.OBSERVATION_MAX_MATERIALIZE);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
})();
const MATERIALIZE_LIMIT_ENABLED = MAX_MATERIALIZE > 0;
/** Worker loop tick (catch-up when lagging). Per-observation cadence is ≥ MIN_REFRESH_SEC. */
const MIN_INTERVAL_SEC = 60;
/** Min live refresh / materialize cadence — один шаг rollup-бакета. */
const MIN_REFRESH_SEC = 300;
/** Observation rollup bucket (aligned with dashboard 5m charts). */
const ROLLUP_TABLE = 'observation_rollups_5m';
const ROLLUP_BUCKET_SEC = 300;
/** Сколько измерений разреза хранит rollup — колонки dim0…dim3. */
const ROLLUP_DIM_COUNT = 4;
const DEFAULT_TTL_HINT_DAYS = 14;
const BACKFILL_HOURS = Math.max(0, Number(process.env.OBSERVATION_BACKFILL_HOURS) || 24);
const STUCK_SEC = Math.max(60, Number(process.env.OBSERVATION_ROLLUP_STUCK_SEC) || 900);
const MAX_FAIL_COUNT = 10;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/** Absolute origin for report links; relative links still work in the browser. */
const REPORT_BASE_URL = String(process.env.OBSERVATION_REPORT_BASE_URL || '').replace(/\/+$/, '');
const REPORT_HTML_TOP_ROWS = 100;
/** Everything outside the stored top-N is folded into one bucket. */
const OTHER_KEY = '__other__';
const OTHER_LABEL = 'Прочие';
const OTHER_COLOR = '#9aa0a6';

const NATIVE_FILTER_FIELDS = new Set([
  'direction', 'collector', 'vlan', 'vlan_attachment',
  'src_asn', 'dst_asn', 'proto', 'src_country', 'dst_country',
]);

const LOOKBACKS = new Set(['15m', '30m', '1h', '6h', '24h', '7d']);
const REFRESH_SECS = new Set([300, 900]);
const WIDGET_TYPES = new Set(['timeseries_bps', 'top_table']);

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function newId(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function looksLikeCidr(value) {
  const s = String(value ?? '').trim();
  return /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(s)
    || /^[0-9a-fA-F:]+\/\d{1,3}$/.test(s);
}

function normalizeFilters(filters) {
  if (!Array.isArray(filters)) return [];
  return filters.map((f, i) => {
    const field = String(f.field || '').trim();
    let op = String(f.op || '=').trim();
    const value = f.value ?? '';
    // CIDR value with "=" never matches — coerce to cidr for IP fields
    if (
      looksLikeCidr(value)
      && (op === '=' || op === '==' || op === 'contains')
      && (field === 'src_ip' || field === 'dst_ip' || field === 'own_network' || field.endsWith('_ip'))
    ) {
      op = 'cidr';
    }
    return {
      id: f.id || `f-${i}`,
      field,
      op,
      value,
      label: f.label ?? null,
      logic: f.logic || 'and',
    };
  }).filter((f) => f.field);
}

function normalizeWidgets(widgets) {
  if (!Array.isArray(widgets) || !widgets.length) {
    return [
      { id: 'w-ts', type: 'timeseries_bps', metric: 'bps', groupBy: [], limit: null },
      { id: 'w-asn', type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: TOP_ROWS_LIMIT },
    ];
  }
  return widgets.map((w, i) => ({
    id: w.id || `w-${i}`,
    type: WIDGET_TYPES.has(w.type) ? w.type : 'top_table',
    metric: w.metric || 'bps',
    groupBy: Array.isArray(w.groupBy) ? w.groupBy.map(String) : [],
    // Лимиты не настраиваются пользователем — держим единые значения.
    limit: w.type === 'timeseries_bps' ? null : TOP_ROWS_LIMIT,
    seriesLimit: w.type === 'timeseries_bps' ? CHART_SERIES_LIMIT : undefined,
  }));
}

function collectWidgetGroupFields(widgets = []) {
  // Do not apply normalizeWidgets defaults here — empty widgets means "no groupBy".
  if (!Array.isArray(widgets) || !widgets.length) return [];
  const fields = [];
  for (const w of widgets) {
    for (const g of w.groupBy || []) {
      const field = String(g || '').trim();
      if (field) fields.push(field);
    }
  }
  return fields;
}

/**
 * Live observation always uses personal rollup when there is any filter or groupBy.
 * (Earlier "native" shortcut skipped rollup for proto/collector/asn/… and broke
 * charts that group by non-aggregate dims like tcp_flags.)
 * Empty filters + empty groupBy → total traffic from traffic_* (no materialize).
 */
function classifyScope(filters, widgets = []) {
  const list = normalizeFilters(filters);
  const groupFields = collectWidgetGroupFields(widgets);
  const fields = [...new Set([
    ...list.map((f) => f.field),
    ...groupFields,
  ])];

  if (!fields.length) {
    return {
      tier: 'native',
      materializeRequired: false,
      reason: 'Нет фильтров и группировок — общий трафик (native агрегаты)',
    };
  }
  return {
    tier: 'materialize_required',
    materializeRequired: true,
    reason: `Для live нужен rollup по фильтрам/группировке: ${fields.join(', ')}`,
    fields,
  };
}

function isActiveMaterialize(o, exceptId = null) {
  return o.id !== exceptId
    && o.materialize?.enabled
    && classifyScope(o.filters, o.widgets).materializeRequired;
}

function countActiveMaterialize(items, exceptId = null) {
  return items.filter((o) => isActiveMaterialize(o, exceptId)).length;
}

function materializeOccupants(items, exceptId = null) {
  return items
    .filter((o) => isActiveMaterialize(o, exceptId))
    .map((o) => ({ id: o.id, name: o.name || o.id }));
}

function quotaError(items, exceptId = null) {
  const occupants = materializeOccupants(items, exceptId);
  const err = new Error(
    `Достигнут лимит материализаций (${MAX_MATERIALIZE}). Отключите другое live-наблюдение.`,
  );
  err.status = 400;
  err.occupants = occupants;
  err.quotas = { maxMaterialize: MAX_MATERIALIZE, activeMaterialize: occupants.length };
  return err;
}

function normalizeEmailTo(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const item of list) {
    const s = String(item || '').trim();
    if (!s) continue;
    if (!EMAIL_RE.test(s)) {
      const err = new Error(`Некорректный email: ${s}`);
      err.status = 400;
      throw err;
    }
    out.push(s);
    if (out.length > 10) {
      const err = new Error('Не больше 10 адресов в emailTo');
      err.status = 400;
      throw err;
    }
  }
  return out;
}

/** Ширина плитки не настраивается — всегда одна колонка (раскрытие даёт полную ширину). */
function normalizeLayout(raw, existing) {
  const src = raw?.layout != null ? raw.layout : existing?.layout;
  const order = Number(src && typeof src === 'object' ? src.order : 0);
  return {
    order: Number.isFinite(order) ? order : 0,
    width: 1,
  };
}

function initBackfillFields(createdAt, existingMat = {}) {
  if (existingMat.backfillDone && existingMat.backfillFrom) {
    return {
      backfillFrom: existingMat.backfillFrom,
      backfillCursor: existingMat.backfillCursor || existingMat.backfillFrom,
      backfillDone: true,
    };
  }
  const createdMs = new Date(createdAt).getTime();
  const fromMs = Number.isFinite(createdMs)
    ? createdMs - BACKFILL_HOURS * 3600 * 1000
    : Date.now() - BACKFILL_HOURS * 3600 * 1000;
  const backfillFrom = new Date(Math.max(0, fromMs)).toISOString();
  return {
    backfillFrom,
    backfillCursor: existingMat.backfillCursor || backfillFrom,
    backfillDone: Boolean(existingMat.backfillDone),
  };
}

function disabledBackfillFields() {
  return { backfillFrom: null, backfillCursor: null, backfillDone: true };
}

function wantsHistoryBackfill(rawMat = {}) {
  return rawMat?.backfill === true || rawMat?.backfill === 'true';
}

/** History before createdAt is opt-in. Default: count from creation only. */
function resolveObservationBackfill({
  materializeEnabled,
  wasEnabled,
  createdAt,
  existingMat = {},
  rawMat = {},
} = {}) {
  const current = {
    backfillFrom: existingMat.backfillFrom ?? null,
    backfillCursor: existingMat.backfillCursor ?? null,
    backfillDone: Boolean(existingMat.backfillDone),
  };
  if (!materializeEnabled) return current;
  if (!wasEnabled) {
    return wantsHistoryBackfill(rawMat)
      ? initBackfillFields(createdAt, {})
      : disabledBackfillFields();
  }
  if (!current.backfillFrom && !current.backfillDone) return disabledBackfillFields();
  return current;
}

function isObservationOwner(item, userId) {
  if (!item) return false;
  const owner = String(item.ownerId || '').trim();
  const uid = String(userId || '').trim();
  if (!owner) return true;
  return owner === uid;
}

function materializeWarning(activeCount) {
  if (MATERIALIZE_LIMIT_ENABLED) {
    return `Подготовка данных: ${activeCount}/${MAX_MATERIALIZE}`;
  }
  return null;
}

function normalizeObservation(raw = {}, { userId, existing = null } = {}) {
  const filters = normalizeFilters(raw.filters != null ? raw.filters : existing?.filters);
  const thresholds = normalizeExplorerThresholds(
    raw.thresholds != null ? raw.thresholds : (existing?.thresholds || []),
  );
  const widgets = normalizeWidgets(raw.widgets != null ? raw.widgets : existing?.widgets);
  const scope = classifyScope(filters, widgets);
  const lookback = LOOKBACKS.has(raw.lookback) ? raw.lookback : (existing?.lookback || '1h');
  // Live не настраивается: доска всегда обновляется раз в 5 минут (запас на late flows).
  const refreshSec = MIN_REFRESH_SEC;
  const liveEnabled = true;

  // Подготовка данных (rollup) — отдельное решение: она и создаёт нагрузку на ClickHouse.
  let materializeEnabled = Boolean(raw.materialize?.enabled ?? existing?.materialize?.enabled);
  if (!scope.materializeRequired) materializeEnabled = false;

  // Worker cadence follows live.refreshSec (same setting as UI), floor 5 minutes.
  let intervalSec = Number(raw.materialize?.intervalSec ?? existing?.materialize?.intervalSec ?? refreshSec);
  if (!Number.isFinite(intervalSec) || intervalSec < MIN_REFRESH_SEC) intervalSec = refreshSec;
  intervalSec = Math.max(MIN_REFRESH_SEC, intervalSec, refreshSec);

  const createdAt = existing?.createdAt || raw.createdAt || new Date().toISOString();
  const wasEnabled = Boolean(existing?.materialize?.enabled);
  let cursorMinute = existing?.materialize?.cursorMinute ?? raw.materialize?.cursorMinute ?? null;
  let matStatus = existing?.materialize?.status || (materializeEnabled ? 'queued' : 'idle');
  let backfill = resolveObservationBackfill({
    materializeEnabled,
    wasEnabled,
    createdAt,
    existingMat: existing?.materialize || {},
    rawMat: raw.materialize || {},
  });
  if (materializeEnabled && !wasEnabled) {
    // Live from creation. History backfill only if materialize.backfill === true.
    matStatus = 'queued';
    cursorMinute = createdAt;
  }
  if (!materializeEnabled) {
    matStatus = 'idle';
  } else if (matStatus === 'idle') {
    matStatus = 'queued';
  }

  const reportRaw = raw.report != null ? raw.report : (existing?.report || {});
  const schedule = normalizeSchedule(reportRaw, existing?.report || {});

  return {
    id: existing?.id || raw.id || newId('obs'),
    name: String(raw.name ?? existing?.name ?? 'Без названия').trim() || 'Без названия',
    description: String(raw.description ?? existing?.description ?? '').trim(),
    folder: String(raw.folder ?? existing?.folder ?? 'Мои наблюдения').trim() || 'Мои наблюдения',
    ownerId: existing?.ownerId || userId || 'anonymous',
    // Наблюдения всегда видны всем; редактировать по-прежнему может владелец.
    isShared: true,
    filters,
    thresholds,
    lookback,
    widgets,
    layout: normalizeLayout(raw, existing),
    live: {
      enabled: liveEnabled,
      refreshSec,
    },
    materialize: {
      enabled: materializeEnabled,
      intervalSec,
      status: matStatus,
      lagSeconds: existing?.materialize?.lagSeconds ?? null,
      lastCatchupAt: existing?.materialize?.lastCatchupAt ?? null,
      lastError: existing?.materialize?.lastError ?? null,
      cursorMinute,
      failCount: Number(existing?.materialize?.failCount) || 0,
      nextAttemptAt: existing?.materialize?.nextAttemptAt ?? null,
      cancelRequested: Boolean(existing?.materialize?.cancelRequested),
      runningStartedAt: existing?.materialize?.runningStartedAt ?? null,
      dataThrough: existing?.materialize?.dataThrough ?? null,
      ...backfill,
    },
    report: {
      enabled: Boolean(reportRaw.enabled ?? false),
      period: ['yesterday', 'last_24h'].includes(reportRaw.period)
        ? reportRaw.period
        : (existing?.report?.period || 'yesterday'),
      schedule,
      emailTo: normalizeEmailTo(
        Array.isArray(reportRaw.emailTo) ? reportRaw.emailTo : (existing?.report?.emailTo || []),
      ),
    },
    createdAt,
    updatedAt: new Date().toISOString(),
  };
}

async function withMeta(item, allItems = null) {
  const scope = classifyScope(item.filters, item.widgets);
  const all = allItems || await loadAllObservations();
  const active = countActiveMaterialize(all);
  const warnings = [];
  if (scope.materializeRequired && item.materialize?.enabled) {
    const mw = materializeWarning(active);
    if (mw) warnings.push(mw);
  }
  if (item.materialize?.lastError) {
    warnings.push(`Ошибка подготовки данных: ${item.materialize.lastError}`);
  }
  const report = {
    ...(item.report || {}),
    schedule: (item.report && item.report.schedule && item.report.schedule.kind)
      ? item.report.schedule
      : normalizeSchedule(item.report || {}, item.report || {}),
  };
  // Drop legacy dead fields from API responses.
  delete report.cron;
  delete report.formats;
  delete report.timezone;

  return {
    ...item,
    report,
    scope,
    quotas: {
      maxMaterialize: MATERIALIZE_LIMIT_ENABLED ? MAX_MATERIALIZE : null,
      activeMaterialize: active,
      minIntervalSec: MIN_INTERVAL_SEC,
      occupants: materializeOccupants(all),
    },
    warnings,
    backfillProgress: backfillProgress(item.materialize),
  };
}

async function listObservations(userId) {
  const all = await loadAllObservations();
  const visible = all.filter((item) => item.isShared
    || !String(item.ownerId || '').trim()
    || isObservationOwner(item, userId));
  return Promise.all(visible.map((item) => withMeta(item, all)));
}

async function getObservation(id, userId) {
  const item = await loadObservationById(id);
  if (!item) return null;
  if (!item.isShared
    && String(item.ownerId || '').trim()
    && !isObservationOwner(item, userId)) return null;
  return withMeta(item);
}

async function createObservation(userId, payload = {}) {
  const items = await loadAllObservations();
  const item = normalizeObservation(payload, { userId });
  if (MATERIALIZE_LIMIT_ENABLED
    && item.materialize.enabled
    && countActiveMaterialize(items) >= MAX_MATERIALIZE) {
    throw quotaError(items);
  }
  if (item.materialize.enabled) item.materialize.status = 'queued';
  await upsertObservation(item);
  return withMeta(item, [...items, item]);
}

async function updateObservation(id, userId, payload = {}) {
  const items = await loadAllObservations();
  const existing = items.find((row) => row.id === id);
  if (!existing) return null;
  if (!isObservationOwner(existing, userId)) return null;
  const next = normalizeObservation(payload, { userId, existing });
  if (MATERIALIZE_LIMIT_ENABLED
    && next.materialize.enabled
    && countActiveMaterialize(items, id) >= MAX_MATERIALIZE) {
    throw quotaError(items, id);
  }
  if (next.materialize.enabled && !existing.materialize?.enabled) {
    next.materialize.status = 'queued';
    next.materialize.cursorMinute = existing.createdAt || next.createdAt;
    Object.assign(
      next.materialize,
      wantsHistoryBackfill(payload.materialize)
        ? initBackfillFields(existing.createdAt || next.createdAt, {})
        : disabledBackfillFields(),
    );
    next.materialize.failCount = 0;
    next.materialize.nextAttemptAt = null;
    next.materialize.cancelRequested = false;
  }
  await upsertObservation(next);
  return withMeta(next, items.map((row) => (row.id === id ? next : row)));
}

async function duplicateObservation(id, userId) {
  const existing = await getObservation(id, userId);
  if (!existing) return null;
  if (!isObservationOwner(existing, userId) && !existing.isShared) return null;
  const copy = normalizeObservation({
    ...existing,
    id: undefined,
    name: `${existing.name} (копия)`,
    materialize: {
      ...(existing.materialize || {}),
      enabled: false,
      status: 'idle',
      cursorMinute: null,
      cancelRequested: false,
      failCount: 0,
      nextAttemptAt: null,
      runningStartedAt: null,
      lastError: null,
      backfillDone: false,
      backfillFrom: null,
      backfillCursor: null,
    },
    report: {
      ...(existing.report || {}),
      enabled: false,
    },
    createdAt: undefined,
    updatedAt: undefined,
  }, { userId });
  await upsertObservation(copy);
  return withMeta(copy);
}

async function cancelMaterialize(id, userId) {
  const items = await loadAllObservations();
  const existing = items.find((row) => row.id === id);
  if (!existing) return null;
  if (!isObservationOwner(existing, userId)) return null;
  const next = {
    ...existing,
    materialize: {
      ...(existing.materialize || {}),
      cancelRequested: true,
    },
    updatedAt: new Date().toISOString(),
  };
  // If not currently running, stop immediately.
  if (existing.materialize?.status !== 'running') {
    next.materialize.status = 'idle';
    next.materialize.cancelRequested = false;
    next.materialize.enabled = false;
  }
  await upsertObservation(next);
  return withMeta(next, items.map((row) => (row.id === id ? next : row)));
}

async function deleteObservation(id, userId) {
  const item = await getObservation(id, userId);
  if (!item || !isObservationOwner(item, userId)) return false;
  await softDeleteObservation(item);
  // best-effort rollup cleanup (needs write privileges)
  executeCommand(`
    ALTER TABLE default.${ROLLUP_TABLE}
    DELETE WHERE observation_id = {id:String}
  `, { id }, { name: 'observations/rollup-cleanup' }).catch(() => {});
  return true;
}

async function queueMaterialize(id, userId) {
  const items = await loadAllObservations();
  const existing = items.find((row) => row.id === id);
  if (!existing) return null;
  if (!isObservationOwner(existing, userId)) return null;
  const scope = classifyScope(existing.filters, existing.widgets);
  if (!scope.materializeRequired) {
    const err = new Error('Для этого scope materialize не нужен (native агрегаты).');
    err.status = 400;
    throw err;
  }
  if (MATERIALIZE_LIMIT_ENABLED
    && countActiveMaterialize(items, id) >= MAX_MATERIALIZE
    && !existing.materialize?.enabled) {
    throw quotaError(items, id);
  }
  const refreshSec = Math.max(
    MIN_REFRESH_SEC,
    Number(existing.live?.refreshSec) || MIN_REFRESH_SEC,
  );
  const next = {
    ...existing,
    materialize: {
      ...(existing.materialize || {}),
      enabled: true,
      intervalSec: refreshSec,
      status: 'queued',
      // Live from creation — do not null cursor (null used to fall back to 24h backfill).
      cursorMinute: existing.materialize?.cursorMinute || existing.createdAt || new Date().toISOString(),
    },
    live: { ...(existing.live || {}), enabled: true, refreshSec },
    updatedAt: new Date().toISOString(),
  };
  if (!existing.materialize?.enabled) {
    next.materialize.cursorMinute = existing.createdAt || new Date().toISOString();
  }
  await upsertObservation(next);
  return withMeta(next, items.map((row) => (row.id === id ? next : row)));
}

const ROLLUP_BUCKET_MS = ROLLUP_BUCKET_SEC * 1000;

function floorToRollupBucket(ms) {
  return Math.floor(Number(ms) / ROLLUP_BUCKET_MS) * ROLLUP_BUCKET_MS;
}

/**
 * Правый край готовых данных rollup: dataThrough — метка последнего записанного
 * бакета, поэтому окно заканчивается на бакет позже. Опираться на wall clock
 * нельзя — последний бакет ещё не закрыт, и график упирался бы в пустоту.
 */
function previewWindowEndMs(obs) {
  const through = Date.parse(obs?.materialize?.dataThrough || '');
  if (Number.isFinite(through)) {
    return Math.min(through + ROLLUP_BUCKET_MS, Date.now());
  }
  const cursor = Date.parse(obs?.materialize?.cursorMinute || '');
  if (Number.isFinite(cursor)) {
    return Math.min(cursor, Date.now());
  }
  return Date.now();
}

function lookbackWindow(lookback, endMs = Date.now()) {
  const map = {
    '15m': 15 * 60 * 1000,
    '30m': 30 * 60 * 1000,
    '1h': 3600 * 1000,
    '6h': 6 * 3600 * 1000,
    '24h': 86400 * 1000,
    '7d': 7 * 86400 * 1000,
  };
  const ms = map[lookback] || 3600 * 1000;
  const toMs = Number(endMs) || Date.now();
  const fromMs = floorToRollupBucket(toMs - ms);
  return {
    range: 'custom',
    from: new Date(fromMs).toISOString(),
    to: new Date(toMs).toISOString(),
  };
}

function resolvePreviewWindow(obs, body = {}) {
  if (body.from && body.to) {
    return { range: 'custom', from: String(body.from), to: String(body.to) };
  }
  return lookbackWindow(body.lookback || obs.lookback, previewWindowEndMs(obs));
}

function reportWindow(obs, now = new Date()) {
  const schedule = obs.report?.schedule || normalizeSchedule(obs.report || {}, obs.report || {});
  return reportWindowForPeriod(obs.report?.period || 'yesterday', schedule, now);
}

function observationChartGroupBy(obs, timeseriesWidget) {
  if (timeseriesWidget?.groupBy?.length) return timeseriesWidget.groupBy.map(String);
  const top = (obs.widgets || []).find((w) => w.type === 'top_table' && w.groupBy?.length);
  return top ? top.groupBy.map(String) : [];
}

/**
 * Лимиты фиксированы и не берутся из сохранённого наблюдения: 100 линий на графике
 * нечитаемы, а остаток всё равно виден как «Прочие». Иначе старые наблюдения
 * остались бы со своими 8/15 без миграции.
 */
function observationSeriesLimit() {
  return CHART_SERIES_LIMIT;
}

/** Колонки разреза rollup: dim0…dim3. */
function rollupDimColumns(count = ROLLUP_DIM_COUNT) {
  const n = Math.min(Math.max(Number(count) || 1, 1), ROLLUP_DIM_COUNT);
  return Array.from({ length: n }, (_, i) => `dim${i}`);
}

/**
 * Ключ серии — значения ровно тех колонок, которые занимает разрез. Для одного и
 * двух измерений совпадает с прежним форматом, поэтому старые строки rollup
 * читаются без миграции данных.
 */
function dimKey(values, count) {
  const list = Array.isArray(values) ? values : [values];
  const n = Math.min(Math.max(Number(count) || list.length || 1, 1), ROLLUP_DIM_COUNT);
  return Array.from({ length: n }, (_, i) => String(list[i] ?? '')).join('|');
}

function dimKeyFromRow(row, count) {
  return dimKey(rollupDimColumns(count).map((c) => row[c]), count);
}

function dimLabel(values) {
  const shown = (Array.isArray(values) ? values : [values])
    .map((v) => String(v ?? '').trim())
    .filter(Boolean);
  return shown.length ? shown.join(' · ') : '—';
}

/** Итоговые строки rollup помечены пустыми значениями во всех колонках разреза. */
function rollupTotalRowSql() {
  return rollupDimColumns().map((c) => `${c} = ''`).join('\n        AND ');
}

function rollupGroupedRowSql() {
  return `NOT (${rollupDimColumns().map((c) => `${c} = ''`).join(' AND ')})`;
}

/** SQL-ключ серии; должен совпадать с dimKey для того же разреза. */
function rollupKeySql(count) {
  const cols = rollupDimColumns(count);
  return cols.length > 1 ? `arrayStringConcat([${cols.join(', ')}], '|')` : cols[0];
}

function asnGroupIndexes(groupBy = []) {
  return groupBy
    .map((g, i) => (g === 'src_asn' || g === 'dst_asn' ? i : -1))
    .filter((i) => i >= 0);
}

/** Enrich ASN group labels with registry names (rollup stores raw AS123…). */
async function enrichAsnLabelsInRows(rows, groupBy = []) {
  const indexes = asnGroupIndexes(groupBy);
  if (!indexes.length || !rows?.length) return rows || [];

  const asnNums = new Set();
  for (const row of rows) {
    for (const idx of indexes) {
      const n = parseExplorerAsnNumber(row.rawValues?.[idx] ?? row.values?.[idx]);
      if (n != null) asnNums.add(n);
    }
  }
  const nameMap = await lookupAsnDisplayNames([...asnNums]);
  return rows.map((row) => {
    const rawValues = Array.isArray(row.rawValues)
      ? [...row.rawValues]
      : [...(row.values || [])];
    const values = Array.isArray(row.values) ? [...row.values] : [...rawValues];
    for (const idx of indexes) {
      const asn = parseExplorerAsnNumber(rawValues[idx] ?? values[idx]);
      if (asn == null) continue;
      values[idx] = asnExplorerDisplayLabel(asn, nameMap.get(asn) || '');
    }
    return { ...row, values, rawValues };
  });
}

function entityGroupIndexes(groupBy = []) {
  return groupBy
    .map((g, i) => (g === 'src_entity' || g === 'dst_entity' ? i : -1))
    .filter((i) => i >= 0);
}

/** Rollup хранит entity_id; в UI показываем display_name из справочника. */
async function enrichEntityLabelsInRows(rows, groupBy = []) {
  const indexes = entityGroupIndexes(groupBy);
  if (!indexes.length || !rows?.length) return rows || [];

  const ids = new Set();
  for (const row of rows) {
    for (const idx of indexes) {
      const id = String(row.rawValues?.[idx] ?? row.values?.[idx] ?? '').trim();
      if (id && id !== '—') ids.add(id);
    }
  }
  const nameMap = await lookupEntityDisplayNames([...ids]);
  return rows.map((row) => {
    const rawValues = Array.isArray(row.rawValues)
      ? [...row.rawValues]
      : [...(row.values || [])];
    const values = Array.isArray(row.values) ? [...row.values] : [...rawValues];
    for (const idx of indexes) {
      const id = String(rawValues[idx] ?? values[idx] ?? '').trim();
      values[idx] = explorerEntityDisplayLabel(id, nameMap.get(id) || '');
    }
    return { ...row, values, rawValues };
  });
}

function tcpFlagsGroupIndexes(groupBy = []) {
  return groupBy
    .map((g, i) => (g === 'tcp_flags' ? i : -1))
    .filter((i) => i >= 0);
}

/** Rollup stores tcp_flags as raw UInt8; show FIN/SYN/ACK labels in UI. */
function enrichTcpFlagsLabelsInRows(rows, groupBy = []) {
  const indexes = tcpFlagsGroupIndexes(groupBy);
  if (!indexes.length || !rows?.length) return rows || [];
  return rows.map((row) => {
    const rawValues = Array.isArray(row.rawValues)
      ? [...row.rawValues]
      : [...(row.values || [])];
    const values = Array.isArray(row.values) ? [...row.values] : [...rawValues];
    for (const idx of indexes) {
      const raw = rawValues[idx] ?? values[idx];
      if (raw === '' || raw == null) continue;
      if (!/^\d+$/.test(String(raw).trim())) continue;
      values[idx] = tcpFlagsMaskToLabel(Number(raw));
    }
    return { ...row, values, rawValues };
  });
}

async function readRollupTimeseries(observationId, window) {
  try {
    // Totals only — rows with empty dims. Do not sum grouped dims (would double-count).
    const { rows } = await query(`
      SELECT
        minute,
        toUnixTimestamp(minute) AS bucket_ts,
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows) AS flows
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= ${parseDataDatetimeSql('from')}
        AND minute < ${parseDataDatetimeSql('to')}
        AND ${rollupTotalRowSql()}
      GROUP BY minute
      ORDER BY minute
    `, {
      id: observationId,
      from: window.from,
      to: window.to,
    }, { name: 'observations/rollup-ts' });
    const points = rows.map((r) => {
      const bytes = Number(r.bytes) || 0;
      const ts = Number(r.bucket_ts);
      const bucketMs = Number.isFinite(ts) && ts > 0 ? ts * 1000 : null;
      return {
        t: r.minute,
        bucket: r.minute,
        bucketMs,
        bytes,
        bps: Math.round((bytes * 8) / ROLLUP_BUCKET_SEC),
        packets: Number(r.packets) || 0,
        flows: Number(r.flows) || 0,
      };
    });
    return { points };
  } catch (err) {
    return { points: [], error: err.message };
  }
}

/** Rollup stores dim0='' rows with the unsliced total, so "other" is exact, not guessed. */
async function readRollupPeriodTotals(observationId, window) {
  try {
    const { rows } = await query(`
      SELECT
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows) AS flows
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= ${parseDataDatetimeSql('from')}
        AND minute < ${parseDataDatetimeSql('to')}
        AND ${rollupTotalRowSql()}
    `, {
      id: observationId,
      from: window.from,
      to: window.to,
    }, { name: 'observations/rollup-period-totals' });
    const row = rows?.[0];
    const bytes = Number(row?.bytes) || 0;
    if (!bytes) return null;
    return {
      bytes,
      packets: Number(row?.packets) || 0,
      flows: Number(row?.flows) || 0,
    };
  } catch {
    return null;
  }
}

/** Rows beyond the stored top-N collapse into one "Прочие" row (total minus shown). */
function appendOtherRow(rows, totals, windowSeconds) {
  if (!totals?.bytes || !rows.length) return rows;
  const shownBytes = rows.reduce((s, r) => s + (Number(r.bytes) || 0), 0);
  const restBytes = totals.bytes - shownBytes;
  if (restBytes <= 0 || restBytes / totals.bytes < 0.0001) return rows;
  const groupCount = rows[0].values?.length || 1;
  const values = Array.from({ length: groupCount }, (_, i) => (i === 0 ? OTHER_LABEL : ''));
  return [...rows, {
    id: 'rollup-other',
    key: OTHER_KEY,
    isOther: true,
    values,
    rawValues: [...values],
    metric: Math.round((restBytes * 8) / windowSeconds),
    avgBps: Math.round((restBytes * 8) / windowSeconds),
    pct: Math.round((restBytes * 10000) / totals.bytes) / 100,
    bytes: restBytes,
    packets: Math.max(0, totals.packets - rows.reduce((s, r) => s + (Number(r.packets) || 0), 0)),
    flows: Math.max(0, totals.flows - rows.reduce((s, r) => s + (Number(r.flows) || 0), 0)),
    color: OTHER_COLOR,
  }];
}

async function readRollupTop(observationId, window, { limit = TOP_ROWS_LIMIT, groupBy = [] } = {}) {
  try {
    const windowSeconds = Math.max(
      60,
      Math.round((new Date(window.to) - new Date(window.from)) / 1000) || 3600,
    );
    const dimCount = Math.min(Math.max(groupBy.length || 1, 1), ROLLUP_DIM_COUNT);
    const dimCols = rollupDimColumns(dimCount).join(',\n        ');
    const { rows } = await query(`
      SELECT
        ${dimCols},
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows) AS flows
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= ${parseDataDatetimeSql('from')}
        AND minute < ${parseDataDatetimeSql('to')}
        AND ${rollupGroupedRowSql()}
      GROUP BY ${rollupDimColumns(dimCount).join(', ')}
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `, {
      id: observationId,
      from: window.from,
      to: window.to,
      limit: Math.min(Math.max(Number(limit) || TOP_ROWS_LIMIT, 1), TOP_ROWS_LIMIT),
    }, { name: 'observations/rollup-top' });

    const totals = await readRollupPeriodTotals(observationId, window);
    const shownBytes = rows.reduce((s, r) => s + (Number(r.bytes) || 0), 0);
    // Share is against the whole filtered traffic, not just the rows we display.
    const pctBase = totals?.bytes || shownBytes || 1;
    const mapped = rows.map((r, i) => {
      const bytes = Number(r.bytes) || 0;
      const values = rollupDimColumns(dimCount).map((c) => String(r[c] ?? ''));
      return {
        id: `rollup-${dimKeyFromRow(r, dimCount)}`,
        key: dimKeyFromRow(r, dimCount),
        values,
        rawValues: [...values],
        metric: Math.round((bytes * 8) / windowSeconds),
        avgBps: Math.round((bytes * 8) / windowSeconds),
        pct: Math.round((bytes * 10000) / pctBase) / 100,
        bytes,
        packets: Number(r.packets) || 0,
        flows: Number(r.flows) || 0,
        color: protocolChartColor(i),
      };
    });
    const withAsn = await enrichAsnLabelsInRows(mapped, groupBy);
    const withEntity = await enrichEntityLabelsInRows(withAsn, groupBy);
    return { rows: enrichTcpFlagsLabelsInRows(withEntity, groupBy), totals, windowSeconds };
  } catch (err) {
    return { rows: [], error: err.message };
  }
}

async function readRollupGroupedTimeseries(observationId, window, { seriesLimit = 8, groupBy = [] } = {}) {
  const top = await readRollupTop(observationId, window, { limit: seriesLimit, groupBy });
  if (!top.rows.length) {
    return {
      points: [],
      lines: [],
      rows: [],
      error: top.error || null,
    };
  }

  const keys = top.rows.map((r) => r.key);
  const dimCount = Math.min(Math.max(groupBy.length || 1, 1), ROLLUP_DIM_COUNT);

  try {
    const totalSeries = await readRollupTimeseries(observationId, window);
    const { rows } = await query(`
      SELECT
        minute,
        toUnixTimestamp(minute) AS bucket_ts,
        ${rollupDimColumns(dimCount).join(',\n        ')},
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows) AS flows
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= ${parseDataDatetimeSql('from')}
        AND minute < ${parseDataDatetimeSql('to')}
        AND ${rollupGroupedRowSql()}
        AND ${rollupKeySql(dimCount)} IN ({keys:Array(String)})
      GROUP BY minute, ${rollupDimColumns(dimCount).join(', ')}
      ORDER BY minute
    `, {
      id: observationId,
      from: window.from,
      to: window.to,
      keys,
    }, { name: 'observations/rollup-grouped-ts' });

    const wanted = new Set(keys);
    const bucketMap = new Map();
    for (const r of rows) {
      const key = dimKeyFromRow(r, dimCount);
      if (!wanted.has(key)) continue;
      const minute = r.minute;
      const ts = Number(r.bucket_ts);
      const bucketMs = Number.isFinite(ts) && ts > 0 ? ts * 1000 : null;
      if (!bucketMap.has(minute)) {
        bucketMap.set(minute, { t: minute, bucket: minute, bucketMs });
      }
      const bytes = Number(r.bytes) || 0;
      bucketMap.get(minute)[key] = Math.round((bytes * 8) / ROLLUP_BUCKET_SEC);
    }

    const totalByBucket = new Map();
    for (const p of totalSeries.points || []) {
      totalByBucket.set(p.t, Number(p.bps) || 0);
      if (!bucketMap.has(p.t)) bucketMap.set(p.t, { t: p.t, bucket: p.t, bucketMs: p.bucketMs ?? null });
    }

    let otherSeen = false;
    for (const point of bucketMap.values()) {
      const total = totalByBucket.get(point.bucket);
      if (!total) continue;
      const shown = keys.reduce((s, key) => s + (Number(point[key]) || 0), 0);
      const rest = total - shown;
      // Grouped and total rows come from the same rollup rows, so tiny drift is rounding only.
      if (rest > 0 && rest / total >= 0.0001) {
        point[OTHER_KEY] = Math.round(rest);
        otherSeen = true;
      }
    }

    const points = [...bucketMap.values()].sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)));
    const lines = top.rows.map((row) => ({
      key: row.key,
      label: dimLabel(row.values),
      color: row.color,
    }));
    if (otherSeen) {
      lines.push({ key: OTHER_KEY, label: OTHER_LABEL, color: OTHER_COLOR, isOther: true });
    }

    const topRows = appendOtherRow(top.rows, top.totals, top.windowSeconds || ROLLUP_BUCKET_SEC);
    return {
      points,
      lines,
      rows: topRows,
      totals: top.totals || null,
      windowSeconds: top.windowSeconds || ROLLUP_BUCKET_SEC,
      error: null,
    };
  } catch (err) {
    return { points: [], lines: [], rows: top.rows, error: err.message };
  }
}

async function runExplorerSpec(spec) {
  const { rows } = await query(spec.sql, spec.params || {}, {
    name: 'observations/explorer-threshold',
    clickhouse_settings: spec.clickhouse_settings,
    requestTimeoutMs: spec.requestTimeoutMs,
  });
  return { data: await spec.map(rows), meta: spec.meta || {} };
}

function mapFlowRowsToObservationRows(flowRows, groupBy = []) {
  return (flowRows || []).map((r, i) => {
    const values = r.values || [];
    const rawValues = r.rawValues || values;
    const key = dimKey(rawValues, groupBy.length || 1);
    return {
      id: r.id,
      key,
      values,
      rawValues,
      metric: r.avgBps ?? r.metric,
      avgBps: r.avgBps ?? r.metric,
      pct: r.pct,
      bytes: r.bytes,
      packets: r.packets,
      flows: r.flows,
      color: r.color || protocolChartColor(i),
    };
  });
}

async function fetchThresholdTopRows(obs, window, { groupBy, limit, metric = 'bps' }) {
  const body = {
    range: 'custom',
    from: window.from,
    to: window.to,
    filters: obs.filters,
    thresholds: obs.thresholds,
    metric,
    groupBy,
    limit,
    includeSummary: false,
    includeTimeseries: false,
  };
  const spec = await explorerFlows(body);
  const result = await runExplorerSpec(spec);
  const windowSeconds = result.meta?.windowSeconds || Math.max(
    60,
    Math.round((Date.parse(window.to) - Date.parse(window.from)) / 1000) || 3600,
  );
  const summary = summaryFromExplorerFlowRows(result.data, windowSeconds);
  return {
    rows: mapFlowRowsToObservationRows(result.data, groupBy),
    totals: summary ? { bytes: summary.bytes, packets: summary.packets, flows: summary.flows } : null,
    windowSeconds,
    meta: result.meta,
  };
}

async function fetchThresholdGroupedTimeseries(obs, window, { groupBy, seriesLimit }) {
  const top = await fetchThresholdTopRows(obs, window, { groupBy, limit: seriesLimit });
  if (!top.rows.length) {
    return {
      points: [],
      lines: [],
      rows: [],
      totals: top.totals,
      windowSeconds: top.windowSeconds,
      warning: top.meta?.thresholdWarning || null,
    };
  }

  const body = {
    range: 'custom',
    from: window.from,
    to: window.to,
    filters: obs.filters,
    thresholds: obs.thresholds,
    metric: 'bps',
    groupBy,
    granularity: '5m',
  };
  const seriesSpec = await explorerResultSeries(body, top.rows);
  const seriesResult = await runExplorerSpec(seriesSpec);
  const seriesByRow = seriesResult.data?.seriesByRow || {};
  const bucketMap = new Map();
  for (const row of top.rows) {
    const series = seriesByRow[row.id] || [];
    for (const pt of series) {
      const bucket = pt.bucket;
      if (!bucketMap.has(bucket)) {
        bucketMap.set(bucket, { t: bucket, bucket, bucketMs: pt.bucketMs ?? null });
      }
      bucketMap.get(bucket)[row.key] = Number(pt.bps ?? pt.value) || 0;
    }
  }
  const points = [...bucketMap.values()].sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)));
  const lines = top.rows.map((row) => ({
    key: row.key,
    label: dimLabel(row.values),
    color: row.color,
  }));
  return {
    points,
    lines,
    rows: top.rows,
    totals: top.totals,
    windowSeconds: top.windowSeconds,
    warning: top.meta?.thresholdWarning || null,
  };
}

async function previewObservationWithThresholds(obs, window) {
  const widgets = [];
  let cachedTop = null;

  for (const w of obs.widgets) {
    try {
      if (w.type === 'timeseries_bps') {
        const groupBy = observationChartGroupBy(obs, w);
        if (groupBy.length) {
          const seriesLimit = observationSeriesLimit(obs, w);
          const data = await fetchThresholdGroupedTimeseries(obs, window, { groupBy, seriesLimit });
          widgets.push({
            id: w.id,
            type: w.type,
            mode: 'grouped',
            groupBy,
            source: 'flows_raw',
            status: data.points.length || data.rows.length ? 'ok' : 'ok',
            series: data.points,
            points: data.points,
            lines: data.lines,
            rows: data.rows,
            warning: data.warning,
          });
          if (!cachedTop) {
            cachedTop = {
              rows: data.rows,
              groupBy,
              requested: seriesLimit,
              totals: data.totals,
              windowSeconds: data.windowSeconds,
            };
          }
          continue;
        }

        const bundle = await explorerTimeseries({
          ...window,
          metric: 'bps',
          filters: obs.filters,
          thresholds: obs.thresholds,
          granularity: '5m',
        });
        const { rows } = await query(bundle.sql, bundle.params, { name: 'observations/threshold-ts' });
        const series = await bundle.map(rows);
        widgets.push({
          id: w.id,
          type: w.type,
          mode: 'total',
          source: 'flows_raw',
          status: 'ok',
          series,
          warning: null,
        });
        continue;
      }

      if (w.type === 'top_table') {
        const groupBy = w.groupBy?.length ? w.groupBy : ['src_asn'];
        const wantRows = TOP_ROWS_LIMIT;
        const cachedRows = Array.isArray(cachedTop?.rows)
          ? cachedTop.rows.filter((r) => !r.isOther)
          : null;
        const cacheCovers = cachedTop
          && cachedTop.groupBy.join('|') === groupBy.join('|')
          && cachedRows
          && (cachedRows.length >= wantRows || cachedRows.length < (cachedTop.requested || 0));
        if (cacheCovers) {
          widgets.push({
            id: w.id,
            type: w.type,
            source: 'flows_raw',
            status: 'ok',
            rows: cachedRows.slice(0, wantRows),
            groupBy,
            warning: null,
          });
          continue;
        }
        const data = await fetchThresholdTopRows(obs, window, { groupBy, limit: wantRows });
        widgets.push({
          id: w.id,
          type: w.type,
          source: 'flows_raw',
          status: 'ok',
          rows: data.rows.slice(0, wantRows),
          groupBy,
          warning: data.meta?.thresholdWarning || null,
        });
      }
    } catch (err) {
      widgets.push({
        id: w.id,
        type: w.type,
        status: 'error',
        error: err.message,
      });
    }
  }

  return {
    observation: obs,
    window,
    widgets,
  };
}

function rollupEmptyWarning(obs) {
  const st = obs.materialize?.status || 'queued';
  if (st === 'error') {
    return `Rollup ошибка: ${obs.materialize?.lastError || 'неизвестно'}`;
  }
  if (st === 'queued' || st === 'running' || st === 'lagging') {
    const lag = Number(obs.materialize?.lagSeconds);
    if (Number.isFinite(lag) && lag > 120) {
      return `Воркер догоняет данные (отставание ~${Math.round(lag / 60)} мин) — график появится после догона окна.`;
    }
    return 'Rollup ещё пуст — воркер готовит данные.';
  }
  return 'В rollup пока нет точек за выбранное окно.';
}

async function previewObservation(id, userId, body = {}) {
  const obs = await getObservation(id, userId);
  if (!obs) return null;
  const window = resolvePreviewWindow(obs, body);
  if (explorerThresholdsActive(obs.thresholds)) {
    return previewObservationWithThresholds(obs, window);
  }
  const widgets = [];
  let cachedTop = null;
  const useRollup = Boolean(obs.materialize?.enabled);

  for (const w of obs.widgets) {
    try {
      if (w.type === 'timeseries_bps') {
        const groupBy = observationChartGroupBy(obs, w);
        if (groupBy.length) {
          if (!useRollup) {
            widgets.push({
              id: w.id,
              type: w.type,
              mode: 'grouped',
              groupBy,
              source: 'none',
              status: 'error',
              series: [],
              points: [],
              lines: [],
              rows: [],
              warning: 'График по группировке только из rollup — включите подготовку данных.',
            });
            continue;
          }
          const seriesLimit = observationSeriesLimit(obs, w);
          const data = await readRollupGroupedTimeseries(obs.id, window, { seriesLimit, groupBy });
          widgets.push({
            id: w.id,
            type: w.type,
            mode: 'grouped',
            groupBy,
            source: ROLLUP_TABLE,
            status: data.points.length ? 'ok' : (obs.materialize.status || 'queued'),
            series: data.points,
            points: data.points,
            lines: data.lines,
            rows: data.rows,
            warning: data.points.length ? null : rollupEmptyWarning(obs),
            error: data.error || undefined,
          });
          if (!cachedTop) {
            cachedTop = {
              rows: data.rows,
              groupBy,
              requested: seriesLimit,
              totals: data.totals || null,
              windowSeconds: data.windowSeconds || ROLLUP_BUCKET_SEC,
            };
          }
          continue;
        }

        if (useRollup) {
          const data = await readRollupTimeseries(obs.id, window);
          widgets.push({
            id: w.id,
            type: w.type,
            mode: 'total',
            source: ROLLUP_TABLE,
            status: data.points.length ? 'ok' : (obs.materialize.status || 'queued'),
            series: data.points,
            points: data.points,
            warning: data.points.length ? null : rollupEmptyWarning(obs),
          });
        } else if (obs.scope.materializeRequired) {
          widgets.push({
            id: w.id,
            type: w.type,
            mode: 'total',
            source: 'none',
            status: 'error',
            series: [],
            warning: 'Live без rollup недоступен — включите подготовку данных.',
          });
        } else {
          const bundle = await explorerTimeseries({
            ...window,
            metric: 'bps',
            filters: obs.filters,
            granularity: '5m',
          });
          const { rows } = await query(bundle.sql, bundle.params, { name: 'observations/preview-ts' });
          const series = await bundle.map(rows);
          widgets.push({
            id: w.id,
            type: w.type,
            mode: 'total',
            source: 'explorer/native',
            status: 'ok',
            series,
            warning: null,
          });
        }
        continue;
      }

      if (w.type === 'top_table') {
        const groupBy = w.groupBy?.length ? w.groupBy : ['src_asn'];
        const wantRows = TOP_ROWS_LIMIT;
        const cachedRows = Array.isArray(cachedTop?.rows)
          ? cachedTop.rows.filter((r) => !r.isOther)
          : null;
        // График берёт меньше серий, чем нужно таблице — переиспользуем только
        // когда его выборка уже покрывает нужное число строк (или данные исчерпаны).
        const cacheCovers = cachedRows
          && (cachedRows.length >= wantRows || cachedRows.length < (cachedTop.requested || 0));
        if (
          cachedTop
          && cachedTop.groupBy.join('|') === groupBy.join('|')
          && cacheCovers
        ) {
          const shown = cachedRows.slice(0, wantRows);
          widgets.push({
            id: w.id,
            type: w.type,
            source: useRollup ? ROLLUP_TABLE : 'none',
            status: 'ok',
            rows: appendOtherRow(shown, cachedTop.totals, cachedTop.windowSeconds || ROLLUP_BUCKET_SEC),
            groupBy,
            warning: cachedTop.rows.length ? null : (useRollup ? rollupEmptyWarning(obs) : null),
          });
          continue;
        }
        if (!useRollup) {
          widgets.push({
            id: w.id,
            type: w.type,
            source: 'none',
            status: 'error',
            rows: [],
            groupBy,
            warning: 'Таблица топа только из rollup — включите подготовку данных.',
          });
          continue;
        }
        const data = await readRollupTop(obs.id, window, { limit: wantRows, groupBy });
        widgets.push({
          id: w.id,
          type: w.type,
          source: ROLLUP_TABLE,
          status: data.rows.length ? 'ok' : (obs.materialize.status || 'queued'),
          rows: appendOtherRow(data.rows, data.totals, data.windowSeconds || ROLLUP_BUCKET_SEC),
          groupBy,
          warning: data.rows.length ? null : rollupEmptyWarning(obs),
          error: data.error || undefined,
        });
      }
    } catch (err) {
      widgets.push({
        id: w.id,
        type: w.type,
        status: 'error',
        error: err.message,
      });
    }
  }

  return {
    observation: obs,
    window,
    widgets,
  };
}

async function listRuns(observationId, userId) {
  const obs = await getObservation(observationId, userId);
  if (!obs) return null;
  return loadRunsForObservation(observationId);
}

function csvEscape(v) {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function fmtBitsRu(bps) {
  const n = Number(bps);
  if (!Number.isFinite(n)) return '—';
  const units = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с', 'Тбит/с', 'Пбит/с'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  const digits = v < 10 ? 2 : v < 100 ? 1 : 0;
  return `${n < 0 ? '-' : ''}${v.toFixed(digits)} ${units[i]}`;
}

function fmtBytesRu(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n)) return '—';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${n < 0 ? '-' : ''}${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

function fmtCountRu(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString('ru-RU') : '—';
}

function fmtPctRu(value) {
  const n = Number(value);
  return Number.isFinite(n) ? `${n.toFixed(2)}%` : '—';
}

/** ClickHouse returns naive UTC stamps ("2026-07-26 00:05:00"). */
function parseUtcStamp(value) {
  if (value instanceof Date) return value;
  const s = String(value ?? '').trim();
  if (!s) return null;
  const base = s.includes('T') ? s : s.replace(' ', 'T');
  const iso = /([Zz]|[+-]\d{2}:?\d{2})$/.test(base) ? base : `${base}Z`;
  const d = new Date(iso);
  return Number.isFinite(d.getTime()) ? d : null;
}

function zonedParts(value, timeZone) {
  const d = parseUtcStamp(value);
  if (!d) return null;
  try {
    const fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
    });
    return Object.fromEntries(fmt.formatToParts(d).map((p) => [p.type, p.value]));
  } catch {
    return null;
  }
}

function zonedDateTime(value, timeZone, sep = ' ') {
  const p = zonedParts(value, timeZone);
  if (!p) return String(value ?? '');
  return `${p.year}-${p.month}-${p.day}${sep}${p.hour}:${p.minute}`;
}

function zonedDate(value, timeZone) {
  const p = zonedParts(value, timeZone);
  return p ? `${p.year}-${p.month}-${p.day}` : '';
}

function zonedClock(value, timeZone) {
  const p = zonedParts(value, timeZone);
  return p ? `${p.hour}:${p.minute}` : '';
}

let explorerLabelCache = null;
function explorerFieldLabel(id) {
  if (!explorerLabelCache) {
    explorerLabelCache = new Map();
    try {
      const schema = explorerSchema();
      for (const d of schema.dimensions || []) explorerLabelCache.set(d.id, d.label);
      for (const f of schema.filterFields || []) {
        if (!explorerLabelCache.has(f.id)) explorerLabelCache.set(f.id, f.label);
      }
    } catch {
      // labels are cosmetic — fall back to raw ids
    }
  }
  return explorerLabelCache.get(String(id)) || String(id);
}

const FILTER_OP_LABELS = {
  '=': '=',
  '==': '=',
  '!=': '≠',
  in: 'из списка',
  not_in: 'кроме',
  cidr: 'в подсети',
  contains: 'содержит',
  not_contains: 'не содержит',
};

function describeFilters(filters) {
  const list = normalizeFilters(filters);
  if (!list.length) return 'без фильтров (весь трафик)';
  return list.map((f) => {
    const value = Array.isArray(f.value) ? f.value.join(', ') : String(f.value ?? '');
    return `${explorerFieldLabel(f.field)} ${FILTER_OP_LABELS[f.op] || f.op} ${value || '—'}`;
  }).join(' · ');
}

function describeObservationScope(obs) {
  const filterDesc = describeFilters(obs.filters);
  const thrDesc = describeThresholds(obs.thresholds);
  if (thrDesc) return `${filterDesc}; пороги: ${thrDesc}`;
  return filterDesc;
}

function describeGroupBy(widgets = []) {
  const fields = [...new Set(collectWidgetGroupFields(widgets))];
  if (!fields.length) return 'без группировки';
  return fields.map(explorerFieldLabel).join(' + ');
}

/** Deep link back into Explorer with the same filters and report window. */
function explorerLinkForReport(obs, window, timeZone) {
  const params = new URLSearchParams();
  params.set('metric', 'bps');
  const groupBy = [...new Set(collectWidgetGroupFields(obs.widgets))];
  if (groupBy.length) params.set('groupBy', groupBy.join(','));
  const filters = normalizeFilters(obs.filters).map((f) => ({
    id: f.id,
    field: f.field,
    op: f.op,
    value: f.value,
    logic: f.logic,
  }));
  if (filters.length) params.set('filters', encodeURIComponent(JSON.stringify(filters)));
  if (obs.thresholds?.length) {
    params.set('thresholds', encodeURIComponent(JSON.stringify(obs.thresholds)));
  }
  params.set('range', 'custom');
  params.set('from', zonedDateTime(window.from, timeZone, 'T'));
  params.set('to', zonedDateTime(window.to, timeZone, 'T'));
  return `${REPORT_BASE_URL}/#explorer?${params.toString()}`;
}

/** Grouped points store bps under series keys; total points use p.bps. */
function timeseriesReportData(previewWidget) {
  const points = previewWidget?.series || previewWidget?.points || [];
  const seriesLines = Array.isArray(previewWidget?.lines) ? previewWidget.lines : [];
  const grouped = previewWidget?.mode === 'grouped' && seriesLines.length > 0;
  return { points, seriesLines, grouped };
}

/**
 * Grouped charts are written long (one row per bucket+series) so the file matches
 * the top table shape and survives a changing series set.
 */
function timeseriesReportCsv(previewWidget, timeZone, groupBy = []) {
  const { points, seriesLines, grouped } = timeseriesReportData(previewWidget);
  const timeHeader = `Время (${timeZone})`;
  const dimHeader = groupBy.length ? groupBy.map(explorerFieldLabel).join(' / ') : 'Серия';
  const headers = grouped
    ? [timeHeader, dimHeader, 'Средняя бит/с']
    : [timeHeader, 'Средняя бит/с', 'Объём (байты)', 'Пакеты', 'Потоки'];

  const lines = [headers.map(csvEscape).join(',')];
  for (const p of points) {
    const stamp = zonedDateTime(p.t || p.bucket, timeZone);
    if (!grouped) {
      lines.push([stamp, p.bps, p.bytes, p.packets, p.flows].map(csvEscape).join(','));
      continue;
    }
    for (const ln of seriesLines) {
      if (p[ln.key] == null) continue;
      lines.push([stamp, ln.label || ln.key, p[ln.key]].map(csvEscape).join(','));
    }
  }
  return { lines, points, seriesLines, grouped };
}

function topReportCsv(previewWidget, groupBy) {
  const rows = Array.isArray(previewWidget?.rows) ? previewWidget.rows : [];
  const headers = [
    ...groupBy.map(explorerFieldLabel),
    'Средняя бит/с',
    'Доля %',
    'Объём (байты)',
    'Пакеты',
    'Потоки',
  ];
  const lines = [headers.map(csvEscape).join(',')];
  for (const row of rows) {
    lines.push([
      ...(row.values || []),
      row.metric,
      row.pct,
      row.bytes,
      row.packets,
      row.flows,
    ].map(csvEscape).join(','));
  }
  return { lines, rows };
}

/** Inline SVG chart — same shape as the tile chart, readable without JS. */
function reportChartSvg(previewWidget, timeZone) {
  const { points, seriesLines, grouped } = timeseriesReportData(previewWidget);
  if (!points.length) return '';

  const series = grouped
    ? seriesLines.map((ln) => ({
      label: ln.label || ln.key,
      color: ln.color || '#2f6feb',
      values: points.map((p) => Number(p[ln.key]) || 0),
    }))
    : [{
      label: 'Суммарно',
      color: '#2f6feb',
      values: points.map((p) => Number(p.bps) || 0),
    }];

  const width = 920;
  const height = 280;
  const padL = 86;
  const padR = 18;
  const padT = 16;
  const padB = 36;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;

  let maxY = 0;
  for (const s of series) {
    for (const v of s.values) if (v > maxY) maxY = v;
  }
  if (maxY <= 0) maxY = 1;

  const xAt = (i) => (points.length === 1
    ? padL + plotW / 2
    : padL + (i * plotW) / (points.length - 1));
  const yAt = (v) => padT + plotH - (Math.max(0, v) / maxY) * plotH;

  const gridSteps = 4;
  let grid = '';
  for (let i = 0; i <= gridSteps; i += 1) {
    const value = (maxY * i) / gridSteps;
    const y = yAt(value);
    grid += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${padL + plotW}" y2="${y.toFixed(1)}" stroke="#e6e6e6" stroke-width="1"/>`;
    grid += `<text x="${padL - 8}" y="${(y + 4).toFixed(1)}" text-anchor="end" font-size="11" fill="#666">${escapeHtml(fmtBitsRu(value))}</text>`;
  }

  const tickCount = Math.min(6, points.length);
  let ticks = '';
  for (let i = 0; i < tickCount; i += 1) {
    const idx = tickCount === 1
      ? 0
      : Math.round((i * (points.length - 1)) / (tickCount - 1));
    const p = points[idx];
    const x = xAt(idx);
    ticks += `<text x="${x.toFixed(1)}" y="${height - 12}" text-anchor="middle" font-size="11" fill="#666">${escapeHtml(zonedClock(p.t || p.bucket, timeZone))}</text>`;
  }

  const paths = series.map((s) => {
    const d = s.values
      .map((v, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`)
      .join(' ');
    return `<path d="${d}" fill="none" stroke="${escapeHtml(s.color)}" stroke-width="1.8" stroke-linejoin="round"/>`;
  }).join('');

  const legend = series.map((s) => (
    `<span class="legend-item"><span class="legend-dot" style="background:${escapeHtml(s.color)}"></span>${escapeHtml(s.label)}</span>`
  )).join('');

  const firstLabel = zonedDateTime(points[0].t || points[0].bucket, timeZone);
  const lastLabel = zonedDateTime(points[points.length - 1].t || points[points.length - 1].bucket, timeZone);

  return `<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" xmlns="http://www.w3.org/2000/svg" role="img">
<rect x="${padL}" y="${padT}" width="${plotW}" height="${plotH}" fill="#fafafa" stroke="#e6e6e6"/>
${grid}${paths}${ticks}
</svg>
<div class="legend">${legend}</div>
<p class="muted">Ось времени: ${escapeHtml(firstLabel)} — ${escapeHtml(lastLabel)} (${escapeHtml(timeZone)})</p>`;
}

/** Тот же график растром: почта вырезает inline SVG, картинку показывает. */
function reportChartImage(previewWidget, timeZone) {
  const { points, seriesLines, grouped } = timeseriesReportData(previewWidget);
  if (!points.length) return null;

  const series = grouped
    ? seriesLines.map((ln) => ({
      label: ln.label || ln.key,
      color: ln.color || '#2f6feb',
      values: points.map((p) => Number(p[ln.key]) || 0),
    }))
    : [{
      label: 'Суммарно',
      color: '#2f6feb',
      values: points.map((p) => Number(p.bps) || 0),
    }];

  let maxY = 0;
  for (const s of series) {
    for (const v of s.values) if (v > maxY) maxY = v;
  }
  if (maxY <= 0) maxY = 1;

  const gridSteps = 4;
  const yTicks = [];
  for (let i = 0; i <= gridSteps; i += 1) {
    yTicks.push({ ratio: i / gridSteps, text: i === 0 ? '0' : fmtBitsRu((maxY * i) / gridSteps) });
  }

  const tickCount = Math.min(6, points.length);
  const xTicks = [];
  for (let i = 0; i < tickCount; i += 1) {
    const idx = tickCount === 1
      ? 0
      : Math.round((i * (points.length - 1)) / (tickCount - 1));
    xTicks.push({
      ratio: points.length === 1 ? 0.5 : idx / (points.length - 1),
      text: zonedClock(points[idx].t || points[idx].bucket, timeZone),
    });
  }

  const png = renderChartPng({
    series: series.map((s) => ({ color: s.color, values: s.values.map((v) => v / maxY) })),
    yTicks,
    xTicks,
  });

  return {
    ...png,
    series,
    firstLabel: zonedDateTime(points[0].t || points[0].bucket, timeZone),
    lastLabel: zonedDateTime(points[points.length - 1].t || points[points.length - 1].bucket, timeZone),
  };
}

function chartLegendHtml(series = []) {
  if (!series.length) return '';
  const items = series.map((s) => (
    `<span class="legend-item"><span class="legend-dot" style="background:${escapeHtml(s.color || '#2f6feb')}"></span>${escapeHtml(s.label || '')}</span>`
  )).join('');
  return `<div class="legend">${items}</div>`;
}

function chartImageHtml(chart, src, timeZone) {
  if (!chart) return '';
  return `<img src="${escapeHtml(src)}" width="${chart.width}" height="${chart.height}" alt="График трафика за период"`
    + ` style="display:block;width:100%;max-width:${chart.width}px;height:auto;border:1px solid #e6e6e6;border-radius:6px"/>`
    + chartLegendHtml(chart.series)
    + `<p class="muted">Ось времени: ${escapeHtml(chart.firstLabel)} — ${escapeHtml(chart.lastLabel)}`
    + ` (${escapeHtml(timeZone)})</p>`;
}

/** Period totals come from rollup total rows (dim0=''), so they are not top-N capped. */
function summarizeTotalPoints(points, windowSeconds) {
  if (!points?.length) return null;
  let bytes = 0;
  let packets = 0;
  let flows = 0;
  let peakBps = 0;
  let peakAt = null;
  for (const p of points) {
    bytes += Number(p.bytes) || 0;
    packets += Number(p.packets) || 0;
    flows += Number(p.flows) || 0;
    const bps = Number(p.bps) || 0;
    if (bps > peakBps) {
      peakBps = bps;
      peakAt = p.t || p.bucket;
    }
  }
  return {
    bytes,
    packets,
    flows,
    peakBps,
    peakAt,
    avgBps: windowSeconds > 0 ? Math.round((bytes * 8) / windowSeconds) : 0,
    estimated: false,
  };
}

function summarizeGroupedPoints(previewWidget, windowSeconds) {
  const { points, seriesLines, grouped } = timeseriesReportData(previewWidget);
  if (!points.length) return null;
  let peakBps = 0;
  let peakAt = null;
  let sumBps = 0;
  for (const p of points) {
    const bps = grouped
      ? seriesLines.reduce((sum, ln) => sum + (Number(p[ln.key]) || 0), 0)
      : (Number(p.bps) || 0);
    sumBps += bps;
    if (bps > peakBps) {
      peakBps = bps;
      peakAt = p.t || p.bucket;
    }
  }
  const avgBps = Math.round(sumBps / points.length);
  return {
    bytes: Math.round((avgBps * windowSeconds) / 8),
    packets: null,
    flows: null,
    peakBps,
    peakAt,
    avgBps,
    estimated: true,
  };
}

function reportKpiHtml(totals, timeZone) {
  if (!totals) return '';
  const cards = [
    { label: 'Объём за период', value: fmtBytesRu(totals.bytes) },
    { label: 'Средняя скорость', value: fmtBitsRu(totals.avgBps) },
    {
      label: 'Пик',
      value: fmtBitsRu(totals.peakBps),
      sub: totals.peakAt ? zonedDateTime(totals.peakAt, timeZone) : '',
    },
    {
      label: 'Потоки / пакеты',
      value: totals.flows != null ? fmtCountRu(totals.flows) : '—',
      sub: totals.packets != null ? `${fmtCountRu(totals.packets)} пакетов` : '',
    },
  ];
  const items = cards.map((c) => (
    `<div class="kpi"><div class="kpi-label">${escapeHtml(c.label)}</div>`
    + `<div class="kpi-value">${escapeHtml(c.value)}</div>`
    + (c.sub ? `<div class="kpi-sub">${escapeHtml(c.sub)}</div>` : '')
    + '</div>'
  )).join('');
  const note = totals.estimated
    ? '<p class="muted">Итоги оценены по топ-сериям графика — точные суммы появятся, когда rollup соберёт итоговые строки.</p>'
    : '';
  return `<div class="kpis">${items}</div>${note}`;
}

function topTableHtml(previewWidget, groupBy, fileName, limit) {
  const rows = Array.isArray(previewWidget?.rows) ? previewWidget.rows : [];
  const title = `Топ · ${groupBy.map(explorerFieldLabel).join(' + ') || 'без группировки'}`;
  if (!rows.length) {
    const reason = previewWidget?.error || previewWidget?.warning || 'нет данных за период';
    return `<h2>${escapeHtml(title)}</h2><p class="muted">${escapeHtml(reason)}</p>`;
  }
  const head = [
    ...groupBy.map(explorerFieldLabel),
    'Средняя бит/с',
    'Доля',
    'Объём',
    'Пакеты',
    'Потоки',
  ].map((h) => `<th>${escapeHtml(h)}</th>`).join('');
  const otherRow = rows.find((r) => r.isOther);
  const shown = rows.filter((r) => !r.isOther).slice(0, limit);
  if (otherRow) shown.push(otherRow);
  const body = shown.map((r) => {
    const cells = [
      ...(r.values || []).map((v) => escapeHtml(v)),
      escapeHtml(fmtBitsRu(r.metric)),
      escapeHtml(fmtPctRu(r.pct)),
      escapeHtml(fmtBytesRu(r.bytes)),
      escapeHtml(fmtCountRu(r.packets)),
      escapeHtml(fmtCountRu(r.flows)),
    ];
    return `<tr${r.isOther ? ' class="other-row"' : ''}>${cells.map((c) => `<td>${c}</td>`).join('')}</tr>`;
  }).join('');
  const note = rows.length > shown.length
    ? `<p class="muted">Показаны ${shown.length} из ${rows.length} строк. Полные данные: ${escapeHtml(fileName)}</p>`
    : `<p class="muted">Полные данные: ${escapeHtml(fileName)}</p>`;
  return `<h2>${escapeHtml(title)}</h2>`
    + `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>${note}`;
}

function buildReportHtml({
  obs,
  window,
  preview,
  previewError = null,
  tables = [],
  totals = null,
  timeZone = DEFAULT_TIMEZONE,
  generatedAt = new Date().toISOString(),
  chart = null,
  chartSrc = CHART_IMAGE_FILE,
}) {
  const widgets = preview?.widgets || [];
  const chartTable = tables.find((t) => t.type === 'timeseries_bps');
  const chartPreview = chartTable
    ? widgets.find((pw) => pw.id === chartTable.widgetId)
    : widgets.find((pw) => pw.type === 'timeseries_bps');

  let chartSection = '';
  if (chart) {
    chartSection = chartImageHtml(chart, chartSrc, timeZone);
  } else if (chartPreview) {
    chartSection = `<p class="muted">${escapeHtml(chartPreview.warning || chartPreview.error || 'Нет точек за период')}</p>`;
  }

  const topSections = tables
    .filter((t) => t.type === 'top_table')
    .map((t) => {
      const w = (obs.widgets || []).find((x) => x.id === t.widgetId);
      const groupBy = w?.groupBy?.length ? w.groupBy : ['src_asn'];
      return topTableHtml(
        widgets.find((pw) => pw.id === t.widgetId),
        groupBy,
        t.file,
        REPORT_HTML_TOP_ROWS,
      );
    })
    .join('\n');

  const periodLabel = window.label || `${window.from} — ${window.to}`;
  const filesLine = tables.map((t) => t.file).join(' · ');
  const explorerLink = explorerLinkForReport(obs, window, timeZone);

  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>${escapeHtml(obs.name)}</title>
<style>
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;margin:24px;color:#111;max-width:1000px}
h1{margin:0 0 4px;font-size:22px}
h2{margin:28px 0 8px;font-size:16px}
.sub{margin:2px 0;color:#444;font-size:13px}
.muted{color:#666;font-size:12px;margin:6px 0}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.kpi{flex:1 1 180px;border:1px solid #e6e6e6;border-radius:8px;padding:10px 12px;background:#fafafa}
.kpi-label{color:#666;font-size:12px}
.kpi-value{font-size:19px;font-weight:600;margin-top:2px}
.kpi-sub{color:#666;font-size:12px;margin-top:2px}
.legend{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0;font-size:12px;color:#333}
.legend-item{display:inline-flex;align-items:center;gap:5px}
.legend-dot{display:inline-block;width:10px;height:10px;border-radius:2px}
table{border-collapse:collapse;width:100%;margin:10px 0}
td,th{border:1px solid #ddd;padding:6px 8px;font-size:13px}
th{background:#f5f5f5;text-align:left}
td:nth-child(n+2){text-align:right;font-variant-numeric:tabular-nums}
.other-row td{background:#f7f7f7;color:#444;font-style:italic}
a{color:#1a56c4}
</style>
</head><body>
<h1>${escapeHtml(obs.name)}</h1>
<p class="sub">Период: ${escapeHtml(periodLabel)}</p>
<p class="sub">Фильтры: ${escapeHtml(describeObservationScope(obs))}</p>
<p class="sub">Группировка: ${escapeHtml(describeGroupBy(obs.widgets))}</p>
${previewError ? `<p style="color:#a00">Ошибка выборки: ${escapeHtml(previewError)}</p>` : ''}
${reportKpiHtml(totals, timeZone)}
${chartSection ? `<h2>График</h2>${chartSection}${chartTable ? `<p class="muted">Полные данные: ${escapeHtml(chartTable.file)}</p>` : ''}` : ''}
${topSections}
<p class="sub" style="margin-top:22px"><a href="${escapeHtml(explorerLink)}">Открыть в разборе трафика</a></p>
<p class="muted">Файлы: ${escapeHtml(filesLine)}. Окно UTC: ${escapeHtml(window.from)} — ${escapeHtml(window.to)}. Сформировано ${escapeHtml(zonedDateTime(generatedAt, timeZone))} (${escapeHtml(timeZone)}).</p>
</body></html>`;
}

async function runObservationReport(id, userId) {
  const obs = await getObservation(id, userId);
  if (!obs) return null;
  const startedAt = new Date().toISOString();
  const runId = newId('run');
  const dir = path.join(ARTIFACTS_DIR, id, runId);
  fs.mkdirSync(dir, { recursive: true });

  const window = reportWindow(obs);
  const period = window.period;
  const timeZone = obs.report?.schedule?.timezone || DEFAULT_TIMEZONE;
  const windowSeconds = Math.max(
    60,
    Math.round((Date.parse(window.to) - Date.parse(window.from)) / 1000) || 3600,
  );
  const dayStamp = zonedDate(window.from, timeZone) || 'period';

  let preview;
  let previewError = null;
  try {
    preview = await previewObservation(id, userId, { from: window.from, to: window.to });
  } catch (err) {
    previewError = err.message;
    preview = { widgets: [] };
  }
  const tables = [];
  const usedNames = new Set(['report.html', 'manifest.json', CHART_IMAGE_FILE]);
  const uniqueName = (base) => {
    let name = `${base}.csv`;
    let i = 2;
    while (usedNames.has(name)) {
      name = `${base}-${i}.csv`;
      i += 1;
    }
    usedNames.add(name);
    return name;
  };

  for (const w of obs.widgets.filter((x) => x.type === 'timeseries_bps')) {
    const previewWidget = preview.widgets.find((pw) => pw.id === w.id) || { id: w.id, type: w.type };
    const csv = timeseriesReportCsv(previewWidget, timeZone, observationChartGroupBy(obs, w));
    const fileName = uniqueName(`chart-${dayStamp}`);
    fs.writeFileSync(path.join(dir, fileName), `\uFEFF${csv.lines.join('\n')}\n`);
    tables.push({
      widgetId: w.id,
      type: w.type,
      label: 'График',
      file: fileName,
      rows: Math.max(0, csv.lines.length - 1),
    });
  }

  for (const w of obs.widgets.filter((x) => x.type === 'top_table')) {
    const groupBy = w.groupBy?.length ? w.groupBy : ['src_asn'];
    const previewWidget = preview.widgets.find((pw) => pw.id === w.id);
    const csv = topReportCsv(previewWidget, groupBy);
    const slug = groupBy.join('-').replace(/[^a-zA-Z0-9_-]/g, '') || 'top';
    const fileName = uniqueName(`top-${slug}-${dayStamp}`);
    fs.writeFileSync(path.join(dir, fileName), `\uFEFF${csv.lines.join('\n')}\n`);
    tables.push({
      widgetId: w.id,
      type: w.type,
      label: `Топ · ${groupBy.map(explorerFieldLabel).join(' + ')}`,
      file: fileName,
      rows: csv.rows.length,
    });
  }

  const chartWidgetId = obs.widgets.find((w) => w.type === 'timeseries_bps')?.id;
  const chartPreview = chartWidgetId
    ? preview.widgets.find((pw) => pw.id === chartWidgetId)
    : null;

  let totals = null;
  if (obs.materialize?.enabled) {
    const totalSeries = await readRollupTimeseries(obs.id, window);
    totals = summarizeTotalPoints(totalSeries.points, windowSeconds);
  }
  if (!totals) totals = summarizeGroupedPoints(chartPreview, windowSeconds);

  const widgetErrors = (preview.widgets || []).filter((w) => w.status === 'error' || w.error);
  const status = previewError || widgetErrors.length
    ? (tables.some((t) => t.rows > 0) ? 'partial' : 'error')
    : 'ok';

  const periodLabel = window.label || `${window.from} — ${window.to}`;
  const chart = chartPreview ? reportChartImage(chartPreview, timeZone) : null;
  if (chart) fs.writeFileSync(path.join(dir, CHART_IMAGE_FILE), chart.buffer);

  const reportHtmlArgs = {
    obs,
    window,
    preview,
    previewError,
    tables,
    totals,
    timeZone,
    generatedAt: startedAt,
    chart,
  };
  // Артефакт отдаётся через ?file=…, относительная ссылка не разрешится — вставляем data URI.
  const html = buildReportHtml({
    ...reportHtmlArgs,
    chartSrc: chart ? `data:image/png;base64,${chart.buffer.toString('base64')}` : CHART_IMAGE_FILE,
  });
  const htmlPath = path.join(dir, 'report.html');
  fs.writeFileSync(htmlPath, html);

  const finishedAt = new Date().toISOString();
  let emailStatus = 'skipped';
  let emailTo = '';
  let emailError = '';
  const recipients = Array.isArray(obs.report?.emailTo) ? obs.report.emailTo : [];
  if (recipients.length && (status === 'ok' || status === 'partial')) {
    try {
      const smtp = await getSmtpSettings();
      if (!smtp.enabled) {
        emailStatus = 'skipped';
        emailError = 'SMTP не настроен';
      } else {
        const attachments = tables.map((t) => ({
          filename: t.file,
          path: path.join(dir, t.file),
        }));
        // Inline PNG вместо SVG: почтовые клиенты вырезают <svg> из письма.
        if (chart) {
          attachments.push({
            filename: CHART_IMAGE_FILE,
            path: path.join(dir, CHART_IMAGE_FILE),
            cid: CHART_IMAGE_CID,
            contentType: 'image/png',
          });
        }
        await sendSmtpMail({
          to: recipients,
          subject: `GrapesNTA: ${obs.name} — ${periodLabel}`,
          html: buildReportHtml({ ...reportHtmlArgs, chartSrc: `cid:${CHART_IMAGE_CID}` }),
          attachments,
        });
        emailStatus = 'sent';
        emailTo = recipients.join(', ');
      }
    } catch (err) {
      emailStatus = 'error';
      emailTo = recipients.join(', ');
      emailError = err.message || String(err);
    }
  }

  const run = {
    id: runId,
    observationId: id,
    startedAt,
    finishedAt,
    status,
    period,
    window: { from: window.from, to: window.to },
    artifactPath: dir,
    tables,
    previewWidgetCount: preview?.widgets?.length || 0,
    error: previewError || (widgetErrors[0]?.error || null),
    emailStatus,
    emailTo,
    emailError,
  };
  await insertRun(run);
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(run, null, 2));
  return run;
}

async function getRunArtifact(observationId, runId, userId, fileName) {
  const obs = await getObservation(observationId, userId);
  if (!obs) return null;
  const run = await loadRunById(observationId, runId);
  if (!run) return null;
  const safe = path.basename(String(fileName || 'report.html'));
  if (!/^[a-zA-Z0-9._-]+$/.test(safe)) {
    const err = new Error('Некорректное имя файла');
    err.status = 400;
    throw err;
  }
  const full = path.join(ARTIFACTS_DIR, observationId, runId, safe);
  if (!full.startsWith(path.join(ARTIFACTS_DIR, observationId, runId))) {
    const err = new Error('Некорректный путь');
    err.status = 400;
    throw err;
  }
  if (!fs.existsSync(full)) {
    const err = new Error(
      'Артефакт недоступен: UI и analytics не делят каталог данных (server/data)',
    );
    err.status = 404;
    err.code = 'artifact_missing';
    throw err;
  }
  const contentType = safe.endsWith('.html')
    ? 'text/html; charset=utf-8'
    : safe.endsWith('.png')
      ? 'image/png'
      : 'text/csv; charset=utf-8';
  return { path: full, fileName: safe, contentType };
}

async function listReportJobs() {
  const all = await loadAllObservations();
  return all
    .filter((o) => o.report?.enabled)
    .map((o) => {
      const schedule = o.report?.schedule || normalizeSchedule(o.report || {}, o.report || {});
      return {
        id: o.id,
        ownerId: o.ownerId,
        name: o.name,
        schedule,
        period: o.report.period || 'yesterday',
      };
    });
}

async function lastSuccessfulRunAt(observationId) {
  return storeLastSuccessfulRunAt(observationId);
}

async function isReportDue(job, now = new Date()) {
  const last = await lastSuccessfulRunAt(job.id);
  const schedule = job.schedule || normalizeSchedule({}, {});
  return isScheduleDue(schedule, last, now, { graceHours: 6 });
}

async function runDueObservationReports() {
  const jobs = await listReportJobs();
  const results = [];
  const now = new Date();
  for (const job of jobs) {
    if (!(await isReportDue(job, now))) continue;
    try {
      const run = await runObservationReport(job.id, job.ownerId);
      results.push({ id: job.id, name: job.name, ok: true, runId: run?.id });
    } catch (err) {
      results.push({ id: job.id, name: job.name, ok: false, error: err.message });
    }
  }
  return results;
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function listMaterializeJobs() {
  const all = await loadAllObservations();
  return all
    .filter((o) => o.materialize?.enabled && classifyScope(o.filters, o.widgets).materializeRequired)
    .map((o) => {
      const ts = (o.widgets || []).find((w) => w.type === 'timeseries_bps');
      const top = (o.widgets || []).find((w) => w.type === 'top_table' && w.groupBy?.length);
      const groupBy = observationChartGroupBy(o, ts).slice(0, ROLLUP_DIM_COUNT);
      const mat = o.materialize || {};
      return {
        id: o.id,
        name: o.name,
        status: mat.status,
        intervalSec: Math.max(
          MIN_REFRESH_SEC,
          Number(o.live?.refreshSec) || Number(mat.intervalSec) || MIN_REFRESH_SEC,
        ),
        cursorMinute: mat.cursorMinute,
        lastCatchupAt: mat.lastCatchupAt || null,
        startedAt: o.createdAt || o.updatedAt || null,
        failCount: Number(mat.failCount) || 0,
        nextAttemptAt: mat.nextAttemptAt || null,
        cancelRequested: Boolean(mat.cancelRequested),
        runningStartedAt: mat.runningStartedAt || null,
        backfillFrom: mat.backfillFrom || null,
        backfillCursor: mat.backfillCursor || null,
        backfillDone: Boolean(mat.backfillDone),
        filters: o.filters,
        groupBy,
        seriesLimit: Math.min(
          50,
          Math.max(
            observationSeriesLimit(o, ts),
            Number(top?.limit) || 0,
            20,
          ),
        ),
      };
    });
}

async function patchMaterializeStatus(id, patch) {
  const item = await loadObservationById(id);
  if (!item) return;
  item.materialize = { ...item.materialize, ...patch };
  item.updatedAt = new Date().toISOString();
  await upsertObservation(item);
}

function observationPresets() {
  return [
    {
      id: 'preset-vlan',
      name: 'VLAN overview',
      filters: [{ field: 'vlan', op: '=', value: '100' }],
      widgets: [
        { type: 'timeseries_bps', metric: 'bps', groupBy: [] },
        { type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: TOP_ROWS_LIMIT },
      ],
      lookback: '1h',
    },
    {
      id: 'preset-own-net',
      name: 'Своя сеть',
      filters: [{ field: 'own_network', op: '=', value: '' }],
      widgets: [
        { type: 'timeseries_bps', metric: 'bps', groupBy: [] },
        { type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: TOP_ROWS_LIMIT },
      ],
      lookback: '1h',
      materialize: { enabled: true, intervalSec: 300 },
      live: { enabled: true, refreshSec: 300 },
    },
    {
      id: 'preset-ip-asn',
      name: 'Клиентский IP → ASN',
      filters: [{ field: 'src_ip', op: '=', value: '' }],
      widgets: [
        { type: 'timeseries_bps', metric: 'bps', groupBy: [] },
        { type: 'top_table', metric: 'bps', groupBy: ['dst_asn'], limit: TOP_ROWS_LIMIT },
      ],
      lookback: '24h',
      materialize: { enabled: true, intervalSec: 300 },
      live: { enabled: true, refreshSec: 300 },
    },
    {
      id: 'preset-vlan-net',
      name: 'VLAN + сеть',
      filters: [
        { field: 'vlan', op: '=', value: '100' },
        { field: 'src_ip', op: 'cidr', value: '10.0.0.0/8' },
      ],
      widgets: [
        { type: 'timeseries_bps', metric: 'bps', groupBy: [] },
        { type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: TOP_ROWS_LIMIT },
      ],
      lookback: '1h',
      materialize: { enabled: true, intervalSec: 300 },
      live: { enabled: true, refreshSec: 300 },
    },
  ];
}

function observationsConfig() {
  return {
    maxMaterialize: MATERIALIZE_LIMIT_ENABLED ? MAX_MATERIALIZE : null,
    minIntervalSec: MIN_INTERVAL_SEC,
    backfillHours: BACKFILL_HOURS,
    stuckSec: STUCK_SEC,
    lookbacks: ['30m', '1h', '6h', '24h', '7d'],
    refreshSecs: [...REFRESH_SECS],
    widgetTypes: [...WIDGET_TYPES],
    nativeFilterFields: [...NATIVE_FILTER_FIELDS],
    presets: observationPresets(),
    schema: explorerSchema(),
  };
}

function backfillProgress(mat) {
  if (!mat?.enabled || !mat.backfillFrom) return null;
  if (mat.backfillDone) {
    return { done: true, hoursDone: BACKFILL_HOURS, hoursTotal: BACKFILL_HOURS };
  }
  const fromMs = Date.parse(mat.backfillFrom);
  const cursorMs = Date.parse(mat.backfillCursor || mat.backfillFrom);
  const createdBound = Date.parse(mat.cursorMinute || '') || Date.now();
  // Live cursor starts at createdAt; backfill fills [backfillFrom, createdAt).
  const totalMs = Math.max(1, (Number.isFinite(createdBound) ? createdBound : Date.now()) - fromMs);
  // Approximation: progress by how far backfillCursor advanced from backfillFrom toward createdAt
  // When backfill runs, backfillCursor moves forward from backfillFrom.
  const doneMs = Math.max(0, (Number.isFinite(cursorMs) ? cursorMs : fromMs) - fromMs);
  const hoursTotal = Math.max(1, Math.round(totalMs / 3600000));
  const hoursDone = Math.min(hoursTotal, Math.round(doneMs / 3600000));
  return { done: false, hoursDone, hoursTotal };
}

async function getObservationAnalyticsDiagnostics() {
  // Local file if co-located; otherwise shared ClickHouse heartbeat from remote worker.
  const diag = await getMergedDiagnosticsPayload();
  const all = await loadAllObservations();
  const items = all.filter((o) => o.materialize?.enabled);
  const ids = items.map((o) => o.id);

  let rollupStats = [];
  let rollupStatsError = null;
  // Skip CH peek when worker is offline/stale — UI still shows cursor from store.
  if (ids.length && diag.worker?.alive) {
    try {
      const statsPromise = query(`
        SELECT
          observation_id,
          max(minute) AS max_minute
        FROM default.${ROLLUP_TABLE}
        WHERE observation_id IN {ids:Array(String)}
        GROUP BY observation_id
      `, { ids }, { name: 'observations/diag-rollup-stats' });
      const { rows } = await Promise.race([
        statsPromise,
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error('таймаут CH stats 3с')), 3000);
        }),
      ]);
      rollupStats = rows;
    } catch (err) {
      rollupStatsError = err.message;
    }
  } else if (ids.length && !diag.worker?.alive) {
    rollupStatsError = 'воркер не запущен — max(minute) из CH не запрашивался';
  }

  const statsById = Object.fromEntries(
    rollupStats.filter((r) => r.observation_id).map((r) => [r.observation_id, r]),
  );
  const jobs = items.map((o) => {
    const st = statsById[o.id];
    return {
      id: o.id,
      name: o.name,
      createdAt: o.createdAt,
      materialize: o.materialize,
      scope: classifyScope(o.filters, o.widgets),
      rollup: {
        maxMinute: st?.max_minute || null,
        rowCount: null,
        groupedRows: null,
      },
    };
  });
  return { ...diag, jobs, rollupStatsError, rollupTable: ROLLUP_TABLE };
}

module.exports = {
  classifyScope,
  ensureObservationsStore,
  listObservations,
  getObservation,
  createObservation,
  updateObservation,
  deleteObservation,
  duplicateObservation,
  cancelMaterialize,
  queueMaterialize,
  previewObservation,
  runObservationReport,
  listRuns,
  getRunArtifact,
  listReportJobs,
  runDueObservationReports,
  listMaterializeJobs,
  patchMaterializeStatus,
  observationsConfig,
  getObservationAnalyticsDiagnostics,
  timeseriesReportCsv,
  topReportCsv,
  reportChartSvg,
  reportChartImage,
  buildReportHtml,
  summarizeTotalPoints,
  summarizeGroupedPoints,
  describeFilters,
  MAX_MATERIALIZE,
  MIN_INTERVAL_SEC,
  MIN_REFRESH_SEC,
  ROLLUP_TABLE,
  ROLLUP_BUCKET_SEC,
  ROLLUP_DIM_COUNT,
  ARTIFACTS_DIR,
  BACKFILL_HOURS,
  STUCK_SEC,
  MAX_FAIL_COUNT,
  resolveObservationBackfill,
};
