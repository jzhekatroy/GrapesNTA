'use strict';

const fs = require('fs');
const path = require('path');
const { query, executeCommand, parseDataDatetimeSql } = require('./clickhouse');
const {
  explorerTimeseries,
  explorerSchema,
  parseExplorerAsnNumber,
  asnExplorerDisplayLabel,
  lookupAsnDisplayNames,
} = require('./explorer');
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
} = require('./observation-schedule');
const { getSmtpSettings, sendSmtpMail } = require('./smtp-settings');

const ARTIFACTS_DIR = path.join(__dirname, 'data', 'observation_runs');

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
/** Min live refresh / materialize cadence — wait for late flows. */
const MIN_REFRESH_SEC = 300;
/** Observation rollup bucket (aligned with dashboard 5m charts). */
const ROLLUP_TABLE = 'observation_rollups_5m';
const ROLLUP_BUCKET_SEC = 300;
const DEFAULT_TTL_HINT_DAYS = 14;
const BACKFILL_HOURS = Math.max(0, Number(process.env.OBSERVATION_BACKFILL_HOURS) || 24);
const STUCK_SEC = Math.max(60, Number(process.env.OBSERVATION_ROLLUP_STUCK_SEC) || 900);
const MAX_FAIL_COUNT = 10;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const NATIVE_FILTER_FIELDS = new Set([
  'direction', 'collector', 'vlan', 'vlan_attachment',
  'src_asn', 'dst_asn', 'proto', 'src_country', 'dst_country',
]);

const LOOKBACKS = new Set(['15m', '1h', '6h', '24h', '7d']);
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
      { id: 'w-asn', type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: 15 },
    ];
  }
  return widgets.map((w, i) => ({
    id: w.id || `w-${i}`,
    type: WIDGET_TYPES.has(w.type) ? w.type : 'top_table',
    metric: w.metric || 'bps',
    groupBy: Array.isArray(w.groupBy) ? w.groupBy.map(String) : [],
    limit: w.limit != null ? Number(w.limit) : 15,
    seriesLimit: w.seriesLimit != null ? Number(w.seriesLimit) : undefined,
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
    && o.live?.enabled
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

function normalizeLayout(raw, existing) {
  const src = raw?.layout != null ? raw.layout : existing?.layout;
  if (!src || typeof src !== 'object') {
    return { order: 0, width: 1 };
  }
  const order = Number(src.order);
  const width = Number(src.width) === 2 ? 2 : 1;
  return {
    order: Number.isFinite(order) ? order : 0,
    width,
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

function isObservationOwner(item, userId) {
  if (!item) return false;
  const owner = String(item.ownerId || '').trim();
  const uid = String(userId || '').trim();
  if (!owner) return true;
  return owner === uid;
}

function materializeWarning(activeCount) {
  const quota = MATERIALIZE_LIMIT_ENABLED
    ? `Активных: ${activeCount}/${MAX_MATERIALIZE}. `
    : `Активных: ${activeCount}. `;
  return `Частые/сложные материализации нагружают ClickHouse. ${quota}`
    + `Шаг наблюдения ≥ ${MIN_REFRESH_SEC}s (запас на late flows). TTL rollup ~${DEFAULT_TTL_HINT_DAYS}д. `
    + `Персональные данные пишутся в общую таблицу ${ROLLUP_TABLE} (бакет ${ROLLUP_BUCKET_SEC}s, не отдельный MV на каждый id).`;
}

function normalizeObservation(raw = {}, { userId, existing = null } = {}) {
  const filters = normalizeFilters(raw.filters != null ? raw.filters : existing?.filters);
  const widgets = normalizeWidgets(raw.widgets != null ? raw.widgets : existing?.widgets);
  const scope = classifyScope(filters, widgets);
  const lookback = LOOKBACKS.has(raw.lookback) ? raw.lookback : (existing?.lookback || '1h');
  let refreshSec = Number(raw.live?.refreshSec ?? existing?.live?.refreshSec ?? MIN_REFRESH_SEC);
  if (!Number.isFinite(refreshSec) || refreshSec < MIN_REFRESH_SEC) refreshSec = MIN_REFRESH_SEC;
  if (!REFRESH_SECS.has(refreshSec)) {
    // clamp legacy 15/30/60 → 5m
    refreshSec = MIN_REFRESH_SEC;
  }

  const liveEnabled = Boolean(raw.live?.enabled ?? existing?.live?.enabled ?? false);
  let materializeEnabled = Boolean(raw.materialize?.enabled ?? existing?.materialize?.enabled);
  // Live + filter/groupBy always needs personal rollup — never allow UI save to turn it off.
  if (scope.materializeRequired && liveEnabled) materializeEnabled = true;
  if (!scope.materializeRequired) materializeEnabled = false;

  // Worker cadence follows live.refreshSec (same setting as UI), floor 5 minutes.
  let intervalSec = Number(raw.materialize?.intervalSec ?? existing?.materialize?.intervalSec ?? refreshSec);
  if (!Number.isFinite(intervalSec) || intervalSec < MIN_REFRESH_SEC) intervalSec = refreshSec;
  intervalSec = Math.max(MIN_REFRESH_SEC, intervalSec, refreshSec);

  const createdAt = existing?.createdAt || raw.createdAt || new Date().toISOString();
  const wasEnabled = Boolean(existing?.materialize?.enabled);
  let cursorMinute = existing?.materialize?.cursorMinute ?? raw.materialize?.cursorMinute ?? null;
  let matStatus = existing?.materialize?.status || (materializeEnabled ? 'queued' : 'idle');
  let backfill = {
    backfillFrom: existing?.materialize?.backfillFrom ?? null,
    backfillCursor: existing?.materialize?.backfillCursor ?? null,
    backfillDone: Boolean(existing?.materialize?.backfillDone),
  };
  if (materializeEnabled && !wasEnabled) {
    // Fresh live: catch up from creation time first; history via separate backfill cursor.
    matStatus = 'queued';
    cursorMinute = createdAt;
    backfill = initBackfillFields(createdAt, {});
  } else if (materializeEnabled && !backfill.backfillFrom) {
    backfill = initBackfillFields(createdAt, existing?.materialize || {});
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
    isShared: Boolean(raw.isShared ?? existing?.isShared),
    filters,
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
  if (scope.materializeRequired && item.live?.enabled) {
    warnings.push(materializeWarning(active));
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
    Object.assign(next.materialize, initBackfillFields(existing.createdAt || next.createdAt, {}));
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
    isShared: false,
    live: { ...(existing.live || {}), enabled: false },
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
    next.live = { ...(existing.live || {}), enabled: false };
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

function lookbackWindow(lookback) {
  const map = {
    '15m': 15 * 60 * 1000,
    '1h': 3600 * 1000,
    '6h': 6 * 3600 * 1000,
    '24h': 86400 * 1000,
    '7d': 7 * 86400 * 1000,
  };
  const ms = map[lookback] || 3600 * 1000;
  const to = new Date();
  const from = new Date(to.getTime() - ms);
  return {
    range: 'custom',
    from: from.toISOString(),
    to: to.toISOString(),
  };
}

function resolvePreviewWindow(obs, body = {}) {
  if (body.from && body.to) {
    return { range: 'custom', from: String(body.from), to: String(body.to) };
  }
  return lookbackWindow(body.lookback || obs.lookback);
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

function observationSeriesLimit(obs, timeseriesWidget) {
  const fromTs = Number(timeseriesWidget?.seriesLimit);
  if (Number.isFinite(fromTs) && fromTs > 0) return Math.min(Math.max(fromTs, 1), 12);
  const top = (obs.widgets || []).find((w) => w.type === 'top_table');
  const fromTop = Number(top?.limit);
  if (Number.isFinite(fromTop) && fromTop > 0) return Math.min(Math.max(fromTop, 1), 12);
  return 8;
}

function dimKey(dim0, dim1) {
  return dim1 ? `${dim0}|${dim1}` : String(dim0 || '');
}

function dimLabel(dim0, dim1) {
  if (dim1) return `${dim0} · ${dim1}`;
  return String(dim0 || '—');
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
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows) AS flows
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= ${parseDataDatetimeSql('from')}
        AND minute < ${parseDataDatetimeSql('to')}
        AND dim0 = ''
        AND dim1 = ''
      GROUP BY minute
      ORDER BY minute
    `, {
      id: observationId,
      from: window.from,
      to: window.to,
    }, { name: 'observations/rollup-ts' });
    const points = rows.map((r) => {
      const bytes = Number(r.bytes) || 0;
      return {
        t: r.minute,
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

async function readRollupTop(observationId, window, { limit = 15, groupBy = [] } = {}) {
  try {
    const windowSeconds = Math.max(
      60,
      Math.round((new Date(window.to) - new Date(window.from)) / 1000) || 3600,
    );
    const { rows } = await query(`
      SELECT
        dim0,
        dim1,
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows) AS flows
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= ${parseDataDatetimeSql('from')}
        AND minute < ${parseDataDatetimeSql('to')}
        AND dim0 != ''
      GROUP BY dim0, dim1
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `, {
      id: observationId,
      from: window.from,
      to: window.to,
      limit: Math.min(Math.max(Number(limit) || 15, 1), 50),
    }, { name: 'observations/rollup-top' });

    const totalBytes = rows.reduce((s, r) => s + (Number(r.bytes) || 0), 0) || 1;
    const mapped = rows.map((r, i) => {
      const bytes = Number(r.bytes) || 0;
      const values = r.dim1 ? [String(r.dim0), String(r.dim1)] : [String(r.dim0)];
      return {
        id: `rollup-${dimKey(r.dim0, r.dim1)}`,
        key: dimKey(r.dim0, r.dim1),
        values,
        rawValues: [...values],
        metric: Math.round((bytes * 8) / windowSeconds),
        avgBps: Math.round((bytes * 8) / windowSeconds),
        pct: Math.round((bytes * 10000) / totalBytes) / 100,
        bytes,
        packets: Number(r.packets) || 0,
        flows: Number(r.flows) || 0,
        color: protocolChartColor(i),
      };
    });
    const withAsn = await enrichAsnLabelsInRows(mapped, groupBy);
    return { rows: enrichTcpFlagsLabelsInRows(withAsn, groupBy) };
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

  try {
    const { rows } = await query(`
      SELECT
        minute,
        dim0,
        dim1,
        sum(bytes) AS bytes,
        sum(packets) AS packets,
        sum(flows) AS flows
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= ${parseDataDatetimeSql('from')}
        AND minute < ${parseDataDatetimeSql('to')}
        AND dim0 != ''
        AND if(dim1 = '', dim0, concat(dim0, '|', dim1)) IN ({keys:Array(String)})
      GROUP BY minute, dim0, dim1
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
      const key = dimKey(r.dim0, r.dim1);
      if (!wanted.has(key)) continue;
      const minute = r.minute;
      if (!bucketMap.has(minute)) {
        bucketMap.set(minute, { t: minute, bucket: minute });
      }
      const bytes = Number(r.bytes) || 0;
      bucketMap.get(minute)[key] = Math.round((bytes * 8) / ROLLUP_BUCKET_SEC);
    }

    const points = [...bucketMap.values()].sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)));
    const lines = top.rows.map((row) => ({
      key: row.key,
      label: dimLabel(row.values[0], row.values[1]),
      color: row.color,
    }));

    return { points, lines, rows: top.rows, error: null };
  } catch (err) {
    return { points: [], lines: [], rows: top.rows, error: err.message };
  }
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
            cachedTop = { rows: data.rows, groupBy };
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
        if (
          cachedTop
          && cachedTop.groupBy.join('|') === groupBy.join('|')
          && Array.isArray(cachedTop.rows)
        ) {
          widgets.push({
            id: w.id,
            type: w.type,
            source: useRollup ? ROLLUP_TABLE : 'none',
            status: 'ok',
            rows: cachedTop.rows.slice(0, w.limit || 15),
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
        const data = await readRollupTop(obs.id, window, { limit: w.limit || 15, groupBy });
        widgets.push({
          id: w.id,
          type: w.type,
          source: ROLLUP_TABLE,
          status: data.rows.length ? 'ok' : (obs.materialize.status || 'queued'),
          rows: data.rows,
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

/** Build timeseries CSV rows; grouped points store bps under series keys, not p.bps. */
function timeseriesReportCsv(previewWidget) {
  const points = previewWidget?.series || previewWidget?.points || [];
  const seriesLines = Array.isArray(previewWidget?.lines) ? previewWidget.lines : [];
  const grouped = previewWidget?.mode === 'grouped' && seriesLines.length > 0;

  if (grouped) {
    const headers = ['t', ...seriesLines.map((ln) => ln.label || ln.key || 'series')];
    const lines = [headers.map(csvEscape).join(',')];
    for (const p of points) {
      lines.push([
        p.t || p.bucket,
        ...seriesLines.map((ln) => (p[ln.key] != null ? p[ln.key] : '')),
      ].map(csvEscape).join(','));
    }
    return { lines, points, seriesLines, grouped: true, headers };
  }

  const headers = ['t', 'bps', 'bytes', 'packets', 'flows'];
  const lines = [headers.map(csvEscape).join(',')];
  for (const p of points) {
    lines.push([p.t || p.bucket, p.bps, p.bytes, p.packets, p.flows].map(csvEscape).join(','));
  }
  return { lines, points, seriesLines: [], grouped: false, headers };
}

function timeseriesReportHtml(previewWidget, fileName, rowCount) {
  const { points, seriesLines, grouped, headers } = timeseriesReportCsv(previewWidget);
  if (!points.length) {
    return `<h2>${escapeHtml(previewWidget?.id || 'timeseries')}</h2>`
      + `<p>Нет точек за окно. CSV: ${escapeHtml(fileName)}</p>`;
  }
  const head = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join('');
  const sample = points.slice(0, 50);
  const body = sample.map((p) => {
    if (grouped) {
      const cells = [
        p.t || p.bucket,
        ...seriesLines.map((ln) => (p[ln.key] != null ? p[ln.key] : '')),
      ];
      return `<tr>${cells.map((v) => `<td>${escapeHtml(v)}</td>`).join('')}</tr>`;
    }
    return `<tr>${[
      p.t || p.bucket, p.bps, p.bytes, p.packets, p.flows,
    ].map((v) => `<td>${escapeHtml(v)}</td>`).join('')}</tr>`;
  }).join('');
  const note = points.length > 50
    ? `<p>Показаны первые 50 из ${rowCount} точек. Полные данные: ${escapeHtml(fileName)}</p>`
    : `<p>CSV: ${escapeHtml(fileName)}</p>`;
  return `<h2>${escapeHtml(previewWidget?.id || 'timeseries')}</h2>`
    + `<p>${grouped ? 'График (bps по сериям)' : 'График (total bps)'}</p>`
    + `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>${note}`;
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
  let preview;
  let previewError = null;
  try {
    preview = await previewObservation(id, userId, { from: window.from, to: window.to });
  } catch (err) {
    previewError = err.message;
    preview = { widgets: [] };
  }
  const tables = [];

  for (const w of obs.widgets.filter((x) => x.type === 'timeseries_bps')) {
    const previewWidget = preview.widgets.find((pw) => pw.id === w.id) || { id: w.id, type: w.type };
    const csv = timeseriesReportCsv(previewWidget);
    const csvPath = path.join(dir, `${w.id}.csv`);
    fs.writeFileSync(csvPath, `${csv.lines.join('\n')}\n`);
    tables.push({
      widgetId: w.id,
      type: w.type,
      file: path.basename(csvPath),
      rows: csv.points.length,
    });
  }

  for (const w of obs.widgets.filter((x) => x.type === 'top_table')) {
    const groupBy = w.groupBy?.length ? w.groupBy : ['src_asn'];
    const mapped = preview.widgets.find((pw) => pw.id === w.id)?.rows || [];
    const csvPath = path.join(dir, `${w.id}.csv`);
    const headers = [...groupBy, 'metric', 'pct', 'bytes', 'packets', 'flows'];
    const lines = [headers.join(',')];
    for (const row of mapped) {
      lines.push([
        ...(row.values || []),
        row.metric,
        row.pct,
        row.bytes,
        row.packets,
        row.flows,
      ].map(csvEscape).join(','));
    }
    fs.writeFileSync(csvPath, `${lines.join('\n')}\n`);
    tables.push({ widgetId: w.id, type: w.type, file: path.basename(csvPath), rows: mapped.length });
  }

  const htmlTables = tables.map((t) => {
    const previewWidget = preview.widgets.find((pw) => pw.id === t.widgetId);
    if (previewWidget?.type === 'timeseries_bps' || t.type === 'timeseries_bps') {
      return timeseriesReportHtml(previewWidget || { id: t.widgetId, type: t.type }, t.file, t.rows);
    }
    if (previewWidget?.type === 'top_table' && Array.isArray(previewWidget.rows)) {
      const gb = previewWidget.groupBy || [];
      const head = [...gb, 'metric'].map((h) => `<th>${escapeHtml(h)}</th>`).join('');
      const body = previewWidget.rows.slice(0, 50).map((r) => (
        `<tr>${(r.values || []).map((v) => `<td>${escapeHtml(v)}</td>`).join('')}<td>${escapeHtml(r.metric)}</td></tr>`
      )).join('');
      return `<h2>${escapeHtml(t.widgetId)}</h2><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table><p>CSV: ${escapeHtml(t.file)}</p>`;
    }
    if (previewWidget?.error) {
      return `<h2>${escapeHtml(t.widgetId)}</h2><p style="color:#a00">Ошибка: ${escapeHtml(previewWidget.error)}</p>`;
    }
    return `<h2>${escapeHtml(t.widgetId)}</h2><p>Строк: ${t.rows}. Файл: ${escapeHtml(t.file)}</p>`;
  }).join('\n');

  const widgetErrors = (preview.widgets || []).filter((w) => w.status === 'error' || w.error);
  const status = previewError || widgetErrors.length
    ? (tables.some((t) => t.rows > 0) ? 'partial' : 'error')
    : 'ok';

  const periodLabel = window.label || `${window.from} — ${window.to}`;
  const html = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>${escapeHtml(obs.name)}</title>
<style>body{font-family:system-ui,sans-serif;margin:24px;color:#111}table{border-collapse:collapse;width:100%;margin:16px 0}td,th{border:1px solid #ddd;padding:6px 8px;font-size:13px}th{background:#f5f5f5;text-align:left}</style>
</head><body>
<h1>${escapeHtml(obs.name)}</h1>
<p>Период (${escapeHtml(period)}): ${escapeHtml(periodLabel)}</p>
<p>Окно UTC: ${escapeHtml(window.from)} — ${escapeHtml(window.to)}</p>
<p>Фильтры: ${escapeHtml(JSON.stringify(obs.filters))}</p>
${previewError ? `<p style="color:#a00">Preview error: ${escapeHtml(previewError)}</p>` : ''}
${htmlTables}
<p style="color:#666">Сформировано ${escapeHtml(startedAt)}.</p>
</body></html>`;
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
        await sendSmtpMail({
          to: recipients,
          subject: `GrapesNTA: ${obs.name} — ${periodLabel}`,
          html,
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
  return { path: full, fileName: safe, contentType: safe.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/csv; charset=utf-8' };
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
      const groupBy = observationChartGroupBy(o, ts).slice(0, 2);
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
        { type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: 15 },
      ],
      lookback: '1h',
    },
    {
      id: 'preset-own-net',
      name: 'Своя сеть',
      filters: [{ field: 'own_network', op: '=', value: '' }],
      widgets: [
        { type: 'timeseries_bps', metric: 'bps', groupBy: [] },
        { type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: 15 },
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
        { type: 'top_table', metric: 'bps', groupBy: ['dst_asn'], limit: 20 },
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
        { type: 'top_table', metric: 'bps', groupBy: ['src_asn'], limit: 15 },
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
    lookbacks: [...LOOKBACKS],
    refreshSecs: [...REFRESH_SECS],
    widgetTypes: [...WIDGET_TYPES],
    nativeFilterFields: [...NATIVE_FILTER_FIELDS],
    presets: observationPresets(),
    schema: explorerSchema(),
  };
}

function backfillProgress(mat) {
  if (!mat?.enabled || !mat.backfillFrom || mat.backfillDone) {
    return mat?.backfillDone ? { done: true, hoursDone: BACKFILL_HOURS, hoursTotal: BACKFILL_HOURS } : null;
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
  MAX_MATERIALIZE,
  MIN_INTERVAL_SEC,
  MIN_REFRESH_SEC,
  ROLLUP_TABLE,
  ROLLUP_BUCKET_SEC,
  ARTIFACTS_DIR,
  BACKFILL_HOURS,
  STUCK_SEC,
  MAX_FAIL_COUNT,
};
