'use strict';

const { executeCommand } = require('../clickhouse');
const { explorerSchema, validateCabinetExplorerFields } = require('../explorer');
const {
  loadAllObservations,
  loadObservationById,
  upsertObservation,
  softDeleteObservation,
} = require('../observations-store');
const {
  newId,
  CABINET_LOOKBACKS,
  collectWidgetGroupFields,
  userIdOf,
  normalizeObservation,
  isNativeAggregateWidget,
  observationUsesNativeAggregate,
  previewObservation,
  MIN_REFRESH_SEC,
  ROLLUP_TABLE,
} = require('../observations');

const CABINET_WIDGET_TYPES = new Set(['timeseries_bps', 'top_table']);
const {
  loadObservationClients,
  upsertObservationClient,
  softDeleteObservationClient,
} = require('../observation-clients');
const { getUserById } = require('../users');

const CABINET_OBSERVATIONS_MAX = (() => {
  const n = Number(process.env.CABINET_OBSERVATIONS_MAX);
  if (!Number.isFinite(n) || n <= 0) return 5;
  return Math.floor(n);
})();

function httpError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function cabinetFieldError(message = 'Поле недоступно в кабинете') {
  return httpError(message, 400);
}

function assertCabinetPayload(raw = {}) {
  const widgets = raw.widgets != null ? raw.widgets : [];
  if (!Array.isArray(widgets) || !widgets.length) {
    throw cabinetFieldError('Нужен хотя бы один виджет');
  }
  for (const w of widgets) {
    if (!CABINET_WIDGET_TYPES.has(w.type)) {
      throw cabinetFieldError(`Недопустимый тип виджета: ${w.type || '?'}`);
    }
    if (isNativeAggregateWidget(w)) {
      throw cabinetFieldError('Нативные графики обзора недоступны в кабинете');
    }
  }
  if (observationUsesNativeAggregate(widgets)) {
    throw cabinetFieldError('Нативные графики обзора недоступны в кабинете');
  }
  const lookback = String(raw.lookback || '').trim();
  if (lookback && !CABINET_LOOKBACKS.has(lookback)) {
    throw cabinetFieldError('Недопустимый период наблюдения');
  }
  const groupBy = collectWidgetGroupFields(widgets);
  try {
    validateCabinetExplorerFields({
      filters: raw.filters || [],
      groupBy,
    });
  } catch (err) {
    throw cabinetFieldError(err.message || 'Поле недоступно в кабинете');
  }
}

async function assertObservationBoundToClient(observationId, clientId) {
  const bindings = await loadObservationClients();
  if (bindings.get(observationId) !== clientId) return null;
  return loadObservationById(observationId);
}

function collectCabinetObservationIds(clientId, bindings, observations) {
  const liveIds = new Set((observations || []).map((o) => o.id));
  const ids = new Set();
  for (const [obsId, cid] of bindings) {
    if (cid === clientId && liveIds.has(obsId)) ids.add(obsId);
  }
  return ids;
}

async function countCabinetObservations(clientId) {
  const [all, bindings] = await Promise.all([
    loadAllObservations(),
    loadObservationClients(),
  ]);
  return collectCabinetObservationIds(clientId, bindings, all).size;
}

function cabinetMaterializeStatus(item) {
  const st = String(item?.materialize?.status || 'queued');
  if (st === 'error') return 'error';
  if (st === 'ready' || st === 'idle' || st === 'ok') {
    return item?.materialize?.dataThrough ? 'ready' : 'preparing';
  }
  if (st === 'queued' || st === 'running' || st === 'lagging') return 'preparing';
  return 'preparing';
}

function stripCabinetObservation(item, meta = {}) {
  if (!item) return null;
  const out = { ...item };
  delete out.ownerId;
  return {
    ...out,
    canEdit: true,
    cabinetStatus: cabinetMaterializeStatus(item),
    quotas: {
      maxObservations: CABINET_OBSERVATIONS_MAX,
      usedObservations: meta.usedCount ?? null,
    },
    ...(meta.author ? { author: meta.author } : {}),
  };
}

async function resolveAuthor(ownerId) {
  const id = String(ownerId || '').trim();
  if (!id) return { kind: 'unknown', label: '—' };
  const user = await getUserById(id);
  if (!user) return { kind: 'unknown', label: '—' };
  const roleId = String(user.roleId || '');
  if (roleId === 'Client') {
    return {
      kind: 'client',
      label: user.fullName || user.username || id,
      userId: id,
    };
  }
  return {
    kind: 'staff',
    label: user.fullName || user.username || id,
    userId: id,
  };
}

async function listCabinetObservations(clientId, { includeAuthor = false } = {}) {
  const [all, bindings] = await Promise.all([
    loadAllObservations(),
    loadObservationClients(),
  ]);
  const ids = collectCabinetObservationIds(clientId, bindings, all);
  const usedCount = ids.size;
  const items = all.filter((o) => ids.has(o.id));
  items.sort((a, b) => {
    const aTs = String(a.editedAt || a.createdAt || a.updatedAt || '');
    const bTs = String(b.editedAt || b.createdAt || b.updatedAt || '');
    return bTs.localeCompare(aTs);
  });
  const out = [];
  for (const item of items) {
    let author;
    if (includeAuthor) {
      author = await resolveAuthor(item.ownerId);
    }
    out.push(stripCabinetObservation(item, { usedCount, author }));
  }
  return out;
}

async function getCabinetObservation(clientId, observationId, opts = {}) {
  const item = await assertObservationBoundToClient(observationId, clientId);
  if (!item) return null;
  const usedCount = await countCabinetObservations(clientId);
  let author;
  if (opts.includeAuthor) {
    author = await resolveAuthor(item.ownerId);
  }
  return stripCabinetObservation(item, { usedCount, author });
}

async function createCabinetObservation(clientId, user, payload = {}) {
  assertCabinetPayload(payload);
  const used = await countCabinetObservations(clientId);
  if (used >= CABINET_OBSERVATIONS_MAX) {
    throw httpError(`Достигнут предел: ${CABINET_OBSERVATIONS_MAX} наблюдений`, 409);
  }
  const uid = userIdOf(user);
  const observationId = newId('obs');
  await upsertObservationClient(observationId, clientId);
  const item = normalizeObservation({
    ...payload,
    materialize: { enabled: true },
    report: { enabled: false },
  }, { userId: uid, existing: { id: observationId }, cabinet: true });
  await upsertObservation(item);
  return getCabinetObservation(clientId, observationId, { includeAuthor: true });
}

async function updateCabinetObservation(clientId, observationId, user, payload = {}) {
  const existing = await assertObservationBoundToClient(observationId, clientId);
  if (!existing) return null;
  assertCabinetPayload({ ...existing, ...payload, widgets: payload.widgets ?? existing.widgets });
  const uid = userIdOf(user);
  const item = normalizeObservation({
    ...existing,
    ...payload,
    id: observationId,
    materialize: { ...(existing.materialize || {}), enabled: true },
    report: { enabled: false },
  }, { userId: uid, existing, cabinet: true });
  await upsertObservation(item);
  return getCabinetObservation(clientId, observationId, { includeAuthor: true });
}

async function deleteCabinetObservation(clientId, observationId) {
  const existing = await assertObservationBoundToClient(observationId, clientId);
  if (!existing) return false;
  await softDeleteObservation(existing);
  await softDeleteObservationClient(observationId);
  executeCommand(`
    ALTER TABLE default.${ROLLUP_TABLE}
    DELETE WHERE observation_id = {id:String}
  `, { id: observationId }, { name: 'cabinet/observations/rollup-cleanup' }).catch(() => {});
  return true;
}

async function duplicateCabinetObservation(clientId, user, observationId, payload = {}) {
  const existing = await assertObservationBoundToClient(observationId, clientId);
  if (!existing) return null;
  const used = await countCabinetObservations(clientId);
  if (used >= CABINET_OBSERVATIONS_MAX) {
    throw httpError(`Достигнут предел: ${CABINET_OBSERVATIONS_MAX} наблюдений`, 409);
  }
  const uid = userIdOf(user);
  const newObservationId = newId('obs');
  await upsertObservationClient(newObservationId, clientId);
  const copy = normalizeObservation({
    ...existing,
    ...payload,
    id: newObservationId,
    name: payload.name || `${existing.name} (копия)`,
    materialize: { enabled: true, status: 'queued' },
    report: { enabled: false },
    createdAt: undefined,
    updatedAt: undefined,
  }, { userId: uid, existing: { id: newObservationId }, cabinet: true });
  await upsertObservation(copy);
  return getCabinetObservation(clientId, newObservationId);
}

async function previewCabinetObservation(clientId, observationId, body = {}) {
  const result = await previewObservation(observationId, null, body, { cabinetClientId: clientId });
  if (!result) return null;
  const obs = { ...result.observation };
  delete obs.ownerId;
  return { ...result, observation: obs };
}

async function retryCabinetObservation(clientId, observationId) {
  const existing = await assertObservationBoundToClient(observationId, clientId);
  if (!existing) return null;
  if (existing.materialize?.status !== 'error') {
    throw httpError('Наблюдение не в ошибке — повторять нечего.', 400);
  }
  const next = {
    ...existing,
    materialize: {
      ...(existing.materialize || {}),
      enabled: true,
      status: 'queued',
      failCount: 0,
      nextAttemptAt: null,
      runningStartedAt: null,
      cancelRequested: false,
      lastError: null,
    },
    updatedAt: new Date().toISOString(),
  };
  await upsertObservation(next);
  return getCabinetObservation(clientId, observationId);
}

function cabinetObservationsConfig() {
  return {
    maxObservations: CABINET_OBSERVATIONS_MAX,
    lookbacks: ['15m', '30m', '1h', '6h', '24h'],
    refreshSecs: [MIN_REFRESH_SEC],
    widgetTypes: ['timeseries_bps', 'top_table'],
    schema: explorerSchema({ cabinet: true }),
  };
}

async function setCabinetObservationsMaterialize(clientId, enabled) {
  const bindings = await loadObservationClients();
  const ids = [];
  for (const [obsId, cid] of bindings) {
    if (cid === clientId) ids.push(obsId);
  }
  if (!ids.length) return 0;
  const all = await loadAllObservations();
  let patched = 0;
  for (const item of all) {
    if (!ids.includes(item.id)) continue;
    const want = Boolean(enabled);
    if (Boolean(item.materialize?.enabled) === want) continue;
    const next = {
      ...item,
      materialize: {
        ...(item.materialize || {}),
        enabled: want,
        status: want ? 'queued' : 'idle',
      },
      updatedAt: new Date().toISOString(),
    };
    await upsertObservation(next);
    patched += 1;
  }
  return patched;
}

module.exports = {
  CABINET_OBSERVATIONS_MAX,
  assertCabinetPayload,
  listCabinetObservations,
  getCabinetObservation,
  createCabinetObservation,
  updateCabinetObservation,
  deleteCabinetObservation,
  duplicateCabinetObservation,
  previewCabinetObservation,
  retryCabinetObservation,
  cabinetObservationsConfig,
  setCabinetObservationsMaterialize,
  countCabinetObservations,
  stripCabinetObservation,
  cabinetMaterializeStatus,
  resolveAuthor,
};
