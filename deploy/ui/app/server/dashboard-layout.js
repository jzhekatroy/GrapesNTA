'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const GRID_COLS = 12;
const LAYOUT_VERSION = 2;
const MAX_LAYOUT_BYTES = 16 * 1024;
const TREND_SPLIT_MIN = 0.35;
const TREND_SPLIT_MAX = 0.65;
const DEFAULT_TREND_SPLIT = 0.5;

const LEGACY_V1_COMPOSITE_IDS = new Set(['traffic-stats', 'traffic-chart-row']);

const OPERATOR_WIDGET_CONSTRAINTS = {
  'stat-max': { allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-avg': { allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-volume': { allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'traffic-chart': { allowedW: [6, 7, 8, 12], minH: 2, maxH: 3 },
  'distribution-protocols': { allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  'distribution-services': { allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  vlan: { allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
  'top-talkers': { allowedW: [6, 7, 8, 12], minH: 2, maxH: 3 },
  countries: { allowedW: [4, 5, 6, 12], minH: 2, maxH: 3 },
  'recent-flows': { allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
};

const OPERATOR_WIDGET_IDS = Object.keys(OPERATOR_WIDGET_CONSTRAINTS);

const DEFAULT_OPERATOR_LAYOUT = {
  version: LAYOUT_VERSION,
  widgets: [
    { id: 'stat-max', x: 0, y: 0, w: 4, h: 1, visible: true },
    { id: 'stat-avg', x: 4, y: 0, w: 4, h: 1, visible: true },
    { id: 'stat-volume', x: 8, y: 0, w: 4, h: 1, visible: true },
    { id: 'traffic-chart', x: 0, y: 1, w: 8, h: 2, visible: true },
    { id: 'distribution-protocols', x: 8, y: 1, w: 4, h: 1, visible: true },
    { id: 'distribution-services', x: 8, y: 2, w: 4, h: 1, visible: true },
    { id: 'vlan', x: 0, y: 3, w: 12, h: 1, visible: true },
    { id: 'top-talkers', x: 0, y: 4, w: 7, h: 2, visible: true },
    { id: 'countries', x: 7, y: 4, w: 5, h: 2, visible: true },
    { id: 'recent-flows', x: 0, y: 6, w: 12, h: 1, visible: true },
  ],
  settings: {
    distribution: {
      protocolsMode: 'share',
      servicesMode: 'share',
      trendSplit: DEFAULT_TREND_SPLIT,
    },
  },
};

const V1_STAT_CHILDREN = ['stat-max', 'stat-avg', 'stat-volume'];
const V1_CHART_CHILDREN = ['traffic-chart', 'distribution-protocols', 'distribution-services'];

let db = null;
let testDbPath = null;

function getDbPath() {
  if (testDbPath) return testDbPath;
  return process.env.DASHBOARD_LAYOUTS_DB
    || path.join(__dirname, 'data', 'dashboard-layouts.db');
}

function clampTrendSplit(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return DEFAULT_TREND_SPLIT;
  return Math.min(TREND_SPLIT_MAX, Math.max(TREND_SPLIT_MIN, n));
}

function normalizeDistributionCardMode(value) {
  return value === 'trend' ? 'trend' : 'share';
}

function cloneLayout(layout) {
  return JSON.parse(JSON.stringify(layout));
}

function nearestAllowedW(value, allowedW) {
  const n = Number(value);
  if (!Number.isFinite(n)) return allowedW[0];
  let best = allowedW[0];
  let bestDist = Math.abs(n - best);
  for (const candidate of allowedW) {
    const dist = Math.abs(n - candidate);
    if (dist < bestDist) {
      best = candidate;
      bestDist = dist;
    }
  }
  return best;
}

function clampWidget(widget, constraints) {
  const w = nearestAllowedW(widget.w, constraints.allowedW);
  const h = Math.min(constraints.maxH, Math.max(constraints.minH, Math.round(Number(widget.h) || constraints.minH)));
  const x = Math.min(GRID_COLS - w, Math.max(0, Math.round(Number(widget.x) || 0)));
  const y = Math.max(0, Math.round(Number(widget.y) || 0));
  return {
    id: widget.id,
    x,
    y,
    w,
    h,
    visible: widget.visible !== false,
  };
}

function normalizeSettings(raw = {}, defaults = DEFAULT_OPERATOR_LAYOUT.settings) {
  const base = defaults || {};
  const input = raw && typeof raw === 'object' ? raw : {};
  const legacyChart = input['traffic-chart-row'] && typeof input['traffic-chart-row'] === 'object'
    ? input['traffic-chart-row']
    : {};
  const chart = input.distribution && typeof input.distribution === 'object'
    ? input.distribution
    : legacyChart;
  const defaultChart = base.distribution || {};
  const legacyMode = chart.distributionMode != null
    ? normalizeDistributionCardMode(chart.distributionMode)
    : null;
  return {
    distribution: {
      protocolsMode: normalizeDistributionCardMode(
        chart.protocolsMode ?? legacyMode ?? defaultChart.protocolsMode ?? 'share',
      ),
      servicesMode: normalizeDistributionCardMode(
        chart.servicesMode ?? legacyMode ?? defaultChart.servicesMode ?? 'share',
      ),
      trendSplit: clampTrendSplit(chart.trendSplit ?? defaultChart.trendSplit),
    },
  };
}

function isLegacyV1Layout(saved) {
  if (!saved || typeof saved !== 'object') return false;
  if (Number(saved.version) >= LAYOUT_VERSION) return false;
  const widgets = Array.isArray(saved.widgets) ? saved.widgets : [];
  return widgets.some((w) => LEGACY_V1_COMPOSITE_IDS.has(String(w.id || '')));
}

function migrateV1ToV2(saved) {
  const byId = new Map((saved.widgets || []).map((w) => [String(w.id), w]));
  const widgets = DEFAULT_OPERATOR_LAYOUT.widgets.map((defaultWidget) => {
    const next = { ...defaultWidget };
    const direct = byId.get(defaultWidget.id);
    if (direct) {
      next.visible = direct.visible !== false;
      next.x = direct.x;
      next.y = direct.y;
      next.w = direct.w;
      next.h = direct.h;
    }
    const statsParent = byId.get('traffic-stats');
    if (statsParent && V1_STAT_CHILDREN.includes(defaultWidget.id)) {
      next.visible = statsParent.visible !== false;
    }
    const chartParent = byId.get('traffic-chart-row');
    if (chartParent && V1_CHART_CHILDREN.includes(defaultWidget.id)) {
      next.visible = chartParent.visible !== false;
    }
    return clampWidget(next, OPERATOR_WIDGET_CONSTRAINTS[defaultWidget.id]);
  });

  return {
    version: LAYOUT_VERSION,
    widgets,
    settings: normalizeSettings(saved.settings),
  };
}

function mergeWithDefaults(saved, defaults = DEFAULT_OPERATOR_LAYOUT) {
  const normalizedSaved = isLegacyV1Layout(saved) ? migrateV1ToV2(saved) : saved;
  const base = cloneLayout(defaults);
  if (!normalizedSaved || typeof normalizedSaved !== 'object') return base;

  const savedWidgets = Array.isArray(normalizedSaved.widgets) ? normalizedSaved.widgets : [];
  const byId = new Map(savedWidgets.map((w) => [String(w.id), w]));
  const mergedWidgets = [];

  for (const defaultWidget of base.widgets) {
    const savedWidget = byId.get(defaultWidget.id);
    if (savedWidget) {
      mergedWidgets.push(clampWidget(
        { ...defaultWidget, ...savedWidget, id: defaultWidget.id },
        OPERATOR_WIDGET_CONSTRAINTS[defaultWidget.id],
      ));
      byId.delete(defaultWidget.id);
    } else {
      mergedWidgets.push(clampWidget(defaultWidget, OPERATOR_WIDGET_CONSTRAINTS[defaultWidget.id]));
    }
  }

  for (const leftover of byId.values()) {
    const id = String(leftover.id || '');
    if (!OPERATOR_WIDGET_CONSTRAINTS[id]) continue;
    mergedWidgets.push(clampWidget(leftover, OPERATOR_WIDGET_CONSTRAINTS[id]));
  }

  mergedWidgets.sort((a, b) => (a.y - b.y) || (a.x - b.x));

  return {
    version: LAYOUT_VERSION,
    widgets: mergedWidgets,
    settings: normalizeSettings(normalizedSaved.settings, base.settings),
  };
}

function validateLayout(layout) {
  if (!layout || typeof layout !== 'object') {
    const err = new Error('Некорректный layout');
    err.statusCode = 400;
    throw err;
  }

  const raw = JSON.stringify(layout);
  if (Buffer.byteLength(raw, 'utf8') > MAX_LAYOUT_BYTES) {
    const err = new Error('Layout слишком большой');
    err.statusCode = 413;
    throw err;
  }

  if (!Array.isArray(layout.widgets) || !layout.widgets.length) {
    const err = new Error('Layout должен содержать виджеты');
    err.statusCode = 400;
    throw err;
  }

  const ids = new Set();
  let visibleCount = 0;

  for (const widget of layout.widgets) {
    const id = String(widget?.id || '');
    if (!OPERATOR_WIDGET_CONSTRAINTS[id]) {
      const err = new Error(`Неизвестный виджет: ${id || '(пусто)'}`);
      err.statusCode = 400;
      throw err;
    }
    if (ids.has(id)) {
      const err = new Error(`Дублирующийся виджет: ${id}`);
      err.statusCode = 400;
      throw err;
    }
    ids.add(id);
    if (widget.visible !== false) visibleCount += 1;
  }

  if (visibleCount < 1) {
    const err = new Error('Должен остаться хотя бы один видимый виджет');
    err.statusCode = 400;
    throw err;
  }

  for (const requiredId of OPERATOR_WIDGET_IDS) {
    if (!ids.has(requiredId)) {
      const err = new Error(`Отсутствует виджет: ${requiredId}`);
      err.statusCode = 400;
      throw err;
    }
  }

  return mergeWithDefaults(layout);
}

function ensureStore() {
  if (db) return db;
  const dbPath = getDbPath();
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS dashboard_layouts (
      user_id TEXT PRIMARY KEY,
      layout_json TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);
  return db;
}

function getLayout(userId) {
  const id = String(userId || '').trim();
  if (!id) return null;
  ensureStore();
  const row = db.prepare(
    'SELECT layout_json, updated_at FROM dashboard_layouts WHERE user_id = ?',
  ).get(id);
  if (!row) return null;
  let parsed;
  try {
    parsed = JSON.parse(String(row.layout_json || '{}'));
  } catch {
    return null;
  }
  return {
    layout: mergeWithDefaults(parsed),
    updatedAt: Number(row.updated_at) || null,
  };
}

function putLayout(userId, layout) {
  const id = String(userId || '').trim();
  if (!id) {
    const err = new Error('userId обязателен');
    err.statusCode = 400;
    throw err;
  }
  const normalized = validateLayout(layout);
  const now = Date.now();
  ensureStore();
  db.prepare(`
    INSERT INTO dashboard_layouts (user_id, layout_json, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      layout_json = excluded.layout_json,
      updated_at = excluded.updated_at
  `).run(id, JSON.stringify(normalized), now);
  return { layout: normalized, updatedAt: now };
}

function resetLayout(userId) {
  const id = String(userId || '').trim();
  if (!id) {
    const err = new Error('userId обязателен');
    err.statusCode = 400;
    throw err;
  }
  ensureStore();
  db.prepare('DELETE FROM dashboard_layouts WHERE user_id = ?').run(id);
  return { layout: null, updatedAt: null };
}

function resetStoreForTests(dbPath = null) {
  if (db) {
    try { db.close(); } catch { /* ignore */ }
  }
  db = null;
  testDbPath = dbPath;
}

module.exports = {
  GRID_COLS,
  LAYOUT_VERSION,
  OPERATOR_WIDGET_IDS,
  OPERATOR_WIDGET_CONSTRAINTS,
  DEFAULT_OPERATOR_LAYOUT,
  isLegacyV1Layout,
  migrateV1ToV2,
  mergeWithDefaults,
  validateLayout,
  clampTrendSplit,
  getLayout,
  putLayout,
  resetLayout,
  resetStoreForTests,
};
