'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const GRID_COLS = 12;
const LAYOUT_VERSION = 3;
const STACK_ID_PATTERN = /^stack-[vh]-[a-z0-9]+$/;
const MAX_LAYOUT_BYTES = 16 * 1024;
const TREND_SPLIT_MIN = 0.35;
const TREND_SPLIT_MAX = 0.65;
const DEFAULT_TREND_SPLIT = 0.5;

const LEGACY_V1_COMPOSITE_IDS = new Set(['traffic-stats', 'traffic-chart-row']);

const OPERATOR_WIDGET_CONSTRAINTS = {
  'stat-max': { allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-avg': { allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-volume': { allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'traffic-chart': { allowedW: [6, 7, 8, 12], minH: 1, maxH: 6 },
  'distribution-protocols': { allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  'distribution-services': { allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  vlan: { allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
  'top-talkers': { allowedW: [6, 7, 8, 12], minH: 2, maxH: 3 },
  countries: { allowedW: [4, 5, 6, 12], minH: 2, maxH: 3 },
  'recent-flows': { allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
};

const STACK_WIDGET_CONSTRAINTS = {
  vertical: { allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 2, maxH: 8 },
  horizontal: { allowedW: [6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 3 },
};

const OPERATOR_WIDGET_IDS = Object.keys(OPERATOR_WIDGET_CONSTRAINTS);

const DEFAULT_OPERATOR_LAYOUT = {
  version: LAYOUT_VERSION,
  widgets: [
    { id: 'stat-max', x: 0, y: 0, w: 4, h: 1, visible: false },
    { id: 'traffic-chart', x: 0, y: 0, w: 8, h: 2, visible: true },
    { id: 'stat-volume', x: 8, y: 0, w: 4, h: 1, visible: false },
    {
      id: 'stack-v-bsu8e0s',
      kind: 'stack',
      direction: 'vertical',
      x: 8,
      y: 0,
      w: 4,
      h: 2,
      visible: true,
      childIds: ['distribution-protocols', 'distribution-services'],
    },
    { id: 'stat-avg', x: 0, y: 2, w: 4, h: 1, visible: false },
    { id: 'vlan', x: 0, y: 2, w: 12, h: 1, visible: false },
    {
      id: 'stack-h-kiphmzp',
      kind: 'stack',
      direction: 'horizontal',
      x: 0,
      y: 2,
      w: 12,
      h: 2,
      visible: true,
      childIds: ['countries', 'top-talkers'],
    },
    { id: 'recent-flows', x: 0, y: 4, w: 12, h: 1, visible: true },
    { id: 'distribution-protocols', x: 0, y: 0, w: 12, h: 1, visible: true, parentStack: 'stack-v-bsu8e0s' },
    { id: 'top-talkers', x: 0, y: 0, w: 6, h: 2, visible: true, parentStack: 'stack-h-kiphmzp' },
    { id: 'countries', x: 6, y: 0, w: 6, h: 2, visible: true, parentStack: 'stack-h-kiphmzp' },
    { id: 'distribution-services', x: 0, y: 1, w: 12, h: 1, visible: true, parentStack: 'stack-v-bsu8e0s' },
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

function dashboardHeightStep(widgetId) {
  return widgetId === 'traffic-chart' ? 0.5 : 1;
}

function snapDashboardHeight(h, minH, maxH, step = 1) {
  const raw = Number(h);
  const n = Number.isFinite(raw) ? raw : minH;
  const snapped = Math.round(n / step) * step;
  const clean = Math.round(snapped / step) * step;
  return Math.min(maxH, Math.max(minH, clean));
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

function isStackWidget(widget) {
  return widget?.kind === 'stack' || isStackWidgetId(widget?.id);
}

function isStackWidgetId(id) {
  return STACK_ID_PATTERN.test(String(id || ''));
}

function stackDirectionKey(direction) {
  return direction === 'horizontal' ? 'horizontal' : 'vertical';
}

function clampContentWidget(widget, constraints) {
  const inner = !!widget.parentStack;
  const h = snapDashboardHeight(widget.h, constraints.minH, constraints.maxH, dashboardHeightStep(widget.id));
  const y = Math.max(0, Math.round(Number(widget.y) || 0));
  const w = inner
    ? Math.min(GRID_COLS, Math.max(1, Math.round(Number(widget.w) || 1)))
    : nearestAllowedW(widget.w, constraints.allowedW);
  const x = Math.min(GRID_COLS - w, Math.max(0, Math.round(Number(widget.x) || 0)));
  const next = {
    id: widget.id,
    x,
    y,
    w,
    h,
    visible: widget.visible !== false,
  };
  if (widget.parentStack) next.parentStack = String(widget.parentStack);
  return next;
}

function clampStackWidget(widget) {
  const direction = stackDirectionKey(
    widget.direction || (String(widget.id || '').startsWith('stack-h') ? 'horizontal' : 'vertical'),
  );
  const constraints = STACK_WIDGET_CONSTRAINTS[direction];
  const w = nearestAllowedW(widget.w, constraints.allowedW);
  const h = Math.min(constraints.maxH, Math.max(constraints.minH, Math.round(Number(widget.h) || constraints.minH)));
  const x = Math.min(GRID_COLS - w, Math.max(0, Math.round(Number(widget.x) || 0)));
  const y = Math.max(0, Math.round(Number(widget.y) || 0));
  return {
    id: String(widget.id),
    kind: 'stack',
    direction,
    x,
    y,
    w,
    h,
    visible: widget.visible !== false,
    childIds: Array.isArray(widget.childIds)
      ? widget.childIds.map((id) => String(id)).filter(Boolean)
      : [],
  };
}

function clampWidget(widget, constraints) {
  return clampContentWidget(widget, constraints);
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
    if (isStackWidget(defaultWidget)) return clampStackWidget(defaultWidget);
    const next = { ...defaultWidget };
    const direct = byId.get(defaultWidget.id);
    if (direct && !defaultWidget.parentStack) {
      next.visible = direct.visible !== false;
      next.x = direct.x;
      next.y = direct.y;
      next.w = direct.w;
      next.h = direct.h;
    } else if (direct) {
      next.visible = direct.visible !== false;
    }
    const statsParent = byId.get('traffic-stats');
    if (statsParent && V1_STAT_CHILDREN.includes(defaultWidget.id)) {
      next.visible = statsParent.visible !== false;
    }
    const chartParent = byId.get('traffic-chart-row');
    if (chartParent && V1_CHART_CHILDREN.includes(defaultWidget.id)) {
      next.visible = chartParent.visible !== false;
    }
    return clampContentWidget(next, OPERATOR_WIDGET_CONSTRAINTS[defaultWidget.id]);
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
    if (isStackWidget(defaultWidget)) {
      if (!savedWidget) continue;
      mergedWidgets.push(clampStackWidget({ ...defaultWidget, ...savedWidget, id: defaultWidget.id }));
      byId.delete(defaultWidget.id);
      continue;
    }
    const constraints = OPERATOR_WIDGET_CONSTRAINTS[defaultWidget.id];
    if (savedWidget) {
      const merged = { ...defaultWidget, ...savedWidget, id: defaultWidget.id };
      if (!savedWidget.parentStack) delete merged.parentStack;
      mergedWidgets.push(clampContentWidget(merged, constraints));
      byId.delete(defaultWidget.id);
    } else {
      const fresh = { ...defaultWidget };
      delete fresh.parentStack;
      mergedWidgets.push(clampContentWidget(fresh, constraints));
    }
  }

  for (const leftover of byId.values()) {
    const id = String(leftover.id || '');
    if (isStackWidget(leftover) && isStackWidgetId(id)) {
      mergedWidgets.push(clampStackWidget(leftover));
    }
  }

  mergedWidgets.sort((a, b) => {
    if (a.parentStack && !b.parentStack) return 1;
    if (!a.parentStack && b.parentStack) return -1;
    return (a.y - b.y) || (a.x - b.x);
  });

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
  const stacksById = new Map();
  const parentByContentId = new Map();

  for (const widget of layout.widgets) {
    const id = String(widget?.id || '');
    if (isStackWidget(widget)) {
      if (!isStackWidgetId(id)) {
        const err = new Error(`Некорректный стек: ${id || '(пусто)'}`);
        err.statusCode = 400;
        throw err;
      }
      if (ids.has(id)) {
        const err = new Error(`Дублирующийся стек: ${id}`);
        err.statusCode = 400;
        throw err;
      }
      ids.add(id);
      stacksById.set(id, clampStackWidget(widget));
      if (widget.visible !== false) visibleCount += 1;
      continue;
    }

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
    if (widget.parentStack) parentByContentId.set(id, String(widget.parentStack));
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

  for (const [childId, stackId] of parentByContentId.entries()) {
    const stack = stacksById.get(stackId);
    if (!stack) {
      const err = new Error(`Стек не найден для виджета: ${childId}`);
      err.statusCode = 400;
      throw err;
    }
    if (!stack.childIds.includes(childId)) {
      const err = new Error(`Виджет ${childId} не входит в стек ${stackId}`);
      err.statusCode = 400;
      throw err;
    }
  }

  for (const stack of stacksById.values()) {
    for (const childId of stack.childIds) {
      if (!OPERATOR_WIDGET_CONSTRAINTS[childId]) {
        const err = new Error(`Стек ${stack.id} содержит неизвестный виджет: ${childId}`);
        err.statusCode = 400;
        throw err;
      }
      if (parentByContentId.get(childId) !== stack.id) {
        const err = new Error(`Несогласованный parentStack для ${childId}`);
        err.statusCode = 400;
        throw err;
      }
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
