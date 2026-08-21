/* Operator dashboard layout: grid, edit mode, server persistence. */

const { useState, useEffect, useLayoutEffect, useCallback, useRef } = React;

const DASHBOARD_GRID_COLS = 12;
const DASHBOARD_LAYOUT_SAVE_MS = 400;
const DASHBOARD_CHART_SPLIT_KEY = 'grapes-dashboard-chart-split';
const DEFAULT_TREND_SPLIT = 0.5;
const TREND_SPLIT_MIN = 0.35;
const TREND_SPLIT_MAX = 0.65;
const SHARE_RIGHT_SPLIT = 1 / 3;

const DASHBOARD_LAYOUT_VERSION = 2;
const LEGACY_V1_COMPOSITE_IDS = new Set(['traffic-stats', 'traffic-chart-row']);

const OPERATOR_WIDGET_REGISTRY = {
  'stat-max': { label: 'Максимально', allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-avg': { label: 'Среднее', allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-volume': { label: 'Объём', allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'traffic-chart': { label: 'График трафика', allowedW: [6, 7, 8, 12], minH: 2, maxH: 3 },
  'distribution-protocols': { label: 'Протоколы', allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  'distribution-services': { label: 'Сервисы', allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  vlan: { label: 'VLAN', allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
  'top-talkers': { label: 'Топ ASN', allowedW: [6, 7, 8, 12], minH: 2, maxH: 3 },
  countries: { label: 'География', allowedW: [4, 5, 6, 12], minH: 2, maxH: 3 },
  'recent-flows': { label: 'Последние потоки', allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
};

const DEFAULT_OPERATOR_LAYOUT = {
  version: DASHBOARD_LAYOUT_VERSION,
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

function isStatWidgetId(id) {
  return V1_STAT_CHILDREN.includes(id);
}

function cloneDashboardLayout(layout) {
  return JSON.parse(JSON.stringify(layout));
}

function clampTrendSplit(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return DEFAULT_TREND_SPLIT;
  return Math.min(TREND_SPLIT_MAX, Math.max(TREND_SPLIT_MIN, n));
}

function loadLegacyTrendSplit() {
  try {
    const raw = localStorage.getItem(DASHBOARD_CHART_SPLIT_KEY);
    if (raw == null) return null;
    const n = Number(raw);
    if (!Number.isFinite(n)) return null;
    const split = clampTrendSplit(n);
    if (Math.abs(split - SHARE_RIGHT_SPLIT) < 0.005) return null;
    return split;
  } catch {
    return null;
  }
}

function clearLegacyTrendSplit() {
  try {
    localStorage.removeItem(DASHBOARD_CHART_SPLIT_KEY);
  } catch { /* ignore */ }
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

function clampDashboardWidget(widget, registry = OPERATOR_WIDGET_REGISTRY) {
  const meta = registry[widget.id];
  if (!meta) return null;
  const w = nearestAllowedW(widget.w, meta.allowedW);
  const h = Math.min(meta.maxH, Math.max(meta.minH, Math.round(Number(widget.h) || meta.minH)));
  const x = Math.min(DASHBOARD_GRID_COLS - w, Math.max(0, Math.round(Number(widget.x) || 0)));
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

function normalizeDistributionCardMode(value) {
  return value === 'trend' ? 'trend' : 'share';
}

function normalizeDashboardSettings(raw, defaults = DEFAULT_OPERATOR_LAYOUT.settings) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const base = defaults || {};
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
  if (Number(saved.version) >= DASHBOARD_LAYOUT_VERSION) return false;
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
    return clampDashboardWidget(next);
  });
  return {
    version: DASHBOARD_LAYOUT_VERSION,
    widgets,
    settings: normalizeDashboardSettings(saved.settings),
  };
}

function mergeDashboardLayout(saved, defaults = DEFAULT_OPERATOR_LAYOUT) {
  const normalizedSaved = isLegacyV1Layout(saved) ? migrateV1ToV2(saved) : saved;
  const base = cloneDashboardLayout(defaults);
  if (!normalizedSaved || typeof normalizedSaved !== 'object') return base;

  const savedWidgets = Array.isArray(normalizedSaved.widgets) ? normalizedSaved.widgets : [];
  const byId = new Map(savedWidgets.map((w) => [String(w.id), w]));
  const mergedWidgets = [];

  for (const defaultWidget of base.widgets) {
    const savedWidget = byId.get(defaultWidget.id);
    if (savedWidget) {
      mergedWidgets.push(clampDashboardWidget(
        { ...defaultWidget, ...savedWidget, id: defaultWidget.id },
      ));
      byId.delete(defaultWidget.id);
    } else {
      mergedWidgets.push(clampDashboardWidget(defaultWidget));
    }
  }

  for (const leftover of byId.values()) {
    const id = String(leftover.id || '');
    if (!OPERATOR_WIDGET_REGISTRY[id]) continue;
    mergedWidgets.push(clampDashboardWidget(leftover));
  }

  mergedWidgets.sort((a, b) => (a.y - b.y) || (a.x - b.x));

  const layout = {
    version: DASHBOARD_LAYOUT_VERSION,
    widgets: mergedWidgets,
    settings: normalizeDashboardSettings(normalizedSaved.settings, base.settings),
  };

  const legacySplit = loadLegacyTrendSplit();
  if (legacySplit != null) {
    layout.settings.distribution.trendSplit = legacySplit;
  }

  layout.widgets = finalizeResizeDashboardLayout(layout.widgets);
  return layout;
}

function sortDashboardWidgets(widgets) {
  return [...widgets].sort((a, b) => (a.y - b.y) || (a.x - b.x));
}

function dashboardWidgetsOverlap(a, b) {
  if (!a || !b || a.id === b.id) return false;
  return a.x < b.x + b.w
    && a.x + a.w > b.x
    && a.y < b.y + b.h
    && a.y + a.h > b.y;
}

function dashboardLayoutHasCollisions(visible) {
  for (let i = 0; i < visible.length; i += 1) {
    for (let j = i + 1; j < visible.length; j += 1) {
      if (dashboardWidgetsOverlap(visible[i], visible[j])) return true;
    }
  }
  return false;
}

function finalizeResizeDashboardLayout(widgets) {
  const hidden = widgets.filter((w) => !w.visible);
  const visible = sortDashboardWidgets(widgets.filter((w) => w.visible !== false));
  if (!dashboardLayoutHasCollisions(visible)) return widgets;
  return repackDashboardWidgets([...visible, ...hidden], { keepOrder: true });
}

function layoutHiddenDashboardWidgets(visibleWidgets, hidden, { startY = null } = {}) {
  if (!hidden.length) return [];
  const maxY = visibleWidgets.reduce((max, widget) => Math.max(max, widget.y + widget.h), 0);
  let y = startY ?? maxY;
  return hidden.map((widget) => {
    const placed = clampDashboardWidget({
      ...widget,
      x: 0,
      y,
      w: DASHBOARD_GRID_COLS,
    });
    y += placed.h;
    return placed;
  });
}

function ensureOccupancyRows(grid, rows) {
  while (grid.length < rows) grid.push(Array(DASHBOARD_GRID_COLS).fill(null));
}

function canPlaceOnGrid(grid, x, y, w, h) {
  ensureOccupancyRows(grid, y + h);
  for (let dy = 0; dy < h; dy += 1) {
    for (let dx = 0; dx < w; dx += 1) {
      if (grid[y + dy][x + dx] != null) return false;
    }
  }
  return true;
}

function markGridOccupancy(grid, x, y, w, h, id) {
  ensureOccupancyRows(grid, y + h);
  for (let dy = 0; dy < h; dy += 1) {
    for (let dx = 0; dx < w; dx += 1) {
      grid[y + dy][x + dx] = id;
    }
  }
}

function preferredWidgetWidths(widget) {
  const meta = OPERATOR_WIDGET_REGISTRY[widget.id];
  const allowed = meta?.allowedW || [DASHBOARD_GRID_COLS];
  return [...allowed].sort((a, b) => Math.abs(a - widget.w) - Math.abs(b - widget.w));
}

function findWidgetPlacement(widget, grid) {
  const clamped = clampDashboardWidget(widget);
  if (!clamped) return null;
  const widths = preferredWidgetWidths(clamped);
  const h = clamped.h;

  for (let y = 0; y < 200; y += 1) {
    for (let x = 0; x < DASHBOARD_GRID_COLS; x += 1) {
      for (const w of widths) {
        if (x + w > DASHBOARD_GRID_COLS) continue;
        if (canPlaceOnGrid(grid, x, y, w, h)) {
          return { ...clamped, x, y, w, h };
        }
      }
    }
  }
  return null;
}

function normalizeGroupedStatWidths(visible) {
  const list = visible.map((widget) => ({ ...widget }));
  for (let i = 0; i < list.length; i += 1) {
    if (!isStatWidgetId(list[i].id)) continue;
    let j = i;
    while (j < list.length && isStatWidgetId(list[j].id)) j += 1;
    const runLen = j - i;
    if (runLen === 3) {
      for (let k = i; k < j; k += 1) list[k] = { ...list[k], w: 4 };
    } else if (runLen === 2) {
      list[i] = { ...list[i], w: 6 };
      list[i + 1] = { ...list[i + 1], w: 6 };
    }
    i = j - 1;
  }
  return list;
}

function layoutDashboardWidgets(visible) {
  const grid = [];
  const packed = [];
  for (const widget of visible) {
    const placed = findWidgetPlacement(widget, grid);
    if (!placed) continue;
    markGridOccupancy(grid, placed.x, placed.y, placed.w, placed.h, placed.id);
    packed.push(placed);
  }
  return packed;
}

function repackDashboardWidgets(widgets, { keepOrder = false } = {}) {
  const hidden = widgets.filter((w) => !w.visible);
  let visible = keepOrder
    ? widgets.filter((w) => w.visible !== false)
    : sortDashboardWidgets(widgets.filter((w) => w.visible));
  visible = normalizeGroupedStatWidths(visible);
  const packed = layoutDashboardWidgets(visible);
  return [...packed, ...layoutHiddenDashboardWidgets(packed, hidden)];
}

function moveDashboardWidget(widgets, sourceId, targetId, { insertAfter = false } = {}) {
  if (!sourceId || !targetId || sourceId === targetId) return widgets;
  const visible = sortDashboardWidgets(widgets.filter((w) => w.visible));
  const hidden = widgets.filter((w) => !w.visible);
  const fromIdx = visible.findIndex((w) => w.id === sourceId);
  let toIdx = visible.findIndex((w) => w.id === targetId);
  if (fromIdx < 0 || toIdx < 0) return widgets;
  if (insertAfter) toIdx += 1;
  if (fromIdx < toIdx) toIdx -= 1;

  const nextVisible = [...visible];
  const [moved] = nextVisible.splice(fromIdx, 1);
  nextVisible.splice(toIdx, 0, moved);
  return repackDashboardWidgets([...nextVisible, ...hidden], { keepOrder: true });
}

function previewDashboardMove(widgets, sourceId, targetId, options) {
  if (!sourceId || !targetId) return null;
  if (sourceId === targetId && !options?.insertAfter) return null;
  return moveDashboardWidget(widgets, sourceId, targetId, options);
}

function findDropTargetFromPoint(clientX, clientY, sourceId, grid, layoutWidgets) {
  if (!grid) return null;

  const activeWidgets = sortDashboardWidgets(
    layoutWidgets.filter((w) => w.visible !== false && w.id !== sourceId),
  );
  if (!activeWidgets.length) return null;

  const gridRect = grid.getBoundingClientRect();
  const colWidth = gridRect.width / DASHBOARD_GRID_COLS;
  const hoverCol = Math.max(0, Math.min(
    DASHBOARD_GRID_COLS - 1,
    Math.floor((clientX - gridRect.left) / Math.max(colWidth, 1)),
  ));

  const rowsByY = new Map();
  for (const widget of activeWidgets) {
    if (!rowsByY.has(widget.y)) rowsByY.set(widget.y, []);
    rowsByY.get(widget.y).push(widget);
  }

  let targetRow = null;

  for (const [, rowWidgets] of rowsByY.entries()) {
    let rowTop = Infinity;
    let rowBottom = -Infinity;
    for (const widget of rowWidgets) {
      const el = grid.querySelector(`[data-widget-id="${widget.id}"]`);
      if (!el) continue;
      const rect = el.getBoundingClientRect();
      rowTop = Math.min(rowTop, rect.top);
      rowBottom = Math.max(rowBottom, rect.bottom);
    }
    if (!Number.isFinite(rowTop)) continue;
    if (clientY >= rowTop - 20 && clientY <= rowBottom + 20) {
      targetRow = rowWidgets.sort((a, b) => a.x - b.x);
      break;
    }
  }

  if (!targetRow) {
    const rowEntries = [...rowsByY.entries()].sort((a, b) => a[0] - b[0]);
    let nearest = rowEntries[0]?.[1]?.sort((a, b) => a.x - b.x) || null;
    let nearestDist = Infinity;
    for (const [, rowWidgets] of rowEntries) {
      let rowTop = Infinity;
      let rowBottom = -Infinity;
      for (const widget of rowWidgets) {
        const el = grid.querySelector(`[data-widget-id="${widget.id}"]`);
        if (!el) continue;
        const rect = el.getBoundingClientRect();
        rowTop = Math.min(rowTop, rect.top);
        rowBottom = Math.max(rowBottom, rect.bottom);
      }
      if (!Number.isFinite(rowTop)) continue;
      const rowMid = (rowTop + rowBottom) / 2;
      const dist = Math.abs(clientY - rowMid);
      if (dist < nearestDist) {
        nearestDist = dist;
        nearest = rowWidgets.sort((a, b) => a.x - b.x);
      }
    }
    targetRow = nearest;
  }

  if (!targetRow?.length) {
    const last = activeWidgets[activeWidgets.length - 1];
    return { id: last.id, insertAfter: true };
  }

  for (let i = 0; i < targetRow.length; i += 1) {
    const widget = targetRow[i];
    const startCol = widget.x;
    const endCol = widget.x + widget.w - 1;

    if (hoverCol < startCol) {
      return { id: widget.id, insertAfter: false };
    }

    if (hoverCol >= startCol && hoverCol <= endCol) {
      const midCol = widget.x + widget.w / 2;
      return hoverCol < midCol
        ? { id: widget.id, insertAfter: false }
        : { id: widget.id, insertAfter: true };
    }

    const next = targetRow[i + 1];
    if (!next && hoverCol > endCol) {
      return { id: widget.id, insertAfter: true };
    }
    if (next && hoverCol > endCol && hoverCol < next.x) {
      return { id: widget.id, insertAfter: true };
    }
  }

  const last = targetRow[targetRow.length - 1];
  return { id: last.id, insertAfter: true };
}

function resizeDashboardWidgetHeight(widgets, widgetId, nextH, { anchorBottom = null } = {}) {
  const list = widgets.map((w) => ({ ...w }));
  const idx = list.findIndex((w) => w.id === widgetId);
  if (idx < 0) return widgets;

  const widget = list[idx];
  const meta = OPERATOR_WIDGET_REGISTRY[widget.id];
  if (!meta || meta.maxH <= meta.minH) return widgets;

  let h = Math.min(meta.maxH, Math.max(meta.minH, Math.round(Number(nextH) || meta.minH)));
  let y = widget.y;
  if (anchorBottom != null) {
    y = anchorBottom - h;
    if (y < 0) {
      y = 0;
      h = Math.min(meta.maxH, Math.max(meta.minH, anchorBottom));
    }
  }

  list[idx] = clampDashboardWidget({ ...widget, y: Math.max(0, y), h });
  return finalizeResizeDashboardLayout(list);
}

function resizeDashboardWidget(widgets, widgetId, nextW, { anchorRight = null } = {}) {
  const list = widgets.map((w) => ({ ...w }));
  const idx = list.findIndex((w) => w.id === widgetId);
  if (idx < 0) return widgets;

  const widget = list[idx];
  const meta = OPERATOR_WIDGET_REGISTRY[widget.id];
  if (!meta) return widgets;

  let newW = nearestAllowedW(nextW, meta.allowedW);
  let x = widget.x;
  if (anchorRight != null) {
    x = anchorRight - newW;
    if (x < 0) {
      x = 0;
      newW = nearestAllowedW(anchorRight, meta.allowedW);
    }
  } else if (x + newW > DASHBOARD_GRID_COLS) {
    x = DASHBOARD_GRID_COLS - newW;
  }

  list[idx] = clampDashboardWidget({
    ...widget,
    x: Math.max(0, x),
    w: newW,
  });
  return finalizeResizeDashboardLayout(list);
}

function previewResizeDashboardWidget(widgets, widgetId, { w, h, anchorRight, anchorBottom } = {}) {
  let next = widgets;
  if (w != null) next = resizeDashboardWidget(next, widgetId, w, { anchorRight });
  if (h != null) next = resizeDashboardWidgetHeight(next, widgetId, h, { anchorBottom });
  return next;
}

function finalizeDashboardWidgetLayout(prev, widgets) {
  return {
    ...prev,
    version: DASHBOARD_LAYOUT_VERSION,
    widgets: widgets.map((widget) => clampDashboardWidget(widget)).filter(Boolean),
  };
}

function toggleDashboardWidgetVisibility(widgets, widgetId, visible) {
  const nextVisible = visible !== false;
  const visibleCount = widgets.filter((w) => w.visible && w.id !== widgetId).length;
  if (!nextVisible && visibleCount < 1) return widgets;
  const next = widgets.map((w) => (
    w.id === widgetId ? { ...w, visible: nextVisible } : w
  ));
  return repackDashboardWidgets(next);
}

function useDashboardLayout({ enabled = true, canEdit = true } = {}) {
  const [layout, setLayout] = useState(() => mergeDashboardLayout(null));
  const [loadState, setLoadState] = useState(enabled ? 'loading' : 'ready');
  const [saveState, setSaveState] = useState('idle');
  const [editMode, setEditMode] = useState(false);
  const layoutRef = useRef(layout);
  const saveTimerRef = useRef(null);
  const pendingSaveRef = useRef(false);

  layoutRef.current = layout;

  useEffect(() => {
    if (!enabled) {
      setLoadState('ready');
      return undefined;
    }
    let cancelled = false;
    setLoadState('loading');
    ApiClient.loadDashboardLayout()
      .then((result) => {
        if (cancelled) return;
        setLayout(mergeDashboardLayout(result.data));
        setLoadState('ready');
      })
      .catch(() => {
        if (!cancelled) {
          setLayout(mergeDashboardLayout(null));
          setLoadState('error');
        }
      });
    return () => { cancelled = true; };
  }, [enabled]);

  const flushSave = useCallback(async () => {
    if (!canEdit) return;
    const payload = layoutRef.current;
    pendingSaveRef.current = false;
    setSaveState('saving');
    try {
      await ApiClient.saveDashboardLayout(payload);
      clearLegacyTrendSplit();
      setSaveState('saved');
    } catch {
      setSaveState('error');
    }
  }, [canEdit]);

  const scheduleSave = useCallback(() => {
    if (!canEdit) return;
    pendingSaveRef.current = true;
    setSaveState('pending');
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      saveTimerRef.current = null;
      flushSave();
    }, DASHBOARD_LAYOUT_SAVE_MS);
  }, [canEdit, flushSave]);

  useEffect(() => () => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
  }, []);

  const updateLayout = useCallback((updater, { save = true } = {}) => {
    setLayout((prev) => {
      const next = typeof updater === 'function' ? updater(prev) : updater;
      if (Array.isArray(next.widgets)) {
        return finalizeDashboardWidgetLayout(prev, next.widgets);
      }
      if (next.settings && next.widgets === prev.widgets) {
        return {
          ...prev,
          settings: normalizeDashboardSettings(next.settings, DEFAULT_OPERATOR_LAYOUT.settings),
        };
      }
      return mergeDashboardLayout(next);
    });
    if (save) scheduleSave();
  }, [scheduleSave]);

  const setDistributionSettings = useCallback((patch) => {
    setLayout((prev) => {
      const distribution = {
        ...(prev.settings?.distribution || {}),
        ...patch,
      };
      delete distribution.distributionMode;
      return {
        ...prev,
        settings: normalizeDashboardSettings({
          ...prev.settings,
          distribution,
        }, DEFAULT_OPERATOR_LAYOUT.settings),
      };
    });
    scheduleSave();
  }, [scheduleSave]);

  const resetLayout = useCallback(async () => {
    if (!canEdit) return;
    setSaveState('saving');
    try {
      await ApiClient.resetDashboardLayout();
      clearLegacyTrendSplit();
      setLayout(mergeDashboardLayout(null));
      setSaveState('saved');
    } catch {
      setSaveState('error');
    }
  }, [canEdit]);

  return {
    layout,
    loadState,
    saveState,
    editMode,
    setEditMode,
    updateLayout,
    setDistributionSettings,
    resetLayout,
    moveWidget: (sourceId, targetId, options) => updateLayout((prev) => ({
      ...prev,
      widgets: moveDashboardWidget(prev.widgets, sourceId, targetId, options),
    })),
    resizeWidget: (widgetId, nextW, options) => updateLayout((prev) => ({
      ...prev,
      widgets: resizeDashboardWidget(prev.widgets, widgetId, nextW, options),
    })),
    resizeWidgetHeight: (widgetId, nextH, options) => updateLayout((prev) => ({
      ...prev,
      widgets: resizeDashboardWidgetHeight(prev.widgets, widgetId, nextH, options),
    })),
    setWidgetVisible: (widgetId, visible) => updateLayout((prev) => ({
      ...prev,
      widgets: toggleDashboardWidgetVisibility(prev.widgets, widgetId, visible),
    })),
  };
}

function DashboardLayoutToolbar({
  editMode,
  onToggleEdit,
  onReset,
  saveState,
  canEdit,
}) {
  if (!canEdit) return null;

  const saveLabel = {
    idle: '',
    pending: 'Сохранение…',
    saving: 'Сохранение…',
    saved: 'Сохранено',
    error: 'Ошибка сохранения',
  }[saveState] || '';

  return (
    <div className="dashboard-layout-toolbar">
      {saveLabel ? (
        <span className={`dashboard-layout-toolbar__status${saveState === 'error' ? ' is-error' : ''}`}>
          {saveLabel}
        </span>
      ) : null}
      {editMode ? (
        <>
          <Button kind="ghost" size="sm" onClick={onReset}>Сбросить</Button>
          <Button kind="primary" size="sm" onClick={() => onToggleEdit(false)}>Готово</Button>
        </>
      ) : (
        <Button kind="ghost" size="sm" icon="sliders" onClick={() => onToggleEdit(true)}>Настроить</Button>
      )}
    </div>
  );
}

function DashboardWidgetChrome({
  widget,
  editMode,
  onToggleVisibility,
  onDragHandleMouseDown,
  children,
}) {
  if (!editMode) return children;

  const meta = OPERATOR_WIDGET_REGISTRY[widget.id];

  return (
    <div className={`dashboard-widget-chrome${widget.visible ? '' : ' is-hidden'}`}>
      <div className="dashboard-widget-chrome__bar">
        <div
          className="dashboard-widget-chrome__handle"
          title="Перетащите для изменения порядка"
          onMouseDown={onDragHandleMouseDown}
        >
          <Icon name="drag" />
          <span>{meta?.label || widget.id}</span>
        </div>
        <button
          type="button"
          className="dashboard-widget-chrome__hide"
          title={widget.visible ? 'Скрыть виджет' : 'Показать виджет'}
          onClick={onToggleVisibility}
        >
          <Icon name={widget.visible ? 'eyeOff' : 'eye'} />
        </button>
      </div>
      <div className="dashboard-widget-chrome__body">
        {children}
      </div>
    </div>
  );
}

function DashboardWidgetPhantom({ widget, compact, detail }) {
  const meta = OPERATOR_WIDGET_REGISTRY[widget.id];
  const w = compact ? DASHBOARD_GRID_COLS : widget.w;
  const style = {
    gridColumn: `${widget.x + 1} / span ${w}`,
    gridRow: `${widget.y + 1} / span ${widget.h}`,
  };

  return (
    <div
      className="dashboard-widget dashboard-widget--phantom"
      style={style}
      data-flip-id={`phantom-${widget.id}`}
      aria-hidden="true"
    >
      <div className="dashboard-widget-phantom__frame">
        <span>{detail || meta?.label || widget.id}</span>
      </div>
    </div>
  );
}

function dashboardWidgetStyle(widget, compact) {
  const w = compact ? DASHBOARD_GRID_COLS : widget.w;
  return {
    gridColumn: `${widget.x + 1} / span ${w}`,
    gridRow: `${widget.y + 1} / span ${widget.h}`,
    '--dw-w': w,
  };
}

const DASHBOARD_FLIP_TRANSITION = 'transform 0.34s cubic-bezier(0.22, 1, 0.36, 1)';

function dashboardLayoutPreviewKey(widgets) {
  return widgets
    .filter((w) => w.visible !== false)
    .map((w) => `${w.id}@${w.x},${w.y},${w.w},${w.h}`)
    .join('|');
}

function captureDashboardFlipRects(grid) {
  if (!grid) return new Map();
  const rects = new Map();
  grid.querySelectorAll('[data-flip-id]').forEach((el) => {
    const id = el.dataset.flipId;
    if (!id) return;
    rects.set(id, el.getBoundingClientRect());
  });
  return rects;
}

function runDashboardFlipAnimation(grid, firstRects) {
  if (!grid || !firstRects?.size) return;
  grid.querySelectorAll('[data-flip-id]').forEach((el) => {
    const id = el.dataset.flipId;
    const first = firstRects.get(id);
    if (!first) return;
    const last = el.getBoundingClientRect();
    const dx = first.left - last.left;
    const dy = first.top - last.top;
    if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) return;

    el.style.transform = `translate3d(${dx}px, ${dy}px, 0)`;
    el.style.transition = 'none';

    requestAnimationFrame(() => {
      el.style.transition = DASHBOARD_FLIP_TRANSITION;
      el.style.transform = '';
    });
  });
}

function DashboardGrid({
  layout,
  distributionModes,
  editMode,
  renderers,
  onMoveWidget,
  onResizeWidget,
  onResizeWidgetHeight,
  onToggleWidgetVisible,
}) {
  const gridRef = useRef(null);
  const dragSourceRef = useRef(null);
  const flipFirstRectsRef = useRef(null);
  const dragPreviewKeyRef = useRef('');
  const dragMoveRafRef = useRef(null);
  const resizeMoveRafRef = useRef(null);
  const [dragPreview, setDragPreview] = useState(null);
  const [resizePreview, setResizePreview] = useState(null);
  const dragContextRef = useRef({ layout, dragPreview, resizePreview });
  const [draggingId, setDraggingId] = useState(null);
  const [resizingId, setResizingId] = useState(null);
  const [compact, setCompact] = useState(() => (
    typeof window !== 'undefined' ? window.matchMedia('(max-width: 1200px)').matches : false
  ));

  dragContextRef.current = { layout, dragPreview, resizePreview };

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 1200px)');
    const onChange = () => setCompact(mq.matches);
    onChange();
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  useLayoutEffect(() => {
    if (!flipFirstRectsRef.current || !gridRef.current) return;
    runDashboardFlipAnimation(gridRef.current, flipFirstRectsRef.current);
    flipFirstRectsRef.current = null;
  }, [dragPreview, resizePreview, layout.widgets, draggingId, resizingId]);

  const layoutWidgets = resizePreview?.widgets || dragPreview?.widgets || layout.widgets;
  const visibleWidgets = sortDashboardWidgets(
    layoutWidgets.filter((w) => w.visible && !(draggingId && w.id === draggingId)),
  );
  const hiddenSource = layoutWidgets.filter((w) => !w.visible);
  const maxVisibleY = visibleWidgets.reduce((max, widget) => Math.max(max, widget.y + widget.h), 0);
  const hiddenWidgets = editMode
    ? layoutHiddenDashboardWidgets(visibleWidgets, hiddenSource, { startY: maxVisibleY + 1 })
    : [];
  const hiddenDividerY = editMode && hiddenWidgets.length ? maxVisibleY : null;
  const phantomWidget = draggingId && dragPreview
    ? layoutWidgets.find((w) => w.id === draggingId && w.visible !== false)
    : null;
  const resizePhantomWidget = resizingId && resizePreview
    ? layoutWidgets.find((w) => w.id === resizingId && w.visible !== false)
    : null;
  const interactionPhantom = resizePhantomWidget || phantomWidget;

  const queueResizePreview = (widgetId, previewWidgets) => {
    if (!previewWidgets) {
      setResizePreview(null);
      return;
    }
    const nextKey = dashboardLayoutPreviewKey(previewWidgets);
    const currentKey = resizePreview ? dashboardLayoutPreviewKey(resizePreview.widgets) : '';
    if (nextKey === currentKey) return;
    flipFirstRectsRef.current = captureDashboardFlipRects(gridRef.current);
    setResizePreview({ widgetId, widgets: previewWidgets });
  };

  const resolveDropTarget = (clientX, clientY, sourceId) => {
    const { layout: liveLayout, dragPreview: livePreview } = dragContextRef.current;
    const widgetsForHitTest = livePreview?.widgets || liveLayout.widgets;
    return findDropTargetFromPoint(
      clientX,
      clientY,
      sourceId,
      gridRef.current,
      widgetsForHitTest,
    );
  };

  const queueDragPreview = (nextPreview) => {
    const nextKey = nextPreview ? dashboardLayoutPreviewKey(nextPreview.widgets) : '';
    if (nextKey === dragPreviewKeyRef.current) return;
    dragPreviewKeyRef.current = nextKey;
    flipFirstRectsRef.current = captureDashboardFlipRects(gridRef.current);
    setDragPreview(nextPreview);
  };

  const onDragHandleMouseDown = (widgetId) => (e) => {
    if (!editMode || e.button !== 0) return;
    e.preventDefault();
    dragSourceRef.current = widgetId;
    dragPreviewKeyRef.current = dashboardLayoutPreviewKey(layout.widgets);
    setDraggingId(widgetId);
    setDragPreview(null);

    const applyDragPreview = (ev) => {
      const sourceId = dragSourceRef.current;
      if (!sourceId) return;
      const { layout: liveLayout } = dragContextRef.current;
      const dropTarget = resolveDropTarget(ev.clientX, ev.clientY, sourceId);
      if (!dropTarget) {
        queueDragPreview(null);
        return;
      }
      const previewWidgets = previewDashboardMove(
        liveLayout.widgets,
        sourceId,
        dropTarget.id,
        { insertAfter: dropTarget.insertAfter },
      );
      if (!previewWidgets) {
        queueDragPreview(null);
        return;
      }
      const previewKey = dashboardLayoutPreviewKey(previewWidgets);
      const originalKey = dashboardLayoutPreviewKey(liveLayout.widgets);
      if (previewKey === originalKey) {
        queueDragPreview(null);
        return;
      }
      queueDragPreview({
        sourceId,
        targetId: dropTarget.id,
        insertAfter: dropTarget.insertAfter,
        widgets: previewWidgets,
      });
    };

    const onMove = (ev) => {
      if (dragMoveRafRef.current) return;
      dragMoveRafRef.current = requestAnimationFrame(() => {
        dragMoveRafRef.current = null;
        applyDragPreview(ev);
      });
    };

    const onUp = (ev) => {
      if (dragMoveRafRef.current) {
        cancelAnimationFrame(dragMoveRafRef.current);
        dragMoveRafRef.current = null;
      }
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      const sourceId = dragSourceRef.current;
      const { layout: liveLayout } = dragContextRef.current;
      const dropTarget = resolveDropTarget(ev.clientX, ev.clientY, sourceId);
      const preview = sourceId && dropTarget
        ? previewDashboardMove(liveLayout.widgets, sourceId, dropTarget.id, {
          insertAfter: dropTarget.insertAfter,
        })
        : null;
      dragSourceRef.current = null;
      dragPreviewKeyRef.current = '';
      const previewKey = preview ? dashboardLayoutPreviewKey(preview) : '';
      const originalKey = dashboardLayoutPreviewKey(liveLayout.widgets);
      if (sourceId && dropTarget && preview && previewKey !== originalKey) {
        onMoveWidget(sourceId, dropTarget.id, { insertAfter: dropTarget.insertAfter });
      }
      setDraggingId(null);
      setDragPreview(null);
    };

    document.body.style.cursor = 'grabbing';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  const onResizeWidthMouseDown = (widget, edge) => (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    const grid = gridRef.current;
    if (!grid || compact) return;

    setResizingId(widget.id);
    setResizePreview(null);
    setDragPreview(null);
    setDraggingId(null);

    const fromWest = edge === 'west';
    const startX = e.clientX;
    const startW = widget.w;
    const startWidgetX = widget.x;
    const anchorRight = fromWest ? widget.x + widget.w : null;
    const rect = grid.getBoundingClientRect();
    const colWidth = rect.width / DASHBOARD_GRID_COLS;
    let pendingW = startW;
    let pendingEv = null;

    const resizeOptions = () => (anchorRight != null ? { w: pendingW, anchorRight } : { w: pendingW });

    const applyPreview = () => {
      pendingEv = null;
      const { layout: liveLayout } = dragContextRef.current;
      const previewWidgets = previewResizeDashboardWidget(
        liveLayout.widgets,
        widget.id,
        resizeOptions(),
      );
      queueResizePreview(widget.id, previewWidgets);
    };

    const onMove = (ev) => {
      pendingEv = ev;
      if (resizeMoveRafRef.current) return;
      resizeMoveRafRef.current = requestAnimationFrame(() => {
        resizeMoveRafRef.current = null;
        if (!pendingEv) return;
        const deltaCols = Math.round((pendingEv.clientX - startX) / colWidth);
        pendingW = fromWest ? startW - deltaCols : startW + deltaCols;
        applyPreview();
      });
    };

    const onUp = () => {
      if (resizeMoveRafRef.current) {
        cancelAnimationFrame(resizeMoveRafRef.current);
        resizeMoveRafRef.current = null;
      }
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      const { layout: liveLayout, resizePreview: liveResizePreview } = dragContextRef.current;
      const previewWidgets = liveResizePreview?.widgets
        || previewResizeDashboardWidget(liveLayout.widgets, widget.id, resizeOptions());
      const previewWidget = previewWidgets?.find((item) => item.id === widget.id);
      const widthChanged = previewWidget && previewWidget.w !== startW;
      const positionChanged = previewWidget && previewWidget.x !== startWidgetX;
      if (previewWidget && (widthChanged || positionChanged)) {
        onResizeWidget(
          widget.id,
          previewWidget.w,
          anchorRight != null ? { anchorRight } : undefined,
        );
      }
      setResizingId(null);
      setResizePreview(null);
    };

    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  const onResizeHeightMouseDown = (widget, edge) => (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    const grid = gridRef.current;
    if (!grid || compact) return;

    const meta = OPERATOR_WIDGET_REGISTRY[widget.id];
    if (!meta || meta.maxH <= meta.minH) return;

    setResizingId(widget.id);
    setResizePreview(null);
    setDragPreview(null);
    setDraggingId(null);

    const fromNorth = edge === 'north';
    const widgetEl = grid.querySelector(`[data-widget-id="${widget.id}"]`);
    const rowHeight = widgetEl && widget.h > 0
      ? widgetEl.getBoundingClientRect().height / widget.h
      : 120;
    const startY = e.clientY;
    const startH = widget.h;
    const startWidgetY = widget.y;
    const anchorBottom = fromNorth ? widget.y + widget.h : null;
    let pendingH = startH;
    let pendingEv = null;

    const resizeOptions = () => (anchorBottom != null ? { h: pendingH, anchorBottom } : { h: pendingH });

    const applyPreview = () => {
      pendingEv = null;
      const { layout: liveLayout } = dragContextRef.current;
      const previewWidgets = previewResizeDashboardWidget(
        liveLayout.widgets,
        widget.id,
        resizeOptions(),
      );
      queueResizePreview(widget.id, previewWidgets);
    };

    const onMove = (ev) => {
      pendingEv = ev;
      if (resizeMoveRafRef.current) return;
      resizeMoveRafRef.current = requestAnimationFrame(() => {
        resizeMoveRafRef.current = null;
        if (!pendingEv) return;
        const deltaRows = Math.round((pendingEv.clientY - startY) / Math.max(rowHeight, 1));
        pendingH = fromNorth ? startH - deltaRows : startH + deltaRows;
        applyPreview();
      });
    };

    const onUp = () => {
      if (resizeMoveRafRef.current) {
        cancelAnimationFrame(resizeMoveRafRef.current);
        resizeMoveRafRef.current = null;
      }
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      const { layout: liveLayout, resizePreview: liveResizePreview } = dragContextRef.current;
      const previewWidgets = liveResizePreview?.widgets
        || previewResizeDashboardWidget(liveLayout.widgets, widget.id, resizeOptions());
      const previewWidget = previewWidgets?.find((item) => item.id === widget.id);
      const heightChanged = previewWidget && previewWidget.h !== startH;
      const positionChanged = previewWidget && previewWidget.y !== startWidgetY;
      if (previewWidget && (heightChanged || positionChanged)) {
        onResizeWidgetHeight(
          widget.id,
          previewWidget.h,
          anchorBottom != null ? { anchorBottom } : undefined,
        );
      }
      setResizingId(null);
      setResizePreview(null);
    };

    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  const distributionRenderKey = distributionModes
    ? `${distributionModes.protocols}:${distributionModes.services}`
    : '';

  const renderWidgetShell = (widget, { hiddenPreview = false } = {}) => {
    const meta = OPERATOR_WIDGET_REGISTRY[widget.id];
    const isInteractionSource = widget.id === draggingId || widget.id === resizingId;
    const canResizeWidth = editMode && !compact && !!meta;
    const canResizeHeight = editMode && !compact && !!meta && meta.maxH > meta.minH;
    const style = dashboardWidgetStyle(widget, compact);
    const modeKey = (widget.id === 'distribution-protocols' || widget.id === 'distribution-services')
      ? distributionRenderKey
      : '';
    const content = renderers[widget.id] ? renderers[widget.id]() : null;
    if (!content && !editMode && !hiddenPreview) return null;

    return (
      <div
        key={`${widget.id}${modeKey ? `:${modeKey}` : ''}`}
        data-widget-id={widget.id}
        data-flip-id={widget.id}
        className={`dashboard-widget${hiddenPreview ? ' is-hidden-preview' : ''}${isInteractionSource && interactionPhantom ? ' is-interaction-source' : ''}${dragPreview || resizePreview ? ' is-preview-shifted' : ''}`}
        style={style}
      >
        <DashboardWidgetChrome
          widget={widget}
          editMode={editMode}
          onToggleVisibility={() => onToggleWidgetVisible(widget.id, !widget.visible)}
          onDragHandleMouseDown={onDragHandleMouseDown(widget.id)}
        >
          {content || (
            <div className="dashboard-widget-phantom__frame dashboard-widget-phantom__frame--compact">
              <span>{meta?.label || widget.id}</span>
            </div>
          )}
        </DashboardWidgetChrome>
        {canResizeWidth ? (
          <>
            <div
              className="dashboard-widget__resize-w"
              role="separator"
              aria-orientation="vertical"
              aria-label="Изменить ширину слева"
              onMouseDown={onResizeWidthMouseDown(widget, 'west')}
            />
            <div
              className="dashboard-widget__resize-e"
              role="separator"
              aria-orientation="vertical"
              aria-label="Изменить ширину справа"
              onMouseDown={onResizeWidthMouseDown(widget, 'east')}
            />
          </>
        ) : null}
        {canResizeHeight ? (
          <>
            <div
              className="dashboard-widget__resize-n"
              role="separator"
              aria-orientation="horizontal"
              aria-label="Изменить высоту сверху"
              onMouseDown={onResizeHeightMouseDown(widget, 'north')}
            />
            <div
              className="dashboard-widget__resize-s"
              role="separator"
              aria-orientation="horizontal"
              aria-label="Изменить высоту снизу"
              onMouseDown={onResizeHeightMouseDown(widget, 'south')}
            />
          </>
        ) : null}
      </div>
    );
  };

  return (
    <div
      ref={gridRef}
      className={`dashboard-grid${editMode ? ' dashboard-grid--edit' : ''}${dragPreview || resizePreview ? ' dashboard-grid--drag-preview' : ''}${compact ? ' dashboard-grid--compact' : ''}`}
    >
      {visibleWidgets.map((widget) => {
        if (interactionPhantom && widget.id === interactionPhantom.id) return null;
        return renderWidgetShell(widget);
      })}
      {interactionPhantom ? (
        <DashboardWidgetPhantom
          widget={interactionPhantom}
          compact={compact}
          detail={`${OPERATOR_WIDGET_REGISTRY[interactionPhantom.id]?.label || interactionPhantom.id} · ${interactionPhantom.w}×${interactionPhantom.h}`}
        />
      ) : null}
      {editMode && hiddenDividerY != null ? (
        <div
          key="dashboard-hidden-divider"
          className="dashboard-grid__hidden-divider"
          style={{ gridColumn: '1 / -1', gridRow: `${hiddenDividerY + 1} / span 1` }}
        >
          Скрытые виджеты
        </div>
      ) : null}
      {hiddenWidgets.map((widget) => renderWidgetShell(widget, { hiddenPreview: true }))}
    </div>
  );
}

Object.assign(window, {
  DASHBOARD_GRID_COLS,
  DEFAULT_OPERATOR_LAYOUT,
  OPERATOR_WIDGET_REGISTRY,
  mergeDashboardLayout,
  useDashboardLayout,
  DashboardGrid,
  DashboardLayoutToolbar,
  clampTrendSplit,
});
