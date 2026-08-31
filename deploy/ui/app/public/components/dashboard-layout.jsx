/* Operator dashboard layout: grid, edit mode, server persistence. */

const { useState, useEffect, useLayoutEffect, useCallback, useMemo, useRef } = React;

const DASHBOARD_GRID_COLS = 12;
const DASHBOARD_LAYOUT_SAVE_MS = 400;
const DASHBOARD_CHART_SPLIT_KEY = 'grapes-dashboard-chart-split';
const DEFAULT_TREND_SPLIT = 0.5;
const TREND_SPLIT_MIN = 0.35;
const TREND_SPLIT_MAX = 0.65;
const SHARE_RIGHT_SPLIT = 1 / 3;

const DASHBOARD_LAYOUT_VERSION = 3;
const STACK_INNER_COLS = 12;
const STACK_ROW_SIZE_PX = 128;
const DASHBOARD_GRID_ROW_PX = 200;
const DASHBOARD_GRID_GAP_PX = 16;
// Whole traffic-chart widget in edit mode: chrome + paddings + titles + donut (~150–180px).
const TRAFFIC_CHART_MIN_HEIGHT_PX = 368;
const TRAFFIC_CHART_HEIGHT_STEP = 0.5;
const STACK_ID_PATTERN = /^stack-[vh]-[a-z0-9]+$/;
const LEGACY_V1_COMPOSITE_IDS = new Set(['traffic-stats', 'traffic-chart-row']);

const OPERATOR_WIDGET_REGISTRY = {
  'stat-max': { label: 'Максимально', allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-avg': { label: 'Среднее', allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'stat-volume': { label: 'Объём', allowedW: [4, 6, 12], minH: 1, maxH: 1 },
  'traffic-chart': { label: 'График трафика', allowedW: [6, 7, 8, 12], minH: 1, maxH: 6 },
  'distribution-protocols': { label: 'Протоколы', allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  'distribution-services': { label: 'Сервисы', allowedW: [4, 5, 6, 12], minH: 1, maxH: 2 },
  vlan: { label: 'VLAN', allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
  'top-talkers': { label: 'Топ ASN', allowedW: [6, 7, 8, 12], minH: 2, maxH: 3 },
  countries: { label: 'География', allowedW: [4, 5, 6, 12], minH: 2, maxH: 3 },
  'recent-flows': { label: 'Последние потоки', allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12], minH: 1, maxH: 2 },
};

const STACK_WIDGET_TEMPLATES = {
  'stack-v': {
    label: 'Вертикальный стек',
    direction: 'vertical',
    allowedW: [4, 5, 6, 7, 8, 9, 10, 11, 12],
    minH: 2,
    maxH: 8,
  },
  'stack-h': {
    label: 'Горизонтальный стек',
    direction: 'horizontal',
    allowedW: [6, 7, 8, 9, 10, 11, 12],
    minH: 1,
    maxH: 3,
  },
};

const CONTENT_WIDGET_IDS = Object.keys(OPERATOR_WIDGET_REGISTRY);

const DEFAULT_OPERATOR_LAYOUT = {
  version: DASHBOARD_LAYOUT_VERSION,
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

function isStackWidget(widget) {
  return widget?.kind === 'stack' || isStackWidgetId(widget?.id);
}

function normalizeStackWidget(widget) {
  if (!isStackWidget(widget)) return widget;
  const direction = widget.direction === 'horizontal' || String(widget.id || '').startsWith('stack-h')
    ? 'horizontal'
    : 'vertical';
  return {
    ...widget,
    kind: 'stack',
    direction,
    childIds: Array.isArray(widget.childIds) ? widget.childIds.map(String) : [],
  };
}

function isStackChild(widget) {
  return !!widget?.parentStack;
}

function isStackWidgetId(id) {
  return STACK_ID_PATTERN.test(String(id || ''));
}

function getTopLevelWidgets(widgets) {
  return widgets.filter((w) => !w.parentStack);
}

function getDashboardWidgetMeta(widget) {
  if (isStackWidget(widget)) {
    return STACK_WIDGET_TEMPLATES[widget.direction === 'horizontal' ? 'stack-h' : 'stack-v'];
  }
  return OPERATOR_WIDGET_REGISTRY[widget.id];
}

function getStackChildWidgets(widgets, stack) {
  if (!stack) return [];
  const ids = new Set(Array.isArray(stack.childIds) ? stack.childIds : []);
  for (const widget of widgets) {
    if (widget.parentStack === stack.id) ids.add(widget.id);
  }
  return [...ids]
    .map((id) => widgets.find((w) => w.id === id))
    .filter(Boolean);
}

function isEmptyStack(widgets, stack) {
  return isStackWidget(stack) && getStackChildWidgets(widgets, stack).length === 0;
}

function stackContentsLabel(widgets, stack) {
  const children = getStackChildWidgets(widgets, stack);
  if (!children.length) return 'Пустой стек';
  const order = Array.isArray(stack.childIds) ? stack.childIds : [];
  return [...children]
    .sort((a, b) => {
      const ai = order.indexOf(a.id);
      const bi = order.indexOf(b.id);
      if (ai >= 0 && bi >= 0) return ai - bi;
      if (ai >= 0) return -1;
      if (bi >= 0) return 1;
      return String(a.id).localeCompare(String(b.id));
    })
    .map((child) => getDashboardWidgetMeta(child)?.label || child.id)
    .join(', ');
}

function removeDashboardStack(widgets, stackId) {
  const stack = widgets.find((widget) => widget.id === stackId);
  if (!stack || !isStackWidget(stack)) return widgets;
  const remainingVisible = widgets.filter((widget) => widget.visible !== false && widget.id !== stackId).length;
  if (remainingVisible < 1) return widgets;
  const next = widgets
    .filter((widget) => widget.id !== stackId)
    .map((widget) => {
      if (widget.parentStack !== stackId) return widget;
      const copy = { ...widget };
      delete copy.parentStack;
      return copy;
    });
  return repackDashboardWidgets(next, { keepOrder: true });
}

function pruneHiddenEmptyStacks(widgets) {
  const drop = new Set(
    widgets
      .filter((widget) => widget.visible === false && isEmptyStack(widgets, widget))
      .map((widget) => widget.id),
  );
  if (!drop.size) return widgets;
  return widgets.filter((widget) => !drop.has(widget.id));
}

function reconcileStackMembership(widgets) {
  const list = widgets.map((w) => normalizeStackWidget(w));
  const stackIds = new Set(list.filter(isStackWidget).map((stack) => stack.id));

  for (const widget of list) {
    if (widget.parentStack && !stackIds.has(widget.parentStack)) {
      delete widget.parentStack;
    }
  }

  for (const stack of list.filter(isStackWidget)) {
    const members = list.filter((widget) => widget.parentStack === stack.id);
    stack.childIds = members.map((member) => member.id);
    const visible = members.filter((member) => member.visible !== false);
    const hidden = members.filter((member) => member.visible === false);
    const packed = stack.direction === 'horizontal'
      ? reflowHorizontalStackChildren(visible)
      : reflowVerticalStackChildren(visible);
    const nextMembers = [
      ...packed,
      ...hidden.map((member) => normalizeStackChildLayout(member, stack)),
    ];
    for (const member of nextMembers) {
      const memberIdx = list.findIndex((widget) => widget.id === member.id);
      if (memberIdx >= 0) list[memberIdx] = member;
    }
  }

  return list;
}

function clampStackInnerW(value) {
  const n = Math.round(Number(value) || 1);
  return Math.min(STACK_INNER_COLS, Math.max(1, n));
}

function sortStackChildren(children) {
  return [...children].sort((a, b) => (
    (Number(a.x) || 0) - (Number(b.x) || 0)
    || (Number(a.y) || 0) - (Number(b.y) || 0)
    || String(a.id).localeCompare(String(b.id))
  ));
}

function equalSplitInnerWidths(count) {
  const n = Math.max(1, count);
  if (n >= STACK_INNER_COLS) return Array.from({ length: n }, () => 1);
  const base = Math.floor(STACK_INNER_COLS / n);
  const remainder = STACK_INNER_COLS % n;
  return Array.from({ length: n }, (_, i) => base + (i < remainder ? 1 : 0));
}

function applyHorizontalInnerXs(children, widths) {
  let x = 0;
  return children.map((child, i) => {
    const w = clampStackInnerW(widths[i]);
    const next = { ...child, x, y: 0, w };
    x += w;
    return next;
  });
}

function normalizeStackChildLayout(child, stack) {
  const meta = getDashboardWidgetMeta(child);
  if (!meta || !stack) return child;

  const next = { ...child };
  next.h = snapDashboardHeight(next.h, meta.minH, meta.maxH, dashboardHeightStep(next));
  if (stack.direction === 'vertical') {
    next.x = 0;
    next.w = STACK_INNER_COLS;
    next.y = Math.max(0, Math.round(Number(next.y) || 0));
    return next;
  }

  next.y = 0;
  next.w = clampStackInnerW(next.w);
  next.x = Math.max(0, Math.min(Math.round(Number(next.x) || 0), STACK_INNER_COLS - next.w));
  return next;
}

function reflowVerticalStackChildren(children) {
  const ordered = sortStackChildren(children.map((child) => normalizeStackChildLayout(child, { direction: 'vertical' })));
  let y = 0;
  return ordered.map((child) => {
    const next = { ...child, x: 0, y, w: STACK_INNER_COLS };
    y += next.h;
    return next;
  });
}

function horizontalStackNeedsReflow(children) {
  const ordered = sortStackChildren(children);
  if (!ordered.length) return false;
  let x = 0;
  for (const child of ordered) {
    const w = Math.round(Number(child.w) || 0);
    if ((Number(child.y) || 0) !== 0 || (Number(child.x) || 0) !== x || w < 1) return true;
    x += w;
  }
  return x !== STACK_INNER_COLS;
}

function redistributeHorizontalStackChildren(children) {
  const ordered = sortStackChildren(children);
  if (!ordered.length) return [];
  if (ordered.length === 1) {
    return [{ ...ordered[0], x: 0, y: 0, w: STACK_INNER_COLS }];
  }
  return applyHorizontalInnerXs(ordered, equalSplitInnerWidths(ordered.length));
}

function reflowHorizontalStackChildren(children) {
  const ordered = sortStackChildren(children.map((child) => normalizeStackChildLayout(child, { direction: 'horizontal' })));
  if (!ordered.length) return [];
  if (!horizontalStackNeedsReflow(ordered)) return ordered.map((child) => ({ ...child, y: 0 }));
  const widths = ordered.map((child) => clampStackInnerW(child.w));
  const total = widths.reduce((sum, w) => sum + w, 0);
  if (total === STACK_INNER_COLS) return applyHorizontalInnerXs(ordered, widths);
  return redistributeHorizontalStackChildren(ordered);
}

function applyHorizontalStackChildWidth(children, childId, nextW, { fromWest = false } = {}) {
  const ordered = reflowHorizontalStackChildren(children);
  const idx = ordered.findIndex((child) => child.id === childId);
  if (idx < 0) return ordered;
  const neighborIdx = fromWest ? idx - 1 : idx + 1;
  if (neighborIdx < 0 || neighborIdx >= ordered.length) return ordered;
  const self = ordered[idx];
  const neighbor = ordered[neighborIdx];
  const pair = self.w + neighbor.w;
  self.w = Math.min(pair - 1, Math.max(1, clampStackInnerW(nextW)));
  neighbor.w = pair - self.w;
  return applyHorizontalInnerXs(ordered, ordered.map((child) => child.w));
}

function syncStackDimensions(stack, widgets, { followChildren = false } = {}) {
  const template = getDashboardWidgetMeta(stack);
  const children = getStackChildWidgets(widgets, stack).filter((child) => child.visible !== false);
  const packed = stack.direction === 'horizontal'
    ? reflowHorizontalStackChildren(children)
    : reflowVerticalStackChildren(children);
  if (!packed.length) {
    return {
      ...stack,
      w: nearestAllowedW(stack.w, template.allowedW),
      h: template.minH,
    };
  }
  const maxBottom = Math.max(...packed.map((child) => child.y + child.h));
  const contentH = Math.max(template.minH, maxBottom);
  const nextH = followChildren
    ? contentH
    : Math.max(contentH, Math.round(Number(stack.h) || contentH));
  return {
    ...stack,
    w: nearestAllowedW(stack.w, template.allowedW),
    h: Math.min(template.maxH, nextH),
  };
}

function syncAllStackDimensions(widgets) {
  const list = widgets.map((w) => ({ ...w }));
  for (const stack of list.filter(isStackWidget)) {
    const synced = syncStackDimensions(stack, list);
    const idx = list.findIndex((w) => w.id === stack.id);
    if (idx >= 0) list[idx] = synced;
  }
  return list;
}

function createStackWidget(direction) {
  const dir = direction === 'horizontal' ? 'horizontal' : 'vertical';
  const templateKey = dir === 'horizontal' ? 'stack-h' : 'stack-v';
  const template = STACK_WIDGET_TEMPLATES[templateKey];
  const id = `${templateKey}-${Math.random().toString(36).slice(2, 9)}`;
  const defaultW = template.allowedW[Math.min(2, template.allowedW.length - 1)];
  return {
    id,
    kind: 'stack',
    direction: dir,
    x: 0,
    y: 0,
    w: defaultW,
    h: dir === 'horizontal' ? Math.max(template.minH, 2) : template.minH,
    visible: true,
    childIds: [],
  };
}

function stackChildStyle(child) {
  const h = Math.max(1, Number(child.h) || 1);
  const spanH = dashboardGridSpanH(h);
  return {
    gridColumn: `${child.x + 1} / span ${child.w}`,
    gridRow: `${child.y + 1} / span ${spanH}`,
    minHeight: `${h * STACK_ROW_SIZE_PX}px`,
  };
}

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

function dashboardHeightStep(widget) {
  return widget?.id === 'traffic-chart' ? TRAFFIC_CHART_HEIGHT_STEP : 1;
}

function snapDashboardHeight(h, minH, maxH, step = 1) {
  const raw = Number(h);
  const n = Number.isFinite(raw) ? raw : minH;
  const snapped = Math.round(n / step) * step;
  const clean = Math.round(snapped / step) * step;
  return Math.min(maxH, Math.max(minH, clean));
}

function dashboardGridSpanH(h) {
  return Math.max(1, Math.ceil(Number(h) || 1));
}

function isTrafficChartHalfHeight(widget) {
  return widget?.id === 'traffic-chart' && Number(widget.h) % 1 !== 0;
}

function trafficChartHeightPx(h) {
  return TRAFFIC_CHART_MIN_HEIGHT_PX * Math.max(1, Number(h) || 1);
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
  if (isStackWidget(widget)) {
    const normalized = normalizeStackWidget(widget);
    const template = STACK_WIDGET_TEMPLATES[normalized.direction === 'horizontal' ? 'stack-h' : 'stack-v'];
    if (!template) return null;
    const w = nearestAllowedW(normalized.w, template.allowedW);
    const h = snapDashboardHeight(normalized.h, template.minH, template.maxH);
    const x = Math.min(DASHBOARD_GRID_COLS - w, Math.max(0, Math.round(Number(normalized.x) || 0)));
    const y = Math.max(0, Math.round(Number(normalized.y) || 0));
    return {
      id: String(normalized.id),
      kind: 'stack',
      direction: normalized.direction,
      x,
      y,
      w,
      h,
      visible: normalized.visible !== false,
      childIds: Array.isArray(normalized.childIds) ? normalized.childIds.map(String) : [],
    };
  }

  const meta = registry[widget.id];
  if (!meta) return null;
  let h = snapDashboardHeight(widget.h, meta.minH, meta.maxH, dashboardHeightStep(widget));
  let y = Math.max(0, Math.round(Number(widget.y) || 0));
  if (widget.parentStack) {
    const w = clampStackInnerW(widget.w);
    const x = Math.max(0, Math.min(Math.round(Number(widget.x) || 0), STACK_INNER_COLS - w));
    return {
      id: widget.id,
      x,
      y,
      w,
      h,
      visible: widget.visible !== false,
      parentStack: String(widget.parentStack),
    };
  }
  const w = nearestAllowedW(widget.w, meta.allowedW);
  const x = Math.min(DASHBOARD_GRID_COLS - w, Math.max(0, Math.round(Number(widget.x) || 0)));
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
    if (isStackWidget(defaultWidget)) return clampDashboardWidget(defaultWidget);
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
    if (isStackWidget(defaultWidget)) {
      if (!savedWidget) continue;
      mergedWidgets.push(clampDashboardWidget({ ...defaultWidget, ...savedWidget, id: defaultWidget.id }));
      byId.delete(defaultWidget.id);
      continue;
    }
    if (savedWidget) {
      const merged = { ...defaultWidget, ...savedWidget, id: defaultWidget.id };
      if (!savedWidget.parentStack) delete merged.parentStack;
      mergedWidgets.push(clampDashboardWidget(merged));
      byId.delete(defaultWidget.id);
    } else {
      const fresh = { ...defaultWidget };
      delete fresh.parentStack;
      mergedWidgets.push(clampDashboardWidget(fresh));
    }
  }

  for (const leftover of byId.values()) {
    const id = String(leftover.id || '');
    if (isStackWidget(leftover) && isStackWidgetId(id)) {
      mergedWidgets.push(clampDashboardWidget(leftover));
    }
  }

  mergedWidgets.sort((a, b) => {
    if (a.parentStack && !b.parentStack) return 1;
    if (!a.parentStack && b.parentStack) return -1;
    return (a.y - b.y) || (a.x - b.x);
  });

  const layout = {
    version: DASHBOARD_LAYOUT_VERSION,
    widgets: mergedWidgets,
    settings: normalizeDashboardSettings(normalizedSaved.settings, base.settings),
  };

  const legacySplit = loadLegacyTrendSplit();
  if (legacySplit != null) {
    layout.settings.distribution.trendSplit = legacySplit;
  }

  layout.widgets = syncAllStackDimensions(reconcileStackMembership(layout.widgets));
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

function dashboardWidgetsOverlapX(a, b) {
  if (!a || !b || a.id === b.id) return false;
  return a.x < b.x + b.w && a.x + a.w > b.x;
}

function shiftTopLevelWidgetsBelow(widgets, resized, oldBottom, newBottom) {
  const delta = newBottom - oldBottom;
  if (!delta || !resized || resized.parentStack) return widgets;

  const nextById = new Map(widgets.map((widget) => [widget.id, { ...widget }]));
  const candidates = widgets
    .filter((other) => (
      other.id !== resized.id
      && !other.parentStack
      && other.visible !== false
      && other.y >= oldBottom
      && dashboardWidgetsOverlapX(other, resized)
    ))
    // Growing pushes down, so move the lowest widget first to free the row below it.
    .sort((a, b) => (delta > 0 ? b.y - a.y : a.y - b.y) || (a.x - b.x));

  for (const candidate of candidates) {
    const current = nextById.get(candidate.id);
    const nextY = Math.max(0, current.y + delta);
    if (nextY === current.y) continue;
    const moved = { ...current, y: nextY };
    const blocked = [...nextById.values()].some((blocker) => {
      if (blocker.parentStack || blocker.visible === false) return false;
      return dashboardWidgetsOverlap(moved, blocker);
    });
    if (!blocked) nextById.set(candidate.id, moved);
  }

  return widgets.map((widget) => nextById.get(widget.id) || widget);
}

function syncStackAfterChildHeightChange(widgets, childId) {
  const list = widgets.map((item) => ({ ...item }));
  const child = list.find((item) => item.id === childId);
  if (!child?.parentStack) return list;
  const stackIdx = list.findIndex((item) => item.id === child.parentStack);
  if (stackIdx < 0) return list;
  const prev = list[stackIdx];
  const oldBottom = prev.y + prev.h;
  const synced = syncStackDimensions(prev, list, { followChildren: true });
  list[stackIdx] = synced;
  return shiftTopLevelWidgetsBelow(list, synced, oldBottom, synced.y + synced.h);
}

function dashboardLayoutHasCollisions(visible) {
  const topLevel = getTopLevelWidgets(visible);
  for (let i = 0; i < topLevel.length; i += 1) {
    for (let j = i + 1; j < topLevel.length; j += 1) {
      if (dashboardWidgetsOverlap(topLevel[i], topLevel[j])) return true;
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

function ensureOccupancyRows(grid, rows) {
  while (grid.length < rows) grid.push(Array(DASHBOARD_GRID_COLS).fill(null));
}

function canPlaceOnGrid(grid, x, y, w, h) {
  const spanH = dashboardGridSpanH(h);
  ensureOccupancyRows(grid, y + spanH);
  for (let dy = 0; dy < spanH; dy += 1) {
    for (let dx = 0; dx < w; dx += 1) {
      if (grid[y + dy][x + dx] != null) return false;
    }
  }
  return true;
}

function markGridOccupancy(grid, x, y, w, h, id) {
  const spanH = dashboardGridSpanH(h);
  ensureOccupancyRows(grid, y + spanH);
  for (let dy = 0; dy < spanH; dy += 1) {
    for (let dx = 0; dx < w; dx += 1) {
      grid[y + dy][x + dx] = id;
    }
  }
}

function preferredWidgetWidths(widget) {
  const meta = getDashboardWidgetMeta(widget);
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
  const inputById = new Map(widgets.map((widget) => [widget.id, widget]));
  const all = reconcileStackMembership(syncAllStackDimensions(widgets.map((w) => ({ ...w }))));
  const hiddenTop = all.filter((w) => !w.visible && !isStackChild(w));
  const hiddenChildren = all.filter((w) => !w.visible && isStackChild(w));

  let visibleTop = getTopLevelWidgets(all).filter((w) => w.visible !== false);
  if (keepOrder) {
    const order = all.filter((w) => w.visible !== false && !isStackChild(w)).map((w) => w.id);
    visibleTop.sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
  } else {
    visibleTop = sortDashboardWidgets(visibleTop);
  }
  visibleTop = normalizeGroupedStatWidths(visibleTop).map((widget) => (
    isStackWidget(widget) ? syncStackDimensions(widget, all) : widget
  ));
  const packed = layoutDashboardWidgets(visibleTop);
  const visibleChildren = all.filter((w) => isStackChild(w) && w.visible !== false);

  const resultById = new Map();
  for (const widget of [...packed, ...visibleChildren, ...hiddenTop, ...hiddenChildren]) {
    resultById.set(widget.id, widget);
  }
  for (const [id, widget] of inputById.entries()) {
    if (!resultById.has(id)) resultById.set(id, widget);
  }

  return reconcileStackMembership([...resultById.values()]);
}

function moveWidgetIntoStack(widgets, widgetId, stackId) {
  if (!widgetId || !stackId || widgetId === stackId) return widgets;
  const list = widgets.map((w) => ({ ...w }));
  const widget = list.find((w) => w.id === widgetId);
  const stack = list.find((w) => w.id === stackId);
  if (!widget || !stack || !isStackWidget(stack) || isStackWidget(widget)) return widgets;
  if (widget.visible === false) widget.visible = true;
  if (widget.parentStack === stackId) {
    return repackDashboardWidgets(reconcileStackMembership(list), { keepOrder: true });
  }

  if (widget.parentStack) {
    const oldStack = list.find((w) => w.id === widget.parentStack);
    if (oldStack?.childIds) {
      oldStack.childIds = oldStack.childIds.filter((id) => id !== widgetId);
    }
  }

  const siblings = getStackChildWidgets(list, stack).filter((w) => w.id !== widgetId);
  let relX = 0;
  let relY = 0;
  if (stack.direction === 'horizontal') {
    relX = siblings.reduce((max, child) => Math.max(max, child.x + child.w), 0);
  } else {
    relY = siblings.reduce((max, child) => Math.max(max, child.y + child.h), 0);
  }

  widget.parentStack = stackId;
  widget.x = relX;
  widget.y = relY;

  if (!stack.childIds.includes(widgetId)) {
    stack.childIds = [...(stack.childIds || []), widgetId];
  }

  if (stack.direction === 'horizontal') {
    const members = list.filter((item) => item.parentStack === stackId && item.visible !== false);
    const packed = redistributeHorizontalStackChildren(members);
    for (const member of packed) {
      const memberIdx = list.findIndex((item) => item.id === member.id);
      if (memberIdx >= 0) list[memberIdx] = member;
    }
  }

  return repackDashboardWidgets(reconcileStackMembership(list), { keepOrder: true });
}

function extractWidgetFromStack(widgets, widgetId) {
  const list = widgets.map((w) => ({ ...w }));
  const widget = list.find((w) => w.id === widgetId);
  if (!widget?.parentStack) return widgets;
  const stack = list.find((w) => w.id === widget.parentStack);
  if (stack?.childIds) {
    stack.childIds = stack.childIds.filter((id) => id !== widgetId);
  }
  delete widget.parentStack;
  return repackDashboardWidgets(list, { keepOrder: true });
}

function addDashboardStack(widgets, direction) {
  const stack = createStackWidget(direction);
  return repackDashboardWidgets([...widgets, stack], { keepOrder: true });
}

function moveDashboardWidget(widgets, sourceId, targetId, { insertAfter = false, insertIntoStack = false } = {}) {
  if (!sourceId || !targetId) return widgets;
  if (sourceId === targetId && !insertAfter && !insertIntoStack) return widgets;

  let list = widgets.map((w) => ({ ...w }));
  const source = list.find((w) => w.id === sourceId);
  if (!source) return widgets;
  const wasHidden = source.visible === false;
  if (wasHidden) source.visible = true;

  if (insertIntoStack) {
    const target = list.find((w) => w.id === targetId);
    if (target && isStackWidget(target) && !isStackWidget(source)) {
      return moveWidgetIntoStack(list, sourceId, targetId);
    }
  }

  if (source.parentStack && !isStackWidget(source)) {
    if (!wasHidden) return widgets;
    list = extractWidgetFromStack(list, sourceId);
  }

  const visible = sortDashboardWidgets(getTopLevelWidgets(list).filter((w) => w.visible));
  const hidden = list.filter((w) => !w.visible);
  const stackChildren = list.filter((w) => isStackChild(w) && w.visible !== false);
  const fromIdx = visible.findIndex((w) => w.id === sourceId);
  let toIdx = visible.findIndex((w) => w.id === targetId);
  if (fromIdx < 0 || toIdx < 0) return widgets;
  if (insertAfter) toIdx += 1;
  if (fromIdx < toIdx) toIdx -= 1;

  const nextVisible = [...visible];
  const [moved] = nextVisible.splice(fromIdx, 1);
  nextVisible.splice(toIdx, 0, moved);
  return repackDashboardWidgets([...nextVisible, ...stackChildren, ...hidden], { keepOrder: true });
}

function previewDashboardMove(widgets, sourceId, targetId, options) {
  if (!sourceId || !targetId) return null;
  if (sourceId === targetId && !options?.insertAfter && !options?.insertIntoStack) {
    const source = widgets.find((w) => w.id === sourceId);
    if (source?.visible !== false) return null;
  }
  const next = moveDashboardWidget(widgets, sourceId, targetId, options);
  return next === widgets ? null : next;
}

function readWidgetLayoutRect(el) {
  if (!el) return null;
  const rect = el.getBoundingClientRect();
  const transform = getComputedStyle(el).transform;
  if (!transform || transform === 'none') return rect;
  try {
    const matrix = new DOMMatrixReadOnly(transform);
    return new DOMRect(
      rect.left - matrix.e,
      rect.top - matrix.f,
      rect.width,
      rect.height,
    );
  } catch {
    return rect;
  }
}

function widgetCoversColumn(widget, hoverCol) {
  return hoverCol >= widget.x && hoverCol <= widget.x + widget.w - 1;
}

function pointInRect(rect, clientX, clientY, inset = 0) {
  if (!rect) return false;
  return clientX >= rect.left + inset
    && clientX <= rect.right - inset
    && clientY >= rect.top + inset
    && clientY <= rect.bottom - inset;
}

const STACK_DROP_BODY_INSET_PX = 10;

function stackDropBodyRect(grid, widgetId) {
  const el = grid?.querySelector(`[data-widget-id="${widgetId}"] .dashboard-stack`);
  return el ? el.getBoundingClientRect() : null;
}

function pointInStackDropZone(rect, clientX, clientY) {
  if (!rect) return false;
  const insetX = Math.min(STACK_DROP_BODY_INSET_PX, Math.max(4, rect.width * 0.04));
  const insetY = Math.min(STACK_DROP_BODY_INSET_PX, Math.max(4, rect.height * 0.08));
  return clientX >= rect.left + insetX
    && clientX <= rect.right - insetX
    && clientY >= rect.top + insetY
    && clientY <= rect.bottom - insetY;
}

function dropTargetFromWidgetHit(widget, rect, clientX, clientY, {
  sourceWidget = null,
  directHit = false,
  stackBodyRect = null,
} = {}) {
  if (
    directHit
    && isStackWidget(widget)
    && sourceWidget
    && !isStackWidget(sourceWidget)
    && pointInStackDropZone(stackBodyRect || rect, clientX, clientY)
  ) {
    return { id: widget.id, insertIntoStack: true, insertAfter: false };
  }
  const midY = rect.top + rect.height / 2;
  return {
    id: widget.id,
    insertAfter: clientY >= midY,
    insertIntoStack: false,
  };
}

function findDropTargetFromPoint(clientX, clientY, sourceId, grid, layoutWidgets, {
  phantomRect = null,
  lastTarget = null,
} = {}) {
  if (!grid) return null;

  if (phantomRect && pointInRect(phantomRect, clientX, clientY) && lastTarget) {
    if (!lastTarget.insertIntoStack) return lastTarget;
    const bodyRect = stackDropBodyRect(grid, lastTarget.id);
    if (pointInStackDropZone(bodyRect || phantomRect, clientX, clientY)) return lastTarget;
  }

  const sourceWidget = layoutWidgets.find((w) => w.id === sourceId) || null;
  const activeWidgets = sortDashboardWidgets(
    getTopLevelWidgets(layoutWidgets).filter((w) => w.visible !== false && w.id !== sourceId),
  );
  if (!activeWidgets.length) return lastTarget;

  const gridRect = grid.getBoundingClientRect();
  const colWidth = gridRect.width / DASHBOARD_GRID_COLS;
  const hoverCol = Math.max(0, Math.min(
    DASHBOARD_GRID_COLS - 1,
    Math.floor((clientX - gridRect.left) / Math.max(colWidth, 1)),
  ));

  const widgetHits = [];
  for (const widget of activeWidgets) {
    const el = grid.querySelector(`[data-widget-id="${widget.id}"]`);
    const rect = readWidgetLayoutRect(el);
    if (!rect) continue;
    widgetHits.push({ widget, rect });
  }
  if (!widgetHits.length) return lastTarget;

  const directHits = widgetHits.filter(({ rect }) => pointInRect(rect, clientX, clientY));
  if (directHits.length) {
    directHits.sort((a, b) => (
      (a.rect.width * a.rect.height) - (b.rect.width * b.rect.height)
    ));
    const hit = directHits[0];
    return dropTargetFromWidgetHit(hit.widget, hit.rect, clientX, clientY, {
      sourceWidget,
      directHit: true,
      stackBodyRect: isStackWidget(hit.widget) ? stackDropBodyRect(grid, hit.widget.id) : null,
    });
  }

  const colHits = widgetHits.filter(({ widget, rect }) => (
    widgetCoversColumn(widget, hoverCol) || (clientX >= rect.left && clientX <= rect.right)
  ));
  const candidates = colHits.length ? colHits : widgetHits;
  let nearest = null;
  let nearestDist = Infinity;
  for (const hit of candidates) {
    const midY = hit.rect.top + hit.rect.height / 2;
    const dist = Math.abs(clientY - midY);
    if (dist < nearestDist) {
      nearestDist = dist;
      nearest = hit;
    }
  }

  if (!nearest) {
    const last = activeWidgets[activeWidgets.length - 1];
    return { id: last.id, insertAfter: true, insertIntoStack: false };
  }

  return dropTargetFromWidgetHit(nearest.widget, nearest.rect, clientX, clientY, {
    sourceWidget,
    directHit: false,
  });
}

const DASHBOARD_DROP_TARGET_SWITCH_PX = 28;

function dropTargetMatches(a, b) {
  return !!a && !!b
    && a.id === b.id
    && !!a.insertIntoStack === !!b.insertIntoStack
    && (a.insertIntoStack || a.insertAfter === b.insertAfter);
}

function stabilizeDropTarget(next, prev, clientX, clientY, grid) {
  if (!next) return null;
  if (!prev || dropTargetMatches(next, prev)) return next;

  const el = grid?.querySelector(`[data-widget-id="${next.id}"]`);
  const rect = readWidgetLayoutRect(el);
  if (!rect) return next;

  if (next.id !== prev.id) {
    const inset = DASHBOARD_DROP_TARGET_SWITCH_PX;
    const insideNext = pointInRect(rect, clientX, clientY, inset);
    return insideNext ? next : prev;
  }

  if (prev.insertIntoStack !== next.insertIntoStack) {
    if (next.insertIntoStack) {
      const bodyRect = stackDropBodyRect(grid, next.id) || rect;
      return pointInStackDropZone(bodyRect, clientX, clientY) ? next : prev;
    }
    return next;
  }

  const midY = rect.top + rect.height / 2;
  const buffer = DASHBOARD_DROP_TARGET_SWITCH_PX;
  if (next.insertAfter && clientY < midY + buffer) return prev;
  if (!next.insertAfter && clientY > midY - buffer) return prev;
  return next;
}

function applyDashboardWidgetResize(widgets, widgetId, { w, h, anchorRight, anchorBottom } = {}) {
  let list = widgets.map((item) => ({ ...item }));
  const idx = list.findIndex((item) => item.id === widgetId);
  if (idx < 0) return widgets;

  const widget = list[idx];
  const meta = getDashboardWidgetMeta(widget);
  if (!meta) return widgets;

  if (widget.parentStack && w != null) {
    const stack = list.find((item) => item.id === widget.parentStack);
    if (stack?.direction === 'horizontal') {
      const members = list.filter((item) => item.parentStack === stack.id && item.visible !== false);
      const packed = applyHorizontalStackChildWidth(members, widget.id, w, { fromWest: anchorRight != null });
      for (const member of packed) {
        const memberIdx = list.findIndex((item) => item.id === member.id);
        if (memberIdx >= 0) list[memberIdx] = clampDashboardWidget(member);
      }
      if (h == null) return list;
    }
  }

  let next = { ...list[idx] };

  if (w != null && !widget.parentStack) {
    let newW = nearestAllowedW(w, meta.allowedW);
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
    next = { ...next, x: Math.max(0, x), w: newW };
  }

  if (h != null && meta.maxH > meta.minH) {
    const oldBottom = widget.y + widget.h;
    let newH = snapDashboardHeight(h, meta.minH, meta.maxH, dashboardHeightStep(widget));
    let y = widget.y;
    if (anchorBottom != null) {
      y = anchorBottom - newH;
      if (y < 0) {
        y = 0;
        newH = snapDashboardHeight(newH, meta.minH, meta.maxH, dashboardHeightStep(widget));
      } else {
        y = Math.max(0, Math.floor(y + 1e-9));
      }
    }
    next = { ...next, y: Math.max(0, y), h: newH };
    list[idx] = clampDashboardWidget(next);
    if (!next.parentStack) {
      list = shiftTopLevelWidgetsBelow(list, list[idx], oldBottom, list[idx].y + list[idx].h);
    }
  } else {
    list[idx] = clampDashboardWidget(next);
  }

  next = list[idx];

  if (next.parentStack) {
    const stack = list.find((item) => item.id === next.parentStack);
    if (stack?.direction === 'vertical') {
      const members = list.filter((item) => item.parentStack === stack.id && item.visible !== false);
      const packed = reflowVerticalStackChildren(members);
      for (const member of packed) {
        const memberIdx = list.findIndex((item) => item.id === member.id);
        if (memberIdx >= 0) list[memberIdx] = clampDashboardWidget(member);
      }
    }
  }

  return list;
}

function finalizeStackChildResize(widgets, childId) {
  const list = reconcileStackMembership(widgets.map((item) => ({ ...item })));
  return syncStackAfterChildHeightChange(list, childId);
}

function resizeDashboardWidgetHeight(widgets, widgetId, nextH, { anchorBottom = null } = {}) {
  const next = applyDashboardWidgetResize(widgets, widgetId, { h: nextH, anchorBottom });
  const widget = next.find((item) => item.id === widgetId);
  if (widget?.parentStack) return finalizeStackChildResize(next, widgetId);
  return finalizeResizeDashboardLayout(next);
}

function resizeDashboardWidget(widgets, widgetId, nextW, { anchorRight = null } = {}) {
  const next = applyDashboardWidgetResize(widgets, widgetId, { w: nextW, anchorRight });
  const widget = next.find((item) => item.id === widgetId);
  if (widget?.parentStack) return finalizeStackChildResize(next, widgetId);
  return finalizeResizeDashboardLayout(next);
}

function previewResizeDashboardWidget(widgets, widgetId, { w, h, anchorRight, anchorBottom } = {}) {
  let next = widgets;
  if (w != null) next = applyDashboardWidgetResize(next, widgetId, { w, anchorRight });
  if (h != null) next = applyDashboardWidgetResize(next, widgetId, { h, anchorBottom });
  const widget = next.find((item) => item.id === widgetId);
  if (widget?.parentStack) return syncStackAfterChildHeightChange(next, widgetId);
  return next;
}

function finalizeDashboardWidgetLayout(prev, widgets) {
  const clamped = pruneHiddenEmptyStacks(
    reconcileStackMembership(
      widgets.map((widget) => clampDashboardWidget(widget)).filter(Boolean),
    ),
  );
  return {
    ...prev,
    version: DASHBOARD_LAYOUT_VERSION,
    widgets: reconcileStackMembership(clamped),
  };
}

function toggleDashboardWidgetVisibility(widgets, widgetId, visible) {
  const target = widgets.find((w) => w.id === widgetId);
  if (!target) return widgets;
  const nextVisible = visible !== false;
  if (!nextVisible && isEmptyStack(widgets, target)) {
    return removeDashboardStack(widgets, widgetId);
  }
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
    extractFromStack: (widgetId) => updateLayout((prev) => ({
      ...prev,
      widgets: extractWidgetFromStack(prev.widgets, widgetId),
    })),
    addStack: (direction) => updateLayout((prev) => ({
      ...prev,
      widgets: addDashboardStack(prev.widgets, direction),
    })),
    setWidgetVisible: (widgetId, visible) => updateLayout((prev) => ({
      ...prev,
      widgets: toggleDashboardWidgetVisibility(prev.widgets, widgetId, visible),
    })),
  };
}

function getHiddenDashboardWidgets(widgets) {
  const list = Array.isArray(widgets) ? widgets : [];
  return list
    .filter((widget) => {
      if (widget.visible !== false) return false;
      if (isEmptyStack(list, widget)) return false;
      if (!widget.parentStack) return true;
      const stack = list.find((item) => item.id === widget.parentStack);
      return stack && stack.visible !== false;
    })
    .sort((a, b) => {
      const labelA = getDashboardWidgetMeta(a)?.label || a.id;
      const labelB = getDashboardWidgetMeta(b)?.label || b.id;
      return String(labelA).localeCompare(String(labelB), 'ru');
    });
}

function hiddenWidgetCaption(widgets, widget) {
  if (isStackWidget(widget)) return stackContentsLabel(widgets, widget);
  if (!widget.parentStack) return '';
  const stack = (widgets || []).find((item) => item.id === widget.parentStack);
  if (!stack) return '';
  const stackLabel = getDashboardWidgetMeta(stack)?.label || stack.id;
  return `В стеке «${stackLabel}»`;
}

function DashboardHiddenWidgetsMenu({ widgets, onRestore, onDragStart, editMode }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);
  const hidden = useMemo(() => getHiddenDashboardWidgets(widgets), [widgets]);

  useEffect(() => {
    if (!editMode) setOpen(false);
  }, [editMode]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event) => {
      if (rootRef.current?.contains(event.target)) return;
      setOpen(false);
    };
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  if (!editMode) return null;

  const handleDragMouseDown = (widgetId) => (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    setOpen(false);
    onDragStart?.(widgetId, event);
  };

  return (
    <div className={`dashboard-hidden-menu${open ? ' is-open' : ''}`} ref={rootRef}>
      <Button
        kind="ghost"
        size="sm"
        icon="eyeOff"
        iconRight="chevD"
        onClick={() => setOpen((value) => !value)}
        title="Скрытые карточки"
      >
        Скрытые
        {hidden.length ? (
          <span className="dashboard-hidden-menu__count">{hidden.length}</span>
        ) : null}
      </Button>
      {open ? (
        <div className="dashboard-hidden-menu__dropdown" role="menu">
          <div className="dashboard-hidden-menu__title">Скрытые карточки</div>
          {hidden.length ? (
            <div className="dashboard-hidden-menu__hint">Перетащите на дашборд, чтобы разместить</div>
          ) : null}
          {hidden.length ? hidden.map((widget) => {
            const meta = getDashboardWidgetMeta(widget);
            const caption = hiddenWidgetCaption(widgets, widget);
            return (
              <div
                key={widget.id}
                className="dashboard-hidden-menu__item"
                role="menuitem"
              >
                <button
                  type="button"
                  className="dashboard-hidden-menu__item-drag"
                  title="Перетащите на дашборд"
                  onMouseDown={handleDragMouseDown(widget.id)}
                >
                  <Icon name="drag" size={14} />
                  <span className="dashboard-hidden-menu__item-text">
                    <span className="dashboard-hidden-menu__item-label">{meta?.label || widget.id}</span>
                    {caption ? (
                      <span className="dashboard-hidden-menu__item-meta">{caption}</span>
                    ) : null}
                  </span>
                </button>
                <button
                  type="button"
                  className="dashboard-hidden-menu__restore"
                  onClick={() => onRestore(widget.id)}
                >
                  <Icon name="eye" size={14} />
                  Вернуть
                </button>
              </div>
            );
          }) : (
            <div className="dashboard-hidden-menu__empty">Нет скрытых карточек</div>
          )}
        </div>
      ) : null}
    </div>
  );
}

function DashboardLayoutToolbar({
  editMode,
  onToggleEdit,
  onReset,
  onAddVerticalStack,
  onAddHorizontalStack,
  saveState,
  canEdit,
  widgets,
  onRestoreWidget,
  onHiddenWidgetDragStart,
  className = '',
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
    <div className={`dashboard-layout-toolbar${editMode ? ' dashboard-layout-toolbar--edit' : ''}${className ? ` ${className}` : ''}`}>
      {saveLabel ? (
        <span className={`dashboard-layout-toolbar__status${saveState === 'error' ? ' is-error' : ''}`}>
          {saveLabel}
        </span>
      ) : null}
      {editMode ? (
        <>
          <DashboardHiddenWidgetsMenu
            editMode={editMode}
            widgets={widgets}
            onRestore={(widgetId) => onRestoreWidget?.(widgetId)}
            onDragStart={(widgetId, event) => onHiddenWidgetDragStart?.(widgetId, event)}
          />
          <Button kind="ghost" size="sm" onClick={onAddVerticalStack}>Вертикальный стек</Button>
          <Button kind="ghost" size="sm" onClick={onAddHorizontalStack}>Горизонтальный стек</Button>
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
  onExtractFromStack,
  inStack = false,
  emptyStack = false,
  caption = '',
  children,
}) {
  if (!editMode) return children;

  const meta = getDashboardWidgetMeta(widget);
  const hideTitle = emptyStack
    ? 'Удалить пустой стек'
    : (widget.visible ? 'Скрыть виджет' : 'Показать виджет');

  return (
    <div className={`dashboard-widget-chrome${widget.visible ? '' : ' is-hidden'}${inStack ? ' dashboard-widget-chrome--in-stack' : ''}`}>
      <div className="dashboard-widget-chrome__bar">
        {onDragHandleMouseDown ? (
          <div
            className="dashboard-widget-chrome__handle"
            title="Перетащите для изменения порядка"
            onMouseDown={onDragHandleMouseDown}
          >
            <Icon name="drag" />
            <span className="dashboard-widget-chrome__title">
              <span>{meta?.label || widget.id}</span>
              {caption ? <span className="dashboard-widget-chrome__caption">{caption}</span> : null}
            </span>
          </div>
        ) : (
          <div className="dashboard-widget-chrome__label">
            <span>{meta?.label || widget.id}</span>
            {caption ? <span className="dashboard-widget-chrome__caption">{caption}</span> : null}
          </div>
        )}
        <div className="dashboard-widget-chrome__actions">
          {inStack && onExtractFromStack ? (
            <button
              type="button"
              className="dashboard-widget-chrome__extract"
              title="Извлечь из стека"
              onClick={onExtractFromStack}
            >
              <Icon name="arrowURight" />
            </button>
          ) : null}
          <button
            type="button"
            className={`dashboard-widget-chrome__hide${emptyStack ? ' is-delete' : ''}`}
            title={hideTitle}
            onClick={onToggleVisibility}
          >
            <Icon name={emptyStack ? 'trash' : (widget.visible ? 'eyeOff' : 'eye')} />
          </button>
        </div>
      </div>
      <div className="dashboard-widget-chrome__body">
        {children}
      </div>
    </div>
  );
}

function DashboardStack({
  stack,
  widgets,
  editMode,
  renderChild,
}) {
  const children = getStackChildWidgets(widgets, stack).filter((child) => child.visible !== false);

  return (
    <div className={`dashboard-stack dashboard-stack--${stack.direction === 'horizontal' ? 'horizontal' : 'vertical'}${editMode ? ' dashboard-stack--edit' : ''}`}>
      {children.length ? children.map((child) => (
        <div
          key={child.id}
          className="dashboard-stack__item"
          style={stackChildStyle(child)}
        >
          {renderChild(child, { inStack: true, stack })}
        </div>
      )) : (
        editMode ? <div className="dashboard-stack__empty">Перетащите виджеты сюда</div> : null
      )}
    </div>
  );
}

function DashboardWidgetPhantom({ widget, compact, detail }) {
  const meta = getDashboardWidgetMeta(widget);
  const style = dashboardWidgetStyle(widget, compact);

  return (
    <div
      className={`dashboard-widget dashboard-widget--phantom${isStackWidget(widget) ? ' dashboard-widget--phantom-stack' : ''}${isTrafficChartHalfHeight(widget) ? ' dashboard-widget--fixed-h' : ''}`}
      style={style}
      data-dashboard-phantom="true"
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
  const h = Math.max(1, Number(widget.h) || 1);
  const spanH = dashboardGridSpanH(h);
  const meta = getDashboardWidgetMeta(widget);
  const rowPx = (isStackWidget(widget) || widget.parentStack) ? STACK_ROW_SIZE_PX : DASHBOARD_GRID_ROW_PX;
  const style = {
    gridColumn: `${widget.x + 1} / span ${w}`,
    gridRow: `${widget.y + 1} / span ${spanH}`,
    '--dw-w': w,
    '--dw-h': h,
  };
  if (meta && meta.maxH > meta.minH) {
    let minHeightPx = h * rowPx;
    if (widget.id === 'traffic-chart') {
      minHeightPx = trafficChartHeightPx(h);
      if (isTrafficChartHalfHeight(widget)) {
        style.height = `${minHeightPx}px`;
        style.maxHeight = `${minHeightPx}px`;
        style.alignSelf = 'start';
        style['--dw-fixed-h'] = `${minHeightPx}px`;
      }
    }
    style.minHeight = `${minHeightPx}px`;
  }
  return style;
}

const DASHBOARD_FLIP_TRANSITION = 'transform 0.34s cubic-bezier(0.22, 1, 0.36, 1)';

function dashboardLayoutPreviewKey(widgets) {
  return widgets
    .filter((w) => w.visible !== false)
    .map((w) => {
      let key = `${w.id}@${w.x},${w.y},${w.w},${w.h}`;
      if (w.parentStack) key += `:p${w.parentStack}`;
      if (isStackWidget(w)) key += `:c${(w.childIds || []).join('.')}`;
      return key;
    })
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
  onExtractFromStack,
  beginDragRef,
}) {
  const gridRef = useRef(null);
  const dragSourceRef = useRef(null);
  const lastDropTargetRef = useRef(null);
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
    if (draggingId || resizingId || !flipFirstRectsRef.current || !gridRef.current) return;
    runDashboardFlipAnimation(gridRef.current, flipFirstRectsRef.current);
    flipFirstRectsRef.current = null;
  }, [dragPreview, resizePreview, layout.widgets, draggingId, resizingId]);

  const layoutWidgets = resizePreview?.widgets || dragPreview?.widgets || layout.widgets;
  const visibleWidgets = sortDashboardWidgets(
    getTopLevelWidgets(layoutWidgets).filter((w) => w.visible && !(draggingId && w.id === draggingId)),
  );
  const phantomWidget = draggingId
    ? layoutWidgets.find((w) => w.id === draggingId && w.visible !== false)
    : null;
  const interactionPhantom = phantomWidget;

  const queueResizePreview = (widgetId, previewWidgets) => {
    if (!previewWidgets) {
      setResizePreview(null);
      return;
    }
    const nextKey = dashboardLayoutPreviewKey(previewWidgets);
    const currentKey = resizePreview ? dashboardLayoutPreviewKey(resizePreview.widgets) : '';
    if (nextKey === currentKey) return;
    setResizePreview({ widgetId, widgets: previewWidgets });
  };

  const resolveDropTarget = (clientX, clientY, sourceId) => {
    const { layout: liveLayout, dragPreview: livePreview } = dragContextRef.current;
    const widgetsForHitTest = livePreview?.widgets || liveLayout.widgets;
    const phantomEl = gridRef.current?.querySelector('[data-dashboard-phantom="true"]');
    const phantomRect = phantomEl ? phantomEl.getBoundingClientRect() : null;
    return findDropTargetFromPoint(
      clientX,
      clientY,
      sourceId,
      gridRef.current,
      widgetsForHitTest,
      { phantomRect, lastTarget: lastDropTargetRef.current },
    );
  };

  const queueDragPreview = (nextPreview) => {
    const nextKey = nextPreview ? dashboardLayoutPreviewKey(nextPreview.widgets) : '';
    if (nextKey === dragPreviewKeyRef.current) return;
    dragPreviewKeyRef.current = nextKey;
    setDragPreview(nextPreview);
  };

  const onDragHandleMouseDown = (widgetId) => (e) => {
    if (!editMode || e.button !== 0) return;
    e.preventDefault();
    dragSourceRef.current = widgetId;
    lastDropTargetRef.current = null;
    dragPreviewKeyRef.current = dashboardLayoutPreviewKey(layout.widgets);
    setDragPreview(null);

    const originX = e.clientX;
    const originY = e.clientY;
    let dragStarted = false;

    const ensureDragStarted = (ev) => {
      if (dragStarted) return true;
      if (Math.hypot(ev.clientX - originX, ev.clientY - originY) < 8) return false;
      dragStarted = true;
      setDraggingId(widgetId);
      return true;
    };

    const applyDragPreview = (ev) => {
      if (!ensureDragStarted(ev)) return;
      const sourceId = dragSourceRef.current;
      if (!sourceId) return;
      const { layout: liveLayout } = dragContextRef.current;
      const rawTarget = resolveDropTarget(ev.clientX, ev.clientY, sourceId);
      const dropTarget = stabilizeDropTarget(
        rawTarget,
        lastDropTargetRef.current,
        ev.clientX,
        ev.clientY,
        gridRef.current,
      );
      if (dropTarget) lastDropTargetRef.current = dropTarget;
      if (!dropTarget) {
        queueDragPreview(null);
        return;
      }
      const previewWidgets = previewDashboardMove(
        liveLayout.widgets,
        sourceId,
        dropTarget.id,
        {
          insertAfter: dropTarget.insertAfter,
          insertIntoStack: dropTarget.insertIntoStack,
        },
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
      dragSourceRef.current = null;
      lastDropTargetRef.current = null;
      dragPreviewKeyRef.current = '';
      if (!dragStarted) {
        setDraggingId(null);
        setDragPreview(null);
        return;
      }
      const { layout: liveLayout } = dragContextRef.current;
      const dropTarget = resolveDropTarget(ev.clientX, ev.clientY, sourceId);
      const preview = sourceId && dropTarget
        ? previewDashboardMove(liveLayout.widgets, sourceId, dropTarget.id, {
          insertAfter: dropTarget.insertAfter,
          insertIntoStack: dropTarget.insertIntoStack,
        })
        : null;
      const previewKey = preview ? dashboardLayoutPreviewKey(preview) : '';
      const originalKey = dashboardLayoutPreviewKey(liveLayout.widgets);
      if (sourceId && dropTarget && preview && previewKey !== originalKey) {
        onMoveWidget(sourceId, dropTarget.id, {
          insertAfter: dropTarget.insertAfter,
          insertIntoStack: dropTarget.insertIntoStack,
        });
      }
      setDraggingId(null);
      setDragPreview(null);
    };

    document.body.style.cursor = 'grabbing';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  if (beginDragRef) {
    beginDragRef.current = (widgetId, event) => onDragHandleMouseDown(widgetId)(event);
  }

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
    const isStackChild = !!widget.parentStack;
    const stackEl = isStackChild
      ? grid.querySelector(`[data-widget-id="${widget.parentStack}"] .dashboard-stack`)
      : null;
    const measureEl = (isStackChild && stackEl) ? stackEl : grid;
    const maxCols = isStackChild ? STACK_INNER_COLS : DASHBOARD_GRID_COLS;
    const rect = measureEl.getBoundingClientRect();
    const colWidth = rect.width / maxCols;
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
    if (!grid) return;

    const meta = getDashboardWidgetMeta(widget);
    if (!meta || meta.maxH <= meta.minH) return;

    setResizingId(widget.id);
    setResizePreview(null);
    setDragPreview(null);
    setDraggingId(null);

    const fromNorth = edge === 'north';
    const rowPx = (widget.parentStack || isStackWidget(widget)) ? STACK_ROW_SIZE_PX : DASHBOARD_GRID_ROW_PX;
    const heightStep = dashboardHeightStep(widget);
    const rowHeight = Math.max(72, (rowPx + DASHBOARD_GRID_GAP_PX) / 2) * heightStep;
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
        const rawDelta = (pendingEv.clientY - startY) / Math.max(rowHeight, 1);
        const deltaRows = Math.round(rawDelta) * heightStep;
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

  const renderWidgetShell = (widget, { hiddenPreview = false, inStack = false, stack = null } = {}) => {
    const meta = getDashboardWidgetMeta(widget);
    const stackWidget = isStackWidget(widget);

    if (inStack) {
      const childContent = renderers[widget.id] ? renderers[widget.id]() : null;
      const parentStack = stack || (widget.parentStack
        ? layoutWidgets.find((item) => item.id === widget.parentStack)
        : null);
      const siblings = parentStack
        ? sortStackChildren(getStackChildWidgets(layoutWidgets, parentStack).filter((item) => item.visible !== false))
        : [];
      const siblingIdx = siblings.findIndex((item) => item.id === widget.id);
      const canResizeWidth = editMode && !compact && parentStack?.direction === 'horizontal' && siblings.length > 1;
      const canResizeWest = canResizeWidth && siblingIdx > 0;
      const canResizeEast = canResizeWidth && siblingIdx >= 0 && siblingIdx < siblings.length - 1;
      const canResizeHeight = editMode && !!meta && meta.maxH > meta.minH;
      return (
        <div
          key={widget.id}
          className={`dashboard-widget dashboard-widget--in-stack${editMode ? ' dashboard-widget--in-stack-edit' : ''}`}
          data-widget-id={widget.id}
        >
          <DashboardWidgetChrome
            widget={widget}
            editMode={editMode}
            inStack
            onToggleVisibility={() => onToggleWidgetVisible(widget.id, !widget.visible)}
            onExtractFromStack={() => onExtractFromStack(widget.id)}
          >
            {childContent || (editMode ? (
              <div className="dashboard-widget-phantom__frame dashboard-widget-phantom__frame--compact">
                <span>{meta?.label || widget.id}</span>
              </div>
            ) : null)}
          </DashboardWidgetChrome>
          {canResizeWest ? (
            <div
              className="dashboard-widget__resize-w"
              role="separator"
              aria-orientation="vertical"
              aria-label="Изменить ширину слева"
              onMouseDown={onResizeWidthMouseDown(widget, 'west')}
            />
          ) : null}
          {canResizeEast ? (
            <div
              className="dashboard-widget__resize-e"
              role="separator"
              aria-orientation="vertical"
              aria-label="Изменить ширину справа"
              onMouseDown={onResizeWidthMouseDown(widget, 'east')}
            />
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
    }

    const isInteractionSource = widget.id === draggingId && interactionPhantom;
    const canResizeWidth = editMode && !compact && !!meta;
    const canResizeHeight = editMode && !!meta && meta.maxH > meta.minH;
    const style = dashboardWidgetStyle(widget, compact);
    const modeKey = (widget.id === 'distribution-protocols' || widget.id === 'distribution-services')
      ? distributionRenderKey
      : '';
    const emptyStack = stackWidget && isEmptyStack(layoutWidgets, widget);
    const stackCaption = stackWidget && !emptyStack ? stackContentsLabel(layoutWidgets, widget) : '';
    let content = null;
    if (stackWidget) {
      content = (
        <DashboardStack
          stack={widget}
          widgets={layoutWidgets}
          editMode={editMode}
          renderChild={(child, options) => renderWidgetShell(child, options)}
        />
      );
    } else {
      content = renderers[widget.id] ? renderers[widget.id]() : null;
    }
    if (!content && !editMode && !hiddenPreview && !stackWidget) return null;

    return (
      <div
        key={`${widget.id}${modeKey ? `:${modeKey}` : ''}`}
        data-widget-id={widget.id}
        data-flip-id={widget.id}
        className={`dashboard-widget${stackWidget ? ' dashboard-widget--stack' : ''}${hiddenPreview ? ' is-hidden-preview' : ''}${isInteractionSource && interactionPhantom ? ' is-interaction-source' : ''}${dragPreview || resizePreview ? ' is-preview-shifted' : ''}${widget.id === resizingId ? ' is-resizing' : ''}${isTrafficChartHalfHeight(widget) ? ' dashboard-widget--fixed-h' : ''}`}
        style={style}
      >
        <DashboardWidgetChrome
          widget={widget}
          editMode={editMode}
          emptyStack={emptyStack}
          caption={stackCaption}
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
      className={`dashboard-grid${editMode ? ' dashboard-grid--edit' : ''}${draggingId ? ' dashboard-grid--dragging' : ''}${resizingId ? ' dashboard-grid--resizing' : ''}${dragPreview || resizePreview ? ' dashboard-grid--drag-preview' : ''}${compact ? ' dashboard-grid--compact' : ''}`}
    >
      {visibleWidgets.map((widget) => {
        if (interactionPhantom && widget.id === interactionPhantom.id) return null;
        return renderWidgetShell(widget);
      })}
      {interactionPhantom ? (
        <DashboardWidgetPhantom
          widget={interactionPhantom}
          compact={compact}
          detail={`${getDashboardWidgetMeta(interactionPhantom)?.label || interactionPhantom.id} · ${interactionPhantom.w}×${interactionPhantom.h}`}
        />
      ) : null}
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
