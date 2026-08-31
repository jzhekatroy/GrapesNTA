'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  DEFAULT_OPERATOR_LAYOUT,
  OPERATOR_WIDGET_IDS,
  mergeWithDefaults,
  validateLayout,
  migrateV1ToV2,
  getLayout,
  putLayout,
  resetLayout,
  resetStoreForTests,
} = require('./dashboard-layout');

function tempDbPath(name) {
  return path.join(os.tmpdir(), `grapes-dash-layout-${name}-${process.pid}-${Date.now()}.db`);
}

const LEGACY_V1_LAYOUT = {
  version: 1,
  widgets: [
    { id: 'traffic-stats', x: 0, y: 0, w: 12, h: 1, visible: true },
    { id: 'traffic-chart-row', x: 0, y: 1, w: 12, h: 2, visible: false },
    { id: 'vlan', x: 0, y: 3, w: 12, h: 1, visible: true },
    { id: 'top-talkers', x: 0, y: 4, w: 7, h: 2, visible: true },
    { id: 'countries', x: 7, y: 4, w: 5, h: 2, visible: true },
    { id: 'recent-flows', x: 0, y: 6, w: 12, h: 1, visible: true },
  ],
  settings: { 'traffic-chart-row': { distributionMode: 'trend', trendSplit: 0.4 } },
};

test.afterEach(() => {
  resetStoreForTests();
});

const DEFAULT_HIDDEN_WIDGET_IDS = new Set(['stat-max', 'stat-avg', 'stat-volume', 'vlan']);

function isDefaultStackWidget(widget) {
  return widget?.kind === 'stack' || String(widget?.id || '').startsWith('stack-');
}

function defaultContentWidgets() {
  return DEFAULT_OPERATOR_LAYOUT.widgets
    .filter((widget) => !isDefaultStackWidget(widget))
    .map((widget) => {
      const next = { ...widget };
      delete next.parentStack;
      return next;
    });
}

test('default layout hides stats and VLAN widgets', () => {
  const content = defaultContentWidgets();
  assert.equal(content.length, OPERATOR_WIDGET_IDS.length);
  assert.equal(content.length, 10);
  for (const widget of content) {
    assert.ok(OPERATOR_WIDGET_IDS.includes(widget.id));
    assert.equal(widget.visible, !DEFAULT_HIDDEN_WIDGET_IDS.has(widget.id));
  }
});

test('default layout stacks protocols/services and countries/talkers', () => {
  const vertical = DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'stack-v-bsu8e0s');
  const horizontal = DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'stack-h-kiphmzp');
  assert.equal(vertical?.direction, 'vertical');
  assert.deepEqual(vertical?.childIds, ['distribution-protocols', 'distribution-services']);
  assert.equal(horizontal?.direction, 'horizontal');
  assert.deepEqual(horizontal?.childIds, ['countries', 'top-talkers']);
  assert.equal(
    DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'distribution-protocols').parentStack,
    'stack-v-bsu8e0s',
  );
  assert.equal(
    DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'top-talkers').parentStack,
    'stack-h-kiphmzp',
  );
  assert.equal(
    DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'countries').parentStack,
    'stack-h-kiphmzp',
  );
  assert.equal(DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'countries').w, 6);
  assert.equal(DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'recent-flows').parentStack, undefined);
  assert.equal(DEFAULT_OPERATOR_LAYOUT.widgets.find((w) => w.id === 'recent-flows').w, 12);
});

test('mergeWithDefaults preserves user order and adds new widgets', () => {
  const saved = {
    version: 2,
    widgets: DEFAULT_OPERATOR_LAYOUT.widgets.map((w) => (
      w.id === 'vlan' ? { ...w, y: 99, visible: false } : w
    )),
    settings: { distribution: { distributionMode: 'trend', trendSplit: 0.4 } },
  };
  const merged = mergeWithDefaults(saved);
  const vlan = merged.widgets.find((w) => w.id === 'vlan');
  assert.equal(vlan.y, 99);
  assert.equal(vlan.visible, false);
  assert.equal(merged.settings.distribution.protocolsMode, 'trend');
  assert.equal(merged.settings.distribution.servicesMode, 'trend');
  assert.equal(merged.settings.distribution.trendSplit, 0.4);
  assert.equal(merged.widgets.length, DEFAULT_OPERATOR_LAYOUT.widgets.length);
});

test('mergeWithDefaults does not inject default stacks into existing layouts', () => {
  const saved = {
    version: 3,
    widgets: defaultContentWidgets().map((w) => (
      w.id === 'countries' ? { ...w, y: 8 } : w
    )),
    settings: DEFAULT_OPERATOR_LAYOUT.settings,
  };
  const merged = mergeWithDefaults(saved);
  assert.equal(merged.widgets.some((w) => isDefaultStackWidget(w)), false);
  assert.equal(merged.widgets.find((w) => w.id === 'countries').y, 8);
  assert.equal(merged.widgets.find((w) => w.id === 'distribution-protocols').parentStack, undefined);
});

test('migrateV1ToV2 expands composite widgets and maps settings', () => {
  const migrated = migrateV1ToV2(LEGACY_V1_LAYOUT);
  assert.equal(migrated.version, 3);
  assert.equal(migrated.settings.distribution.protocolsMode, 'trend');
  assert.equal(migrated.settings.distribution.servicesMode, 'trend');
  assert.equal(migrated.settings.distribution.trendSplit, 0.4);
  for (const id of ['stat-max', 'stat-avg', 'stat-volume']) {
    assert.equal(migrated.widgets.find((w) => w.id === id).visible, true);
  }
  for (const id of ['traffic-chart', 'distribution-protocols', 'distribution-services']) {
    assert.equal(migrated.widgets.find((w) => w.id === id).visible, false);
  }
});

test('mergeWithDefaults migrates legacy v1 layouts', () => {
  const merged = mergeWithDefaults(LEGACY_V1_LAYOUT);
  assert.equal(merged.version, 3);
  assert.equal(merged.widgets.length, DEFAULT_OPERATOR_LAYOUT.widgets.length);
  assert.equal(merged.settings.distribution.protocolsMode, 'trend');
  assert.equal(merged.settings.distribution.servicesMode, 'trend');
});

test('validateLayout rejects unknown widget and all hidden', () => {
  assert.throws(
    () => validateLayout({
      version: 2,
      widgets: [{ id: 'unknown', x: 0, y: 0, w: 12, h: 1, visible: true }],
      settings: {},
    }),
    /Неизвестный виджет/,
  );

  assert.throws(
    () => validateLayout({
      version: 2,
      widgets: DEFAULT_OPERATOR_LAYOUT.widgets.map((w) => ({ ...w, visible: false })),
      settings: {},
    }),
    /хотя бы один видимый/,
  );
});

test('validateLayout clamps widget width', () => {
  const layout = validateLayout({
    version: 2,
    widgets: DEFAULT_OPERATOR_LAYOUT.widgets.map((w) => (
      w.id === 'traffic-chart' ? { ...w, w: 9 } : w
    )),
    settings: {},
  });
  const chart = layout.widgets.find((w) => w.id === 'traffic-chart');
  assert.equal(chart.w, 8);
});

test('validateLayout allows a taller traffic-chart', () => {
  const layout = validateLayout({
    version: 3,
    widgets: DEFAULT_OPERATOR_LAYOUT.widgets.map((w) => (
      w.id === 'traffic-chart' ? { ...w, h: 6 } : w
    )),
    settings: DEFAULT_OPERATOR_LAYOUT.settings,
  });
  assert.equal(layout.widgets.find((w) => w.id === 'traffic-chart').h, 6);
});

test('validateLayout keeps traffic-chart at least one row', () => {
  const layout = validateLayout({
    version: 3,
    widgets: DEFAULT_OPERATOR_LAYOUT.widgets.map((w) => (
      w.id === 'traffic-chart' ? { ...w, h: 0 } : w
    )),
    settings: DEFAULT_OPERATOR_LAYOUT.settings,
  });
  assert.equal(layout.widgets.find((w) => w.id === 'traffic-chart').h, 1);
});

test('validateLayout accepts stack grouping', () => {
  const layout = validateLayout({
    version: 3,
    widgets: [
      ...defaultContentWidgets().filter((w) => !['top-talkers', 'countries'].includes(w.id)),
      {
        id: 'stack-v-test01',
        kind: 'stack',
        direction: 'vertical',
        x: 0,
        y: 4,
        w: 12,
        h: 4,
        visible: true,
        childIds: ['top-talkers', 'countries'],
      },
      { id: 'top-talkers', parentStack: 'stack-v-test01', x: 0, y: 0, w: 7, h: 2, visible: true },
      { id: 'countries', parentStack: 'stack-v-test01', x: 0, y: 2, w: 5, h: 2, visible: true },
    ],
    settings: DEFAULT_OPERATOR_LAYOUT.settings,
  });
  const stack = layout.widgets.find((w) => w.id === 'stack-v-test01');
  assert.equal(stack.kind, 'stack');
  assert.deepEqual(stack.childIds, ['top-talkers', 'countries']);
});

test('validateLayout accepts horizontal stack children with inner widths', () => {
  const layout = validateLayout({
    version: 3,
    widgets: [
      ...defaultContentWidgets().filter((w) => !['stat-max', 'stat-avg', 'stat-volume'].includes(w.id)),
      {
        id: 'stack-h-test01',
        kind: 'stack',
        direction: 'horizontal',
        x: 0,
        y: 0,
        w: 12,
        h: 2,
        visible: true,
        childIds: ['stat-max', 'stat-avg', 'stat-volume'],
      },
      { id: 'stat-max', parentStack: 'stack-h-test01', x: 0, y: 0, w: 4, h: 1, visible: true },
      { id: 'stat-avg', parentStack: 'stack-h-test01', x: 4, y: 0, w: 4, h: 1, visible: true },
      { id: 'stat-volume', parentStack: 'stack-h-test01', x: 8, y: 0, w: 4, h: 1, visible: true },
    ],
    settings: DEFAULT_OPERATOR_LAYOUT.settings,
  });
  const stack = layout.widgets.find((w) => w.id === 'stack-h-test01');
  assert.equal(stack.direction, 'horizontal');
  assert.equal(layout.widgets.find((w) => w.id === 'stat-max').w, 4);
  assert.equal(layout.widgets.find((w) => w.id === 'stat-avg').parentStack, 'stack-h-test01');
});

test('validateLayout keeps non-allowed inner widths for stacked widgets', () => {
  const layout = validateLayout({
    version: 3,
    widgets: [
      ...defaultContentWidgets().filter((w) => !['stat-max', 'stat-avg', 'stat-volume'].includes(w.id)),
      {
        id: 'stack-h-test02',
        kind: 'stack',
        direction: 'horizontal',
        x: 0,
        y: 0,
        w: 12,
        h: 2,
        visible: true,
        childIds: ['stat-max', 'stat-avg', 'stat-volume'],
      },
      { id: 'stat-max', parentStack: 'stack-h-test02', x: 0, y: 0, w: 3, h: 1, visible: true },
      { id: 'stat-avg', parentStack: 'stack-h-test02', x: 3, y: 0, w: 3, h: 1, visible: true },
      { id: 'stat-volume', parentStack: 'stack-h-test02', x: 6, y: 0, w: 6, h: 1, visible: true },
    ],
    settings: DEFAULT_OPERATOR_LAYOUT.settings,
  });
  assert.equal(layout.widgets.find((w) => w.id === 'stat-max').w, 3);
  assert.equal(layout.widgets.find((w) => w.id === 'stat-volume').w, 6);
});

test('validateLayout rejects inconsistent stack membership', () => {
  assert.throws(
    () => validateLayout({
      version: 3,
      widgets: [
        ...defaultContentWidgets(),
        {
          id: 'stack-v-bad001',
          kind: 'stack',
          direction: 'vertical',
          x: 0,
          y: 8,
          w: 6,
          h: 2,
          visible: true,
          childIds: ['vlan'],
        },
      ],
      settings: {},
    }),
    /Несогласованный parentStack/,
  );
});

test('putLayout and getLayout round-trip per user', () => {
  const dbPath = tempDbPath('roundtrip');
  resetStoreForTests(dbPath);
  const custom = validateLayout({
    version: 2,
    widgets: DEFAULT_OPERATOR_LAYOUT.widgets.map((w) => (
      w.id === 'recent-flows' ? { ...w, y: 10 } : w
    )),
    settings: DEFAULT_OPERATOR_LAYOUT.settings,
  });
  putLayout('user-1', custom);
  const loaded = getLayout('user-1');
  assert.ok(loaded);
  assert.equal(loaded.layout.widgets.find((w) => w.id === 'recent-flows').y, 10);
  resetLayout('user-1');
  assert.equal(getLayout('user-1'), null);
});

test.after(() => {
  resetStoreForTests();
});
