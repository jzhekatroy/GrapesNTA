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

test('default layout contains all widgets visible', () => {
  assert.equal(DEFAULT_OPERATOR_LAYOUT.widgets.length, OPERATOR_WIDGET_IDS.length);
  assert.equal(DEFAULT_OPERATOR_LAYOUT.widgets.length, 10);
  for (const widget of DEFAULT_OPERATOR_LAYOUT.widgets) {
    assert.equal(widget.visible, true);
    assert.ok(OPERATOR_WIDGET_IDS.includes(widget.id));
  }
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
  assert.equal(merged.widgets.length, OPERATOR_WIDGET_IDS.length);
});

test('migrateV1ToV2 expands composite widgets and maps settings', () => {
  const migrated = migrateV1ToV2(LEGACY_V1_LAYOUT);
  assert.equal(migrated.version, 2);
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
  assert.equal(merged.version, 2);
  assert.equal(merged.widgets.length, OPERATOR_WIDGET_IDS.length);
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
      w.id === 'top-talkers' ? { ...w, w: 9 } : w
    )),
    settings: {},
  });
  const talkers = layout.widgets.find((w) => w.id === 'top-talkers');
  assert.equal(talkers.w, 8);
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
