'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public', 'data');

function loadLocaleMessages(locale) {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(PUBLIC, 'i18n', `${locale}.js`), 'utf8'), sandbox);
  return sandbox.window.GrapesI18nMessages[locale];
}

function loadI18n() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(PUBLIC, 'i18n', 'ru.js'), 'utf8'), sandbox);
  vm.runInContext(fs.readFileSync(path.join(PUBLIC, 'i18n', 'en.js'), 'utf8'), sandbox);
  vm.runInContext(fs.readFileSync(path.join(PUBLIC, 'i18n.js'), 'utf8'), sandbox);
  return sandbox.window.GrapesI18n;
}

test('ru и en имеют одинаковый набор ключей', () => {
  const ru = loadLocaleMessages('ru');
  const en = loadLocaleMessages('en');
  assert.deepEqual(Object.keys(en).sort(), Object.keys(ru).sort());
});

test('английские подписи меню совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['nav.section.overview'], 'Main');
  assert.equal(en['nav.item.explorer'], 'Traffic explorer');
  assert.equal(en['directions.all'], 'All directions');
  assert.equal(en['directions.countOf'], '{n} of {total}');
  assert.equal(en['collectors.all'], 'All collectors');
  assert.equal(en['chrome.refresh'], 'Refresh');
  assert.equal(en['nav.sidebar.collapse'], 'Collapse menu');
  assert.equal(en['user.allowedSections'], 'Allowed sections');
  assert.equal(en['tz.auto'], 'Auto — browser time zone');
});

test('GrapesI18n подставляет параметры и fallback на ru', () => {
  const GrapesI18n = loadI18n();
  GrapesI18n.setLocale('en');
  assert.equal(GrapesI18n.t('directions.countOf', { n: 2, total: 6 }), '2 of 6');
  GrapesI18n.setLocale('ru');
  assert.equal(GrapesI18n.t('directions.countOf', { n: 2, total: 6 }), '2 из 6');
  GrapesI18n.setLocale('en');
  assert.equal(GrapesI18n.localizedPageMeta('dashboard', { title: 'Обзор', section: 'Главное' }).title, 'Overview');
});

test('английские подписи дашборда совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['dashboard.title'], 'Network summary');
  assert.equal(en['dashboard.chart.title'], 'Bandwidth and PPS');
  assert.equal(en['dashboard.chart.selectRange'], 'Select a range on the chart');
  assert.equal(en['dashboard.stack.horizontal'], 'Horizontal stack');
  assert.equal(en['dashboard.stack.drop'], 'Drag widgets here');
  assert.equal(en['dashboard.geo.asnCountry'], 'ASN Country (Registry)');
  assert.equal(en['dashboard.otherPorts.title'], 'Top 20 other ports');
});

test('английские подписи наблюдений совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['observations.title'], 'Observations');
  assert.equal(en['observations.collector'], 'Collector');
  assert.equal(en['observations.filters'], 'Filters');
  assert.equal(en['observations.filters.none'], 'no filters');
  assert.equal(en['observations.materialize.label'], 'Data preparation (rollup every 5 minutes)');
  assert.equal(en['observations.group'], 'Group');
  assert.equal(en['observations.prep.active'], 'Data preparation: active {n}');
  assert.equal(en['observations.expand'], 'Expand');
  assert.equal(en['observations.collapse'], 'Collapse');
  assert.equal(en['observations.new'], 'New');
  assert.equal(en['observations.fromExplorer'], 'From Explorer…');
  assert.equal(en['observations.preset.uplink'], 'Inbound/Outbound traffic');
  assert.equal(en['observations.preset.vlan'], 'VLAN Traffic');
  assert.equal(en['observations.settings'], 'Settings');
  assert.equal(en['observations.settings.back'], 'Dashboard');
  assert.equal(en['observations.stats.avgTitle'], 'Average over window points');
  assert.equal(en['observations.stats.nowMaxTitle'], 'Last point relative to window peak');
  assert.equal(en['observations.settings.save'], 'Save');
  assert.equal(en['observations.settings.changeFilters'], 'Change filters in the traffic explorer');
  assert.equal(en['observations.deleteConfirm'], 'Delete observation?');
  assert.equal(en['observations.series.add'], 'Add to selected');
  assert.equal(en['observations.series.remove'], 'Remove from selected');
  assert.equal(en['observations.chart.lines'], 'Lines');
  assert.equal(en['observations.chart.linesHint'], 'Overlapping lines by series');
  assert.equal(en['observations.chart.stack'], 'Stack');
  assert.equal(en['observations.chart.stackHint'], 'Stacked areas, sum of selected series');
  assert.equal(en['chart.tip.interval'], 'interval {bucket}');
  assert.equal(en['chart.tip.from'], '5 min from {time}');
});
