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
