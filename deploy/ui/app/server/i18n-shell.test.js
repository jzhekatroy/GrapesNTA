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

test('английские подписи страницы DNS-резолверы совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(
    en['dnsResolvers.subtitle'],
    'Directory for badges on the DNS queries page: operator, subscriber, and public resolvers.',
  );
  assert.equal(en['dnsResolvers.role.resolver'], 'Operator resolver');
  assert.equal(en['dnsResolvers.confirm.delete'], 'Delete resolver {prefix} permanently?');
  assert.equal(en['dnsResolvers.err.prefixRequired'], 'Enter a prefix (CIDR)');
});

test('английские подписи страницы DNS совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(
    en['dns.subtitle'],
    'Real-time overview of DNS activity, sources, domains, and servers',
  );
  assert.equal(
    en['dns.chart.hint'],
    '"All responses" includes successful responses, NXDOMAIN and SERVFAIL - the last two lines show subsets of responses.',
  );
  assert.equal(en['dns.chart.line.requests'], 'Requests');
  assert.equal(en['dns.chart.line.allAnswers'], 'All answers');
  assert.equal(en['dns.chart.line.domainNotFound'], 'Domain not found');
  assert.equal(en['dns.chart.line.dnsServerError'], 'DNS Server error');
  assert.equal(en['dns.table.querySources'], 'Query sources');
  assert.equal(en['dns.table.domains'], 'Domains');
  assert.equal(en['dns.table.dnsServers'], 'DNS servers');
  assert.equal(en['dns.table.recentEvents'], 'Recent DNS events');
  assert.equal(en['dns.hideResolvers'], 'Hide resolvers from the list');
  assert.equal(en['dns.configureList'], 'Configure list');
  assert.equal(en['dns.openInExplorer'], 'Open in DNS explorer');
  assert.equal(en['dns.chart.rateUnit'], 'req/s');
  assert.equal(en['dns.rcode.success'], 'Success');
  assert.equal(en['dns.rcode.dnsServerError'], 'DNS Server error');
  assert.equal(en['dns.rcode.domainNotFound'], 'Domain not found');
});

test('английские подписи страницы разбора DNS совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['dnsExplorer.title'], 'DNS explorer');
  assert.equal(en['dnsExplorer.metric.queries_per_sec'], 'Queries/s');
  assert.equal(en['dnsExplorer.field.query_name'], 'Domain');
  assert.equal(en['dnsExplorer.err.filterEmpty'], 'Filter is empty');
  assert.equal(en['dnsExplorer.showAnswers'], 'Show answers');
});

test('английские подписи страницы Топ ASN совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['dashboard.topAsn'], 'Top ASN');
  assert.equal(en['topAsn.export'], 'Export');
  assert.equal(en['topAsn.metric.bps'], 'Average bitrate');
  assert.equal(en['topAsn.source.error'], 'Error');
  assert.equal(en['topAsn.barTooltip'], '{label} — {metric}');
  const GrapesI18n = loadI18n();
  GrapesI18n.setLocale('en');
  assert.equal(
    GrapesI18n.t('topAsn.queryTimeMsSql', { load: 42, server: 10 }),
    '42 ms (SQL 10 ms)',
  );
});

test('английские подписи страницы разбора трафика совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['explorer.title'], 'Traffic explorer');
  assert.equal(en['explorer.shareFilters'], 'Share filters');
  assert.equal(en['explorer.apply'], 'Apply');
  assert.equal(en['explorer.others'], 'Other');
  assert.equal(en['explorer.vis.stack'], 'Stack (sum)');
  assert.equal(en['explorer.vis.data'], 'Data');
  assert.equal(en['explorer.chart.selectRange'], 'Select a range on the chart');
  assert.equal(en['explorer.col.volume'], 'Объём');
  assert.equal(en['explorer.col.avgBps'], 'Средняя скорость / Average bitrate');
  assert.equal(en['table.scrollLeft'], 'Scroll left');
});

test('английские подписи журнала аудита совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['auditPage.title'], 'Audit log');
  assert.equal(en['auditPage.apply'], 'Apply');
  assert.equal(en['auditPage.adminOnly'], 'The audit log is available to administrators only.');
  assert.equal(en['auditPage.emptyTitle'], 'No records for this period');
  assert.equal(en['auditPage.kind.login_fail'], 'Sign-in denied');
  assert.equal(en['auditPage.action.user_delete'], 'User: deleted');
  assert.equal(en['auditPage.result.denied'], 'Denied');
  assert.equal(en['auditPage.export.nothingTitle'], 'Nothing to export');
  assert.equal(en['auditPage.detail.elapsed'], 'Elapsed:');
  assert.equal(en['auditPage.changes.more'], '… {count} more');
  assert.equal(en['auditPage.unit.ms'], '{ms} ms');
  assert.equal(en['auditPage.object.dnsResolver'], 'DNS resolver');
  assert.equal(en['auditPage.object.page.entities'], 'L3 owners');
  const GrapesI18n = loadI18n();
  GrapesI18n.setLocale('en');
  assert.equal(GrapesI18n.t('auditPage.export.count', { count: 3 }), '3 records.');
  GrapesI18n.setLocale('ru');
  assert.equal(GrapesI18n.t('auditPage.export.count', { count: 3 }), '3 записей.');
});

test('подпись числа записей в таблице на английском', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['table.records.one'], '{count} record');
  assert.equal(en['table.records.many'], '{count} records');
  const GrapesI18n = loadI18n();
  GrapesI18n.setLocale('en');
  assert.equal(GrapesI18n.t('table.records.many', { count: 50 }), '50 records');
});

test('английские подписи страницы BMP / BGP совпадают с требованиями', () => {
  const en = loadLocaleMessages('en');
  assert.equal(en['period.15m'], '15 minutes');
  assert.equal(en['bmpPage.title'], 'BMP / BGP');
  assert.equal(en['bmpPage.tab.health'], 'Overview');
  assert.equal(en['bmpPage.tab.routes'], 'Routes');
  assert.equal(en['bmpPage.churn.chartTitle'], 'Announce / withdraw dynamics');
  assert.equal(en['bmpPage.churn.tipUnit'], 'events');
  const GrapesI18n = loadI18n();
  GrapesI18n.setLocale('en');
  assert.equal(
    GrapesI18n.t('bmpPage.pager.range', { from: 1, to: 25, total: '100' }),
    '1–25 of 100',
  );
  assert.equal(
    GrapesI18n.t('bmpPage.err.invalidRange', { key: '7d' }),
    'Invalid range: 7d',
  );
});
