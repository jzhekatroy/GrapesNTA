const test = require('node:test');
const assert = require('node:assert/strict');
const { getResourceForPath } = require('./rbac/api-map');
const { parseLookbackHours, DEFAULT_LOOKBACK_HOURS, MAX_LOOKBACK_HOURS } = require('./direction-audit');
const {
  portDirectionSql,
  listInterfaceRoleSwitches,
  saveInterfaceRole,
  mapSettingsRow,
  normalizeUnknownNetworks,
  UNKNOWN_NETWORKS,
} = require('./net-interface-roles');
const { ALLOWED_ROLES, validateL3PrefixPayload } = require('./l3-prefixes');
const { CHART_LINE_META } = require('./queries');

test('api-map maps direction-settings to traffic-classification', () => {
  assert.equal(getResourceForPath('/api/refs/direction-settings'), 'traffic-classification');
});

test('api-map maps interface-roles refs endpoints', () => {
  assert.equal(getResourceForPath('/api/refs/interface-role-rules'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-role-rules/preview', 'POST'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-roles/summary'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-roles/switches'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-roles/172.18.1.1'), 'interface-roles');
});

test('api-map normalizes paths stripped by /api mount', () => {
  assert.equal(getResourceForPath('/dashboard/traffic-stats'), 'dashboard');
  assert.equal(getResourceForPath('/clients/foo/impersonate', 'POST'), 'clients');
  assert.equal(getResourceForPath('/users'), 'users');
});

test('api-map maps direction diagnostics before generic diagnostics', () => {
  assert.equal(getResourceForPath('/api/diagnostics/direction/coverage'), 'traffic-classification');
  assert.equal(getResourceForPath('/api/diagnostics/direction/compare'), 'traffic-classification');
  assert.equal(getResourceForPath('/api/diagnostics/direction/interfaces'), 'traffic-classification');
  assert.equal(getResourceForPath('/api/diagnostics/enrichment'), 'diagnostics');
  assert.equal(getResourceForPath('/api/erp-piterix/status'), 'diagnostics');
  assert.equal(getResourceForPath('/api/erp-piterix/run', 'POST'), 'diagnostics');
  assert.equal(getResourceForPath('/api/detection/latest'), 'diagnostics');
});

test('parseLookbackHours clamps invalid values', () => {
  assert.equal(parseLookbackHours(undefined), DEFAULT_LOOKBACK_HOURS);
  assert.equal(parseLookbackHours('abc'), DEFAULT_LOOKBACK_HOURS);
  assert.equal(parseLookbackHours(-3), DEFAULT_LOOKBACK_HOURS);
  assert.equal(parseLookbackHours(3), 3);
  assert.equal(parseLookbackHours(999), MAX_LOOKBACK_HOURS);
});

test('portDirectionSql uses strict pair branches only', () => {
  const sql = portDirectionSql('in_b', 'out_b');
  assert.match(sql, /in_b = 'external' AND out_b = 'internal', 'in'/);
  assert.match(sql, /in_b = 'internal' AND out_b = 'external', 'out'/);
  assert.match(sql, /'unknown'\)$/);
  assert.doesNotMatch(sql, /infer/i);
});

test('listInterfaceRoleSwitches map returns camelCase rows', async () => {
  const spec = listInterfaceRoleSwitches();
  assert.match(spec.sql, /net_interfaces_current/);
  assert.match(spec.sql, /ORDER BY unmarked DESC/);
  const mapped = await spec.map([{
    switch_ip: '10.0.0.1',
    display_name: 'core-sw1',
    ports: 48,
    ports_with_alias: 12,
    marked: 10,
    unmarked: 38,
  }]);
  assert.deepEqual(mapped[0], {
    switchIp: '10.0.0.1',
    displayName: 'core-sw1',
    ports: 48,
    portsWithAlias: 12,
    marked: 10,
    unmarked: 38,
  });
});

test('saveInterfaceRole rejects missing boundary', async () => {
  await assert.rejects(
    () => saveInterfaceRole({ switchIp: '10.0.0.1', ifIndex: 1, boundary: 'unknown' }),
    (err) => err.message === 'Укажите сторону сети',
  );
});

test('resolvePageId redirects collector-status and unknown pages', () => {
  function resolvePageId(pageId, validIdSet) {
    if (pageId === 'collector-status') return 'collectors';
    return validIdSet.has(pageId) ? pageId : 'dashboard';
  }
  const ids = new Set(['dashboard', 'collectors', 'interface-roles']);
  assert.equal(resolvePageId('collector-status', ids), 'collectors');
  assert.equal(resolvePageId('interface-roles', ids), 'interface-roles');
  assert.equal(resolvePageId('missing-page', ids), 'dashboard');
});

test('hidden pages stay valid but excluded from visible nav', () => {
  const pages = [
    { id: 'dashboard', hidden: false },
    { id: 'routers', hidden: true },
    { id: 'interface-roles', hidden: false },
  ];
  const visible = pages.filter((p) => !p.hidden);
  const hidden = new Set(pages.filter((p) => p.hidden).map((p) => p.id));
  const valid = new Set(pages.map((p) => p.id));
  assert.equal(visible.length, 2);
  assert.ok(hidden.has('routers'));
  assert.ok(valid.has('routers'));
});

test('listInterfacesByTraffic map returns rows and stats shape', async () => {
  const { listInterfacesByTraffic } = require('./direction-audit');
  const spec = listInterfacesByTraffic({ hours: 1, limit: 10, onlyUnmarked: true, switchIp: '10.0.0.1' });
  assert.match(spec.sql, /stats_total_bytes/);
  assert.match(spec.sql, /switch_ip = \{switch_ip:String\}/);
  const mapped = await spec.map([]);
  assert.deepEqual(mapped, {
    rows: [],
    stats: {
      totalBytes: 0,
      classifiedBytes: 0,
      unmarkedPortsWithTraffic: 0,
      classifiedPercent: 0,
    },
  });
  const mappedRows = await spec.map([{
    switch_ip: '10.0.0.1',
    if_index: 10,
    ingress_bytes: 100,
    egress_bytes: 50,
    bytes: 150,
    flows: 3,
    ingress_asn_count: 2,
    boundary: 'unknown',
    boundary_source: 'default',
    connectivity: '',
    if_name: 'Gi0/1',
    if_alias: '',
    if_descr: 'uplink',
    speed_mbps: 1000,
    in_catalog: 1,
    suggested_boundary: 'external',
    stats_total_bytes: 150,
    stats_classified_bytes: 0,
    stats_unmarked_ports: 1,
  }]);
  assert.equal(mappedRows.rows.length, 1);
  assert.equal(mappedRows.stats.unmarkedPortsWithTraffic, 1);
  assert.equal(mappedRows.rows[0].switchIp, '10.0.0.1');
});

test('normalizeVlanDirections keeps unknown like protocol charts', () => {
  const { normalizeVlanDirections } = require('./queries');
  assert.deepEqual(
    normalizeVlanDirections(['in', 'out', 'transit', 'internal', 'unknown']),
    ['in', 'out', 'transit', 'internal', 'unknown'],
  );
  assert.ok(normalizeVlanDirections(undefined).includes('unknown'));
});

test('mapSettingsRow defaults unknownNetworks to foreign', () => {
  assert.equal(mapSettingsRow({ direction_mode: 'prefixes' }).unknownNetworks, 'foreign');
  assert.equal(
    mapSettingsRow({ direction_mode: 'prefixes', unknown_networks: 'unclassified' }).unknownNetworks,
    'unclassified',
  );
});

test('normalizeUnknownNetworks rejects invalid values', () => {
  assert.equal(normalizeUnknownNetworks('foreign'), 'foreign');
  assert.equal(normalizeUnknownNetworks('unclassified'), 'unclassified');
  assert.equal(normalizeUnknownNetworks('invalid'), 'foreign');
  assert.deepEqual(UNKNOWN_NETWORKS, ['foreign', 'unclassified']);
});

test('l3 prefixes allow remote role', () => {
  assert.ok(ALLOWED_ROLES.has('remote'));
});

test('validateL3PrefixPayload rejects unknown l3 role', async () => {
  const result = await validateL3PrefixPayload({
    prefix: '203.0.113.0/24',
    family: 4,
    role: 'not-a-role',
    entityId: 'entity-1',
    enabled: 1,
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /роль/i);
});

test('chart line meta uses Неразмеченный label', () => {
  const line = CHART_LINE_META.find((entry) => entry.id === 'unclassified');
  assert.equal(line.label, 'Неразмеченный');
  assert.equal(line.sql, 'unknown');
});

test('api-map maps l3-prefixes refs to cidr', () => {
  assert.equal(getResourceForPath('/api/refs/l3-prefixes'), 'cidr');
});
