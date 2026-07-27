const test = require('node:test');
const assert = require('node:assert/strict');
const { getResourceForPath } = require('./rbac/api-map');
const { parseLookbackHours, DEFAULT_LOOKBACK_HOURS, MAX_LOOKBACK_HOURS } = require('./direction-audit');

test('api-map maps interface-roles refs endpoints', () => {
  assert.equal(getResourceForPath('/api/refs/direction-settings'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-role-rules'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-role-rules/preview', 'POST'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-roles/summary'), 'interface-roles');
  assert.equal(getResourceForPath('/api/refs/interface-roles/172.18.1.1'), 'interface-roles');
});

test('api-map maps direction diagnostics before generic diagnostics', () => {
  assert.equal(getResourceForPath('/api/diagnostics/direction/coverage'), 'interface-roles');
  assert.equal(getResourceForPath('/api/diagnostics/direction/compare'), 'interface-roles');
  assert.equal(getResourceForPath('/api/diagnostics/direction/interfaces'), 'interface-roles');
  assert.equal(getResourceForPath('/api/diagnostics/enrichment'), 'diagnostics');
});

test('parseLookbackHours clamps invalid values', () => {
  assert.equal(parseLookbackHours(undefined), DEFAULT_LOOKBACK_HOURS);
  assert.equal(parseLookbackHours('abc'), DEFAULT_LOOKBACK_HOURS);
  assert.equal(parseLookbackHours(-3), DEFAULT_LOOKBACK_HOURS);
  assert.equal(parseLookbackHours(3), 3);
  assert.equal(parseLookbackHours(999), MAX_LOOKBACK_HOURS);
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
