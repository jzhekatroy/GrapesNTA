'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { observationClientsFromRows } = require('./observation-clients');
const { explorerOptionsForJob, assertKnownGroupBy } = require('./observations-rollup');
const { explorerGroupedTimeseries, explorerTimeseries } = require('./explorer');

const WINDOW = {
  range: 'custom',
  from: '2026-10-19T07:00:00.000Z',
  to: '2026-10-19T07:15:00.000Z',
  granularity: '5m',
};

test('привязки: удалённые и пустые строки не считаются', () => {
  const map = observationClientsFromRows([
    { observation_id: 'obs-1', client_id: '116691', deleted: 0 },
    { observation_id: 'obs-2', client_id: '116691', deleted: 1 },
    { observation_id: 'obs-3', client_id: '', deleted: 0 },
    { observation_id: '', client_id: '116691', deleted: 0 },
  ]);
  assert.deepEqual([...map.entries()], [['obs-1', '116691']]);
});

test('обычное наблюдение считается без кабинета', () => {
  assert.deepEqual(explorerOptionsForJob({ id: 'obs-1', cabinetClientId: null }), {});
  assert.deepEqual(explorerOptionsForJob({ id: 'obs-1' }), {});
});

test('«К вам / От вас» есть только у наблюдения кабинета', () => {
  assert.throws(() => assertKnownGroupBy(['in_if_alias'], { cabinetClientId: '116691' }), /Неизвестное измерение/);
  assert.doesNotThrow(() => assertKnownGroupBy(['client_direction'], { cabinetClientId: '116691' }));
  assert.doesNotThrow(() => assertKnownGroupBy(['in_if_alias'], {}));
});

test('разрез по направлению считается относительно клиента наблюдения', async () => {
  const bundle = await explorerGroupedTimeseries({
    ...WINDOW,
    metric: 'bps',
    groupBy: ['client_direction'],
    filters: [{ field: 'proto', op: '=', value: 'UDP' }],
    limit: 20,
  }, explorerOptionsForJob({ cabinetClientId: '116691' }));

  assert.equal(bundle.params.cabinet_client_id, '116691');
  assert.match(bundle.sql, /f\.src_client = \{cabinet_client_id:String\} OR f\.dst_client = \{cabinet_client_id:String\}/);
  assert.match(bundle.sql, /f\.dst_client = \{cabinet_client_id:String\}, 'in'/);
  assert.equal(bundle.meta.groupBy[0].id, 'client_direction');
});

test('итоговый ряд наблюдения кабинета ограничен трафиком клиента', async () => {
  const bundle = await explorerTimeseries({ ...WINDOW, filters: [] }, explorerOptionsForJob({ cabinetClientId: '116691' }));
  assert.equal(bundle.params.cabinet_client_id, '116691');
  assert.match(bundle.sql, /f\.src_client = \{cabinet_client_id:String\} OR f\.dst_client = \{cabinet_client_id:String\}/);
});

test('без клиента разрез и итог не ограничены кабинетом', async () => {
  const grouped = await explorerGroupedTimeseries({ ...WINDOW, groupBy: ['proto'], limit: 20 });
  const total = await explorerTimeseries({ ...WINDOW, filters: [] });
  assert.equal(grouped.params.cabinet_client_id, undefined);
  assert.equal(total.params.cabinet_client_id, undefined);
});

test('задания: наблюдение кабинета без фильтров готовится, обычное — нет', async () => {
  const stubs = {
    './observations-store': {
      ensureObservationsStore: async () => {},
      loadAllObservations: async () => [
        { id: 'obs-client', filters: [], widgets: [{ type: 'timeseries_bps' }], materialize: { enabled: true } },
        { id: 'obs-plain', filters: [], widgets: [{ type: 'timeseries_bps' }], materialize: { enabled: true } },
        {
          id: 'obs-udp',
          filters: [{ field: 'proto', op: '=', value: 'UDP' }],
          widgets: [{ type: 'timeseries_bps' }],
          materialize: { enabled: true },
        },
      ],
    },
    './observation-clients': {
      loadObservationClients: async () => new Map([['obs-client', '116691']]),
    },
  };
  const observationsPath = require.resolve('./observations');
  const saved = {};
  for (const [rel, exports] of Object.entries(stubs)) {
    const resolved = require.resolve(rel);
    saved[resolved] = require.cache[resolved];
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  }
  const savedObservations = require.cache[observationsPath];
  delete require.cache[observationsPath];
  try {
    const { listMaterializeJobs } = require(path.join(__dirname, 'observations'));
    const jobs = await listMaterializeJobs();
    const byId = Object.fromEntries(jobs.map((j) => [j.id, j]));
    assert.deepEqual(Object.keys(byId).sort(), ['obs-client', 'obs-udp']);
    assert.equal(byId['obs-client'].cabinetClientId, '116691');
    assert.equal(byId['obs-udp'].cabinetClientId, null);
  } finally {
    for (const [resolved, entry] of Object.entries(saved)) {
      if (entry) require.cache[resolved] = entry;
      else delete require.cache[resolved];
    }
    if (savedObservations) require.cache[observationsPath] = savedObservations;
    else delete require.cache[observationsPath];
  }
});
