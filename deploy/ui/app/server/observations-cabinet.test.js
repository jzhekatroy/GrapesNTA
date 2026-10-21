'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const {
  assertCabinetPayload,
  CABINET_OBSERVATIONS_MAX,
} = require('./cabinet/observations');

const validWidgets = [
  { id: 'w-ts', type: 'timeseries_bps', metric: 'bps', groupBy: ['client_direction'] },
  { id: 'w-top', type: 'top_table', metric: 'bps', groupBy: ['client_direction'] },
];

test('cabinet payload: client_direction сохраняется', () => {
  assert.doesNotThrow(() => assertCabinetPayload({
    lookback: '1h',
    filters: [{ field: 'client_direction', op: '=', value: 'in' }],
    widgets: validWidgets,
  }));
});

test('cabinet payload: cabinet_client и in_if_alias → 400', () => {
  assert.throws(
    () => assertCabinetPayload({
      lookback: '1h',
      filters: [{ field: 'cabinet_client', op: '=', value: 'x' }],
      widgets: validWidgets,
    }),
    (err) => err.statusCode === 400,
  );
  assert.throws(
    () => assertCabinetPayload({
      lookback: '1h',
      filters: [{ field: 'in_if_alias', op: '=', value: 'x' }],
      widgets: validWidgets,
    }),
    (err) => err.statusCode === 400,
  );
});

test('cabinet payload: native widget и 7d → 400', () => {
  assert.throws(
    () => assertCabinetPayload({
      lookback: '1h',
      filters: [],
      widgets: [{ id: 'w', type: 'timeseries_bps', dataSource: 'traffic_direction' }],
    }),
    (err) => err.statusCode === 400,
  );
  assert.throws(
    () => assertCabinetPayload({
      lookback: '7d',
      filters: [],
      widgets: validWidgets,
    }),
    (err) => err.statusCode === 400,
  );
});

test('preview наблюдения кабинета передаёт cabinet_client_id в explorer', async () => {
  const { explorerTimeseries } = require('./explorer');
  const bundle = await explorerTimeseries({
    range: 'custom',
    from: '2026-10-19T07:00:00.000Z',
    to: '2026-10-19T07:15:00.000Z',
    filters: [],
    granularity: '5m',
  }, { cabinetClientId: 'client-a' });
  assert.equal(bundle.params.cabinet_client_id, 'client-a');
});

test('наблюдение клиента A недоступно клиенту B', async () => {
  const stubs = {
    './observation-clients': {
      loadObservationClients: async () => new Map([['obs-a', 'client-a']]),
    },
    './observations-store': {
      loadAllObservations: async () => [
        { id: 'obs-a', name: 'A', filters: [], widgets: validWidgets, materialize: { enabled: true } },
      ],
      loadObservationById: async (id) => (id === 'obs-a' ? { id: 'obs-a', name: 'A', filters: [], widgets: validWidgets, materialize: { enabled: true } } : null),
    },
  };
  const modPath = require.resolve('./cabinet/observations');
  const saved = {};
  for (const [rel, exports] of Object.entries(stubs)) {
    const resolved = require.resolve(rel);
    saved[resolved] = require.cache[resolved];
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  }
  delete require.cache[modPath];
  try {
    const { getCabinetObservation } = require('./cabinet/observations');
    assert.ok(await getCabinetObservation('client-a', 'obs-a'));
    assert.equal(await getCabinetObservation('client-b', 'obs-a'), null);
  } finally {
    for (const [resolved, mod] of Object.entries(saved)) {
      if (mod) require.cache[resolved] = mod;
      else delete require.cache[resolved];
    }
    delete require.cache[modPath];
  }
});

test('кабинетное наблюдение не попадает в listObservations сотрудника', async () => {
  const stubs = {
    './observation-clients': {
      loadObservationClients: async () => new Map([['obs-cab', 'client-x']]),
    },
    './observations-store': {
      loadAllObservations: async () => [
        { id: 'obs-cab', name: 'Cab', filters: [], widgets: validWidgets, materialize: { enabled: true } },
        { id: 'obs-staff', name: 'Staff', filters: [], widgets: validWidgets, materialize: { enabled: true } },
      ],
    },
    './observation-sections': {
      GENERAL_SECTION_ID: 'general',
      createObservationSectionContext: async () => ({
        access: { general: 'edit' },
        sectionMap: {},
      }),
      sectionIdForObservation: () => 'general',
      canViewInSection: () => true,
      canEditInSection: () => true,
    },
  };
  const observationsPath = require.resolve('./observations');
  const saved = {};
  for (const [rel, exports] of Object.entries(stubs)) {
    const resolved = require.resolve(rel);
    saved[resolved] = require.cache[resolved];
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  }
  delete require.cache[observationsPath];
  try {
    const { listObservations } = require(path.join(__dirname, 'observations'));
    const list = await listObservations({ id: 'u1', roleId: 'Administrator' });
    assert.deepEqual(list.map((o) => o.id), ['obs-staff']);
    assert.equal(list[0].quotas.activeMaterialize, 1);
  } finally {
    for (const [resolved, mod] of Object.entries(saved)) {
      if (mod) require.cache[resolved] = mod;
      else delete require.cache[resolved];
    }
    delete require.cache[observationsPath];
  }
});

test('шестое наблюдение → 409', async () => {
  const bindings = new Map();
  const obsRows = [];
  for (let i = 0; i < 5; i += 1) {
    const id = `obs-${i}`;
    bindings.set(id, 'client-q');
    obsRows.push({ id, name: `n${i}`, filters: [], widgets: validWidgets });
  }
  const stubs = {
    './observation-clients': {
      loadObservationClients: async () => bindings,
      upsertObservationClient: async () => {},
    },
    './observations-store': {
      loadAllObservations: async () => obsRows,
      upsertObservation: async () => {},
    },
    './users': {
      getUserById: async () => null,
    },
  };
  const modPath = require.resolve('./cabinet/observations');
  const saved = {};
  for (const [rel, exports] of Object.entries(stubs)) {
    const resolved = require.resolve(rel);
    saved[resolved] = require.cache[resolved];
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  }
  delete require.cache[modPath];
  try {
    const { createCabinetObservation } = require('./cabinet/observations');
    await assert.rejects(
      () => createCabinetObservation('client-q', { id: 'u1' }, {
        name: 'sixth',
        lookback: '1h',
        filters: [],
        widgets: validWidgets,
      }),
      (err) => err.statusCode === 409 && /предел: 5/.test(err.message),
    );
  } finally {
    for (const [resolved, mod] of Object.entries(saved)) {
      if (mod) require.cache[resolved] = mod;
      else delete require.cache[resolved];
    }
    delete require.cache[modPath];
  }
});

test('createCabinetObservation: привязка до upsert и materialize включён', async () => {
  const order = [];
  const stubs = {
    './observation-clients': {
      loadObservationClients: async () => new Map(),
      upsertObservationClient: async (obsId, clientId) => {
        order.push(['link', obsId, clientId]);
      },
    },
    './observations-store': {
      loadAllObservations: async () => [],
      loadObservationById: async (id) => ({
        id,
        name: 'n',
        filters: [],
        widgets: validWidgets,
        materialize: { enabled: true, status: 'queued' },
        ownerId: 'u1',
      }),
      upsertObservation: async (item) => {
        order.push(['upsert', item.id, item.materialize?.enabled]);
      },
    },
    './users': {
      getUserById: async () => ({ id: 'u1', roleId: 'Client', username: 'c' }),
    },
  };
  const modPath = require.resolve('./cabinet/observations');
  const saved = {};
  for (const [rel, exports] of Object.entries(stubs)) {
    const resolved = require.resolve(rel);
    saved[resolved] = require.cache[resolved];
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  }
  delete require.cache[modPath];
  try {
    const { createCabinetObservation } = require('./cabinet/observations');
    await createCabinetObservation('client-z', { id: 'u1' }, {
      name: 'n',
      lookback: '1h',
      filters: [],
      widgets: validWidgets,
    });
    assert.equal(order[0][0], 'link');
    assert.equal(order[1][0], 'upsert');
    assert.equal(order[1][2], true);
    assert.ok(order[0][1] === order[1][1]);
  } finally {
    for (const [resolved, mod] of Object.entries(saved)) {
      if (mod) require.cache[resolved] = mod;
      else delete require.cache[resolved];
    }
    delete require.cache[modPath];
  }
});

test('квота не считает привязки без живого наблюдения', async () => {
  const bindings = new Map([
    ['obs-live', 'client-q'],
    ['obs-deleted', 'client-q'],
  ]);
  const stubs = {
    './observation-clients': {
      loadObservationClients: async () => bindings,
    },
    './observations-store': {
      loadAllObservations: async () => [
        { id: 'obs-live', name: 'live', filters: [], widgets: validWidgets },
      ],
    },
    './users': { getUserById: async () => null },
  };
  const modPath = require.resolve('./cabinet/observations');
  const saved = {};
  for (const [rel, exports] of Object.entries(stubs)) {
    const resolved = require.resolve(rel);
    saved[resolved] = require.cache[resolved];
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  }
  delete require.cache[modPath];
  try {
    const { listCabinetObservations, countCabinetObservations } = require('./cabinet/observations');
    const list = await listCabinetObservations('client-q');
    assert.equal(list.length, 1);
    assert.equal(list[0].quotas.usedObservations, 1);
    assert.equal(await countCabinetObservations('client-q'), 1);
  } finally {
    for (const [resolved, mod] of Object.entries(saved)) {
      if (mod) require.cache[resolved] = mod;
      else delete require.cache[resolved];
    }
    delete require.cache[modPath];
  }
});

test('duplicateCabinetObservation сохраняет id привязки', async () => {
  const bindings = new Map([['obs-src', 'client-q']]);
  let upsertedId = null;
  const stubs = {
    './observation-clients': {
      loadObservationClients: async () => bindings,
      upsertObservationClient: async (obsId) => {
        bindings.set(obsId, 'client-q');
      },
    },
    './observations-store': {
      loadAllObservations: async () => [{
        id: 'obs-src',
        name: 'Src',
        filters: [],
        widgets: validWidgets,
        materialize: { enabled: true },
        ownerId: 'u1',
      }],
      loadObservationById: async (id) => ({
        id,
        name: id === 'obs-src' ? 'Src' : 'Src (копия)',
        filters: [],
        widgets: validWidgets,
        materialize: { enabled: true },
        ownerId: 'u1',
      }),
      upsertObservation: async (item) => {
        upsertedId = item.id;
      },
    },
    './users': { getUserById: async () => ({ id: 'u1', roleId: 'Client' }) },
  };
  const modPath = require.resolve('./cabinet/observations');
  const saved = {};
  for (const [rel, exports] of Object.entries(stubs)) {
    const resolved = require.resolve(rel);
    saved[resolved] = require.cache[resolved];
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  }
  delete require.cache[modPath];
  try {
    const { duplicateCabinetObservation } = require('./cabinet/observations');
    const copy = await duplicateCabinetObservation('client-q', { id: 'u1' }, 'obs-src', {});
    assert.ok(copy);
    assert.notEqual(copy.id, 'obs-src');
    assert.equal(upsertedId, copy.id);
    assert.equal(bindings.get(copy.id), 'client-q');
  } finally {
    for (const [resolved, mod] of Object.entries(saved)) {
      if (mod) require.cache[resolved] = mod;
      else delete require.cache[resolved];
    }
    delete require.cache[modPath];
  }
});

test('CABINET_OBSERVATIONS_MAX default', () => {
  assert.equal(CABINET_OBSERVATIONS_MAX, 5);
});
