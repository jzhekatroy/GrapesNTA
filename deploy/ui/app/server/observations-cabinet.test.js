'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  filterObservationsByRealm,
  observationInRealm,
  normalizeObservation,
  assertCabinetObservationAcceptable,
  observationExplorerOptions,
} = require('./observations');
const { explorerTimeseries } = require('./explorer');
const { layoutStorageKey } = require('./observations-board-layout');
const { isReadOnlyCabinetPost } = require('./cabinet/guard');

describe('observations cabinet realm', () => {
  it('filters staff vs client observations', () => {
    const items = [
      { id: 'a', clientId: '' },
      { id: 'b', clientId: 'client:one' },
      { id: 'c', clientId: 'client:two' },
    ];
    assert.deepEqual(
      filterObservationsByRealm(items, { clientId: '' }).map((x) => x.id),
      ['a'],
    );
    assert.deepEqual(
      filterObservationsByRealm(items, { clientId: 'client:one' }).map((x) => x.id),
      ['b'],
    );
    assert.equal(observationInRealm(items[1], 'client:one'), true);
    assert.equal(observationInRealm(items[1], 'client:two'), false);
  });

  it('sets clientId only from server options on create', () => {
    const item = normalizeObservation({ name: 'Test' }, { userId: 'u1', clientId: 'client:x' });
    assert.equal(item.clientId, 'client:x');
    const updated = normalizeObservation(
      { name: 'Renamed' },
      { userId: 'u2', clientId: 'client:evil', existing: item },
    );
    assert.equal(updated.clientId, 'client:x');
  });

  it('rejects dashboard native widgets for cabinet', () => {
    assert.throws(
      () => assertCabinetObservationAcceptable('client:a', {
        filters: [],
        widgets: [{ type: 'timeseries_bps', dataSource: 'traffic_direction' }],
      }),
      (err) => err.status === 400,
    );
  });

  it('rejects non-cabinet filter fields for cabinet', () => {
    assert.throws(
      () => assertCabinetObservationAcceptable('client:a', {
        filters: [{ field: 'vlan', op: '=', value: '10' }],
        widgets: [{ type: 'timeseries_bps', groupBy: ['src_asn'] }],
      }),
    );
  });

  it('accepts cabinet explorer fields', () => {
    assert.doesNotThrow(() => assertCabinetObservationAcceptable('client:a', {
      filters: [{ field: 'client_direction', op: '=', value: 'in' }],
      widgets: [
        { type: 'timeseries_bps', groupBy: ['src_asn'] },
        { type: 'top_table', groupBy: ['src_asn'] },
      ],
    }));
  });
});

describe('observations cabinet query scope', () => {
  it('injects client predicate into explorer timeseries SQL', async () => {
    const opts = observationExplorerOptions({ clientId: 'client:acme' });
    const bundle = await explorerTimeseries({
      range: 'custom',
      from: '2026-01-01T00:00:00.000Z',
      to: '2026-01-01T01:00:00.000Z',
      filters: [],
      granularity: '5m',
    }, opts);
    assert.match(bundle.sql, /src_client\s*=\s*\{cabinet_client_id:String\}/);
    assert.equal(bundle.params.cabinet_client_id, 'client:acme');
  });
});

describe('observations cabinet board layout', () => {
  it('uses separate storage keys for cabinet sessions', () => {
    assert.equal(layoutStorageKey('user-1'), 'user-1');
    assert.equal(layoutStorageKey('user-1', 'client:a'), 'cabinet:client:a:u:user-1');
  });
});

describe('cabinet guard observations', () => {
  it('allows cabinet observation preview POST in read-only impersonation', () => {
    assert.equal(
      isReadOnlyCabinetPost('/api/cabinet/observations/obs-1/preview'),
      true,
    );
    assert.equal(isReadOnlyCabinetPost('/api/cabinet/observations'), false);
    assert.equal(isReadOnlyCabinetPost('/api/observations/obs-1/preview'), false);
  });
});
