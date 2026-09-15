'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  classifyScope,
  normalizeWidgets,
  widgetDataSource,
  isNativeAggregateWidget,
  observationUsesNativeAggregate,
  normalizePreviewCollectorFilter,
  normalizeNativeScope,
  nativeScopeCollectorId,
  resolveNativeCollectorId,
  windowToNativeTrafficQuery,
  observationsConfig,
} = require('./observations');

describe('observations native dashboard widgets', () => {
  it('сохраняет dataSource в normalizeWidgets', () => {
    const widgets = normalizeWidgets([
      { type: 'timeseries_bps', dataSource: 'traffic_direction', groupBy: [] },
    ]);
    assert.equal(widgets[0].dataSource, 'traffic_direction');
    assert.equal(widgetDataSource(widgets[0]), 'traffic_direction');
  });

  it('неизвестный dataSource откатывается к explorer', () => {
    assert.equal(widgetDataSource({ dataSource: 'unknown' }), 'explorer');
  });

  it('классифицирует direction/vlan шаблоны как native без materialize', () => {
    for (const ds of ['traffic_direction', 'vlan_trend']) {
      const widgets = [{ type: 'timeseries_bps', dataSource: ds, groupBy: ['src_asn'] }];
      const scope = classifyScope([], widgets);
      assert.equal(scope.tier, 'native');
      assert.equal(scope.materializeRequired, false);
      assert.equal(scope.dataSource, ds);
      assert.ok(observationUsesNativeAggregate(widgets));
      assert.ok(isNativeAggregateWidget(widgets[0]));
    }
  });

  it('explorer-путь по-прежнему требует materialize при groupBy', () => {
    const scope = classifyScope([], [
      { type: 'timeseries_bps', dataSource: 'explorer', groupBy: ['src_asn'] },
    ]);
    assert.equal(scope.materializeRequired, true);
  });

  it('нормализует collectorFilter для preview (массив и loc: scope)', () => {
    assert.equal(
      normalizePreviewCollectorFilter({ collectorFilter: ['col-a', 'loc:1'] }),
      'col-a,loc:1',
    );
    assert.equal(normalizePreviewCollectorFilter({ collectorId: 'col-b' }), 'col-b');
    assert.equal(normalizePreviewCollectorFilter({ collectorFilter: [] }), null);
  });

  it('windowToNativeTrafficQuery передаёт custom окно', () => {
    const q = windowToNativeTrafficQuery({
      range: 'custom',
      from: '2026-01-01T00:00:00.000Z',
      to: '2026-01-01T01:00:00.000Z',
    });
    assert.equal(q.range, 'custom');
    assert.equal(q.from, '2026-01-01T00:00:00.000Z');
  });

  it('сохраняет nativeScope коллектора и VLAN в widgets', () => {
    const widgets = normalizeWidgets([
      {
        type: 'timeseries_bps',
        dataSource: 'vlan_trend',
        nativeScope: {
          collectorFilter: ['col-a', 'loc:1'],
          vlanIds: ['100', 200, 'bad'],
        },
      },
    ]);
    assert.deepEqual(widgets[0].nativeScope, {
      collectorFilter: ['col-a', 'loc:1'],
      vlanIds: [100, 200],
    });
    assert.equal(nativeScopeCollectorId(widgets[0].nativeScope), 'col-a,loc:1');
    assert.equal(
      resolveNativeCollectorId(widgets[0], {}),
      'col-a,loc:1',
    );
    assert.deepEqual(
      normalizeNativeScope({ collectorFilter: ['x'] }, 'traffic_direction').collectorFilter,
      ['x'],
    );
  });

  it('presets содержат два нативных шаблона', () => {
    const presets = observationsConfig().presets;
    const ids = presets.map((p) => p.id);
    assert.ok(ids.includes('preset-uplink-direction'));
    assert.ok(ids.includes('preset-vlan-trend'));
    const dir = presets.find((p) => p.id === 'preset-uplink-direction');
    assert.equal(dir.widgets[0].dataSource, 'traffic_direction');
    assert.deepEqual(dir.filters, []);
    const vlan = presets.find((p) => p.id === 'preset-vlan-trend');
    assert.equal(vlan.widgets[0].dataSource, 'vlan_trend');
    assert.equal(classifyScope(dir.filters, dir.widgets).materializeRequired, false);
  });
});
