'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  explorerSchema,
  explorerDimensions,
  explorerFieldMatchesQuery,
} = require('./explorer');

const HIDDEN_PICKER = new Set([
  'src_network', 'dst_network', 'src_label', 'dst_label', 'vlan_attachment',
]);

describe('explorer schema field naming', () => {
  it('uses bilingual labels for core fields', () => {
    const schema = explorerSchema();
    const srcIp = schema.filterFields.find((f) => f.id === 'src_ip');
    assert.equal(srcIp?.label, 'IP источника / Source IP');
    const switchIp = schema.filterFields.find((f) => f.id === 'switch_ip');
    assert.equal(switchIp?.label, 'Оборудование — источник потоков / Flow-exporting device');
  });

  it('exposes IPv4 mask settings only for groupable source and destination IPs', () => {
    const schema = explorerSchema();
    for (const id of ['src_ip', 'dst_ip']) {
      const field = schema.dimensions.find((d) => d.id === id);
      assert.equal(field?.maskable, true);
      assert.equal(field?.maskMin, 1);
      assert.equal(field?.maskMax, 32);
      assert.equal(field?.maskDefault, 32);
    }
    assert.equal(schema.dimensions.find((d) => d.id === 'switch_ip')?.maskable, undefined);
    assert.equal(schema.dimensions.find((d) => d.id === 'src_port')?.maskable, undefined);
  });

  it('hides duplicate fields from pickers but keeps them in dimensions registry', () => {
    const schema = explorerSchema();
    const dims = explorerDimensions();
    for (const id of HIDDEN_PICKER) {
      assert.equal(schema.dimensions.some((d) => d.id === id), false, id);
      assert.equal(schema.filterFields.some((f) => f.id === id), false, id);
      assert.ok(dims[id], `${id} must remain in internal registry`);
    }
  });

  it('keeps entity owner fields out of filters and virtual L3 in filters only', () => {
    const schema = explorerSchema();
    assert.equal(schema.filterFields.some((f) => f.id === 'src_entity'), false);
    assert.equal(schema.filterFields.some((f) => f.id === 'dst_entity'), false);
    assert.equal(schema.dimensions.some((d) => d.id === 'src_entity'), true);
    assert.equal(schema.dimensions.some((d) => d.id === 'dst_entity'), true);
    assert.equal(schema.filterFields.some((f) => f.id === 'l3_owner'), true);
    assert.equal(schema.filterFields.some((f) => f.id === 'own_network'), true);
    assert.equal(schema.dimensions.some((d) => d.id === 'l3_owner'), false);
    assert.equal(schema.dimensions.some((d) => d.id === 'own_network'), false);
  });

  it('includes vlan_name in both filter and dimension lists', () => {
    const schema = explorerSchema();
    assert.ok(schema.filterFields.some((f) => f.id === 'vlan_name'));
    assert.ok(schema.dimensions.some((d) => d.id === 'vlan_name'));
  });

  it('exposes scope value options with bilingual labels', () => {
    const schema = explorerSchema();
    const srcScope = schema.filterFields.find((f) => f.id === 'src_scope');
    assert.ok(srcScope?.valueOptions?.length >= 4);
    assert.ok(srcScope.valueOptions.some((o) => o.value === 'local' && o.label.includes('Наш')));
  });

  it('exposes source_id as a searchable value picker', () => {
    const schema = explorerSchema();
    const sourceId = schema.filterFields.find((f) => f.id === 'source_id');
    assert.equal(sourceId?.entityType, 'source_id');
  });

  it('matches side aliases in field search', () => {
    const schema = explorerSchema();
    const srcIp = schema.filterFields.find((f) => f.id === 'src_ip');
    assert.equal(explorerFieldMatchesQuery(srcIp, 'src'), true);
    assert.equal(explorerFieldMatchesQuery(srcIp, 'source'), true);
    assert.equal(explorerFieldMatchesQuery(srcIp, 'источник'), true);
    const dstIp = schema.filterFields.find((f) => f.id === 'dst_ip');
    assert.equal(explorerFieldMatchesQuery(dstIp, 'dst'), true);
    assert.equal(explorerFieldMatchesQuery(dstIp, 'destination'), true);
  });

  it('uses bilingual metric labels', () => {
    const schema = explorerSchema();
    const bps = schema.metrics.find((m) => m.id === 'bps');
    assert.equal(bps?.label, 'Средняя скорость / Average bitrate');
    const uniq = schema.metrics.find((m) => m.id === 'uniq_src');
    assert.equal(uniq?.label, 'Уникальных IP источника / Unique source IPs');
  });

  it('exposes cabinet_client in operator schema with entity picker', () => {
    const schema = explorerSchema();
    const filter = schema.filterFields.find((f) => f.id === 'cabinet_client');
    const dimension = schema.dimensions.find((d) => d.id === 'cabinet_client');
    assert.ok(filter);
    assert.equal(filter.entityType, 'cabinet_client');
    assert.ok(filter.ops.includes('='));
    assert.ok(filter.ops.includes('in'));
    assert.ok(dimension);
    assert.equal(dimension.groupable, true);
    assert.equal(schema.maxCabinetClientRangeHours, 6);
    assert.deepEqual(schema.dimensionGroups['Система / System'], ['collector', 'cabinet_client']);
  });

  it('reserves client alias for cabinet_client field', () => {
    const schema = explorerSchema();
    const cabinetClient = schema.filterFields.find((f) => f.id === 'cabinet_client');
    const l3Owner = schema.filterFields.find((f) => f.id === 'l3_owner');
    assert.equal(explorerFieldMatchesQuery(cabinetClient, 'клиент'), true);
    assert.equal((cabinetClient.aliases || []).includes('клиент'), true);
    assert.equal((l3Owner.aliases || []).includes('клиент'), false);
    assert.match(l3Owner.valueHint, /net_entities/i);
  });
});
