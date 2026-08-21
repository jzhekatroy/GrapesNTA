const test = require('node:test');
const assert = require('node:assert/strict');

const {
  sanitizeCabinetExplorerBody,
  cabinetExplorerSchema,
  cabinetExplorerQuery,
  cabinetExplorerFlows,
  cabinetExplorerExportCsv,
} = require('./explorer');
const { explorerSchema } = require('../explorer');

const CABINET_FIELDS = new Set([
  'src_ip', 'dst_ip', 'src_port', 'dst_port',
  'proto', 'src_service', 'dst_service', 'tcp_flags',
  'src_asn', 'dst_asn', 'src_country', 'dst_country',
  'client_direction',
]);

test('sanitizeCabinetExplorerBody removes client and collector fields', () => {
  const body = sanitizeCabinetExplorerBody({
    clientId: 'client:other',
    collectorId: 'c1',
    metric: 'volume',
    filters: [{ field: 'collector', op: 'in', value: 'x' }, { field: 'src_ip', op: '=', value: '1.1.1.1' }],
  });
  assert.equal(body.clientId, undefined);
  assert.equal(body.collectorId, undefined);
  assert.equal(body.metric, 'volume');
});

test('cabinetExplorerSchema exposes only client-safe fields', () => {
  const schema = cabinetExplorerSchema();
  assert.ok(schema.dimensions.length > 0);
  assert.ok(schema.filterFields.length > 0);
  assert.equal(schema.dimensions.every((field) => CABINET_FIELDS.has(field.id)), true);
  assert.equal(schema.filterFields.every((field) => CABINET_FIELDS.has(field.id)), true);
  assert.equal(
    Object.values(schema.dimensionGroups).flat().every((id) => CABINET_FIELDS.has(id)),
    true,
  );
  assert.equal(schema.maxRangeDays, 6);
});

test('cabinetExplorerSchema describes computed client direction labels', () => {
  const schema = cabinetExplorerSchema();
  const dimension = schema.dimensions.find((field) => field.id === 'client_direction');
  const filter = schema.filterFields.find((field) => field.id === 'client_direction');

  assert.ok(dimension);
  assert.deepEqual(filter.valueOptions, [
    { value: 'in', label: 'К вам' },
    { value: 'out', label: 'От вас' },
    { value: 'internal', label: 'Внутри вашей сети' },
  ]);
  assert.deepEqual(dimension.valueOptions, filter.valueOptions);
  assert.equal(schema.dimensions.some((field) => field.id === 'direction'), false);
  assert.equal(schema.filterFields.some((field) => field.id === 'direction'), false);
});

test('cabinet client_direction supports grouping and filtering', async () => {
  const body = {
    groupBy: ['client_direction'],
    filters: [{ field: 'client_direction', op: '=', value: 'internal' }],
    range: 'custom',
    from: '2026-08-18 10:00:00',
    to: '2026-08-18 11:00:00',
    includeSummary: false,
    includeTimeseries: false,
  };
  const spec = await cabinetExplorerFlows('client:mine', body);
  const bundle = await cabinetExplorerQuery('client:mine', body);

  assert.match(spec.sql, /f\.src_client = \{cabinet_client_id:String\}/);
  assert.match(spec.sql, /f\.dst_client = \{cabinet_client_id:String\}/);
  assert.match(spec.sql, /К вам/);
  assert.match(spec.sql, /От вас/);
  assert.match(spec.sql, /Внутри вашей сети/);
  assert.equal(spec.params.cabinet_client_id, 'client:mine');
  assert.equal(spec.meta.groupBy[0].id, 'client_direction');
  assert.ok(bundle.flowsSpec);
  assert.equal(bundle.flowsSpec.meta.groupBy[0].id, 'client_direction');
});

test('cabinet query, flows and export reject fields outside the allowlist', async () => {
  const invalidGroup = { groupBy: ['direction'], includeSummary: false, includeTimeseries: false };
  const invalidFilter = {
    groupBy: ['src_ip'],
    filters: [{ field: 'source_id', op: '=', value: 'hidden' }],
    includeSummary: false,
    includeTimeseries: false,
  };
  const operations = [
    cabinetExplorerQuery,
    cabinetExplorerFlows,
    cabinetExplorerExportCsv,
  ];

  for (const operation of operations) {
    await assert.rejects(operation('client:mine', invalidGroup), (error) => (
      error.statusCode === 400 && /Недоступная группировка: direction/.test(error.message)
    ));
    await assert.rejects(operation('client:mine', invalidFilter), (error) => (
      error.statusCode === 400 && /Недоступное поле фильтра: source_id/.test(error.message)
    ));
  }
});

test('operator schema publishes its own range limit so the UI can follow it', () => {
  const schema = explorerSchema();
  assert.equal(schema.maxRangeDays, 365);
  assert.ok(schema.maxRangeDays > cabinetExplorerSchema().maxRangeDays);
});

test('cabinet explorer schema excludes cabinet_client field', () => {
  const schema = cabinetExplorerSchema();
  assert.equal(schema.filterFields.some((f) => f.id === 'cabinet_client'), false);
  assert.equal(schema.dimensions.some((d) => d.id === 'cabinet_client'), false);
});
