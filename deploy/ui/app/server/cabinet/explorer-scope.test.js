const test = require('node:test');
const assert = require('node:assert/strict');

const {
  sanitizeCabinetExplorerBody,
  cabinetExplorerSchema,
} = require('./explorer');

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

test('cabinetExplorerSchema hides collector and source_id', () => {
  const schema = cabinetExplorerSchema();
  assert.equal(schema.filterFields.some((f) => f.id === 'collector'), false);
  assert.equal(schema.dimensions.some((d) => d.id === 'source_id'), false);
  assert.equal(schema.maxRangeDays, 6);
});
