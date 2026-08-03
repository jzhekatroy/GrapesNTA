const test = require('node:test');
const assert = require('node:assert/strict');
const { getResourceForPath } = require('./rbac/api-map');
const {
  listFlowExclusions,
  validateFlowExclusionPayload,
  hasRuleCondition,
} = require('./flow-exclusions');

test('api-map maps flow-exclusions refs endpoints', () => {
  assert.equal(getResourceForPath('/api/refs/flow-exclusions'), 'flow-exclusions');
  assert.equal(getResourceForPath('/api/refs/flow-exclusions/toggle', 'POST'), 'flow-exclusions');
});

test('listFlowExclusions sql uses latest row per rule_id', () => {
  const spec = listFlowExclusions();
  assert.match(spec.sql, /row_number\(\)/);
  assert.match(spec.sql, /PARTITION BY rule_id/);
  assert.match(spec.sql, /WHERE rn = 1/);
});

test('validateFlowExclusionPayload rejects empty rule', async () => {
  const result = await validateFlowExclusionPayload({});
  assert.equal(result.ok, false);
  assert.match(result.error, /Правило без условий/);
});

test('validateFlowExclusionPayload accepts prefix rule', async () => {
  const result = await validateFlowExclusionPayload({
    prefix: '10.10.0.0/16',
    matchSide: 'any',
  });
  assert.equal(result.ok, true);
  assert.equal(result.record.prefix, '10.10.0.0/16');
  assert.equal(result.record.family, 4);
});

test('validateFlowExclusionPayload rejects invalid CIDR', async () => {
  const result = await validateFlowExclusionPayload({ prefix: 'not-a-cidr' });
  assert.equal(result.ok, false);
  assert.match(result.error, /CIDR/);
});

test('validateFlowExclusionPayload rejects family mismatch', async () => {
  const result = await validateFlowExclusionPayload({
    prefix: '10.0.0.0/8',
    family: 6,
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /Версия IP/);
});

test('validateFlowExclusionPayload rejects if_index without switch_ip', async () => {
  const result = await validateFlowExclusionPayload({
    ifIndex: 42,
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /IP коммутатора/);
});

test('validateFlowExclusionPayload rejects port range inversion', async () => {
  const result = await validateFlowExclusionPayload({
    portFrom: 100,
    portTo: 10,
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /диапазона больше конца/);
});

test('validateFlowExclusionPayload rejects invalid switch_ip', async () => {
  const result = await validateFlowExclusionPayload({
    switchIp: 'not-an-ip',
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /IP коммутатора/);
});

test('validateFlowExclusionPayload accepts source_id only rule', async () => {
  const result = await validateFlowExclusionPayload({
    sourceId: 'collector-1',
  });
  assert.equal(result.ok, true);
  assert.equal(result.record.source_id, 'collector-1');
});

test('validateFlowExclusionPayload requires ruleId on update', async () => {
  const result = await validateFlowExclusionPayload(
    { prefix: '10.0.0.0/8' },
    { isUpdate: true },
  );
  assert.equal(result.ok, false);
  assert.match(result.error, /идентификатор правила/);
});

test('hasRuleCondition detects individual fields', () => {
  assert.equal(hasRuleCondition({ prefix: '10.0.0.0/8', family: 4, match_side: 'any', proto: 0, port_from: 0, port_to: 0, port_side: 'any', vlan_id: 0, switch_ip: '', if_index: 0, source_id: '' }), true);
  assert.equal(hasRuleCondition({ prefix: '', family: 0, match_side: 'any', proto: 17, port_from: 0, port_to: 0, port_side: 'any', vlan_id: 0, switch_ip: '', if_index: 0, source_id: '' }), true);
  assert.equal(hasRuleCondition({ prefix: '', family: 0, match_side: 'any', proto: 0, port_from: 53, port_to: 53, port_side: 'dst', vlan_id: 0, switch_ip: '', if_index: 0, source_id: '' }), true);
  assert.equal(hasRuleCondition({ prefix: '', family: 0, match_side: 'any', proto: 0, port_from: 0, port_to: 0, port_side: 'any', vlan_id: 0, switch_ip: '', if_index: 0, source_id: '' }), false);
});
