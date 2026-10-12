const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { rollupVlanDisplayLabel } = require('./observations');

describe('rollupVlanDisplayLabel', () => {
  it('подставляет display_name для обычного VLAN', () => {
    const nameMap = new Map([[105, { displayName: 'Office' }]]);
    assert.equal(rollupVlanDisplayLabel(105, nameMap), 'VLAN 105 · Office');
  });

  it('без имени в справочнике — только номер', () => {
    const nameMap = new Map();
    assert.equal(rollupVlanDisplayLabel(444, nameMap), 'VLAN 444');
  });

  it('VLAN 0 — untagged, не «VLAN —»', () => {
    assert.equal(rollupVlanDisplayLabel(0, new Map()), 'VLAN 0');
    const nameMap = new Map([[0, { displayName: 'Native' }]]);
    assert.equal(rollupVlanDisplayLabel(0, nameMap), 'VLAN 0 · Native');
  });
});
