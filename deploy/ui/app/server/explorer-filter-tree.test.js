'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const T = require('../public/data/explorer-filter-tree.js');

describe('explorer filter tree', () => {
  it('keeps legacy flat filters', () => {
    const filters = [{ id: 'a', field: 'src_ip', op: '=', value: '1.1.1.1', logic: 'and' }];
    const normalized = T.normalizeExplorerFilterTree(filters);
    assert.equal(normalized.length, 1);
    assert.equal(normalized[0].field, 'src_ip');
  });

  it('moves nodes between siblings', () => {
    const filters = [
      { id: 'a', field: 'src_ip', op: '=', value: '1.1.1.1', logic: 'and' },
      { id: 'b', field: 'dst_ip', op: '=', value: '2.2.2.2', logic: 'and' },
      { id: 'c', field: 'proto', op: '=', value: 'UDP', logic: 'and' },
    ];
    const next = T.moveExplorerFilterNode(filters, 'c', null, 0);
    assert.deepEqual(next.map((f) => f.id), ['c', 'a', 'b']);
  });

  it('wraps filters in a group', () => {
    const filters = [
      { id: 'a', field: 'src_ip', op: '=', value: '1.1.1.1', logic: 'and' },
    ];
    const grouped = T.addExplorerFilterGroup(filters, { logic: 'or' });
    assert.equal(grouped.length, 2);
    assert.equal(grouped[1].type, 'group');
    assert.equal(grouped[1].logic, 'or');
  });

  it('detects nested field usage', () => {
    const filters = [
      { id: 'a', field: 'src_ip', op: '=', value: '1.1.1.1', logic: 'and' },
      {
        type: 'group',
        id: 'g1',
        logic: 'and',
        children: [{ id: 'b', field: 'cabinet_client', op: '=', value: '42', logic: 'and' }],
      },
    ];
    assert.equal(T.explorerFilterUsesField(filters, 'cabinet_client'), true);
  });

  it('does not mutate the original filters while moving', () => {
    const filters = [
      { id: 'a', field: 'src_ip', op: '=', value: '1.1.1.1', logic: 'and' },
      { id: 'b', field: 'dst_ip', op: '=', value: '2.2.2.2', logic: 'and' },
      { id: 'c', field: 'proto', op: '=', value: 'UDP', logic: 'and' },
    ];
    const before = filters.map((f) => f.id);
    T.moveExplorerFilterNode(filters, 'a', null, 2);
    assert.deepEqual(filters.map((f) => f.id), before);
  });

  it('finds and moves nodes when ids differ only by type', () => {
    const filters = [
      { id: 10, field: 'src_ip', op: '=', value: '1.1.1.1', logic: 'and' },
      { id: 20, field: 'dst_ip', op: '=', value: '2.2.2.2', logic: 'and' },
    ];
    const loc = T.findExplorerFilterLocation(filters, '10');
    assert.equal(loc?.index, 0);
    const next = T.moveExplorerFilterNode(filters, '10', null, 2);
    assert.deepEqual(next.map((f) => f.id), [20, 10]);
  });

  it('reorders a list including the last slot', () => {
    assert.deepEqual(T.reorderExplorerList(['a', 'b', 'c'], 0, 2), ['b', 'c', 'a']);
    assert.deepEqual(T.reorderExplorerList(['a', 'b', 'c'], 2, 0), ['c', 'a', 'b']);
    assert.deepEqual(T.reorderExplorerList(['a', 'b', 'c'], 1, 1), ['a', 'b', 'c']);
  });
});
