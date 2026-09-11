'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { resolveIncludeInTotal } = require('./net-flow-sources');
const { sourcesScopeSql } = require('./queries');

describe('resolveIncludeInTotal', () => {
  it('галка «дополнительный» выключает учёт в всего', () => {
    assert.equal(resolveIncludeInTotal({ additional: true }), 0);
    assert.equal(resolveIncludeInTotal({ additional: 1 }), 0);
    assert.equal(resolveIncludeInTotal({ additional: '1' }), 0);
  });

  it('снятая галка включает учёт в всего', () => {
    assert.equal(resolveIncludeInTotal({ additional: false }, 0), 1);
    assert.equal(resolveIncludeInTotal({ additional: 0 }), 1);
  });

  it('явный includeInTotal важнее fallback', () => {
    assert.equal(resolveIncludeInTotal({ includeInTotal: 0 }, 1), 0);
    assert.equal(resolveIncludeInTotal({ include_in_total: 1 }, 0), 1);
  });

  it('без полей оставляет fallback', () => {
    assert.equal(resolveIncludeInTotal({}, 1), 1);
    assert.equal(resolveIncludeInTotal({}, 0), 0);
    assert.equal(resolveIncludeInTotal(null, 1), 1);
  });
});

describe('sourcesScopeSql', () => {
  it('по умолчанию только источники с include_in_total=1', () => {
    assert.match(sourcesScopeSql([]), /include_in_total.*= 1/);
  });

  it('в разборе с totalsOnly=false не режет дополнительные', () => {
    assert.equal(sourcesScopeSql([], 's', { totalsOnly: false }), '1');
    assert.doesNotMatch(
      sourcesScopeSql([{ type: 'collector', collectorId: 'nta' }], 's', { totalsOnly: false }),
      /include_in_total/,
    );
  });
});
