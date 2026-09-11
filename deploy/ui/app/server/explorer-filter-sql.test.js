'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { combineExplorerFilterSql } = require('./explorer');

describe('combineExplorerFilterSql', () => {
  it('builds A AND (B OR C) precedence via grouped clause', () => {
    const sql = combineExplorerFilterSql([
      { clause: 'A', logic: 'and' },
      { clause: '(B OR C)', logic: 'and' },
    ]);
    assert.equal(sql, '(A AND (B OR C))');
  });

  it('builds left-associative chain for flat clauses', () => {
    const sql = combineExplorerFilterSql([
      { clause: 'A', logic: 'and' },
      { clause: 'B', logic: 'or' },
      { clause: 'C', logic: 'and' },
    ]);
    assert.equal(sql, '((A OR B) AND C)');
  });
});
