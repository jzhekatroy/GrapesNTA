'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.join(__dirname, 'detection-investigate.js'), 'utf8')
  .replace(/\/\/[^\n]*/g, '');

describe('detection-investigate SQL', () => {
  it('не сворачивает агрегат сам в себя — ClickHouse 24.8 тогда падает ILLEGAL_AGGREGATION', () => {
    assert.doesNotMatch(src, /sum\(\s*byte_sum\s*\)\s+AS\s+byte_sum/);
    assert.match(src, /sum\(\s*pair_bytes\s*\)\s+AS\s+ip_bytes/);
    assert.match(src, /sum\(bytes\) AS pair_bytes/);
  });
});
