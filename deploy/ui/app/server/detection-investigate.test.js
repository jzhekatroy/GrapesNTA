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
    assert.match(src, /LIMIT 1 BY proto/);
    assert.match(src, /status IN \('active', 'normalized'\)/);
    assert.doesNotMatch(src, /status != 'peak'/);
  });

  it('форма адреса отдаётся массивом: пустой скалярный кортеж ClickHouse не переваривает', () => {
    assert.match(src, /victim_flow AS \(\s*SELECT groupArray\(tuple\(/);
    assert.match(src, /sum\(flow_bytes\) AS ip_bytes/);
  });
});

describe('mapVictimShape', () => {
  const { mapVictimShape } = require('./detection-investigate');

  it('считает долю трёх крупнейших сеансов и средний пакет', () => {
    const shape = mapVictimShape(['176.116.255.95', '115628', 1000, 2, 69, 65, 67, 2, 910]);
    assert.equal(shape.clientId, '115628');
    assert.equal(shape.avgPkt, 500);
    assert.equal(shape.sessions, 69);
    assert.equal(shape.topShare, 0.91);
  });

  it('пустая минута — формы нет', () => {
    assert.equal(mapVictimShape(undefined), null);
    assert.equal(mapVictimShape(['', '', 0]), null);
  });
});
