'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { formatDateTime64 } = require('./clickhouse');

test('formatDateTime64 writes ClickHouse naive time in Europe/Moscow, not UTC', () => {
  const utc = new Date('2026-09-02T09:03:23.400Z');
  assert.equal(formatDateTime64(utc, 'Europe/Moscow'), '2026-09-02 12:03:23.400');
  assert.equal(formatDateTime64(utc, 'UTC'), '2026-09-02 09:03:23.400');
});

test('formatDateTime64 UTC wall-clock is behind Moscow now64-style stamps', () => {
  const utc = new Date('2026-09-02T08:56:15.450Z');
  const utcNaive = utc.toISOString().replace('T', ' ').replace('Z', '');
  const moscow = formatDateTime64(utc, 'Europe/Moscow');
  assert.equal(utcNaive, '2026-09-02 08:56:15.450');
  assert.equal(moscow, '2026-09-02 11:56:15.450');
  assert.ok(moscow > utcNaive);
});
