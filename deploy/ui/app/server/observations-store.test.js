'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { naiveChToIso, sanitizeCreatedAt } = require('./observations-store');
const { formatDateTime64 } = require('./clickhouse');

const TZ = 'Europe/Moscow';

describe('observations store timestamps', () => {
  it('naiveChToIso reads a naive DateTime as CLICKHOUSE_TIMEZONE, not UTC', () => {
    assert.equal(naiveChToIso('2026-09-27 07:13:55.827', TZ), '2026-09-27T04:13:55.827Z');
    assert.equal(naiveChToIso('2026-08-12 16:13:55.878', TZ), '2026-08-12T13:13:55.878Z');
    assert.equal(naiveChToIso('2026-08-12 16:13:55', 'UTC'), '2026-08-12T16:13:55.000Z');
  });

  it('write → read round trip keeps the instant (created_at used to drift +offset per save)', () => {
    let iso = '2026-08-12T13:13:55.878Z';
    for (let i = 0; i < 5; i += 1) {
      iso = naiveChToIso(formatDateTime64(new Date(iso), TZ), TZ);
    }
    assert.equal(iso, '2026-08-12T13:13:55.878Z');
  });

  it('sanitizeCreatedAt recovers a future created_at from the id stamp', () => {
    const future = new Date(Date.now() + 30 * 86400 * 1000).toISOString();
    assert.equal(
      sanitizeCreatedAt(future, 'obs-1786540435878-86wulh', '2026-09-03T07:12:25.562Z'),
      '2026-08-12T13:13:55.878Z',
    );
  });

  it('sanitizeCreatedAt keeps a sane created_at untouched', () => {
    assert.equal(
      sanitizeCreatedAt('2026-08-12T13:13:55.878Z', 'obs-1786540435878-86wulh', null),
      '2026-08-12T13:13:55.878Z',
    );
  });

  it('sanitizeCreatedAt falls back to updated_at when the id carries no stamp', () => {
    const future = new Date(Date.now() + 3600 * 1000).toISOString();
    assert.equal(
      sanitizeCreatedAt(future, 'preset-own-net', '2026-09-03T07:12:25.562Z'),
      '2026-09-03T07:12:25.562Z',
    );
  });
});
