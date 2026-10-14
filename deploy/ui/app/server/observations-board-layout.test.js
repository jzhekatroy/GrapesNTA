'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const path = require('path');
const {
  validateLayout,
  normalizeObservationIds,
  getLayout,
  putLayout,
  resetStoreForTests,
} = require('./observations-board-layout');

function tempDbPath(name) {
  return path.join(os.tmpdir(), `grapes-obs-board-${name}-${process.pid}-${Date.now()}.db`);
}

test.afterEach(() => {
  resetStoreForTests();
});

test('validateLayout normalizes observation ids', () => {
  const layout = validateLayout({
    version: 1,
    observationIds: ['  a  ', 'b', ''],
  });
  assert.deepEqual(layout.observationIds, ['a', 'b']);
});

test('validateLayout rejects duplicate ids in input', () => {
  assert.throws(
    () => validateLayout({ version: 1, observationIds: ['x', 'x'] }),
    /Дублирующиеся/,
  );
});

test('validateLayout rejects invalid payload', () => {
  assert.throws(() => validateLayout(null), /Некорректная/);
});

test('normalizeObservationIds caps count and dedupes', () => {
  const ids = Array.from({ length: 600 }, (_, i) => `id-${i}`);
  const out = normalizeObservationIds(ids);
  assert.equal(out.length, 500);
});

test('putLayout and getLayout round-trip per user', () => {
  const dbPath = tempDbPath('roundtrip');
  resetStoreForTests(dbPath);
  putLayout('user-1', { version: 1, observationIds: ['obs-2', 'obs-1'] });
  const loaded = getLayout('user-1');
  assert.ok(loaded);
  assert.deepEqual(loaded.layout.observationIds, ['obs-2', 'obs-1']);
  putLayout('user-2', { version: 1, observationIds: ['obs-9'] });
  assert.deepEqual(getLayout('user-2').layout.observationIds, ['obs-9']);
  assert.deepEqual(getLayout('user-1').layout.observationIds, ['obs-2', 'obs-1']);
});

test('getLayout returns null for unknown user', () => {
  const dbPath = tempDbPath('empty');
  resetStoreForTests(dbPath);
  assert.equal(getLayout('nobody'), null);
});

test.after(() => {
  resetStoreForTests();
});
