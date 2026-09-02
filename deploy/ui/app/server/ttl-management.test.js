'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { summarizeDisks, diskUsageTone } = require('./ttl-management');

test('summarizeDisks sums Local disks and skips object storage', () => {
  const disk = summarizeDisks([
    { name: 'default', type: 'Local', total_space: 1000, free_space: 400 },
    { name: 's3', type: 'ObjectStorage', total_space: 0, free_space: 0 },
    { name: 'cache', type: 'Cache', total_space: 200, free_space: 50 },
  ]);
  assert.deepEqual(disk, {
    totalBytes: 1000,
    freeBytes: 400,
    usedBytes: 600,
    usedPct: 60,
  });
});

test('summarizeDisks sums multiple Local disks', () => {
  const disk = summarizeDisks([
    { name: 'default', type: 'Local', total_space: 800, free_space: 200 },
    { name: 'hot', type: 'Local', total_space: 200, free_space: 50 },
  ]);
  assert.equal(disk.totalBytes, 1000);
  assert.equal(disk.freeBytes, 250);
  assert.equal(disk.usedBytes, 750);
  assert.equal(disk.usedPct, 75);
});

test('summarizeDisks treats missing type as Local when total_space > 0', () => {
  const disk = summarizeDisks([
    { name: 'default', total_space: 500, free_space: 125 },
  ]);
  assert.equal(disk.totalBytes, 500);
  assert.equal(disk.usedBytes, 375);
  assert.equal(disk.usedPct, 75);
});

test('summarizeDisks returns null without usable disks', () => {
  assert.equal(summarizeDisks([]), null);
  assert.equal(summarizeDisks(null), null);
  assert.equal(summarizeDisks([
    { name: 's3', type: 'ObjectStorage', total_space: 0, free_space: 0 },
  ]), null);
});

test('diskUsageTone thresholds: green < 65, yellow from 65, red from 90', () => {
  assert.equal(diskUsageTone(0), 'ok');
  assert.equal(diskUsageTone(64.9), 'ok');
  assert.equal(diskUsageTone(65), 'warn');
  assert.equal(diskUsageTone(89.9), 'warn');
  assert.equal(diskUsageTone(90), 'crit');
  assert.equal(diskUsageTone(100), 'crit');
  assert.equal(diskUsageTone(NaN), 'ok');
});
