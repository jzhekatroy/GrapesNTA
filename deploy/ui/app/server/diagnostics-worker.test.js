'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { classifyTrafficJob } = require('./diagnostics-worker');

const HOUR = 3600;

test('a fresh hour job a couple of hours behind is not stale', () => {
  const got = classifyTrafficJob('traffic_client_1h', 'ok', 2 * HOUR, 60);
  assert.equal(got.stale, false);
  assert.equal(got.deferred, false);
});

test('an hour job days behind is stale even if it just updated', () => {
  const got = classifyTrafficJob('traffic_client_service_1h', 'ok', 76 * HOUR, 30);
  assert.equal(got.stale, true);
});

test('a deferred job is reported on its own, not as a silent ok', () => {
  const got = classifyTrafficJob('traffic_client_service_1h', 'deferred', 76 * HOUR, 30);
  assert.equal(got.deferred, true);
  assert.equal(got.stale, false);
});

test('yesterday is normal for a day job, four days is not', () => {
  assert.equal(classifyTrafficJob('traffic_dashboard_1d', 'ok', 33 * HOUR, 10 * HOUR).stale, false);
  assert.equal(classifyTrafficJob('traffic_client_service_1d', 'ok', 100 * HOUR, 10 * 60).stale, true);
});
