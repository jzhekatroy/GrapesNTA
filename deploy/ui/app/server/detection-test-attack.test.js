'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  TEST_ATTACK_DURATION_MS,
  TEST_KINDS,
  buildTestAttackEventRow,
  testAttackAlertSnapshot,
  isTestDetectionEvent,
  isTestAttackExpired,
  shouldHideTestFromHistory,
  filterDetectionEventsForList,
} = require('./detection-test-attack');
const { mapEventRow } = require('./detection-telegram');

describe('detection test attack', () => {
  it('builds active test row with 25s lifetime marker', () => {
    const nowMs = Date.UTC(2026, 9, 22, 9, 0, 0);
    const row = buildTestAttackEventRow({ nowMs, triggeredBy: 'admin' });
    assert.match(row.event_id, /^test\|ui-test\|/);
    assert.equal(row.scope, 'test');
    assert.equal(row.status, 'active');
    const snapshot = JSON.parse(row.alert_json);
    assert.equal(snapshot.test, true);
    assert.equal(snapshot.telegramSkip, 'test');
    const expires = Date.parse(snapshot.testExpiresAt);
    assert.equal(expires - nowMs, TEST_ATTACK_DURATION_MS);
  });

  it('maps test flag from snapshot and scope', () => {
    const row = buildTestAttackEventRow({ nowMs: Date.now(), triggeredBy: 'x' });
    const event = mapEventRow(row);
    const snapshot = JSON.parse(row.alert_json);
    assert.equal(event.test, true);
    assert.equal(event.verdict?.kind, snapshot.verdict.kind);
    assert.ok(TEST_KINDS.includes(event.verdict?.kind));
  });

  it('drops expired active tests and all tests from history', () => {
    const nowMs = Date.UTC(2026, 9, 22, 10, 0, 0);
    const fresh = {
      id: 'a',
      scope: 'test',
      test: true,
      status: 'active',
      testExpiresAt: new Date(nowMs + 5000).toISOString(),
    };
    const expired = {
      id: 'b',
      scope: 'test',
      test: true,
      status: 'active',
      testExpiresAt: new Date(nowMs - 1000).toISOString(),
    };
    const real = { id: 'c', scope: 'client', status: 'active' };

    const active = filterDetectionEventsForList([fresh, expired, real], { listKind: 'active', nowMs });
    assert.deepEqual(active.map((e) => e.id), ['a', 'c']);
    assert.equal(isTestAttackExpired(expired, nowMs), true);
    assert.equal(isTestAttackExpired(fresh, nowMs), false);

    const history = filterDetectionEventsForList([fresh, real], { listKind: 'history', nowMs });
    assert.deepEqual(history.map((e) => e.id), ['c']);
    assert.equal(shouldHideTestFromHistory(fresh), true);
    assert.equal(isTestDetectionEvent({ scope: 'client' }), false);
  });

  it('snapshot includes triggeredBy', () => {
    const snap = testAttackAlertSnapshot({ nowMs: Date.now(), triggeredBy: 'alice' });
    assert.equal(snap.testTriggeredBy, 'alice');
  });

  it('snapshot has traffic breakdown, verdict ratio and investigate target', () => {
    const snap = testAttackAlertSnapshot({ nowMs: Date.now(), triggeredBy: 'admin' });
    assert.ok(snap.all.bps >= 600_000_000);
    assert.equal(snap.all.bps, snap.tcp.bps + snap.udp.bps);
    assert.ok(snap.verdict.hourRatio > 1);
    assert.match(snap.investigate?.victim?.ip, /^\d+\.\d+\.\d+\.\d+$/);
    assert.ok(snap.investigate?.switchIn?.ifName);
    assert.match(snap.testNote, /Синтетическое/);
  });

  it('snapshots differ across invocations', () => {
    const samples = Array.from({ length: 16 }, () => testAttackAlertSnapshot({
      nowMs: Date.now(),
      triggeredBy: 'admin',
    }));
    const ips = new Set(samples.map((s) => s.investigate.victim.ip));
    const kinds = new Set(samples.map((s) => s.verdict.kind));
    const totals = new Set(samples.map((s) => s.all.bps));
    assert.ok(ips.size > 1 || kinds.size > 1 || totals.size > 1);
  });

  it('attachTestAttackLiveState adds ongoing live metrics', () => {
    const row = buildTestAttackEventRow({ nowMs: Date.now(), triggeredBy: 'admin' });
    const event = mapEventRow(row);
    const { attachTestAttackLiveState } = require('./detection-test-attack');
    attachTestAttackLiveState([event]);
    assert.equal(event.live?.state, 'ongoing');
    assert.equal(event.live?.lastHotBps, event.alertByProto?.all?.bps);
    assert.ok(event.live?.lastHotExcessBps > 0);
  });
});
