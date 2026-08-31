'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { growthRatio, variationPercent, minuteMetrics, ratePercent } = require('./detection-core');

describe('detection-core', () => {
  it('рост пустой, если квантиль ноль', () => {
    assert.equal(growthRatio(100, 0), null);
    assert.equal(growthRatio(100, null), null);
    assert.equal(growthRatio(230, 100), 2.3);
    assert.equal(growthRatio(0, 100), 0);
  });

  it('разброс: три потока 60, 150, 1400 дают CV около 114%', () => {
    const sample = [60, 150, 1400];
    const n = sample.length;
    const sumX = sample.reduce((a, b) => a + b, 0);
    const sumSqX = sample.reduce((a, b) => a + b * b, 0);
    const cv = variationPercent(n, sumX, sumSqX);
    assert.ok(Math.abs(cv - 113.96) < 0.05, `CV ${cv}`);
    assert.equal(variationPercent(0, 0, 0), null);
  });

  it('доля: без знаменателя пусто, ноль попыток не ноль процентов', () => {
    assert.equal(ratePercent(0, 0), null);
    assert.equal(ratePercent(0, 100), 0);
    assert.equal(ratePercent(88, 100), 88);
  });

  it('минута без трафика даёт нули и пустые доли', () => {
    const m = minuteMetrics({});
    assert.equal(m.bytes, 0);
    assert.equal(m.bps, 0);
    assert.equal(m.avgPacketBytes, 0);
    assert.equal(m.cvPercent, 0);
    assert.equal(m.synAttempts, 0);
    assert.equal(m.answerPct, null);
    assert.equal(m.halfOpenPct, null);
    assert.equal(m.halfOpenReplyPct, null);
  });

  it('атака: почти нет ответа, почти все полуоткрытые', () => {
    const m = minuteMetrics({
      synAttempts: 55040,
      synAnswered: 320,
      synInFlows: 55400,
      synHalfOpen: 54644,
      synHalfOpenReply: 3,
    });
    assert.ok(Math.abs(m.answerPct - 0.581) < 0.01);
    assert.ok(Math.abs(m.halfOpenPct - 98.635) < 0.02);
    assert.ok(m.halfOpenReplyPct < 0.01);
  });
});
