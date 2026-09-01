'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { growthRatio, variationPercent, minuteMetrics, ratePercent, MIN_BPS } = require('./detection-core');

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
    assert.equal(ratePercent(200, 100), 100);
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
    assert.equal(m.udpPortEntropy, null);
    assert.equal(m.udpPortEntropyOut, null);
    assert.equal(m.udpPortsPerIp, null);
    assert.equal(m.udpPortsPerIpOut, null);
  });

  it('энтропия UDP: число сохраняется, NaN становится пустым', () => {
    assert.equal(minuteMetrics({ udpPortEntropy: 5.25 }).udpPortEntropy, 5.25);
    assert.equal(minuteMetrics({ udpPortEntropy: Number.NaN }).udpPortEntropy, null);
  });

  it('энтропия UDP: входящая и исходящая независимы', () => {
    const m = minuteMetrics({ udpPortEntropy: 2.75, udpPortEntropyOut: 11.4 });
    assert.equal(m.udpPortEntropy, 2.75);
    assert.equal(m.udpPortEntropyOut, 11.4);
    assert.equal(minuteMetrics({ udpPortEntropyOut: 4.5 }).udpPortEntropy, null);
  });

  it('пик портов на адрес: стороны независимы, NaN становится пустым', () => {
    const m = minuteMetrics({ udpPortsPerIp: 5477, udpPortsPerIpOut: 12 });
    assert.equal(m.udpPortsPerIp, 5477);
    assert.equal(m.udpPortsPerIpOut, 12);
    assert.equal(minuteMetrics({ udpPortsPerIpOut: 3 }).udpPortsPerIp, null);
    assert.equal(minuteMetrics({ udpPortsPerIp: Number.NaN }).udpPortsPerIp, null);
  });

  it('порог тишины: 20 Мбит/с, объект на 19.9 не проходит', () => {
    assert.equal(MIN_BPS, 20e6);
    const quiet = minuteMetrics({ bytes: 19.9e6 * 60 / 8 });
    const loud = minuteMetrics({ bytes: 20.1e6 * 60 / 8 });
    assert.ok(quiet.bps < MIN_BPS);
    assert.ok(loud.bps >= MIN_BPS);
  });

  it('доля топ-1 порта больше не считается', () => {
    const m = minuteMetrics({ udpTopPortPct: 70.5, udpTopPortPctOut: 9.2 });
    assert.equal(m.udpTopPortPct, undefined);
    assert.equal(m.udpTopPortPctOut, undefined);
  });

  it('ответ и «не зашли» не больше 100%, даже если sFlow поймал SYN+ACK без SYN', () => {
    const m = minuteMetrics({
      synAttempts: 50,
      synAnswered: 100,
      synInFlows: 80,
      synHalfOpen: 90,
      synHalfOpenReply: 91,
    });
    assert.equal(m.answerPct, 100);
    assert.equal(m.halfOpenPct, 100);
    assert.equal(m.halfOpenReplyPct, 100);
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
