'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { growthRatio, variationPercent, minuteMetrics, ratePercent, MIN_BPS } = require('./detection-core');
const { loadHistory, HISTORY_METRICS } = require('./detection-engine');

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
    assert.equal(m.portEntropy, null);
    assert.equal(m.portEntropyOut, null);
    assert.equal(m.portsPerIp, null);
    assert.equal(m.portsPerIpOut, null);
  });

  it('энтропия портов: число сохраняется, NaN становится пустым', () => {
    assert.equal(minuteMetrics({ portEntropy: 5.25 }).portEntropy, 5.25);
    assert.equal(minuteMetrics({ portEntropy: Number.NaN }).portEntropy, null);
    assert.equal(minuteMetrics({ udpPortEntropy: 5.25 }).portEntropy, 5.25);
  });

  it('энтропия портов: входящая и исходящая независимы', () => {
    const m = minuteMetrics({ portEntropy: 2.75, portEntropyOut: 11.4 });
    assert.equal(m.portEntropy, 2.75);
    assert.equal(m.portEntropyOut, 11.4);
    assert.equal(minuteMetrics({ portEntropyOut: 4.5 }).portEntropy, null);
  });

  it('пик портов на адрес: стороны независимы, NaN становится пустым', () => {
    const m = minuteMetrics({ portsPerIp: 5477, portsPerIpOut: 12 });
    assert.equal(m.portsPerIp, 5477);
    assert.equal(m.portsPerIpOut, 12);
    assert.equal(minuteMetrics({ portsPerIpOut: 3 }).portsPerIp, null);
    assert.equal(minuteMetrics({ portsPerIp: Number.NaN }).portsPerIp, null);
    assert.equal(minuteMetrics({ udpPortsPerIp: 88 }).portsPerIp, 88);
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

describe('detection history', () => {
  it('метрики только из белого списка колонок', () => {
    for (const spec of Object.values(HISTORY_METRICS)) {
      assert.match(spec.column, /^[a-z_]+$/);
    }
    assert.ok(HISTORY_METRICS.portEntropy);
    assert.equal(HISTORY_METRICS.udpPortEntropy, undefined);
  });

  it('отклоняет неизвестную метрику, объект и протокол', async () => {
    await assert.rejects(
      () => loadHistory({ scope: 'client', scopeId: '1', metric: 'drop_table' }),
      (err) => err.statusCode === 400,
    );
    await assert.rejects(
      () => loadHistory({ scope: 'x', scopeId: '1', metric: 'bps' }),
      (err) => err.statusCode === 400,
    );
    await assert.rejects(
      () => loadHistory({ scope: 'client', scopeId: '1', proto: 'icmp', metric: 'bps' }),
      (err) => err.statusCode === 400,
    );
    await assert.rejects(
      () => loadHistory({ scope: 'client', scopeId: '1', metric: 'bps', from: 'плохо', to: '2026-09-01 10:00:00' }),
      (err) => err.statusCode === 400,
    );
  });
});
