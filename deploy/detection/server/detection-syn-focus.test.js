'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { isSynFloodHit, SIGNALS } = require('./detection-signals');
const { refineClassification, KINDS } = require('./detection-classify');
const { formatAlertMessage } = require('./detection-telegram');

const SYN_OPTS = { ppsMin: 200_000, hourRatio: 10 };

// Строка минуты PiterIX: голого SYN pps п/с, rows проб, targets пар адрес:порт.
function synRow({ pps, rows, targets, growth, answer }) {
  const packets = pps * 60;
  return {
    proto: 'all',
    syn_only_packets: packets,
    syn_only_bytes: packets * 64,
    syn_only_rows: rows,
    syn_only_targets: targets,
    growth_syn: growth,
    answer_pct: answer,
  };
}

describe('SYN-флуд в одну цель ниже пола', () => {
  // 101443 01.10 12:00 МСК: 89.208.43.152 → 109.232.248.252:80.
  const flood = synRow({ pps: 136_533, rows: 125, targets: 2, growth: 62.5, answer: 0.79 });

  it('ловит флуд 101443', () => {
    assert.equal(isSynFloodHit(flood, SYN_OPTS), true);
  });

  it('не ловит сканы с той же формой пакетов', () => {
    // 54556 29.09 21:00 UTC: 84 пробы на 84 пары, Yandex.Cloud обходит 67 адресов.
    assert.equal(isSynFloodHit(synRow({ pps: 91_750, rows: 84, targets: 84, growth: 10.5, answer: 4.8 }), SYN_OPTS), false);
    // 71766 30.09 03:02 UTC: 93 пробы на 93 пары.
    assert.equal(isSynFloodHit(synRow({ pps: 50_790, rows: 93, targets: 93, growth: 18.6, answer: 0 }), SYN_OPTS), false);
  });

  it('без нормы часа, ответов или числа целей решает только пол', () => {
    assert.equal(isSynFloodHit({ ...flood, growth_syn: null }, SYN_OPTS), false);
    assert.equal(isSynFloodHit({ ...flood, answer_pct: null }, SYN_OPTS), false);
    assert.equal(isSynFloodHit({ ...flood, syn_only_targets: 0 }, SYN_OPTS), false);
    assert.equal(isSynFloodHit({ ...flood, answer_pct: 6 }, SYN_OPTS), false);
    assert.equal(isSynFloodHit({ ...flood, growth_syn: 8 }, SYN_OPTS), false);
  });

  it('ниже 50 тыс. п/с молчит', () => {
    assert.equal(isSynFloodHit(synRow({ pps: 40_000, rows: 125, targets: 2, growth: 62.5, answer: 0.79 }), SYN_OPTS), false);
  });
});

describe('цель по пакетам, когда по байтам — закачка', () => {
  // Снимок алерта 101443 09:02 UTC: по байтам первым шёл Yandex.Cloud на 185.191.34.125.
  const investigate = {
    victim: { ip: '185.191.34.125', port: 53037, proto: 6, protoLabel: 'TCP', share: 0.216, bytes: 1 },
    syn: {
      packets: 8_192_000,
      pps: 136_533,
      avgPkt: 64,
      srcIps: 2,
      dest: [
        { ip: '109.232.248.252', port: 80, packets: 8_126_464, share: 0.992 },
        { ip: '185.170.204.91', port: 21101, packets: 65_536, share: 0.008 },
      ],
    },
  };
  const verdict = { kind: KINDS.benign_peak, reason: 'нет явных признаков атаки', answerPct: 0.79, hourRatio: 0.86 };

  it('голый SYN в одну пару — SYN-флуд, а не «в один сервер»', () => {
    const next = refineClassification(verdict, investigate, { scope: 'client' });
    assert.equal(next.kind, KINDS.syn_flood);
    assert.match(next.reason, /^109\.232\.248\.252 80 99% SYN · голый SYN 137 тыс\. п\/с/);
  });

  it('SYN размазан или отвечают — прежний разбор', () => {
    const spread = { ...investigate, syn: { ...investigate.syn, dest: [{ ip: '109.232.248.252', port: 80, share: 0.3 }] } };
    assert.notEqual(refineClassification(verdict, spread, { scope: 'client' }).kind, KINDS.syn_flood);
    assert.notEqual(refineClassification({ ...verdict, answerPct: 40 }, investigate, { scope: 'client' }).kind, KINDS.syn_flood);
  });

  it('строка объёма говорит про пакеты', () => {
    const text = formatAlertMessage({
      name: '101443', scope: 'client', scopeId: '101443', minute: '2026-10-01 09:00:00', threshold: 1.6,
      byProto: { all: { bps: 516e6, pps: 218_453, growth_bps: 0.84, growth_pps: 2.38 } },
      verdict: { kind: KINDS.volumetric, hourRatio: 0.86, hourCeiling: 598e6 },
      investigate: { victim: investigate.victim },
      signals: [SIGNALS.volume],
    });
    assert.match(text, /<b>В 2,4 раза больше обычного по пакетам:<\/b> 218 тыс\. п\/с, обычно до ~91\.8 тыс\. п\/с/);
    assert.match(text, /Весь трафик клиента: 516 Мбит\/с \(обычно 598 Мбит\/с\) · 218 тыс\. п\/с \(×2,4\)/);
  });
});
