'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  isAmplificationHit,
  evaluateForeignGeo,
  SIGNALS,
} = require('./detection-signals');
const {
  pickAlertCandidates,
  pickNormalizeCandidates,
  shouldSendAlert,
} = require('./detection-telegram');

describe('detection-signals', () => {
  it('101443: share 0.179, 40 источников, 906 Б → амплификация', () => {
    const udp = {
      bytes: 20.5e9,
      amp_bytes: 3.683e9,
      amp_packets: 4_065_536,
      amp_srcs: 40,
    };
    assert.equal(isAmplificationHit(udp), true);
  });

  it('81050: share 0.343, 119 источников, 1505 Б → амплификация', () => {
    const udp = {
      bytes: 35.3e9,
      amp_bytes: 12.12 * 1024 ** 3,
      amp_packets: Math.round(12.12 * 1024 ** 3 / 1505),
      amp_srcs: 119,
    };
    assert.equal(isAmplificationHit(udp), true);
  });

  it('69459: один источник и 4.6 Мбит/с → не амплификация', () => {
    assert.equal(isAmplificationHit({
      bytes: 34e6, amp_bytes: 34e6, amp_packets: 34000, amp_srcs: 1,
    }), false);
  });

  it('95558: доля 0.12 → не амплификация', () => {
    assert.equal(isAmplificationHit({
      bytes: 25e9, amp_bytes: 3e9, amp_packets: 2e6, amp_srcs: 24,
    }), false);
  });

  it('мелкий клиент: 30 Мбит/с отражателей и 20 источников → амплификация', () => {
    const ampBytes = 30e6 * 60 / 8;
    assert.equal(isAmplificationHit({
      bytes: ampBytes / 0.75,
      amp_bytes: ampBytes,
      amp_packets: Math.round(ampBytes / 900),
      amp_srcs: 20,
    }), true);
  });

  it('мелкий DNS-сервер: весь UDP с порта 53, но 9 кбит/с → не амплификация', () => {
    const ampBytes = 9e3 * 60 / 8;
    assert.equal(isAmplificationHit({
      bytes: ampBytes,
      amp_bytes: ampBytes,
      amp_packets: Math.round(ampBytes / 1129),
      amp_srcs: 16,
    }), false);
  });

  it('география 101443: доля ×3.7 и объём ×10 → срабатывает', () => {
    const geo = evaluateForeignGeo({
      bytes: 152e9,
      foreign_bytes: 38.93e9,
      growth_foreign_share: 3.7,
      growth_foreign_bps: 10,
    });
    assert.equal(geo.hit, true);
  });

  it('география 81050: доля ниже нормы → не срабатывает', () => {
    const geo = evaluateForeignGeo({
      bytes: 5.79 * 1024 ** 4,
      foreign_bytes: 3.36 * 1024 ** 4,
      growth_foreign_share: 0.58 / 0.65,
      growth_foreign_bps: 0.8,
    });
    assert.equal(geo.hit, false);
  });

  it('география: нет нормы → не срабатывает', () => {
    assert.equal(evaluateForeignGeo({
      bytes: 1e9, foreign_bytes: 0.5e9,
    }).hit, false);
  });

  it('география: стабильные 100% зарубежного → не срабатывает', () => {
    assert.equal(evaluateForeignGeo({
      bytes: 10e9, foreign_bytes: 10e9, growth_foreign_share: 1, growth_foreign_bps: 1,
    }).hit, false);
  });

  it('география: мелкий клиент с 50 Мбит/с зарубежного → срабатывает', () => {
    const bytes = 50e6 * 60 / 8 / 0.99;
    assert.equal(evaluateForeignGeo({
      bytes,
      foreign_bytes: bytes * 0.99,
      growth_foreign_share: 9.4,
      growth_foreign_bps: 14,
    }).hit, true);
  });

  it('география: 10 Мбит/с зарубежного — ниже пола, не срабатывает', () => {
    const bytes = 10e6 * 60 / 8;
    assert.equal(evaluateForeignGeo({
      bytes,
      foreign_bytes: bytes,
      growth_foreign_share: 9.4,
      growth_foreign_bps: 14,
    }).hit, false);
  });

  it('география: доля 0.01 при норме 0.001 → не срабатывает', () => {
    assert.equal(evaluateForeignGeo({
      bytes: 10e9, foreign_bytes: 0.1e9, growth_foreign_share: 10, growth_foreign_bps: 10,
    }).hit, false);
  });

  it('два признака в одну минуту — два события, один объект', () => {
    const udp = {
      proto: 'udp',
      bytes: 20.5e9,
      amp_bytes: 3.683e9,
      amp_packets: 4_065_536,
      amp_srcs: 40,
    };
    const all = {
      scope: 'client',
      scope_id: '101443',
      proto: 'all',
      growth_bps: 1.1,
      bytes: 21e9,
      foreign_bytes: 8e9,
      growth_foreign_share: 3.7,
      growth_foreign_bps: 10,
    };
    const grouped = new Map([['client|101443', { byProto: { all, udp } }]]);
    const picked = pickAlertCandidates([all], new Map(), 1.6, {
      streak: 3,
      grouped,
      settings: { ampEnabled: true, geoEnabled: true, ampStreak: 1, geoStreak: 1 },
    });
    const signals = picked.map((c) => c.signal).sort();
    assert.deepEqual(signals, ['amplification', 'foreign_geo']);
    assert.equal(shouldSendAlert([all], 1.6, 3), false);
  });

  it('признак выключен — кандидатов нет', () => {
    const all = {
      scope: 'client', scope_id: '1', proto: 'all', growth_bps: 3,
    };
    const picked = pickAlertCandidates([all], new Map([['client|1', [
      { growth_bps: 3 }, { growth_bps: 3 },
    ]]]), 1.6, {
      streak: 3,
      settings: { ampEnabled: false, geoEnabled: false },
    });
    assert.equal(picked.length, 1);
    assert.equal(picked[0].signal, SIGNALS.volume);
  });

  it('нормализация одного признака не закрывает другой', () => {
    const row = { scope: 'client', scope_id: '1', proto: 'all', growth_bps: 1.1, bps: 3.2e9 };
    const activeAmp = {
      id: 'e1',
      scope: 'client',
      scopeId: '1',
      signal: SIGNALS.amplification,
      threshold: 1.6,
      alertByProto: { all: { bps: 1e9 } },
    };
    const activeVol = {
      id: 'e2',
      scope: 'client',
      scopeId: '1',
      signal: SIGNALS.volume,
      threshold: 1.6,
      alertByProto: { all: { bps: 3e9 } },
      verdict: { hourP95: 1e9 },
    };
    const prev = [
      { growth_bps: 1.1, bps: 3.1e9 },
      { growth_bps: 1.1, bps: 3.0e9 },
    ];
    const picked = pickNormalizeCandidates([row], new Map([['client|1', prev]]), 1.6, {
      settings: { ampNormalizeStreak: 3, normalizeStreak: 3 },
      activeByKey: new Map([
        ['client|1|amplification', activeAmp],
        ['client|1|volume', activeVol],
        ['client|1', activeVol],
      ]),
    });
    assert.equal(picked.some((c) => c.signal === SIGNALS.amplification), true);
    assert.equal(picked.some((c) => c.signal === SIGNALS.volume), false);
  });
});
