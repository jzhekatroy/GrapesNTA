'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { SIGNALS } = require('./detection-signals');
const { srcCountrySql } = require('./detection-engine');
const {
  dropDuplicateGeo,
  summarizeRepeat,
  formatRepeatLine,
  formatAlertMessage,
} = require('./detection-telegram');

// 57469, 30.09 18:20 МСК: всплеск объёма и чужая география в одну минуту.
const row57469 = { scope: 'client', scope_id: '57469', proto: 'all', bps: 4.33e9 };
const cand = (signal) => ({ row: row57469, signal, key: `client|57469|${signal}`, objectKey: 'client|57469' });

describe('одно событие на одну аномалию', () => {
  it('география в одну минуту со всплеском не заводит своего события', () => {
    const out = dropDuplicateGeo([cand(SIGNALS.volume), cand(SIGNALS.foreign_geo)], new Map());
    assert.deepEqual(out.map((c) => c.signal), [SIGNALS.volume]);
  });

  it('география при уже открытом событии клиента молчит', () => {
    const active = new Map([['client|57469', { id: 'client|57469|2026-09-30 15:20:00' }]]);
    assert.equal(dropDuplicateGeo([cand(SIGNALS.foreign_geo)], active).length, 0);
    const activeAmp = new Map([['client|57469|amplification', { id: 'x' }]]);
    assert.equal(dropDuplicateGeo([cand(SIGNALS.foreign_geo)], activeAmp).length, 0);
  });

  it('география одна — событие остаётся', () => {
    assert.equal(dropDuplicateGeo([cand(SIGNALS.foreign_geo)], new Map()).length, 1);
  });
});

describe('одна объёмная атака — одно событие', () => {
  // 71747, 04.10: удар в 37.230.162.0/24 открыт в 09:50, рост объёма — в 09:54.
  const row71747 = { scope: 'client', scope_id: '71747', proto: 'all', bps: 53.46e9 };
  const c = (signal) => ({ row: row71747, signal, key: `client|71747|${signal}`, objectKey: 'client|71747' });

  it('рост объёма при открытом ударе в /24 молчит', () => {
    const active = new Map([['client|71747|net_spike', { id: 'client|71747|net_spike|2026-10-04 06:50:00' }]]);
    assert.equal(dropDuplicateGeo([c(SIGNALS.volume)], active).length, 0);
  });

  it('удар в /24 при открытом росте объёма молчит', () => {
    const active = new Map([['client|71747', { id: 'client|71747|2026-10-04 06:50:00' }]]);
    assert.equal(dropDuplicateGeo([c(SIGNALS.net_spike)], active).length, 0);
  });

  it('в одну минуту остаётся удар в /24', () => {
    const out = dropDuplicateGeo([c(SIGNALS.volume), c(SIGNALS.net_spike)], new Map());
    assert.deepEqual(out.map((x) => x.signal), [SIGNALS.net_spike]);
  });

  it('SYN и амплификация открываются отдельно', () => {
    const active = new Map([['client|71747|net_spike', { id: 'x' }]]);
    const out = dropDuplicateGeo([c(SIGNALS.syn_flood), c(SIGNALS.amplification)], active);
    assert.deepEqual(out.map((x) => x.signal), [SIGNALS.syn_flood, SIGNALS.amplification]);
  });
});

describe('повтор атаки', () => {
  // 57469: 30.09 18:20, 18:30, 18:39 МСК — UDP на 185.97.252.138:7219, снова в 21:46.
  const prior57469 = [
    { minute: '2026-09-30 15:20:00', victimIp: '185.97.252.138' },
    { minute: '2026-09-30 15:30:00', victimIp: '185.97.252.138' },
    { minute: '2026-09-30 15:39:00', victimIp: '185.97.252.138' },
  ];

  it('считает заходы на тот же адрес', () => {
    const repeat = summarizeRepeat(prior57469, '185.97.252.138');
    assert.deepEqual(repeat, { nth: 4, target: '185.97.252.138', lastMinute: '2026-09-30 15:39:00' });
    assert.equal(
      formatRepeatLine(repeat, 'client', '2026-09-30 18:46:00'),
      'Повтор: 4-я атака за сутки на 185.97.252.138, прошлая в 18:39 МСК',
    );
  });

  it('другой адрес — считает по клиенту, прошлые сутки с датой', () => {
    // 72573: SYN 29.09 20:25 МСК (в снимке адрес по байтам 194.26.229.177), повтор 30.09 07:09 на 85.192.30.234.
    const repeat = summarizeRepeat([{ minute: '2026-09-29 17:25:00', victimIp: '194.26.229.177' }], '85.192.30.234');
    assert.deepEqual(repeat, { nth: 2, target: '', lastMinute: '2026-09-29 17:25:00' });
    assert.equal(
      formatRepeatLine(repeat, 'client', '2026-09-30 04:09:00'),
      'Повтор: 2-я атака за сутки на этого клиента, прошлая в 29.09 20:25 МСК',
    );
  });

  it('первая атака — без строки', () => {
    assert.equal(summarizeRepeat([], '185.97.252.138'), null);
    const text = formatAlertMessage({
      name: '57469', scope: 'client', scopeId: '57469', minute: '2026-09-30 15:20:00', threshold: 1.6,
      byProto: { all: row57469 }, verdict: { kind: 'volumetric' }, investigate: {}, signals: [SIGNALS.volume],
    });
    assert.doesNotMatch(text, /Повтор/);
  });

  it('строка стоит в шапке алерта', () => {
    const text = formatAlertMessage({
      name: '57469', scope: 'client', scopeId: '57469', minute: '2026-09-30 18:46:00', threshold: 1.6,
      byProto: { all: row57469 }, verdict: { kind: 'volumetric' }, investigate: {}, signals: [SIGNALS.volume],
      repeat: summarizeRepeat(prior57469, '185.97.252.138'),
    });
    assert.match(text, /\nНачало: .*\nПовтор: <b>4-я атака за сутки<\/b> на 185\.97\.252\.138, прошлая в 18:39 МСК\n/);
  });
});

describe('страна источника', () => {
  it('российский AS перекрывает страну блока из RIR', () => {
    const sql = srcCountrySql('f.src_addr', 'f.src_asn');
    assert.match(sql, /f\.src_asn IN \(SELECT asn FROM .*asn_registry_enriched.* WHERE cc = 'RU'\), 'RU'/);
    assert.match(sql, /geo_country_dict/);
  });

  it('без колонки AS — только страна блока', () => {
    const sql = srcCountrySql('f.src_addr', '');
    assert.doesNotMatch(sql, /asn_registry/);
    assert.match(sql, /^trimBoth\(/);
  });
});
