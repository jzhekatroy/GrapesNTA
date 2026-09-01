'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  DEFAULT_GROWTH_THRESHOLD,
  DEFAULT_ALERT_SCOPE,
  DEFAULT_STREAK,
  DEFAULT_NORMALIZE_STREAK,
  isAboveGrowthThreshold,
  shouldSendAlert,
  shouldSendNormalize,
  matchesAlertScope,
  pickAlertCandidates,
  pickNormalizeCandidates,
  formatAlertMessage,
  formatNormalizeMessage,
  snapshotByProto,
} = require('./detection-telegram');

function above(minute) {
  return { minute, growth_bps: 2.0, growth_pps: 0.5 };
}

function below(minute) {
  return { minute, growth_bps: 1.2, growth_pps: 1.1 };
}

describe('detection-telegram', () => {
  it('порог и серия по умолчанию', () => {
    assert.equal(DEFAULT_GROWTH_THRESHOLD, 1.6);
    assert.equal(DEFAULT_ALERT_SCOPE, 'all');
    assert.equal(DEFAULT_STREAK, 3);
    assert.equal(DEFAULT_NORMALIZE_STREAK, 3);
  });

  it('выше порога: рост bps или pps (OR)', () => {
    assert.equal(isAboveGrowthThreshold({ growth_bps: 1.6, growth_pps: null }, 1.6), true);
    assert.equal(isAboveGrowthThreshold({ growth_bps: 1.0, growth_pps: 2.0 }, 1.6), true);
    assert.equal(isAboveGrowthThreshold({ growth_bps: 1.0, growth_pps: 1.0 }, 1.6), false);
    assert.equal(isAboveGrowthThreshold({ growth_bps: null, growth_pps: null }, 1.6), false);
  });

  it('фильтр объектов: всё / абоненты / сети', () => {
    const client = { scope: 'client' };
    const net = { scope: 'net' };
    assert.equal(matchesAlertScope(client, 'all'), true);
    assert.equal(matchesAlertScope(net, 'all'), true);
    assert.equal(matchesAlertScope(client, 'client'), true);
    assert.equal(matchesAlertScope(net, 'client'), false);
    assert.equal(matchesAlertScope(net, 'net'), true);
    assert.equal(matchesAlertScope(client, 'net'), false);
  });

  it('серия: одно значение недостаточно при streak=3', () => {
    assert.equal(shouldSendAlert([above('2026-09-01 12:08:00')], 1.6, 3), false);
    assert.equal(shouldSendAlert([above('2026-09-01 12:08:00'), above('2026-09-01 12:05:00')], 1.6, 3), false);
  });

  it('серия: третье значение подряд — отправка', () => {
    const history = [
      above('2026-09-01 12:11:00'),
      above('2026-09-01 12:08:00'),
      above('2026-09-01 12:05:00'),
    ];
    assert.equal(shouldSendAlert(history, 1.6, 3), true);
  });

  it('серия: четвёртое подряд — уже отправлено', () => {
    const history = [
      above('2026-09-01 12:14:00'),
      above('2026-09-01 12:11:00'),
      above('2026-09-01 12:08:00'),
      above('2026-09-01 12:05:00'),
    ];
    assert.equal(shouldSendAlert(history, 1.6, 3), false);
  });

  it('серия: разрыв и снова 3 подряд — второе оповещение', () => {
    const history = [
      above('2026-09-01 12:20:00'),
      above('2026-09-01 12:17:00'),
      above('2026-09-01 12:14:00'),
      below('2026-09-01 12:11:00'),
    ];
    assert.equal(shouldSendAlert(history, 1.6, 3), true);
  });

  it('серия: разрыв внутри окна — не слать', () => {
    const history = [
      above('2026-09-01 12:11:00'),
      below('2026-09-01 12:08:00'),
      above('2026-09-01 12:05:00'),
    ];
    assert.equal(shouldSendAlert(history, 1.6, 3), false);
  });

  it('уже 3 подряд, но Telegram включили позже — шлём один раз', () => {
    const history = [
      above('2026-09-01 12:11:00'),
      above('2026-09-01 12:08:00'),
      above('2026-09-01 12:05:00'),
      { minute: '2026-09-01 12:00:00', growth_bps: 2.1, growth_pps: 0.4 },
    ];
    const enabledAt = Date.parse('2026-09-01T12:07:25Z');
    assert.equal(shouldSendAlert(history, 1.6, 3, enabledAt), true);
    const enabledEarlier = Date.parse('2026-09-01T11:00:00Z');
    assert.equal(shouldSendAlert(history, 1.6, 3, enabledEarlier), false);
  });

  it('pickAlertCandidates только proto all и выбранный scope', () => {
    const rows = [
      { scope: 'net', scope_id: '10.0.0.0/24', proto: 'all', growth_bps: 2, growth_pps: 0.1 },
      { scope: 'net', scope_id: '10.0.0.0/24', proto: 'tcp', growth_bps: 2, growth_pps: 0.1 },
      { scope: 'client', scope_id: '42', proto: 'all', growth_bps: 2, growth_pps: 0.1 },
    ];
    const prev = new Map([
      ['net|10.0.0.0/24', [above('2026-09-01 12:08:00'), above('2026-09-01 12:05:00')]],
      ['client|42', [above('2026-09-01 12:08:00'), above('2026-09-01 12:05:00')]],
    ]);
    const all = pickAlertCandidates(rows, prev, 1.6, { streak: 3, alertScope: 'all' });
    assert.equal(all.length, 2);
    const nets = pickAlertCandidates(rows, prev, 1.6, { streak: 3, alertScope: 'net' });
    assert.equal(nets.length, 1);
    assert.equal(nets[0].key, 'net|10.0.0.0/24');
    const clients = pickAlertCandidates(rows, prev, 1.6, { streak: 3, alertScope: 'client' });
    assert.equal(clients.length, 1);
    assert.equal(clients[0].key, 'client|42');
  });

  it('formatAlertMessage содержит все три протокола и настройки серии', () => {
    const text = formatAlertMessage({
      name: 'TestNet',
      scope: 'net',
      scopeId: '10.0.0.0/24',
      minute: '2026-09-01 10:00:00',
      threshold: 1.6,
      streak: 3,
      alertScope: 'all',
      byProto: {
        all: { bps: 1e9, pps: 1000, growth_bps: 2, growth_pps: 1.1, syn_attempts: 10, answer_pct: 50 },
        tcp: { bps: 5e8, pps: 500, growth_bps: 1.8, growth_pps: 1.0, syn_attempts: 10, answer_pct: 50 },
        udp: { bps: 1e6, pps: 10, growth_bps: 3, growth_pps: 2, port_entropy: 4.5 },
      },
    });
    assert.match(text, /TestNet/);
    assert.match(text, /общее/);
    assert.match(text, /TCP/);
    assert.match(text, /UDP/);
    assert.match(text, /попытки \/ ответ/);
    assert.match(text, /3 знач/);
    assert.match(text, /всё/);
    assert.match(text, /🔴/);
  });

  it('нормализация: 3 подряд ниже порога', () => {
    assert.equal(shouldSendNormalize([below('2026-09-01 12:11:00')], 1.6, 3), false);
    assert.equal(shouldSendNormalize([
      below('2026-09-01 12:11:00'),
      below('2026-09-01 12:08:00'),
      below('2026-09-01 12:05:00'),
    ], 1.6, 3), true);
    assert.equal(shouldSendNormalize([
      below('2026-09-01 12:11:00'),
      above('2026-09-01 12:08:00'),
      below('2026-09-01 12:05:00'),
    ], 1.6, 3), false);
  });

  it('активный объект не получает повторный алерт', () => {
    const rows = [
      { scope: 'net', scope_id: '10.0.0.0/24', proto: 'all', growth_bps: 2, growth_pps: 0.1 },
    ];
    const prev = new Map([
      ['net|10.0.0.0/24', [above('2026-09-01 12:08:00'), above('2026-09-01 12:05:00')]],
    ]);
    const picked = pickAlertCandidates(rows, prev, 1.6, {
      streak: 3,
      activeKeys: new Set(['net|10.0.0.0/24']),
    });
    assert.equal(picked.length, 0);
  });

  it('нормализация только для активного события', () => {
    const rows = [
      { scope: 'net', scope_id: '10.0.0.0/24', proto: 'all', growth_bps: 1.0, growth_pps: 1.0 },
    ];
    const prev = new Map([
      ['net|10.0.0.0/24', [below('2026-09-01 12:08:00'), below('2026-09-01 12:05:00')]],
    ]);
    const none = pickNormalizeCandidates(rows, prev, 1.6, { streak: 3, activeByKey: new Map() });
    assert.equal(none.length, 0);
    const activeByKey = new Map([
      ['net|10.0.0.0/24', { id: 'e1', scope: 'net', scopeId: '10.0.0.0/24' }],
    ]);
    const picked = pickNormalizeCandidates(rows, prev, 1.6, { streak: 3, activeByKey });
    assert.equal(picked.length, 1);
    assert.equal(picked[0].key, 'net|10.0.0.0/24');
  });

  it('formatNormalizeMessage с зелёной меткой и срезом метрик', () => {
    const text = formatNormalizeMessage({
      name: 'TestNet',
      scope: 'net',
      scopeId: '10.0.0.0/24',
      minute: '2026-09-01 11:00:00',
      alertMinute: '2026-09-01 10:00:00',
      threshold: 1.6,
      streak: 3,
      byProto: {
        all: { bps: 1e7, pps: 100, growth_bps: 1.1, growth_pps: 1.0 },
        tcp: { bps: 5e6, pps: 50, growth_bps: 1.0, growth_pps: 0.9 },
        udp: { bps: 1e6, pps: 10, growth_bps: 0.8, growth_pps: 0.7 },
      },
    });
    assert.match(text, /🟢/);
    assert.match(text, /нормализация/i);
    assert.match(text, /общее/);
    assert.match(text, /TCP/);
    assert.match(text, /UDP/);
  });

  it('snapshotByProto сохраняет все метрики трёх протоколов', () => {
    const snap = snapshotByProto({
      byProto: {
        all: { bps: 10, pps: 2, growth_bps: 2, growth_pps: 1.5, syn_attempts: 9, answer_pct: 10, port_entropy: 4 },
        tcp: { bps: 8, pps: 1, growthBps: 1.8, synAttempts: 9 },
        udp: { bps: 2, pps: 1, port_entropy: 3 },
      },
    });
    assert.equal(snap.all.bps, 10);
    assert.equal(snap.all.syn_attempts, 9);
    assert.equal(snap.all.answer_pct, 10);
    assert.equal(snap.tcp.syn_attempts, 9);
    assert.equal(snap.udp.port_entropy, 3);
  });
});
