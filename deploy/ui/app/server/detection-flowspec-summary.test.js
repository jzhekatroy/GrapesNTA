'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  findVariant,
  parseCidr,
  eventRules,
  buildFlowspecSummary,
  activeObjects,
} = require('./detection-flowspec-summary');

const band = { lo: 1000, hi: 1500 };

function item(name, scope, destinations, rows24, extra = {}) {
  return {
    name,
    scope,
    scopeId: name,
    minute: '2026-10-12 06:40:00',
    destinations,
    band,
    row: {
      atk_big: rows24.reduce((sum, r) => sum + r[1], 0),
      atk_src: 900,
      base_src: 10,
      rows24,
      rows16: [],
      ...extra,
    },
  };
}

function summary(variantId, items) {
  const variant = findVariant(variantId);
  items.forEach((it) => { it.rules = eventRules(variant, it); });
  return buildFlowspecSummary({ variant, items, nowTs: Date.parse('2026-10-12T06:45:00Z') });
}

describe('общий фильтр: дубли', () => {
  it('одна сеть источника на одно назначение у двух аварий — одно правило', () => {
    const out = summary('src24-90', [
      item('skynet', 'client', ['91.0.0.0/24'], [['5.77.1.0/24', 500, 0]]),
      item('skynet-net', 'net', ['91.0.0.0/24'], [['5.77.1.0/24', 300, 0]]),
    ]);
    assert.equal(out.rules, 1);
    assert.equal(out.duplicates, 1);
    assert.equal((out.text.match(/then discard/g) || []).length, 1);
    assert.match(out.text, /# 5\.77\.1\.0\/24 → 91\.0\.0\.0\/24 · .* · skynet, skynet-net/);
  });

  it('назначение клиента внутри провайдера выбрасывается как вложенное', () => {
    const out = summary('src24-90', [
      item('pin', 'provider', ['91.0.0.0/16'], [['5.77.1.0/24', 900, 0]]),
      item('client', 'client', ['91.0.4.0/22'], [['5.77.1.0/24', 400, 0]]),
    ]);
    assert.equal(out.rules, 1);
    assert.match(out.text, /match destination 91\.0\.0\.0\/16/);
    assert.doesNotMatch(out.text, /match destination 91\.0\.4\.0\/22/);
    const client = out.events.find((ev) => ev.name === 'client');
    assert.equal(client.kept, 0);
    assert.equal(client.duplicates, 1);
  });

  it('разные источники на одно назначение остаются оба, по убыванию трафика', () => {
    const out = summary('src24-90', [
      item('a', 'client', ['91.0.0.0/24'], [['5.77.1.0/24', 100, 0]]),
      item('b', 'client', ['91.0.0.0/24'], [['8.8.8.0/24', 900, 0]]),
    ]);
    assert.equal(out.rules, 2);
    assert.ok(out.text.indexOf('8.8.8.0/24') < out.text.indexOf('5.77.1.0/24'));
  });

  it('имя правила по условиям: у одного правила в двух сборках одно имя', () => {
    const one = summary('src24-90', [item('a', 'client', ['91.0.0.0/24'], [['5.77.1.0/24', 100, 0]])]);
    const two = summary('src24-90', [item('b', 'client', ['91.0.0.0/24'], [['5.77.1.0/24', 700, 0]])]);
    const name = (text) => /flow route (gnta-[0-9a-f]{10}) match destination/.exec(text)[1];
    assert.equal(name(one.text), name(two.text));
  });
});

describe('общий фильтр: по пакету', () => {
  it('действие не выбирается, правило на назначение без источника', () => {
    const out = summary('packet-src', [item('a', 'client', ['91.0.0.0/24', '91.0.1.0/24'], [['5.77.1.0/24', 900, 0]])]);
    assert.equal(out.rules, 2);
    assert.match(out.text, /match source-port 1024-65535/);
    assert.match(out.text, /match packet-length 1000-1500/);
    assert.doesNotMatch(out.text, /^set .* then /m);
    assert.doesNotMatch(out.text, /match source \d/);
  });

  it('разный диапазон пакета на одном назначении не сливается', () => {
    const a = item('a', 'client', ['91.0.0.0/24'], [['5.77.1.0/24', 900, 0]]);
    const b = item('b', 'net', ['91.0.0.0/24'], [['5.77.1.0/24', 900, 0]]);
    b.band = { lo: 300, hi: 1500 };
    const out = summary('packet-src', [a, b]);
    assert.equal(out.rules, 2);
  });
});

describe('общий фильтр: какие аварии берутся', () => {
  const nowTs = Date.parse('2026-10-12T07:00:00Z');
  const ev = (scope, scopeId, lastHotMinute, name = scopeId) => ({ scope, scopeId, name, live: lastHotMinute ? { lastHotMinute } : null });

  it('старая горячая минута и её отсутствие — в пропущенные', () => {
    const { ready, skipped } = activeObjects([
      ev('client', '1', '2026-10-12 06:55:00'),
      ev('client', '2', '2026-10-12 06:30:00'),
      ev('client', '3', null),
    ], nowTs);
    assert.deepEqual(ready.map((o) => o.scopeId), ['1']);
    assert.match(skipped.find((s) => s.scopeId === '2').reason, /30 мин назад/);
    assert.equal(skipped.find((s) => s.scopeId === '3').reason, 'нет горячей минуты');
  });

  it('два события одного объекта — одна авария с самой свежей минутой', () => {
    const { ready } = activeObjects([
      ev('client', '1', '2026-10-12 06:50:00'),
      ev('client', '1', '2026-10-12 06:56:00'),
    ], nowTs);
    assert.equal(ready.length, 1);
    assert.equal(ready[0].minute, '2026-10-12 06:56:00');
  });
});

describe('общий фильтр: адреса', () => {
  it('разбирает префикс и приводит адрес к сети', () => {
    assert.deepEqual(parseCidr('91.0.4.7/22'), { base: parseCidr('91.0.4.0/22').base, len: 22 });
    assert.equal(parseCidr('2a00::/32'), null);
    assert.equal(findVariant('src24-90').ratio, 90);
    assert.equal(findVariant('nope'), null);
  });
});
