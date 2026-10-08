'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  buildFlowspecReport,
  choosePacketBand,
  takeUntil,
  rateLimitHintMbps,
  routeSlug,
} = require('./detection-flowspec-report');

describe('срез сетей для FlowSpec', () => {
  it('берёт столько сетей, сколько нужно чтобы перейти долю', () => {
    const rows = [
      { prefix: 'a', attackBytes: 10, baselineBytes: 1 },
      { prefix: 'b', attackBytes: 10, baselineBytes: 0 },
      { prefix: 'c', attackBytes: 10, baselineBytes: 4 },
    ];
    const half = takeUntil(rows, 30, 0.5);
    assert.equal(half.n, 2);
    assert.equal(half.complete, true);
    assert.equal(half.baselineBytes, 1);
    const most = takeUntil(rows, 30, 0.9);
    assert.equal(most.n, 3);
    assert.equal(most.complete, true);
  });

  it('помечает неполный набор, если списка не хватило', () => {
    const cut = takeUntil([{ prefix: 'a', attackBytes: 10, baselineBytes: 0 }], 100, 0.5);
    assert.equal(cut.complete, false);
    assert.equal(cut.n, 1);
  });
});

describe('текст правил', () => {
  const report = buildFlowspecReport({
    scopeId: 'isp:verolayn',
    minute: '2026-10-07 17:04:00',
    baselineMinute: '2026-10-06 17:04:00',
    destinations: ['91.151.176.0/20'],
    row: {
      atk_all: 1000,
      atk_big: 900,
      atk_src: 900,
      base_src: 10,
      atk_dst: 800,
      base_dst: 12,
      atk_both: 790,
      base_both: 9,
      n16: 3,
      n24: 3,
      rows16: [['213.230.0.0/16', 500, 2], ['84.54.0.0/16', 300, 0], ['5.77.0.0/16', 100, 1]],
      rows24: [['213.230.86.0/24', 500, 0], ['84.54.73.0/24', 300, 0], ['5.77.1.0/24', 100, 0]],
    },
  });

  it('не выбирает действие за сотрудника в правиле по пакету', () => {
    const file = report.files.find((item) => item.id === 'packet-src');
    assert.match(file.text, /match protocol udp/);
    assert.match(file.text, /match source-port 1024-65535/);
    assert.match(file.text, /match packet-length 1000-1500/);
    assert.match(file.text, /# set routing-options flow route verolayn-pkt-src then rate-limit/);
    assert.match(file.text, /# set routing-options flow route verolayn-pkt-src then discard/);
    assert.doesNotMatch(file.text, /^set .* then /m);
  });

  it('по сетям даёт оба варианта и не упоминает AS', () => {
    const file = report.files.find((item) => item.id === 'src24-50');
    assert.match(file.text, /match source 213\.230\.86\.0\/24/);
    assert.match(file.text, /then discard/);
    assert.doesNotMatch(file.text, /match source-as|AS\d+/);
    assert.equal(report.nets.find((net) => net.mask === 24).total, 3);
    assert.equal(report.nets.find((net) => net.mask === 16).cuts.find((cut) => cut.ratio === 50).prefixes, 1);
    assert.equal(report.nets.find((net) => net.mask === 16).cuts.find((cut) => cut.ratio === 80).prefixes, 2);
  });

  it('подсказка лимита считается от нормы ×5 и округляется', () => {
    assert.equal(rateLimitHintMbps(41e6), 200);
    assert.equal(report.rateHintMbps, rateLimitHintMbps(10 * 8 / 60));
  });
});

describe('диапазон пакета', () => {
  const zeros = () => new Array(15).fill(0);

  it('Веролайн 07.10: флуд 1000–1500 Б', () => {
    const attack = zeros();
    attack[10] = 3.74e9; attack[11] = 3.74e9; attack[12] = 2.41e9; attack[13] = 2.62e9; attack[14] = 2.0e9;
    const quiet = zeros();
    quiet[12] = 10e6; quiet[13] = 10e6;
    const band = choosePacketBand(attack, quiet);
    assert.equal(band.lo, 1000);
    assert.equal(band.hi, 1500);
  });

  it('ПИН 08.10: флуд 300–1499 Б, обычный QUIC вычитается', () => {
    const attack = zeros();
    [2.96, 4.85, 5.45, 6.12, 7.05, 7.35, 7.45, 7.22, 7.49, 8.11, 7.03, 5.91]
      .forEach((g, i) => { attack[i + 3] = g * 1e9; });
    const quiet = zeros();
    quiet[12] = 300e6; quiet[13] = 400e6;
    const band = choosePacketBand(attack, quiet);
    assert.ok(band.lo >= 300 && band.lo <= 500);
    assert.equal(band.hi, 1500);
    assert.ok(band.cover >= 0.9);
  });

  it('без превышения остаётся прежний диапазон', () => {
    const band = choosePacketBand(zeros(), zeros());
    assert.equal(band.fallback, true);
    assert.equal(band.lo, 1000);
  });
});

describe('имя правила', () => {
  it('берётся из идентификатора, без префикса isp', () => {
    assert.equal(routeSlug('isp:verolayn'), 'verolayn');
  });
});
