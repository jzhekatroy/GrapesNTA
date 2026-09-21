'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const P = require('../public/data/period-range.js');

const DAY_19 = { y: 2026, mo: 9, d: 19 };

describe('конец периода как первая невключённая минута', () => {
  // Запросы фильтруют `time >= ts_from AND time < ts_to`, поэтому «до 23:59»
  // теряло последнюю минуту суток.
  it('сутки целиком заканчиваются полуночью следующего дня', () => {
    assert.deepEqual(P.wholeDayPeriod(DAY_19), {
      from: '2026-09-19T00:00',
      to: '2026-09-20T00:00',
    });
  });

  it('полночь показывается как 24:00 предыдущих суток', () => {
    assert.deepEqual(P.endDisplayParts('2026-09-20T00:00'), { y: 2026, mo: 9, d: 19, h: 24, mi: 0 });
  });

  it('обычное время конца не сдвигается', () => {
    assert.deepEqual(P.endDisplayParts('2026-09-19T14:30'), { y: 2026, mo: 9, d: 19, h: 14, mi: 30 });
  });

  it('показ и хранение переводятся друг в друга без потерь', () => {
    for (const stored of ['2026-09-20T00:00', '2026-09-19T14:30', '2026-01-01T00:00']) {
      assert.equal(P.endStoredValue(P.endDisplayParts(stored)), stored);
    }
  });

  it('24:00 конца месяца уезжает в первое число следующего', () => {
    assert.equal(P.endStoredValue({ y: 2026, mo: 9, d: 30, h: 24, mi: 0 }), '2026-10-01T00:00');
  });
});

describe('выбор в календаре', () => {
  it('один день ищется за все сутки', () => {
    const period = P.buildRangePeriod(DAY_19, DAY_19, { h: 0, mi: 0 }, { h: 24, mi: 0 });
    assert.deepEqual(period, { from: '2026-09-19T00:00', to: '2026-09-20T00:00' });
    assert.ok(period.from < period.to, 'период должен проходить проверку from < to');
    assert.equal(P.isWholeDayPeriod(period), true);
  });

  it('диапазон можно тянуть справа налево', () => {
    const forward = P.buildRangePeriod(DAY_19, { y: 2026, mo: 9, d: 21 }, { h: 0, mi: 0 }, { h: 24, mi: 0 });
    const backward = P.buildRangePeriod({ y: 2026, mo: 9, d: 21 }, DAY_19, { h: 0, mi: 0 }, { h: 24, mi: 0 });
    assert.deepEqual(backward, forward);
    assert.deepEqual(forward, { from: '2026-09-19T00:00', to: '2026-09-22T00:00' });
  });

  it('время сужает выбранные сутки', () => {
    assert.deepEqual(
      P.buildRangePeriod(DAY_19, DAY_19, { h: 10, mi: 0 }, { h: 14, mi: 30 }),
      { from: '2026-09-19T10:00', to: '2026-09-19T14:30' },
    );
  });

  it('сутки целиком подсвечивают в календаре один день, а не два', () => {
    const period = P.wholeDayPeriod(DAY_19);
    const from = P.parseParts(period.from);
    const to = P.endDisplayParts(period.to);
    assert.equal(P.dayRangeState(DAY_19, from, to).inRange, true);
    assert.equal(P.dayRangeState({ y: 2026, mo: 9, d: 20 }, from, to).inRange, false);
  });
});

describe('подпись периода', () => {
  it('сутки целиком читаются как один день до 24:00', () => {
    assert.equal(P.formatPeriodLabel(P.wholeDayPeriod(DAY_19)), '19.09 00:00–24:00');
  });

  it('многодневный период называет обе даты', () => {
    assert.equal(
      P.formatPeriodLabel({ from: '2026-09-19T00:00', to: '2026-09-22T00:00' }),
      '19.09 00:00 — 21.09 24:00',
    );
  });

  it('битый период не выдаёт мусор', () => {
    assert.equal(P.formatPeriodLabel({ from: 'нет', to: '' }), 'Свой период');
  });
});

describe('пресет «Вчера»', () => {
  // Раньше пресет задавал 00:00–23:59 и терял последнюю минуту суток.
  it('берёт прошедшие сутки целиком', () => {
    assert.deepEqual(P.yesterdayPeriod({ y: 2026, mo: 9, d: 21 }), {
      from: '2026-09-20T00:00',
      to: '2026-09-21T00:00',
    });
  });

  it('переживает переход через начало месяца', () => {
    assert.deepEqual(P.yesterdayPeriod({ y: 2026, mo: 9, d: 1 }), {
      from: '2026-08-31T00:00',
      to: '2026-09-01T00:00',
    });
  });
});

describe('ввод времени', () => {
  // Пустая строка раньше превращалась в 0, и стереть ведущий ноль было нельзя.
  it('пустое поле не подставляет ноль', () => {
    assert.equal(P.clampTimePart('', 23), null);
    assert.equal(P.clampTimePart('   ', 23), null);
    assert.equal(P.clampTimePart('нет', 23), null);
  });

  it('число зажимается в допустимые границы', () => {
    assert.equal(P.clampTimePart('9', 23), 9);
    assert.equal(P.clampTimePart('99', 23), 23);
    assert.equal(P.clampTimePart('-5', 23), 0);
    assert.equal(P.clampTimePart('24', 24), 24);
    assert.equal(P.clampTimePart('7.9', 59), 7);
  });
});
