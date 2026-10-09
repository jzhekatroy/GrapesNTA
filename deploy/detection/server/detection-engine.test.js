'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  BASELINE_CACHE_MS,
  isBaselineCacheFresh,
  dedupeClientsByDisplayName,
  providerDisplayName,
  closedMinuteLagMinutes,
  clampClosedMinute,
  pendingMinutes,
  netBaselineSql,
  BASELINE_UDP_MEDIAN_CAP,
  BASELINE_UDP_MEDIAN_MIN_BPS,
} = require('./detection-engine');

describe('detection-engine net baseline', () => {
  it('норма UDP без минут выше 1.6 медианы часа (Искрателеком 09.10)', () => {
    const sql = netBaselineSql(true, 14);
    assert.equal(BASELINE_UDP_MEDIAN_CAP, 1.6);
    assert.match(sql, /udp_hour_median AS \(/);
    assert.match(sql, /quantileExact\(0\.5\)\(bps\) AS med/);
    assert.match(sql, /LEFT JOIN udp_hour_median AS um ON um\.scope = a\.scope/);
    assert.match(sql, /a\.proto != 'udp' OR \(NOT has\(cm\.minutes, a\.minute\) AND \(um\.med < 20000000 OR a\.bps <= 1\.6 \* um\.med\)\)/);
  });

  it('час с медианой UDP ниже 20 Мбит/с не чистится (ШПД, игры и VPN)', () => {
    assert.equal(BASELINE_UDP_MEDIAN_MIN_BPS, 20e6);
    assert.doesNotMatch(netBaselineSql(true, 14), /um\.med <= 0/);
  });

  it('запасной запрос без окон медиану не читает', () => {
    const sql = netBaselineSql(false, 14);
    assert.doesNotMatch(sql, /udp_hour_median/);
    assert.doesNotMatch(sql, /um\.med/);
  });
});

describe('detection-engine catch-up', () => {
  const at = (hm) => Date.parse(`2026-10-04T${hm}:00Z`);
  const fmt = (list) => list.map((ts) => new Date(ts).toISOString().slice(11, 16));

  it('свёртка закрыла пачку минут — считаем каждую по порядку (ШПД 04.10)', () => {
    assert.deepEqual(fmt(pendingMinutes(at('15:41'), at('15:38'))), ['15:39', '15:40', '15:41']);
    assert.deepEqual(fmt(pendingMinutes(at('15:46'), at('15:41'))), ['15:42', '15:43', '15:44', '15:45', '15:46']);
  });

  it('обычный тик — одна минута', () => {
    assert.deepEqual(fmt(pendingMinutes(at('15:30'), at('15:29'))), ['15:30']);
  });

  it('отставание больше окна — догоняем только последние 10 минут', () => {
    assert.deepEqual(fmt(pendingMinutes(at('16:00'), at('15:49'))), [
      '15:51', '15:52', '15:53', '15:54', '15:55', '15:56', '15:57', '15:58', '15:59', '16:00',
    ]);
  });

  it('без записанных минут в окне (перезапуск воркера) — только последняя', () => {
    assert.deepEqual(fmt(pendingMinutes(at('16:00'), null)), ['16:00']);
    assert.deepEqual(fmt(pendingMinutes(at('16:00'), 0)), ['16:00']);
  });
});

describe('detection-engine closed minute', () => {
  const now = Date.parse('2026-09-28T13:23:40Z');
  const saved = process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES;
  const restore = () => {
    if (saved === undefined) delete process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES;
    else process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES = saved;
  };

  it('оставляет минуту, которая уже старше запаса', () => {
    delete process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES;
    try {
      const ts = Date.parse('2026-09-28T13:10:00Z');
      assert.equal(clampClosedMinute(ts, now), ts);
    } finally {
      restore();
    }
  });

  it('по умолчанию обрезает минуту моложе четырёх минут', () => {
    delete process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES;
    try {
      assert.equal(closedMinuteLagMinutes(), 4);
      const ts = Date.parse('2026-09-28T13:23:00Z');
      assert.equal(clampClosedMinute(ts, now), Date.parse('2026-09-28T13:19:00Z'));
    } finally {
      restore();
    }
  });

  it('берёт запас из DETECTION_CLOSED_MINUTE_LAG_MINUTES', () => {
    try {
      process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES = '2';
      assert.equal(closedMinuteLagMinutes(), 2);
      const ts = Date.parse('2026-09-28T13:23:00Z');
      assert.equal(clampClosedMinute(ts, now), Date.parse('2026-09-28T13:21:00Z'));
      process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES = '0';
      assert.equal(closedMinuteLagMinutes(), 4);
      process.env.DETECTION_CLOSED_MINUTE_LAG_MINUTES = 'abc';
      assert.equal(closedMinuteLagMinutes(), 4);
    } finally {
      restore();
    }
  });

  it('пустую минуту не берёт', () => {
    assert.equal(clampClosedMinute(0, now), null);
    assert.equal(clampClosedMinute(NaN, now), null);
  });
});

describe('detection-engine baselines cache', () => {
  it('кэш живой только при данных внутри TTL', () => {
    const now = BASELINE_CACHE_MS * 2;
    const map = new Map([['net|10.0.0.0/24|all', { bps: 1 }]]);
    assert.equal(isBaselineCacheFresh({ at: now, map }, now), true);
    assert.equal(isBaselineCacheFresh({ at: now - BASELINE_CACHE_MS + 1, map }, now), true);
    assert.equal(isBaselineCacheFresh({ at: now - BASELINE_CACHE_MS, map }, now), false);
    assert.equal(isBaselineCacheFresh({ at: now, map: new Map() }, now), false);
    assert.equal(isBaselineCacheFresh({ at: 0, map }, now), false);
  });
});

describe('detection-engine client dedupe', () => {
  it('склеивает одно display_name и оставляет меньший числовой id', () => {
    const rows = dedupeClientsByDisplayName([
      { client_id: '106740', display_name: 'WEST CALL' },
      { client_id: '81993', display_name: 'WEST CALL' },
      { client_id: '1', display_name: 'Other' },
    ]);
    assert.deepEqual(
      rows.map((r) => r.client_id).sort((a, b) => Number(a) - Number(b)),
      ['1', '81993'],
    );
  });

  it('пустые имена не склеивает', () => {
    const rows = dedupeClientsByDisplayName([
      { client_id: '10', display_name: '' },
      { client_id: '11', display_name: '  ' },
    ]);
    assert.equal(rows.length, 2);
  });
});

describe('detection-engine provider name', () => {
  it('берёт название из справочника, а не entity id', () => {
    assert.equal(providerDisplayName('isp:verolayn', 'Веролайн', ''), 'Веролайн');
    assert.equal(providerDisplayName('isp:pin', '', 'ПИН'), 'ПИН');
    assert.equal(providerDisplayName('isp:verolayn', 'Веролайн', 'префикс'), 'Веролайн');
    assert.equal(providerDisplayName('isp:verolayn', '', ''), 'verolayn');
  });
});
