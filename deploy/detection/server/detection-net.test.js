'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  SIGNALS,
  isNetSpikeHit,
  isNetSpikeStrong,
  netSpikeMetrics,
  parseNetList,
} = require('./detection-signals');
const {
  portClientIds,
  clientNetMinuteSql,
  clientNetHourSql,
  hourBounds,
  nextMissingHour,
  netUsual,
  summarizeClientNets,
} = require('./detection-engine');
const {
  shouldSendNetSpike,
  shouldSkipTelegramForShare,
  pickAlertCandidates,
  pickNormalizeCandidates,
  isAlertAttack,
  isNetFocus,
  netSpikeVerdict,
  withClientVolume,
  formatAlertMessage,
  snapshotByProto,
} = require('./detection-telegram');

const HOUR = 3600 * 1000;

// 81050, 30.09 03:24 МСК: 37.75 Гбит/с в 95.129.234.0/24 при медиане часа
// 53 Мбит/с; весь клиент ~46 Гбит/с, рост ×1.0.
function hotRow(minute, extra = {}) {
  return {
    scope: 'client',
    scope_id: '81050',
    proto: 'all',
    minute,
    bps: 46e9,
    pps: 5e6,
    growth_bps: 0.98,
    growth_pps: 0.95,
    net_top: '95.129.234.0/24',
    net_bps: 37.75e9,
    net_pps: 3.2e6,
    net_usual_bps: 53.3e6,
    net_usual_pps: 9000,
    net_growth_bps: 708.5,
    net_growth_pps: 355,
    net_udp_bps: 37e9,
    net_tcp_bps: 0.7e9,
    net_list: '95.129.234.0/24:37750000000:708.5',
    ...extra,
  };
}

function quietRow(minute) {
  return {
    scope: 'client',
    scope_id: '81050',
    proto: 'all',
    minute,
    bps: 45e9,
    growth_bps: 0.97,
    growth_pps: 0.96,
    net_top: '',
    net_bps: 0,
    net_growth_bps: null,
    net_growth_pps: null,
  };
}

describe('сигнал сети /24', () => {
  it('горит при росте ×4 и объёме от 1 Гбит/с', () => {
    assert.equal(isNetSpikeHit(hotRow('2026-09-30 00:24:00')), true);
    assert.equal(isNetSpikeHit(hotRow('m', { net_bps: 0.9e9 })), false);
    assert.equal(isNetSpikeHit(hotRow('m', { net_growth_bps: 3.5, net_growth_pps: 1 })), false);
    assert.equal(isNetSpikeHit(hotRow('m', { net_growth_bps: 1, net_growth_pps: 4.2 })), true);
    assert.equal(isNetSpikeHit(quietRow('m')), false);
  });

  it('закачка TCP крупными пакетами не горит, TCP-флуд мелкими — горит', () => {
    // 72313 30.09 01:57: 6.3 Гбит/с на 194.55.234.147:8080, TCP, пакет 1458 Б, 17 источников.
    const download = hotRow('m', {
      net_bps: 6.3e9, net_pps: 6.3e9 / 8 / 1458, net_tcp_bps: 6.24e9, net_udp_bps: 0.06e9,
      net_growth_bps: 9.3, net_growth_pps: 9,
    });
    assert.equal(isNetSpikeHit(download), false);
    // 72573 30.09 07:09: 1.67 Гбит/с на 85.192.30.234:443, TCP, пакет 101 Б, 1889 источников.
    const flood = hotRow('m', {
      net_bps: 1.67e9, net_pps: 1.67e9 / 8 / 101, net_tcp_bps: 1.67e9, net_udp_bps: 0,
      net_growth_bps: 35, net_growth_pps: 40,
    });
    assert.equal(isNetSpikeHit(flood), true);
  });

  it('без нормы (growth null) не горит', () => {
    assert.equal(isNetSpikeHit(hotRow('m', { net_growth_bps: null, net_growth_pps: null })), false);
  });

  it('сильный рост ×20 отличает от обычного горячего', () => {
    assert.equal(isNetSpikeStrong(hotRow('m')), true);
    assert.equal(isNetSpikeStrong(hotRow('m', { net_growth_bps: 9.4, net_growth_pps: 2 })), false);
  });

  it('разбирает список сетей и метрики', () => {
    assert.deepEqual(parseNetList('1.2.3.0/24:2000000000:9.4,5.6.7.0/24:1500000000:5.0'), [
      { net: '1.2.3.0/24', bps: 2e9, growth: 9.4 },
      { net: '5.6.7.0/24', bps: 1.5e9, growth: 5 },
    ]);
    const m = netSpikeMetrics(hotRow('m'));
    assert.equal(m.net, '95.129.234.0/24');
    assert.equal(m.growth, 708.5);
  });
});

describe('нормы и сводка сетей в движке', () => {
  it('берёт только клиентов на портах', () => {
    assert.deepEqual(portClientIds([
      { scope: 'client', scopeId: '1', bindMode: 'ports' },
      { scope: 'client', scopeId: '2', bindMode: 'prefixes' },
      { scope: 'net', scopeId: '10.0.0.0/24' },
    ]), ['1']);
  });

  it('норма: пик не выше p95×4, не ниже медианы часа ×1.6 и пола', () => {
    assert.equal(netUsual(400e6, 300e6, 0, 20e6), 400e6);
    assert.equal(netUsual(5e9, 100e6, 0, 20e6), 400e6);
    assert.equal(netUsual(100e6, 90e6, 200e6, 20e6), 320e6);
    assert.equal(netUsual(0, 0, 0, 20e6), 20e6);
  });

  it('сводка клиента: самая выросшая горячая сеть сверху, холодные не попадают', () => {
    const rows = [
      { client_id: '81050', net: '95.129.234.0/24', bytes: 37.75e9 * 60 / 8, packets: 3.2e6 * 60, udp_bytes: 0, tcp_bytes: 0 },
      { client_id: '81050', net: '10.0.0.0/24', bytes: 2e9 * 60 / 8, packets: 1e5 * 60, udp_bytes: 0, tcp_bytes: 0 },
      { client_id: '81050', net: '10.0.1.0/24', bytes: 5e9 * 60 / 8, packets: 5e5 * 60, udp_bytes: 0, tcp_bytes: 0 },
    ];
    const norms = new Map([
      ['81050|95.129.234.0/24', { bpsPeak: 60e6, bpsTyp: 40e6, ppsPeak: 9000, ppsTyp: 7000 }],
      ['81050|10.0.0.0/24', { bpsPeak: 400e6, bpsTyp: 300e6, ppsPeak: 2e4, ppsTyp: 1.5e4 }],
      ['81050|10.0.1.0/24', { bpsPeak: 4.8e9, bpsTyp: 4e9, ppsPeak: 6e5, ppsTyp: 5e5 }],
    ]);
    const out = summarizeClientNets(rows, { norms, recent: new Map(), mature: true });
    const fields = out.get('81050');
    assert.equal(fields.net_top, '95.129.234.0/24');
    assert.ok(fields.net_growth_bps > 600);
    const listed = parseNetList(fields.net_list).map((x) => x.net);
    assert.deepEqual(listed, ['95.129.234.0/24', '10.0.0.0/24']);
  });

  it('пока сводок меньше суток, рост не считается', () => {
    const rows = [{ client_id: '81050', net: '95.129.234.0/24', bytes: 37.75e9 * 60 / 8, packets: 1 }];
    const out = summarizeClientNets(rows, { norms: new Map(), recent: new Map(), mature: false });
    assert.equal(out.size, 0);
  });

  it('ищет пропущенный час сверху вниз', () => {
    const last = Date.parse('2026-10-01T07:00:00Z');
    const done = new Set([last, last - HOUR]);
    assert.equal(nextMissingHour(last, last - 5 * HOUR, done), last - 2 * HOUR);
    assert.equal(nextMissingHour(last, last - HOUR, done), null);
  });

  it('границы часа берут хвост экспорта как у минуты', () => {
    const b = hourBounds(Date.parse('2026-10-01T07:00:00Z'));
    assert.equal(b.from, '2026-10-01 07:00:00');
    assert.equal(b.to, '2026-10-01 08:00:00');
    assert.equal(b.until, '2026-10-01 08:04:00');
  });

  it('SQL режет по клиентам на портах и полу объёма', () => {
    const minuteSql = clientNetMinuteSql();
    assert.match(minuteSql, /f\.dst_client IN \{clients:Array\(String\)\}/);
    assert.match(minuteSql, /bytes \* 8 \/ 60 >= \{minBps:Float64\}/);
    const hourSql = clientNetHourSql();
    assert.match(hourSql, /^\s*INSERT INTO .*traffic_client_net_1h/m);
    assert.match(hourSql, /toStartOfMinute\(f\.time_flow_start_ns\)/);
    assert.match(hourSql, /HAVING bps_max >= \{minBps:Float64\}/);
  });
});

describe('алерт по сети /24', () => {
  const m0 = '2026-09-30 00:24:00';
  const m1 = '2026-09-30 00:23:00';
  const m2 = '2026-09-30 00:22:00';

  it('рост ×708 открывает событие сразу, без серии', () => {
    const hot = (row) => isNetSpikeHit(row);
    assert.equal(shouldSendNetSpike([hotRow(m0), quietRow(m1)], hot, 2), true);
  });

  it('рост ×9 ждёт вторую минуту', () => {
    const weak = { net_growth_bps: 9.4, net_growth_pps: 2 };
    const hot = (row) => isNetSpikeHit(row);
    assert.equal(shouldSendNetSpike([hotRow(m0, weak), quietRow(m1)], hot, 2), false);
    assert.equal(shouldSendNetSpike([hotRow(m0, weak), hotRow(m1, weak), quietRow(m2)], hot, 2), true);
  });

  it('pickAlertCandidates даёт net_spike на клиенте, а объём клиента молчит', () => {
    const row = hotRow(m0);
    const prev = new Map([['client|81050', [quietRow(m1), quietRow(m2)]]]);
    const picked = pickAlertCandidates([row], prev, 1.6, { streak: 3, alertScope: 'all' });
    assert.deepEqual(picked.map((c) => c.signal), [SIGNALS.net_spike]);
    assert.equal(picked[0].objectKey, 'client|81050');
  });

  it('активное событие сети не открывается повторно', () => {
    const row = hotRow(m0);
    const picked = pickAlertCandidates([row], new Map(), 1.6, {
      streak: 3,
      activeKeys: new Set(['client|81050|net_spike']),
    });
    assert.equal(picked.length, 0);
  });

  it('закрывается после десяти тихих минут, импульсы держат одно событие', () => {
    const activeByKey = new Map([['client|81050|net_spike', {
      id: 'client|81050|net_spike|2026-09-30 00:24:00',
      scope: 'client',
      scopeId: '81050',
      signal: SIGNALS.net_spike,
    }]]);
    const quietMinutes = (n) => Array.from({ length: n }, (_, i) => quietRow(`2026-09-30 00:${String(23 - i).padStart(2, '0')}:00`));
    const closed = pickNormalizeCandidates([quietRow(m0)], new Map([['client|81050', quietMinutes(9)]]), 1.6, {
      activeByKey,
      settings: { normalizeStreak: 3 },
    });
    assert.equal(closed.length, 1);
    const early = pickNormalizeCandidates([quietRow(m0)], new Map([['client|81050', quietMinutes(3)]]), 1.6, {
      activeByKey,
      settings: { normalizeStreak: 3 },
    });
    assert.equal(early.length, 0);
    const pulse = [...quietMinutes(4)];
    pulse[4] = hotRow('2026-09-30 00:19:00');
    pulse.push(...quietMinutes(9).slice(5));
    const kept = pickNormalizeCandidates([quietRow(m0)], new Map([['client|81050', pulse]]), 1.6, {
      activeByKey,
      settings: { normalizeStreak: 3 },
    });
    assert.equal(kept.length, 0);
  });

  it('доля от клиента сеть не глушит', () => {
    const byProto = { all: hotRow(m0) };
    assert.equal(shouldSkipTelegramForShare([SIGNALS.net_spike], { byProto }, { volumeMinSharePct: 10 }), false);
  });

  it('пик загрузки в сети атакой не считается, остальное — атака', () => {
    assert.equal(isAlertAttack({ kind: 'benign_peak', reason: 'пик загрузки · узкий источник' }, [SIGNALS.net_spike]), false);
    assert.equal(isAlertAttack({ kind: 'benign_peak', reason: 'нет явных признаков атаки' }, [SIGNALS.net_spike]), true);
  });

  it('вердикт по сети: кратность сети, а строки объёма — по клиенту', () => {
    const net = netSpikeMetrics(hotRow(m0));
    assert.equal(isNetFocus(net, { kind: 'benign_peak' }), true);
    assert.equal(isNetFocus(net, { kind: 'amplification' }), false);
    const v = netSpikeVerdict(net, {});
    assert.ok(v.hourRatio > 700);
    assert.equal(v.kind, 'carpet');
    const shown = withClientVolume(v, { hourP95: 40e9, hourP999: 47e9, hourCeiling: 47e9, hourRatio: 0.98 });
    assert.equal(shown.hourRatio, 0.98);
    assert.equal(shown.hourCeiling, 47e9);
    assert.ok(shown.netHourRatio > 700);
  });

  it('в тексте есть строка «Сеть /24» с нормой и кратностью', () => {
    const row = hotRow(m0, {
      net_list: '95.129.234.0/24:37750000000:708.5,95.129.235.0/24:1200000000:6.1',
    });
    const text = formatAlertMessage({
      name: '81050',
      scope: 'client',
      scopeId: '81050',
      minute: m0,
      threshold: 1.6,
      byProto: { all: row },
      verdict: { kind: 'volumetric', reason: 'топ IP 90%' },
      investigate: {},
      signals: [SIGNALS.net_spike],
    });
    assert.match(text, /^🔴 <b>[A-Z]*-?флуд в сеть \/24<\/b> · ID <b>81050<\/b>/i);
    assert.match(text, /<b>В 709 раз больше обычного:<\/b> 37\.8 Гбит\/с в 95\.129\.234\.0\/24, обычно 53\.3 Мбит\/с/);
    assert.match(text, /Ещё сети: 95\.129\.235\.0\/24 — 1\.20 Гбит\/с ×6\.1/);
  });

  it('без сигнала сети строки нет', () => {
    const text = formatAlertMessage({
      name: '81050',
      scope: 'client',
      scopeId: '81050',
      minute: m0,
      threshold: 1.6,
      byProto: { all: hotRow(m0) },
      verdict: { kind: 'volumetric' },
      investigate: {},
      signals: [SIGNALS.volume],
    });
    assert.doesNotMatch(text, /в сеть \/24|в 95\.129\.234\.0\/24/);
  });

  it('снимок события хранит поля сети строками и числами', () => {
    const snap = snapshotByProto({ byProto: { all: hotRow(m0) } });
    assert.equal(snap.all.net_top, '95.129.234.0/24');
    assert.equal(snap.all.net_bps, 37.75e9);
  });
});
