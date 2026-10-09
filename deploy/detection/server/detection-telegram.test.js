'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { carpetHoldGrowth, isCarpetHolding } = require('./detection-signals');
const {
  DEFAULT_GROWTH_THRESHOLD,
  DEFAULT_ALERT_SCOPE,
  DEFAULT_ALERT_KIND,
  DEFAULT_STREAK,
  DEFAULT_NORMALIZE_STREAK,
  DEFAULT_TELEGRAM_API_URL,
  DEFAULT_MIN_CLIENT_SHARE_PCT,
  normalizeMinSharePct,
  parasiticClientShare,
  shouldSkipTelegramForShare,
  shortErrorMsg,
  normalizeTelegramApiUrl,
  normalizeTelegramProxyUrl,
  redactTelegramProxyUrl,
  resolveTelegramProxyUrl,
  telegramMethodUrl,
  isAboveGrowthThreshold,
  shouldSendAlert,
  heaviestHotMinute,
  shouldSendNormalize,
  shouldNormalizeQuiet,
  shouldSendSignal,
  matchesAlertScope,
  matchesAlertKind,
  isAlertAttack,
  historyStatusSql,
  normalizeAlertKind,
  pickAlertCandidates,
  pickNormalizeCandidates,
  pickSilentNormalizeCandidates,
  formatAlertMessage,
  formatCutLine,
  formatVectorChangeMessage,
  formatPeakGrewMessage,
  formatSourceOperatorLines,
  vectorSnapshot,
  vectorChanged,
  rateDoubled,
  bumpPeak,
  mapSettings,
  alertStartMinute,
  signalSettings,
  mapEventRow,
  formatNormalizeMessage,
  snapshotByProto,
  PREV_ROWS_GAP_MINUTES,
  previousRowsLookbackMinutes,
  previousRowsScopeFilter,
  recentAttackPeaksSql,
  liveEventState,
  markHourHot,
  markCarpetHot,
  carpetVerdict,
  heaviestCarpetUdp,
  openedByCarpetOnly,
  HOUR_GATE_RATIO,
  parentProviderOf,
  parseCidr,
  concurrentAttacksLine,
  TELEGRAM_SKIP_PARENT_ACTIVE,
  isAttackMinute,
  attackPeakBps,
  isStrongUdpMinute,
} = require('./detection-telegram');
const { emptyInvestigate } = require('./detection-investigate');

describe('актуальное состояние открытого события', () => {
  const pulse = (hm, gbps, growth) => ({ minute: `2026-10-04 ${hm}:00`, bps: gbps * 1e9, growth_bps: growth });
  const opts = { alertMinute: '2026-10-04 16:19:00', threshold: 1.6, signal: 'volume', normalizeStreak: 10 };

  // verolayn, ШПД 04.10: удары раз в 2–3 минуты, между ними тишина.
  it('импульсы — атака идёт, видно последний удар и пик', () => {
    const rows = [
      pulse('16:18', 0.14, 0.3),
      pulse('16:19', 11.34, 21.3),
      pulse('16:20', 0.13, 0.2),
      pulse('16:21', 10.66, 20),
      pulse('16:22', 0.27, 0.5),
      pulse('16:23', 0.12, 0.2),
    ];
    const live = liveEventState(rows, { ...opts, nowTs: Date.parse('2026-10-04T16:29:00Z') });
    assert.equal(live.state, 'ongoing');
    assert.equal(live.lastHotMinute, '2026-10-04 16:21:00');
    assert.equal(live.sinceHotMin, 2);
    assert.equal(live.quietStreak, 2);
    assert.equal(live.peakMinute, '2026-10-04 16:19:00');
    assert.equal(live.hotMinutes, 2);
    assert.equal(live.lagMin, 6);
    assert.equal(live.normalizeStreak, 10);
    // 10.66 Гбит/с при росте ×20: норма 0.533, лишних 10.127.
    assert.ok(Math.abs(live.lastHotExcessBps - 10.66e9 * (1 - 1 / 20)) < 1);
    assert.ok(Math.abs(live.lastHotBaselineBps - 10.66e9 / 20) < 1);
  });

  it('тишина дольше трёх минут — затихает, счёт тихих минут до закрытия', () => {
    const rows = ['16:19', '16:20', '16:21', '16:22', '16:23', '16:24', '16:25']
      .map((hm, i) => pulse(hm, i === 0 ? 11 : 0.2, i === 0 ? 21 : 0.3));
    const live = liveEventState(rows, opts);
    assert.equal(live.state, 'fading');
    assert.equal(live.quietStreak, 6);
  });

  it('строк после срабатывания нет — состояния нет', () => {
    assert.equal(liveEventState([pulse('16:10', 1, 1)], opts), null);
  });
});

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
    assert.equal(DEFAULT_ALERT_KIND, 'all');
    assert.equal(DEFAULT_STREAK, 3);
    assert.equal(DEFAULT_NORMALIZE_STREAK, 3);
    assert.equal(DEFAULT_TELEGRAM_API_URL, 'https://api.telegram.org');
    assert.equal(DEFAULT_MIN_CLIENT_SHARE_PCT, 10);
  });

  it('доля паразита: отражение больше не глушится долей клиента', () => {
    const byProto = {
      all: { bps: 10.7e9, bytes: 10.7e9 * 60 / 8 },
      udp: {
        bps: 86.2e6 / 0.04,
        bytes: (86.2e6 / 0.04) * 60 / 8,
        amp_bytes: 86.2e6 * 60 / 8,
        amp_packets: (86.2e6 * 60 / 8) / 1096,
        amp_srcs: 14,
      },
    };
    const share = parasiticClientShare('amplification', { byProto });
    assert.ok(share != null && share < 0.02 && share > 0.005);
    assert.equal(shouldSkipTelegramForShare(['amplification'], { byProto }, { ampMinSharePct: 10 }), false);
    assert.equal(shouldSkipTelegramForShare(['amplification'], { byProto }, { ampMinSharePct: 0.5 }), false);
    assert.equal(shouldSkipTelegramForShare(['amplification'], { byProto }, { ampMinSharePct: 0 }), false);
  });

  // 80249: 2 млн п/с голого SYN по 70 Б — около 1.1 Гбит/с из 27, то есть 4%.
  it('доля паразита: SYN-флуд тоже не глушится долей клиента', () => {
    const synPackets = 2e6 * 60;
    const byProto = {
      all: {
        bps: 27e9, bytes: 27e9 * 60 / 8,
        syn_only_packets: synPackets, syn_only_bytes: synPackets * 70,
      },
    };
    assert.equal(shouldSkipTelegramForShare(['syn_flood'], { byProto }, { synMinSharePct: 10 }), false);
  });

  it('доля паразита: если любой вектор выше порога — Telegram шлём', () => {
    const byProto = {
      all: { bps: 10.7e9, growth_bps: 2.2, bytes: 10.7e9 * 60 / 8 },
      udp: {
        bytes: 2e9 * 60 / 8,
        amp_bytes: 86.2e6 * 60 / 8,
        amp_packets: (86.2e6 * 60 / 8) / 1096,
        amp_srcs: 14,
      },
    };
    assert.equal(shouldSkipTelegramForShare(['amplification'], { byProto }, {
      ampMinSharePct: 10,
      volumeMinSharePct: 10,
    }), false);
    assert.equal(shouldSkipTelegramForShare(['amplification', 'volume'], { byProto }, {
      ampMinSharePct: 10,
      volumeMinSharePct: 10,
    }), false);
  });

  it('доля паразита: без замера не глушим', () => {
    assert.equal(normalizeMinSharePct(-1), 10);
    assert.equal(normalizeMinSharePct(250), 100);
    assert.equal(shouldSkipTelegramForShare(['amplification'], { byProto: { all: { bps: 1e9 } } }, {
      ampMinSharePct: 10,
    }), false);
  });

  it('нормализует URL локального Bot API', () => {
    assert.equal(normalizeTelegramApiUrl(''), 'https://api.telegram.org');
    assert.equal(normalizeTelegramApiUrl('https://tba.pinspb.ru/'), 'https://tba.pinspb.ru');
    assert.equal(normalizeTelegramApiUrl('http://tba.pinspb.ru:8081/bot'), 'http://tba.pinspb.ru:8081');
    assert.equal(
      telegramMethodUrl('https://tba.pinspb.ru/', 'tok', 'sendMessage'),
      'https://tba.pinspb.ru/bottok/sendMessage',
    );
    assert.throws(() => normalizeTelegramApiUrl('ftp://tba.pinspb.ru'), /http/);
  });

  it('нормализует SOCKS/HTTP прокси и прячет пароль', () => {
    assert.equal(normalizeTelegramProxyUrl(''), '');
    assert.equal(
      normalizeTelegramProxyUrl('tgntasocks5temp20proxy:pass@63.141.251.43:31720'),
      'socks5://tgntasocks5temp20proxy:pass@63.141.251.43:31720',
    );
    assert.equal(
      normalizeTelegramProxyUrl('socks5h://u:p@10.0.0.1:1080'),
      'socks5h://u:p@10.0.0.1:1080',
    );
    assert.equal(
      redactTelegramProxyUrl('socks5://u:secret@63.141.251.43:31720'),
      'socks5://u@63.141.251.43:31720',
    );
    const stored = 'socks5://u:secret@63.141.251.43:31720';
    assert.equal(resolveTelegramProxyUrl('socks5://u@63.141.251.43:31720', stored), stored);
    assert.equal(resolveTelegramProxyUrl('', stored), '');
    assert.equal(
      resolveTelegramProxyUrl('socks5://u:new@63.141.251.43:31720', stored),
      'socks5://u:new@63.141.251.43:31720',
    );
    assert.throws(() => normalizeTelegramProxyUrl('ftp://x:1'), /socks5/);
    assert.throws(() => normalizeTelegramProxyUrl('socks5://host-without-port'), /порт/);
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
    // ШПД, 03.10: рассылка «по сетям» отсекала провайдера с 88 Гбит/с.
    assert.equal(matchesAlertScope({ scope: 'provider' }, 'net'), true);
    assert.equal(matchesAlertScope({ scope: 'provider' }, 'client'), false);
  });

  it('рассылка: атаки / всплески / всё, в историю пишем всё', () => {
    assert.equal(normalizeAlertKind(''), 'all');
    assert.equal(normalizeAlertKind('attack'), 'attack');
    assert.equal(normalizeAlertKind('peak'), 'peak');
    assert.equal(normalizeAlertKind('noise'), 'all');
    assert.equal(matchesAlertKind(true, 'all'), true);
    assert.equal(matchesAlertKind(false, 'all'), true);
    assert.equal(matchesAlertKind(true, 'attack'), true);
    assert.equal(matchesAlertKind(false, 'attack'), false);
    assert.equal(matchesAlertKind(true, 'peak'), false);
    assert.equal(matchesAlertKind(false, 'peak'), true);
    assert.equal(historyStatusSql('all'), "status IN ('normalized', 'peak')");
    assert.equal(historyStatusSql('attack'), "status = 'normalized'");
    assert.equal(historyStatusSql('peak'), "status = 'peak'");
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

  // ШПД 03.10: удар 1 минута через 1–2 тихих, три горячих подряд не набиралось.
  it('окно объёма: 3 горячих из 6 минут открывают импульсную атаку', () => {
    const impulses = [
      above('2026-10-03 12:16:00'),
      below('2026-10-03 12:15:00'),
      above('2026-10-03 12:14:00'),
      below('2026-10-03 12:13:00'),
      below('2026-10-03 12:12:00'),
      above('2026-10-03 12:11:00'),
      below('2026-10-03 12:10:00'),
    ];
    assert.equal(shouldSendAlert(impulses, 1.6, 3), false);
    assert.equal(shouldSendAlert(impulses, 1.6, 3, undefined, 6), true);
    const next = [above('2026-10-03 12:18:00'), below('2026-10-03 12:17:00'), ...impulses];
    assert.equal(shouldSendAlert(next, 1.6, 3, undefined, 6), false);
    assert.equal(shouldSendAlert(impulses.slice(0, 5), 1.6, 3, undefined, 3), false);
  });

  it('окно объёма: воркер под атакой пишет не каждую минуту — серия по времени', () => {
    const sparse = [
      above('2026-10-04 15:46:00'),
      above('2026-10-04 15:41:00'),
      below('2026-10-04 15:38:00'),
      below('2026-10-04 15:37:00'),
    ];
    assert.equal(shouldSendAlert(sparse, 1.6, 3, undefined, 6), true);
    const next = [above('2026-10-04 15:47:00'), ...sparse];
    assert.equal(shouldSendAlert(next, 1.6, 3, undefined, 6), false);
    const close = [above('2026-10-04 15:42:00'), above('2026-10-04 15:41:00'), below('2026-10-04 15:38:00')];
    assert.equal(shouldSendAlert(close, 1.6, 3, undefined, 6), false);
    const mixed = [above('2026-10-04 15:46:00'), below('2026-10-04 15:43:00'), above('2026-10-04 15:41:00')];
    assert.equal(shouldSendAlert(mixed, 1.6, 3, undefined, 6), false);
  });

  it('окно объёма: начало атаки — первый импульс, а не последний', () => {
    const history = [
      above('2026-10-03 12:16:00'),
      below('2026-10-03 12:15:00'),
      above('2026-10-03 12:14:00'),
      below('2026-10-03 12:13:00'),
      above('2026-10-03 12:12:00'),
      below('2026-10-03 12:11:00'),
      below('2026-10-03 12:10:00'),
      below('2026-10-03 12:09:00'),
      below('2026-10-03 12:08:00'),
      below('2026-10-03 12:07:00'),
      below('2026-10-03 12:06:00'),
      above('2026-10-03 12:05:00'),
    ];
    const hot = (row) => row.growth_bps >= 1.6;
    assert.equal(alertStartMinute(history, hot, 6), '2026-10-03 12:12:00');
    assert.equal(alertStartMinute(history, hot, 1), '2026-10-03 12:16:00');
  });

  it('настройки объёма: окно 6 и 10 тихих минут, у SYN прежняя тишина', () => {
    const settings = { streak: 3, normalizeStreak: 3, volumeWindow: 6, volumeQuiet: 10 };
    const volume = signalSettings(settings, 'volume');
    assert.equal(volume.streak, 3);
    assert.equal(volume.window, 6);
    assert.equal(volume.normalizeStreak, 10);
    assert.equal(signalSettings(settings, 'syn_flood').normalizeStreak, 3);
    assert.equal(signalSettings({ streak: 3 }, 'volume').window, 3);
  });

  it('строка «Резать» у провайдера: UDP, пакет, префиксы, порты случайные', () => {
    const line = formatCutLine({
      mode: 'carpet',
      scope: 'provider',
      scopeId: 'isp:verolayn',
      byProto: { all: { bps: 29.6e9, avg_packet_bytes: 1250 }, udp: { bps: 29.5e9 } },
      investigate: { destPort: { count: 50000, top: [{ port: 41234, share: 0.005 }] } },
      binding: { prefixes: ['91.151.176.0/20'] },
      verdict: { kind: 'carpet' },
    });
    assert.equal(line, 'Резать: входящий UDP, пакет около 1250 Б, на 91.151.176.0/20. Порты случайные, по порту не резать');
    const onePort = formatCutLine({
      mode: 'carpet',
      scope: 'provider',
      byProto: { all: { bps: 10e9, avg_packet_bytes: 1100 }, udp: { bps: 10e9 } },
      investigate: { destPort: { count: 2, top: [{ port: 443, share: 0.9 }] } },
      binding: { prefixes: [] },
    });
    assert.equal(onePort, 'Резать: входящий UDP, пакет около 1100 Б, на сети провайдера, порт 443');
    assert.equal(formatCutLine({
      mode: 'volumetric',
      scope: 'client',
      byProto: { all: { bps: 1e9 }, udp: { bps: 1e9 } },
    }), '');
    assert.equal(formatCutLine({
      mode: 'carpet',
      scope: 'provider',
      byProto: { all: { bps: 10e9 }, udp: { bps: 1e9 } },
    }), '');
  });

  it('шапка провайдера без isp: и строка «Резать» в алерте', () => {
    const text = formatAlertMessage({
      name: 'isp:verolayn',
      scope: 'provider',
      scopeId: 'isp:verolayn',
      minute: '2026-10-03 12:12:00',
      byProto: {
        all: { bps: 29.6e9, avg_packet_bytes: 1250, growth_bps: 29.6 },
        udp: { bps: 29.5e9 },
        tcp: { bps: 0.1e9 },
      },
      verdict: { kind: 'carpet', hourRatio: 29.6, hourCeiling: 1e9 },
      investigate: {
        sources: { dstIpCount: 4096, dstNetCount: 16 },
        destPort: { count: 50000, top: [{ port: 41234, share: 0.005 }] },
      },
      binding: { bindMode: 'prefixes', prefixes: ['91.151.176.0/20'], ports: [] },
      signals: ['volume'],
    });
    assert.match(text, /^🔴 <b>UDP-флуд по сети<\/b> · провайдер <b>verolayn<\/b>/);
    assert.match(text, /Цель: сети провайдера, не один сервер/);
    assert.match(text, /Резать: входящий UDP, пакет около 1250 Б, на 91\.151\.176\.0\/20\. Порты случайные, по порту не резать/);
    assert.match(text, /Весь трафик провайдера: /);
    assert.match(text, /Сети: 91\.151\.176\.0\/20/);
  });

  it('ковёр поверх TCP-фона подписан UDP и меряется по UDP', () => {
    // СКАЙНЭТ 09.10 13:19 МСК: TCP 54% — обычный фон, атака — UDP ×1.7.
    const text = formatAlertMessage({
      name: 'ООО "СКАЙНЭТ"',
      scope: 'client',
      scopeId: '71761',
      minute: '2026-10-09 10:19:00',
      byProto: {
        all: { bps: 28.8e9, growth_bps: 0.64 },
        tcp: { bps: 15.5e9 },
        udp: { bps: 13.3e9, growth_bps: 1.68 },
      },
      verdict: { kind: 'carpet', carpetOnly: true, hourRatio: 0.88, hourCeiling: 32.7e9 },
      investigate: {
        victim: { ip: '88.201.175.1', port: 443, protoLabel: 'TCP', share: 0.01 },
        sources: { dstIpCount: 1542, dstNetCount: 552 },
      },
      signals: ['volume'],
    });
    assert.match(text, /^🔴 <b>UDP-флуд по сети<\/b>/);
    assert.match(text, /<b>В 1,7 раза больше обычного по UDP:<\/b> 13\.3 Гбит\/с, обычно ~7\.92 Гбит\/с/);
    assert.doesNotMatch(text, /ниже обычного/);
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

  it('formatAlertMessage: саммери, полные метрики и без полей-дублей', () => {
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
    // Без вердикта не знаем, атака ли это: жёлтый и без слова «атака».
    assert.match(text, /^🟡 <b>Рост трафика выше порога<\/b> · сеть <b>10\.0\.0\.0\/24<\/b> · TestNet\n/);
    assert.match(text, /\nНачало: <b>01\.09 13:00 МСК<\/b>\n/);
    // Нормы часа нет — сравниваем с потолком 14 дней.
    assert.match(text, /<b>В 2 раза больше обычного:<\/b> 1\.00 Гбит\/с, обычно до ~500 Мбит\/с/);
    // Метрики — коротким блоком в конце.
    assert.match(text, /\n\nМетрики минуты\nВесь трафик: 1\.00 Гбит\/с · 1\.00 тыс\. п\/с\nTCP 50% · UDP 0\.1%$/);
    for (const gone of [/Порог/, /Что делать/, /14д/, /к часу/, /энтропия/, /попытки/, /рассылка/, /Минута:/]) {
      assert.doesNotMatch(text, gone);
    }
  });

  it('метрики: вышедшее за рамки помечено, подставленный текст экранирован', () => {
    const text = formatAlertMessage({
      name: 'Ромашка & Ко <НТА>',
      scope: 'client',
      scopeId: '101443',
      minute: '2026-09-06 16:27:00',
      threshold: 1.6,
      streak: 3,
      byProto: {
        all: { bps: 3e9, growth_bps: 4, bytes: 3e9 * 60 / 8 },
        tcp: { bps: 1e9, growth_bps: 1.1 },
        udp: {
          bps: 2e9, bytes: 2e9 * 60 / 8, avg_packet_bytes: 1200,
          amp_bytes: 1.125e10, amp_packets: 1.125e10 / 1200, amp_srcs: 40,
        },
      },
      verdict: { kind: 'amplification', reason: 'амплификация', hourRatio: 12 },
    });
    assert.match(text, /^🔴 <b>Амплификация<\/b> · <b>Ромашка &amp; Ко &lt;НТА&gt;<\/b> · ID <b>101443<\/b>/);
    assert.match(text, /Ответы усилителей: <b>1\.50 Гбит\/с<\/b> — 75% UDP клиента/);
    assert.match(text, /Откуда: 40 отражателей · ответы по ~1[\s ]?200 Б/);
    assert.match(text, /TCP 33% · UDP 67%/);
    assert.doesNotMatch(text, /‼/);
  });

  it('formatAlertMessage для обычного пика — жёлтый заголовок, без атаки', () => {
    const text = formatAlertMessage({
      name: 'TTK',
      scope: 'client',
      scopeId: '107397',
      minute: '2026-09-01 20:00:00',
      threshold: 1.6,
      streak: 3,
      byProto: { all: { bps: 9.4e9, growth_bps: 1.8 } },
      verdict: { kind: 'benign_peak', reason: 'в пределах нормы часа' },
    });
    assert.match(text, /^🟡 <b>Пик трафика, не атака<\/b> · <b>TTK<\/b> · ID <b>107397<\/b>/);
    assert.match(text, /Почему не атака: в пределах нормы часа/);
    assert.doesNotMatch(text, /🔴/);
  });

  it('mapEventRow отдаёт текст сообщения из снимка', () => {
    const event = mapEventRow({
      event_id: 'client|1|2026-09-01 10:00:00',
      scope: 'client',
      scope_id: '1',
      name: 'Hostland',
      status: 'peak',
      alert_minute: '2026-09-01 10:00:00',
      normalize_minute: '2026-09-01 10:00:00',
      threshold: 1.6,
      alert_json: JSON.stringify({
        all: { bps: 1 },
        verdict: { kind: 'benign_peak' },
        telegramText: '🟡 ПИК НАГРУЗКИ · обычный пик\nHostland',
      }),
      normalize_json: '',
    });
    assert.equal(event.alertText, '🟡 ПИК НАГРУЗКИ · обычный пик\nHostland');
    assert.equal(event.normalizeText, '');
    assert.equal(event.verdict.kind, 'benign_peak');
    assert.equal(event.signal, 'volume');
  });

  it('mapEventRow восстанавливает текст пика, если его ещё не сохраняли', () => {
    const event = mapEventRow({
      event_id: 'client|107397|2026-09-01 20:00:00',
      scope: 'client',
      scope_id: '107397',
      name: 'TTK',
      status: 'peak',
      alert_minute: '2026-09-01 20:00:00',
      threshold: 1.6,
      alert_json: JSON.stringify({
        all: { bps: 9.4e9, growth_bps: 1.8 },
        verdict: { kind: 'benign_peak', reason: 'в пределах нормы часа' },
      }),
    });
    assert.match(event.alertText, /^🟡 <b>Пик трафика, не атака<\/b> · <b>TTK<\/b> · ID <b>107397<\/b>/);
    assert.match(event.alertText, /Почему не атака: в пределах нормы часа/);
  });

  it('formatAlertMessage для загрузки пишет жёлтый пик, не атаку', () => {
    const text = formatAlertMessage({
      name: '94.26.164.0/24',
      scope: 'net',
      scopeId: '94.26.164.0/24',
      minute: '2026-09-08 07:36:00',
      threshold: 1.6,
      byProto: { all: { bps: 923.6e6, growth_bps: 3.76, avg_packet_bytes: 1507 } },
      verdict: { kind: 'benign_peak', reason: 'пик загрузки · TCP/443 · топ IP 99.4%', hourRatio: 15.21 },
      investigate: {
        victim: { ip: '94.26.164.176', port: 53495, protoLabel: 'TCP', share: 0.994 },
        l4src: [{ port: 443, proto: 6, share: 1 }],
      },
    });
    assert.match(text, /^🟡 <b>Пик трафика, не атака<\/b> · сеть <b>94\.26\.164\.0\/24<\/b>\n/);
    assert.match(text, /<b>В 15 раз больше обычного:<\/b> 924 Мбит\/с/);
    assert.match(text, /Почему не атака: похоже на загрузку — TCP на 443/);
    assert.doesNotMatch(text, /атака ·|Что делать|резать/);
  });

  it('пик загрузки + foreign_geo не становится атакой', () => {
    const verdict = { kind: 'benign_peak', reason: 'пик загрузки · TCP/443 · топ IP 94.0%', hourRatio: 3.56 };
    assert.equal(isAlertAttack(verdict, ['foreign_geo']), false);
    assert.equal(isAlertAttack(verdict, ['volume', 'foreign_geo']), false);
    assert.equal(isAlertAttack({ kind: 'benign_peak', reason: 'нет явных признаков атаки' }, ['foreign_geo']), true);
    assert.equal(isAlertAttack({ kind: 'volumetric' }, ['foreign_geo']), true);
    assert.equal(isAlertAttack({ kind: 'benign_peak', reason: 'пик загрузки · UDP/443' }, ['amplification']), true);
    const text = formatAlertMessage({
      name: 'Кузина Ольга Игоревна',
      scope: 'client',
      scopeId: '71500',
      minute: '2026-09-08 12:20:00',
      threshold: 1.6,
      byProto: {
        all: {
          bps: 115e6, growth_bps: 3.93, bytes: 115e6 * 60 / 8,
          foreign_bytes: 115e6 * 60 / 8, growth_foreign_share: 16.23,
          top_countries: 'US:1',
        },
      },
      verdict,
      signals: ['foreign_geo'],
      investigate: {
        victim: { ip: '176.116.245.82', port: 46846, protoLabel: 'TCP', share: 0.94 },
        l4src: [{ port: 443, proto: 6, share: 1 }],
      },
    });
    assert.match(text, /^🟡 <b>Пик трафика, не атака<\/b>/);
    assert.match(text, /Почему не атака: похоже на загрузку — TCP на 443/);
    assert.match(text, /Из-за рубежа: 100% · US 100%/);
    assert.doesNotMatch(text, /🔴/);
  });

  it('85783: CDN /24 + география — жёлтый пик, не атака', () => {
    const { refineClassification, classifyFromMetrics, KINDS } = require('./detection-classify');
    const first = classifyFromMetrics({
      all: {
        bps: 2.74e9, port_entropy: 1.46, syn_attempts: 3, answer_pct: 0,
        bytes: 2.74e9 * 60 / 8, foreign_bytes: 2.60e9 * 60 / 8,
        growth_foreign_share: 4.66, top_countries: 'SC:0.82,KZ:0.08,RU:0.05',
      },
      tcp: { bps: 2.64e9 },
      udp: { bps: 91e6 },
    }, { p95: 116e6, p999: 116e6 });
    const verdict = refineClassification(first, {
      victim: { ip: '43.175.146.57', port: 1935, protoLabel: 'TCP', share: 0.411 },
      source24: [{
        net24: '154.85.88.0/24', asn: 139057,
        asnName: 'ELD-AS-AP - Edgenext Legend Dynasty Pte. Ltd.',
        share: 0.814, ips: 37,
      }],
      l4src: [{ port: 42328, proto: 6, share: 0.01 }],
    });
    assert.equal(verdict.kind, KINDS.benign_peak);
    assert.equal(isAlertAttack(verdict, ['volume', 'foreign_geo']), false);
    const text = formatAlertMessage({
      name: 'ООО "ACE (as139341)"',
      scope: 'client',
      scopeId: '85783',
      minute: '2026-09-10 08:31:00',
      threshold: 1.6,
      byProto: {
        all: {
          bps: 2.74e9, growth_bps: 13.72, bytes: 2.74e9 * 60 / 8,
          foreign_bytes: 2.60e9 * 60 / 8, growth_foreign_share: 4.66,
          top_countries: 'SC:0.82,KZ:0.08,RU:0.05',
        },
        tcp: { bps: 2.64e9 },
        udp: { bps: 91e6 },
      },
      verdict,
      signals: ['volume', 'foreign_geo'],
      investigate: {
        victim: { ip: '43.175.146.57', port: 1935, protoLabel: 'TCP', share: 0.411, net24: '43.175.146.0/24' },
        source24: [{
          net24: '154.85.88.0/24', asn: 139057,
          asnName: 'ELD-AS-AP - Edgenext Legend Dynasty Pte. Ltd.',
          share: 0.814, ips: 37,
        }],
        l4src: [{ port: 42328, proto: 6, share: 0.01 }],
      },
    });
    assert.match(text, /^🟡 <b>Пик трафика, не атака<\/b> · <b>ООО "ACE \(as139341\)"<\/b> · ID <b>85783<\/b>/);
    assert.match(text, /<b>В 24 раза больше обычного:<\/b> 2\.74 Гбит\/с, обычно 116 Мбит\/с/);
    assert.match(text, /Почему не атака: похоже на загрузку — с 154\.85\.88\.0\/24 \(AS139057 Edgenext Legend Dynasty\) · TCP на 1935 · 81% трафика/);
    assert.match(text, /Из-за рубежа: 95% · SC 82% · KZ 8% · RU 5%/);
    assert.match(text, /TCP 96% · UDP 3%/);
    assert.doesNotMatch(text, /🔴|L4 откуда|Что делать/);
  });

  it('81050: шапка amp — без паразита, чужого L4 и тихой заграницы', () => {
    const text = formatAlertMessage({
      name: 'АО "Когнитивные машины"',
      scope: 'client',
      scopeId: '81050',
      minute: '2026-09-08 11:42:00',
      threshold: 1.6,
      byProto: {
        all: {
          bps: 15.5e9, growth_bps: 0.32, bytes: 15.5e9 * 60 / 8,
          foreign_bytes: 7.31e9 * 60 / 8, growth_foreign_share: 0.68, top_countries: 'RU:0.49,CZ:0.22',
        },
        tcp: { bps: 12.2e9 },
        udp: {
          bps: 2.25e9, bytes: 2.25e9 * 60 / 8, avg_packet_bytes: 637,
          amp_bytes: 516e6 * 60 / 8, amp_packets: (516e6 * 60 / 8) / 1136, amp_srcs: 36,
          growth_amp: 8.2,
        },
      },
      verdict: { kind: 'amplification', reason: 'амплификация', hourRatio: 0.29, hourCeiling: 53e9 },
      investigate: {
        victim: { ip: '185.129.101.255', port: 0, proto: 47, protoLabel: '47', share: 0.057, net24: '185.129.101.0/24' },
        l4src: [
          { port: 443, proto: 6, share: 0.43 },
          { port: 80, proto: 6, share: 0.06 },
          { port: 8443, proto: 6, share: 0.06 },
          { port: 53, proto: 17, share: 0.03 },
        ],
      },
    });
    assert.match(text, /^🔴 <b>Амплификация DNS<\/b> · <b>АО "Когнитивные машины"<\/b> · ID <b>81050<\/b>/);
    assert.match(text, /<b>В 8,2 раза больше обычного:<\/b> 516 Мбит\/с ответов усилителей, обычно ~62\.9 Мбит\/с/);
    assert.match(text, /Откуда: 36 отражателей · ответы по ~1[\s ]?136 Б/);
    assert.match(text, /\n   порт 53\n/);
    assert.match(text, /Весь трафик клиента: 15\.5 Гбит\/с \(обычно 53\.0 Гбит\/с\)/);
    // GRE-адрес по байтам и TCP/443 — чужой трафик, не цель отражения.
    assert.doesNotMatch(text, /185\.129\.101\.255|443|Паразит|Откуда порты|Там порты|Из-за рубежа/);
  });

  it('amp в один IP: в «Куда» пишет /24 и сам адрес', () => {
    const ampBytes = 188e6 * 60 / 8;
    const text = formatAlertMessage({
      name: 'клиент',
      scope: 'client',
      scopeId: '1',
      minute: '2026-09-10 12:00:00',
      threshold: 1.6,
      byProto: {
        all: { bps: 1.06e9, bytes: 1.06e9 * 60 / 8 },
        udp: {
          bps: 188e6 / 0.35, bytes: ampBytes / 0.35,
          amp_bytes: ampBytes, amp_packets: ampBytes / 827, amp_srcs: 45,
        },
      },
      verdict: { kind: 'amplification', reason: 'амплификация', hourRatio: 0.86, hourCeiling: 1.23e9 },
      investigate: {
        l4src: [
          { port: 53, proto: 17, share: 0.2 },
          { port: 123, proto: 17, share: 0.1 },
          { port: 1900, proto: 17, share: 0.05 },
        ],
        ampDest24: [{ net24: '185.221.214.0/24', ips: 1, share: 1, bps: 188e6 }],
        ampDestIp: [{ ip: '185.221.214.17', share: 1, bps: 188e6 }],
        ampDestPort: { count: 1, top: [{ port: 7709, share: 1 }] },
      },
    });
    assert.match(text, /^🔴 <b>Амплификация DNS\/NTP и др\.<\/b>/);
    assert.match(text, /Ответы усилителей: <b>188 Мбит\/с<\/b> — 35% UDP клиента/);
    assert.match(text, /Куда: 1 адрес в 185\.221\.214\.0\/24\n   185\.221\.214\.17 — 100%/);
    assert.match(text, /Порты назначения: 1\n   7709 — 100%/);
    assert.match(text, /Откуда: 45 отражателей · ответы по ~827 Б\n   порт 53\n   порт 123\n   порт 1900/);
    assert.doesNotMatch(text, /Там порты|Топ 5/);
  });

  it('amp: топ портов без ведущего двоеточия, сети и IP раздельно', () => {
    const ampBytes = 591e6 * 60 / 8;
    const text = formatAlertMessage({
      name: 'HETZNER',
      scope: 'client',
      scopeId: '79616',
      minute: '2026-09-10 14:48:00',
      threshold: 1.6,
      byProto: {
        all: { bps: 42.9e9, bytes: 42.9e9 * 60 / 8 },
        udp: {
          bps: 9.41e9, bytes: 9.41e9 * 60 / 8,
          amp_bytes: ampBytes, amp_packets: ampBytes / 878, amp_srcs: 24,
        },
      },
      verdict: { kind: 'amplification', reason: 'амплификация', hourRatio: 0.53, hourCeiling: 80.2e9 },
      investigate: {
        l4src: [{ port: 443, proto: 6, share: 0.4 }],
        ampSrcPort: {
          count: 3,
          top: [
            { port: 53, share: 0.48 },
            { port: 123, share: 0.31 },
            { port: 1900, share: 0.21 },
          ],
        },
        ampDest24: [
          { net24: '65.109.94.0/24', ips: 1, share: 0.56, bps: 333e6 },
          { net24: '65.21.150.0/24', ips: 1, share: 0.21, bps: 126e6 },
        ],
        ampDestIp: [
          { ip: '65.109.94.78', share: 0.56, bps: 333e6 },
          { ip: '65.21.150.220', share: 0.21, bps: 126e6 },
        ],
        ampDestPort: {
          count: 6,
          top: [
            { port: 443, share: 0.56 },
            { port: 49740, share: 0.21 },
          ],
        },
      },
    });
    assert.match(text, /^🔴 <b>Амплификация DNS\/NTP и др\.<\/b> · <b>HETZNER<\/b> · ID <b>79616<\/b>/);
    assert.match(text, /Ответы усилителей: <b>591 Мбит\/с<\/b> — 6% UDP клиента/);
    assert.match(text, /Куда: 2 адреса в 65\.109\.94\.0\/24 56% · 65\.21\.150\.0\/24 21%\n   65\.109\.94\.78 — 56%\n   65\.21\.150\.220 — 21%/);
    assert.match(text, /Порты назначения: 6\n   443 — 56%\n   49740 — 21%/);
    assert.match(text, /Откуда: 24 отражателя · ответы по ~878 Б\n   порт 53 — 48%\n   порт 123 — 31%\n   порт 1900 — 21%/);
    // TCP/443 из общего L4 — чужой трафик, в отражатели не попадает.
    assert.doesNotMatch(text, /порты 443|Откуда порты|Там порты|L4 откуда/);
  });

  it('81953: куда — топ /24 только по UDP с усилителей', () => {
    const ampBytes = 174e6 * 60 / 8;
    const text = formatAlertMessage({
      name: 'ООО «Delta Telecom AS29049»',
      scope: 'client',
      scopeId: '81953',
      minute: '2026-09-10 07:46:00',
      threshold: 1.6,
      byProto: {
        all: { bps: 4.68e9, bytes: 4.68e9 * 60 / 8 },
        tcp: { bps: 3.59e9 },
        udp: {
          bps: 174e6 / 0.16, bytes: ampBytes / 0.16,
          amp_bytes: ampBytes, amp_packets: ampBytes / 1419, amp_srcs: 13,
        },
      },
      verdict: { kind: 'amplification', reason: 'амплификация', hourRatio: 0.67, hourCeiling: 6.97e9 },
      investigate: {
        victim: { ip: '188.143.1.10', port: 443, protoLabel: 'TCP', share: 0.017 },
        l4src: [{ port: 53, proto: 17, share: 0.04 }],
        ampSrcPort: { count: 1, top: [{ port: 53, share: 1 }] },
        ampDest24: [
          { net24: '31.171.101.0/24', ips: 10, share: 0.99, bps: 172e6 },
          { net24: '91.218.160.0/24', ips: 1, share: 0.01 },
        ],
        ampDestIp: [
          { ip: '31.171.101.14', share: 0.12, bps: 20e6 },
          { ip: '31.171.101.88', share: 0.11, bps: 18e6 },
        ],
        ampDestPort: {
          count: 214,
          top: [
            { port: 53, share: 0.022 },
            { port: 443, share: 0.005 },
            { port: 55094, share: 0.004 },
            { port: 14397, share: 0.004 },
            { port: 8010, share: 0.004 },
          ],
        },
      },
    });
    assert.match(text, /^🔴 <b>Амплификация DNS<\/b>/);
    assert.match(text, /Ответы усилителей: <b>174 Мбит\/с<\/b> — 16% UDP клиента/);
    // Адреса размазаны (топ 12%), поэтому цель — сети клиента по UDP с усилителей.
    assert.match(text, /Куда: 10 адресов в 31\.171\.101\.0\/24 99%\n   31\.171\.101\.14 — 12%\n   31\.171\.101\.88 — 11%/);
    assert.match(text, /Порты назначения: 214\n   53 — 2,2%/);
    assert.match(text, /Откуда: 13 отражателей · ответы по ~1[\s ]?419 Б\n   порт 53 — 100%/);
    assert.match(text, /Весь трафик клиента: 4\.68 Гбит\/с \(обычно 6\.97 Гбит\/с\)/);
    assert.doesNotMatch(text, /188\.143\.1\.10|91\.218\.160|Паразит|Там порты/);
  });

  it('foreign_geo без пика загрузки остаётся атакой', () => {
    const text = formatAlertMessage({
      name: 'TTK',
      scope: 'client',
      scopeId: '107397',
      minute: '2026-09-01 20:00:00',
      threshold: 1.6,
      byProto: { all: { bps: 9.4e9, growth_bps: 1.8, bytes: 9.4e9 * 60 / 8, foreign_bytes: 8e9 } },
      verdict: { kind: 'benign_peak', reason: 'нет явных признаков атаки' },
      signals: ['foreign_geo'],
    });
    assert.match(text, /^🔴 <b>Всплеск трафика из-за рубежа<\/b> · <b>TTK<\/b> · ID <b>107397<\/b>/);
    assert.match(text, /Из-за рубежа: <b>11% трафика \(1\.07 Гбит\/с\)<\/b>/);
  });

  it('formatAlertMessage с разбором пишет жертву и коммутатор', () => {
    const text = formatAlertMessage({
      name: 'Hostland',
      scope: 'client',
      scopeId: '83106',
      minute: '2026-09-01 16:49:00',
      threshold: 1.6,
      streak: 3,
      byProto: { all: { bps: 5.8e9, growth_bps: 2.45 } },
      verdict: { kind: 'volumetric', reason: 'топ IP 99.4%', hourRatio: 1.57 },
      investigate: {
        victim: { ip: '185.26.122.4', port: 443, protoLabel: 'UDP', share: 0.994, net24: '185.26.122.0/24' },
        source24: [{ net24: '125.224.150.0/24', share: 0.01, asn: 3462, ips: 4 }],
        switchIn: { switchIp: '172.18.19.165', ifName: 'port-channel2', ifAlias: 'imaqliq.9236', share: 1 },
        switchOut: { switchIp: '172.18.19.165', ifName: 'Ethernet1/31', ifAlias: 'hostland-', share: 1 },
        l4src: [{ port: 80, proto: 17, share: 0.14 }],
        destPort: { count: 1, top: [{ port: 443, share: 0.99 }] },
      },
    });
    assert.match(text, /^🔴 <b>UDP-флуд в один сервер<\/b> · <b>Hostland<\/b> · ID <b>83106<\/b>/);
    assert.match(text, /<b>В 1,6 раза больше обычного:<\/b> 5\.80 Гбит\/с\n/);
    assert.match(text, /Цель: <b>185\.26\.122\.4:443<\/b> \(UDP\) — 99% трафика клиента/);
    assert.match(text, /Вход: 172\.18\.19\.165 port-channel2 \(imaqliq\.9236\) 100% · выход: 172\.18\.19\.165 Ethernet1\/31 \(hostland-\) 100%/);
    assert.doesNotMatch(text, /14д|к часу|Откуда порты|Там порты/);
  });

  it('шапка атаки по сети — размазано, без цели', () => {
    const text = formatAlertMessage({
      name: 'TestNet',
      scope: 'net',
      scopeId: '10.0.0.0/24',
      minute: '2026-09-01 10:00:00',
      threshold: 1.6,
      byProto: { all: { bps: 5.9e9 }, udp: { bps: 5.8e9 }, tcp: { bps: 80e6 } },
      verdict: { kind: 'carpet', hourRatio: 7, hourCeiling: 840e6 },
      investigate: {
        victim: { ip: '10.0.0.8', port: 80, protoLabel: 'UDP', share: 0.002, net24: '10.0.0.0/24' },
        destPort: { count: 3, top: [{ port: 80, share: 0.4 }, { port: 443, share: 0.3 }, { port: 53, share: 0.2 }] },
      },
    });
    assert.match(text, /^🔴 <b>UDP-флуд по сети<\/b> · сеть <b>10\.0\.0\.0\/24<\/b> · TestNet\n/);
    assert.match(text, /<b>В 7 раз больше обычного:<\/b> 5\.90 Гбит\/с, обычно 840 Мбит\/с/);
    assert.match(text, /Цель: сеть клиента, не один сервер/);
    assert.doesNotMatch(text, /10\.0\.0\.8|Там порты/);
  });

  it('WEST CALL: шапка — один сервер, оба роста, без ведущего двоеточия и без фильтра по сети', () => {
    const text = formatAlertMessage({
      name: 'WEST CALL',
      scope: 'client',
      scopeId: '81993',
      minute: '2026-09-18 04:44:00',
      threshold: 1.6,
      byProto: {
        all: { bps: 30.8e9, growth_bps: 1.68 },
        tcp: { bps: 3.1e9 },
        udp: { bps: 26.3e9, port_entropy: 8.9 },
      },
      verdict: { kind: 'volumetric', reason: 'топ IP 86.0%', hourRatio: 3.45, hourCeiling: 8.9e9 },
      investigate: {
        victim: { ip: '195.209.212.16', port: 38749, protoLabel: 'UDP', share: 0.86, net24: '195.209.212.0/24' },
        destPort: { count: 584, top: [{ port: 443, share: 0.1 }, { port: 38749, share: 0.009 }] },
        l4src: [{ port: 38749, proto: 17, share: 0.01 }],
        binding: {
          bindMode: 'ports',
          ports: [{ switchIp: '172.18.19.124', ifIndex: 1, comment: 'Ethernet1/52' }],
        },
      },
      binding: {
        bindMode: 'ports',
        ports: [{ switchIp: '172.18.19.124', ifIndex: 1, comment: 'Ethernet1/52' }],
      },
    });
    assert.match(text, /^🔴 <b>UDP-флуд в один сервер<\/b> · <b>WEST CALL<\/b> · ID <b>81993<\/b>/);
    assert.match(text, /<b>В 3,5 раза больше обычного:<\/b> 30\.8 Гбит\/с, обычно 8\.90 Гбит\/с/);
    // Портов у адреса 584 — порт в цель не пишем.
    assert.match(text, /Цель: <b>195\.209\.212\.16<\/b> \(UDP\) — 86% трафика клиента/);
    assert.match(text, /Порт клиента: .*Ethernet1\/52/);
    assert.doesNotMatch(text, /:443|:38749|Что делать/);
  });

  // 81050, 11.09 19:29 UTC на nta: 134 905 856 пакетов голого SYN по 72 Б с
  // 2 057 адресов, 98.8% на :22 трёх серверов. В ту же минуту шла закачка,
  // поэтому топ IP и порт по байтам — чужие, и брать их в шапку нельзя.
  it('шапка SYN-флуда: объём, откуда, куда и норма клиента', () => {
    const text = formatAlertMessage({
      name: 'Когнитивные машины',
      scope: 'client',
      scopeId: '81050',
      minute: '2026-09-11 19:29:00',
      threshold: 1.6,
      byProto: {
        all: {
          bps: 17.56e9,
          pps: 587792384 / 60,
          syn_only_packets: 134905856,
          syn_only_bytes: 9671344128,
          syn_only_rows: 2059,
          sampling_rate: 32768,
        },
      },
      verdict: { kind: 'syn_flood', hourCeiling: 27.7e9, hourRatio: 0.63 },
      investigate: {
        victim: { ip: '5.39.222.140', port: 443, protoLabel: 'TCP', share: 0.091 },
        source24: [{ net24: '143.204.233.0/24', asn: 16509, asnName: 'AMAZON-02', share: 0.07, ips: 6 }],
        destPort: { count: 240, top: [{ port: 443, share: 0.091, ips: 11 }] },
        syn: {
          packets: 134905856,
          srcIps: 2057,
          srcNets: 2057,
          srcAsns: 619,
          dstIps: 25,
          portCount: 10,
          dest: [
            { ip: '5.39.222.138', port: 22, packets: 52232192, share: 0.387 },
            { ip: '5.39.218.156', port: 22, packets: 45481984, share: 0.337 },
          ],
          ports: [{ port: 22, packets: 133300224, ips: 3, share: 0.988 }],
          source24: [{ net24: '150.241.92.0/24', asn: 198550, packets: 131072, ips: 1, share: 0.001 }],
        },
      },
    });
    assert.match(text, /^🔴 <b>SYN-флуд<\/b> · <b>Когнитивные машины<\/b> · ID <b>81050<\/b>/);
    assert.match(text, /Голый SYN: <b>2\.25 млн SYN\/с<\/b>/);
    assert.match(text, /Цели: 25 адресов, больше всего 5\.39\.222\.138:22 — 39%/);
    assert.match(text, /Источники: 2[\s ]?057 адресов · 2[\s ]?057 сетей \/24 · 619 AS/);
    assert.match(text, /SYN: пакет 72 Б/);
    // Закачка на :443 в ту же минуту не должна попасть ни в цель, ни в метрики.
    assert.doesNotMatch(text, /5\.39\.222\.140|443|AMAZON|150\.241\.92\.0|Что делать/);
  });

  it('шапка зарубежного трафика — доля, норма и страны', () => {
    const text = formatAlertMessage({
      name: 'TTK',
      scope: 'client',
      scopeId: '107397',
      minute: '2026-09-01 20:00:00',
      threshold: 1.6,
      byProto: {
        all: {
          bps: 2.74e9, bytes: 2.74e9 * 60 / 8,
          foreign_bytes: 2.60e9 * 60 / 8,
          growth_foreign_share: 4.66,
          top_countries: 'SC:0.82,KZ:0.08,RU:0.05',
        },
      },
      verdict: { kind: 'benign_peak', reason: 'нет явных признаков атаки' },
      signals: ['foreign_geo'],
    });
    assert.match(text, /^🔴 <b>Всплеск трафика из-за рубежа<\/b>/);
    assert.match(text, /<b>Доля из-за рубежа в 4,7 раза больше обычного:<\/b> 95% трафика \(2\.60 Гбит\/с\), обычно 20%/);
    assert.match(text, /Страны: SC 82% · KZ 8% · RU 5%/);
  });

  // 95558, 21.09 10:05 UTC: полное имя из биллинга занимало всю строку превью.
  it('шапка: короткое имя клиента', () => {
    const ampBytes = 177e6 * 60 / 8;
    const text = formatAlertMessage({
      name: 'Общество с ограниченной ответственностью "Сторм Нетворкс" [ООО "Сторм Нетворкс" ]',
      scope: 'client',
      scopeId: '95558',
      minute: '2026-09-21 10:05:00',
      threshold: 1.6,
      byProto: {
        all: { bps: 40.6e9, bytes: 40.6e9 * 60 / 8 },
        udp: {
          bps: 4.1e9, bytes: 4.1e9 * 60 / 8,
          amp_bytes: ampBytes, amp_packets: ampBytes / 1125, amp_srcs: 13,
        },
      },
      verdict: { kind: 'amplification', reason: 'амплификация', hourRatio: 0.7, hourCeiling: 58e9 },
      investigate: { ampSrcPort: { count: 1, top: [{ port: 53, share: 1 }] } },
    });
    assert.match(text, /^🔴 <b>Амплификация DNS<\/b> · <b>ООО "Сторм Нетворкс"<\/b> · ID <b>95558<\/b>/);
    assert.doesNotMatch(text, /Общество с ограниченной/);
    assert.match(text, /— 4% UDP клиента/);
    assert.match(text, /\nUDP 10%/);
  });

  it('шапка объёмной атаки: кто бьёт — сети, адреса и AS', () => {
    const text = formatAlertMessage({
      name: 'Hostland',
      scope: 'client',
      scopeId: '83106',
      minute: '2026-09-21 16:49:00',
      threshold: 1.6,
      byProto: { all: { bps: 5.8e9, growth_bps: 2.45 } },
      verdict: { kind: 'volumetric', reason: 'топ IP 99.4%', hourRatio: 1.57 },
      investigate: {
        victim: { ip: '185.26.122.4', port: 443, protoLabel: 'UDP', share: 0.994, net24: '185.26.122.0/24' },
        sources: { ipCount: 1840, net24Count: 612, dstIpCount: 3, dstNetCount: 1 },
        source24: [
          { net24: '154.85.88.0/24', asn: 139057, asnName: 'ELD-AS-AP - Edgenext Legend Dynasty Pte. Ltd.', share: 0.41, ips: 37 },
          { net24: '45.12.30.0/24', asn: 3462, share: 0.12, ips: 9 },
          { net24: '5.5.5.0/24', share: 0.004, ips: 1 },
        ],
        destPort: { count: 1, top: [{ port: 443, share: 0.99 }] },
      },
    });
    assert.match(text, /Источники: 1[\s ]?840 адресов · 612 сетей \/24/);
    assert.match(text, /154\.85\.88\.0\/24 — 41% · 37 адресов · AS139057 Edgenext Legend Dynasty/);
    assert.match(text, /45\.12\.30\.0\/24 — 12% · 9 адресов · AS3462/);
    assert.match(text, /Цель: <b>185\.26\.122\.4:443<\/b> \(UDP\) — 99% трафика клиента/);
    // Сети-крохи и дубль в футере только зашумляют шапку.
    assert.doesNotMatch(text, /5\.5\.5\.0\/24|Откуда сети:/);
  });

  it('ковровая атака называет подсети цели, а не только «по сети клиента»', () => {
    const text = formatAlertMessage({
      name: 'TestNet',
      scope: 'net',
      scopeId: '10.0.0.0/24',
      minute: '2026-09-21 10:00:00',
      threshold: 1.6,
      byProto: { all: { bps: 5.9e9 }, udp: { bps: 5.8e9 }, tcp: { bps: 80e6 } },
      verdict: { kind: 'carpet', hourRatio: 7, hourCeiling: 840e6 },
      investigate: {
        victim: { ip: '10.0.0.8', port: 80, protoLabel: 'UDP', share: 0.002, net24: '10.0.0.0/24' },
        sources: { ipCount: 9100, net24Count: 3400, dstIpCount: 512, dstNetCount: 6 },
        dest24: [
          { net24: '10.0.0.0/24', ips: 240, share: 0.52 },
          { net24: '10.0.1.0/24', ips: 180, share: 0.31 },
        ],
        destPort: { count: 3, top: [{ port: 80, share: 0.4 }] },
      },
    });
    assert.match(text, /Цель: сеть клиента, не один сервер — 512 адресов · 6 сетей \/24/);
    assert.match(text, /   10\.0\.0\.0\/24 — 52%\n   10\.0\.1\.0\/24 — 31%/);
    assert.match(text, /Источники: 9[\s ]?100 адресов · 3[\s ]?400 сетей \/24/);
  });

  it('formatAlertMessage для абонента по порту пишет коммутатор', () => {
    const text = formatAlertMessage({
      name: 'КИНГ-ОНЛАЙН',
      scope: 'client',
      scopeId: '94737',
      minute: '2026-09-02 18:11:00',
      threshold: 1.6,
      byProto: { all: { bps: 4.14e10, growth_bps: 5.65 } },
      verdict: { kind: 'volumetric', reason: 'узкий набор портов' },
      binding: {
        bindMode: 'ports',
        ports: [{ switchIp: '172.18.19.207', ifIndex: 436209664, comment: 'КМ11350 · Ethernet1/5 · king-' }],
      },
    });
    assert.match(text, /\nПорт клиента: 172\.18\.19\.207 · КМ11350 · Ethernet1\/5 · king-$/);
    assert.doesNotMatch(text, /Разметка/);
  });

  it('отношение к норме часа не называется ростом', () => {
    const text = formatAlertMessage({
      name: 'СпейсВэб',
      scope: 'client',
      scopeId: '71764',
      minute: '2026-09-03 13:39:00',
      threshold: 1.6,
      byProto: { all: { bps: 2.37e9, growth_bps: 3.25 } },
      verdict: { kind: 'volumetric', reason: 'узкий набор портов', hourRatio: 0.96 },
    });
    // Норма часа важнее потолка 14 дней: ×3.25 к p999 — обычный объём этого часа.
    assert.match(text, /Объём <b>2\.37 Гбит\/с<\/b> — ниже обычного\n/);
    assert.doesNotMatch(text, /рост ×0\.96|больше обычного/);
  });

  it('упавший разбор не выдаёт «не эскалировать» и не тащит весь текст ошибки', () => {
    const text = formatAlertMessage({
      name: 'СпейсВэб',
      scope: 'client',
      scopeId: '71764',
      minute: '2026-09-03 13:39:00',
      threshold: 1.6,
      byProto: { all: { bps: 2.37e9 } },
      verdict: { kind: 'volumetric', reason: 'узкий набор портов' },
      investigate: {
        ...emptyInvestigate(),
        error: 'Cannot parse IPv4 a02:408:7722:54:168:222:203:60: Cannot parse IPv4 from String:'
          + " while executing 'FUNCTION toIPv4(if(equals(__table3.etype, 2048_UInt16)",
      },
    });
    assert.match(text, /Цель: не удалось разобрать \(Cannot parse IPv4/);
    assert.doesNotMatch(text, /не эскалировать|__table3/);
  });

  it('shortErrorMsg режет исключение ClickHouse до первой мысли', () => {
    assert.equal(shortErrorMsg(''), '');
    assert.equal(
      shortErrorMsg("Code: 6. Cannot parse IPv4: while executing 'FUNCTION toIPv4(x)'"),
      'Code: 6. Cannot parse IPv4:',
    );
    assert.ok(shortErrorMsg('x'.repeat(400)).length <= 120);
  });

  it('formatAlertMessage для абонента по префиксу пишет IP', () => {
    const text = formatAlertMessage({
      name: 'Hostland',
      scope: 'client',
      scopeId: '83106',
      minute: '2026-09-01 16:49:00',
      threshold: 1.6,
      byProto: { all: { bps: 1e9 } },
      binding: { bindMode: 'prefixes', prefixes: ['185.26.122.0/24'] },
    });
    assert.match(text, /\nIP клиента: 185\.26\.122\.0\/24$/);
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

  it('индивидуальный порог выше общего не даёт алерт', () => {
    const rows = [
      { scope: 'client', scope_id: '71764', proto: 'all', growth_bps: 2, growth_pps: 0.5 },
    ];
    const prev = new Map([
      ['client|71764', [above('2026-09-01 12:08:00'), above('2026-09-01 12:05:00')]],
    ]);
    const picked = pickAlertCandidates(rows, prev, 1.6, {
      streak: 3,
      thresholdByKey: new Map([['client|71764', 4]]),
    });
    assert.equal(picked.length, 0);
  });

  it('кандидат несёт сработавший порог, и текст помечает его индивидуальным', () => {
    const rows = [
      { scope: 'client', scope_id: '71764', proto: 'all', growth_bps: 6, growth_pps: 0.5 },
      { scope: 'net', scope_id: '10.0.0.0/24', proto: 'all', growth_bps: 6, growth_pps: 0.5 },
    ];
    // Серия должна пробивать и ×4, поэтому рост выше, чем в above().
    const history = [
      { minute: '2026-09-01 12:08:00', growth_bps: 6, growth_pps: 0.5 },
      { minute: '2026-09-01 12:05:00', growth_bps: 6, growth_pps: 0.5 },
    ];
    const prev = new Map([['client|71764', history], ['net|10.0.0.0/24', history]]);
    const picked = pickAlertCandidates(rows, prev, 1.6, {
      streak: 3,
      thresholdByKey: new Map([['client|71764', 4]]),
    });
    const client = picked.find((c) => c.key === 'client|71764');
    const net = picked.find((c) => c.key === 'net|10.0.0.0/24');
    assert.equal(client.threshold, 4);
    assert.equal(client.thresholdIsCustom, true);
    assert.equal(net.threshold, 1.6);
    assert.equal(net.thresholdIsCustom, false);
    // Порог — настройка детектора, клиенту в тексте алерта он не нужен.
    const custom = formatAlertMessage({
      name: 'СпейсВэб',
      scope: 'client',
      scopeId: '71764',
      minute: '2026-09-03 13:39:00',
      byProto: { all: { bps: 1e9 } },
      investigate: emptyInvestigate(),
    });
    assert.doesNotMatch(custom, /Порог|индивидуальный/);
  });

  it('начало атаки — первая из подряд горячих минут, а не минута отправки', () => {
    const rows = [{ scope: 'client', scope_id: '71764', proto: 'all', minute: '2026-09-01 12:10:00', growth_bps: 2, growth_pps: 0.5 }];
    const prev = new Map([['client|71764', [
      above('2026-09-01 12:09:00'),
      above('2026-09-01 12:08:00'),
      below('2026-09-01 12:07:00'),
    ]]]);
    const [picked] = pickAlertCandidates(rows, prev, 1.6, { streak: 3 });
    assert.equal(picked.startMinute, '2026-09-01 12:08:00');
    const text = formatAlertMessage({
      name: 'СпейсВэб',
      scope: 'client',
      scopeId: '71764',
      minute: '2026-09-01 12:10:00',
      startMinute: picked.startMinute,
      byProto: { all: { bps: 1e9, growth_bps: 2 } },
    });
    assert.match(text, /\nНачало: <b>01\.09 15:08 МСК<\/b>\n/);
  });

  it('pin: идущая серия, уже записанная пиком, пересматривается один раз', () => {
    const row = {
      minute: '2026-10-03 12:18:00',
      scope: 'provider',
      scope_id: 'isp:pin',
      proto: 'all',
      bps: 25e9,
      growth_bps: 1.8,
    };
    const prev = new Map([['provider|isp:pin', [
      below('2026-10-03 12:17:00'),
      above('2026-10-03 12:16:00'),
      below('2026-10-03 12:15:00'),
      above('2026-10-03 12:14:00'),
      below('2026-10-03 12:13:00'),
      above('2026-10-03 12:11:00'),
    ]]]);
    const grouped = new Map([['provider|isp:pin', {
      byProto: { all: row, udp: { bps: 19e9 } },
    }]]);
    const peaks = new Map([['provider|isp:pin', {
      id: 'provider|isp:pin|2026-10-03 12:11:00',
      alertMinute: '2026-10-03 12:11:00',
      startMinute: '2026-10-03 12:11:00',
    }]]);
    const opts = {
      streak: 3,
      settings: { streak: 3, volumeWindow: 6 },
      grouped,
      peaksByKey: peaks,
      peakUpgradeChecked: new Set(),
    };
    const [picked] = pickAlertCandidates([row], prev, 1.6, opts);
    assert.equal(picked.upgradePeak.id, 'provider|isp:pin|2026-10-03 12:11:00');
    assert.equal(picked.startMinute, '2026-10-03 12:11:00');
    opts.peakUpgradeChecked.add('provider|isp:pin');
    assert.equal(pickAlertCandidates([row], prev, 1.6, opts).length, 0);
    const quietUdp = new Map([['provider|isp:pin', {
      byProto: { all: row, udp: { bps: 1e9 } },
    }]]);
    assert.equal(pickAlertCandidates([row], prev, 1.6, {
      ...opts,
      grouped: quietUdp,
      peakUpgradeChecked: new Set(),
    }).length, 0);
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

  it('идущий SYN-флуд без активного события всё равно открывает алерт', () => {
    const flood = (minute) => ({
      minute,
      scope: 'client',
      scope_id: '81050',
      proto: 'all',
      growth_bps: 0.8,
      syn_only_packets: 266_772_480,
      syn_only_bytes: 266_772_480 * 72,
      syn_only_rows: 4484,
      established_packets: 12_000_000,
      data_packets: 11_912_448,
      sampling_rate: 4096,
    });
    const current = flood('2026-09-11 19:29:00');
    const picked = pickAlertCandidates([current], new Map([['client|81050', [
      flood('2026-09-11 19:28:00'),
      flood('2026-09-11 19:27:00'),
    ]]]), 1.6, {
      grouped: new Map([['client|81050', { byProto: { all: current, tcp: current } }]]),
      settings: { ampEnabled: false, geoEnabled: false },
    });
    assert.deepEqual(picked.map((c) => c.signal), ['syn_flood']);
    const again = pickAlertCandidates([current], new Map(), 1.6, {
      grouped: new Map([['client|81050', { byProto: { all: current } }]]),
      settings: { ampEnabled: false, geoEnabled: false },
      activeKeys: new Set(['client|81050|syn_flood']),
    });
    assert.equal(again.length, 0);
  });

  it('нормализация не закрывает, пока объём выше алерта', () => {
    const history = [
      { minute: '2026-09-01 19:45:00', growth_bps: 1.1, growth_pps: 1.0, bps: 9.4e9 },
      { minute: '2026-09-01 19:44:00', growth_bps: 1.2, growth_pps: 1.0, bps: 9.1e9 },
      { minute: '2026-09-01 19:43:00', growth_bps: 1.1, growth_pps: 1.0, bps: 8.8e9 },
    ];
    assert.equal(shouldSendNormalize(history, 1.6, 3), true);
    assert.equal(shouldSendNormalize(history, 1.6, 3, { alertBps: 6.9e9 }), false);
    assert.equal(shouldSendNormalize([
      { minute: '2026-09-01 17:12:00', growth_bps: 0.3, bps: 0.64e9 },
      { minute: '2026-09-01 17:11:00', growth_bps: 1.3, bps: 3e9 },
      { minute: '2026-09-01 17:10:00', growth_bps: 0.9, bps: 2e9 },
    ], 1.6, 3, { alertBps: 5.8e9 }), true);
    assert.equal(shouldSendNormalize([
      { minute: '2026-09-16 01:42:00', growth_bps: 0.13, bps: 1.42e9 },
      { minute: '2026-09-16 01:41:00', growth_bps: 0.14, bps: 1.45e9 },
      { minute: '2026-09-16 01:40:00', growth_bps: 0.15, bps: 1.60e9 },
    ], 1.6, 3, { alertBps: 2.745e9, hourP95: 0.104e9 }), true);
  });

  it('SYN: три тихие минуты закрывают без rising edge', () => {
    const quiet = (minute) => ({
      minute,
      scope: 'client',
      scope_id: '72966',
      proto: 'all',
      growth_bps: 0.26,
      syn_only_packets: 5188 * 60,
      syn_only_bytes: 5188 * 60 * 72,
      syn_only_rows: 8,
      established_packets: 80_000_000,
      data_packets: 70_000_000,
    });
    const flood = (minute) => ({
      minute,
      scope: 'client',
      scope_id: '72966',
      proto: 'all',
      growth_bps: 0.8,
      syn_only_packets: 266_772_480,
      syn_only_bytes: 266_772_480 * 72,
      syn_only_rows: 4484,
      established_packets: 12_000_000,
      data_packets: 11_912_448,
      sampling_rate: 4096,
    });
    const isQuiet = (item) => !item.syn_only_packets || item.syn_only_packets / 60 < 500_000;
    assert.equal(shouldNormalizeQuiet([quiet('12:11'), quiet('12:10')], isQuiet, 3), false);
    assert.equal(shouldNormalizeQuiet([
      quiet('12:11'), quiet('12:10'), quiet('12:09'),
    ], isQuiet, 3), true);
    assert.equal(shouldSendSignal([
      quiet('12:11'), quiet('12:10'), quiet('12:09'), quiet('12:08'),
    ], isQuiet, 3), false);

    const current = quiet('2026-09-16 01:42:00');
    const picked = pickNormalizeCandidates([current], new Map([
      ['client|72966', [quiet('2026-09-16 01:41:00'), quiet('2026-09-16 01:40:00'), quiet('2026-09-16 01:39:00')]],
    ]), 1.6, {
      streak: 3,
      activeByKey: new Map([
        ['client|72966|syn_flood', {
          id: 'e-syn',
          scope: 'client',
          scopeId: '72966',
          signal: 'syn_flood',
        }],
      ]),
    });
    assert.equal(picked.length, 1);
    assert.equal(picked[0].signal, 'syn_flood');

    const stillHot = pickNormalizeCandidates([flood('2026-09-16 01:42:00')], new Map(), 1.6, {
      streak: 3,
      activeByKey: new Map([
        ['client|72966|syn_flood', { id: 'e-syn', scope: 'client', scopeId: '72966', signal: 'syn_flood' }],
      ]),
    });
    assert.equal(stillHot.length, 0);
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

  // 101443 на PiterIX: SYN-флуд в 109.232.248.252:80 открылся 01.10 09:02 UTC,
  // нормализация пришла в 09:07 после трёх спокойных минут.
  it('formatNormalizeMessage: что за атака, сколько длилась и что сейчас', () => {
    const syn = { syn_only_bytes: 524681216, syn_only_packets: 8192000, syn_only_rows: 125, sampling_rate: 65536 };
    const text = formatNormalizeMessage({
      name: 'Общество с ограниченной ответственностью "Митигатор Клауд" [ООО "Митигатор Клауд" ]',
      scope: 'client',
      scopeId: '101443',
      minute: '2026-10-01 09:07:00',
      alertMinute: '2026-10-01 09:02:00',
      streak: 3,
      byProto: {
        all: { bps: 409967001.6, pps: 74274.13, growth_bps: 0.66, syn_only_packets: 0, syn_only_bytes: 0, sampling_rate: 65536 },
        tcp: { bps: 379296153.6, pps: 65536, syn_only_packets: 0, syn_only_bytes: 0, sampling_rate: 65536 },
      },
      alertByProto: {
        all: { bps: 516371251.2, pps: 218453.33, ...syn },
        tcp: { bps: 509459387.73, pps: 212992, ...syn },
      },
      verdict: { kind: 'syn_flood' },
      investigate: { syn: { dest: [{ ip: '109.232.248.252', port: 80, share: 0.992 }] } },
      signals: ['volume'],
    });
    assert.equal(text, [
      '🟢 <b>Атака закончилась</b> · <b>ООО "Митигатор Клауд"</b> · ID <b>101443</b>',
      'SYN-флуд на 109.232.248.252:80',
      'Длилась <b>3 мин</b>: 12:02–12:05 МСК',
      'В начале 137 тыс. SYN/с · сейчас 0 SYN/с',
    ].join('\n'));
  });

  it('formatNormalizeMessage без снимка алерта — только время и объём', () => {
    const text = formatNormalizeMessage({
      name: '94.26.150.0/24',
      scope: 'net',
      scopeId: '94.26.150.0/24',
      minute: '2026-09-29 20:50:00',
      alertMinute: '2026-09-29 20:40:00',
      byProto: { all: { bps: 410e6 } },
    });
    assert.match(text, /^🟢 <b>Атака закончилась<\/b> · сеть <b>94\.26\.150\.0\/24<\/b>\n/);
    assert.match(text, /Началась 29\.09 23:40 МСК, закончилась 23:48 МСК/);
    assert.match(text, /Сейчас 410 Мбит\/с$/);
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
    const withSyn = snapshotByProto({
      byProto: {
        all: { syn_only_packets: 120000, syn_only_bytes: 8640000, syn_only_rows: 2059, sampling_rate: 32768 },
      },
    });
    assert.equal(withSyn.all.syn_only_packets, 120000);
    assert.equal(withSyn.all.sampling_rate, 32768);
    assert.equal(snap.udp.port_entropy, 3);
  });

  it('список стран переживает снимок и не превращается в число', () => {
    const snap = snapshotByProto({
      byProto: {
        all: {
          bps: 10, bytes: 100, foreign_bytes: 40, foreign_srcs: 7,
          top_countries: 'RU:0.6,UZ:0.12', growth_foreign_share: 3.7,
        },
      },
    });
    assert.equal(snap.all.top_countries, 'RU:0.6,UZ:0.12');
    const event = mapEventRow({
      event_id: 'client|101443|2026-09-06 16:27:00',
      scope: 'client',
      scope_id: '101443',
      signal: 'foreign_geo',
      status: 'active',
      alert_minute: '2026-09-06 16:27:00',
      threshold: 1.6,
      alert_json: JSON.stringify(snap),
    });
    assert.equal(event.alertByProto.all.topCountries, 'RU:0.6,UZ:0.12');
    assert.equal(event.signal, 'foreign_geo');
    assert.equal(event.telegramSkip, '');
  });

  it('mapEventRow сохраняет telegramSkip из снимка', () => {
    const event = mapEventRow({
      event_id: 'client|79305|amplification|2026-09-14 16:11:00',
      scope: 'client',
      scope_id: '79305',
      signal: 'amplification',
      status: 'active',
      alert_minute: '2026-09-14 16:11:00',
      threshold: 1.6,
      alert_json: JSON.stringify({
        all: { bps: 10.7e9 },
        telegramSkip: 'below_client_share',
      }),
    });
    assert.equal(event.telegramSkip, 'below_client_share');
  });

  it('buildDetectionEventsCsv содержит фазы alert и normalize', () => {
    const { buildDetectionEventsCsv } = require('./detection-telegram');
    const csv = buildDetectionEventsCsv([{
      id: 'net|10.0.0.0/24|2026-09-01 10:00:00',
      scope: 'net',
      scopeId: '10.0.0.0/24',
      name: 'TestNet',
      status: 'normalized',
      alertMinute: '2026-09-01 10:00:00',
      normalizeMinute: '2026-09-01 11:00:00',
      threshold: 1.6,
      alertByProto: {
        all: { bps: 1e9, growthBps: 2, synAttempts: 10 },
        tcp: { bps: 5e8 },
        udp: { bps: 1e6 },
      },
      normalizeByProto: {
        all: { bps: 1e7, growthBps: 1.1 },
        tcp: { bps: 5e6 },
        udp: { bps: 1e5 },
      },
    }]);
    assert.match(csv, /event_id/);
    assert.match(csv, /,signal,/);
    assert.match(csv, /TestNet/);
    assert.match(csv, /,alert,/);
    assert.match(csv, /,normalize,/);
    assert.match(csv, /,all,/);
    assert.match(csv, /,tcp,/);
    assert.match(csv, /,udp,/);
  });

  it('окно прошлых строк: streak + rising edge + запас на дыры', () => {
    assert.equal(previousRowsLookbackMinutes(3), 3 + 1 + PREV_ROWS_GAP_MINUTES);
    assert.equal(previousRowsLookbackMinutes(1), 1 + 1 + PREV_ROWS_GAP_MINUTES);
    assert.equal(previousRowsLookbackMinutes(60), 60 + 1 + PREV_ROWS_GAP_MINUTES);
    assert.equal(previousRowsLookbackMinutes(100), 60 + 1 + PREV_ROWS_GAP_MINUTES);
  });

  it('фильтр прошлых строк режет по scope и уникальным id', () => {
    const empty = previousRowsScopeFilter([]);
    assert.equal(empty.sql, '0');

    const mixed = previousRowsScopeFilter([
      { scope: 'client', scopeId: '100' },
      { scope: 'client', scope_id: '100' },
      { scope: 'net', scopeId: '10.0.0.0/24' },
      { scope: '', scopeId: 'skip' },
    ]);
    assert.match(mixed.sql, /scope = \{scope_0:String\} AND scope_id IN \{ids_0:Array\(String\)\}/);
    assert.match(mixed.sql, /scope = \{scope_1:String\} AND scope_id IN \{ids_1:Array\(String\)\}/);
    assert.equal(mixed.params.scope_0, 'client');
    assert.deepEqual(mixed.params.ids_0, ['100']);
    assert.equal(mixed.params.scope_1, 'net');
    assert.deepEqual(mixed.params.ids_1, ['10.0.0.0/24']);
  });

  it('пики недавних атак фильтруют объект по колонкам, а не по argMax', () => {
    const sql = recentAttackPeaksSql(previousRowsScopeFilter([{ scope: 'client', scopeId: '116691' }]).sql);
    assert.doesNotMatch(sql, /AS scope\b|AS scope_id\b/);
    assert.match(sql, /GROUP BY event_id, scope, scope_id/);
    assert.match(sql, /scope = \{scope_0:String\}/);
  });

  it('серия судится по минуте с самым большим ростом, не по последней', () => {
    const history = [
      { minute: '2026-09-22 16:23:00', growth_bps: 1.35, growth_pps: 1.77, bps: 1.3e9 },
      { minute: '2026-09-22 16:22:00', growth_bps: 4.1, growth_pps: 1.35, bps: 3.8e9 },
      { minute: '2026-09-22 16:21:00', growth_bps: 6.02, growth_pps: 1.5, bps: 5.7e9 },
      { minute: '2026-09-22 16:20:00', growth_bps: 0.92, growth_pps: 0.96, bps: 0.8e9 },
    ];
    assert.equal(heaviestHotMinute(history, 1.6, 3).minute, '2026-09-22 16:21:00');
  });

  it('метрики минуты: энтропия портов и CV пакета по всему трафику, порты на IP — нет', () => {
    const text = formatAlertMessage({
      name: '82035',
      scope: 'client',
      scopeId: '82035',
      minute: '2026-09-22 16:27:00',
      threshold: 1.6,
      byProto: {
        all: { bps: 1.63e9, growth_bps: 1.73, port_entropy: 7.775, cv_percent: 50.3 },
        udp: {
          bps: 928e6,
          growth_bps: 1.68,
          port_entropy: 0,
          port_entropy_out: null,
          ports_per_ip: 10,
          ports_per_ip_out: null,
        },
      },
      verdict: { kind: 'benign_peak', reason: 'объём в пределах часа' },
    });
    assert.doesNotMatch(text, /портов\/IP|CV:/);
    assert.match(text, /Метрики минуты\nВесь трафик клиента: 1\.63 Гбит\/с\nUDP 57%\nЭнтропия портов 7,78 бит · CV пакета 50%$/);
  });

  it('в шапке есть цель, которая выросла к своему часу', () => {
    const focus = {
      protoLabel: 'UDP',
      ip: '80.242.59.107',
      port: 2302,
      bps: 380e6,
      avgPkt: 119,
      srcs: 393,
      share: 0.41,
      fresh: true,
    };
    const text = formatAlertMessage({
      name: '82035',
      scope: 'client',
      scopeId: '82035',
      minute: '2026-09-22 16:27:00',
      threshold: 1.6,
      byProto: { all: { bps: 1.63e9, growth_bps: 1.73 }, udp: { bps: 928e6 } },
      verdict: { kind: 'syn_flood', reason: 'голый SYN' },
      investigate: { focus, focuses: [focus], syn: { dest: [{ ip: '195.18.27.62', port: 199, share: 0.99 }] } },
    });
    // У SYN-флуда цель — по пакетам SYN; UDP-цель по байтам сюда не тащим.
    assert.match(text, /Цель: <b>195\.18\.27\.62:199<\/b> — 99% атаки/);
    assert.doesNotMatch(text, /80\.242\.59\.107/);
    const volumetric = formatAlertMessage({
      name: '82035',
      scope: 'client',
      scopeId: '82035',
      minute: '2026-09-22 16:27:00',
      byProto: { all: { bps: 1.63e9, growth_bps: 1.73 }, udp: { bps: 928e6 } },
      verdict: { kind: 'volumetric', reason: 'топ IP' },
      investigate: { focus, focuses: [focus] },
    });
    assert.match(volumetric, /Цель UDP: 80\.242\.59\.107:2302 — 380 Мбит\/с · пакет 119 Б · 393 источника · раньше почти не было · 41% UDP/);
  });

  // Зеркало, 08.09: тихий абонент ниже 20 Мбит/с не пишется в минутную
  // таблицу, и событие висело три недели.
  it('замолчавший объект закрывается после N тихих тиков', () => {
    const active = {
      id: 'client|69201|2026-09-08 08:10:00', scope: 'client', scopeId: '69201',
      signal: 'volume', alertMinute: '2026-09-08 08:10:00',
    };
    const activeByKey = new Map([['client|69201', active], ['client|69201|volume', active]]);
    const ticks = new Map();
    const opts = { settings: { normalizeStreak: 3 }, ticks };
    const empty = new Set();
    assert.equal(pickSilentNormalizeCandidates(activeByKey, empty, '2026-09-29 05:00:00', opts).length, 0);
    assert.equal(pickSilentNormalizeCandidates(activeByKey, empty, '2026-09-29 05:01:00', opts).length, 0);
    const out = pickSilentNormalizeCandidates(activeByKey, empty, '2026-09-29 05:02:00', opts);
    assert.equal(out.length, 1);
    assert.equal(out[0].active.id, active.id);
    assert.equal(out[0].telegram, false);
  });

  it('объект снова в таблице — счёт тихих тиков сбрасывается', () => {
    const active = {
      id: 'e1', scope: 'client', scopeId: '1', signal: 'volume', alertMinute: '2026-09-29 04:50:00',
    };
    const activeByKey = new Map([['client|1', active]]);
    const ticks = new Map();
    const opts = { settings: { normalizeStreak: 2 }, ticks };
    pickSilentNormalizeCandidates(activeByKey, new Set(), '2026-09-29 05:00:00', opts);
    pickSilentNormalizeCandidates(activeByKey, new Set(['client|1']), '2026-09-29 05:01:00', opts);
    assert.equal(pickSilentNormalizeCandidates(activeByKey, new Set(), '2026-09-29 05:02:00', opts).length, 0);
    const out = pickSilentNormalizeCandidates(activeByKey, new Set(), '2026-09-29 05:03:00', opts);
    assert.equal(out.length, 1);
    assert.equal(out[0].telegram, true);
  });

  it('«в один сервер»: источники и порты по самому адресу, рост ×1,23 не «ниже нормы»', () => {
    const text = formatAlertMessage({
      name: '176.116.255.0/24',
      scope: 'net',
      scopeId: '176.116.255.0/24',
      minute: '2026-09-25 16:47:00',
      threshold: 1.6,
      byProto: { all: { bps: 416.4e6, growth_bps: 1.18 }, udp: { bps: 261.1e6 }, tcp: { bps: 155.2e6 } },
      verdict: { kind: 'volumetric', reason: 'топ IP 58.5%', hourRatio: 1.233, hourCeiling: 337.7e6 },
      investigate: {
        victim: { ip: '176.116.255.95', port: 53286, protoLabel: 'UDP', share: 0.5846, net24: '176.116.255.0/24' },
        victimShape: {
          ip: '176.116.255.95', clientId: '115628', sessions: 69, srcs: 65, dstPorts: 2, topShare: 0.91,
        },
        sources: { ipCount: 2598, net24Count: 2124, dstIpCount: 256, dstNetCount: 1 },
        source24: [{ net24: '92.244.240.0/24', asn: 6856, share: 0.3446, ips: 1 }],
        destPort: { count: 8126, top: [{ port: 53286, share: 0.5846 }] },
      },
    });
    assert.match(text, /Источники: 65 адресов · 69 сеансов · 3 крупнейших — 91%/);
    assert.match(text, /Цель: <b>176\.116\.255\.95<\/b> \(UDP\) — 58% трафика клиента · на 2 порта/);
    assert.doesNotMatch(text, /2[\s ]598 адресов|8[\s ]126 портов/);
    // ×1.23 к часу — рост, хоть и ниже порога пика.
    assert.match(text, /<b>В 1,2 раза больше обычного:<\/b> 416 Мбит\/с, обычно 338 Мбит\/с/);
    assert.doesNotMatch(text, /ниже/);
  });

  it('оповещение о смене вектора включено, если колонки ещё нет', () => {
    assert.equal(mapSettings({}).vectorNotify, true);
    assert.equal(mapSettings({ vector_notify: 0 }).vectorNotify, false);
    assert.equal(mapSettings({ vectorNotify: false }).vectorNotify, false);
  });

  it('в атаке видны операторы и страны источников', () => {
    const investigate = {
      victim: { ip: '176.123.128.10', port: 0, protoLabel: 'UDP', share: 0.02 },
      sources: {
        ipCount: 559,
        net24Count: 424,
        asns: [
          { asn: 8193, asnName: 'BRM-AS', share: 0.411 },
          { asn: 28885, asnName: 'OMANTEL-NAP-AS', share: 0.117 },
        ],
        countries: [{ cc: 'BR', share: 0.41 }, { cc: 'OM', share: 0.12 }],
      },
      destPort: { count: 40, top: [{ port: 443, share: 0.04 }] },
    };
    const lines = formatSourceOperatorLines(investigate).join('\n');
    assert.match(lines, /AS8193 BRM-AS — 41%/);
    assert.match(lines, /Страны источников: BR 41% · OM 12%/);
    const text = formatAlertMessage({
      name: 'metrobit',
      scope: 'provider',
      scopeId: 'isp:metrobit',
      minute: '2026-10-03 12:12:00',
      byProto: {
        all: { bps: 14e9, pps: 1.4e6, avg_packet_bytes: 1250 },
        udp: { bps: 13.5e9 },
        tcp: { bps: 0.5e9 },
      },
      verdict: { kind: 'carpet' },
      investigate,
      signals: ['volume'],
    });
    assert.match(text, /AS8193 BRM-AS/);
    assert.match(text, /Страны источников: BR 41%/);
  });

  it('смена вектора: подпись, скорость и строка «Резать»', () => {
    const byProto = {
      all: { bps: 88.2e9, pps: 8.79e6, avg_packet_bytes: 1250 },
      udp: { bps: 88.2e9 },
    };
    const investigate = {
      destPort: { count: 20, top: [{ port: 443, share: 0.05 }] },
      sources: { asns: [{ asn: 8193, asnName: 'BRM-AS', share: 0.41 }] },
    };
    const text = formatVectorChangeMessage({
      name: 'metrobit',
      scope: 'provider',
      scopeId: 'isp:metrobit',
      byProto,
      verdict: { kind: 'carpet' },
      investigate,
      binding: { prefixes: ['176.123.128.0/19'] },
      signals: ['volume'],
      rate: { bps: 88.2e9, pps: 8.79e6, unit: 'bps' },
    });
    assert.match(text, /Вектор сменился/);
    assert.match(text, /UDP, пакет от 800 Б, порты случайные/);
    assert.match(text, /Сейчас 88\.2 Гбит\/с, 8\.79 млн п\/с/);
    assert.match(text, /Резать: входящий UDP/);
    assert.match(text, /AS8193 BRM-AS/);

    // ШПД, 03.10 16:11: подпись та же, сменились операторы — пишем было → стало.
    const told = formatVectorChangeMessage({
      name: 'metrobit',
      scope: 'provider',
      scopeId: 'isp:metrobit',
      byProto,
      verdict: { kind: 'carpet' },
      investigate,
      signals: ['volume'],
      rate: { bps: 17.5e9, pps: 1.75e6, unit: 'bps' },
      previous: { proto: 'udp', pkt: 'large', ports: 'scatter', asns: 'spread' },
    });
    assert.match(told, /Источники: были разбросаны по многим операторам → теперь в основном AS8193 BRM-AS/);
    assert.doesNotMatch(told, /Было:/);
  });

  it('рост вдвое — короткое сообщение со скоростью и пакетами', () => {
    const text = formatPeakGrewMessage({
      name: 'metrobit',
      scope: 'provider',
      scopeId: 'isp:metrobit',
      rate: { bps: 88.2e9, pps: 8.79e6, unit: 'bps' },
    });
    assert.match(text, /Атака растёт/);
    assert.match(text, /Растёт: 88\.2 Гбит\/с, 8\.79 млн п\/с/);
    assert.equal(rateDoubled({ lastReportBps: 7e9, lastReportPps: 1 }, { bps: 14e9, pps: 1, unit: 'bps' }), true);
    assert.equal(rateDoubled({ lastReportBps: 7e9, lastReportPps: 1 }, { bps: 10e9, pps: 1, unit: 'bps' }), false);
  });

  it('закрытие пишет пик и все векторы', () => {
    const text = formatNormalizeMessage({
      name: 'metrobit',
      scope: 'provider',
      scopeId: 'isp:metrobit',
      minute: '2026-10-03 14:25:00',
      alertMinute: '2026-10-03 12:12:00',
      startMinute: '2026-10-03 12:10:00',
      streak: 10,
      byProto: { all: { bps: 2e9, pps: 2e5 } },
      alertByProto: { all: { bps: 14e9, pps: 1.4e6 } },
      verdict: { kind: 'carpet' },
      signals: ['volume'],
      track: {
        peak: { bps: 88.2e9, pps: 8.79e6, minute: '2026-10-03 12:49:00' },
        vectors: ['UDP, пакет от 800 Б, порты случайные', 'TCP, пакет до 200 Б, порт 443'],
      },
    });
    assert.match(text, /Пик: 88\.2 Гбит\/с, 8\.79 млн п\/с в 15:49 МСК/);
    assert.match(text, /Векторы: UDP, пакет от 800 Б, порты случайные → TCP, пакет до 200 Б, порт 443/);
  });

  it('вектор сравнивает только заполненные поля', () => {
    const udp = vectorSnapshot({
      byProto: {
        all: { bps: 10e9, avg_packet_bytes: 1250 },
        udp: { bps: 10e9 },
      },
      investigate: { destPort: { count: 30, top: [{ port: 80, share: 0.02 }] } },
      verdict: { kind: 'carpet' },
    });
    const tcp = vectorSnapshot({
      byProto: {
        all: { bps: 10e9, avg_packet_bytes: 80 },
        tcp: { bps: 10e9 },
      },
      investigate: { destPort: { count: 1, top: [{ port: 443, share: 0.9 }] } },
      verdict: { kind: 'syn_flood' },
    });
    assert.equal(vectorChanged(udp, tcp), true);
    assert.equal(vectorChanged(udp, { ...udp, pkt: 'large' }), false);
    assert.equal(vectorChanged({ ...udp, asns: '' }, { ...udp, asns: '8193' }), false);
    // Доля у границы не даёт значения и не шлёт «вектор сменился».
    const edge = (share) => vectorSnapshot({
      byProto: { all: { bps: 10e9, avg_packet_bytes: 1250 }, udp: { bps: 10e9 } },
      investigate: {
        dest24: [{ net24: '176.123.140.0/24', share }],
        sources: { asns: [{ asn: 8193, share }] },
      },
    });
    assert.equal(edge(0.1).prefixes, 'spread');
    assert.equal(edge(0.35).prefixes, '');
    assert.equal(edge(0.6).prefixes, '176.123.140.0/24');
    assert.equal(edge(0.41).asns, '8193');
    assert.equal(edge(0.3).asns, '');
    assert.equal(vectorChanged(edge(0.41), edge(0.3)), false);
    const peak = bumpPeak({ bps: 7e9, pps: 1, minute: '2026-10-03 12:11:00' }, { bps: 14e9, pps: 2, unit: 'bps' }, '2026-10-03 12:12:00');
    assert.equal(peak.bps, 14e9);
    assert.equal(peak.minute, '2026-10-03 12:12:00');
  });

  it('вектор по выросшему протоколу, а не по фону клиента', () => {
    // 81050, 04.10: фон 12–15 Гбит/с TCP, UDP-флуд в 95.129.234.0/24 импульсами.
    const minute = (udpBps, udpGrowth, udpPkt, tcpBps, allPkt) => vectorSnapshot({
      byProto: {
        all: { bps: udpBps + tcpBps, avg_packet_bytes: allPkt },
        udp: { bps: udpBps, growth_bps: udpGrowth, avg_packet_bytes: udpPkt },
        tcp: { bps: tcpBps, growth_bps: 1.05, avg_packet_bytes: 600 },
      },
      verdict: { kind: 'volumetric' },
    });
    const open = minute(13.9e9, 40, 1032, 11.0e9, 801);
    const strong = minute(19.8e9, 60, 1024, 11.7e9, 820);
    const weak = minute(8.9e9, 25, 889, 12.5e9, 721);
    const faint = minute(11.1e9, 30, 744, 11.6e9, 686);
    assert.equal(open.proto, 'udp');
    assert.equal(open.pkt, 'large');
    assert.equal(vectorChanged(open, strong), false);
    assert.equal(vectorChanged(open, weak), false);
    assert.equal(faint.pkt, 'mid');
    assert.equal(vectorChanged(open, faint), false);
    const small = minute(11e9, 30, 150, 11.6e9, 300);
    assert.equal(vectorChanged(open, small), true);
  });
});

describe('порог по норме часа', () => {
  // Повтор атаки ШПД 05.10 утром: pin 31.8, 27.5 и 37.5 Гбит/с при росте
  // к дневному потолку ×1.09–1.28. Утренняя норма pin около 4.8 Гбит/с.
  const replay = () => [
    { scope: 'provider', scope_id: 'isp:pin', minute: '2026-10-05 04:17:00', bps: 37.48e9, growth_bps: 1.28 },
    { scope: 'provider', scope_id: 'isp:pin', minute: '2026-10-05 04:16:00', bps: 27.53e9, growth_bps: 0.94 },
    { scope: 'provider', scope_id: 'isp:pin', minute: '2026-10-05 04:15:00', bps: 31.76e9, growth_bps: 1.09 },
    { scope: 'provider', scope_id: 'isp:pin', minute: '2026-10-05 04:14:00', bps: 3.37e9, growth_bps: 0.12 },
  ];
  const norm = () => 4.8e9;

  it('без нормы часа серия pin не набирается', () => {
    assert.equal(shouldSendAlert(replay(), 1.6, 3, null, 6), false);
  });

  it('UDP-объём втрое выше нормы часа открывает серию', () => {
    const history = replay();
    markHourHot(history, 0.89, norm);
    assert.deepEqual(history.map((r) => r.hour_hot === true), [true, true, true, false]);
    assert.equal(shouldSendAlert(history, 1.6, 3, null, 6), true);
  });

  it('без UDP или без нормы часа минуты не помечаются', () => {
    const tcp = replay();
    markHourHot(tcp, 0.12, norm);
    assert.equal(tcp.some((r) => r.hour_hot), false);
    const unknown = replay();
    markHourHot(unknown, 0.89, () => null);
    assert.equal(unknown.some((r) => r.hour_hot), false);
    const net = replay().map((r) => ({ ...r, scope: 'net' }));
    markHourHot(net, 0.89, norm);
    assert.equal(net.some((r) => r.hour_hot), false);
  });

  it('объём ниже ×3 к норме часа не горячий', () => {
    const history = replay();
    markHourHot(history, 0.89, () => 13e9);
    assert.equal(history.some((r) => r.hour_hot), false);
    assert.equal(HOUR_GATE_RATIO, 3);
  });
});

describe('UDP-ковёр открывает событие объёма', () => {
  // СКАЙНЭТ 07.10 11:02–11:06 МСК: весь трафик ×0.4–1.0 к потолку, UDP ×0.9–3.5
  // к своей норме, энтропия портов 7–7.8. Норма 11 часа без минут ковра 23.8 Гбит/с.
  const udp = (minute, bps, growth, entropy) => ({
    scope: 'client', scope_id: '71761', proto: 'udp', minute, bps, growth_bps: growth, port_entropy: entropy,
  });
  const skynet = () => [
    ['2026-10-07 08:06:00', 37.83e9, 0.87, udp('2026-10-07 08:06:00', 23.84e9, 3.06, 7.12)],
    ['2026-10-07 08:05:00', 43.12e9, 1.0, udp('2026-10-07 08:05:00', 27.36e9, 3.51, 7.08)],
    ['2026-10-07 08:04:00', 37.96e9, 0.88, udp('2026-10-07 08:04:00', 23.43e9, 3.01, 7.01)],
    ['2026-10-07 08:03:00', 24.0e9, 0.55, udp('2026-10-07 08:03:00', 13.23e9, 1.7, 7.25)],
    ['2026-10-07 08:02:00', 16.5e9, 0.38, udp('2026-10-07 08:02:00', 7.0e9, 0.9, 7.78)],
  ].map(([minute, bps, growth, udpRow]) => ({
    scope: 'client', scope_id: '71761', proto: 'all', minute, bps, growth_bps: growth, udpRow,
  }));
  const norm = () => 23.8e9;

  it('без ковра серия СКАЙНЭТ не набирается', () => {
    assert.equal(shouldSendAlert(skynet(), 1.6, 3, null, 10), false);
  });

  it('три минуты ковра из десяти открывают серию', () => {
    const history = skynet();
    markCarpetHot(history, norm);
    assert.deepEqual(history.map((r) => r.carpet_hot === true), [true, true, true, false, false]);
    assert.equal(shouldSendAlert(history, 1.6, 3, null, 10), true);
  });

  it('WireGuard ВапТак ×32 к норме UDP, но в один порт — не ковёр', () => {
    const rows = [{
      scope: 'client', scope_id: '71815', minute: '2026-10-05 06:01:00', bps: 0.7e9, growth_bps: 1.1,
      udpRow: { bps: 0.628e9, growth_bps: 32, port_entropy: 0 },
    }];
    markCarpetHot(rows, () => 0.3e9);
    assert.equal(rows[0].carpet_hot, undefined);
  });

  it('без нормы часа, у сети /24 и при малом лишнем UDP минута не горит', () => {
    const noNorm = skynet();
    markCarpetHot(noNorm, () => null);
    assert.equal(noNorm.some((r) => r.carpet_hot), false);
    const net = skynet().map((r) => ({ ...r, scope: 'net' }));
    markCarpetHot(net, norm);
    assert.equal(net.some((r) => r.carpet_hot), false);
    const big = skynet();
    markCarpetHot(big, () => 80e9);
    assert.equal(big.some((r) => r.carpet_hot), false);
  });

  it('ковёр держит событие открытым, пока весь трафик ниже порога', () => {
    const history = skynet();
    markCarpetHot(history, norm);
    assert.equal(isAttackMinute(history[0], 1.6, 43.12e9), true);
    assert.equal(isAboveGrowthThreshold(history[3], 1.6), false);
  });

  it('событие, открытое ковром, не подписывается обычным пиком', () => {
    const history = skynet();
    markCarpetHot(history, norm);
    const best = heaviestCarpetUdp(history, 10, null);
    assert.equal(best.bps, 27.36e9);
    const verdict = carpetVerdict({ kind: 'benign_peak', reason: 'объём в пределах часа, форма смешанная · UDP 63%' }, best);
    assert.equal(verdict.kind, 'carpet');
    assert.match(verdict.reason, /^UDP-ковёр · UDP ×3\.5 к норме · энтропия портов 7\.1 · UDP 63%$/);
    const amp = { kind: 'amplification', reason: 'амплификация' };
    assert.equal(carpetVerdict(amp, best), amp);
  });

  it('открытие только ковром отличается от открытия ростом объёма', () => {
    const history = skynet();
    markCarpetHot(history, norm);
    assert.equal(openedByCarpetOnly(history, 10, 1.6), true);
    const volume = skynet();
    volume[1].growth_bps = 1.7;
    markCarpetHot(volume, norm);
    assert.equal(openedByCarpetOnly(volume, 10, 1.6), false);
  });

  it('после ковра событие закрывается, хотя фон СКАЙНЭТ выше минуты открытия', () => {
    const quiet = Array.from({ length: 10 }, (_, i) => ({
      scope: 'client', scope_id: '71761', proto: 'all',
      minute: `2026-10-07 08:${String(30 - i).padStart(2, '0')}:00`, bps: 35e9, growth_bps: 0.9,
    }));
    const opts = { alertBps: 37.83e9, hourP95: 23.8e9, peakBps: 43.12e9 };
    assert.equal(shouldSendNormalize(quiet, 1.6, 10, opts), false);
    assert.equal(shouldSendNormalize(quiet, 1.6, 10, { ...opts, carpetOnly: true }), true);
  });

  it('ковёр держит событие, пока UDP выше ×1.3 к норме', () => {
    const history = (udpGrowth) => Array.from({ length: 10 }, (_, i) => ({
      scope: 'client', scope_id: '71761', proto: 'all',
      minute: `2026-10-09 12:${String(30 - i).padStart(2, '0')}:00`, bps: 35e9, growth_bps: 0.9,
      udpRow: { proto: 'udp', bps: 7.63e9 * udpGrowth(i), growth_bps: udpGrowth(i), port_entropy: 7.5 },
    }));
    const opts = { alertBps: 37.83e9, hourP95: 23.8e9, peakBps: 43.12e9, carpetOnly: true };
    const dip = history((i) => (i === 4 ? 1.4 : 0.7));
    assert.equal(shouldSendNormalize(dip, 1.6, 10, opts), false);
    assert.equal(shouldSendNormalize(history(() => 1.25), 1.6, 10, opts), true);
    const lowEntropy = history((i) => (i === 4 ? 1.4 : 0.7));
    lowEntropy[4].udpRow.port_entropy = 3;
    assert.equal(shouldSendNormalize(lowEntropy, 1.6, 10, opts), true);
  });

  it('у текущей минуты строка UDP берётся из группы тика', () => {
    const quiet = Array.from({ length: 10 }, (_, i) => ({
      scope: 'client', scope_id: '71761', proto: 'all',
      minute: `2026-10-09 12:${String(30 - i).padStart(2, '0')}:00`, bps: 35e9, growth_bps: 0.9,
    }));
    const current = { proto: 'udp', bps: 11e9, growth_bps: 1.45, port_entropy: 7.9 };
    const udpRowOf = (item) => item?.udpRow || (item === quiet[0] ? current : null);
    assert.equal(shouldSendNormalize(quiet, 1.6, 10, { carpetOnly: true, udpRowOf }), false);
    assert.equal(shouldSendNormalize(quiet, 1.6, 10, { carpetOnly: true }), true);
  });

  it('порог удержания ковра берётся из DETECTION_CARPET_HOLD_GROWTH', () => {
    const saved = process.env.DETECTION_CARPET_HOLD_GROWTH;
    try {
      delete process.env.DETECTION_CARPET_HOLD_GROWTH;
      assert.equal(carpetHoldGrowth(), 1.3);
      process.env.DETECTION_CARPET_HOLD_GROWTH = '1.2';
      assert.equal(carpetHoldGrowth(), 1.2);
      assert.equal(isCarpetHolding({ growth_bps: 1.25, port_entropy: 7 }), true);
      for (const bad of ['1', '0.9', '1.7', 'abc']) {
        process.env.DETECTION_CARPET_HOLD_GROWTH = bad;
        assert.equal(carpetHoldGrowth(), 1.3);
      }
      assert.equal(isCarpetHolding({ growth_bps: 1.25, port_entropy: 7 }), false);
      assert.equal(isCarpetHolding(null), false);
    } finally {
      if (saved === undefined) delete process.env.DETECTION_CARPET_HOLD_GROWTH;
      else process.env.DETECTION_CARPET_HOLD_GROWTH = saved;
    }
  });

  it('алерт ковра не режется долей роста всего трафика', () => {
    const byProto = {
      all: { bps: 43.12e9, growth_bps: 1.05 },
      udp: { bps: 27.36e9, growth_bps: 3.51 },
    };
    const settings = { volumeMinSharePct: 10 };
    assert.equal(shouldSkipTelegramForShare(['volume'], { byProto, verdict: {} }, settings), true);
    assert.equal(shouldSkipTelegramForShare(['volume'], { byProto, verdict: { carpetOnly: true } }, settings), false);
  });
});

describe('одна атака — одно сообщение', () => {
  // Префиксы провайдеров ШПД и сети /24, открытые на повторе 05.10.
  const prefixes = [
    { ...parseCidr('176.116.240.0/20'), entityId: 'isp:aykonet' },
    { ...parseCidr('176.123.128.0/19'), entityId: 'isp:metrobit' },
    { ...parseCidr('91.151.176.0/20'), entityId: 'isp:verolayn' },
    { ...parseCidr('188.143.128.0/17'), entityId: 'isp:pin' },
  ];

  it('сеть /24 находит своего провайдера', () => {
    assert.equal(parentProviderOf('91.151.189.0/24', prefixes), 'isp:verolayn');
    assert.equal(parentProviderOf('176.116.249.0/24', prefixes), 'isp:aykonet');
    assert.equal(parentProviderOf('176.123.129.0/24', prefixes), 'isp:metrobit');
    assert.equal(parentProviderOf('95.215.3.0/24', prefixes), null);
  });

  it('самый узкий префикс выигрывает', () => {
    const nested = [...prefixes, { ...parseCidr('91.151.188.0/22'), entityId: 'isp:inner' }];
    assert.equal(parentProviderOf('91.151.189.0/24', nested), 'isp:inner');
  });

  it('строка о соседних атаках берёт только последние 15 минут', () => {
    const active = new Map([
      ['provider|isp:verolayn', { scope: 'provider', scopeId: 'isp:verolayn', name: 'isp:verolayn', alertMinute: '2026-10-05 04:15:00' }],
      ['net|91.151.182.0/24', { scope: 'net', scopeId: '91.151.182.0/24', name: '91.151.182.0/24', alertMinute: '2026-10-05 04:17:00' }],
      ['client|1', { scope: 'client', scopeId: '1', name: 'Старый', alertMinute: '2026-10-05 03:00:00' }],
    ]);
    const opened = new Map([
      ['provider|isp:metrobit', { scope: 'provider', scopeId: 'isp:metrobit', name: 'isp:metrobit', minute: '2026-10-05 04:16:00' }],
    ]);
    const line = concurrentAttacksLine('provider|isp:aykonet', '2026-10-05 04:17:00', active, opened);
    assert.match(line, /ещё атакованы/);
    assert.match(line, /07:15/);
    assert.match(line, /07:16/);
    assert.doesNotMatch(line, /91\.151\.182/);
    assert.doesNotMatch(line, /Старый/);
    assert.equal(concurrentAttacksLine('provider|isp:aykonet', '2026-10-05 04:17:00', new Map(), new Map()), '');
  });

  it('у события есть отдельная причина молчания', () => {
    assert.equal(TELEGRAM_SKIP_PARENT_ACTIVE, 'parent_attack_active');
  });
});

describe('хвост атаки ниже доли пика', () => {
  const t = 1.6;
  const at = (hm, bps, growth) => ({ minute: `2026-10-05 05:${hm}:00`, bps, growth_bps: growth, proto: 'all' });
  // verolayn 05.10: удар 26.6 Гбит/с, после него живой TCP около слабой нормы 0.53 Гбит/с.
  const tail = [
    at('52', 0.942e9, 1.76), at('51', 0.605e9, 1.13), at('50', 0.864e9, 1.62),
    at('49', 0.508e9, 0.95), at('48', 0.766e9, 1.44), at('47', 0.594e9, 1.11),
    at('46', 0.81e9, 1.52), at('45', 0.532e9, 1.0), at('44', 0.788e9, 1.48),
    at('43', 0.45e9, 0.84),
  ];
  const event = { alertByProto: { all: { bps: 26.6e9 } }, track: { peak: { bps: 26.6e9 } } };

  it('минута ×1.76 при 3% пика не продолжает атаку', () => {
    assert.equal(isAttackMinute(tail[0], t, attackPeakBps(event)), false);
    assert.equal(isAttackMinute(at('31', 16.5e9, 30.96), t, attackPeakBps(event)), true);
  });

  it('без пика остаётся прежний порог роста', () => {
    assert.equal(isAttackMinute(tail[0], t, null), true);
  });

  it('verolayn закрывается, хотя рост живого трафика выше порога', () => {
    assert.equal(shouldSendNormalize(tail, t, 10, { alertBps: 26.6e9, peakBps: attackPeakBps(event) }), true);
    assert.equal(shouldSendNormalize(tail, t, 10, { alertBps: 26.6e9 }), false);
  });
});

describe('сильная UDP-минута открывает атаку сразу', () => {
  const opts = (row, udpBps, extra = {}) => ({
    streak: 3,
    settings: { streak: 3, volumeWindow: 6, ampEnabled: false, geoEnabled: false },
    grouped: new Map([[`${row.scope}|${row.scope_id}`, { byProto: { all: row, udp: { bps: udpBps } } }]]),
    ...extra,
  });
  // aykonet 04.10 18:41 МСК: 23 Гбит/с, ×6.5, UDP 98%; события не было.
  const aykonet = {
    scope: 'provider', scope_id: 'isp:aykonet', proto: 'all',
    minute: '2026-10-04 15:41:00', bps: 22962394269.47, growth_bps: 6.476,
  };
  // 66543 03.10: ×9113, но всего 109 Мбит/с.
  const small = {
    scope: 'client', scope_id: '66543', proto: 'all',
    minute: '2026-10-03 12:14:00', bps: 108675240.53, growth_bps: 9112.97,
  };

  it('aykonet открывается на первой минуте', () => {
    const [picked] = pickAlertCandidates([aykonet], new Map(), 1.6, opts(aykonet, 22493200128));
    assert.equal(picked.key, 'provider|isp:aykonet');
    assert.equal(picked.upgradePeak, null);
  });

  it('меньше 1 Гбит/с, мало UDP или порог объекта выше — ждём серию', () => {
    assert.equal(pickAlertCandidates([small], new Map(), 1.6, opts(small, 108675224.53)).length, 0);
    assert.equal(pickAlertCandidates([aykonet], new Map(), 1.6, opts(aykonet, 5e9)).length, 0);
    assert.equal(pickAlertCandidates([aykonet], new Map(), 1.6, opts(aykonet, 22493200128, {
      thresholdByKey: new Map([['provider|isp:aykonet', 8]]),
    })).length, 0);
    const net = { ...aykonet, scope: 'net', scope_id: '91.151.189.0/24' };
    assert.equal(isStrongUdpMinute(net, 0.98), false);
  });

  it('открытый пик пересматривается, отбракованный — нет', () => {
    const peak = { id: 'provider|isp:aykonet|2026-10-04 15:30:00', alertMinute: '2026-10-04 15:30:00' };
    const extra = { peaksByKey: new Map([['provider|isp:aykonet', peak]]), peakUpgradeChecked: new Set() };
    const [picked] = pickAlertCandidates([aykonet], new Map(), 1.6, opts(aykonet, 22493200128, extra));
    assert.equal(picked.upgradePeak.id, peak.id);
    extra.peakUpgradeChecked.add('provider|isp:aykonet');
    assert.equal(pickAlertCandidates([aykonet], new Map(), 1.6, opts(aykonet, 22493200128, extra)).length, 0);
  });
});

describe('хвост закрытой атаки не открывается заново', () => {
  const minute = (hm, bps, growth) => ({
    scope: 'provider', scope_id: 'isp:verolayn', proto: 'all',
    minute: `2026-10-05 ${hm}:00`, bps, growth_bps: growth,
  });
  // 09:01–09:05 МСК: три горячие минуты из шести, все около 0.9 Гбит/с.
  const current = minute('06:05', 0.917e9, 1.72);
  const prev = new Map([['provider|isp:verolayn', [
    minute('06:04', 0.676e9, 1.27),
    minute('06:03', 0.924e9, 1.73),
    minute('06:02', 0.784e9, 1.47),
    minute('06:01', 0.902e9, 1.69),
    minute('06:00', 0.713e9, 1.34),
  ]]]);

  it('0.9 Гбит/с после пика 26.6 Гбит/с не открывает объём', () => {
    const open = pickAlertCandidates([current], prev, 1.6, { streak: 3, settings: { streak: 3, volumeWindow: 6 } });
    assert.equal(open.length, 1);
    const held = pickAlertCandidates([current], prev, 1.6, {
      streak: 3,
      settings: { streak: 3, volumeWindow: 6 },
      recentPeakByKey: new Map([['provider|isp:verolayn', 26.6e9]]),
    });
    assert.equal(held.length, 0);
  });

  it('уже открытый хвост закрывается по пику прошлой атаки', () => {
    const tail = [current, ...prev.get('provider|isp:verolayn')];
    const active = new Map([['provider|isp:verolayn', {
      id: 'provider|isp:verolayn|2026-10-05 06:05:00',
      signal: 'volume',
      scope: 'provider',
      scopeId: 'isp:verolayn',
      alertByProto: { all: { bps: 0.924e9 } },
      verdict: { hourP95: 367e6 },
      track: { peak: { bps: 1.22e9 } },
    }]]);
    const opts = {
      settings: { volumeQuiet: 5 },
      activeByKey: active,
      recentPeakByKey: new Map([['provider|isp:verolayn', 26.6e9]]),
    };
    assert.equal(pickNormalizeCandidates(tail, prev, 1.6, opts).length, 1);
    assert.equal(pickNormalizeCandidates(tail, prev, 1.6, { ...opts, recentPeakByKey: new Map() }).length, 0);
  });
});
