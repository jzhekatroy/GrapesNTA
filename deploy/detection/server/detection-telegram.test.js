'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  DEFAULT_GROWTH_THRESHOLD,
  DEFAULT_ALERT_SCOPE,
  DEFAULT_ALERT_KIND,
  DEFAULT_STREAK,
  DEFAULT_NORMALIZE_STREAK,
  DEFAULT_TELEGRAM_API_URL,
  shortErrorMsg,
  normalizeTelegramApiUrl,
  normalizeTelegramProxyUrl,
  redactTelegramProxyUrl,
  resolveTelegramProxyUrl,
  telegramMethodUrl,
  isAboveGrowthThreshold,
  shouldSendAlert,
  shouldSendNormalize,
  matchesAlertScope,
  matchesAlertKind,
  isAlertAttack,
  historyStatusSql,
  normalizeAlertKind,
  pickAlertCandidates,
  pickNormalizeCandidates,
  formatAlertMessage,
  mapEventRow,
  formatNormalizeMessage,
  snapshotByProto,
} = require('./detection-telegram');
const { emptyInvestigate } = require('./detection-investigate');

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
    assert.match(text, /Сеть \/24: <b>TestNet \(10\.0\.0\.0\/24\)<\/b>/);
    assert.match(text, /Пришло <b>1\.00 Гбит\/с<\/b>/);
    assert.match(text, /TCP 500 Мбит\/с · UDP 1\.00 Мбит\/с/);
    assert.doesNotMatch(text, /Объём:/);
    assert.match(text, /Порог ×1\.60 · стабильно 3 знач\. · рассылка: всё/);
    assert.match(text, /🔴/);
    // Полные метрики по трём протоколам остаются под саммери.
    assert.match(text, /<b>Метрики за минуту<\/b>/);
    assert.match(text, /<b>общее<\/b>/);
    assert.match(text, /попытки \/ ответ/);
    assert.match(text, /энтропия портов вх\./);
    // Поля, дублировавшие шапку и порог.
    assert.doesNotMatch(text, /Тип объекта/);
    assert.doesNotMatch(text, /^ID: /m);
    assert.doesNotMatch(text, /Порог: ×/);
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
    assert.match(text, /Ромашка &amp; Ко &lt;НТА&gt;/);
    assert.match(text, /‼ рост bps: ×4\.00/);
    assert.match(text, /‼ с портов усилителей: 1\.50 Гбит\/с · доля 75% · 40 источников/);
    assert.match(text, /<b>UDP<\/b>/);
    // Спокойная метрика идёт без метки.
    assert.match(text, / рост bps: ×1\.10/);
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
    assert.match(text, /🟡/);
    assert.match(text, /похоже на легитимный всплеск/);
    assert.match(text, /в пределах нормы часа/);
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
    assert.match(event.alertText, /🟡/);
    assert.match(event.alertText, /похоже на легитимный всплеск/);
    assert.match(event.alertText, /TTK/);
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
    assert.match(text, /🟡/);
    assert.match(text, /легитимная загрузка/);
    assert.match(text, /пик загрузки, фильтр не нужен/);
    assert.doesNotMatch(text, /АТАКА/);
    assert.doesNotMatch(text, /резать TCP/);
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
    assert.match(text, /🟡/);
    assert.match(text, /легитимная загрузка/);
    assert.match(text, /пик загрузки, фильтр не нужен/);
    assert.doesNotMatch(text, /АТАКА/);
    assert.doesNotMatch(text, /Заграница/);
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
    assert.match(text, /🟡/);
    assert.match(text, /легитимная загрузка/);
    assert.match(text, /пик загрузки, фильтр не нужен/);
    assert.match(text, /С сети 154\.85\.88\.0\/24 \(AS139057 Edgenext Legend Dynasty\) пришло <b>2\.23 Гбит\/с<\/b>/);
    assert.match(text, /37 адресов · TCP на :1935/);
    assert.match(text, /это 81% трафика клиента/);
    assert.match(text, /43\.175\.146\.57:1935 — 41% · 43\.175\.146\.0\/24/);
    assert.match(text, /Объём клиента сейчас 2\.74 Гбит\/с, обычно 116 Мбит\/с — в 24 раза выше/);
    assert.doesNotMatch(text, /АТАКА/);
    assert.doesNotMatch(text, /Заграница/);
    assert.doesNotMatch(text, /Объём:/);
    assert.doesNotMatch(text, /L4 откуда/);
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
    assert.match(text, /С порта 53 \(DNS\) пришло <b>516 Мбит\/с<\/b>/);
    assert.match(text, /36 чужих резолверов · ответы по ~1\s?136 байт/);
    assert.match(text, /это 23% его UDP и 3% всего трафика клиента/);
    assert.match(text, /Куда: по сети клиента, не один сервер/);
    assert.match(text, /Объём клиента сейчас 15\.5 Гбит\/с, обычно 53\.0 Гбит\/с — ниже нормы/);
    assert.match(text, /По общему графику эту атаку не видно/);
    assert.match(text, /резать входящий UDP\/53 на сеть клиента/);
    assert.doesNotMatch(text, /Паразит/);
    assert.doesNotMatch(text, /отражател/i);
    assert.doesNotMatch(text, /в один адрес не бьёт/);
    assert.doesNotMatch(text, /TCP\/443/);
    assert.doesNotMatch(text, /185\.129\.101\.255/);
    assert.doesNotMatch(text, /Заграница/);
    assert.doesNotMatch(text, /⚠ Объём/);
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
    assert.match(text, /185\.221\.214\.0\/24 — 100% · 1 адрес · 188 Мбит\/с/);
    assert.match(text, /185\.221\.214\.17 — 100% · 188 Мбит\/с/);
    assert.match(text, /На порт :7709/);
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
    assert.match(text, /С порта 53 \(DNS\) пришло <b>174 Мбит\/с<\/b>/);
    assert.match(text, /13 чужих резолверов · ответы по ~1\s?419 байт/);
    assert.match(text, /это 16% его UDP и 4% всего трафика клиента/);
    assert.match(text, /Куда \(UDP\/53\):/);
    assert.match(text, /31\.171\.101\.0\/24 — 99% · 10 адресов · 172 Мбит\/с/);
    assert.match(text, /91\.218\.160\.0\/24 — 1% · 1 адрес/);
    assert.match(text, /31\.171\.101\.14 — 12% · 20(?:\.0)? Мбит\/с/);
    assert.match(text, /31\.171\.101\.88 — 11% · 18(?:\.0)? Мбит\/с/);
    assert.match(text, /На 214 портов/);
    assert.match(text, /топ :53 2% · :443 0\.5% · :55094 0\.4% · :14397 0\.4% · :8010 0\.4%/);
    assert.match(text, /резать входящий UDP\/53 на 31\.171\.101\.0\/24/);
    assert.match(text, /Объём клиента сейчас 4\.68 Гбит\/с, обычно 6\.97 Гбит\/с — ниже нормы/);
    assert.doesNotMatch(text, /188\.143\.1\.10/);
    assert.doesNotMatch(text, /Паразит/);
    assert.doesNotMatch(text, /×1\.43/);
    assert.doesNotMatch(text, /122 Мбит/);
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
    assert.match(text, /🔴/);
    assert.match(text, /АТАКА · зарубежный трафик/);
    assert.match(text, /Заграница 11% · <b>1\.07 Гбит\/с<\/b>/);
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
      },
    });
    assert.match(text, /АТАКА · в один сервер/);
    assert.match(text, /На 185\.26\.122\.4:443 пришло <b>5\.80 Гбит\/с<\/b>/);
    assert.match(text, /UDP · топ IP 99%/);
    assert.match(text, /185\.26\.122\.4:443 — 99% · 185\.26\.122\.0\/24/);
    assert.match(text, /port-channel2/);
    assert.match(text, /Ethernet1\/31/);
    assert.match(text, /UDP\/80/);
    assert.doesNotMatch(text, /‼ Цель/);
    assert.doesNotMatch(text, /Объём:/);
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
    assert.match(text, /АТАКА · по сети/);
    assert.match(text, /Пришло <b>5\.90 Гбит\/с<\/b> UDP/);
    assert.match(text, /размазано · топ IP 0\.2%/);
    assert.match(text, /Куда: по сети клиента, не один сервер/);
    assert.match(text, /На порты :80 40% · :443 30% · :53 20%/);
    assert.match(text, /Объём клиента сейчас 5\.90 Гбит\/с, обычно 840 Мбит\/с — в 7 раз выше/);
    assert.doesNotMatch(text, /10\.0\.0\.8:80/);
  });

  it('шапка SYN-флуда — попытки и ответы', () => {
    const text = formatAlertMessage({
      name: 'Hostland',
      scope: 'client',
      scopeId: '83106',
      minute: '2026-09-01 16:49:00',
      threshold: 1.6,
      byProto: { all: { bps: 2e9, syn_attempts: 12000, answer_pct: 4 } },
      verdict: { kind: 'syn_flood' },
    });
    assert.match(text, /АТАКА · SYN-флуд/);
    assert.match(text, /SYN-попыток 12 тыс\. · ответов 4%/);
    assert.match(text, /Куда: на сеть клиента/);
    assert.match(text, /SYN-защита \/ лимит на сеть клиента/);
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
    assert.match(text, /АТАКА · зарубежный трафик/);
    assert.match(text, /Заграница 95% · <b>2\.60 Гбит\/с<\/b>/);
    assert.match(text, /обычно 20% · сейчас ×4\.7/);
    assert.match(text, /SC 82% · KZ 8% · RU 5%/);
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
    assert.match(text, /Порт: 172\.18\.19\.207 · КМ11350 · Ethernet1\/5 · king-/);
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
    assert.match(text, /Пришло <b>2\.37 Гбит\/с<\/b>/);
    assert.doesNotMatch(text, /рост ×0\.96/);
    assert.doesNotMatch(text, /Объём:/);
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
    assert.match(text, /Куда: — \(разбор не удался: Cannot parse IPv4/);
    assert.match(text, /<b>Что делать:<\/b> разбор минуты не удался/);
    assert.doesNotMatch(text, /не эскалировать/);
    assert.doesNotMatch(text, /__table3/);
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
    assert.match(text, /IP: 185\.26\.122\.0\/24/);
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

    const custom = formatAlertMessage({
      name: 'СпейсВэб',
      scope: 'client',
      scopeId: '71764',
      minute: '2026-09-03 13:39:00',
      threshold: client.threshold,
      thresholdIsCustom: client.thresholdIsCustom,
      byProto: { all: { bps: 1e9 } },
      investigate: emptyInvestigate(),
    });
    assert.match(custom, /Порог ×4\.00 \(индивидуальный\) · стабильно/);
    const shared = formatAlertMessage({
      name: 'TestNet',
      scope: 'net',
      scopeId: '10.0.0.0/24',
      minute: '2026-09-03 13:39:00',
      threshold: net.threshold,
      thresholdIsCustom: net.thresholdIsCustom,
      byProto: { all: { bps: 1e9 } },
      investigate: emptyInvestigate(),
    });
    assert.match(shared, /Порог ×1\.60 · стабильно/);
    assert.doesNotMatch(shared, /индивидуальный/);
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
});
