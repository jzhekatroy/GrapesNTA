'use strict';

const crypto = require('crypto');
const { insertRows } = require('./clickhouse');
const { parseUtc, formatCh } = require('./detection-core');
const {
  EVENTS_TABLE,
  ensureDetectionTelegramTables,
  loadDetectionEvent,
  mapEventRow,
} = require('./detection-telegram');

const TEST_ATTACK_DURATION_MS = 25_000;
const TEST_SCOPE = 'test';
const TEST_SCOPE_ID = 'ui-test';

const TEST_KINDS = ['volumetric', 'carpet', 'syn_flood', 'amplification'];
const TEST_CLIENT_NAMES = [
  'Демо-клиент (тест)',
  'Песочница NTA',
  'Учебный абонент',
  'QA-профиль',
  'Стенд интеграции',
];
const TEST_COUNTRY_CODES = ['CN', 'US', 'RU', 'DE', 'BR', 'IN', 'VN', 'ID'];
const TEST_ASN_NAMES = ['TEST-ASN-DEMO', 'TEST-ASN-BOT', 'TEST-ASN-SCAN', 'TEST-ASN-FLOOD'];
const TEST_IF_PREFIXES = ['xe-0/0/', 'ae', 'et-', 'Gi0/0/'];

const scheduledNormalize = new Map();

function randInt(min, max) {
  return crypto.randomInt(min, max + 1);
}

function randFloat(min, max) {
  return min + crypto.randomInt(0, 10_000) / 10_000 * (max - min);
}

function pick(list) {
  return list[crypto.randomInt(list.length)];
}

function randomDocHost() {
  const block = pick([
    [203, 0, 113],
    [198, 51, 100],
    [192, 0, 2],
  ]);
  return `${block[0]}.${block[1]}.${block[2]}.${randInt(1, 254)}`;
}

function net24Of(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return `${ip}/24`;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function randomSwitchPort() {
  const ip = `10.255.${randInt(0, 40)}.${randInt(1, 254)}`;
  const ifName = `${pick(TEST_IF_PREFIXES)}${randInt(0, 48)}${pick(['', '.100', '.200'])}`;
  return {
    switchIp: ip,
    ifName,
    ifAlias: pick(['DEMO uplink', 'to core', 'customer access', 'peering', 'backup link']),
  };
}

function randomTestProfile() {
  const kind = pick(TEST_KINDS);
  const totalBps = randInt(600, 7200) * 1_000_000;
  let udpShare = randFloat(0.35, 0.88);
  if (kind === 'syn_flood') udpShare = randFloat(0.05, 0.25);
  if (kind === 'amplification' || kind === 'carpet') udpShare = randFloat(0.72, 0.95);
  const tcpBps = Math.round(totalBps * (1 - udpShare));
  const udpBps = totalBps - tcpBps;
  const totalPps = Math.max(20_000, Math.round(totalBps / randInt(700, 1400)));
  const tcpPps = Math.round(totalPps * (1 - udpShare));
  const udpPps = totalPps - tcpPps;
  const hourP95 = randInt(80, 320) * 1_000_000;
  const victimIp = randomDocHost();
  const victimPort = kind === 'syn_flood' ? 443 : pick([53, 443, 8080, 123, 19]);
  const protoLabel = kind === 'syn_flood' ? 'TCP' : (udpShare > 0.55 ? 'UDP' : 'TCP');
  const clientName = pick(TEST_CLIENT_NAMES);
  const victimShare = randFloat(0.42, 0.78);
  const srcIp1 = randomDocHost();
  let srcIp2 = randomDocHost();
  while (srcIp2 === srcIp1) srcIp2 = randomDocHost();
  const src1Share = randFloat(0.08, 0.22);
  const src2Share = randFloat(0.06, 0.18);
  const country1 = pick(TEST_COUNTRY_CODES);
  let country2 = pick(TEST_COUNTRY_CODES);
  while (country2 === country1) country2 = pick(TEST_COUNTRY_CODES);
  const c1Share = randFloat(0.38, 0.62);
  const c2Share = randFloat(0.12, 0.28);
  const asn1Share = randFloat(0.22, 0.45);
  const asn2Share = randFloat(0.12, 0.28);

  return {
    kind,
    totalBps,
    tcpBps,
    udpBps,
    totalPps,
    tcpPps,
    udpPps,
    hourP95,
    hourRatio: totalBps / hourP95,
    victimIp,
    victimPort,
    protoLabel,
    clientName,
    victimShare,
    srcIp1,
    srcIp2,
    src1Share,
    src2Share,
    src1Bps: Math.round(totalBps * src1Share),
    src2Bps: Math.round(totalBps * src2Share),
    country1,
    country2,
    c1Share,
    c2Share,
    c1Bps: Math.round(totalBps * c1Share),
    c2Bps: Math.round(totalBps * c2Share),
    asn1Share,
    asn2Share,
    asn1Bps: Math.round(totalBps * asn1Share),
    asn2Bps: Math.round(totalBps * asn2Share),
    asn1: randInt(64490, 64512),
    asn2: randInt(64490, 64512),
    switchIn: randomSwitchPort(),
    switchOut: randomSwitchPort(),
    ipCount: randInt(2500, 28_000),
    net24Count: randInt(120, 1800),
    growthBps: randFloat(4, 42),
    growthPps: randFloat(3, 35),
  };
}

function testAttackInvestigate(profile) {
  const dest24Bps = Math.round(profile.totalBps * profile.victimShare);
  const synHeavy = profile.kind === 'syn_flood';
  return {
    victim: {
      ip: profile.victimIp,
      share: profile.victimShare,
      protoLabel: profile.protoLabel,
      port: profile.victimPort,
    },
    dest24: [{ net24: net24Of(profile.victimIp), share: profile.victimShare, bps: dest24Bps }],
    sources: {
      ipCount: profile.ipCount,
      net24Count: profile.net24Count,
      top: [
        { ip: profile.srcIp1, bps: profile.src1Bps, share: profile.src1Share },
        { ip: profile.srcIp2, bps: profile.src2Bps, share: profile.src2Share },
      ],
      asns: [
        {
          asn: profile.asn1,
          name: pick(TEST_ASN_NAMES),
          bps: profile.asn1Bps,
          share: profile.asn1Share,
        },
        {
          asn: profile.asn2,
          name: pick(TEST_ASN_NAMES),
          bps: profile.asn2Bps,
          share: profile.asn2Share,
        },
      ],
      countries: [
        { code: profile.country1, bps: profile.c1Bps, share: profile.c1Share },
        { code: profile.country2, bps: profile.c2Bps, share: profile.c2Share },
      ],
    },
    source24: [{ net24: net24Of(profile.srcIp1), share: profile.src1Share, bps: profile.src1Bps }],
    switchIn: profile.switchIn,
    switchOut: profile.switchOut,
    syn: {
      packets: synHeavy ? randInt(800_000, 4_000_000) : 0,
      bytes: synHeavy ? randInt(40_000_000, 200_000_000) : 0,
      pps: synHeavy ? randInt(12_000, 90_000) : 0,
      bps: synHeavy ? profile.tcpBps : 0,
      avgPkt: synHeavy ? randInt(40, 80) : 0,
      srcIps: synHeavy ? randInt(500, 8000) : 0,
      srcNets: synHeavy ? randInt(80, 900) : 0,
      srcAsns: synHeavy ? randInt(5, 80) : 0,
      dstIps: synHeavy ? randInt(1, 40) : 0,
      portCount: synHeavy ? randInt(1, 12) : 0,
    },
    destPort: {
      count: randInt(2, 5),
      top: [
        { port: profile.victimPort, share: randFloat(0.55, 0.82) },
        { port: pick([53, 80, 443, 123]), share: randFloat(0.08, 0.25) },
      ],
    },
    targets: [],
    focus: null,
    focuses: [],
    replies: {},
    victimShape: null,
    ampDest24: [],
    ampDestIp: [],
    ampDestPort: { count: 0, top: [] },
    ampSrcIp: [],
    ampSrcPort: { count: 0, top: [] },
    l4src: [],
  };
}

function testAttackAlertSnapshot({ nowMs, triggeredBy }) {
  const profile = randomTestProfile();
  const minute = formatCh(nowMs);
  const expiresAt = new Date(nowMs + TEST_ATTACK_DURATION_MS).toISOString();
  const avgPacketAll = Math.round(profile.totalBps / Math.max(1, profile.totalPps) / 8);
  return {
    all: {
      proto: 'all',
      bps: profile.totalBps,
      pps: profile.totalPps,
      bytes: profile.totalBps * 60 / 8,
      packets: profile.totalPps * 60,
      avg_packet_bytes: avgPacketAll,
      growth_bps: profile.growthBps,
      growth_pps: profile.growthPps,
    },
    tcp: {
      proto: 'tcp',
      bps: profile.tcpBps,
      pps: profile.tcpPps,
      bytes: profile.tcpBps * 60 / 8,
      packets: profile.tcpPps * 60,
      avg_packet_bytes: Math.max(64, avgPacketAll - randInt(20, 180)),
      growth_bps: randFloat(2, profile.growthBps),
      port_entropy: randFloat(2.2, 4.8),
    },
    udp: {
      proto: 'udp',
      bps: profile.udpBps,
      pps: profile.udpPps,
      bytes: profile.udpBps * 60 / 8,
      packets: profile.udpPps * 60,
      avg_packet_bytes: Math.max(64, avgPacketAll + randInt(0, 220)),
      growth_bps: randFloat(3, profile.growthBps + 8),
      port_entropy: randFloat(2.8, 5.4),
      ports_per_ip: randInt(4, 42),
    },
    verdict: {
      kind: profile.kind,
      hourP95: profile.hourP95,
      hourP999: profile.hourP95 * randFloat(1.2, 1.55),
      hourCeiling: profile.hourP95 * randFloat(1.8, 2.6),
      hourRatio: profile.hourRatio,
    },
    investigate: testAttackInvestigate(profile),
    binding: {
      clientId: `demo-test-${crypto.randomBytes(3).toString('hex')}`,
      displayName: profile.clientName,
    },
    telegramSkip: 'test',
    telegramText: '',
    test: true,
    testDisplayName: `Тестовая атака · ${profile.clientName}`,
    testNote: `Синтетическое событие (${profile.kind}): проверка модального окна и мониторинга. Цель ${profile.victimIp}.`,
    testExpiresAt: expiresAt,
    testTriggeredBy: String(triggeredBy || ''),
    startMinute: minute,
  };
}

function attachTestAttackLiveState(events) {
  for (const event of events) {
    if (!isTestDetectionEvent(event) || event.status !== 'active') continue;
    const bps = Number(event.alertByProto?.all?.bps) || 0;
    const usual = Number(event.verdict?.hourP95) || 0;
    event.live = {
      state: 'ongoing',
      lastHotBps: bps,
      lastHotBaselineBps: usual,
      lastHotExcessBps: usual > 0 ? Math.max(0, bps - usual) : null,
      peakBps: bps,
      peakMinute: event.alertMinute,
      quietStreak: 0,
      normalizeStreak: 3,
    };
  }
}

function buildTestAttackEventRow({ nowMs = Date.now(), eventId, triggeredBy } = {}) {
  const snapshot = testAttackAlertSnapshot({ nowMs, triggeredBy });
  const id = eventId || `test|${TEST_SCOPE_ID}|${formatCh(nowMs)}|${crypto.randomBytes(4).toString('hex')}`;
  const alertMinute = formatCh(nowMs);
  return {
    event_id: id,
    scope: TEST_SCOPE,
    scope_id: TEST_SCOPE_ID,
    name: snapshot.testDisplayName || `Тестовая атака · ${snapshot.investigate?.victim?.ip || 'demo'}`,
    status: 'active',
    alert_minute: alertMinute,
    normalize_minute: null,
    alert_json: JSON.stringify(snapshot),
    normalize_json: '',
    threshold: 1,
    signal: 'volume',
  };
}

function parseTestExpiresAt(event) {
  const raw = event?.testExpiresAt;
  if (!raw) return NaN;
  return Date.parse(raw);
}

function isTestDetectionEvent(event) {
  return event?.scope === TEST_SCOPE || event?.test === true;
}

function isTestAttackExpired(event, nowMs = Date.now()) {
  if (!isTestDetectionEvent(event)) return false;
  if (event.status !== 'active') return false;
  const expires = parseTestExpiresAt(event);
  if (!Number.isFinite(expires)) return false;
  return nowMs >= expires;
}

function shouldHideTestFromHistory(event) {
  return isTestDetectionEvent(event);
}

function filterDetectionEventsForList(events, { listKind = 'active', nowMs = Date.now() } = {}) {
  return (events || []).filter((event) => {
    if (!isTestDetectionEvent(event)) return true;
    if (listKind === 'history') return false;
    if (event.status === 'active' && isTestAttackExpired(event, nowMs)) return false;
    return true;
  });
}

async function insertDetectionEventRow(row) {
  await insertRows(EVENTS_TABLE, [row], { name: 'detection/events-insert' });
}

async function normalizeTestAttack(eventId, alertJson = '') {
  const pending = scheduledNormalize.get(eventId);
  if (pending?.timer) {
    clearTimeout(pending.timer);
    scheduledNormalize.delete(eventId);
  }
  let event;
  try {
    event = await loadDetectionEvent(eventId);
  } catch {
    return;
  }
  if (!isTestDetectionEvent(event) || event.status !== 'active') return;
  const nowMs = Date.now();
  const minute = formatCh(nowMs);
  await insertDetectionEventRow({
    event_id: event.id,
    scope: event.scope,
    scope_id: event.scopeId,
    name: event.name,
    status: 'normalized',
    alert_minute: event.alertMinute,
    normalize_minute: minute,
    alert_json: alertJson,
    normalize_json: JSON.stringify({ telegramSkip: 'test', telegramText: '' }),
    threshold: event.threshold,
    signal: event.signal || 'volume',
  });
}

function scheduleTestAttackNormalize(eventId, alertJson, delayMs = TEST_ATTACK_DURATION_MS) {
  const prev = scheduledNormalize.get(eventId);
  if (prev?.timer) clearTimeout(prev.timer);
  const timer = setTimeout(() => {
    scheduledNormalize.delete(eventId);
    normalizeTestAttack(eventId, alertJson).catch((err) => {
      console.warn(new Date().toISOString(), 'test attack normalize failed', eventId, err.message);
    });
  }, delayMs);
  if (typeof timer.unref === 'function') timer.unref();
  scheduledNormalize.set(eventId, { timer, alertJson });
}

async function createTestAttack({ triggeredBy } = {}) {
  await ensureDetectionTelegramTables();
  const row = buildTestAttackEventRow({ triggeredBy });
  await insertDetectionEventRow(row);
  scheduleTestAttackNormalize(row.event_id, row.alert_json);
  return mapEventRow(row);
}

module.exports = {
  TEST_ATTACK_DURATION_MS,
  TEST_SCOPE,
  TEST_KINDS,
  buildTestAttackEventRow,
  testAttackAlertSnapshot,
  randomTestProfile,
  isTestDetectionEvent,
  isTestAttackExpired,
  shouldHideTestFromHistory,
  filterDetectionEventsForList,
  createTestAttack,
  scheduleTestAttackNormalize,
  normalizeTestAttack,
  attachTestAttackLiveState,
};
