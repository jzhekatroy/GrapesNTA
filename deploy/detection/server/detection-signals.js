'use strict';

const SIGNALS = {
  volume: 'volume',
  amplification: 'amplification',
  syn_flood: 'syn_flood',
  foreign_geo: 'foreign_geo',
};

const SIGNAL_LABEL = {
  volume: 'рост объёма',
  amplification: 'амплификация',
  syn_flood: 'SYN-флуд',
  foreign_geo: 'зарубежный трафик',
};

const SIGNAL_ORDER = [
  SIGNALS.volume,
  SIGNALS.amplification,
  SIGNALS.syn_flood,
  SIGNALS.foreign_geo,
];

const AMPLIFIER_PORTS = [53, 123, 1900, 11211, 389, 161, 19, 111, 3702, 5683, 137];
const AMPLIFIER_PORT_SET = new Set(AMPLIFIER_PORTS);
const AMPLIFIER_PORT_LABEL = {
  53: 'DNS',
  123: 'NTP',
  1900: 'SSDP',
  11211: 'memcached',
  389: 'CLDAP',
  161: 'SNMP',
  19: 'chargen',
  111: 'portmap',
  3702: 'WS-Discovery',
  5683: 'CoAP',
  137: 'NetBIOS',
};

const AMP_SHARE_MIN = 0.15;
const AMP_SRCS_MIN = 10;
const AMP_PKT_MIN = 800;
// Отбор: число отражателей, размер пакета и пол по Мбит. Доля от всего UDP
// клиента не гейтит — у 81953 днём amp 150 Мбит при своём UDP ~1.1 Гбит это
// ~13%, и дежурный терял активное событие. Пол нужен против мелких серверов,
// у которых весь UDP — ответы с 53/123. Замер 07.09: с портов усилителей
// нигде не больше 34 кбит/с; долю/источников/пакет прошли две минуты по 8–9
// кбит/с. При 200 Мбит/с без пола не видно атаку, забившую мелкий канал.
const AMP_BPS_MIN = 20e6;

// SYN-флуд — по пакетам голого SYN, не по uniq рукопожатий.
// Пороги абсолютные и не привязаны к sampling_rate: прежний пол
// max(2000, 30 * rate / 60) сокращался ровно в «30 проб за минуту», потому что
// сами пакеты уже масштабированы (pps = строки * rate / 60). На nta 14.09 это
// открыло 11 событий на фоновом скане хостеров.
// Замер за 12 ч по 217 258 клиенто-минутам: голого SYN нигде не больше 110 тыс.
// п/с, а доля от TCP-классов при заметном объёме — не больше 2.6%. Эталон 81050
// (11.09 19:29) — 4.45 млн п/с и 92% TCP. Новое правило даёт ноль ложных и
// проходит эталон с девятикратным запасом; мелкий флуд сознательно пропускаем.
const TCP_FLOOD_PPS_MIN = 500_000;
const TCP_FLOOD_SHARE_MIN = 0.5;
const TCP_FLOOD_PKT_MAX = 100;
// Страховка от одиночной строки-артефакта. На sFlow 500 тыс. п/с — это сотни
// проб, так что порог работает только на NetFlow, где rate=1.
const TCP_FLOOD_ROWS_MIN = 5;
const TCP_SCAN_ROWS_MIN = 200;
const TCP_CLASS_KEYS = ['syn_only', 'ack_only', 'rst', 'established', 'data'];

const GEO_SHARE_GROWTH_MIN = 3;
const GEO_VOLUME_GROWTH_MIN = 4;
const GEO_SHARE_MIN = 0.2;
// Абсолютного «много» у географии нет: для одного клиента 200 Мбит/с — обычный
// день, для другого — весь его трафик. Масштаб держат относительные пороги
// выше, а этот пол нужен только против шума на пустых клиентах. Замер за 10
// спокойных минут 07.09: при 200 Мбит/с признак не срабатывает ни разу, при
// 20 — 4 клиенто-минуты, при 10 — уже 26.
const GEO_BPS_MIN = 20e6;

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function share(part, whole) {
  const w = num(whole);
  const p = num(part);
  if (!(w > 0) || p == null) return null;
  return Math.max(0, Math.min(1, p / w));
}

function classField(row, prefix, suffix) {
  const snake = `${prefix}_${suffix}`;
  const camel = snake.replace(/_([a-z])/g, (_, ch) => ch.toUpperCase());
  return num(row?.[snake] ?? row?.[camel]) || 0;
}

function tcpClassMetrics(row = {}, prefix = 'syn_only') {
  const bytes = classField(row, prefix, 'bytes');
  const packets = classField(row, prefix, 'packets');
  const rows = classField(row, prefix, 'rows');
  return {
    bytes,
    packets,
    rows,
    pps: packets / 60,
    bps: bytes * 8 / 60,
    avgPkt: packets > 0 ? bytes / packets : 0,
  };
}

// Доля голого SYN среди TCP-пакетов минуты. Знаменатель собираем из классов
// той же строки, а не из строки proto='tcp': классы считаются только по TCP и
// есть в любой строке минуты, поэтому признак не зависит от того, какой срез
// протокола пришёл. Классы слегка пересекаются (SYN+ACK+PSH попадает и в
// established, и в data) — знаменатель чуть завышен, значит доля занижена.
function synFloodShare(row = {}) {
  const syn = tcpClassMetrics(row, 'syn_only').packets;
  const total = TCP_CLASS_KEYS
    .reduce((sum, key) => sum + tcpClassMetrics(row, key).packets, 0);
  return share(syn, total);
}

function isSynFloodHit(row = {}, options = {}) {
  const m = tcpClassMetrics(row, 'syn_only');
  const pktMax = num(options.pktMax) ?? TCP_FLOOD_PKT_MAX;
  const rowsMin = num(options.rowsMin) ?? TCP_FLOOD_ROWS_MIN;
  const ppsMin = num(options.ppsMin) ?? TCP_FLOOD_PPS_MIN;
  const shareMin = num(options.shareMin) ?? TCP_FLOOD_SHARE_MIN;
  if (m.rows < rowsMin) return false;
  if (!(m.avgPkt > 0 && m.avgPkt < pktMax)) return false;
  if (m.pps < ppsMin) return false;
  const synShare = synFloodShare(row);
  return synShare != null && synShare >= shareMin;
}

function synFloodStillGoing(row = {}, options = {}) {
  return isSynFloodHit(row, options);
}

function isTcpScan(row = {}) {
  if (isSynFloodHit(row)) return false;
  const m = tcpClassMetrics(row, 'syn_only');
  const attempts = num(row.syn_attempts ?? row.synAttempts) || 0;
  return m.rows >= TCP_SCAN_ROWS_MIN || attempts >= TCP_SCAN_ROWS_MIN;
}

function ampMetrics(row = {}) {
  const bytes = num(row.amp_bytes ?? row.ampBytes) || 0;
  const packets = num(row.amp_packets ?? row.ampPackets) || 0;
  const srcs = num(row.amp_srcs ?? row.ampSrcs) || 0;
  const udpBytes = num(row.bytes) || 0;
  return {
    bytes,
    packets,
    srcs,
    share: share(bytes, udpBytes),
    avgPkt: packets > 0 ? bytes / packets : 0,
    bps: bytes * 8 / 60,
    growth: num(row.growth_amp ?? row.growthAmp),
  };
}

function isAmplificationHit(row = {}, options = {}) {
  const m = ampMetrics(row);
  const srcsMin = num(options.srcsMin) ?? AMP_SRCS_MIN;
  const pktMin = num(options.pktMin) ?? AMP_PKT_MIN;
  const bpsMin = num(options.bpsMin) ?? AMP_BPS_MIN;
  return m.srcs >= srcsMin
    && m.avgPkt >= pktMin
    && m.bps >= bpsMin;
}

// Упор нормализации: крупные ответы с усилителей ещё идут, даже если доля
// UDP или число IP на минуту просели ниже порога открытия. Открытие не трогаем.
function ampStillGoing(row = {}, options = {}) {
  const m = ampMetrics(row);
  const pktMin = num(options.pktMin) ?? AMP_PKT_MIN;
  const bpsMin = num(options.bpsMin) ?? AMP_BPS_MIN;
  return m.bps >= bpsMin && m.avgPkt >= pktMin;
}

function amplifierPortsFromL4(list) {
  const rows = Array.isArray(list) ? list : [];
  const ports = [];
  for (const row of rows) {
    const port = Number(row.port);
    if (AMPLIFIER_PORT_SET.has(port) && !ports.includes(port)) ports.push(port);
  }
  return ports;
}

function amplifierLabel(ports) {
  const names = (ports || [])
    .map((p) => AMPLIFIER_PORT_LABEL[p])
    .filter(Boolean);
  return names.length ? names.join('/') : '';
}

function parseTopCountries(raw) {
  const text = String(raw || '').trim();
  if (!text) return [];
  return text.split(',').map((part) => {
    const [cc, shareRaw] = part.split(':');
    const code = String(cc || '').trim().toUpperCase();
    const value = Number(shareRaw);
    if (!code) return null;
    return { cc: code, share: Number.isFinite(value) ? value : null };
  }).filter(Boolean);
}

function formatTopCountries(list) {
  const rows = Array.isArray(list) ? list : parseTopCountries(list);
  if (!rows.length) return '';
  return rows.slice(0, 5).map((row) => {
    const pct = row.share != null ? ` ${(row.share * 100).toFixed(0)}%` : '';
    return `${row.cc}${pct}`;
  }).join(' · ');
}

function foreignMetrics(row = {}) {
  const bytes = num(row.foreign_bytes ?? row.foreignBytes) || 0;
  const srcs = num(row.foreign_srcs ?? row.foreignSrcs) || 0;
  const total = num(row.bytes) || 0;
  return {
    bytes,
    srcs,
    share: share(bytes, total),
    bps: bytes * 8 / 60,
    shareGrowth: num(row.growth_foreign_share ?? row.growthForeignShare),
    bpsGrowth: num(row.growth_foreign_bps ?? row.growthForeignBps),
    top: parseTopCountries(row.top_countries ?? row.topCountries),
  };
}

function evaluateForeignGeo(row = {}, envelope = {}, options = {}) {
  const m = foreignMetrics(row);
  const shareNormRaw = num(envelope.shareP95 ?? envelope.p95Share);
  const bpsNorm = num(envelope.bpsP95 ?? envelope.p95Bps);
  const shareGrowth = m.shareGrowth != null
    ? m.shareGrowth
    : (shareNormRaw > 0 && m.share != null ? m.share / shareNormRaw : null);
  const bpsGrowth = m.bpsGrowth != null
    ? m.bpsGrowth
    : (bpsNorm > 0 ? m.bps / bpsNorm : null);
  const shareNorm = shareNormRaw > 0
    ? shareNormRaw
    : (shareGrowth > 0 && m.share != null ? m.share / shareGrowth : null);
  const shareGrowthMin = num(options.shareGrowthMin) ?? GEO_SHARE_GROWTH_MIN;
  const volumeGrowthMin = num(options.volumeGrowthMin) ?? GEO_VOLUME_GROWTH_MIN;
  const shareMin = num(options.shareMin) ?? GEO_SHARE_MIN;
  const bpsMin = num(options.bpsMin) ?? GEO_BPS_MIN;
  const hit = shareGrowth != null
    && bpsGrowth != null
    && shareGrowth >= shareGrowthMin
    && bpsGrowth >= volumeGrowthMin
    && m.share != null
    && m.share >= shareMin
    && m.bps >= bpsMin;
  return {
    hit,
    share: m.share,
    bps: m.bps,
    srcs: m.srcs,
    shareGrowth,
    bpsGrowth,
    shareNorm,
    bpsNorm,
    top: m.top,
  };
}

function isForeignGeoHit(row, envelope, options) {
  return evaluateForeignGeo(row, envelope, options).hit;
}

function objectSignalKey(scope, scopeId, signal = SIGNALS.volume) {
  return `${scope}|${scopeId}|${signal || SIGNALS.volume}`;
}

module.exports = {
  SIGNALS,
  SIGNAL_LABEL,
  SIGNAL_ORDER,
  TCP_FLOOD_PPS_MIN,
  TCP_FLOOD_SHARE_MIN,
  TCP_FLOOD_PKT_MAX,
  TCP_FLOOD_ROWS_MIN,
  TCP_SCAN_ROWS_MIN,
  TCP_CLASS_KEYS,
  tcpClassMetrics,
  synFloodShare,
  isSynFloodHit,
  synFloodStillGoing,
  isTcpScan,
  AMPLIFIER_PORTS,
  AMPLIFIER_PORT_SET,
  AMPLIFIER_PORT_LABEL,
  AMP_SHARE_MIN,
  AMP_SRCS_MIN,
  AMP_PKT_MIN,
  AMP_BPS_MIN,
  GEO_SHARE_GROWTH_MIN,
  GEO_VOLUME_GROWTH_MIN,
  GEO_SHARE_MIN,
  GEO_BPS_MIN,
  ampMetrics,
  isAmplificationHit,
  ampStillGoing,
  amplifierPortsFromL4,
  amplifierLabel,
  parseTopCountries,
  formatTopCountries,
  foreignMetrics,
  evaluateForeignGeo,
  isForeignGeoHit,
  objectSignalKey,
};
