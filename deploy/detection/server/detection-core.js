'use strict';

const MINUTE = 60 * 1000;
const EXPORT_LAG = 3 * MINUTE;
const BASELINE_DAYS = 14;
const BASELINE_QUANTILE = 0.999;
// Норма часа берётся по тому же часу ±1 за прошлые недели, поэтому в выборку
// попадают и минуты текущего часа прямо перед алертом. Атака, разогнавшаяся за
// несколько минут, успевает записать себя в норму: на ~250 точках p999 это
// фактически максимум выборки. Ближний час выкидываем...
const BASELINE_QUARANTINE_MINUTES = 60;
// ...а на p999 ставим потолок от p95, чтобы атака длиннее карантина тоже не
// смогла назначить себя нормой.
const BASELINE_P95_CAP = 4;
// Карантин отрезает и сегодняшний контекст, а у растущих клиентов прошлые
// недели ниже текущего рабочего уровня: у АТС Смольного норма без ближнего
// часа выходила 1.27 Гбит/с при честных 2.9, и обычное утро читалось как
// ковровая атака. Поэтому норма не опускается ниже медианы последнего часа с
// небольшим запасом: плавный рост остаётся нормой, скачок в разы — нет.
const BASELINE_RECENT_CAP = 1.6;
// Объекты тише порога не пишем: на них не бывает значимой атаки,
// а таблицу и вкладку они забивают десятками тысяч пустых строк.
const MIN_BPS = Number(process.env.DETECTION_MIN_BPS) || 20e6;

function parseUtc(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return value;
  const raw = String(value || '').trim();
  if (!raw) return NaN;
  if (raw.includes('T')) return Date.parse(raw.endsWith('Z') ? raw : `${raw}Z`);
  return Date.parse(`${raw.replace(' ', 'T')}Z`);
}

function formatCh(ts) {
  return new Date(ts).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '').replace('Z', '');
}

function ratePercent(num, den) {
  const d = Number(den) || 0;
  if (d <= 0) return null;
  // sFlow может поймать SYN+ACK без SYN — тогда числитель больше знаменателя.
  return Math.min(100, 100 * (Number(num) || 0) / d);
}

function growthRatio(fact, quantile) {
  const q = Number(quantile) || 0;
  if (!(q > 0)) return null;
  return (Number(fact) || 0) / q;
}

function variationPercent(n, sumX, sumSqX) {
  const count = Number(n) || 0;
  if (count <= 0) return null;
  const mu = Number(sumX || 0) / count;
  if (!(mu > 0)) return null;
  const variance = Math.max(0, Number(sumSqX || 0) / count - mu * mu);
  return (100 * Math.sqrt(variance)) / mu;
}

function finiteOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function minuteMetrics(raw = {}) {
  const bytes = Number(raw.bytes || 0);
  const packets = Number(raw.packets || 0);
  const synAttempts = Number(raw.synAttempts || 0);
  const synAnswered = Number(raw.synAnswered || 0);
  const synInFlows = Number(raw.synInFlows || 0);
  const synHalfOpen = Number(raw.synHalfOpen || 0);
  const synHalfOpenReply = Number(raw.synHalfOpenReply || 0);
  return {
    bytes,
    packets,
    bps: bytes * 8 / 60,
    pps: packets / 60,
    avgPacketBytes: packets > 0 ? bytes / packets : 0,
    cvPercent: variationPercent(raw.cvN, raw.cvSum, raw.cvSumSq) ?? 0,
    synAttempts,
    synAnswered,
    synInFlows,
    synHalfOpen,
    synHalfOpenReply,
    answerPct: ratePercent(synAnswered, synAttempts),
    halfOpenPct: ratePercent(synHalfOpen, synInFlows),
    halfOpenReplyPct: ratePercent(synHalfOpenReply, synAttempts),
    portEntropy: finiteOrNull(raw.portEntropy ?? raw.udpPortEntropy),
    portEntropyOut: finiteOrNull(raw.portEntropyOut ?? raw.udpPortEntropyOut),
    portsPerIp: finiteOrNull(raw.portsPerIp ?? raw.udpPortsPerIp),
    portsPerIpOut: finiteOrNull(raw.portsPerIpOut ?? raw.udpPortsPerIpOut),
    ampBytes: Number(raw.ampBytes || 0),
    ampPackets: Number(raw.ampPackets || 0),
    ampSrcs: Number(raw.ampSrcs || 0),
    foreignBytes: Number(raw.foreignBytes || 0),
    foreignSrcs: Number(raw.foreignSrcs || 0),
    topCountries: String(raw.topCountries || ''),
  };
}

module.exports = {
  MINUTE,
  EXPORT_LAG,
  BASELINE_DAYS,
  BASELINE_QUANTILE,
  BASELINE_QUARANTINE_MINUTES,
  BASELINE_P95_CAP,
  BASELINE_RECENT_CAP,
  MIN_BPS,
  parseUtc,
  formatCh,
  ratePercent,
  growthRatio,
  variationPercent,
  minuteMetrics,
};
