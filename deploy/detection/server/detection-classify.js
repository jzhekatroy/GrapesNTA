'use strict';

const { BASELINE_P95_CAP, BASELINE_RECENT_CAP } = require('./detection-core');
const {
  isAmplificationHit,
  ampMetrics,
  evaluateForeignGeo,
  amplifierPortsFromL4,
} = require('./detection-signals');

const KINDS = {
  volumetric: 'volumetric',
  carpet: 'carpet',
  syn_flood: 'syn_flood',
  amplification: 'amplification',
  benign_peak: 'benign_peak',
};

const KIND_LABEL = {
  volumetric: 'атака в один сервер',
  carpet: 'атака по сети',
  syn_flood: 'SYN-флуд',
  amplification: 'амплификация',
  benign_peak: 'обычный пик',
};

const HOUR_RATIO_PEAK = 1.3;
const ENTROPY_MIXED = 3;
const ENTROPY_FOCUSED = 1.5;
const TOP_DST_VOLUMETRIC = 0.8;
const TOP_DST_CARPET = 0.08;
const UDP_DOMINANT = 0.6;
const DOWNLOAD_SRC_SHARE_MIN = 0.5;
const DOWNLOAD_SRC_IPS_MAX = 2;
const VICTIM_ACTION_SHARE_MIN = 0.15;
const AMP_DEST_ACTION_SHARE = 0.5;
const NORMALIZE_BPS_KEEP = 0.85;

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

function protoShare(byProto, proto) {
  return share(byProto?.[proto]?.bps, byProto?.all?.bps);
}

function hourRatio(bps, hourP999) {
  const env = num(hourP999);
  const cur = num(bps);
  if (!(env > 0) || cur == null) return null;
  return cur / env;
}

// p999 по выборке из ~250 минут это её максимум, так что одна серия всплесков
// поднимает норму до себя и следующие минуты той же атаки выглядят обычными.
// Потолок от p95 оставляет норме запас на честные пики, но не на порядок,
// а медиана последнего часа не даёт норме отстать от текущего уровня клиента.
function hourCeiling(hour = {}) {
  const p999 = num(hour?.p999);
  const p95 = num(hour?.p95);
  const recent = num(hour?.recentMedian);
  const history = p999 > 0 && p95 > 0 ? Math.min(p999, p95 * BASELINE_P95_CAP) : p999;
  const local = recent > 0 ? recent * BASELINE_RECENT_CAP : null;
  if (local == null) return history;
  if (!(history > 0)) return local;
  return Math.max(history, local);
}

function classifyFromMetrics(byProto = {}, hour = {}) {
  const all = byProto.all || {};
  const tcp = byProto.tcp || {};
  const udp = byProto.udp || {};
  const udpShare = protoShare(byProto, 'udp');
  const tcpShare = protoShare(byProto, 'tcp');
  const entropy = num(udp.port_entropy ?? udp.portEntropy ?? all.port_entropy ?? all.portEntropy);
  const ceiling = hourCeiling(hour);
  const ratio = hourRatio(all.bps, ceiling);
  const synAttempts = num(all.syn_attempts ?? all.synAttempts) || 0;
  const answerPct = num(all.answer_pct ?? all.answerPct);
  const amp = ampMetrics(udp);
  const ampHit = isAmplificationHit(udp);
  const geo = evaluateForeignGeo(all, hour.foreign || {});
  const reasons = [];

  if (ratio != null) reasons.push(`объём ×${ratio.toFixed(2)} к норме часа`);
  if (udpShare != null) reasons.push(`UDP ${(udpShare * 100).toFixed(0)}%`);
  if (entropy != null) reasons.push(`энтропия ${entropy.toFixed(2)}`);
  if (ampHit && amp.share != null) reasons.push(`отражатели ${(amp.share * 100).toFixed(0)}%`);
  if (geo.hit && geo.shareGrowth != null) reasons.push(`зарубежный трафик ×${geo.shareGrowth.toFixed(1)} к норме часа`);

  let kind = KINDS.benign_peak;
  if (synAttempts >= 200 && answerPct != null && answerPct < 15 && (tcpShare == null || tcpShare >= 0.5)) {
    kind = KINDS.syn_flood;
    reasons.unshift('много SYN, мало ответов');
  } else if (ampHit) {
    kind = KINDS.amplification;
    reasons.unshift(`трафик с портов усилителей · ${amp.srcs} источников`);
  } else if (ratio != null && ratio < HOUR_RATIO_PEAK && (entropy == null || entropy >= ENTROPY_MIXED)) {
    kind = KINDS.benign_peak;
    reasons.unshift('объём в пределах часа, форма смешанная');
  } else if (entropy != null && entropy < ENTROPY_FOCUSED && (udpShare == null || udpShare >= 0.45)) {
    kind = KINDS.volumetric;
    reasons.unshift('трафик схлопнулся в узкий набор портов');
  } else if ((ratio == null || ratio >= 1.8) && udpShare != null && udpShare >= UDP_DOMINANT) {
    kind = KINDS.carpet;
    reasons.unshift('сильный рост и доминирует UDP');
  } else {
    // Рост к норме часа сам по себе — не атака: у тихих абонентов любой
    // скачивание даёт ×70–3000. Атака здесь только по форме (UDP / узкие порты / SYN / amp).
    kind = KINDS.benign_peak;
    reasons.unshift('нет явных признаков атаки');
  }

  return {
    kind,
    reason: reasons.slice(0, 3).join(' · '),
    hourP95: num(hour.p95),
    hourP999: num(hour.p999),
    hourCeiling: ceiling,
    hourRatio: ratio,
    udpShare,
    entropy,
    ampShare: amp.share,
    ampSrcs: amp.srcs,
    ampBps: amp.bps,
    foreignShare: geo.share,
    foreignShareGrowth: geo.shareGrowth,
    foreignBpsGrowth: geo.bpsGrowth,
    foreignHit: geo.hit,
    tcpShare,
    avgPkt: num(all.avg_packet_bytes ?? all.avgPacketBytes
      ?? tcp.avg_packet_bytes ?? tcp.avgPacketBytes),
    synAttempts,
    answerPct,
    needsInvestigate: kind !== KINDS.benign_peak || geo.hit,
  };
}

function topL4(investigate) {
  return Array.isArray(investigate?.l4src) ? investigate.l4src[0] : null;
}

function l4ProtoNum(l4) {
  if (!l4) return null;
  if (Number(l4.proto) === 17) return 17;
  if (Number(l4.proto) === 6) return 6;
  const label = String(l4.protoLabel || '').toUpperCase();
  if (label === 'UDP') return 17;
  if (label === 'TCP') return 6;
  return null;
}

function hasNarrowSource(investigate) {
  const src = Array.isArray(investigate?.source24) ? investigate.source24[0] : null;
  if (!src) return false;
  const srcShare = num(src.share);
  const srcIps = num(src.ips);
  if (!(srcShare >= DOWNLOAD_SRC_SHARE_MIN)) return false;
  if (srcIps != null && srcIps > DOWNLOAD_SRC_IPS_MAX) return false;
  return true;
}

function downloadPeakLabel(investigate) {
  const l4 = topL4(investigate);
  const proto = l4ProtoNum(l4) === 17 ? 'UDP' : 'TCP';
  const port = Number(l4?.port);
  return `${proto}/${Number.isFinite(port) ? port : '?'}`;
}

// Один–два адреса принесли большую часть минуты — сессия (VPN, выкачка,
// туннель), не ботнет. Порт не смотрим: они бывают любыми. Без разбора
// источника не утверждаем, что источник узкий.
function isDownloadPeak(verdict = {}, investigate = {}) {
  if (verdict.kind === KINDS.amplification || verdict.kind === KINDS.syn_flood) return false;
  return hasNarrowSource(investigate);
}

function isLegitimatePeak(verdict = {}) {
  return verdict.kind === KINDS.benign_peak
    && /пик загрузки/.test(String(verdict.reason || ''));
}

function refineClassification(verdict, investigate) {
  const next = { ...(verdict || {}) };
  const topShare = num(investigate?.victim?.share);
  const ratio = num(next.hourRatio);
  const udpShare = num(next.udpShare);
  if (next.kind === KINDS.amplification) {
    if (topShare != null && topShare >= TOP_DST_VOLUMETRIC) {
      next.reason = `амплификация в один сервер · топ IP ${(topShare * 100).toFixed(1)}% · ${next.reason || ''}`.trim();
    } else if (topShare != null && topShare < TOP_DST_CARPET) {
      next.reason = `амплификация по сети · топ IP ${(topShare * 100).toFixed(1)}% · ${next.reason || ''}`.trim();
    }
    next.needsInvestigate = true;
    return next;
  }
  if (isDownloadPeak(next, investigate)) {
    next.kind = KINDS.benign_peak;
    const src = Array.isArray(investigate?.source24) ? investigate.source24[0] : null;
    const srcShare = num(src?.share);
    next.reason = `пик загрузки · узкий источник · ${downloadPeakLabel(investigate)}`
      + (srcShare != null ? ` · /24 ${(srcShare * 100).toFixed(0)}%` : '')
      + (topShare != null ? ` · топ IP ${(topShare * 100).toFixed(1)}%` : '');
    next.needsInvestigate = false;
    return next;
  }
  if (topShare != null && topShare >= TOP_DST_VOLUMETRIC) {
    next.kind = KINDS.volumetric;
    next.reason = `топ IP ${(topShare * 100).toFixed(1)}% · ${next.reason || ''}`.trim();
  } else if (
    topShare != null
    && topShare < TOP_DST_CARPET
    && (udpShare == null || udpShare >= UDP_DOMINANT)
    && (ratio == null || ratio >= 1.8)
  ) {
    next.kind = KINDS.carpet;
    next.reason = `топ IP ${(topShare * 100).toFixed(1)}% · ${next.reason || ''}`.trim();
  } else if (topShare != null && topShare < 0.15 && ratio != null && ratio < HOUR_RATIO_PEAK) {
    next.kind = KINDS.benign_peak;
    next.reason = `нет концентрации · ${next.reason || ''}`.trim();
  }
  next.needsInvestigate = next.kind !== KINDS.benign_peak;
  return next;
}

function isAttackKind(kind) {
  return kind === KINDS.volumetric
    || kind === KINDS.carpet
    || kind === KINDS.syn_flood
    || kind === KINDS.amplification;
}

function formatSwitchPort(port) {
  if (!port || (!port.ifName && !port.ifAlias && !port.ifIndex && !port.switchIp)) return '—';
  const name = port.ifName || (port.ifIndex ? `ifIndex ${port.ifIndex}` : '');
  const alias = port.ifAlias ? ` (${port.ifAlias})` : '';
  const sw = port.switchIp ? `${port.switchIp} ` : '';
  const pct = port.share != null ? ` ${(Number(port.share) * 100).toFixed(0)}%` : '';
  return `${sw}${name}${alias}${pct}`.trim() || '—';
}

function formatVictim(victim) {
  if (!victim?.ip) return '—';
  const proto = victim.protoLabel || victim.proto || '';
  const port = victim.port != null ? `:${victim.port}` : '';
  const net = victim.net24 ? ` · ${victim.net24}` : '';
  const pct = victim.share != null ? ` (${(victim.share * 100).toFixed(1)}%)` : '';
  return `${proto} ${victim.ip}${port}${net}${pct}`.trim();
}

function formatSourceNets(list) {
  const rows = Array.isArray(list) ? list.slice(0, 3) : [];
  if (!rows.length) return '—';
  return rows.map((row) => {
    const pct = row.share != null ? ` ${(row.share * 100).toFixed(1)}%` : '';
    const asn = row.asn ? ` AS${row.asn}` : '';
    const ips = row.ips != null ? ` · ${row.ips} IP` : '';
    return `${row.net24 || row.ip || '—'}${asn}${pct}${ips}`;
  }).join('; ');
}

function formatL4Sources(list) {
  const rows = Array.isArray(list) ? list.slice(0, 3) : [];
  if (!rows.length) return '—';
  return rows.map((row) => {
    const proto = Number(row.proto) === 17 ? 'UDP' : Number(row.proto) === 6 ? 'TCP' : (row.protoLabel || '');
    const pct = row.share != null ? ` ${(row.share * 100).toFixed(0)}%` : '';
    return `${proto}/${row.port}${pct}`;
  }).join(' · ');
}

function isUsableVictim(victim) {
  if (!victim?.ip) return false;
  const share = num(victim.share);
  if (share != null && share < VICTIM_ACTION_SHARE_MIN) return false;
  const proto = Number(victim.proto);
  const label = String(victim.protoLabel || '').toUpperCase();
  if (Number.isFinite(proto) && proto !== 6 && proto !== 17) return false;
  if (label && label !== 'TCP' && label !== 'UDP') return false;
  if (num(victim.port) === 0) return false;
  return true;
}

function actionFor(verdict, investigate) {
  const kind = verdict?.kind;
  const victim = investigate?.victim;
  // Without the investigate slice there is nothing to point a filter at, and
  // "не эскалировать" would read as an all-clear on an attack verdict.
  if (isAttackKind(kind) && investigate?.error) {
    return 'разбор минуты не удался — смотреть вручную';
  }
  if (kind === KINDS.volumetric && isUsableVictim(victim)) {
    const proto = victim.protoLabel || 'трафик';
    const port = victim.port != null ? `:${victim.port}` : '';
    return `резать ${proto} на ${victim.ip}${port}`;
  }
  if (kind === KINDS.carpet) {
    const l4 = formatL4Sources(investigate?.l4src);
    return l4 !== '—'
      ? `фильтр по сети клиента, вход ${l4}`
      : 'фильтр UDP по префиксу клиента, не один сервер';
  }
  if (kind === KINDS.syn_flood) return 'SYN-защита / лимит на префикс клиента';
  if (kind === KINDS.amplification) {
    const ports = amplifierPortsFromL4(investigate?.l4src);
    const udp = ports.length ? ports.map((p) => `UDP/${p}`).join(' и ') : 'UDP с портов усилителей';
    const ampNet = Array.isArray(investigate?.ampDest24) ? investigate.ampDest24[0] : null;
    if (ampNet?.net24 && num(ampNet.share) >= AMP_DEST_ACTION_SHARE) {
      return `резать входящий ${udp} на ${ampNet.net24}`;
    }
    if (isUsableVictim(victim)) return `резать входящий ${udp} на ${victim.ip}`;
    return `резать входящий ${udp} на сеть клиента`;
  }
  if (kind === KINDS.benign_peak) {
    return /пик загрузки/.test(String(verdict?.reason || ''))
      ? 'пик загрузки, фильтр не нужен'
      : 'похоже на легитимный всплеск';
  }
  if (kind === KINDS.volumetric) return 'один сервер под нагрузкой, цель в разборе не определилась';
  return 'не эскалировать';
}

function volumeStillHigh(currentBps, alertBps, hourP95) {
  const cur = num(currentBps);
  const alert = num(alertBps);
  const p95 = num(hourP95);
  if (cur == null) return false;
  if (alert > 0 && cur > alert * NORMALIZE_BPS_KEEP) return true;
  if (p95 > 0 && cur > p95 * 1.25) return true;
  return false;
}

module.exports = {
  KINDS,
  KIND_LABEL,
  HOUR_RATIO_PEAK,
  ENTROPY_FOCUSED,
  classifyFromMetrics,
  refineClassification,
  isDownloadPeak,
  isLegitimatePeak,
  isAttackKind,
  formatSwitchPort,
  formatVictim,
  formatSourceNets,
  formatL4Sources,
  isUsableVictim,
  actionFor,
  volumeStillHigh,
  protoShare,
  hourRatio,
  hourCeiling,
  AMP_DEST_ACTION_SHARE,
};
