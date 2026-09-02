'use strict';

const KINDS = {
  volumetric: 'volumetric',
  carpet: 'carpet',
  syn_flood: 'syn_flood',
  benign_peak: 'benign_peak',
};

const KIND_LABEL = {
  volumetric: 'атака в один сервер',
  carpet: 'атака по сети',
  syn_flood: 'SYN-флуд',
  benign_peak: 'обычный пик',
};

const HOUR_RATIO_PEAK = 1.3;
const ENTROPY_MIXED = 3;
const ENTROPY_FOCUSED = 1.5;
const TOP_DST_VOLUMETRIC = 0.8;
const TOP_DST_CARPET = 0.08;
const UDP_DOMINANT = 0.6;
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

function classifyFromMetrics(byProto = {}, hour = {}) {
  const all = byProto.all || {};
  const tcp = byProto.tcp || {};
  const udp = byProto.udp || {};
  const udpShare = protoShare(byProto, 'udp');
  const tcpShare = protoShare(byProto, 'tcp');
  const entropy = num(udp.port_entropy ?? udp.portEntropy ?? all.port_entropy ?? all.portEntropy);
  const ratio = hourRatio(all.bps, hour.p999);
  const synAttempts = num(all.syn_attempts ?? all.synAttempts) || 0;
  const answerPct = num(all.answer_pct ?? all.answerPct);
  const reasons = [];

  if (ratio != null) reasons.push(`объём ×${ratio.toFixed(2)} к норме часа`);
  if (udpShare != null) reasons.push(`UDP ${(udpShare * 100).toFixed(0)}%`);
  if (entropy != null) reasons.push(`энтропия ${entropy.toFixed(2)}`);

  let kind = KINDS.benign_peak;
  if (synAttempts >= 200 && answerPct != null && answerPct < 15 && (tcpShare == null || tcpShare >= 0.5)) {
    kind = KINDS.syn_flood;
    reasons.unshift('много SYN, мало ответов');
  } else if (ratio != null && ratio < HOUR_RATIO_PEAK && (entropy == null || entropy >= ENTROPY_MIXED)) {
    kind = KINDS.benign_peak;
    reasons.unshift('объём в пределах часа, форма смешанная');
  } else if (entropy != null && entropy < ENTROPY_FOCUSED && (udpShare == null || udpShare >= 0.45)) {
    kind = KINDS.volumetric;
    reasons.unshift('трафик схлопнулся в узкий набор портов');
  } else if ((ratio == null || ratio >= 1.8) && udpShare != null && udpShare >= UDP_DOMINANT) {
    kind = KINDS.carpet;
    reasons.unshift('сильный рост и доминирует UDP');
  } else if (ratio != null && ratio >= 1.8) {
    kind = KINDS.carpet;
    reasons.unshift('объём сильно выше нормы часа');
  } else {
    kind = KINDS.benign_peak;
    reasons.unshift('нет явных признаков атаки');
  }

  return {
    kind,
    reason: reasons.slice(0, 3).join(' · '),
    hourP95: num(hour.p95),
    hourP999: num(hour.p999),
    hourRatio: ratio,
    udpShare,
    entropy,
    needsInvestigate: kind !== KINDS.benign_peak,
  };
}

function refineClassification(verdict, investigate) {
  const next = { ...(verdict || {}) };
  const topShare = num(investigate?.victim?.share);
  const ratio = num(next.hourRatio);
  const udpShare = num(next.udpShare);
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
  return kind === KINDS.volumetric || kind === KINDS.carpet || kind === KINDS.syn_flood;
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

function actionFor(verdict, investigate) {
  const kind = verdict?.kind;
  const victim = investigate?.victim;
  if (kind === KINDS.volumetric && victim?.ip) {
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
  classifyFromMetrics,
  refineClassification,
  isAttackKind,
  formatSwitchPort,
  formatVictim,
  formatSourceNets,
  formatL4Sources,
  actionFor,
  volumeStillHigh,
  protoShare,
  hourRatio,
};
