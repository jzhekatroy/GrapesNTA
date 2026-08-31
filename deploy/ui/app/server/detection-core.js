'use strict';

const MINUTE = 60 * 1000;
const EXPORT_LAG = 3 * MINUTE;
const BASELINE_DAYS = 14;
const BASELINE_QUANTILE = 0.999;

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
  return 100 * (Number(num) || 0) / d;
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
  };
}

module.exports = {
  MINUTE,
  EXPORT_LAG,
  BASELINE_DAYS,
  BASELINE_QUANTILE,
  parseUtc,
  formatCh,
  ratePercent,
  growthRatio,
  variationPercent,
  minuteMetrics,
};
