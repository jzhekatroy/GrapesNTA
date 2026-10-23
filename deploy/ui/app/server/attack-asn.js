#!/usr/bin/env node
'use strict';

/**
 * Список AS и сетей /24, которые били по цели с начала атаки.
 *
 *   node server/attack-asn.js
 *   node server/attack-asn.js --attack 'client:115628|2026-10-23 12:01:00'
 *   node server/attack-asn.js --attack 'client:115628|2026-10-23 12:01:00' --csv
 *   node server/attack-asn.js --all --csv
 *
 * На сервере то же самое из контейнера UI:
 *   docker exec -w /app grapes-nta node server/attack-asn.js --attack '<id>' --csv
 */

const { formatCh, parseUtc, MINUTE } = require('./detection-core');

const DEFAULT_LIMIT = 20000;
const MAX_LIMIT = 100000;
const MAX_ALL = 30;

const CSV_HEADER = [
  'section',
  'attack_id',
  'attack_name',
  'status',
  'scope',
  'scope_id',
  'asn',
  'asn_name',
  'prefix',
  'bytes',
  'share_pct',
  'cumulative_pct',
  'prefix_count',
  'truncated',
];

function parseArgs(argv) {
  const out = {
    help: false,
    csv: false,
    all: false,
    attackId: '',
    limit: DEFAULT_LIMIT,
  };
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      out.help = true;
    } else if (arg === '--csv') {
      out.csv = true;
    } else if (arg === '--all') {
      out.all = true;
    } else if (arg === '--attack' || arg === '--id') {
      out.attackId = takeValue(args, i, arg);
      i += 1;
    } else if (arg.startsWith('--attack=')) {
      out.attackId = arg.slice('--attack='.length);
    } else if (arg === '--limit') {
      out.limit = Number(takeValue(args, i, arg));
      i += 1;
    } else if (arg.startsWith('--limit=')) {
      out.limit = Number(arg.slice('--limit='.length));
    } else {
      throw usageError(`Неизвестный аргумент: ${arg}`);
    }
  }
  if (!out.attackId && args.includes('--attack=')) {
    throw usageError('После --attack нужен идентификатор атаки');
  }
  if (!Number.isFinite(out.limit) || out.limit < 1) {
    throw usageError('--limit: нужно число больше нуля');
  }
  out.limit = Math.min(MAX_LIMIT, Math.floor(out.limit));
  return out;
}

function takeValue(args, index, flag) {
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw usageError(`После ${flag} нужно значение`);
  return value;
}

function usageError(message) {
  const err = new Error(message);
  err.statusCode = 2;
  return err;
}

function attackRange(event, now = Date.now()) {
  const start = parseUtc(event?.startMinute) || parseUtc(event?.alertMinute);
  if (!Number.isFinite(start)) return null;
  let to = now;
  let closed = false;
  if (event?.status !== 'active') {
    const endMinute = event?.status === 'peak' ? event?.alertMinute : event?.normalizeMinute;
    const endTs = parseUtc(endMinute);
    if (Number.isFinite(endTs)) {
      to = Math.min(now, endTs + MINUTE);
      closed = true;
    }
  }
  if (to <= start) to = start + MINUTE;
  return {
    from: formatCh(start),
    to: formatCh(to),
    closed,
  };
}

function rollupParticipants(rows) {
  const list = Array.isArray(rows) ? rows : [];
  let totalBytes = 0;
  const byAsn = new Map();
  const prefixes = [];
  for (const row of list) {
    const asn = Number(row?.asn) || 0;
    const bytes = Number(row?.bytes) || 0;
    const prefix = String(row?.prefix || '');
    if (asn <= 0 || bytes <= 0 || !prefix) continue;
    totalBytes += bytes;
    let item = byAsn.get(asn);
    if (!item) {
      item = {
        asn,
        asnName: String(row.asnName || ''),
        bytes: 0,
        prefixCount: 0,
      };
      byAsn.set(asn, item);
    }
    if (!item.asnName && row.asnName) item.asnName = String(row.asnName);
    item.bytes += bytes;
    item.prefixCount += 1;
    prefixes.push({
      asn,
      asnName: String(row.asnName || item.asnName || ''),
      prefix,
      bytes,
    });
  }
  const asns = [...byAsn.values()].sort((a, b) => b.bytes - a.bytes || a.asn - b.asn);
  let cum = 0;
  for (const asn of asns) {
    asn.share = totalBytes > 0 ? asn.bytes / totalBytes : 0;
    cum += asn.bytes;
    asn.cumulative = totalBytes > 0 ? cum / totalBytes : 0;
  }
  for (const prefix of prefixes) {
    prefix.share = totalBytes > 0 ? prefix.bytes / totalBytes : 0;
    const owner = byAsn.get(prefix.asn);
    if (!prefix.asnName && owner?.asnName) prefix.asnName = owner.asnName;
  }
  prefixes.sort((a, b) => b.bytes - a.bytes || a.prefix.localeCompare(b.prefix));
  return { totalBytes, asns, prefixes };
}

function formatAttackList(events) {
  const list = events || [];
  if (!list.length) return 'Активных атак нет.\n';
  const lines = [`Активные атаки: ${list.length}`, ''];
  for (const event of list) {
    lines.push(event.id);
    lines.push(`  ${scopeLabel(event.scope)}  ${event.name || event.scopeId}  ${statusLabel(event.status)}  с ${formatMsk(event.startMinute || event.alertMinute)}`);
  }
  lines.push('');
  lines.push('Дальше: grapes-attack-asn --attack \'<id>\'');
  lines.push('CSV:    grapes-attack-asn --attack \'<id>\' --csv');
  return `${lines.join('\n')}\n`;
}

function formatAttackListCsv(events) {
  const lines = ['attack_id,status,scope,scope_id,name,start'];
  for (const event of events || []) {
    lines.push([
      event.id,
      event.status,
      event.scope,
      event.scopeId,
      event.name,
      event.startMinute || event.alertMinute || '',
    ].map(csvEscape).join(','));
  }
  return `${lines.join('\n')}\n`;
}

function formatReports(reports) {
  return `${(reports || []).map(formatReport).join('\n')}`;
}

function formatReport(report) {
  const event = report.event || {};
  const range = report.range || {};
  const end = range.closed ? formatMsk(parseUtc(range.to) - MINUTE) : 'сейчас';
  const lines = [
    `Атака: ${event.id || ''}`,
    `Объект: ${event.name || event.scopeId || ''} (${scopeLabel(event.scope)})`,
    `Статус: ${statusLabel(event.status)}`,
    `Окно: ${formatMsk(range.from)} — ${end}`,
    'Трафик: мусорный UDP к этой цели, с начала атаки',
  ];
  if (!report.asns?.length) {
    lines.push('Мусорного UDP с начала атаки нет.');
    return `${lines.join('\n')}\n`;
  }
  lines.push(`Всего: ${formatBytes(report.totalBytes)} в ${report.prefixes.length} сетях /24, ${report.asns.length} AS`);
  lines.push('Доля — от этой суммы. Источники без номера AS не входят.');
  if (report.truncated) {
    lines.push(`Показаны ${report.limit} крупнейших сетей /24, более мелкие в сумму не вошли.`);
  }
  lines.push('');
  lines.push('ASN');
  lines.push([
    pad('AS', 12),
    pad('имя', 28),
    padLeft('байты', 12),
    padLeft('доля', 8),
    padLeft('накоплено', 10),
    padLeft('сетей', 7),
  ].join('  '));
  for (const asn of report.asns) {
    lines.push([
      pad(`AS${asn.asn}`, 12),
      pad(clip(asn.asnName, 28), 28),
      padLeft(formatBytes(asn.bytes), 12),
      padLeft(formatPct(asn.share), 8),
      padLeft(formatPct(asn.cumulative), 10),
      padLeft(String(asn.prefixCount), 7),
    ].join('  '));
  }
  lines.push('');
  lines.push('Сети /24');
  lines.push([
    pad('сеть', 18),
    pad('AS', 12),
    pad('имя', 28),
    padLeft('байты', 12),
    padLeft('доля', 8),
  ].join('  '));
  for (const prefix of report.prefixes) {
    lines.push([
      pad(prefix.prefix, 18),
      pad(`AS${prefix.asn}`, 12),
      pad(clip(prefix.asnName, 28), 28),
      padLeft(formatBytes(prefix.bytes), 12),
      padLeft(formatPct(prefix.share), 8),
    ].join('  '));
  }
  return `${lines.join('\n')}\n`;
}

function formatReportsCsv(reports) {
  const lines = [CSV_HEADER.join(',')];
  for (const report of reports || []) {
    const event = report.event || {};
    const truncated = report.truncated ? '1' : '0';
    const common = [
      event.id,
      event.name,
      event.status,
      event.scope,
      event.scopeId,
    ];
    for (const asn of report.asns || []) {
      lines.push([
        'asn',
        ...common,
        asn.asn,
        asn.asnName,
        '',
        byteString(asn.bytes),
        sharePct(asn.share),
        sharePct(asn.cumulative),
        asn.prefixCount,
        truncated,
      ].map(csvEscape).join(','));
    }
    for (const prefix of report.prefixes || []) {
      lines.push([
        'prefix',
        ...common,
        prefix.asn,
        prefix.asnName,
        prefix.prefix,
        byteString(prefix.bytes),
        sharePct(prefix.share),
        '',
        '',
        truncated,
      ].map(csvEscape).join(','));
    }
  }
  return `${lines.join('\n')}\n`;
}

function scopeLabel(scope) {
  if (scope === 'client') return 'клиент';
  if (scope === 'provider') return 'провайдер';
  if (scope === 'net') return 'сеть';
  return String(scope || '');
}

function statusLabel(status) {
  if (status === 'active') return 'идёт';
  if (status === 'normalized') return 'завершена';
  if (status === 'peak') return 'пик';
  return String(status || '');
}

function formatMsk(value) {
  const ts = parseUtc(value);
  if (!Number.isFinite(ts)) return '';
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Moscow',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(ts));
  const pick = (type) => parts.find((part) => part.type === type)?.value || '';
  return `${pick('day')}.${pick('month')}.${pick('year')} ${pick('hour')}:${pick('minute')} МСК`;
}

function formatBytes(value) {
  let number = Number(value) || 0;
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'];
  let index = 0;
  while (number >= 1024 && index < units.length - 1) {
    number /= 1024;
    index += 1;
  }
  const digits = index === 0 || number >= 100 ? 0 : number >= 10 ? 1 : 2;
  return `${number.toFixed(digits)} ${units[index]}`;
}

function formatPct(share) {
  return `${(Number(share) * 100).toFixed(1)}%`;
}

function sharePct(share) {
  return (Number(share) * 100).toFixed(2);
}

function byteString(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return '0';
  return Math.round(number).toString();
}

function csvEscape(value) {
  const text = value == null ? '' : String(value);
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function pad(value, width) {
  const text = String(value ?? '');
  return text.length >= width ? text : text + ' '.repeat(width - text.length);
}

function padLeft(value, width) {
  const text = String(value ?? '');
  return text.length >= width ? text : ' '.repeat(width - text.length) + text;
}

function clip(value, width) {
  const text = String(value ?? '');
  if (text.length <= width) return text;
  if (width <= 1) return text.slice(0, width);
  return `${text.slice(0, width - 1)}…`;
}

function helpText() {
  return `grapes-attack-asn — AS и сети /24 с начала атаки

Без аргументов показывает активные атаки.
С --attack печатает AS по убыванию объёма и все их сети /24.
Считается мусорный UDP к цели, как блок в карточке атаки.

  grapes-attack-asn
  grapes-attack-asn --attack '<id>'
  grapes-attack-asn --attack '<id>' --csv
  grapes-attack-asn --all --csv

--limit N   сколько крупнейших сетей /24 брать (по умолчанию ${DEFAULT_LIMIT})
`;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(helpText());
    return;
  }
  const { loadDetectionEvents, loadDetectionEvent } = require('./detection-telegram');
  if (!args.attackId && !args.all) {
    const events = await loadDetectionEvents({ status: 'active', limit: 200 });
    process.stdout.write(args.csv ? formatAttackListCsv(events) : formatAttackList(events));
    return;
  }
  let events;
  if (args.attackId) {
    events = [await loadDetectionEvent(args.attackId)];
  } else {
    events = await loadDetectionEvents({ status: 'active', limit: 200 });
    if (events.length > MAX_ALL) {
      process.stderr.write(`Активных атак ${events.length}, считаю первые ${MAX_ALL}. Для одной укажите --attack.\n`);
      events = events.slice(0, MAX_ALL);
    }
  }
  if (!events.length) {
    process.stdout.write(args.csv ? formatReportsCsv([]) : 'Активных атак нет.\n');
    return;
  }
  const { loadAttackPrefixes } = require('./detection-investigate');
  const reports = [];
  for (const event of events) {
    const range = attackRange(event);
    if (!range) throw usageError(`У атаки ${event.id} нет времени начала`);
    process.stderr.write(`${event.id}: ${range.from} — ${range.closed ? range.to : 'сейчас'}\n`);
    const loaded = await loadAttackPrefixes({
      scope: event.scope,
      scopeId: event.scopeId,
      from: range.from,
      to: range.to,
      limit: args.limit,
    });
    if (loaded.namesError) {
      process.stderr.write(`Имена AS не прочитались: ${loaded.namesError}\n`);
    }
    reports.push({
      event,
      range,
      truncated: loaded.truncated,
      limit: args.limit,
      ...rollupParticipants(loaded.rows),
    });
  }
  process.stdout.write(args.csv ? formatReportsCsv(reports) : formatReports(reports));
}

if (require.main === module) {
  require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
  main(process.argv).catch((err) => {
    process.stderr.write(`${err.message || err}\n`);
    process.exit(Number(err.statusCode) || 1);
  });
}

module.exports = {
  parseArgs,
  attackRange,
  rollupParticipants,
  formatAttackList,
  formatAttackListCsv,
  formatReports,
  formatReportsCsv,
  helpText,
};
