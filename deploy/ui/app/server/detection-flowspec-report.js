'use strict';

const { query, flowsRawTableRef, l3PrefixesViewRef, col, flowCol, ispPrefixLookupSql } = require('./clickhouse');
const { flowIpExpr, primarySourceIdsSql } = require('./queries');
const { loadClientBinding } = require('./detection-investigate');
const { formatCh, parseUtc, EXPORT_LAG, MINUTE } = require('./detection-core');

const PREFIX_LIMIT = 8000;
const FILE_PREFIX_CAP = 2000;
const BIN_BYTES = 100;
const LAST_BIN = 14;
const BAND_COVER = 0.9;
const DEFAULT_BAND = { lo: 1000, hi: 1500 };

function fail(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function formatBps(value) {
  const n = Math.abs(Number(value) || 0);
  const units = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с'];
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  const digits = v >= 100 || i === 0 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${units[i]}`;
}

function formatPct(share) {
  const n = (Number(share) || 0) * 100;
  if (!Number.isFinite(n) || n <= 0) return '0%';
  const digits = n >= 10 ? 0 : 1;
  return `${n.toFixed(digits)}%`;
}

function bpsOf(bytes) {
  return (Number(bytes) || 0) * 8 / 60;
}

function rateLimitHintMbps(baselineBps) {
  const mbps = (Number(baselineBps) || 0) * 5 / 1e6;
  return Math.max(100, Math.round(mbps / 100) * 100);
}

function routeSlug(scopeId) {
  const raw = String(scopeId || 'net').replace(/^isp:/i, '').toLowerCase();
  const slug = raw.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 18);
  return slug || 'net';
}

function mskStamp(minute) {
  const ts = parseUtc(minute);
  if (!Number.isFinite(ts)) return 'minute';
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Moscow',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(ts));
  const get = (type) => parts.find((p) => p.type === type)?.value || '00';
  return `${get('year')}${get('month')}${get('day')}-${get('hour')}${get('minute')}`;
}

function parseGroups(value) {
  const list = Array.isArray(value) ? value : [];
  return list.map((item) => {
    const t = Array.isArray(item) ? item : Object.values(item || {});
    return {
      prefix: String(t[0] || ''),
      attackBytes: Number(t[1] || 0),
      baselineBytes: Number(t[2] || 0),
    };
  }).filter((row) => row.prefix && row.attackBytes > 0)
    .sort((a, b) => b.attackBytes - a.attackBytes);
}

function takeUntil(rows, totalBytes, ratio) {
  const target = (Number(totalBytes) || 0) * ratio;
  if (!(target > 0)) {
    return { n: 0, rows: [], attackBytes: 0, baselineBytes: 0, complete: true };
  }
  let attackBytes = 0;
  let baselineBytes = 0;
  const picked = [];
  for (const row of rows) {
    picked.push(row);
    attackBytes += row.attackBytes;
    baselineBytes += row.baselineBytes;
    if (attackBytes >= target) {
      return { n: picked.length, rows: picked, attackBytes, baselineBytes, complete: true };
    }
  }
  return {
    n: picked.length,
    rows: picked,
    attackBytes,
    baselineBytes,
    complete: false,
  };
}

function previewRows(rows, totalBytes, limit) {
  let cum = 0;
  return rows.slice(0, limit).map((row) => {
    cum += row.attackBytes;
    return {
      prefix: row.prefix,
      share: totalBytes > 0 ? row.attackBytes / totalBytes : 0,
      cum: totalBytes > 0 ? cum / totalBytes : 0,
      attackBps: bpsOf(row.attackBytes),
      baselineBps: bpsOf(row.baselineBytes),
    };
  });
}

function bandLabel(band) {
  return `${band.lo}–${band.hi}`;
}

const HIGH_PORTS = '1024-65535';

function packetOptions(band) {
  const length = `match packet-length ${band.lo}-${band.hi}`;
  return [
    {
      id: 'src',
      label: `UDP, пакет ${bandLabel(band)}, порт источника ≥ 1024`,
      match: [`match source-port ${HIGH_PORTS}`, length],
      srcPort: HIGH_PORTS,
      dstPort: null,
      attackKey: 'atk_src',
      baseKey: 'base_src',
    },
    {
      id: 'dst',
      label: `UDP, пакет ${bandLabel(band)}, порт назначения ≥ 1024`,
      match: [`match destination-port ${HIGH_PORTS}`, length],
      srcPort: null,
      dstPort: HIGH_PORTS,
      attackKey: 'atk_dst',
      baseKey: 'base_dst',
    },
    {
      id: 'both',
      label: `UDP, пакет ${bandLabel(band)}, оба порта ≥ 1024`,
      match: [`match source-port ${HIGH_PORTS}`, `match destination-port ${HIGH_PORTS}`, length],
      srcPort: HIGH_PORTS,
      dstPort: HIGH_PORTS,
      attackKey: 'atk_both',
      baseKey: 'base_both',
    },
  ];
}

function median(values) {
  const list = values.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  if (!list.length) return 0;
  return list[Math.floor((list.length - 1) / 2)];
}

// Флуд вчера сидел в 1000–1500 Б, сегодня в 300–1400 Б: диапазон берётся из
// превышения минуты над тихими минутами, а не из прошлой атаки.
function choosePacketBand(attackBins, quietBins) {
  const excess = [];
  let total = 0;
  for (let bin = 0; bin <= LAST_BIN; bin += 1) {
    const value = Math.max(0, (Number(attackBins[bin]) || 0) - (Number(quietBins[bin]) || 0));
    excess.push(value);
    total += value;
  }
  if (!(total > 0)) return { ...DEFAULT_BAND, cover: 0, fallback: true };
  let best = null;
  for (let i = 0; i <= LAST_BIN; i += 1) {
    let sum = 0;
    for (let j = i; j <= LAST_BIN; j += 1) {
      sum += excess[j];
      if (sum >= total * BAND_COVER) {
        if (!best || j - i < best.j - best.i || (j - i === best.j - best.i && sum > best.sum)) {
          best = { i, j, sum };
        }
        break;
      }
    }
  }
  const lo = best.i * BIN_BYTES;
  const hi = best.j >= LAST_BIN ? 1500 : (best.j + 1) * BIN_BYTES - 1;
  return { lo, hi, cover: best.sum / total, fallback: false };
}

function quietProfile(binRows, attackFrom) {
  const attackBins = new Array(LAST_BIN + 1).fill(0);
  const byMinute = new Map();
  for (const row of binRows || []) {
    const minute = String(row.m || '');
    const bin = Math.min(LAST_BIN, Math.max(0, Number(row.bin) || 0));
    const bytes = Number(row.bytes) || 0;
    if (minute === attackFrom) {
      attackBins[bin] += bytes;
      continue;
    }
    if (!byMinute.has(minute)) byMinute.set(minute, new Array(LAST_BIN + 1).fill(0));
    byMinute.get(minute)[bin] += bytes;
  }
  const minutes = [...byMinute.entries()];
  const quietBins = attackBins.map((_, bin) => median(minutes.map(([, bins]) => bins[bin])));
  return { attackBins, quietBins, minutes };
}

function pickQuietMinute(minutes, band, fallbackTs) {
  if (!minutes.length) return fallbackTs;
  const loBin = Math.floor(band.lo / BIN_BYTES);
  const hiBin = Math.min(LAST_BIN, Math.floor(band.hi / BIN_BYTES));
  const ranked = minutes.map(([minute, bins]) => {
    let sum = 0;
    for (let bin = loBin; bin <= hiBin; bin += 1) sum += bins[bin];
    return { ts: parseUtc(minute), sum };
  }).filter((row) => Number.isFinite(row.ts)).sort((a, b) => a.sum - b.sum);
  if (!ranked.length) return fallbackTs;
  return ranked[Math.floor((ranked.length - 1) / 2)].ts;
}

function packetFile({ option, destinations, slug, attackBytes, allBytes, baselineBytes, baselineMinute, rateHint }) {
  const share = allBytes > 0 ? attackBytes / allBytes : 0;
  const lines = [
    `# ${option.label}`,
    `# Поймает входящего этой минуты: ${formatPct(share)} (${formatBps(bpsOf(attackBytes))})`,
    `# Тихая минута ${baselineMinute || '—'} UTC, под этим условием: ${formatBps(bpsOf(baselineBytes))}`,
    `# Если ставить лимит, от этой нормы ×5 выходит ${rateHint} Мбит/с.`,
    '# Строку then выберите сами: лимит или сброс. Обе закомментированы.',
    `# Назначений: ${destinations.join(', ')}`,
    '',
  ];
  destinations.forEach((dst, index) => {
    const id = destinations.length > 1 ? `${slug}-pkt-${option.id}-${index + 1}` : `${slug}-pkt-${option.id}`;
    lines.push(`set routing-options flow route ${id} match destination ${dst}`);
    lines.push(`set routing-options flow route ${id} match protocol udp`);
    for (const match of option.match) {
      lines.push(`set routing-options flow route ${id} ${match}`);
    }
    lines.push(`# set routing-options flow route ${id} then rate-limit ${rateHint}m`);
    lines.push(`# set routing-options flow route ${id} then discard`);
    lines.push('');
  });
  return lines.join('\n');
}

function sourceFile({ mask, ratio, cut, destinations, slug, totalBytes, baselineMinute, band }) {
  const share = totalBytes > 0 ? cut.attackBytes / totalBytes : 0;
  const shown = cut.rows.slice(0, FILE_PREFIX_CAP);
  const rules = shown.length * destinations.length;
  const lines = [
    `# Сети /${mask}, набор чтобы срезать ${ratio}% UDP с пакетом ${bandLabel(band)} Б этой минуты`,
    `# Сетей в наборе: ${shown.length}${shown.length < cut.n ? `, всего для ${ratio}% нужно ${cut.n}` : ''}`,
    `# Правил: ${rules} (${shown.length} сетей × ${destinations.length} назначений)`,
    `# Срежет такого UDP: ${formatPct(share)} (${formatBps(bpsOf(cut.attackBytes))})`,
    `# Тихая минута ${baselineMinute || '—'} UTC, эти сети слали такого UDP: ${formatBps(bpsOf(cut.baselineBytes))}`,
    '# Действие в файле — discard. Строку then можно заменить на rate-limit.',
    `# Назначений: ${destinations.join(', ')}`,
    '',
  ];
  let n = 0;
  let cum = 0;
  for (const row of shown) {
    cum += row.attackBytes;
    const rowShare = totalBytes > 0 ? row.attackBytes / totalBytes : 0;
    const rowCum = totalBytes > 0 ? cum / totalBytes : 0;
    lines.push(`# ${row.prefix}  ${formatPct(rowShare)}  накоплено ${formatPct(rowCum)}  тихо ${formatBps(bpsOf(row.baselineBytes))}`);
    for (const dst of destinations) {
      n += 1;
      const id = `${slug}-s${mask}-${n}`;
      lines.push(`set routing-options flow route ${id} match destination ${dst}`);
      lines.push(`set routing-options flow route ${id} match source ${row.prefix}`);
      lines.push(`set routing-options flow route ${id} match protocol udp`);
      lines.push(`set routing-options flow route ${id} then discard`);
      lines.push('');
    }
  }
  return lines.join('\n');
}

function buildFlowspecReport({
  row, destinations, scopeId, minute, baselineMinute, band = { ...DEFAULT_BAND, cover: 0, fallback: true }, profile,
} = {}) {
  const slug = routeSlug(scopeId);
  const stamp = mskStamp(minute);
  const allBytes = Number(row?.atk_all) || 0;
  const bigBytes = Number(row?.atk_big) || 0;
  const srcBaseline = Number(row?.base_src) || 0;
  const rateHint = rateLimitHintMbps(bpsOf(srcBaseline));
  const files = [];
  const packet = packetOptions(band).map((option) => {
    const attackBytes = Number(row?.[option.attackKey]) || 0;
    const baselineBytes = Number(row?.[option.baseKey]) || 0;
    const id = `packet-${option.id}`;
    const filename = `${slug}-${stamp}-packet-${option.id}.txt`;
    const text = packetFile({
      option, destinations, slug, attackBytes, allBytes, baselineBytes, baselineMinute, rateHint,
    });
    files.push({ id, label: option.label, filename, text });
    return {
      id,
      label: option.label,
      attackShare: allBytes > 0 ? attackBytes / allBytes : 0,
      attackBps: bpsOf(attackBytes),
      baselineBps: bpsOf(baselineBytes),
    };
  });
  const nets = [16, 24].map((mask) => {
    const groups = parseGroups(mask === 16 ? row?.rows16 : row?.rows24);
    const total = Number(mask === 16 ? row?.n16 : row?.n24) || groups.length;
    const cuts = [50, 80, 90].map((ratio) => {
      const cut = takeUntil(groups, bigBytes, ratio / 100);
      const id = `src${mask}-${ratio}`;
      const filename = `${slug}-${stamp}-src${mask}-${ratio}.txt`;
      const text = sourceFile({
        mask, ratio, cut, destinations, slug, totalBytes: bigBytes, baselineMinute, band,
      });
      files.push({
        id,
        label: `/${mask} · ${ratio}%`,
        filename,
        text,
      });
      return {
        id,
        ratio,
        prefixes: cut.n,
        rules: cut.rows.slice(0, FILE_PREFIX_CAP).length * destinations.length,
        attackShare: bigBytes > 0 ? cut.attackBytes / bigBytes : 0,
        baselineBps: bpsOf(cut.baselineBytes),
        complete: cut.complete,
      };
    });
    return {
      mask,
      total,
      truncated: total > groups.length,
      cuts,
      preview: previewRows(groups, bigBytes, 8),
    };
  });
  const lengths = (profile?.attackBins || []).map((bytes, bin) => ({
    label: bin >= LAST_BIN ? `${bin * BIN_BYTES}+` : `${bin * BIN_BYTES}–${(bin + 1) * BIN_BYTES - 1}`,
    bps: bpsOf(bytes),
    quietBps: bpsOf(profile.quietBins[bin]),
    inBand: bin * BIN_BYTES >= band.lo && bin * BIN_BYTES <= band.hi,
  }));
  return {
    minute,
    baselineMinute,
    destinations,
    band,
    attackBps: bpsOf(allBytes),
    bigBps: bpsOf(bigBytes),
    bigShare: allBytes > 0 ? bigBytes / allBytes : 0,
    baselineHot: bigBytes > 0 && bpsOf(Number(row?.base_big) || 0) > bpsOf(bigBytes) * 0.3,
    rateHintMbps: rateHint,
    lengths,
    packet,
    nets,
    files,
  };
}

function prefixSql(ipExpr, bits) {
  const n = Number(bits);
  return `if(
    isIPv4String(${ipExpr}),
    concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4OrZero(${ipExpr}), ${n}), 1)), '/${n}'),
    ''
  )`;
}

function scaledBytesSql() {
  const bytes = `f.${col('bytes')}`;
  const sampling = flowCol('samplingRate');
  if (!sampling) return bytes;
  return `${bytes} * greatest(f.${sampling}, 1)`;
}

function dt(param) {
  return `toDateTime64({${param}:String}, 9, 'UTC')`;
}

function windowSql(prefix) {
  const timeCol = col('time');
  return `
    f.time_flow_start_ns >= ${dt(`${prefix}From`)}
    AND f.time_flow_start_ns < ${dt(`${prefix}To`)}
    AND f.${timeCol} >= ${dt(`${prefix}From`)}
    AND f.${timeCol} < ${dt(`${prefix}Until`)}
  `;
}

function bounds(minuteTs, prefix) {
  return {
    [`${prefix}From`]: formatCh(minuteTs),
    [`${prefix}To`]: formatCh(minuteTs + MINUTE),
    [`${prefix}Until`]: formatCh(minuteTs + EXPORT_LAG + MINUTE),
  };
}

function net24Num(prefix) {
  const parts = String(prefix).replace(/\/24$/, '').split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8);
}

// Поток проставляется ключом каждой аварии, которой он принадлежит: клиент внутри
// провайдера считается у обоих. Ключ — номер объекта в списке. Принадлежность ищется
// по массивам, а не условием на каждый объект: иначе цена растёт с числом аварий.
function objectsSql(objects, params) {
  const groups = { net: [], client: [], provider: [] };
  objects.forEach((object, i) => groups[object.scope]?.push({ id: object.scopeId, i }));
  const ipCol = `f.${col('dstIp')}`;
  const parts = [];
  if (groups.net.length) {
    params.netIds = groups.net.map((g) => net24Num(g.id));
    params.netKeys = groups.net.map((g) => g.i);
    const etype = flowCol('etype');
    const addr = `bitAnd(reinterpretAsUInt32(reverse(substring(${ipCol}, 1, 4))), 4294967040)`;
    const pos = `indexOf({netIds:Array(UInt32)}, ${addr})`;
    parts.push({ pos: etype ? `if(f.${etype} = 2048, ${pos}, 0)` : pos, keys: 'netKeys' });
  }
  if (groups.client.length) {
    params.clientIds = groups.client.map((g) => String(g.id));
    params.clientKeys = groups.client.map((g) => g.i);
    parts.push({ pos: 'indexOf({clientIds:Array(String)}, f.dst_client)', keys: 'clientKeys' });
  }
  if (groups.provider.length) {
    params.providerIds = groups.provider.map((g) => String(g.id));
    params.providerKeys = groups.provider.map((g) => g.i);
    parts.push({ pos: `indexOf({providerIds:Array(String)}, ${ispPrefixLookupSql(ipCol)})`, keys: 'providerKeys' });
  }
  return {
    any: parts.map((p) => `${p.pos} > 0`).join(' OR ') || '0',
    key: `arrayJoin(arrayFilter(x -> x >= 0, [${parts
      .map((p) => `if(${p.pos} > 0, toInt32({${p.keys}:Array(Int32)}[${p.pos}]), -1)`)
      .join(', ')}]))`,
  };
}

function memoryLimit(objects) {
  return objects.length > 1 ? '6000000000' : '4000000000';
}

function groupByObject(rows) {
  const out = new Map();
  for (const row of rows) {
    const i = Number(row.obj);
    if (!out.has(i)) out.set(i, []);
    out.get(i).push(row);
  }
  return out;
}

async function loadUdpBinsMulti(objects, minuteTs) {
  const quietTo = minuteTs - 20 * MINUTE;
  const quietFrom = quietTo - 15 * MINUTE;
  const proto = `f.${col('proto')}`;
  const rawBytes = `f.${col('bytes')}`;
  const packets = `f.${col('packets')}`;
  const params = {
    ...bounds(minuteTs, 'attack'),
    quietFrom: formatCh(quietFrom),
    quietTo: formatCh(quietTo),
    quietUntil: formatCh(quietTo + EXPORT_LAG),
  };
  const sel = objectsSql(objects, params);
  const { rows } = await query(`
    SELECT
      ${sel.key} AS obj,
      formatDateTime(toStartOfMinute(f.time_flow_start_ns), '%Y-%m-%d %H:%i:%S', 'UTC') AS m,
      least(intDiv(if(${packets} > 0, intDiv(${rawBytes}, ${packets}), 0), ${BIN_BYTES}), ${LAST_BIN}) AS bin,
      sum(${scaledBytesSql()}) AS bytes
    FROM ${flowsRawTableRef()} AS f
    PREWHERE ${sel.any}
    WHERE f.date >= toDate(${dt('quietFrom')}) - 1
      AND f.date <= toDate(${dt('attackUntil')})
      AND (
        (f.time_flow_start_ns >= ${dt('quietFrom')}
          AND f.time_flow_start_ns < ${dt('quietTo')}
          AND f.${col('time')} >= ${dt('quietFrom')}
          AND f.${col('time')} < ${dt('quietUntil')})
        OR (${windowSql('attack')})
      )
      AND ${primarySourceIdsSql('f')}
      AND ${proto} = 17
      AND ${packets} > 0
    GROUP BY obj, m, bin
  `, params, {
    name: 'detection/flowspec-udp-bins',
    requestTimeoutMs: 50000,
    clickhouse_settings: { max_execution_time: 45, max_memory_usage: memoryLimit(objects) },
  });
  return { byObj: groupByObject(rows), attackFrom: params.attackFrom };
}

function prefix16Of(prefix24) {
  const parts = String(prefix24).split('.');
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.0.0/16` : '';
}

function topTuples(rows) {
  return rows
    .filter((row) => row.attackBytes > 0)
    .sort((a, b) => b.attackBytes - a.attackBytes)
    .map((row) => [row.prefix, row.attackBytes, row.baselineBytes]);
}

// /16 собираются из /24 здесь, а не вторым проходом по потокам: в сеть /16 идёт и
// тихий трафик её /24 без атаки, поэтому запрос отдаёт /24 с атакой или с нормой.
function reportRowFromAggregate(raw = {}) {
  const list24 = (Array.isArray(raw.rows24) ? raw.rows24 : []).map((item) => {
    const t = Array.isArray(item) ? item : Object.values(item || {});
    return { prefix: String(t[0] || ''), attackBytes: Number(t[1] || 0), baselineBytes: Number(t[2] || 0) };
  }).filter((row) => row.prefix);
  const by16 = new Map();
  for (const row of list24) {
    const prefix = prefix16Of(row.prefix);
    if (!prefix) continue;
    const acc = by16.get(prefix) || { prefix, attackBytes: 0, baselineBytes: 0 };
    acc.attackBytes += row.attackBytes;
    acc.baselineBytes += row.baselineBytes;
    by16.set(prefix, acc);
  }
  const rows24 = topTuples(list24);
  const rows16 = topTuples([...by16.values()]);
  const out = {};
  for (const key of ['atk_all', 'atk_big', 'base_big', 'atk_src', 'atk_dst', 'atk_both', 'base_src', 'base_dst', 'base_both']) {
    out[key] = Number(raw[key] || 0);
  }
  return {
    ...out,
    n16: rows16.length,
    n24: rows24.length,
    rows16: rows16.slice(0, PREFIX_LIMIT),
    rows24: rows24.slice(0, PREFIX_LIMIT),
  };
}

function bandSql(plans, pkt) {
  const arms = plans.map((plan, i) => `obj = ${i}, ${pkt} BETWEEN ${Math.trunc(plan.band.lo)} AND ${Math.trunc(plan.band.hi)}`);
  return `multiIf(${arms.join(', ')}, 0)`;
}

function baseSql(plans, baseIndex) {
  const arms = plans.map((plan, i) => {
    const j = baseIndex.get(plan.baselineTs);
    return `obj = ${i}, (f.time_flow_start_ns >= ${dt(`base${j}From`)} AND f.time_flow_start_ns < ${dt(`base${j}To`)})`;
  });
  return `multiIf(${arms.join(', ')}, 0)`;
}

// Один проход по сырым потокам: раньше общий запрос ссылался на свой подзапрос
// 11 раз, и ClickHouse читал минуту атаки и тихую минуту на каждую ссылку.
async function loadReportRowsMulti(objects, minuteTs, plans) {
  const params = { ...bounds(minuteTs, 'attack') };
  const sel = objectsSql(objects, params);
  const baseIndex = new Map();
  for (const plan of plans) {
    if (baseIndex.has(plan.baselineTs)) continue;
    const j = baseIndex.size;
    baseIndex.set(plan.baselineTs, j);
    Object.assign(params, bounds(plan.baselineTs, `base${j}`));
  }
  params.dateFrom = formatCh(Math.min(minuteTs, ...baseIndex.keys()));
  const baseWindows = [...baseIndex.values()].map((j) => `(${windowSql(`base${j}`)})`);
  const srcIp = flowIpExpr(`f.${col('srcIp')}`);
  const proto = `f.${col('proto')}`;
  const srcPort = `f.${col('srcPort')}`;
  const dstPort = `f.${col('dstPort')}`;
  const rawBytes = `f.${col('bytes')}`;
  const packets = `f.${col('packets')}`;
  const pkt = `if(${packets} > 0, intDiv(${rawBytes}, ${packets}), 0)`;
  const { rows } = await query(`
    SELECT
      obj,
      sum(a_all) AS atk_all,
      sum(a_big) AS atk_big,
      sum(b_big) AS base_big,
      sum(a_src) AS atk_src,
      sum(a_dst) AS atk_dst,
      sum(a_both) AS atk_both,
      sum(b_src) AS base_src,
      sum(b_dst) AS base_dst,
      sum(b_both) AS base_both,
      groupArrayIf(tuple(p24, a_big, b_big), p24 != '' AND (a_big > 0 OR b_big > 0)) AS rows24
    FROM (
      SELECT
        obj,
        p24,
        sumIf(bytes, is_atk) AS a_all,
        sumIf(bytes, is_atk AND is_big) AS a_big,
        sumIf(bytes, is_base AND is_big) AS b_big,
        sumIf(bytes, is_atk AND is_big AND hi_src) AS a_src,
        sumIf(bytes, is_atk AND is_big AND hi_dst) AS a_dst,
        sumIf(bytes, is_atk AND is_big AND hi_src AND hi_dst) AS a_both,
        sumIf(bytes, is_base AND is_big AND hi_src) AS b_src,
        sumIf(bytes, is_base AND is_big AND hi_dst) AS b_dst,
        sumIf(bytes, is_base AND is_big AND hi_src AND hi_dst) AS b_both
      FROM (
        SELECT
          ${sel.key} AS obj,
          ${scaledBytesSql()} AS bytes,
          ${proto} = 17 AND ${packets} > 0 AND ${bandSql(plans, pkt)} AS is_big,
          ${srcPort} >= 1024 AS hi_src,
          ${dstPort} >= 1024 AS hi_dst,
          (f.time_flow_start_ns >= ${dt('attackFrom')} AND f.time_flow_start_ns < ${dt('attackTo')}) AS is_atk,
          ${baseSql(plans, baseIndex)} AS is_base,
          ${prefixSql(srcIp, 24)} AS p24
        FROM ${flowsRawTableRef()} AS f
        PREWHERE ${sel.any}
        WHERE f.date >= toDate(${dt('dateFrom')}) - 1
          AND f.date <= toDate(${dt('attackUntil')})
          AND ((${windowSql('attack')}) OR ${baseWindows.join(' OR ')})
          AND ${primarySourceIdsSql('f')}
      )
      GROUP BY obj, p24
    )
    GROUP BY obj
  `, params, {
    name: 'detection/flowspec-report',
    requestTimeoutMs: 70000,
    clickhouse_settings: { max_execution_time: 60, max_memory_usage: memoryLimit(objects) },
  });
  const out = new Map();
  for (const row of rows) out.set(Number(row.obj), reportRowFromAggregate(row));
  return out;
}

// objects: [{ scope, scopeId }] с одной минутой атаки.
async function loadFlowspecInputs(objects, minuteTs) {
  if (!objects.length) return [];
  const bins = await loadUdpBinsMulti(objects, minuteTs);
  const plans = objects.map((_, i) => {
    const profile = quietProfile(bins.byObj.get(i) || [], bins.attackFrom);
    const band = choosePacketBand(profile.attackBins, profile.quietBins);
    const baselineTs = pickQuietMinute(profile.minutes, band, minuteTs - 60 * MINUTE);
    return { profile, band, baselineTs };
  });
  const rows = await loadReportRowsMulti(objects, minuteTs, plans);
  return plans.map((plan, i) => ({
    row: rows.get(i) || reportRowFromAggregate({}),
    band: plan.band,
    profile: plan.profile,
    baselineMinute: formatCh(plan.baselineTs),
  }));
}

// Отчёт, который дежурный только что открыл, общий фильтр не пересчитывает.
const INPUT_CACHE_MS = 10 * MINUTE;
const INPUT_CACHE_MAX = 300;
const inputCache = new Map();

function inputCacheKey(scope, scopeId, minute) {
  return `${scope}|${scopeId}|${minute}`;
}

function cachedInputs(scope, scopeId, minute, nowTs = Date.now()) {
  const key = inputCacheKey(scope, scopeId, minute);
  const hit = inputCache.get(key);
  if (!hit) return null;
  if (nowTs - hit.at > INPUT_CACHE_MS) {
    inputCache.delete(key);
    return null;
  }
  return hit.value;
}

function storeInputs(scope, scopeId, minute, value, nowTs = Date.now()) {
  const key = inputCacheKey(scope, scopeId, minute);
  inputCache.delete(key);
  inputCache.set(key, { at: nowTs, value });
  while (inputCache.size > INPUT_CACHE_MAX) inputCache.delete(inputCache.keys().next().value);
}

async function loadDestinations(scope, scopeId) {
  if (scope === 'net') {
    const id = String(scopeId || '').trim();
    if (!/^\d{1,3}(?:\.\d{1,3}){3}\/24$/.test(id)) throw fail(400, 'Для сети нужен префикс /24');
    return [id];
  }
  if (scope === 'provider') {
    const { rows } = await query(`
      SELECT prefix
      FROM ${l3PrefixesViewRef()}
      WHERE family = 4 AND role = 'provider_public' AND entity_id = {id:String} AND prefix != ''
      ORDER BY prefix
      LIMIT 32
    `, { id: String(scopeId) }, { name: 'detection/flowspec-provider-prefixes', requestTimeoutMs: 8000 });
    const prefixes = rows.map((r) => String(r.prefix || '')).filter(Boolean);
    if (!prefixes.length) throw fail(400, 'У провайдера нет разметки по IP');
    return prefixes;
  }
  if (scope === 'client') {
    const binding = await loadClientBinding(scopeId);
    if (binding.bindMode === 'ports') throw fail(400, 'Отчёт только для сети, размеченной по IP');
    const { rows } = await query(`
      SELECT prefix
      FROM default.net_client_prefixes_enabled
      WHERE client_id = {id:String} AND prefix != ''
      ORDER BY prefix
      LIMIT 32
    `, { id: String(scopeId) }, { name: 'detection/flowspec-client-prefixes', requestTimeoutMs: 8000 });
    const prefixes = rows.map((r) => String(r.prefix || '')).filter(Boolean);
    if (!prefixes.length) throw fail(400, 'У клиента нет разметки по IP');
    return prefixes;
  }
  throw fail(400, 'Отчёт только для сети, размеченной по IP');
}


async function loadFlowspecReport({ scope, scopeId, minute } = {}) {
  const scopeName = String(scope || '');
  const id = String(scopeId || '');
  const minuteTs = parseUtc(minute);
  if (!['client', 'provider', 'net'].includes(scopeName) || !id) throw fail(400, 'Нужны scope и scopeId');
  if (!Number.isFinite(minuteTs)) throw fail(400, 'Нужна текущая минута');
  const destinations = await loadDestinations(scopeName, id);
  const minuteCh = formatCh(minuteTs);
  let inputs = cachedInputs(scopeName, id, minuteCh);
  if (!inputs) {
    [inputs] = await loadFlowspecInputs([{ scope: scopeName, scopeId: id }], minuteTs);
    storeInputs(scopeName, id, minuteCh, inputs);
  }
  return buildFlowspecReport({
    row: inputs.row,
    destinations,
    scopeId: id,
    minute: minuteCh,
    baselineMinute: inputs.baselineMinute,
    band: inputs.band,
    profile: inputs.profile,
  });
}

module.exports = {
  loadFlowspecReport,
  buildFlowspecReport,
  choosePacketBand,
  takeUntil,
  rateLimitHintMbps,
  routeSlug,
  packetOptions,
  parseGroups,
  reportRowFromAggregate,
  loadDestinations,
  loadFlowspecInputs,
  cachedInputs,
  storeInputs,
  formatBps,
  bpsOf,
  FILE_PREFIX_CAP,
};
