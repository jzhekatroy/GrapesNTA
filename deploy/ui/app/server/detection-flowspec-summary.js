'use strict';

const crypto = require('crypto');
const { formatCh, parseUtc, MINUTE } = require('./detection-core');
const {
  packetOptions,
  parseGroups,
  takeUntil,
  rateLimitHintMbps,
  bpsOf,
  formatBps,
  loadDestinations,
  loadFlowspecInputs,
  cachedInputs,
  storeInputs,
  FILE_PREFIX_CAP,
} = require('./detection-flowspec-report');

// Горячая минута старше этого — ботнет мог сменить источники, аварию не берём.
const STALE_HOT_MINUTES = 15;
const DESTINATION_CONCURRENCY = 4;
const MINUTE_GROUP_CONCURRENCY = 2;

const VARIANTS = [
  { id: 'packet-src', kind: 'packet', option: 'src', label: 'UDP по признакам пакета, порт источника ≥ 1024' },
  { id: 'packet-dst', kind: 'packet', option: 'dst', label: 'UDP по признакам пакета, порт назначения ≥ 1024' },
  { id: 'packet-both', kind: 'packet', option: 'both', label: 'UDP по признакам пакета, оба порта ≥ 1024' },
  ...[16, 24].flatMap((mask) => [50, 80, 90].map((ratio) => ({
    id: `src${mask}-${ratio}`, kind: 'source', mask, ratio, label: `Сети источника /${mask} · ${ratio}%`,
  }))),
];

const SCOPE_LABEL = { client: 'абонент', provider: 'провайдер', net: 'сеть /24' };

function fail(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function findVariant(id) {
  return VARIANTS.find((variant) => variant.id === String(id || '')) || null;
}

function parseCidr(value) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(String(value || '').trim());
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((n) => n > 255)) return null;
  const len = m[5] == null ? 32 : Number(m[5]);
  if (len > 32) return null;
  const addr = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  return { base: networkOf(addr, len), len };
}

function networkOf(addr, len) {
  if (len <= 0) return 0;
  return (addr & (0xFFFFFFFF << (32 - len))) >>> 0;
}

function cidrKey(base, len) {
  return `${base >>> 24}.${(base >>> 16) & 255}.${(base >>> 8) & 255}.${base & 255}/${len}`;
}

function normCidr(value) {
  const c = parseCidr(value);
  return c ? cidrKey(c.base, c.len) : String(value || '');
}

function mskMinute(minute) {
  const ts = parseUtc(minute);
  if (!Number.isFinite(ts)) return '—';
  return new Intl.DateTimeFormat('ru-RU', {
    timeZone: 'Europe/Moscow', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).format(new Date(ts)).replace(',', '');
}

function mskFileStamp(ts) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Moscow', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).formatToParts(new Date(ts));
  const get = (type) => parts.find((p) => p.type === type)?.value || '00';
  return `${get('year')}${get('month')}${get('day')}-${get('hour')}${get('minute')}`;
}

// Правила одной аварии по выбранному варианту — те же, что в её файле отчёта.
function eventRules(variant, item) {
  const { row, band, destinations } = item;
  if (variant.kind === 'packet') {
    const option = packetOptions(band).find((o) => o.id === variant.option);
    const attackBytes = Number(row?.[option.attackKey]) || 0;
    if (!(attackBytes > 0)) return [];
    const rateHint = rateLimitHintMbps(bpsOf(Number(row?.base_src) || 0));
    return destinations.map((dst) => ({
      dst: normCidr(dst),
      src: null,
      srcPort: option.srcPort,
      dstPort: option.dstPort,
      len: `${band.lo}-${band.hi}`,
      action: 'choose',
      attackBytes,
      rateHint,
    }));
  }
  const groups = parseGroups(variant.mask === 16 ? row?.rows16 : row?.rows24);
  const cut = takeUntil(groups, Number(row?.atk_big) || 0, variant.ratio / 100);
  const rules = [];
  for (const group of cut.rows.slice(0, FILE_PREFIX_CAP)) {
    for (const dst of destinations) {
      rules.push({
        dst: normCidr(dst),
        src: normCidr(group.prefix),
        srcPort: null,
        dstPort: null,
        len: null,
        action: 'discard',
        attackBytes: group.attackBytes,
        rateHint: null,
      });
    }
  }
  return rules;
}

function signatureOf(rule) {
  return ['udp', rule.srcPort || '', rule.dstPort || '', rule.len || '', rule.action].join('|');
}

function ruleKey(sig, src, dst) {
  return `${sig}|${src || ''}|${dst}`;
}

function ruleName(rule) {
  const hash = crypto.createHash('sha1').update(ruleKey(signatureOf(rule), rule.src, rule.dst)).digest('hex');
  return `gnta-${hash.slice(0, 10)}`;
}

// Правило лишнее, если другое с теми же портами, длиной и действием покрывает
// и его источник, и назначение: /24 внутри /16, клиент внутри провайдера.
function coveringKey(rule, sig, index) {
  const dst = parseCidr(rule.dst);
  const src = rule.src == null ? null : parseCidr(rule.src);
  if (!dst || (rule.src != null && !src)) return null;
  const masks = index.get(sig);
  if (!masks) return null;
  const srcLens = src ? [...masks.src].filter((len) => len <= src.len) : [null];
  const dstLens = [...masks.dst].filter((len) => len <= dst.len);
  for (const sLen of srcLens) {
    for (const dLen of dstLens) {
      if (sLen === (src ? src.len : null) && dLen === dst.len) continue;
      const srcKey = src ? cidrKey(networkOf(src.base, sLen), sLen) : null;
      const key = ruleKey(sig, srcKey, cidrKey(networkOf(dst.base, dLen), dLen));
      if (masks.keys.has(key)) return key;
    }
  }
  return null;
}

function mergeRules(items) {
  const all = [];
  items.forEach((item, owner) => {
    item.stats = { generated: item.rules.length, kept: 0, duplicates: 0 };
    for (const rule of item.rules) all.push({ ...rule, owner });
  });
  all.sort((a, b) => b.attackBytes - a.attackBytes);
  const byKey = new Map();
  for (const rule of all) {
    const sig = signatureOf(rule);
    const key = ruleKey(sig, rule.src, rule.dst);
    const hit = byKey.get(key);
    if (hit) {
      hit.owners.add(rule.owner);
      if (rule.rateHint != null) hit.rateHint = Math.max(hit.rateHint || 0, rule.rateHint);
      items[rule.owner].stats.duplicates += 1;
      continue;
    }
    byKey.set(key, { ...rule, sig, key, owners: new Set([rule.owner]) });
  }
  const index = new Map();
  for (const rule of byKey.values()) {
    const masks = index.get(rule.sig) || { src: new Set(), dst: new Set(), keys: new Set() };
    const dst = parseCidr(rule.dst);
    const src = rule.src == null ? null : parseCidr(rule.src);
    if (dst) masks.dst.add(dst.len);
    if (src) masks.src.add(src.len);
    masks.keys.add(rule.key);
    index.set(rule.sig, masks);
  }
  const kept = [];
  for (const rule of byKey.values()) {
    const cover = coveringKey(rule, rule.sig, index);
    if (cover) {
      const parent = byKey.get(cover);
      for (const owner of rule.owners) parent.owners.add(owner);
      items[rule.owner].stats.duplicates += 1;
      continue;
    }
    items[rule.owner].stats.kept += 1;
    kept.push(rule);
  }
  kept.sort((a, b) => b.attackBytes - a.attackBytes);
  return kept;
}

function ruleLines(rule, names) {
  const id = ruleName(rule);
  const who = [...rule.owners].map((i) => names[i]).join(', ');
  const lines = [
    `# ${rule.src ? `${rule.src} → ` : ''}${rule.dst} · ${formatBps(bpsOf(rule.attackBytes))} · ${who}`,
    `set routing-options flow route ${id} match destination ${rule.dst}`,
  ];
  if (rule.src) lines.push(`set routing-options flow route ${id} match source ${rule.src}`);
  lines.push(`set routing-options flow route ${id} match protocol udp`);
  if (rule.srcPort) lines.push(`set routing-options flow route ${id} match source-port ${rule.srcPort}`);
  if (rule.dstPort) lines.push(`set routing-options flow route ${id} match destination-port ${rule.dstPort}`);
  if (rule.len) lines.push(`set routing-options flow route ${id} match packet-length ${rule.len}`);
  if (rule.action === 'choose') {
    lines.push(`# set routing-options flow route ${id} then rate-limit ${rule.rateHint}m`);
    lines.push(`# set routing-options flow route ${id} then discard`);
  } else {
    lines.push(`set routing-options flow route ${id} then discard`);
  }
  lines.push('');
  return lines;
}

function itemTitle(item) {
  return `${item.name || item.scopeId} (${SCOPE_LABEL[item.scope] || item.scope})`;
}

function buildFlowspecSummary({ variant, items = [], skipped = [], nowTs = Date.now() } = {}) {
  const rules = mergeRules(items);
  const names = items.map((item) => item.name || item.scopeId);
  const generated = items.reduce((sum, item) => sum + item.stats.generated, 0);
  const header = [
    `# Общий фильтр FlowSpec · ${variant.label} · собран ${mskMinute(formatCh(nowTs))} МСК`,
    `# Аварий в файле: ${items.length}, правил: ${rules.length}, дублей убрано: ${generated - rules.length}`,
    '# Правила по убыванию трафика атаки. Имя правила — хеш условий, повторная загрузка не задвоит.',
  ];
  if (variant.kind === 'packet') {
    header.push('# Строку then выберите сами: лимит или сброс. Обе закомментированы.');
  } else {
    header.push('# Действие — discard. Строку then можно заменить на rate-limit.');
  }
  header.push('#');
  for (const item of items) {
    const band = variant.kind === 'packet' ? ` · пакет ${item.band.lo}–${item.band.hi} Б` : '';
    header.push(`# ${itemTitle(item)} · горячая минута ${mskMinute(item.minute)}${band} · правил ${item.stats.generated}, своих ${item.stats.kept}, дублей ${item.stats.duplicates}`);
  }
  if (skipped.length) {
    header.push('#');
    header.push(`# Пропущено: ${skipped.length}`);
    for (const skip of skipped) header.push(`# ${itemTitle(skip)} — ${skip.reason}`);
  }
  header.push('');
  const body = rules.flatMap((rule) => ruleLines(rule, names));
  return {
    filename: `flowspec-all-${mskFileStamp(nowTs)}-${variant.id}.txt`,
    text: [...header, ...body].join('\n'),
    variant: variant.id,
    rules: rules.length,
    duplicates: generated - rules.length,
    events: items.map((item) => ({
      scope: item.scope,
      scopeId: item.scopeId,
      name: item.name,
      minute: item.minute,
      ...item.stats,
    })),
    skipped: skipped.map((skip) => ({ scope: skip.scope, scopeId: skip.scopeId, name: skip.name, reason: skip.reason })),
  };
}

async function mapLimited(list, limit, fn) {
  const out = new Array(list.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, list.length) }, async () => {
    while (next < list.length) {
      const i = next;
      next += 1;
      out[i] = await fn(list[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

// Одна строка на объект: у одного абонента могут быть открыты объём и амплификация.
function activeObjects(events, nowTs) {
  const byKey = new Map();
  for (const event of events || []) {
    const key = `${event.scope}|${event.scopeId}`;
    const minute = event.live?.lastHotMinute || null;
    const prev = byKey.get(key);
    if (!prev || (minute && (!prev.minute || parseUtc(minute) > parseUtc(prev.minute)))) {
      byKey.set(key, { scope: event.scope, scopeId: event.scopeId, name: event.name, minute });
    }
  }
  const ready = [];
  const skipped = [];
  for (const object of byKey.values()) {
    if (!['client', 'provider', 'net'].includes(object.scope)) {
      skipped.push({ ...object, reason: 'не абонент, провайдер или сеть' });
      continue;
    }
    if (!object.minute) {
      skipped.push({ ...object, reason: 'нет горячей минуты' });
      continue;
    }
    const ago = Math.round((nowTs - parseUtc(object.minute)) / MINUTE);
    if (ago > STALE_HOT_MINUTES) {
      skipped.push({ ...object, reason: `горячая минута ${ago} мин назад` });
      continue;
    }
    ready.push(object);
  }
  return { ready, skipped };
}

async function loadFlowspecSummary({ variant: variantId, nowTs = Date.now() } = {}) {
  const variant = findVariant(variantId);
  if (!variant) throw fail(400, 'Неизвестный вариант отчёта');
  const { loadDetectionEvents } = require('./detection-telegram');
  const events = await loadDetectionEvents({ status: 'active', limit: 1000 });
  const { ready, skipped } = activeObjects(events, nowTs);

  const withDest = await mapLimited(ready, DESTINATION_CONCURRENCY, async (object) => {
    try {
      return { ...object, destinations: await loadDestinations(object.scope, object.scopeId) };
    } catch (err) {
      skipped.push({ ...object, reason: err.message || 'нет назначений' });
      return null;
    }
  });

  const groups = new Map();
  const items = [];
  for (const object of withDest.filter(Boolean)) {
    const minute = formatCh(parseUtc(object.minute));
    const hit = cachedInputs(object.scope, object.scopeId, minute, nowTs);
    if (hit) {
      items.push({ ...object, minute, ...hit });
      continue;
    }
    if (!groups.has(minute)) groups.set(minute, []);
    groups.get(minute).push({ ...object, minute });
  }

  await mapLimited([...groups.entries()], MINUTE_GROUP_CONCURRENCY, async ([minute, objects]) => {
    try {
      const inputs = await loadFlowspecInputs(objects, parseUtc(minute));
      objects.forEach((object, i) => {
        storeInputs(object.scope, object.scopeId, minute, inputs[i], nowTs);
        items.push({ ...object, ...inputs[i] });
      });
    } catch (err) {
      for (const object of objects) skipped.push({ ...object, reason: `не посчиталось: ${err.message || err}` });
    }
  });

  for (const item of items) item.rules = eventRules(variant, item);
  items.sort((a, b) => (Number(b.row?.atk_big) || 0) - (Number(a.row?.atk_big) || 0));
  return buildFlowspecSummary({ variant, items, skipped, nowTs });
}

module.exports = {
  VARIANTS,
  STALE_HOT_MINUTES,
  findVariant,
  parseCidr,
  eventRules,
  mergeRules,
  buildFlowspecSummary,
  activeObjects,
  loadFlowspecSummary,
};
