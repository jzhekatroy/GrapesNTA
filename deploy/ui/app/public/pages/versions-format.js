/* Parse component version strings (ui-v1.0.24+ab12cd34). Shared by versions page and tests. */

const COMPONENT_PREFIXES = ['ui-', 'detection-', 'worker-', 'enrichment-', 'schema-'];

function parseComponentVersion(raw) {
  let s = String(raw || '').trim();
  if (!s) return { display: '', dirty: false, commitHash: '' };
  for (const prefix of COMPONENT_PREFIXES) {
    if (s.startsWith(prefix)) {
      s = s.slice(prefix.length);
      break;
    }
  }
  const plusIdx = s.indexOf('+');
  if (plusIdx >= 0) {
    return {
      display: s.slice(0, plusIdx),
      dirty: true,
      commitHash: s.slice(plusIdx + 1),
    };
  }
  return { display: s, dirty: false, commitHash: '' };
}

function formatVersionDayMonth(value, displayTimezone) {
  const ms = typeof parseUserTimestampMs === 'function'
    ? parseUserTimestampMs(value)
    : Date.parse(String(value || ''));
  if (ms == null || Number.isNaN(ms)) return '';
  const tz = displayTimezone || (typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined);
  return new Date(ms).toLocaleString(typeof GrapesI18n !== 'undefined' ? GrapesI18n.intlLocale() : 'ru-RU', {
    day: '2-digit',
    month: '2-digit',
    ...(tz ? { timeZone: tz } : {}),
  });
}

function buildVersionsCopyLine(components, displayTimezone) {
  const parts = [];
  for (const row of components || []) {
    const raw = row?.version;
    if (raw == null || String(raw).trim() === '') continue;
    const { display } = parseComponentVersion(raw);
    if (!display) continue;
    const dm = formatVersionDayMonth(row.versionDate, displayTimezone);
    parts.push(`${row.id} ${display}${dm ? ` (${dm})` : ''}`);
  }
  return parts.join(' · ');
}

const VersionsFormat = {
  COMPONENT_PREFIXES,
  parseComponentVersion,
  formatVersionDayMonth,
  buildVersionsCopyLine,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = VersionsFormat;
} else {
  Object.assign(typeof window !== 'undefined' ? window : globalThis, { VersionsFormat });
}
