const EXPLORER_TCP_FLAG_DEFS = [
  { name: 'FIN', bit: 1 },
  { name: 'SYN', bit: 2 },
  { name: 'RST', bit: 4 },
  { name: 'PSH', bit: 8 },
  { name: 'ACK', bit: 16 },
  { name: 'URG', bit: 32 },
  { name: 'ECE', bit: 64 },
  { name: 'CWR', bit: 128 },
];

const EXPLORER_TCP_FLAG_OPTIONS = EXPLORER_TCP_FLAG_DEFS.map(({ name }) => ({
  value: name,
  label: name,
}));

function parseTcpFlagNames(value) {
  if (Array.isArray(value)) {
    return value.map((v) => String(v).trim().toUpperCase()).filter(Boolean);
  }
  const s = String(value ?? '').trim();
  if (!s) return [];
  return s.split(',').map((v) => v.trim().toUpperCase()).filter(Boolean);
}

function tcpFlagsNamesToMask(names) {
  const list = parseTcpFlagNames(names);
  let mask = 0;
  for (const name of list) {
    const def = EXPLORER_TCP_FLAG_DEFS.find((d) => d.name === name);
    if (def) mask |= def.bit;
  }
  return mask;
}

function tcpFlagsMaskToNames(mask) {
  const n = Number(mask) || 0;
  if (n <= 0) return [];
  return EXPLORER_TCP_FLAG_DEFS
    .filter(({ bit }) => (n & bit) !== 0)
    .map(({ name }) => name);
}

function tcpFlagsMaskToLabel(mask) {
  const n = Number(mask) || 0;
  if (n === 0) return '—';
  const names = tcpFlagsMaskToNames(n);
  return names.length ? names.join(',') : '—';
}

function parseTcpFlagsFilterValue(value) {
  const s = String(value ?? '').trim();
  if (/^\d+$/.test(s)) {
    const mask = Number(s);
    return { mask, names: tcpFlagsMaskToNames(mask) };
  }
  const names = parseTcpFlagNames(value);
  return { mask: tcpFlagsNamesToMask(names), names };
}

function tcpFlagsLabelSql(expr) {
  const flagParts = EXPLORER_TCP_FLAG_DEFS.map(({ name, bit }) => (
    `if(bitAnd(${expr}, ${bit}) != 0, '${name}', '')`
  ));
  return `if(${expr} = 0, '—', nullIf(arrayStringConcat(arrayFilter(x -> x != '', [${flagParts.join(', ')}]), ','), ''))`;
}

function tcpFlagsValueToFilterNames(value) {
  const parsed = parseTcpFlagsFilterValue(value);
  if (parsed.names.length) return parsed.names.join(',');
  if (parsed.mask === 0) return '';
  return tcpFlagsMaskToLabel(parsed.mask);
}

module.exports = {
  EXPLORER_TCP_FLAG_DEFS,
  EXPLORER_TCP_FLAG_OPTIONS,
  parseTcpFlagNames,
  tcpFlagsNamesToMask,
  tcpFlagsMaskToNames,
  tcpFlagsMaskToLabel,
  parseTcpFlagsFilterValue,
  tcpFlagsLabelSql,
  tcpFlagsValueToFilterNames,
};
