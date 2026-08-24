'use strict';

function escapeString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function isNumericType(type) {
  const t = String(type || '').toLowerCase();
  return /^(u?int(8|16|32|64)|int(8|16|32|64)|float(32|64)|decimal|bool)$/.test(t)
    || t.startsWith('uint')
    || t.startsWith('int')
    || t === 'float32'
    || t === 'float64';
}

function isDateTimeType(type) {
  const t = String(type || '').toLowerCase();
  return t.startsWith('datetime') || t === 'date';
}

function arrayElementType(type) {
  const m = String(type || '').match(/^array\((.+)\)$/i);
  return m ? m[1].trim() : 'String';
}

function formatDateTimeLiteral(value) {
  if (value instanceof Date) {
    return value.toISOString().replace('T', ' ').replace('Z', '').slice(0, 23);
  }
  const s = String(value).trim();
  if (!s) return '';
  if (s.includes('T')) return s.replace('T', ' ').replace('Z', '').slice(0, 23);
  return s.slice(0, 23);
}

function formatLiteral(value, type) {
  if (value == null) return 'NULL';

  const normalizedType = String(type || 'String').replace(/^nullable\((.+)\)$/i, '$1');

  if (/^array\(/i.test(normalizedType)) {
    if (!Array.isArray(value)) return formatLiteral([value], normalizedType);
    const elemType = arrayElementType(normalizedType);
    const items = value.map((item) => formatLiteral(item, elemType));
    return `[${items.join(', ')}]`;
  }

  if (isNumericType(normalizedType)) {
    const n = Number(value);
    if (!Number.isFinite(n)) return String(value);
    return String(n);
  }

  if (isDateTimeType(normalizedType)) {
    return `'${escapeString(formatDateTimeLiteral(value))}'`;
  }

  if (typeof value === 'boolean') {
    return value ? '1' : '0';
  }

  if (typeof value === 'number') {
    return String(value);
  }

  return `'${escapeString(value)}'`;
}

function inlineClickHouseParams(sql, params = {}) {
  const source = String(sql || '');
  if (!source || !params || typeof params !== 'object') return source;

  return source.replace(/\{([a-zA-Z_][a-zA-Z0-9_]*)(?::([^}]+))?\}/g, (match, name, type) => {
    if (!Object.prototype.hasOwnProperty.call(params, name)) return match;
    return formatLiteral(params[name], type || 'String');
  });
}

module.exports = {
  inlineClickHouseParams,
  formatLiteral,
};
