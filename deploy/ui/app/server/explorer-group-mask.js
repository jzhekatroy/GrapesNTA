'use strict';

const MASKABLE = new Set(['src_ip', 'dst_ip']);
const MASK_MIN = 1;
const MASK_MAX = 32;
const MASK_DEFAULT = 32;

function validExplorerGroupMask(mask) {
  const value = typeof mask === 'number' ? mask : Number(String(mask ?? '').trim());
  return Number.isInteger(value) && value >= MASK_MIN && value <= MASK_MAX
    ? value
    : MASK_DEFAULT;
}

function parseExplorerGroupToken(token) {
  const raw = String(token ?? '').trim();
  const slash = raw.indexOf('/');
  const candidateId = slash < 0 ? raw : raw.slice(0, slash);
  if (!MASKABLE.has(candidateId)) return { id: raw, mask: null };

  const mask = slash < 0
    ? MASK_DEFAULT
    : validExplorerGroupMask(raw.slice(slash + 1));
  return { id: candidateId, mask };
}

function formatExplorerGroupToken(id, mask) {
  const fieldId = String(id ?? '').trim();
  if (!MASKABLE.has(fieldId)) return fieldId;
  const normalizedMask = validExplorerGroupMask(mask);
  return normalizedMask === MASK_DEFAULT ? fieldId : `${fieldId}/${normalizedMask}`;
}

function explorerGroupFieldId(token) {
  return parseExplorerGroupToken(token).id;
}

function explorerGroupMask(token) {
  return parseExplorerGroupToken(token).mask;
}

function normalizeExplorerGroupTokens(list) {
  const normalized = [];
  const seen = new Set();
  for (const token of Array.isArray(list) ? list : []) {
    const parsed = parseExplorerGroupToken(token);
    if (!parsed.id || seen.has(parsed.id)) continue;
    seen.add(parsed.id);
    normalized.push(formatExplorerGroupToken(parsed.id, parsed.mask));
  }
  return normalized;
}

module.exports = {
  MASKABLE,
  MASK_MIN,
  MASK_MAX,
  MASK_DEFAULT,
  parseExplorerGroupToken,
  formatExplorerGroupToken,
  explorerGroupFieldId,
  explorerGroupMask,
  normalizeExplorerGroupTokens,
};
