'use strict';

/**
 * Unified field search for Explorer filter/dimension pickers and text mode.
 * Matches id, bilingual label, and schema aliases (case-insensitive).
 */
function explorerNormalizeFieldQuery(q) {
  return String(q ?? '').trim().toLocaleLowerCase();
}

function explorerFieldSearchTokens(field) {
  const tokens = new Set();
  const id = String(field?.id ?? '').trim();
  const label = String(field?.label ?? '').trim();
  if (id) tokens.add(id.toLocaleLowerCase());
  if (label) tokens.add(label.toLocaleLowerCase());
  for (const part of label.split('/')) {
    const piece = part.trim();
    if (piece) tokens.add(piece.toLocaleLowerCase());
  }
  for (const alias of field?.aliases || []) {
    const a = String(alias ?? '').trim();
    if (a) tokens.add(a.toLocaleLowerCase());
  }
  return [...tokens];
}

function explorerFieldMatchesQuery(field, q) {
  const needle = explorerNormalizeFieldQuery(q);
  if (!needle) return true;
  return explorerFieldSearchTokens(field).some((token) => token.includes(needle));
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    explorerNormalizeFieldQuery,
    explorerFieldSearchTokens,
    explorerFieldMatchesQuery,
  };
}

if (typeof window !== 'undefined') {
  window.ExplorerFieldSearch = {
    explorerNormalizeFieldQuery,
    explorerFieldSearchTokens,
    explorerFieldMatchesQuery,
  };
}
