'use strict';

(function explorerGroupDslModule() {
  const EXPLORER_GROUP_DSL_MAX = 4;
  const EXPLORER_MASKABLE_GROUPS = new Set(['src_ip', 'dst_ip']);
  const EXPLORER_GROUP_MASK_DEFAULT = 32;

  function explorerFieldSearchApi() {
    if (typeof window !== 'undefined' && window.ExplorerFieldSearch) {
      return window.ExplorerFieldSearch;
    }
    if (typeof module !== 'undefined' && module.exports) {
      try {
        return require('./explorer-field-search.js');
      } catch {
        return {};
      }
    }
    return {};
  }

  function validExplorerGroupMask(mask) {
    const value = typeof mask === 'number' ? mask : Number(String(mask ?? '').trim());
    return Number.isInteger(value) && value >= 1 && value <= 32
      ? value
      : EXPLORER_GROUP_MASK_DEFAULT;
  }

  function parseExplorerGroupToken(token) {
    const raw = String(token ?? '').trim();
    const slash = raw.indexOf('/');
    const candidateId = slash < 0 ? raw : raw.slice(0, slash);
    if (!EXPLORER_MASKABLE_GROUPS.has(candidateId)) return { id: raw, mask: null };

    const mask = slash < 0
      ? EXPLORER_GROUP_MASK_DEFAULT
      : validExplorerGroupMask(raw.slice(slash + 1));
    return { id: candidateId, mask };
  }

  function formatExplorerGroupToken(id, mask) {
    const fieldId = String(id ?? '').trim();
    if (!EXPLORER_MASKABLE_GROUPS.has(fieldId)) return fieldId;
    const normalizedMask = validExplorerGroupMask(mask);
    return normalizedMask === EXPLORER_GROUP_MASK_DEFAULT ? fieldId : `${fieldId}/${normalizedMask}`;
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

  function groupableDimensions(dimensions) {
    return (Array.isArray(dimensions) ? dimensions : [])
      .filter((d) => d && d.id && d.groupable !== false);
  }

  function resolveExplorerDimensionId(token, dimensions) {
    const raw = String(token ?? '').trim();
    if (!raw) return '';
    const { id: rawId } = parseExplorerGroupToken(raw);
    const dims = groupableDimensions(dimensions);
    if (dims.some((d) => d.id === rawId)) return rawId;
    const exactId = dims.find((d) => String(d.id).toLowerCase() === rawId.toLowerCase());
    if (exactId) return exactId.id;
    const { explorerFieldMatchesQuery } = explorerFieldSearchApi();
    const byAlias = dims.filter((d) => explorerFieldMatchesQuery?.(d, rawId));
    if (byAlias.length === 1) return byAlias[0].id;
    const exact = dims.find((d) => String(d.label || '').toLowerCase() === rawId.toLowerCase());
    if (exact) return exact.id;
    const partial = dims.filter((d) => String(d.label || '').toLowerCase().includes(rawId.toLowerCase()));
    if (partial.length === 1) return partial[0].id;
    return rawId;
  }

  function isExplorerGroupByDslLine(line) {
    return /^(group\s+by|группировка)(\s|$)/i.test(String(line || '').trim());
  }

  function serializeExplorerGroupByDsl(groupBy) {
    const tokens = normalizeExplorerGroupTokens(groupBy);
    if (!tokens.length) return 'group by src_ip, dst_ip';
    return `group by ${tokens.join(', ')}`;
  }

  function parseExplorerGroupByDslLine(line, dimensions, { maxCount = EXPLORER_GROUP_DSL_MAX } = {}) {
    const trimmed = String(line || '').trim();
    const match = trimmed.match(/^(group\s+by|группировка)(?:\s+(.*))?$/i);
    if (!match) {
      throw new Error('ожидается строка group by или группировка');
    }

    const rawTokens = String(match[2] || '')
      .split(',')
      .map((part) => part.trim())
      .filter(Boolean);
    if (!rawTokens.length) {
      throw new Error('нужна хотя бы одна группировка');
    }

    const dims = groupableDimensions(dimensions);
    const dimById = Object.fromEntries(dims.map((d) => [d.id, d]));
    const resolved = [];

    for (const rawToken of rawTokens) {
      const { id: tokenId, mask } = parseExplorerGroupToken(rawToken);
      const fieldId = resolveExplorerDimensionId(tokenId, dimensions);
      if (!fieldId || !dimById[fieldId]) {
        throw new Error(`неизвестное измерение: ${tokenId}`);
      }
      resolved.push(formatExplorerGroupToken(fieldId, mask));
    }

    const normalized = normalizeExplorerGroupTokens(resolved);
    if (!normalized.length) {
      throw new Error('нужна хотя бы одна группировка');
    }
    if (normalized.length > maxCount) {
      throw new Error(`не более ${maxCount} измерений в группировке`);
    }
    return normalized;
  }

  function parseGroupByLineParts(trimmed, dimensions) {
    const headerMatch = trimmed.match(/^(group\s+by|группировка)\s*/i);
    if (!headerMatch) return null;
    const header = headerMatch[0];
    const rest = trimmed.slice(header.length);
    const prefixMatch = rest.match(/^(.*,\s*)?([^,]*)$/);
    const prefix = prefixMatch?.[1] || '';
    const fragment = String(prefixMatch?.[2] || '');
    const selectedIds = new Set();
    const completed = prefix.replace(/,\s*$/, '');
    if (completed) {
      completed.split(',').forEach((part) => {
        const piece = part.trim();
        if (!piece) return;
        const { id: tokenId } = parseExplorerGroupToken(piece);
        const fieldId = resolveExplorerDimensionId(tokenId, dimensions);
        if (fieldId) selectedIds.add(fieldId);
      });
    }
    return { header, rest, prefix, fragment, selectedIds };
  }

  function isPartialGroupByHeader(line) {
    const trimmed = String(line || '').trim();
    if (!trimmed || isExplorerGroupByDslLine(trimmed)) return false;
    const lower = trimmed.toLowerCase();
    if (/^г/i.test(lower) && /^г(?:р(?:у(?:п(?:п(?:и(?:р(?:о(?:в(?:к(?:а)?)?)?)?)?)?)?)?)?)?$/i.test(lower)) {
      return true;
    }
    return /^g(?:r(?:o(?:u(?:p(?:\s*(?:b(?:y?)?)?)?)?)?)?)?$/i.test(lower);
  }

  function groupByMaskSuggestions(fragment, header, prefix, lineSuggestion) {
    const suggestions = [];
    const trimmed = fragment.trim();
    if (!trimmed || trimmed.includes('/')) return suggestions;
    const { id } = parseExplorerGroupToken(trimmed);
    if (!EXPLORER_MASKABLE_GROUPS.has(id)) return suggestions;
    [24, 16, 8, 32].forEach((maskValue) => {
      const token = formatExplorerGroupToken(id, maskValue);
      const insertBody = prefix ? `${prefix}${token}, ` : `${token}, `;
      suggestions.push(lineSuggestion(
        `${id}/${maskValue}`,
        `${header}${insertBody}`,
        maskValue === 32 ? 'хост /32' : `сеть /${maskValue}`,
      ));
    });
    return suggestions;
  }

  function buildExplorerGroupByDslSuggestions(trimmed, leading, dimensions) {
    const lineSuggestion = (label, insert, hint) => ({ label, hint, insert: `${leading}${insert}`, mode: 'line' });
    const dims = groupableDimensions(dimensions);
    const { explorerFieldMatchesQuery } = explorerFieldSearchApi();

    if (isExplorerGroupByDslLine(trimmed)) {
      const parts = parseGroupByLineParts(trimmed, dimensions);
      if (!parts) return [];
      const { header, prefix, fragment, selectedIds } = parts;
      const needle = fragment.trim().toLowerCase();
      const suggestions = [];

      groupByMaskSuggestions(fragment, header, prefix, lineSuggestion)
        .forEach((item) => suggestions.push(item));

      dims
        .filter((d) => !selectedIds.has(d.id))
        .filter((d) => !needle || explorerFieldMatchesQuery?.(d, needle))
        .slice(0, 12)
        .forEach((d) => {
          const display = d.label && d.label !== d.id ? d.label : d.id;
          const insertBody = prefix ? `${prefix}${d.id}, ` : `${d.id}, `;
          suggestions.push(lineSuggestion(
            display,
            `${header}${insertBody}`,
            d.id !== display ? d.id : (d.group || 'измерение'),
          ));
        });

      if (!suggestions.length && !needle) {
        dims
          .filter((d) => !selectedIds.has(d.id))
          .slice(0, 12)
          .forEach((d) => {
            const display = d.label && d.label !== d.id ? d.label : d.id;
            suggestions.push(lineSuggestion(
              display,
              `${header}${prefix}${d.id}, `,
              d.id !== display ? d.id : (d.group || 'измерение'),
            ));
          });
      }

      return suggestions;
    }

    if (isPartialGroupByHeader(trimmed)) {
      const lower = trimmed.toLowerCase();
      const suggestions = [];
      if (!lower.startsWith('групп')) {
        suggestions.push(lineSuggestion('group by', 'group by src_ip, dst_ip', 'Группировка'));
      }
      if (!lower.startsWith('group')) {
        suggestions.push(lineSuggestion('группировка', 'группировка src_ip, dst_ip', 'Группировка (RU)'));
      }
      return suggestions;
    }

    return [];
  }

  function isExplorerGroupByDslContext(line) {
    const trimmed = String(line || '').trim();
    if (!trimmed) return false;
    return isExplorerGroupByDslLine(trimmed) || isPartialGroupByHeader(trimmed);
  }

  const api = {
    EXPLORER_GROUP_DSL_MAX,
    resolveExplorerDimensionId,
    parseExplorerGroupByDslLine,
    serializeExplorerGroupByDsl,
    isExplorerGroupByDslLine,
    isExplorerGroupByDslContext,
    buildExplorerGroupByDslSuggestions,
    normalizeExplorerGroupTokens,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof window !== 'undefined') {
    window.ExplorerGroupDsl = api;
  }
}());
