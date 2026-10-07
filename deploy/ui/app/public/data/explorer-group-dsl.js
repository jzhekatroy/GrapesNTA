'use strict';

(function explorerGroupDslModule() {
  const EXPLORER_GROUP_DSL_MAX = 4;

  function groupMaskApi() {
    if (typeof window !== 'undefined' && window.ExplorerGroupMask) {
      return window.ExplorerGroupMask;
    }
    if (typeof module !== 'undefined' && module.exports) {
      try {
        return require('./explorer-group-mask.js');
      } catch {
        return {};
      }
    }
    return {};
  }

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

  function parseExplorerGroupToken(token) {
    return groupMaskApi().parseExplorerGroupToken?.(token) ?? { id: String(token ?? '').trim(), mask: null };
  }

  function formatExplorerGroupToken(id, mask) {
    const fn = groupMaskApi().formatExplorerGroupToken;
    if (fn) return fn(id, mask);
    return String(id ?? '').trim();
  }

  function normalizeExplorerGroupTokens(list) {
    const fn = groupMaskApi().normalizeExplorerGroupTokens;
    if (fn) return fn(list);
    return [];
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
    // Empty grouping is valid; do not default to src_ip/dst_ip.
    if (!tokens.length) return '';
    return `group by ${tokens.join(', ')}`;
  }

  function parseExplorerGroupByDslLine(line, dimensions, { maxCount } = {}) {
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
    if (Number.isFinite(maxCount) && maxCount > 0 && normalized.length > maxCount) {
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

  function bucketStepHint(step) {
    if (step === 10) return 'десятки портов';
    if (step === 100) return 'сотни портов';
    if (step === 1000) return 'тысячи портов';
    return `диапазон /${step}`;
  }

  function groupByMaskSuggestions(fragment, header, prefix, lineSuggestion, dimensions) {
    const suggestions = [];
    const trimmed = fragment.trim();
    if (!trimmed || trimmed.includes('/')) return suggestions;
    const { id } = parseExplorerGroupToken(trimmed);
    const spec = groupMaskApi().getExplorerGroupScaleSpec?.(id);
    if (!spec) return suggestions;

    const dim = groupableDimensions(dimensions).find((d) => d.id === id);
    const steps = dim?.maskSteps || spec.steps || [];
    const def = dim?.maskDefault ?? spec.default;

    if (spec.kind === 'cidr') {
      [24, 16, 8, 32].forEach((maskValue) => {
        const token = formatExplorerGroupToken(id, maskValue);
        const insertBody = prefix ? `${prefix}${token}, ` : `${token}, `;
        suggestions.push(lineSuggestion(
          `${id}/${maskValue}`,
          `${header}${insertBody}`,
          maskValue === def ? 'хост /32' : `сеть /${maskValue}`,
        ));
      });
      return suggestions;
    }

    if (spec.kind === 'bucket') {
      steps.filter((step) => step !== def).forEach((step) => {
        const token = formatExplorerGroupToken(id, step);
        const insertBody = prefix ? `${prefix}${token}, ` : `${token}, `;
        suggestions.push(lineSuggestion(
          `${id}/${step}`,
          `${header}${insertBody}`,
          bucketStepHint(step),
        ));
      });
    }
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

      groupByMaskSuggestions(fragment, header, prefix, lineSuggestion, dimensions)
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
    parseExplorerGroupToken,
    formatExplorerGroupToken,
    explorerGroupFieldId: (token) => groupMaskApi().explorerGroupFieldId?.(token) ?? parseExplorerGroupToken(token).id,
    explorerGroupMask: (token) => groupMaskApi().explorerGroupMask?.(token) ?? parseExplorerGroupToken(token).mask,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof window !== 'undefined') {
    window.ExplorerGroupDsl = api;
  }
}());
