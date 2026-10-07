'use strict';

(function explorerGroupMaskModule() {
  const EXPLORER_GROUP_SCALE_SPECS = {
    src_ip: { kind: 'cidr', min: 1, max: 32, default: 32 },
    dst_ip: { kind: 'cidr', min: 1, max: 32, default: 32 },
    src_port: { kind: 'bucket', steps: [1, 10, 100, 1000], default: 1, maxStep: 65535 },
    dst_port: { kind: 'bucket', steps: [1, 10, 100, 1000], default: 1, maxStep: 65535 },
  };

  const EXPLORER_PORT_BUCKET_MIN = 2;
  const EXPLORER_PORT_BUCKET_MAX = 65535;

  const MASKABLE = new Set(Object.keys(EXPLORER_GROUP_SCALE_SPECS));
  const MASK_MIN = 1;
  const MASK_MAX = 32;
  const MASK_DEFAULT = 32;

  function getExplorerGroupScaleSpec(fieldId) {
    return EXPLORER_GROUP_SCALE_SPECS[String(fieldId ?? '').trim()] || null;
  }

  function validExplorerGroupMaskForField(fieldId, mask) {
    const spec = getExplorerGroupScaleSpec(fieldId);
    if (!spec) return null;
    const value = typeof mask === 'number' ? mask : Number(String(mask ?? '').trim());
    if (!Number.isInteger(value)) return spec.default;
    if (spec.kind === 'cidr') {
      return value >= spec.min && value <= spec.max ? value : spec.default;
    }
    if (spec.kind === 'bucket') {
      if (spec.steps.includes(value)) return value;
      const maxStep = spec.maxStep ?? EXPLORER_PORT_BUCKET_MAX;
      if (value >= EXPLORER_PORT_BUCKET_MIN && value <= maxStep) return value;
      return spec.default;
    }
    return spec.default;
  }

  function validExplorerGroupMask(mask) {
    return validExplorerGroupMaskForField('src_ip', mask);
  }

  function parseExplorerGroupToken(token) {
    const raw = String(token ?? '').trim();
    const slash = raw.indexOf('/');
    const candidateId = slash < 0 ? raw : raw.slice(0, slash);
    const spec = getExplorerGroupScaleSpec(candidateId);
    if (!spec) return { id: raw, mask: null, kind: null };

    const mask = slash < 0
      ? spec.default
      : validExplorerGroupMaskForField(candidateId, raw.slice(slash + 1));
    return { id: candidateId, mask, kind: spec.kind };
  }

  function formatExplorerGroupToken(id, mask) {
    const fieldId = String(id ?? '').trim();
    const spec = getExplorerGroupScaleSpec(fieldId);
    if (!spec) return fieldId;
    const normalizedMask = validExplorerGroupMaskForField(fieldId, mask);
    return normalizedMask === spec.default ? fieldId : `${fieldId}/${normalizedMask}`;
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

  function isCoarseExplorerGroupMask(fieldId, mask, { maskKind, maskDefault } = {}) {
    const spec = getExplorerGroupScaleSpec(fieldId);
    const kind = maskKind || spec?.kind;
    const def = maskDefault ?? spec?.default ?? (kind === 'bucket' ? 1 : 32);
    if (mask == null) return false;
    if (kind === 'bucket') return mask > def;
    if (kind === 'cidr') return mask < def;
    return false;
  }

  function isCoarseExplorerGroupToken(token, dimensionById) {
    const { id, mask } = parseExplorerGroupToken(token);
    const dim = dimensionById?.[id];
    if (!dim?.maskable) return false;
    return isCoarseExplorerGroupMask(id, mask, {
      maskKind: dim.maskKind,
      maskDefault: dim.maskDefault,
    });
  }

  function explorerBucketFilterFromDisplay(displayValue) {
    const s = String(displayValue ?? '').trim();
    const m = s.match(/^(\d+)\s*-\s*(\d+)$/);
    if (!m) return null;
    return { op: 'between', value: `${m[1]},${m[2]}` };
  }

  const api = {
    EXPLORER_GROUP_SCALE_SPECS,
    EXPLORER_PORT_BUCKET_MIN,
    EXPLORER_PORT_BUCKET_MAX,
    MASKABLE,
    MASK_MIN,
    MASK_MAX,
    MASK_DEFAULT,
    getExplorerGroupScaleSpec,
    validExplorerGroupMask,
    validExplorerGroupMaskForField,
    parseExplorerGroupToken,
    formatExplorerGroupToken,
    explorerGroupFieldId,
    explorerGroupMask,
    normalizeExplorerGroupTokens,
    isCoarseExplorerGroupMask,
    isCoarseExplorerGroupToken,
    explorerBucketFilterFromDisplay,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof window !== 'undefined') {
    window.ExplorerGroupMask = api;
  }
}());
