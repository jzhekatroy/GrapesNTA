'use strict';

const { isExplorerFilterGroup } = require('../public/data/explorer-filter-tree.js');
const { serializeExplorerGroupByDsl, normalizeExplorerGroupTokens } = require('../public/data/explorer-group-dsl.js');
const { serializeExplorerThresholdsToDsl } = require('../public/data/explorer-thresholds.js');
const { getAuditQueries } = require('./request-context');
const {
  writeAuditEvent,
  auditContextFromReq,
  sanitizeDetail,
} = require('./audit-log');

const AUDIT_DETAIL_MAX_LEN = 8000;

const FILTER_LOGIC_LABELS = {
  and: 'И',
  or: 'ИЛИ',
  and_not: 'И НЕ',
  or_not: 'ИЛИ НЕ',
};

function quoteFilterVal(value) {
  const s = String(value ?? '');
  return s.includes(' ') ? `"${s}"` : s;
}

function appendExplorerAuditFilterLeaf(f, logicLabel, lines) {
  if (f.field === 'collector') {
    const raw = f.value;
    const values = Array.isArray(raw)
      ? raw.map((v) => String(v).trim()).filter(Boolean)
      : String(raw || '').split(',').map((s) => s.trim()).filter(Boolean);
    const serializedValue = values.length
      ? values.map((value) => quoteFilterVal(value)).join(', ')
      : 'all';
    if (f.op === 'in' || f.op === 'not_in') {
      lines.push(`${logicLabel}${f.field} ${f.op} (${serializedValue})`);
    } else {
      lines.push(`${logicLabel}${f.field} ${f.op} ${serializedValue}`);
    }
    return;
  }
  if (f.field === 'direction') {
    if (f.op === 'in' || f.op === 'not_in') {
      const vals = String(f.value).split(',').map((s) => quoteFilterVal(s.trim())).join(', ');
      lines.push(`${logicLabel}${f.field} ${f.op} (${vals})`);
    } else {
      lines.push(`${logicLabel}${f.field} ${f.op} ${quoteFilterVal(f.value ?? '')}`.trim());
    }
    return;
  }
  if (f.field === 'tcp_flags') {
    const vals = String(f.value).split(',').map((s) => s.trim()).filter(Boolean).join(', ');
    lines.push(`${logicLabel}${f.field} ${f.op} (${vals})`);
    return;
  }
  if (f.op === 'between') {
    const parts = String(f.value).split(',').map((s) => s.trim());
    lines.push(`${logicLabel}${f.field} between ${parts[0]} and ${parts[1] || parts[0]}`);
  } else if (f.op === 'in' || f.op === 'not_in') {
    const vals = String(f.value).split(',').map((s) => quoteFilterVal(s.trim())).join(', ');
    lines.push(`${logicLabel}${f.field} ${f.op} (${vals})`);
  } else if (f.op === 'cidr') {
    lines.push(`${logicLabel}${f.field} cidr ${quoteFilterVal(f.value)}`);
  } else {
    lines.push(`${logicLabel}${f.field} ${f.op} ${quoteFilterVal(f.value ?? '')}`.trim());
  }
}

function appendExplorerAuditFilterNodes(nodes, lines) {
  (nodes || []).forEach((node, index) => {
    const logic = FILTER_LOGIC_LABELS[node.logic] || FILTER_LOGIC_LABELS.and;
    const logicLabel = index === 0 ? '' : `${logic} `;
    if (isExplorerFilterGroup(node)) {
      lines.push(`${logicLabel}(`);
      appendExplorerAuditFilterNodes(node.children, lines);
      lines.push(')');
      return;
    }
    appendExplorerAuditFilterLeaf(node, logicLabel, lines);
  });
}

function buildExplorerAuditFiltersText(body = {}) {
  const lines = [];
  const range = body.range || body.timeRange || '1h';
  const from = body.from;
  const to = body.to;
  if (range === 'custom' && from && to) {
    lines.push(`time between "${from}" and "${to}"`);
  } else {
    lines.push(`time range ${range}`);
  }

  const metric = String(body.metric || 'bps').trim() || 'bps';
  lines.push(`metric ${metric}`);

  const groupLine = serializeExplorerGroupByDsl(normalizeExplorerGroupTokens(body.groupBy || []));
  if (groupLine) lines.push(groupLine);

  appendExplorerAuditFilterNodes(body.filters || [], lines);

  serializeExplorerThresholdsToDsl(body.thresholds || [], null)
    .forEach((line) => lines.push(line));

  if (body.limit != null && body.limit !== '') {
    lines.push(`limit ${body.limit}`);
  }

  return lines.join('\n');
}

function classifyExplorerQueryResult(err) {
  if (!err) return 'ok';
  const msg = String(err?.message || err || '').toLowerCase();
  const code = err?.code ?? err?.error_code ?? err?.type;
  const codeNum = Number(code);
  if (
    codeNum === 159
    || String(code).toUpperCase() === 'TIMEOUT_EXCEEDED'
    || msg.includes('timeout exceeded')
    || msg.includes('timed out')
    || msg.includes('timeout')
    || msg.includes('time limit exceeded')
  ) {
    return 'timeout';
  }
  if (
    codeNum === 241
    || String(code).toUpperCase() === 'MEMORY_LIMIT_EXCEEDED'
    || msg.includes('memory limit exceeded')
    || msg.includes('memory_limit')
  ) {
    return 'oom';
  }
  return 'fail';
}

function auditExplorerApiPath(req) {
  const base = String(req.baseUrl || '').trim();
  const path = String(req.path || '').trim();
  if (base && path) return `${base}${path.startsWith('/') ? path : `/${path}`}`;
  const raw = String(req.path || '').trim();
  if (!raw) return '/api/explorer/query';
  if (raw === '/api' || raw.startsWith('/api/')) return raw;
  return raw.startsWith('/') ? `/api${raw}` : `/api/${raw}`;
}

function trimExplorerAuditDetail(detailObj) {
  const shrinkSql = (maxLen) => {
    const queries = detailObj?.explorer?.queries;
    if (!Array.isArray(queries)) return;
    for (const entry of queries) {
      if (typeof entry.sql === 'string' && entry.sql.length > maxLen) {
        entry.sql = `${entry.sql.slice(0, maxLen)}…`;
      }
    }
  };

  shrinkSql(4000);
  let text = JSON.stringify(detailObj);
  if (text.length <= AUDIT_DETAIL_MAX_LEN) return sanitizeDetail(detailObj);

  shrinkSql(800);
  text = JSON.stringify(detailObj);
  if (text.length <= AUDIT_DETAIL_MAX_LEN) return sanitizeDetail(detailObj);

  const queries = detailObj?.explorer?.queries;
  if (Array.isArray(queries)) {
    while (queries.length > 1 && JSON.stringify(detailObj).length > AUDIT_DETAIL_MAX_LEN) {
      queries.pop();
    }
    shrinkSql(200);
  }

  return sanitizeDetail(detailObj);
}

function buildExplorerAuditDetail({ body, elapsedMs, error }) {
  const captured = getAuditQueries();
  const queries = captured.map((entry) => ({
    name: entry.name || '',
    elapsedMs: entry.elapsedMs ?? null,
    sql: entry.sql || '',
    error: entry.error || null,
  }));

  const detailObj = {
    explorer: {
      filtersText: buildExplorerAuditFiltersText(body || {}),
      elapsedMs: elapsedMs ?? null,
      queries,
      error: error ? String(error?.message || error) : null,
    },
  };

  return trimExplorerAuditDetail(detailObj);
}

async function writeExplorerQueryAudit(req, sessionId, { body, elapsedMs, error } = {}) {
  const ctx = auditContextFromReq(req, sessionId);
  const result = classifyExplorerQueryResult(error);
  const apiPath = auditExplorerApiPath(req);

  return writeAuditEvent({
    ...ctx,
    action: 'explorer_query',
    resource: 'explorer',
    method: 'POST',
    path: apiPath,
    objectId: '',
    objectLabel: 'Разбор трафика',
    result,
    detail: buildExplorerAuditDetail({ body, elapsedMs, error }),
  });
}

module.exports = {
  AUDIT_DETAIL_MAX_LEN,
  buildExplorerAuditFiltersText,
  classifyExplorerQueryResult,
  buildExplorerAuditDetail,
  writeExplorerQueryAudit,
  trimExplorerAuditDetail,
};
