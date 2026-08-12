const crypto = require('crypto');
const {
  config,
  query,
  insertRows,
  executeCommand,
} = require('../clickhouse');

const TABLE = process.env.CLICKHOUSE_IMPERSONATION_AUDIT_TABLE || 'client_impersonation_audit';

function tableRef() {
  return `${config.database}.${TABLE}`;
}

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().replace('T', ' ').replace('Z', '');
}

async function ensureImpersonationAuditTable() {
  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${tableRef()}
      (
        id String,
        session_audit_id String DEFAULT '',
        event LowCardinality(String),
        actor_user_id String,
        actor_username String,
        client_id String,
        client_display_name String,
        reason LowCardinality(String) DEFAULT '',
        event_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY (event_at, id)
    `,
    {},
    { name: 'cabinet/create-impersonation-audit' },
  );
  await executeCommand(
    `ALTER TABLE ${tableRef()} ADD COLUMN IF NOT EXISTS session_audit_id String DEFAULT ''`,
    {},
    { name: 'cabinet/add-session-audit-id' },
  );
}

async function writeImpersonationEvent({
  auditId,
  sessionAuditId,
  event,
  actorUserId,
  actorUsername,
  clientId,
  clientDisplayName,
  reason = '',
}) {
  const id = crypto.randomUUID();
  const resolvedSessionAuditId = String(
    sessionAuditId
    || (event === 'start' ? (auditId || id) : auditId || ''),
  );
  const row = {
    id,
    session_audit_id: resolvedSessionAuditId,
    event: String(event),
    actor_user_id: String(actorUserId || ''),
    actor_username: String(actorUsername || ''),
    client_id: String(clientId || ''),
    client_display_name: String(clientDisplayName || ''),
    reason: String(reason || ''),
    event_at: clickhouseDateTime(),
  };
  await insertRows(TABLE, [row], { name: 'cabinet/impersonation-audit-write' });
  return {
    auditId: auditId || id,
    sessionAuditId: resolvedSessionAuditId,
    eventId: id,
    eventAt: row.event_at,
  };
}

async function listRecentImpersonationEvents({ limit = 50 } = {}) {
  const { rows, elapsedMs } = await query(
    `
      SELECT
        id,
        session_audit_id,
        event,
        actor_user_id,
        actor_username,
        client_id,
        client_display_name,
        reason,
        event_at
      FROM ${tableRef()}
      ORDER BY event_at DESC
      LIMIT {limit:UInt32}
    `,
    { limit: Number(limit) || 50 },
    { name: 'cabinet/impersonation-audit-list' },
  );
  return {
    data: rows.map((r) => ({
      id: String(r.id),
      sessionAuditId: String(r.session_audit_id || r.id),
      event: String(r.event),
      actorUserId: String(r.actor_user_id),
      actorUsername: String(r.actor_username),
      clientId: String(r.client_id),
      clientDisplayName: String(r.client_display_name),
      reason: String(r.reason || ''),
      eventAt: r.event_at,
      orphaned: String(r.event) === 'start' && String(r.reason || '') === 'orphaned',
    })),
    meta: { elapsedMs, rows: rows.length },
  };
}

module.exports = {
  ensureImpersonationAuditTable,
  writeImpersonationEvent,
  listRecentImpersonationEvents,
};
