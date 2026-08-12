const test = require('node:test');
const assert = require('node:assert/strict');

const clickhouse = require('../clickhouse');
const calls = [];

clickhouse.query = async (sql, params, opts) => {
  calls.push({ sql, params, opts });
  return {
    rows: [
      {
        id: 'end-1',
        session_audit_id: 'sess-1',
        event: 'end',
        actor_user_id: 'admin',
        actor_username: 'admin',
        client_id: 'client:demo',
        client_display_name: 'Demo',
        reason: 'stop',
        event_at: '2026-01-02 10:00:00',
      },
      {
        id: 'start-1',
        session_audit_id: 'sess-1',
        event: 'start',
        actor_user_id: 'admin',
        actor_username: 'admin',
        client_id: 'client:demo',
        client_display_name: 'Demo',
        reason: 'impersonate',
        event_at: '2026-01-02 09:30:00',
      },
      {
        id: 'orph-1',
        session_audit_id: 'sess-2',
        event: 'start',
        actor_user_id: 'admin',
        actor_username: 'admin',
        client_id: 'client:other',
        client_display_name: 'Other',
        reason: 'orphaned',
        event_at: '2026-01-01 08:00:00',
      },
    ],
    elapsedMs: 2,
  };
};

clickhouse.executeCommand = async () => ({ elapsedMs: 1 });
clickhouse.insertRows = async (table, rows, opts) => {
  calls.push({ table, rows, opts, kind: 'insert' });
  return { elapsedMs: 1, rows: rows.length };
};

const {
  listRecentImpersonationEvents,
  writeImpersonationEvent,
} = require('./impersonation-audit');

test('listRecentImpersonationEvents maps sessionAuditId and orphaned flag', async () => {
  const result = await listRecentImpersonationEvents({ limit: 10 });
  assert.equal(result.data.length, 3);
  const orphaned = result.data.find((row) => row.sessionAuditId === 'sess-2');
  assert.equal(orphaned.orphaned, true);
  const completed = result.data.find((row) => row.sessionAuditId === 'sess-1' && row.event === 'end');
  assert.equal(completed.orphaned, false);
  assert.match(calls[0].sql, /session_audit_id/);
});

test('writeImpersonationEvent links start/end through sessionAuditId', async () => {
  calls.length = 0;
  const start = await writeImpersonationEvent({
    event: 'start',
    actorUserId: 'admin',
    actorUsername: 'admin',
    clientId: 'client:demo',
    clientDisplayName: 'Demo',
    reason: 'impersonate',
  });
  assert.ok(start.sessionAuditId);
  assert.equal(start.auditId, start.sessionAuditId);

  const end = await writeImpersonationEvent({
    auditId: start.auditId,
    sessionAuditId: start.sessionAuditId,
    event: 'end',
    actorUserId: 'admin',
    actorUsername: 'admin',
    clientId: 'client:demo',
    clientDisplayName: 'Demo',
    reason: 'stop',
  });
  assert.equal(end.sessionAuditId, start.sessionAuditId);
  const inserted = calls.filter((c) => c.kind === 'insert');
  assert.equal(inserted.length, 2);
  assert.equal(inserted[1].rows[0].session_audit_id, start.sessionAuditId);
});
