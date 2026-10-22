'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { mapRoleRow, roleInsertRow } = require('./rbac/permissions');

describe('role attack_alert mapping', () => {
  it('maps attack_alert column to attackAlert boolean', () => {
    assert.equal(mapRoleRow({ id: 'r', name: 'r', display_name: 'R', start_page: 'dashboard', attack_alert: 1 }).attackAlert, true);
    assert.equal(mapRoleRow({ id: 'r', name: 'r', display_name: 'R', start_page: 'dashboard', attack_alert: 0 }).attackAlert, false);
    assert.equal(mapRoleRow({ id: 'r', name: 'r', display_name: 'R', start_page: 'dashboard' }).attackAlert, false);
  });

  it('roleInsertRow preserves attack_alert when not updated', () => {
    const existing = mapRoleRow({
      id: 'Operator',
      name: 'Operator',
      display_name: 'Op',
      start_page: 'monitoring',
      attack_alert: 1,
      created_at: '2026-01-01',
      updated_at: '2026-01-01',
    });
    const row = roleInsertRow(existing, {
      displayName: 'Op 2',
      now: '2026-02-01',
    });
    assert.equal(row.attack_alert, 1);
    assert.equal(row.display_name, 'Op 2');
    assert.equal(row.start_page, 'monitoring');
  });

  it('roleInsertRow writes attack_alert when toggled off', () => {
    const existing = mapRoleRow({
      id: 'Operator',
      name: 'Operator',
      display_name: 'Op',
      start_page: 'dashboard',
      attack_alert: 1,
      created_at: '2026-01-01',
      updated_at: '2026-01-01',
    });
    const row = roleInsertRow(existing, { attackAlert: false, now: '2026-02-01' });
    assert.equal(row.attack_alert, 0);
  });
});
