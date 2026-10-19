const test = require('node:test');
const assert = require('node:assert/strict');
const {
  DEFAULT_START_PAGE,
  normalizeStartPage,
  resolveRoleStartPage,
} = require('./permissions');

test('normalizeStartPage defaults and validates against app pages', () => {
  assert.equal(normalizeStartPage(''), DEFAULT_START_PAGE);
  assert.equal(normalizeStartPage(null), DEFAULT_START_PAGE);
  assert.equal(normalizeStartPage('observations'), 'observations');
  assert.equal(normalizeStartPage('not-a-page'), DEFAULT_START_PAGE);
  assert.equal(DEFAULT_START_PAGE, 'dashboard');
});

test('resolveRoleStartPage requires view permission on the role', () => {
  const perms = { dashboard: true, observations: true, explorer: false };
  assert.equal(resolveRoleStartPage('observations', perms), 'observations');
  assert.equal(resolveRoleStartPage('explorer', perms), DEFAULT_START_PAGE);
  assert.equal(resolveRoleStartPage('unknown', perms), DEFAULT_START_PAGE);
});
