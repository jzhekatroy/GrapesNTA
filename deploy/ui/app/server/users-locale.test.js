const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeLocale } = require('./users');

test('normalizeLocale keeps ru and en', () => {
  assert.equal(normalizeLocale('ru'), 'ru');
  assert.equal(normalizeLocale('en'), 'en');
  assert.equal(normalizeLocale(' RU '), 'ru');
  assert.equal(normalizeLocale('EN'), 'en');
});

test('normalizeLocale rejects anything else', () => {
  assert.equal(normalizeLocale(''), '');
  assert.equal(normalizeLocale(null), '');
  assert.equal(normalizeLocale(undefined), '');
  assert.equal(normalizeLocale('fr'), '');
  assert.equal(normalizeLocale('en-US'), '');
  assert.equal(normalizeLocale('english'), '');
});
