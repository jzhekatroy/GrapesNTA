'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { generateClientId, generateClientSecret } = require('./api-clients');

test('generateClientId produces nta- prefixed lowercase hex', () => {
  for (let i = 0; i < 20; i += 1) {
    const id = generateClientId();
    assert.match(id, /^nta-[0-9a-f]{24}$/);
  }
});

test('generateClientSecret produces 48 lowercase hex chars', () => {
  for (let i = 0; i < 20; i += 1) {
    assert.match(generateClientSecret(), /^[0-9a-f]{48}$/);
  }
});

test('generated credentials do not repeat', () => {
  const ids = new Set(Array.from({ length: 50 }, () => generateClientId()));
  const secrets = new Set(Array.from({ length: 50 }, () => generateClientSecret()));
  assert.equal(ids.size, 50);
  assert.equal(secrets.size, 50);
});
