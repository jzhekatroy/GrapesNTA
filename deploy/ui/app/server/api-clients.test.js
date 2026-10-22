'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { generateClientId, generateClientSecret, validateManualRegistration } = require('./api-clients');

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

test('validateManualRegistration accepts a valid pair and trims name and id', () => {
  const result = validateManualRegistration({
    name: '  Piter-ix  ',
    clientId: ' erp-piterix-prod ',
    clientSecret: '0123456789ab',
  });
  assert.equal(result.error, undefined);
  assert.deepEqual(result.value, {
    clientName: 'Piter-ix',
    clientId: 'erp-piterix-prod',
    clientSecret: '0123456789ab',
  });
});

test('validateManualRegistration enforces client_id length and charset', () => {
  assert.ok(validateManualRegistration({
    name: 'x', clientId: 'a'.repeat(11), clientSecret: '0123456789ab',
  }).error);
  assert.ok(validateManualRegistration({
    name: 'x', clientId: 'a'.repeat(65), clientSecret: '0123456789ab',
  }).error);
  assert.equal(validateManualRegistration({
    name: 'x', clientId: 'a'.repeat(64), clientSecret: '0123456789ab',
  }).error, undefined);
  assert.ok(validateManualRegistration({
    name: 'x', clientId: 'группа710!!!', clientSecret: '0123456789ab',
  }).error);
});

test('validateManualRegistration enforces secret length and keeps it byte-exact', () => {
  assert.ok(validateManualRegistration({
    name: 'x', clientId: 'erp-piterix-prod', clientSecret: '0123456789a',
  }).error);
  assert.ok(validateManualRegistration({
    name: 'x', clientId: 'erp-piterix-prod', clientSecret: 's'.repeat(513),
  }).error);
  assert.equal(validateManualRegistration({
    name: 'x', clientId: 'erp-piterix-prod', clientSecret: 's'.repeat(512),
  }).error, undefined);
  // Секрет не обрезается: пробелы остаются частью секрета, как их будет слать ERP.
  const withSpaces = validateManualRegistration({
    name: 'x', clientId: 'erp-piterix-prod', clientSecret: ' 0123456789ab ',
  });
  assert.equal(withSpaces.value.clientSecret, ' 0123456789ab ');
});

test('validateManualRegistration rejects empty and oversized names', () => {
  assert.ok(validateManualRegistration({ name: '   ', clientId: 'erp-piterix-prod', clientSecret: '0123456789ab' }).error);
  assert.ok(validateManualRegistration({ name: 'n'.repeat(121), clientId: 'erp-piterix-prod', clientSecret: '0123456789ab' }).error);
  assert.equal(validateManualRegistration({ name: 'n'.repeat(120), clientId: 'erp-piterix-prod', clientSecret: '0123456789ab' }).error, undefined);
});
