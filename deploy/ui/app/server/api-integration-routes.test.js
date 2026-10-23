'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildClientsPayload,
  requireClientId,
  mergeJournalEvents,
  JOURNAL_ACTIONS,
} = require('./api-integration-routes');

test('buildClientsPayload merges clients with tokens and monitor stats', () => {
  const payload = buildClientsPayload(
    [
      {
        clientId: 'nta-abc',
        clientName: 'Piter-ix',
        active: true,
        createdAt: '2026-10-01 10:00:00',
        updatedAt: '2026-10-02 11:00:00',
      },
      {
        clientId: 'erp-manual-id-1',
        clientName: 'Ручное',
        active: false,
        createdAt: '2026-10-03 10:00:00',
        updatedAt: '2026-10-03 10:00:00',
      },
    ],
    [
      { clientId: 'nta-abc', count: 2, expiresSoonestAt: 1790000000000 },
    ],
    {
      'nta-abc': { lastUsedAt: 1790000050000, tokensIssuedToday: 3, requestsToday: 7 },
    },
    3600,
  );

  assert.equal(payload.tokenTtlSec, 3600);
  assert.equal(payload.clients.length, 2);

  const generated = payload.clients[0];
  assert.equal(generated.manual, false);
  assert.equal(generated.activeTokens, 2);
  assert.equal(generated.tokenExpiresSoonestAt, 1790000000000);
  assert.equal(generated.lastUsedAt, 1790000050000);
  assert.equal(generated.tokensIssuedToday, 3);
  assert.equal(generated.requestsToday, 7);

  // Клиент без токенов и статистики получает нули, а не undefined.
  const manual = payload.clients[1];
  assert.equal(manual.manual, true);
  assert.equal(manual.activeTokens, 0);
  assert.equal(manual.tokenExpiresSoonestAt, null);
  assert.equal(manual.lastUsedAt, null);
  assert.equal(manual.tokensIssuedToday, 0);
  assert.equal(manual.requestsToday, 0);
});

test('requireClientId trims value and rejects missing id with 400', () => {
  assert.equal(requireClientId({ clientId: '  nta-abc  ' }), 'nta-abc');
  for (const body of [{}, { clientId: '   ' }, { clientId: null }]) {
    assert.throws(() => requireClientId(body), (err) => {
      assert.equal(err.statusCode, 400);
      assert.equal(err.message, 'Укажите client_id');
      return true;
    });
  }
});

test('journal actions cover every mutating admin api-client route', () => {
  assert.deepEqual(JOURNAL_ACTIONS, [
    'api_client_create',
    'api_client_recreate',
    'api_client_manual_register',
    'api_client_activate',
    'api_client_deactivate',
    'api_client_delete',
    'api_client_tokens_revoke',
  ]);
});

test('mergeJournalEvents dedupes by id, sorts newest first and slices to limit', () => {
  const adminOps = [
    { id: 'a1', eventAt: '2026-10-22 10:00:01.000', action: 'api_client_create' },
    { id: 'a2', eventAt: '2026-10-22 09:00:00.000', action: 'api_client_delete' },
  ];
  const apiOps = [
    { id: 'b1', eventAt: '2026-10-22 12:30:00.000', action: 'user_create' },
    // та же запись, пришедшая из другой выборки — дубль
    { id: 'a1', eventAt: '2026-10-22 10:00:01.000', action: 'api_client_create' },
    null,
  ];

  assert.deepEqual(
    mergeJournalEvents([adminOps, apiOps], 2).map((row) => row.id),
    ['b1', 'a1'],
  );
  assert.deepEqual(
    mergeJournalEvents([adminOps, apiOps], 10).map((row) => row.id),
    ['b1', 'a1', 'a2'],
  );
  assert.deepEqual(mergeJournalEvents([[], null, []], 10), []);
});
