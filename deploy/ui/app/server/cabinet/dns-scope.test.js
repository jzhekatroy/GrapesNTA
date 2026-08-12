const test = require('node:test');
const assert = require('node:assert/strict');

// Patched before data.js is loaded, because that module destructures query at
// load time. Every test file runs in its own process, so this stays local.
const clickhouse = require('../clickhouse');
const calls = [];
let nextRows = [];
clickhouse.query = async (sql, params, opts) => {
  calls.push({ sql, params, opts });
  return { rows: nextRows, elapsedMs: 1 };
};

const { dnsDomains, dnsQueries } = require('./data');

function callFor(name) {
  const found = calls.filter((c) => c.opts && c.opts.name === name);
  assert.equal(found.length, 1, `expected one ${name} query, got ${found.length}`);
  return found[0];
}

test('dns domains vitrine is scoped by the context client, not by request params', async () => {
  calls.length = 0;
  await dnsDomains('client:real', { client_id: 'client:other', clientId: 'client:other', limit: '5' });

  const call = callFor('cabinet/dns-domains');
  assert.match(call.sql, /FROM default\.dns_client_domain_1h/);
  assert.match(call.sql, /client_id = \{clientId:String\}/);
  assert.equal(call.params.clientId, 'client:real');
  assert.equal(call.params.limit, 5);
  assert.equal(
    JSON.stringify(call.params).includes('client:other'),
    false,
    'a request-supplied client id must never reach the query',
  );
});

test('dns detail list filters by the tagged client and never by address', async () => {
  calls.length = 0;
  await dnsQueries('client:real', { hours: '2' });

  const call = callFor('cabinet/dns-queries');
  assert.match(call.sql, /FROM default\.dns_log/);
  assert.match(call.sql, /client_id = \{clientId:String\}/);
  assert.equal(call.params.clientId, 'client:real');
  // Matching addresses instead of the tag would hand a client the browsing
  // history of whoever held the address before them, for the whole retention.
  assert.equal(/isIPAddressInRange|client_ip\s*(=|>=|<=)/.test(call.sql), false);
});

test('dns limits are clamped so one call cannot pull the whole log', async () => {
  calls.length = 0;
  await dnsQueries('client:real', { limit: '999999' });
  assert.equal(callFor('cabinet/dns-queries').params.limit, 1000);

  calls.length = 0;
  await dnsDomains('client:real', { limit: '999999' });
  assert.equal(callFor('cabinet/dns-domains').params.limit, 100);
});

test('dns domain filter is applied to the registrable domain', async () => {
  calls.length = 0;
  await dnsQueries('client:real', { domain: 'youtube.com' });

  const call = callFor('cabinet/dns-queries');
  assert.match(call.sql, /cutToFirstSignificantSubdomain\(/);
  assert.equal(call.params.domain, 'youtube.com');
  // Names arrive as FQDNs ending in the root dot, and with it in place
  // cutToFirstSignificantSubdomain returns an empty string for everything.
  assert.match(call.sql, /endsWith\(query_name, '\.'\)/);
});

test('the root dot is tolerated on input and stripped on output', async () => {
  calls.length = 0;
  nextRows = [{ ts: '2026-08-10 13:45:19', query_name: 'scbh.yandex.net.', qtype: 'TypeA' }];
  try {
    const result = await dnsQueries('client:real', { domain: 'yandex.net.' });
    assert.equal(callFor('cabinet/dns-queries').params.domain, 'yandex.net');
    assert.equal(result.data[0].queryName, 'scbh.yandex.net');
  } finally {
    nextRows = [];
  }
});
