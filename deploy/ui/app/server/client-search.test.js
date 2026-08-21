'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  splitClientSearchTokens,
  parseIpv4SearchTerm,
  ipv4InCidr,
  asStringArray,
  clientRowMatchesSearch,
  buildClientSearchWhere,
} = require('./client-search');

describe('client search helpers', () => {
  it('splits tokens on whitespace', () => {
    assert.deepEqual(splitClientSearchTokens('  PortChannel32   172.18.19.12 '), [
      'PortChannel32',
      '172.18.19.12',
    ]);
  });

  it('parses IPv4 and rejects octets over 255', () => {
    assert.equal(parseIpv4SearchTerm('172.18.19.12'), '172.18.19.12');
    assert.equal(parseIpv4SearchTerm('PortChannel32'), null);
    assert.equal(parseIpv4SearchTerm('10.0.0.256'), null);
  });

  it('matches an address inside a CIDR', () => {
    assert.equal(ipv4InCidr('94.26.145.90', '94.26.145.0/24'), true);
    assert.equal(ipv4InCidr('94.26.146.90', '94.26.145.0/24'), false);
    assert.equal(ipv4InCidr('172.18.19.12', '172.18.19.12'), true);
  });

  it('ANDs tokens against name, switch, ifName and CIDR', () => {
    const row = {
      displayName: 'ООО Пример',
      clientId: 'client:primer',
      bindMode: 'ports',
      bindingPreview: ['172.18.19.12 · PortChannel32'],
      bindingSearch: '172.18.19.12 64 PortChannel32 Po32 uplink',
      bindingPrefixes: [],
    };
    assert.equal(clientRowMatchesSearch(row, 'PortChannel32 172.18.19.12'), true);
    assert.equal(clientRowMatchesSearch(row, 'PortChannel32 10.0.0.1'), false);
    assert.equal(clientRowMatchesSearch({
      displayName: 'Сеть',
      clientId: 'client:net',
      bindingPrefixes: ['94.26.145.0/24'],
    }, '94.26.145.90'), true);
  });

  it('builds SQL that ANDs tokens and looks at ifName plus prefix range', () => {
    const params = {};
    const where = buildClientSearchWhere('PortChannel32 172.18.19.12', params);
    assert.match(where, /AND/);
    assert.match(where, /ni\.if_name/);
    assert.match(where, /isIPAddressInRange/);
    assert.equal(params.q0, 'PortChannel32');
    assert.equal(params.q1, '172.18.19.12');
  });

  it('normalizes ClickHouse array-or-string previews', () => {
    assert.deepEqual(asStringArray(['a', ' b ']), ['a', 'b']);
    assert.deepEqual(asStringArray('["x","y"]'), ['x', 'y']);
  });
});
