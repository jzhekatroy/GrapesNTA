'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const G = require('../public/data/explorer-group-dsl.js');

const dimensions = [
  { id: 'src_ip', label: 'IP источника / Source IP', groupable: true, maskable: true },
  { id: 'dst_ip', label: 'IP назначения / Destination IP', groupable: true, maskable: true },
  { id: 'src_asn', label: 'ASN источника / Source ASN', groupable: true },
  { id: 'dst_asn', label: 'ASN назначения / Destination ASN', groupable: true },
  { id: 'proto', label: 'Протокол / Protocol', groupable: true },
  { id: 'src_entity', label: 'Оператор источника / Source owner', groupable: true },
  { id: 'cabinet_client', label: 'Клиент', groupable: true },
  { id: 'l3_owner', label: 'L3 owner', groupable: false },
];

describe('Explorer group-by DSL', () => {
  it('detects group by lines', () => {
    assert.equal(G.isExplorerGroupByDslLine('group by src_ip'), true);
    assert.equal(G.isExplorerGroupByDslLine('  Группировка dst_ip'), true);
    assert.equal(G.isExplorerGroupByDslLine('time range 1h'), false);
  });

  it('serializes groupBy tokens', () => {
    assert.equal(G.serializeExplorerGroupByDsl(['src_ip', 'dst_ip']), 'group by src_ip, dst_ip');
    assert.equal(G.serializeExplorerGroupByDsl(['src_ip/24', 'dst_ip']), 'group by src_ip/24, dst_ip');
    assert.equal(G.serializeExplorerGroupByDsl([]), 'group by src_ip, dst_ip');
  });

  it('parses english and russian headers', () => {
    assert.deepEqual(
      G.parseExplorerGroupByDslLine('group by src_ip, dst_ip', dimensions),
      ['src_ip', 'dst_ip'],
    );
    assert.deepEqual(
      G.parseExplorerGroupByDslLine('группировка dst_ip, proto', dimensions),
      ['dst_ip', 'proto'],
    );
  });

  it('parses IP masks and resolves labels', () => {
    assert.deepEqual(
      G.parseExplorerGroupByDslLine('group by src_ip/24, ASN назначения', dimensions),
      ['src_ip/24', 'dst_asn'],
    );
  });

  it('resolves group-only dimensions', () => {
    assert.deepEqual(
      G.parseExplorerGroupByDslLine('group by src_entity', dimensions),
      ['src_entity'],
    );
    assert.deepEqual(
      G.parseExplorerGroupByDslLine('group by cabinet_client', dimensions),
      ['cabinet_client'],
    );
  });

  it('deduplicates dimensions by field id', () => {
    assert.deepEqual(
      G.parseExplorerGroupByDslLine('group by src_ip, src_ip/24', dimensions),
      ['src_ip'],
    );
  });

  it('rejects unknown dimensions', () => {
    assert.throws(
      () => G.parseExplorerGroupByDslLine('group by unknown_field', dimensions),
      /неизвестное измерение: unknown_field/,
    );
  });

  it('rejects non-groupable dimensions', () => {
    assert.throws(
      () => G.parseExplorerGroupByDslLine('group by l3_owner', dimensions),
      /неизвестное измерение: l3_owner/,
    );
  });

  it('rejects empty group list', () => {
    assert.throws(
      () => G.parseExplorerGroupByDslLine('group by', dimensions),
      /нужна хотя бы одна группировка/,
    );
    assert.throws(
      () => G.parseExplorerGroupByDslLine('group by   ', dimensions),
      /нужна хотя бы одна группировка/,
    );
  });

  it('rejects more than max dimensions when maxCount is set', () => {
    assert.throws(
      () => G.parseExplorerGroupByDslLine(
        'group by src_ip, dst_ip, src_asn, dst_asn, proto',
        dimensions,
        { maxCount: 4 },
      ),
      /не более 4 измерений/,
    );
  });

  it('allows more than four dimensions without maxCount', () => {
    assert.deepEqual(
      G.parseExplorerGroupByDslLine(
        'group by src_ip, dst_ip, src_asn, dst_asn, proto',
        dimensions,
      ),
      ['src_ip', 'dst_ip', 'src_asn', 'dst_asn', 'proto'],
    );
  });

  it('builds suggestions for group by prefix', () => {
    const suggestions = G.buildExplorerGroupByDslSuggestions('group by src', '', dimensions);
    assert.ok(suggestions.some((item) => item.insert.includes('src_ip')));
    assert.ok(suggestions.some((item) => item.label.includes('Source IP') || item.label === 'src_ip'));
  });

  it('builds dimension suggestions on full group by line', () => {
    const suggestions = G.buildExplorerGroupByDslSuggestions('group by src_ip, dst', '', dimensions);
    assert.ok(suggestions.some((item) => item.insert.includes('dst_ip')));
    assert.ok(!suggestions.some((item) => (
      (item.label.includes('Source IP') || item.label === 'src_ip')
      && !String(item.label).includes('/')
    )));
  });

  it('builds partial header suggestions', () => {
    const suggestions = G.buildExplorerGroupByDslSuggestions('group', '', dimensions);
    assert.ok(suggestions.some((item) => item.label === 'group by'));
  });

  it('detects group by input context', () => {
    assert.equal(G.isExplorerGroupByDslContext('group by src_ip'), true);
    assert.equal(G.isExplorerGroupByDslContext('group'), true);
    assert.equal(G.isExplorerGroupByDslContext('групп'), true);
    assert.equal(G.isExplorerGroupByDslContext('proto = UDP'), false);
  });
});
