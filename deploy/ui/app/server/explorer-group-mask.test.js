'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  parseExplorerGroupToken,
  formatExplorerGroupToken,
  explorerGroupFieldId,
  explorerGroupMask,
  normalizeExplorerGroupTokens,
} = require('./explorer-group-mask');

describe('explorer group mask tokens', () => {
  it('parses maskable and regular dimensions', () => {
    assert.deepEqual(parseExplorerGroupToken('src_ip/24'), { id: 'src_ip', mask: 24 });
    assert.deepEqual(parseExplorerGroupToken('src_ip'), { id: 'src_ip', mask: 32 });
    assert.deepEqual(parseExplorerGroupToken('src_ip/32'), { id: 'src_ip', mask: 32 });
    assert.deepEqual(parseExplorerGroupToken('src_asn'), { id: 'src_asn', mask: null });
  });

  it('falls back to a host mask for invalid values', () => {
    assert.deepEqual(parseExplorerGroupToken('src_ip/99'), { id: 'src_ip', mask: 32 });
    assert.deepEqual(parseExplorerGroupToken('src_ip/abc'), { id: 'src_ip', mask: 32 });
    assert.deepEqual(parseExplorerGroupToken('dst_ip/'), { id: 'dst_ip', mask: 32 });
    assert.deepEqual(parseExplorerGroupToken('dst_ip/24.5'), { id: 'dst_ip', mask: 32 });
  });

  it('formats only maskable dimensions and omits /32', () => {
    assert.equal(formatExplorerGroupToken('src_ip', 24), 'src_ip/24');
    assert.equal(formatExplorerGroupToken('src_ip', 32), 'src_ip');
    assert.equal(formatExplorerGroupToken('src_asn', 24), 'src_asn');
    assert.equal(formatExplorerGroupToken('dst_ip', 0), 'dst_ip');
  });

  it('returns the field id and mask separately', () => {
    assert.equal(explorerGroupFieldId('src_ip/24'), 'src_ip');
    assert.equal(explorerGroupMask('src_ip/24'), 24);
    assert.equal(explorerGroupMask('src_ip'), 32);
    assert.equal(explorerGroupMask('src_asn'), null);
  });

  it('normalizes tokens and de-duplicates by field id', () => {
    assert.deepEqual(
      normalizeExplorerGroupTokens(['src_ip/24', 'src_ip', 'dst_ip/32', 'src_asn', '', null]),
      ['src_ip/24', 'dst_ip', 'src_asn'],
    );
    assert.deepEqual(normalizeExplorerGroupTokens(null), []);
  });
});
