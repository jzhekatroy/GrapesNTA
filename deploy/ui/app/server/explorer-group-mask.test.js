'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  parseExplorerGroupToken,
  formatExplorerGroupToken,
  explorerGroupFieldId,
  explorerGroupMask,
  normalizeExplorerGroupTokens,
  explorerBucketFilterFromDisplay,
} = require('./explorer-group-mask');

describe('explorer group mask tokens', () => {
  it('parses maskable and regular dimensions', () => {
    assert.deepEqual(parseExplorerGroupToken('src_ip/24'), { id: 'src_ip', mask: 24, kind: 'cidr' });
    assert.deepEqual(parseExplorerGroupToken('src_ip'), { id: 'src_ip', mask: 32, kind: 'cidr' });
    assert.deepEqual(parseExplorerGroupToken('src_ip/32'), { id: 'src_ip', mask: 32, kind: 'cidr' });
    assert.deepEqual(parseExplorerGroupToken('src_asn'), { id: 'src_asn', mask: null, kind: null });
    assert.deepEqual(parseExplorerGroupToken('src_port/10'), { id: 'src_port', mask: 10, kind: 'bucket' });
    assert.deepEqual(parseExplorerGroupToken('dst_port/100'), { id: 'dst_port', mask: 100, kind: 'bucket' });
    assert.deepEqual(parseExplorerGroupToken('src_port/1000'), { id: 'src_port', mask: 1000, kind: 'bucket' });
    assert.deepEqual(parseExplorerGroupToken('src_port/500'), { id: 'src_port', mask: 500, kind: 'bucket' });
    assert.deepEqual(parseExplorerGroupToken('src_port'), { id: 'src_port', mask: 1, kind: 'bucket' });
  });

  it('falls back to defaults for invalid IP and port steps', () => {
    assert.deepEqual(parseExplorerGroupToken('src_ip/99'), { id: 'src_ip', mask: 32, kind: 'cidr' });
    assert.deepEqual(parseExplorerGroupToken('src_ip/abc'), { id: 'src_ip', mask: 32, kind: 'cidr' });
    assert.deepEqual(parseExplorerGroupToken('dst_ip/'), { id: 'dst_ip', mask: 32, kind: 'cidr' });
    assert.deepEqual(parseExplorerGroupToken('dst_ip/24.5'), { id: 'dst_ip', mask: 32, kind: 'cidr' });
    assert.deepEqual(parseExplorerGroupToken('src_port/7'), { id: 'src_port', mask: 7, kind: 'bucket' });
    assert.deepEqual(parseExplorerGroupToken('src_port/1'), { id: 'src_port', mask: 1, kind: 'bucket' });
    assert.deepEqual(parseExplorerGroupToken('src_port/65536'), { id: 'src_port', mask: 1, kind: 'bucket' });
  });

  it('formats only maskable dimensions and omits default steps', () => {
    assert.equal(formatExplorerGroupToken('src_ip', 24), 'src_ip/24');
    assert.equal(formatExplorerGroupToken('src_ip', 32), 'src_ip');
    assert.equal(formatExplorerGroupToken('src_asn', 24), 'src_asn');
    assert.equal(formatExplorerGroupToken('dst_ip', 0), 'dst_ip');
    assert.equal(formatExplorerGroupToken('src_port', 10), 'src_port/10');
    assert.equal(formatExplorerGroupToken('src_port', 1), 'src_port');
    assert.equal(formatExplorerGroupToken('dst_port', 100), 'dst_port/100');
    assert.equal(formatExplorerGroupToken('src_port', 1000), 'src_port/1000');
    assert.equal(formatExplorerGroupToken('src_port', 500), 'src_port/500');
  });

  it('returns the field id and mask separately', () => {
    assert.equal(explorerGroupFieldId('src_ip/24'), 'src_ip');
    assert.equal(explorerGroupMask('src_ip/24'), 24);
    assert.equal(explorerGroupMask('src_ip'), 32);
    assert.equal(explorerGroupMask('src_asn'), null);
    assert.equal(explorerGroupMask('src_port/10'), 10);
  });

  it('normalizes tokens and de-duplicates by field id', () => {
    assert.deepEqual(
      normalizeExplorerGroupTokens(['src_ip/24', 'src_ip', 'dst_ip/32', 'src_asn', '', null]),
      ['src_ip/24', 'dst_ip', 'src_asn'],
    );
    assert.deepEqual(
      normalizeExplorerGroupTokens(['src_port/10', 'src_port', 'dst_port/100']),
      ['src_port/10', 'dst_port/100'],
    );
    assert.deepEqual(normalizeExplorerGroupTokens(null), []);
  });

  it('parses port bucket display values for between filters', () => {
    assert.deepEqual(explorerBucketFilterFromDisplay('4430-4439'), { op: 'between', value: '4430,4439' });
    assert.equal(explorerBucketFilterFromDisplay('443'), null);
  });
});
