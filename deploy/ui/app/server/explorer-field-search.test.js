'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { explorerFieldMatchesQuery } = require('../public/data/explorer-field-search.js');

describe('explorerFieldMatchesQuery (client helper)', () => {
  const field = {
    id: 'src_ip',
    label: 'IP источника / Source IP',
    aliases: ['src', 'source', 'источник'],
  };

  it('matches id, label parts, and aliases case-insensitively', () => {
    assert.equal(explorerFieldMatchesQuery(field, 'src'), true);
    assert.equal(explorerFieldMatchesQuery(field, 'SRC'), true);
    assert.equal(explorerFieldMatchesQuery(field, 'source'), true);
    assert.equal(explorerFieldMatchesQuery(field, 'источник'), true);
    assert.equal(explorerFieldMatchesQuery(field, 'source ip'), true);
    assert.equal(explorerFieldMatchesQuery(field, 'dst'), false);
  });

  it('returns all fields for empty query', () => {
    assert.equal(explorerFieldMatchesQuery(field, ''), true);
    assert.equal(explorerFieldMatchesQuery(field, '   '), true);
  });
});
