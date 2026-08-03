'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseBoundsConfig } = require('./monitoring-bounds-config');
const { getParameter } = require('./monitoring-intervals');

describe('parseBoundsConfig', () => {
  const apiData = {
    intervals: { ci_low: 5.5, ci_high: 11, ci_minimum: 1 },
    intervals_country_ru: { ci_low: 1.5, ci_high: 1.4, ci_minimum: 0.35 },
    intervals_country_F: { ci_low: 1.75, ci_high: 1.5, ci_minimum: 0.35 },
    intervals_protocols_tcp: { ci_low: 5, ci_high: 3, ci_minimum: 1 },
    intervals_protocols_udp: { ci_low: 1, ci_high: 3, ci_minimum: 0.1 },
    intervals_protocols_oth: { ci_low: 0.01, ci_high: 0.5 },
  };

  it('maps all six monitoring parameters to YAML sections', () => {
    const bounds = parseBoundsConfig(apiData);
    assert.equal(Object.keys(bounds).length, 6);
    assert.equal(bounds.protocol_in_other.ciLow, 0.01);
    assert.equal(bounds.protocol_in_other.ciHigh, 0.5);
    assert.equal(bounds.protocol_in_other.source, 'intervals_protocols_oth');
  });

  it('uses independent config keys for TCP and Other', () => {
    const bounds = parseBoundsConfig(apiData);
    assert.notEqual(bounds.protocol_in_tcp.source, bounds.protocol_in_other.source);
    assert.equal(getParameter('protocol_in_other').boundsConfigKey, 'intervals_protocols_oth');
  });

  it('allows missing ci_minimum for intervals_protocols_oth', () => {
    const bounds = parseBoundsConfig(apiData);
    assert.equal(bounds.protocol_in_other.ciMinimum, null);
    assert.ok(Number.isFinite(bounds.protocol_in_tcp.ciMinimum));
  });
});
