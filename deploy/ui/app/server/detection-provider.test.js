'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { ispPrefixLookupSql } = require('./clickhouse');
const {
  providerNetMinuteSql,
  providerNetHourSql,
  netObjectsSql,
  PROVIDER_BASELINE_FLOOR_BPS,
} = require('./detection-engine');
const { slicePred } = require('./detection-investigate');

describe('провайдер ШПД', () => {
  it('поиск провайдера идёт по словарю IP_TRIE', () => {
    const sql = ispPrefixLookupSql('f.dst_addr');
    assert.match(sql, /dictGetOrDefault\('default\.net_isp_prefix_dict', 'entity_id'/);
    assert.match(sql, /reinterpretAsUInt32\(reverse\(substring\(f\.dst_addr, 1, 4\)\)\)/);
  });

  it('сети /24 провайдера считаются по словарю, без списка клиентов', () => {
    const minute = providerNetMinuteSql();
    assert.match(minute, /net_isp_prefix_dict/);
    assert.doesNotMatch(minute, /dst_client IN/);
    assert.match(minute, /bytes \* 8 \/ 60 >= \{minBps:Float64\}/);
    const hour = providerNetHourSql();
    assert.match(hour, /^\s*INSERT INTO .*traffic_client_net_1h/m);
    assert.match(hour, /net_isp_prefix_dict/);
  });

  it('первая /24 префикса провайдера уходит из объектов-сетей только со словарём', () => {
    assert.match(netObjectsSql({ clientPrefixes: true, excludeProviders: true }), /role != 'provider_public'/);
    assert.doesNotMatch(netObjectsSql({ clientPrefixes: true, excludeProviders: false }), /provider_public/);
    assert.match(netObjectsSql({ clientPrefixes: true, excludeProviders: true }), /net_client_prefixes_enabled/);
  });

  it('срез разбора: провайдер и /24 внутри провайдера', () => {
    assert.match(slicePred('provider'), /net_isp_prefix_dict.*= \{scopeId:String\}/);
    const net = slicePred('net', 'isp:verolayn', 'provider');
    assert.match(net, /net_isp_prefix_dict.*= \{clientId:String\}/);
    assert.doesNotMatch(net, /dst_client/);
    assert.match(slicePred('net', '81050'), /f\.dst_client = \{clientId:String\}/);
  });

  it('пол нормы нового провайдера — 1 Гбит/с', () => {
    assert.equal(PROVIDER_BASELINE_FLOOR_BPS, 1e9);
  });
});
