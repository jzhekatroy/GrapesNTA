'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const clickhouse = require('./clickhouse');

const queryResults = [];
const originalQuery = clickhouse.query;

clickhouse.query = async (sql, params, opts) => {
  const name = String(opts?.name || '');
  for (const entry of queryResults) {
    if (!entry.name || entry.name === name || name.includes(entry.name)) {
      if (entry.error) throw entry.error;
      return entry.result || { rows: [], elapsedMs: 1 };
    }
  }
  return { rows: [], elapsedMs: 1 };
};

const {
  searchCabinetClients,
  getCabinetClientBinding,
  buildCabinetClientMatchSql,
  buildCabinetClientFilterSql,
  cabinetClientGroupKeyExpr,
  queryUsesCabinetClient,
  mapCabinetClientSearchRow,
  appendCabinetClientCatalogToCteHead,
  buildCabinetClientSearchWhere,
} = require('./explorer-cabinet-client');

const { normalizeExplorerQuery } = require('./explorer');

function queueQuery(name, rows) {
  queryResults.push({ name, result: { rows, elapsedMs: 1 } });
}

describe('explorer cabinet client helpers', () => {
  beforeEach(() => {
    queryResults.length = 0;
  });

  it('queryUsesCabinetClient detects filter and groupBy', () => {
    assert.equal(queryUsesCabinetClient({ filters: [{ field: 'cabinet_client', op: '=', value: '69862' }] }), true);
    assert.equal(queryUsesCabinetClient({ groupBy: ['cabinet_client'] }), true);
    assert.equal(queryUsesCabinetClient({ filters: [{ field: 'src_ip', op: '=', value: '1.1.1.1' }] }), false);
  });

  it('mapCabinetClientSearchRow reads ClickHouse qualified column names', () => {
    const row = mapCabinetClientSearchRow({
      'c.client_id': 'client:188-143-203-173',
      'c.display_name': 'Test ISP',
      'c.bind_mode': 'prefixes',
      prefix_count: 1,
      port_count: 0,
    });
    assert.equal(row.id, 'client:188-143-203-173');
    assert.equal(row.value, 'client:188-143-203-173');
    assert.equal(row.label, 'Test ISP');
    assert.match(row.sublabel, /client:188-143-203-173/);
  });

  it('mapCabinetClientSearchRow marks clients without binding as selectable but warns in sublabel', () => {
    const row = mapCabinetClientSearchRow({
      client_id: '69862',
      display_name: 'Бегет',
      bind_mode: 'ports',
      prefix_count: 0,
      port_count: 2,
    });
    assert.equal(row.disabled, false);
    assert.equal(row.hasBinding, true);
    assert.match(row.sublabel, /по портам · 2 порта/);

    const empty = mapCabinetClientSearchRow({
      client_id: 'client:empty',
      display_name: 'Empty',
      bind_mode: 'prefixes',
      prefix_count: 0,
      port_count: 0,
    });
    assert.equal(empty.disabled, false);
    assert.equal(empty.hasBinding, false);
    assert.match(empty.sublabel, /нет привязки/);

    const wrongMode = mapCabinetClientSearchRow({
      client_id: 'client:ports-only',
      display_name: 'Ports only',
      bind_mode: 'prefixes',
      prefix_count: 0,
      port_count: 3,
    });
    assert.equal(wrongMode.disabled, false);
    assert.equal(wrongMode.hasBinding, false);
  });

  it('cabinetClientGroupKeyExpr follows src/dst/prefix/port priority', () => {
    const expr = cabinetClientGroupKeyExpr('f');
    assert.match(expr, /f\.src_client != ''/);
    assert.match(expr, /f\.dst_client != ''/);
    assert.match(expr, /cabinet_client_prefix_rules/);
    assert.match(expr, /cabinet_client_port_rules/);
    assert.match(expr, /arrayFirst/);
    assert.doesNotMatch(expr, /\betype\b/);
    assert.doesNotMatch(expr, /SELECT p\.client_id/);
    assert.match(expr, /f\.`SrcAddr`/);
  });

  it('appendCabinetClientCatalogToCteHead injects catalog arrays for grouping', () => {
    const head = 'ts_from, ts_to,';
    const next = appendCabinetClientCatalogToCteHead(head, ['cabinet_client']);
    assert.match(next, /cabinet_client_prefix_rules/);
    assert.match(next, /cabinet_client_port_rules/);
    assert.equal(appendCabinetClientCatalogToCteHead(head, ['src_ip']), head);
  });
});

describe('cabinet client SQL builders', () => {
  beforeEach(() => {
    queryResults.length = 0;
  });

  it('buildCabinetClientMatchSql combines tag and port branches', async () => {
    queueQuery('cabinet-client-binding', [{
      client_id: '69862',
      display_name: 'Бегет',
      bind_mode: 'ports',
      enabled: 1,
    }]);
    queueQuery('cabinet-client-ports', [{
      switch_ip: '10.0.0.1',
      if_index: 24,
    }]);

    const params = {};
    const sql = await buildCabinetClientMatchSql('69862', params, { i: 0 }, 'f');
    assert.match(sql, /f\.src_client = \{cabinet_client_src_/);
    assert.match(sql, /f\.dst_client = \{cabinet_client_dst_/);
    assert.match(sql, /cabinet_client_switch_/);
    assert.match(sql, /cabinet_client_if_/);
  });

  it('buildCabinetClientFilterSql supports in and not_in', async () => {
    queueQuery('cabinet-client-binding', [{
      client_id: '69862',
      display_name: 'Бегет',
      bind_mode: 'prefixes',
      enabled: 1,
    }]);
    queueQuery('cabinet-client-prefixes', [{ prefix: '10.0.0.0/24' }]);
    queueQuery('cabinet-client-binding', [{
      client_id: '37859',
      display_name: 'Other',
      bind_mode: 'prefixes',
      enabled: 1,
    }]);
    queueQuery('cabinet-client-prefixes', [{ prefix: '192.168.0.0/24' }]);

    const params = {};
    const inSql = await buildCabinetClientFilterSql(['69862', '37859'], 'in', params, 'f');
    assert.match(inSql, /OR/);
    assert.match(inSql, /isIPAddressInRange/);

    queueQuery('cabinet-client-binding', [{
      client_id: '69862',
      display_name: 'Бегет',
      bind_mode: 'prefixes',
      enabled: 1,
    }]);
    queueQuery('cabinet-client-prefixes', [{ prefix: '10.0.0.0/24' }]);
    const notSql = await buildCabinetClientFilterSql(['69862'], '!=', params, 'f');
    assert.match(notSql, /^NOT \(/);
  });

  it('getCabinetClientBinding rejects missing client', async () => {
    queueQuery('cabinet-client-binding', []);
    await assert.rejects(
      () => getCabinetClientBinding('missing'),
      (err) => err.statusCode === 400 && /недоступен/i.test(err.message),
    );
  });

  it('searchCabinetClients maps rows from ClickHouse', async () => {
    queueQuery('entities-cabinet-client', [{
      client_id: '69862',
      display_name: 'Бегет',
      bind_mode: 'ports',
      prefix_count: 0,
      port_count: 2,
    }]);
    const rows = await searchCabinetClients({ q: 'бег', limit: 5 });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].value, '69862');
  });

  it('searchCabinetClients resolves clients by IP or CIDR in prefix bindings', async () => {
    queueQuery('entities-cabinet-client', [{
      client_id: 'client:9426',
      display_name: 'Client 94.26',
      bind_mode: 'prefixes',
      prefix_count: 1,
      port_count: 0,
    }]);
    const rows = await searchCabinetClients({ q: '94.26.145.90', limit: 5 });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].value, 'client:9426');
    assert.equal(rows[0].disabled, false);
    assert.equal(rows[0].hasBinding, true);
  });

  it('buildCabinetClientSearchWhere qualifies client columns for JOIN queries', () => {
    const params = {};
    const where = buildCabinetClientSearchWhere('client:188-143-203-173', params);
    assert.match(where, /positionCaseInsensitive\(c\.display_name/);
    assert.match(where, /positionCaseInsensitive\(c\.client_id/);
    assert.match(where, /c\.client_id = \{q0:String\}/);
    assert.match(where, /ni\.if_name/);
    assert.equal(params.q0, 'client:188-143-203-173');
  });

  it('buildCabinetClientSearchWhere ANDs switch and ifName tokens', () => {
    const params = {};
    const where = buildCabinetClientSearchWhere('PortChannel32 172.18.19.12', params);
    assert.match(where, /AND/);
    assert.match(where, /isIPAddressInRange/);
    assert.equal(params.q0, 'PortChannel32');
    assert.equal(params.q1, '172.18.19.12');
  });

  it('searchCabinetClients finds clients by partial client_id', async () => {
    queueQuery('entities-cabinet-client', [{
      client_id: 'client:188-143-203-173',
      display_name: 'Test Client',
      bind_mode: 'prefixes',
      prefix_count: 2,
      port_count: 0,
    }]);
    const rows = await searchCabinetClients({ q: '188-143', limit: 5 });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].value, 'client:188-143-203-173');
  });
});

describe('normalizeExplorerQuery cabinet client period limit', () => {
  it('rejects periods longer than 6 hours with cabinet_client filter', () => {
    assert.throws(
      () => normalizeExplorerQuery({
        range: '24h',
        filters: [{ field: 'cabinet_client', op: '=', value: '69862' }],
      }),
      /6 часов/,
    );
  });

  it('allows 6h period with cabinet_client filter', () => {
    const q = normalizeExplorerQuery({
      range: '6h',
      filters: [{ field: 'cabinet_client', op: '=', value: '69862' }],
    });
    assert.equal(q.range, '6h');
  });

  it('rejects long period with cabinet_client grouping', () => {
    assert.throws(
      () => normalizeExplorerQuery({
        range: '24h',
        groupBy: ['cabinet_client'],
      }),
      /6 часов/,
    );
  });
});

clickhouse.query = originalQuery;
