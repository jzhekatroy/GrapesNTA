'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  dnsExplorerSchema,
  dnsExplorerQuery,
  dnsExplorerSuggestAnswers,
  dnsExplorerSuggestDomains,
  needsAnswerExpand,
  dnsExplorerDataSource,
  dnsDomainEqSql,
  answerEqFilterSql,
  answerInCidrFilterSql,
  answerContainsFilterSql,
  GROUP_BY,
  FIELDS,
} = require('./dns-explorer');

describe('dnsExplorerSchema answer dimensions', () => {
  it('includes answer and answer_type groupings', () => {
    const schema = dnsExplorerSchema();
    const groupIds = schema.groupBy.map((g) => g.id);
    assert.ok(groupIds.includes('answer'));
    assert.ok(groupIds.includes('answer_type'));
    const answerField = schema.fields.find((f) => f.id === 'answer');
    assert.ok(answerField);
    assert.deepEqual(answerField.ops, ['eq', 'ne', 'in_cidr', 'contains']);
  });
});

describe('needsAnswerExpand', () => {
  it('returns false for legacy groupings', () => {
    assert.equal(needsAnswerExpand(['query_name']), false);
    assert.equal(needsAnswerExpand(['client_ip', 'rcode']), false);
  });

  it('returns true when answer dimensions are present', () => {
    assert.equal(needsAnswerExpand(['answer']), true);
    assert.equal(needsAnswerExpand(['answer_type']), true);
    assert.equal(needsAnswerExpand(['query_name', 'answer']), true);
  });
});

describe('dnsExplorerDataSource', () => {
  const base = {
    whereSql: 'd.ts >= now() - INTERVAL 24 HOUR',
    params: {},
  };

  it('keeps direct dns_log source without answer grouping', () => {
    const source = dnsExplorerDataSource(base, ['query_name']);
    assert.match(source.fromSql, /dns_log/i);
    assert.doesNotMatch(source.fromSql, /arrayJoin/i);
    assert.equal(source.whereSql, base.whereSql);
  });

  it('uses expanded subquery for answer grouping', () => {
    const source = dnsExplorerDataSource(base, ['answer']);
    assert.match(source.fromSql, /arrayJoin/i);
    assert.match(source.fromSql, /answer_pair\.1 AS answer_type/i);
    assert.match(source.fromSql, /answer_pair\.2 AS answer/i);
    assert.match(source.fromSql, /inner_d\.is_response = 1/i);
    assert.match(source.fromSql, /tuple\('none', ''\)/i);
    assert.equal(source.whereSql, '1');
  });

  it('rewrites d alias to inner_d inside expanded subquery WHERE', () => {
    const source = dnsExplorerDataSource({
      whereSql: 'd.ts >= now() - INTERVAL 24 HOUR\n  AND replaceRegexpOne(d.query_name, \'\\\\.$\', \'\') = replaceRegexpOne({f0:String}, \'\\\\.$\', \'\')',
    }, ['answer']);
    assert.match(source.fromSql, /inner_d\.ts >= now\(\) - INTERVAL 24 HOUR/i);
    assert.match(source.fromSql, /replaceRegexpOne\(inner_d\.query_name/i);
    assert.doesNotMatch(source.fromSql, /\bd\.ts\b/);
    assert.doesNotMatch(source.fromSql, /\bd\.query_name\b/);
  });
});

describe('dnsExplorerQuery SQL', () => {
  it('does not expand arrays for legacy grouping', () => {
    const spec = dnsExplorerQuery({
      metric: 'queries_per_sec',
      groupBy: ['query_name'],
      filters: [],
      range: '24h',
      limit: 10,
    });
    assert.match(spec.tableSql, /dns_log/i);
    assert.doesNotMatch(spec.tableSql, /arrayJoin/i);
  });

  it('expands answers only when answer grouping is selected', () => {
    const spec = dnsExplorerQuery({
      metric: 'responses_per_sec',
      groupBy: ['answer'],
      filters: [{ field: 'query_name', op: 'eq', value: 'ya.ru', logic: 'and' }],
      range: '24h',
      limit: 10,
    });
    assert.match(spec.tableSql, /arrayJoin/i);
    assert.match(spec.tableSql, /dim_0/);
    assert.match(spec.params.f0, /ya\.ru/);
  });

  it('applies answer filter before expansion', () => {
    const spec = dnsExplorerQuery({
      metric: 'responses_per_sec',
      groupBy: ['query_name'],
      filters: [{ field: 'answer', op: 'eq', value: '77.88.55.242', logic: 'and' }],
      range: '24h',
      limit: 10,
    });
    assert.doesNotMatch(spec.tableSql, /arrayJoin/i);
    assert.match(spec.tableSql, /answers_a/i);
    assert.equal(spec.params.f0, '77.88.55.242');
  });
});

describe('domain and answer filter helpers', () => {
  it('normalizes trailing dot for domain equality', () => {
    const sql = dnsDomainEqSql('d.query_name', 'f0');
    assert.match(sql, /replaceRegexpOne/);
    assert.match(sql, /f0:String/);
  });

  it('builds IPv4 answer equality filter', () => {
    const sql = answerEqFilterSql('d', 'f0');
    assert.match(sql, /answers_a/);
    assert.match(sql, /answers_aaaa/);
    assert.match(sql, /answers_cname/);
    assert.match(sql, /f0:String/);
  });

  it('builds CIDR answer filter for v4 and v6 arrays', () => {
    const sql = answerInCidrFilterSql('d', 'f0');
    assert.match(sql, /isIPAddressInRange/);
    assert.match(sql, /answers_a/);
    assert.match(sql, /answers_aaaa/);
    assert.doesNotMatch(sql, /answers_cname/);
  });

  it('builds CNAME contains filter', () => {
    const sql = answerContainsFilterSql('d', 'f0');
    assert.match(sql, /answers_cname/);
    assert.match(sql, /positionCaseInsensitive/);
  });
});

describe('dnsExplorerSuggestAnswers', () => {
  it('returns expanded answer suggestions excluding empty none rows', () => {
    const spec = dnsExplorerSuggestAnswers({ range: '24h', filters: [] }, '77', 50);
    assert.match(spec.sql, /arrayJoin/i);
    assert.match(spec.sql, /answer_pair\.1 != 'none'/);
    assert.match(spec.sql, /answer_pair\.2 != ''/);
    assert.match(spec.sql, /LIMIT \{limit:UInt32\}/);
    assert.equal(spec.params.limit, 50);
  });
});

describe('dnsExplorerSuggestDomains normalization', () => {
  it('returns domains without trailing dot in value expression', () => {
    const spec = dnsExplorerSuggestDomains({ range: '24h', filters: [] }, '', 20);
    assert.match(spec.sql, /replaceRegexpOne\(d\.query_name/);
  });
});

describe('GROUP_BY and FIELDS exports', () => {
  it('keeps answer metadata available for CSV headers', () => {
    const answerGroup = GROUP_BY.find((g) => g.id === 'answer');
    const answerField = FIELDS.find((f) => f.id === 'answer');
    assert.equal(answerGroup.label, 'Ответ');
    assert.equal(answerField.label, 'Ответ');
  });
});
