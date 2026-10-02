const test = require('node:test');
const assert = require('node:assert/strict');

const { serviceDistribution, serviceDistributionTimeseries } = require('./queries');

test('услуги за час читают минутную таблицу', () => {
  const sql = serviceDistribution({ range: '1h' }).sql;
  assert.match(sql, /traffic_service_1m/);
  assert.doesNotMatch(sql, /traffic_service_1h/);
  assert.match(sql, /minute >= ts_from/);
});

test('услуги за сутки читают часовую сводку и добирают края из минут', () => {
  const sql = serviceDistribution({ range: '24h' }).sql;
  assert.match(sql, /traffic_service_1h/);
  assert.match(sql, /traffic_service_1m/);
  assert.match(sql, /AS rolled_end/);
  assert.match(sql, /hour >= hour_from/);
  assert.doesNotMatch(sql, /minute >= ts_from\s+AND minute < ts_to/);
});

test('тренд услуг за сутки идёт по часам, за час — по пяти минутам', () => {
  const day = serviceDistributionTimeseries({ range: '24h' }).sql;
  const hour = serviceDistributionTimeseries({ range: '1h' }).sql;
  assert.match(day, /t\.bucket_time AS bucket/);
  assert.match(day, /3600 AS bucket_seconds/);
  assert.match(hour, /INTERVAL 5 MINUTE/);
  assert.doesNotMatch(hour, /traffic_service_1h/);
});

test('неделя и свой период от суток тоже идут в часовую сводку', () => {
  assert.match(serviceDistribution({ range: '7d' }).sql, /traffic_service_1h/);
  const custom = serviceDistribution({
    range: 'custom',
    from: '2026-10-01 00:00:00',
    to: '2026-10-02 00:00:00',
  }).sql;
  assert.match(custom, /traffic_service_1h/);
  const short = serviceDistribution({
    range: 'custom',
    from: '2026-10-01 00:00:00',
    to: '2026-10-01 06:00:00',
  }).sql;
  assert.doesNotMatch(short, /traffic_service_1h/);
});
