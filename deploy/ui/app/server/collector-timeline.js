'use strict';

const { query, config, collectorHealthSnapshotsTableRef } = require('./clickhouse');

const RETENTION_DAYS = 90;
const MAX_RANGE_MS = RETENTION_DAYS * 86400000;
const MIN_RANGE_MS = 10 * 60000;
const MAX_CELLS = 240;
const BUCKET_STEPS_SEC = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200];
/** Snapshots come once a minute; a longer silence means the collector or ClickHouse was down. */
const GAP_SEC = 150;
/** A short silence while counters kept growing is a late snapshot, not an outage. */
const LATE_SNAPSHOT_SEC = 600;
/** Problems of one kind closer than this are one incident. */
const MERGE_GAP_MS = 10 * 60000;
/** Shorter data incidents go to "other events" as a count. */
const MIN_INCIDENT_MS = 5 * 60000;
/** Rows before `from` so the first in-range snapshot has a baseline to diff against. */
const LOOKBACK_MINUTES = 30;
const RUN_LIMIT = 5000;
const EPOCH = "toDateTime64(0, 3, 'UTC')";

const INPUT_COUNTERS = ['xdp_total_packets', 'datagrams', 'records_parsed'];
const WRITE_COUNTERS = ['records_acked', 'records_written'];
const LOSS_COUNTERS = [
  'udp_queue_drops',
  'ch_queue_drops',
  'spool_corruption_frames',
  'xdp_map_full',
  'phy_rx_discards',
  'nf_send_errs',
];
/** Packet funnel for the period charts. Missing on older installs, then the delta is zero. */
const SERIES_COUNTERS = [
  'phy_rx_packets',
  'xdp_non_ip_pass',
  'flow_packets_acked',
  'flow_packets_excluded',
  'records_spooled',
  'nf_records_out',
];
const COUNTERS = [...INPUT_COUNTERS, ...WRITE_COUNTERS, ...LOSS_COUNTERS, 'insert_errs', ...SERIES_COUNTERS];
/** NetFlow send errors are a copy that did not reach its receiver, not data missing from ClickHouse. */
const LOST_COUNTERS = LOSS_COUNTERS.filter((c) => c !== 'nf_send_errs');

/** Status reasons that mean data did not reach ClickHouse on time or was lost. */
const WRITE_BLOCK_REASONS = ['clickhouse_insert_errors'];
const DATA_LOSS_REASONS = ['clickhouse_queue_drops', 'udp_queue_drops', 'xdp_map_full', 'spool_corruption'];
const DATA_REASONS = [...WRITE_BLOCK_REASONS, ...DATA_LOSS_REASONS];

/** Incident kinds, most severe first: they decide the "now" line too. */
const CATEGORY_ORDER = ['gap', 'write_blocked', 'no_input', 'loss'];

const REASONS = {
  gap: { label: 'Коллектор не отвечал', hint: 'нет снимков состояния' },
  no_input: { label: 'Нет входящего потока', hint: 'экспортёр или зеркало ничего не присылает' },
  restart: { label: 'Перезапуски коллектора', hint: 'счётчики начинались заново' },
  late_snapshot: { label: 'Снимки состояния опаздывали', hint: 'коллектор работал, данные не потеряны' },
  clickhouse_insert_errors: { label: 'ClickHouse не принимал запись', hint: 'данные ждали в буфере и дошлются позже' },
  clickhouse_queue_drops: { label: 'Переполнялась очередь записи', hint: 'часть записей потеряна' },
  udp_queue_drops: { label: 'Переполнялась очередь приёма UDP', hint: 'часть датаграмм потеряна' },
  xdp_map_full: { label: 'Переполнялась таблица потоков XDP', hint: 'часть пакетов не учтена' },
  spool_corruption: { label: 'Повреждение буфера на диске', hint: 'повреждённые кадры пропущены' },
  netflow_send_errors: { label: 'Ошибки отправки NetFlow', hint: 'копия потока не дошла до получателя, в ClickHouse данные есть' },
  phy_rx_discards: { label: 'Сетевая карта отбрасывала пакеты', hint: 'порт не успевал принять часть трафика' },
  spool_lag_segments: { label: 'Буфер рос', hint: 'запись в ClickHouse отставала от приёма' },
  writer_lag_rows: { label: 'Запись отставала от приёма', hint: 'ClickHouse медленно принимал вставки' },
  drainer_stalled: { label: 'Досылка из буфера останавливалась', hint: 'буфер не уменьшался' },
};

const CATEGORY_INFO = {
  gap: { severity: 'down', ...REASONS.gap },
  no_input: { severity: 'critical', label: 'Нет входящего потока', hint: 'экспортёр или зеркало ничего не присылало — данных за это время нет' },
  write_blocked: { severity: 'critical', ...REASONS.clickhouse_insert_errors },
  loss: { severity: 'critical', label: 'Потери данных', hint: 'часть потока не попала в ClickHouse' },
};

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function msOrNull(value) {
  const n = num(value);
  return n > 0 ? n : null;
}

function reasonInfo(code) {
  return { code, label: code, hint: '', ...(REASONS[code] || {}) };
}

function sqlList(values) {
  return `[${values.map((v) => `'${v}'`).join(', ')}]`;
}

function parseArray(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      return raw.replace(/^\[|\]$/g, '').split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
    }
  }
  return [];
}

function parseReasons(raw) {
  return parseArray(raw).map(String).filter(Boolean);
}

function parseRange(fromRaw, toRaw, nowMs = Date.now()) {
  const toMs = toRaw != null && toRaw !== '' ? Number(toRaw) : nowMs;
  const fromMs = fromRaw != null && fromRaw !== '' ? Number(fromRaw) : toMs - 86400000;
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs)) throw apiError('Некорректный период');
  const to = Math.min(Math.round(toMs), nowMs);
  const from = Math.max(Math.round(fromMs), nowMs - MAX_RANGE_MS);
  if (to - from < MIN_RANGE_MS) throw apiError('Период слишком короткий: нужно хотя бы 10 минут');
  return { fromMs: from, toMs: to };
}

function chooseBucketSeconds(spanMs) {
  const spanSec = spanMs / 1000;
  for (const step of BUCKET_STEPS_SEC) {
    if (spanSec / step <= MAX_CELLS) return step;
  }
  return BUCKET_STEPS_SEC[BUCKET_STEPS_SEC.length - 1];
}

const COLUMNS_TTL_MS = 5 * 60000;
let columnsCache = { at: 0, names: null };

/** Older installs lack pipeline_stages, phy_* and nf_* columns: read what exists. */
async function snapshotColumns() {
  if (columnsCache.names && Date.now() - columnsCache.at < COLUMNS_TTL_MS) return columnsCache.names;
  try {
    const { rows } = await query(
      'SELECT name FROM system.columns WHERE database = {db:String} AND table = {table:String}',
      { db: config.database, table: config.collectorHealthSnapshotsTable },
      { name: 'collectors/timeline/columns' },
    );
    const names = new Set(rows.map((r) => String(r.name)));
    if (names.size) columnsCache = { at: Date.now(), names };
    return names.size ? names : null;
  } catch {
    return null;
  }
}

function colExpr(cols, name, fallback) {
  return !cols || cols.has(name) ? name : fallback;
}

function deltaSnapsSql(table, cols = null) {
  const lagCols = COUNTERS
    .map((c) => {
      const src = colExpr(cols, c, 'toUInt64(0)');
      return `${src} AS ${c}, lagInFrame(${src}, 1, toUInt64(0)) OVER p AS ${c}_prev`;
    })
    .join(',\n        ');
  const isXdp = !cols || cols.has('pipeline_stages')
    ? "has(pipeline_stages, 'collector')"
    : "daemon = 'xdpflowd'";
  const deltaCols = COUNTERS
    .map((c) => `if(has_base, if(${c} >= ${c}_prev, toUInt64(${c} - ${c}_prev), ${c}), toUInt64(0)) AS ${c}_d`)
    .join(',\n        ');
  const restarted = INPUT_COUNTERS.map((c) => `${c} < ${c}_prev`).join(' OR ');
  return `
    snaps AS (
      SELECT
        ts,
        status,
        status_reasons,
        ${isXdp} AS is_xdp,
        ${colExpr(cols, 'lag_segments', 'toInt64(0)')} AS lag_segments,
        lagInFrame(ts, 1, ${EPOCH}) OVER g AS prev_ts,
        lagInFrame(ts, 1, ${EPOCH}) OVER p AS p_prev_ts,
        ${lagCols}
      FROM ${table}
      WHERE source_id = {source_id:String}
        AND ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC') - INTERVAL ${LOOKBACK_MINUTES} MINUTE
        AND ts <  fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
      WINDOW g AS (ORDER BY ts ROWS BETWEEN 1 PRECEDING AND CURRENT ROW),
             p AS (PARTITION BY collector_id ORDER BY ts ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)
    ),
    d AS (
      SELECT
        ts,
        status,
        status_reasons,
        is_xdp,
        lag_segments,
        prev_ts,
        p_prev_ts != ${EPOCH} AS has_base,
        ${deltaCols},
        has_base AND (${restarted}) AS restarted,
        if(is_xdp, xdp_total_packets_d, datagrams_d) AS input_d,
        records_acked_d + records_written_d AS written_d,
        ${LOST_COUNTERS.map((c) => `${c}_d`).join(' + ')} AS lost_d,
        if(prev_ts = ${EPOCH}, 0, dateDiff('millisecond', prev_ts, ts) / 1000) AS gap_sec,
        gap_sec > {gap_sec:UInt32} AS is_gap,
        is_gap AND NOT restarted AND input_d > 0 AS alive,
        is_gap AND alive AND gap_sec < {late_sec:UInt32} AS late,
        NOT is_gap AND has_base AND input_d = 0 AS no_input,
        hasAny(status_reasons, ${sqlList(WRITE_BLOCK_REASONS)}) AS write_blocked,
        hasAny(status_reasons, ${sqlList(DATA_LOSS_REASONS)}) AS lossy,
        (is_gap AND NOT late) OR no_input OR write_blocked OR lossy AS data_bad,
        NOT data_bad AND (status != 'ok' OR late) AS other_bad
      FROM snaps
      WHERE ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
    )`;
}

function bucketsSql(table, cols = null) {
  return `
    WITH ${deltaSnapsSql(table, cols)}
    SELECT
      toUnixTimestamp(toDateTime(toStartOfInterval(ts, INTERVAL {bucket_sec:UInt32} SECOND))) AS bucket,
      count() AS n,
      countIf(data_bad AND NOT is_gap) AS data_bad_n,
      countIf(other_bad) AS other_n,
      countIf(no_input) AS no_input_n,
      sum(input_d) AS input,
      sum(written_d) AS written,
      sum(xdp_total_packets_d) AS seen,
      sum(phy_rx_packets_d) AS phy,
      sum(phy_rx_discards_d) AS phy_discards,
      sum(xdp_non_ip_pass_d) AS non_ip,
      sum(flow_packets_acked_d) AS acked,
      sum(flow_packets_excluded_d) AS excluded,
      sum(nf_records_out_d) AS nf_records,
      sum(records_spooled_d) AS records_spooled,
      sum(lost_d) AS lost,
      sum(insert_errs_d) AS insert_errs,
      ${LOSS_COUNTERS.map((c) => `sum(${c}_d) AS ${c}`).join(',\n      ')},
      max(lag_segments) AS lag_max,
      groupUniqArrayArray(status_reasons) AS reasons
    FROM d
    GROUP BY bucket
    ORDER BY bucket
  `;
}

/**
 * Data incidents, merged in ClickHouse: a long outage is thousands of minutes,
 * too many rows to ship. A snapshot describes the minute ending at its ts; a
 * gap row describes the silence since the previous snapshot.
 */
function runsSql(table, cols = null) {
  return `
    WITH ${deltaSnapsSql(table, cols)},
    p AS (
      SELECT
        multiIf(is_gap AND NOT late, 'gap', no_input, 'no_input', write_blocked, 'write_blocked', lossy, 'loss', '') AS cat,
        if(cat = 'gap', toUnixTimestamp64Milli(prev_ts), toUnixTimestamp64Milli(ts) - 60000) AS start_ms,
        toUnixTimestamp64Milli(ts) AS end_ms,
        multiIf(
          cat = 'loss', arrayFilter(x -> has(${sqlList(DATA_LOSS_REASONS)}, x), status_reasons),
          cat = 'write_blocked', ${sqlList(WRITE_BLOCK_REASONS)},
          [cat]
        ) AS codes,
        alive,
        input_d,
        written_d,
        lost_d
      FROM d
      WHERE data_bad
    ),
    marked AS (
      SELECT
        *,
        start_ms - lagInFrame(end_ms, 1, toInt64(0)) OVER w > {merge_ms:UInt32} AS is_new
      FROM p
      WINDOW w AS (PARTITION BY cat ORDER BY start_ms ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)
    ),
    runs AS (
      SELECT
        *,
        sum(toUInt32(is_new)) OVER (PARTITION BY cat ORDER BY start_ms ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS run
      FROM marked
    )
    SELECT
      cat,
      min(start_ms) AS start_ms,
      max(end_ms) AS end_ms,
      max(alive) AS alive,
      groupUniqArrayArray(codes) AS codes,
      sum(input_d) AS input,
      sum(written_d) AS written,
      sum(lost_d) AS lost
    FROM runs
    GROUP BY cat, run
    ORDER BY start_ms
    LIMIT {run_limit:UInt32}
  `;
}

/** Everything that did not stop data collection, one line per kind. */
function otherEventsSql(table, cols = null) {
  return `
    WITH ${deltaSnapsSql(table, cols)}
    SELECT
      code,
      count() AS n,
      toUnixTimestamp64Milli(max(ts)) AS last_ms
    FROM d
    ARRAY JOIN arrayConcat(
      arrayFilter(x -> NOT has(${sqlList(DATA_REASONS)}, x), status_reasons),
      if(restarted, ['restart'], []),
      if(late, ['late_snapshot'], [])
    ) AS code
    GROUP BY code
    ORDER BY n DESC
  `;
}

function boundsSql(table, cols = null) {
  const stages = !cols || cols.has('pipeline_stages')
    ? 'argMax(pipeline_stages, ts)'
    : "if(argMax(daemon, ts) = 'xdpflowd', ['collector'], emptyArrayString())";
  return `
    SELECT
      toUnixTimestamp64Milli(min(ts)) AS first_ms,
      toUnixTimestamp64Milli(max(ts)) AS last_ms,
      toUnixTimestamp64Milli(maxIf(ts, ts < fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC'))) AS prior_ms,
      toUnixTimestamp64Milli(minIf(ts, ts >= fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC'))) AS next_ms,
      toUnixTimestamp64Milli(minIf(ts, ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
        AND ts < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC'))) AS first_in_ms,
      toUnixTimestamp64Milli(maxIf(ts, ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
        AND ts < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC'))) AS last_in_ms,
      argMax(daemon, ts) AS last_daemon,
      ${stages} AS last_stages,
      argMax(status_reasons, ts) AS last_reasons
    FROM ${table}
    WHERE source_id = {source_id:String}
  `;
}

function mapBounds(row) {
  const r = row || {};
  return {
    firstMs: msOrNull(r.first_ms),
    lastMs: msOrNull(r.last_ms),
    priorMs: msOrNull(r.prior_ms),
    nextMs: msOrNull(r.next_ms),
    firstInMs: msOrNull(r.first_in_ms),
    lastInMs: msOrNull(r.last_in_ms),
    daemon: String(r.last_daemon || ''),
    stages: parseReasons(r.last_stages),
    isXdp: parseReasons(r.last_stages).includes('collector'),
    lastReasons: parseReasons(r.last_reasons),
  };
}

/** Runs from ClickHouse plus silences at the range edges that no snapshot row can describe. */
function problemIntervals(runRows, bounds, range, nowMs) {
  const intervals = [];
  const clip = (start, end) => [Math.max(start, range.fromMs), Math.min(end, range.toMs)];

  for (const row of runRows) {
    const [start, end] = clip(num(row.start_ms), num(row.end_ms));
    if (end <= start) continue;
    intervals.push({
      category: String(row.cat),
      start,
      end,
      codes: new Set(parseReasons(row.codes)),
      input: num(row.input),
      written: num(row.written),
      lost: num(row.lost),
      // counters grew across the silence: the collector was alive, only the snapshots were lost
      aliveDuringGap: Number(row.alive) === 1 || row.alive === true,
    });
  }

  const gapAt = (start, end) => {
    const [s, e] = clip(start, end);
    if (e - s > GAP_SEC * 1000) {
      intervals.push({
        category: 'gap', start: s, end: e, codes: new Set(['gap']), input: 0, written: 0, lost: 0, aliveDuringGap: false,
      });
    }
  };

  const liveEnd = Math.min(range.toMs, nowMs);
  if (bounds.firstInMs == null) {
    if (bounds.priorMs != null) gapAt(range.fromMs, bounds.nextMs ?? liveEnd);
  } else {
    if (bounds.priorMs != null) gapAt(bounds.priorMs, bounds.firstInMs);
    gapAt(bounds.lastInMs, bounds.nextMs ?? liveEnd);
  }

  return intervals.sort((a, b) => a.start - b.start);
}

/** Merges only problems of one kind so each incident has one clear cause. */
function mergeIncidents(intervals, nowMs) {
  const lastByCategory = new Map();
  const merged = [];
  for (const iv of intervals) {
    const last = lastByCategory.get(iv.category);
    if (last && iv.start - last.end <= MERGE_GAP_MS) {
      last.end = Math.max(last.end, iv.end);
      iv.codes.forEach((c) => last.codes.add(c));
      last.input += iv.input;
      last.written += iv.written;
      last.lost += iv.lost;
      if (iv.aliveDuringGap) last.aliveDuringGap = true;
      continue;
    }
    const inc = { ...iv, codes: new Set(iv.codes) };
    lastByCategory.set(iv.category, inc);
    merged.push(inc);
  }

  return merged
    .sort((a, b) => a.start - b.start)
    .map((inc) => {
      const info = CATEGORY_INFO[inc.category] || CATEGORY_INFO.loss;
      const alive = inc.category === 'gap' && inc.aliveDuringGap;
      return {
        category: inc.category,
        severity: info.severity,
        title: alive ? 'ClickHouse был недоступен' : info.label,
        hint: alive ? 'коллектор работал, данные ждали в буфере и дошлются позже' : info.hint,
        details: inc.category === 'loss' ? [...inc.codes].map(reasonInfo) : [],
        startMs: inc.start,
        endMs: inc.end,
        durationSec: Math.round((inc.end - inc.start) / 1000),
        ongoing: nowMs - inc.end <= GAP_SEC * 1000,
        input: inc.input,
        written: inc.written,
        lost: inc.lost,
        aliveDuringGap: alive,
      };
    });
}

/**
 * Overlapping or adjacent incidents of different kinds are one outage for the
 * reader: "ClickHouse was down" and "writes were rejected" at 04:17 and 04:36
 * are the same story. The longest cause names it, the rest are listed.
 */
function clusterIncidents(incidents) {
  const clusters = [];
  for (const inc of [...incidents].sort((a, b) => a.startMs - b.startMs)) {
    const cur = clusters[clusters.length - 1];
    if (cur && inc.startMs - cur.endMs <= MERGE_GAP_MS) {
      cur.endMs = Math.max(cur.endMs, inc.endMs);
      cur.parts.push(inc);
    } else {
      clusters.push({ startMs: inc.startMs, endMs: inc.endMs, parts: [inc] });
    }
  }

  return clusters.map((c) => {
    const causes = new Map();
    for (const p of c.parts) {
      const cur = causes.get(p.title) || { title: p.title, hint: p.hint, severity: p.severity, durationSec: 0, details: [] };
      cur.durationSec += p.durationSec;
      for (const d of p.details) if (!cur.details.some((x) => x.code === d.code)) cur.details.push(d);
      causes.set(p.title, cur);
    }
    const ordered = [...causes.values()].sort((a, b) => b.durationSec - a.durationSec);
    const main = ordered[0];
    const sum = (key) => c.parts.reduce((acc, p) => acc + p[key], 0);
    return {
      severity: main.severity,
      title: main.title,
      hint: main.hint,
      details: main.details,
      alsoCauses: ordered.slice(1).map(({ title, durationSec }) => ({ title, durationSec })),
      startMs: c.startMs,
      endMs: c.endMs,
      durationSec: Math.round((c.endMs - c.startMs) / 1000),
      ongoing: c.parts.some((p) => p.ongoing),
      input: sum('input'),
      written: sum('written'),
      lost: sum('lost'),
      aliveDuringGap: c.parts.some((p) => p.aliveDuringGap),
    };
  });
}

/**
 * ClickHouse confirms packets in batches: a 10-minute cell swings 97–103% while
 * the hour holds 99.1–100.7% (mirror, netflow). The chart uses a trailing hour.
 */
const COMPLETENESS_SMOOTH_SEC = 3600;

/** Same formula as the collectors table: accounted packets over IP packets the collector saw. */
function completenessPct(seen, nonIp, acked, excluded) {
  const denominator = seen - nonIp;
  if (!(denominator > 0)) return null;
  return Number(Math.min(100, ((acked + excluded) / denominator) * 100).toFixed(2));
}

/** Share of part in whole, capped at 100%: counters of adjacent stages are read at slightly different instants. */
function sharePct(part, whole, digits = 2) {
  if (!(whole > 0)) return null;
  return Number(Math.min(100, (part / whole) * 100).toFixed(digits));
}

function overlapMs(aStart, aEnd, bStart, bEnd) {
  return Math.max(0, Math.min(aEnd, bEnd) - Math.max(aStart, bStart));
}

function buildBuckets(bucketRows, incidents, range, bounds, bucketSec, nowMs) {
  const byStart = new Map(bucketRows.map((r) => [num(r.bucket) * 1000, r]));
  const bucketMs = bucketSec * 1000;
  const first = Math.floor(range.fromMs / bucketMs) * bucketMs;
  const downs = incidents.filter((i) => i.category === 'gap');
  const smoothCells = Math.max(1, Math.round(COMPLETENESS_SMOOTH_SEC / bucketSec));
  const trail = [];
  const out = [];

  for (let start = first; start < range.toMs; start += bucketMs) {
    const end = start + bucketMs;
    const row = byStart.get(start);
    const visibleEnd = Math.min(end, range.toMs, nowMs);
    const before = bounds.firstMs == null || visibleEnd <= bounds.firstMs;
    const downMs = downs.reduce((acc, i) => acc + overlapMs(start, end, i.startMs, i.endMs), 0);
    const spanMs = Math.max(1, visibleEnd - Math.max(start, range.fromMs));

    let state = 'ok';
    if (before) state = 'none';
    else if (!row || downMs >= spanMs / 2) state = 'down';
    else if (num(row.data_bad_n) > 0 || downMs > 0) state = 'critical';
    else if (num(row.other_n) > 0) state = 'warning';

    trail.push(row || null);
    if (trail.length > smoothCells) trail.shift();
    const win = trail.filter(Boolean);
    const wsum = (key) => win.reduce((acc, r) => acc + num(r[key]), 0);

    const reasons = row ? parseReasons(row.reasons) : [];
    if (row && num(row.no_input_n) > 0) reasons.push('no_input');
    if (downMs > 0) reasons.push('gap');

    out.push({
      startMs: start,
      endMs: end,
      state,
      downMinutes: Math.round(downMs / 60000),
      phy: row ? num(row.phy) : null,
      seen: row ? num(row.seen) : null,
      acked: row ? num(row.acked) : null,
      nfRecords: row ? num(row.nf_records) : null,
      input: row ? num(row.input) : null,
      written: row ? num(row.written) : null,
      phyDiscards: row ? num(row.phy_discards) : null,
      completenessPct: row ? completenessPct(wsum('seen'), wsum('non_ip'), wsum('acked'), wsum('excluded')) : null,
      lagSegmentsMax: row ? num(row.lag_max) : null,
      reasons: [...new Set(reasons)].map(reasonInfo),
    });
  }
  return out;
}

function unionMs(incidents) {
  let total = 0;
  let curStart = null;
  let curEnd = null;
  for (const inc of [...incidents].sort((a, b) => a.startMs - b.startMs)) {
    if (curEnd == null || inc.startMs > curEnd) {
      if (curEnd != null) total += curEnd - curStart;
      curStart = inc.startMs;
      curEnd = inc.endMs;
    } else {
      curEnd = Math.max(curEnd, inc.endMs);
    }
  }
  if (curEnd != null) total += curEnd - curStart;
  return total;
}

function buildOtherEvents(otherRows, shortIncidents) {
  const events = otherRows.map((r) => ({
    ...reasonInfo(String(r.code)),
    unit: r.code === 'restart' || r.code === 'late_snapshot' ? 'times' : 'minutes',
    count: num(r.n),
    lastMs: msOrNull(r.last_ms),
  }));
  const shortByTitle = new Map();
  for (const inc of shortIncidents) {
    const cur = shortByTitle.get(inc.title) || { count: 0, lastMs: 0, title: inc.title };
    cur.count += 1;
    cur.lastMs = Math.max(cur.lastMs, inc.endMs);
    shortByTitle.set(inc.title, cur);
  }
  for (const [title, v] of shortByTitle) {
    events.push({
      code: `short_${title}`,
      label: `Короткие сбои: ${v.title.toLowerCase()}`,
      hint: 'меньше 5 минут',
      unit: 'times',
      count: v.count,
      lastMs: v.lastMs,
    });
  }
  return events.sort((a, b) => (b.lastMs || 0) - (a.lastMs || 0));
}

function buildCurrent(incidents, bounds, nowMs) {
  const otherNow = bounds.lastReasons.filter((c) => !DATA_REASONS.includes(c)).map(reasonInfo);
  if (!bounds.lastMs) return { state: 'none', otherNow };
  if (nowMs - bounds.lastMs > GAP_SEC * 1000) return { state: 'gap', sinceMs: bounds.lastMs, otherNow };
  const ongoing = incidents.filter((i) => i.ongoing);
  for (const category of CATEGORY_ORDER) {
    const inc = ongoing.find((i) => i.category === category);
    if (inc) return { state: category, sinceMs: inc.startMs, title: inc.title, hint: inc.hint, otherNow };
  }
  return { state: 'ok', lastSnapshotMs: bounds.lastMs, otherNow };
}

function buildSummary(bucketRows, incidents, visible, range, bounds, nowMs) {
  const observedStart = Math.max(range.fromMs, bounds.firstMs ?? range.toMs);
  const observedMs = Math.max(0, Math.min(range.toMs, nowMs) - observedStart);
  const badMs = Math.min(observedMs, unionMs(incidents));
  const sum = (key) => bucketRows.reduce((acc, r) => acc + num(r[key]), 0);
  const losses = {};
  for (const key of LOSS_COUNTERS) losses[key] = sum(key);
  const longest = visible.reduce((best, i) => (!best || i.durationSec > best.durationSec ? i : best), null);

  return {
    observedSec: Math.round(observedMs / 1000),
    collectedPct: observedMs > 0 ? Number((100 - (badMs / observedMs) * 100).toFixed(2)) : null,
    badSec: Math.round(badMs / 1000),
    incidentCount: visible.length,
    longest: longest ? { startMs: longest.startMs, durationSec: longest.durationSec, title: longest.title } : null,
    input: sum('input'),
    written: sum('written'),
    phy: sum('phy'),
    phyDiscards: sum('phy_discards'),
    phyDiscardPct: sharePct(sum('phy_discards'), sum('phy'), 4),
    seen: sum('seen'),
    seenPctOfPhy: sharePct(sum('seen'), sum('phy')),
    acked: sum('acked'),
    nfRecords: sum('nf_records'),
    flowRecords: sum('records_spooled'),
    nfPctOfFlows: sharePct(sum('nf_records'), sum('records_spooled')),
    completenessPct: completenessPct(sum('seen'), sum('non_ip'), sum('acked'), sum('excluded')),
    lost: sum('lost'),
    insertErrs: sum('insert_errs'),
    losses,
    inputUnit: bounds.isXdp ? 'packets' : 'datagrams',
  };
}

function buildTimeline({ bucketRows, runRows, otherRows = [], boundsRow, range, bucketSec, nowMs }) {
  const bounds = mapBounds(boundsRow);
  const incidents = mergeIncidents(problemIntervals(runRows, bounds, range, nowMs), nowMs);
  const clusters = clusterIncidents(incidents);
  const isVisible = (i) => i.ongoing || i.durationSec * 1000 >= MIN_INCIDENT_MS;
  const visible = clusters.filter(isVisible);
  return {
    fromMs: range.fromMs,
    toMs: range.toMs,
    bucketSeconds: bucketSec,
    completenessSmoothSec: Math.max(COMPLETENESS_SMOOTH_SEC, bucketSec),
    retentionDays: RETENTION_DAYS,
    firstSnapshotMs: bounds.firstMs,
    lastSnapshotMs: bounds.lastMs,
    daemon: bounds.daemon,
    stages: bounds.stages,
    inputUnit: bounds.isXdp ? 'packets' : 'datagrams',
    current: buildCurrent(incidents, bounds, nowMs),
    buckets: buildBuckets(bucketRows, incidents, range, bounds, bucketSec, nowMs),
    incidents: visible.slice().reverse(),
    otherEvents: buildOtherEvents(otherRows, clusters.filter((i) => !isVisible(i))),
    truncated: runRows.length >= RUN_LIMIT,
    summary: buildSummary(bucketRows, incidents, visible, range, bounds, nowMs),
  };
}

async function fetchCollectorTimeline(sourceIdRaw, fromRaw, toRaw) {
  const sourceId = String(sourceIdRaw || '').trim();
  if (!sourceId) throw apiError('Укажите sourceId');
  const nowMs = Date.now();
  const range = parseRange(fromRaw, toRaw, nowMs);
  const bucketSec = chooseBucketSeconds(range.toMs - range.fromMs);
  const table = collectorHealthSnapshotsTableRef();
  const params = {
    source_id: sourceId,
    from_ms: range.fromMs,
    to_ms: range.toMs,
    bucket_sec: bucketSec,
    gap_sec: GAP_SEC,
    late_sec: LATE_SNAPSHOT_SEC,
    merge_ms: MERGE_GAP_MS,
    run_limit: RUN_LIMIT,
  };

  const cols = await snapshotColumns();
  const [buckets, runs, bounds] = await Promise.all([
    query(bucketsSql(table, cols), params, { name: 'collectors/timeline/buckets' }),
    query(runsSql(table, cols), params, { name: 'collectors/timeline/runs' }),
    query(boundsSql(table, cols), params, { name: 'collectors/timeline/bounds' }),
  ]);

  return {
    sourceId,
    ...buildTimeline({
      bucketRows: buckets.rows,
      runRows: runs.rows,
      boundsRow: bounds.rows[0],
      range,
      bucketSec,
      nowMs,
    }),
    meta: { elapsedMs: Math.max(...[buckets, runs, bounds].map((r) => r.elapsedMs || 0)) },
  };
}

module.exports = {
  REASONS,
  GAP_SEC,
  LATE_SNAPSHOT_SEC,
  MERGE_GAP_MS,
  RUN_LIMIT,
  parseRange,
  chooseBucketSeconds,
  problemIntervals,
  mergeIncidents,
  clusterIncidents,
  buildBuckets,
  buildTimeline,
  fetchCollectorTimeline,
  bucketsSql,
  runsSql,
  otherEventsSql,
  boundsSql,
};
