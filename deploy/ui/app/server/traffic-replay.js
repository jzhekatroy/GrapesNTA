'use strict';

// Прогон сырых потоков: копия выбранного периода пишется в flows_raw так,
// будто эти минуты наступают сейчас. Темп тот же, что у оригинала: минута
// источника занимает минуту на часах. Детектор и коллектор здесь не
// останавливаются — их глушит тот, кто запускает прогон.

const { query, executeCommand, flowsRawWriteTableRef, config } = require('./clickhouse');

const MAX_REPLAY_MS = 6 * 60 * 60 * 1000;
const TZ = 'Europe/Moscow';

function replayError(message, status = 400) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function wallOf(ms, timeZone = TZ) {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = Object.fromEntries(fmt.formatToParts(new Date(ms)).map((p) => [p.type, p.value]));
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}

function moscowWallToMs(input, timeZone = TZ) {
  const raw = String(input || '').trim();
  if (!raw) throw replayError('Укажите начало и конец периода');
  if (/[zZ]|[+-]\d{2}:?\d{2}$/.test(raw)) {
    const ms = Date.parse(raw);
    if (!Number.isFinite(ms)) throw replayError('Некорректное время');
    return ms;
  }
  const normalized = raw.replace('T', ' ').replace(/\.\d+$/, '');
  const match = normalized.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2})(?::(\d{2}))?$/);
  if (!match) throw replayError('Некорректное время');
  const wall = `${match[1]} ${match[2]}:${match[3] || '00'}`;
  let ms = Date.parse(`${wall.replace(' ', 'T')}Z`);
  for (let i = 0; i < 4; i += 1) {
    const got = wallOf(ms, timeZone);
    const delta = Date.parse(`${wall.replace(' ', 'T')}Z`) - Date.parse(`${got.replace(' ', 'T')}Z`);
    if (delta === 0) break;
    ms += delta;
  }
  if (wallOf(ms, timeZone) !== wall) throw replayError('Некорректное время');
  return ms;
}

function parseReplayRange(from, to) {
  const fromMs = moscowWallToMs(from);
  const toMs = moscowWallToMs(to);
  if (!(toMs > fromMs)) throw replayError('Конец периода должен быть позже начала');
  if (toMs - fromMs > MAX_REPLAY_MS) {
    throw replayError('Период не длиннее 6 часов');
  }
  return {
    fromMs,
    toMs,
    from: wallOf(fromMs),
    to: wallOf(toMs),
  };
}

function replayMinuteChunks(fromMs, toMs) {
  const chunks = [];
  let cursor = fromMs;
  while (cursor < toMs) {
    const minuteEnd = Math.floor(cursor / 60000) * 60000 + 60000;
    const next = Math.min(toMs, minuteEnd);
    chunks.push({ fromMs: cursor, toMs: next });
    cursor = next;
  }
  return chunks;
}

// Экспортёр сбрасывает потоки пачкой в начале минуты. Сдвиг не на целые
// минуты переносит эту пачку в соседнюю минуту (прогон 05.10: импульс 18:54
// лёг в 07:17 вместо 07:18), поэтому старт ждёт ближайшей границы минуты.
function replayShiftSec(fromMs, nowMs) {
  const sec = Math.ceil((nowMs - fromMs) / 1000);
  return Math.ceil(sec / 60) * 60;
}

function replayInsertSql(table) {
  return `
    INSERT INTO ${table}
    SELECT * REPLACE (
      toDate(addSeconds(time_received_ns, {shift:Int64})) AS date,
      addSeconds(time_inserted_ns, {shift:Int64}) AS time_inserted_ns,
      addSeconds(time_received_ns, {shift:Int64}) AS time_received_ns,
      addSeconds(time_flow_start_ns, {shift:Int64}) AS time_flow_start_ns
    )
    FROM ${table}
    WHERE date >= toDate({srcFrom:String}) - 1
      AND date <= toDate({srcTo:String}) + 1
      AND time_received_ns >= toDateTime({chunkFrom:String}, {tz:String})
      AND time_received_ns < toDateTime({chunkTo:String}, {tz:String})
    SETTINGS max_execution_time = 180
  `;
}

function snapshot(job) {
  if (!job) {
    return { status: 'idle' };
  }
  return {
    status: job.status,
    from: job.from,
    to: job.to,
    shiftSec: job.shiftSec,
    sourceRows: job.sourceRows,
    copiedSteps: job.copiedSteps,
    totalSteps: job.totalSteps,
    cursorFrom: job.cursorFrom ? wallOf(job.cursorFrom) : null,
    cursorTo: job.cursorTo ? wallOf(job.cursorTo) : null,
    stopping: job.status === 'running' && job.stopRequested,
    playingFrom: job.cursorFrom != null && job.shiftSec != null
      ? wallOf(job.cursorFrom + job.shiftSec * 1000)
      : null,
    error: job.error,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
  };
}

function createReplayController(deps = {}) {
  const now = deps.now || (() => Date.now());
  const waitUntil = deps.waitUntil || defaultWaitUntil;
  const countRows = deps.countRows || defaultCountRows;
  const insertChunk = deps.insertChunk || defaultInsertChunk;
  let job = null;

  async function run(current) {
    try {
      current.sourceRows = await countRows(current);
      if (current.stopRequested) {
        finish(current, 'stopped');
        return;
      }
      if (!current.sourceRows) {
        current.error = 'В этом периоде нет потоков';
        finish(current, 'error');
        return;
      }
      current.shiftSec = replayShiftSec(current.fromMs, now());
      current.phase = 'playing';
      for (const chunk of current.chunks) {
        if (current.stopRequested) {
          finish(current, 'stopped');
          return;
        }
        const target = chunk.fromMs + current.shiftSec * 1000;
        const proceed = await waitUntil(target, () => current.stopRequested);
        if (!proceed) {
          finish(current, 'stopped');
          return;
        }
        current.cursorFrom = chunk.fromMs;
        current.cursorTo = chunk.toMs;
        await insertChunk(current, chunk);
        current.copiedSteps += 1;
      }
      finish(current, 'done');
    } catch (err) {
      current.error = err?.message || String(err);
      finish(current, 'error');
    }
  }

  function finish(current, status) {
    current.status = status;
    current.finishedAt = new Date(now()).toISOString();
  }

  function start(from, to) {
    if (job && job.status === 'running') {
      throw replayError('Повтор уже идёт', 409);
    }
    const range = parseReplayRange(from, to);
    const chunks = replayMinuteChunks(range.fromMs, range.toMs);
    job = {
      status: 'running',
      phase: 'counting',
      stopRequested: false,
      ...range,
      chunks,
      shiftSec: null,
      sourceRows: null,
      copiedSteps: 0,
      totalSteps: chunks.length,
      cursorFrom: null,
      cursorTo: null,
      error: null,
      startedAt: new Date(now()).toISOString(),
      finishedAt: null,
    };
    run(job);
    return snapshot(job);
  }

  function stop() {
    if (!job || job.status !== 'running') return snapshot(job);
    job.stopRequested = true;
    return snapshot(job);
  }

  function status() {
    return snapshot(job);
  }

  return { start, stop, status };
}

async function defaultWaitUntil(targetMs, shouldStop) {
  while (Date.now() + 200 < targetMs) {
    if (shouldStop()) return false;
    const left = targetMs - Date.now();
    await new Promise((resolve) => setTimeout(resolve, Math.min(1000, Math.max(left, 0))));
  }
  return !shouldStop();
}

async function defaultCountRows(job) {
  const table = flowsRawWriteTableRef();
  const { rows } = await query(`
    SELECT count() AS n
    FROM ${table}
    WHERE date >= toDate({srcFrom:String}) - 1
      AND date <= toDate({srcTo:String}) + 1
      AND time_received_ns >= toDateTime({srcFrom:String}, {tz:String})
      AND time_received_ns < toDateTime({srcTo:String}, {tz:String})
  `, {
    srcFrom: job.from,
    srcTo: job.to,
    tz: config.dataTimezone || TZ,
  }, {
    name: 'diagnostics/traffic-replay-count',
    requestTimeoutMs: 120000,
    clickhouse_settings: { max_execution_time: 90 },
  });
  return Number(rows[0]?.n) || 0;
}

async function defaultInsertChunk(job, chunk) {
  const tz = config.dataTimezone || TZ;
  await executeCommand(replayInsertSql(flowsRawWriteTableRef()), {
    shift: job.shiftSec,
    srcFrom: job.from,
    srcTo: job.to,
    chunkFrom: wallOf(chunk.fromMs, tz),
    chunkTo: wallOf(chunk.toMs, tz),
    tz,
  }, { name: 'diagnostics/traffic-replay-insert' });
}

const controller = createReplayController();

module.exports = {
  MAX_REPLAY_MS,
  moscowWallToMs,
  parseReplayRange,
  replayMinuteChunks,
  replayShiftSec,
  replayInsertSql,
  createReplayController,
  startTrafficReplay: (from, to) => controller.start(from, to),
  stopTrafficReplay: () => controller.stop(),
  trafficReplayStatus: () => controller.status(),
};
