'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  moscowWallToMs,
  parseReplayRange,
  replayMinuteChunks,
  replayShiftSec,
  replayInsertSql,
  createReplayController,
} = require('./traffic-replay');

describe('traffic replay window', () => {
  it('reads a naive clock as Moscow', () => {
    assert.equal(moscowWallToMs('2026-10-04 18:41:00'), Date.parse('2026-10-04T15:41:00Z'));
    assert.equal(moscowWallToMs('2026-10-04T18:41'), Date.parse('2026-10-04T15:41:00Z'));
  });

  it('rejects an empty, inverted, or too long period', () => {
    assert.throws(() => parseReplayRange('', '2026-10-04 19:00:00'), /начало и конец/);
    assert.throws(() => parseReplayRange('2026-10-04 19:00:00', '2026-10-04 18:00:00'), /позже/);
    assert.throws(() => parseReplayRange('2026-10-04 12:00:00', '2026-10-04 18:00:01'), /6 часов/);
  });

  it('splits the period into source minutes', () => {
    const from = moscowWallToMs('2026-10-04 18:41:00');
    const to = moscowWallToMs('2026-10-04 18:43:30');
    const chunks = replayMinuteChunks(from, to);
    assert.equal(chunks.length, 3);
    assert.equal(chunks[0].fromMs, from);
    assert.equal(chunks[0].toMs - chunks[0].fromMs, 60000);
    assert.equal(chunks[2].toMs, to);
    assert.equal(chunks[2].toMs - chunks[2].fromMs, 30000);
  });

  it('shifts by whole minutes so a source minute stays one wall minute', () => {
    const from = moscowWallToMs('2026-10-04 18:50:00');
    const shift = replayShiftSec(from, Date.parse('2026-10-05T04:13:54Z'));
    assert.equal(shift % 60, 0);
    assert.equal(new Date(from + shift * 1000).toISOString(), '2026-10-05T04:14:00.000Z');
    assert.equal(replayShiftSec(from, Date.parse('2026-10-05T04:14:00Z')) % 60, 0);
  });

  it('shifts receive time and keeps the rest of the row', () => {
    const sql = replayInsertSql('`default`.`flows_raw`');
    assert.match(sql, /INSERT INTO `default`\.`flows_raw`/);
    assert.match(sql, /addSeconds\(time_received_ns, \{shift:Int64\}\)/);
    assert.match(sql, /addSeconds\(time_flow_start_ns, \{shift:Int64\}\)/);
    assert.match(sql, /toDate\(addSeconds\(time_received_ns/);
    assert.doesNotMatch(sql, /isIPAddressInRange/);
  });
});

describe('traffic replay controller', () => {
  it('copies each minute and then finishes', async () => {
    const inserted = [];
    const replay = createReplayController({
      now: () => Date.parse('2026-10-05T04:00:00Z'),
      waitUntil: async (_target, shouldStop) => !shouldStop(),
      countRows: async () => 10,
      insertChunk: async (_job, chunk) => { inserted.push(chunk.fromMs); },
    });
    const started = replay.start('2026-10-04 18:41:00', '2026-10-04 18:43:00');
    assert.equal(started.status, 'running');
    assert.equal(started.totalSteps, 2);
    await waitStatus(replay, 'done');
    assert.equal(inserted.length, 2);
    const done = replay.status();
    assert.equal(done.copiedSteps, 2);
    assert.equal(done.sourceRows, 10);
    assert.equal(
      done.shiftSec,
      Math.round((Date.parse('2026-10-05T04:00:00Z') - Date.parse('2026-10-04T15:41:00Z')) / 1000),
    );
  });

  it('stops between minutes and keeps what was already copied', async () => {
    const replay = createReplayController({
      now: () => Date.parse('2026-10-05T04:00:00Z'),
      waitUntil: async (_target, shouldStop) => !shouldStop(),
      countRows: async () => 4,
      insertChunk: async () => { replay.stop(); },
    });
    replay.start('2026-10-04 18:41:00', '2026-10-04 18:44:00');
    await waitStatus(replay, 'stopped');
    assert.equal(replay.status().copiedSteps, 1);
    assert.equal(replay.status().totalSteps, 3);
  });

  it('refuses a second run while the first is still copying', async () => {
    let release;
    const replay = createReplayController({
      now: () => Date.parse('2026-10-05T04:00:00Z'),
      waitUntil: async () => true,
      countRows: () => new Promise((resolve) => { release = () => resolve(1); }),
      insertChunk: async () => {},
    });
    replay.start('2026-10-04 18:41:00', '2026-10-04 18:42:00');
    assert.throws(
      () => replay.start('2026-10-04 18:41:00', '2026-10-04 18:42:00'),
      (err) => err.status === 409,
    );
    release();
    await waitStatus(replay, 'done');
  });

  it('stops with an error when the period has no flows', async () => {
    const replay = createReplayController({
      now: () => Date.parse('2026-10-05T04:00:00Z'),
      countRows: async () => 0,
      insertChunk: async () => { throw new Error('should not insert'); },
    });
    replay.start('2026-10-04 18:41:00', '2026-10-04 18:42:00');
    await waitStatus(replay, 'error');
    assert.match(replay.status().error, /нет потоков/);
  });
});

async function waitStatus(replay, status) {
  for (let i = 0; i < 20; i += 1) {
    if (replay.status().status === status) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(replay.status().status, status);
}
