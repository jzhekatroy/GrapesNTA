'use strict';

const { query, executeCommand, insertRows, config } = require('./clickhouse');

const SETTINGS_TABLE = 'collector_pipeline_thresholds';
const SETTINGS_VIEW = 'collector_pipeline_thresholds_current';
const SETTINGS_ID = 'global';

const DEFAULT_THRESHOLDS = {
  interface: { warnPct: 0.01, critPct: 0.1 },
  collector: { warnPct: 0.01, critPct: 0.1 },
  receiver: { warnPct: 0.01, critPct: 0.1 },
  spool: { warnAny: true },
  clickhouse: { warnAny: true },
  netflow: { warnAny: true },
  socket: { warnPct: 0.1, critPct: 1.0 },
};

const DEFAULT_ROW = {
  interface_warn_pct: 0.01,
  interface_crit_pct: 0.1,
  collector_warn_pct: 0.01,
  collector_crit_pct: 0.1,
  receiver_warn_pct: 0.01,
  receiver_crit_pct: 0.1,
  socket_warn_pct: 0.1,
  socket_crit_pct: 1.0,
};

let ensurePromise = null;

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function settingsTableRef() {
  return `${config.database}.${SETTINGS_TABLE}`;
}

function settingsViewRef() {
  return `${config.database}.${SETTINGS_VIEW}`;
}

function boundedFloat(value, fallback, min, max, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || n > max) {
    throw apiError(`${label}: ожидается число от ${min} до ${max}`);
  }
  return n;
}

function mapThresholdsRow(row = {}) {
  return {
    interface: {
      warnPct: Number(row.interface_warn_pct ?? DEFAULT_ROW.interface_warn_pct),
      critPct: Number(row.interface_crit_pct ?? DEFAULT_ROW.interface_crit_pct),
    },
    collector: {
      warnPct: Number(row.collector_warn_pct ?? DEFAULT_ROW.collector_warn_pct),
      critPct: Number(row.collector_crit_pct ?? DEFAULT_ROW.collector_crit_pct),
    },
    receiver: {
      warnPct: Number(row.receiver_warn_pct ?? DEFAULT_ROW.receiver_warn_pct),
      critPct: Number(row.receiver_crit_pct ?? DEFAULT_ROW.receiver_crit_pct),
    },
    spool: { warnAny: true },
    clickhouse: { warnAny: true },
    netflow: { warnAny: true },
    socket: {
      warnPct: Number(row.socket_warn_pct ?? DEFAULT_ROW.socket_warn_pct),
      critPct: Number(row.socket_crit_pct ?? DEFAULT_ROW.socket_crit_pct),
    },
  };
}

function mapThresholdsForApi(row = {}) {
  const t = mapThresholdsRow(row);
  return {
    interfaceWarnPct: t.interface.warnPct,
    interfaceCritPct: t.interface.critPct,
    collectorWarnPct: t.collector.warnPct,
    collectorCritPct: t.collector.critPct,
    receiverWarnPct: t.receiver.warnPct,
    receiverCritPct: t.receiver.critPct,
    socketWarnPct: t.socket.warnPct,
    socketCritPct: t.socket.critPct,
    updatedAt: row.updated_at ?? null,
  };
}

async function ensurePipelineThresholdsTables() {
  if (!ensurePromise) {
    ensurePromise = (async () => {
      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${settingsTableRef()}
        (
          settings_id String DEFAULT 'global',
          interface_warn_pct Float64 DEFAULT 0.01,
          interface_crit_pct Float64 DEFAULT 0.1,
          collector_warn_pct Float64 DEFAULT 0.01,
          collector_crit_pct Float64 DEFAULT 0.1,
          receiver_warn_pct Float64 DEFAULT 0.01,
          receiver_crit_pct Float64 DEFAULT 0.1,
          socket_warn_pct Float64 DEFAULT 0.1,
          socket_crit_pct Float64 DEFAULT 1.0,
          updated_at DateTime('UTC') DEFAULT now()
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY settings_id
        SETTINGS index_granularity = 8192
      `, {}, { name: 'pipeline-thresholds/ensure-table' });

      await executeCommand(`
        CREATE VIEW IF NOT EXISTS ${settingsViewRef()}
        (
          settings_id String,
          interface_warn_pct Float64,
          interface_crit_pct Float64,
          collector_warn_pct Float64,
          collector_crit_pct Float64,
          receiver_warn_pct Float64,
          receiver_crit_pct Float64,
          socket_warn_pct Float64,
          socket_crit_pct Float64,
          updated_at DateTime('UTC')
        )
        AS SELECT
          settings_id,
          interface_warn_pct,
          interface_crit_pct,
          collector_warn_pct,
          collector_crit_pct,
          receiver_warn_pct,
          receiver_crit_pct,
          socket_warn_pct,
          socket_crit_pct,
          updated_at_latest AS updated_at
        FROM
        (
          SELECT
            settings_id,
            argMax(interface_warn_pct, updated_at) AS interface_warn_pct,
            argMax(interface_crit_pct, updated_at) AS interface_crit_pct,
            argMax(collector_warn_pct, updated_at) AS collector_warn_pct,
            argMax(collector_crit_pct, updated_at) AS collector_crit_pct,
            argMax(receiver_warn_pct, updated_at) AS receiver_warn_pct,
            argMax(receiver_crit_pct, updated_at) AS receiver_crit_pct,
            argMax(socket_warn_pct, updated_at) AS socket_warn_pct,
            argMax(socket_crit_pct, updated_at) AS socket_crit_pct,
            max(updated_at) AS updated_at_latest
          FROM ${settingsTableRef()}
          GROUP BY settings_id
        )
      `, {}, { name: 'pipeline-thresholds/ensure-view' });
    })().catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

async function getCurrentThresholdsRaw() {
  await ensurePipelineThresholdsTables();
  const { rows } = await query(`
    SELECT *
    FROM ${settingsViewRef()}
    WHERE settings_id = {id:String}
    LIMIT 1
  `, { id: SETTINGS_ID }, { name: 'pipeline-thresholds/current' });
  return rows[0] || null;
}

async function loadPipelineThresholds() {
  const current = await getCurrentThresholdsRaw();
  return mapThresholdsRow(current || DEFAULT_ROW);
}

async function getPipelineThresholds() {
  const current = await getCurrentThresholdsRaw();
  return mapThresholdsForApi(current || DEFAULT_ROW);
}

async function savePipelineThresholds(payload = {}) {
  const existing = await getCurrentThresholdsRaw();
  const base = existing || DEFAULT_ROW;

  const record = {
    settings_id: SETTINGS_ID,
    interface_warn_pct: boundedFloat(payload.interfaceWarnPct, base.interface_warn_pct, 0, 100, 'interface warn'),
    interface_crit_pct: boundedFloat(payload.interfaceCritPct, base.interface_crit_pct, 0, 100, 'interface crit'),
    collector_warn_pct: boundedFloat(payload.collectorWarnPct, base.collector_warn_pct, 0, 100, 'collector warn'),
    collector_crit_pct: boundedFloat(payload.collectorCritPct, base.collector_crit_pct, 0, 100, 'collector crit'),
    receiver_warn_pct: boundedFloat(payload.receiverWarnPct, base.receiver_warn_pct, 0, 100, 'receiver warn'),
    receiver_crit_pct: boundedFloat(payload.receiverCritPct, base.receiver_crit_pct, 0, 100, 'receiver crit'),
    socket_warn_pct: boundedFloat(payload.socketWarnPct, base.socket_warn_pct, 0, 100, 'socket warn'),
    socket_crit_pct: boundedFloat(payload.socketCritPct, base.socket_crit_pct, 0, 100, 'socket crit'),
  };

  if (record.interface_warn_pct > record.interface_crit_pct) {
    throw apiError('Порог предупреждения интерфейса не может быть выше аварийного');
  }
  if (record.collector_warn_pct > record.collector_crit_pct) {
    throw apiError('Порог предупреждения коллектора не может быть выше аварийного');
  }
  if (record.receiver_warn_pct > record.receiver_crit_pct) {
    throw apiError('Порог предупреждения приёмника не может быть выше аварийного');
  }
  if (record.socket_warn_pct > record.socket_crit_pct) {
    throw apiError('Порог предупреждения сокета не может быть выше аварийного');
  }

  const { elapsedMs } = await insertRows(SETTINGS_TABLE, [record], { name: 'pipeline-thresholds/save' });
  return { elapsedMs, settings: mapThresholdsForApi(record) };
}

module.exports = {
  DEFAULT_THRESHOLDS,
  DEFAULT_ROW,
  ensurePipelineThresholdsTables,
  loadPipelineThresholds,
  getPipelineThresholds,
  savePipelineThresholds,
  mapThresholdsRow,
};
