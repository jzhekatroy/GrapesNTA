'use strict';

const nodemailer = require('nodemailer');
const { query, executeCommand, insertRows, config } = require('./clickhouse');

const SETTINGS_TABLE = 'app_smtp_settings';
const SETTINGS_VIEW = 'app_smtp_settings_current';
const SETTINGS_ID = 'global';

const DEFAULT_SETTINGS = {
  host: '',
  port: 587,
  secure: 0,
  username: '',
  password: '',
  from_email: '',
  from_name: 'GrapesNTA',
  enabled: 0,
};

let ensurePromise = null;

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function boolInt(value, fallback) {
  if (value === undefined) return fallback;
  return value === true || value === 1 || value === '1' ? 1 : 0;
}

function boundedInt(value, fallback, min, max, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw apiError(`${label}: ожидается целое число от ${min} до ${max}`);
  }
  return n;
}

function settingsTableRef() {
  return `${config.database}.${SETTINGS_TABLE}`;
}

function settingsViewRef() {
  return `${config.database}.${SETTINGS_VIEW}`;
}

function mapSettings(row = {}) {
  return {
    host: String(row.host ?? ''),
    port: Number(row.port) || DEFAULT_SETTINGS.port,
    secure: Number(row.secure) === 1,
    username: String(row.username ?? ''),
    passwordSet: Boolean(String(row.password ?? '')),
    fromEmail: String(row.from_email ?? ''),
    fromName: String(row.from_name ?? DEFAULT_SETTINGS.from_name),
    enabled: Number(row.enabled) === 1,
    updatedAt: row.updated_at ?? null,
  };
}

async function ensureObservationRunsEmailColumns() {
  await executeCommand(`
    ALTER TABLE ${config.database}.observation_runs
      ADD COLUMN IF NOT EXISTS email_status String DEFAULT '',
      ADD COLUMN IF NOT EXISTS email_to String DEFAULT '',
      ADD COLUMN IF NOT EXISTS email_error String DEFAULT ''
  `, {}, { name: 'smtp/ensure-runs-email-columns' });
}

async function ensureSmtpSettingsTables() {
  if (!ensurePromise) {
    ensurePromise = (async () => {
      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${settingsTableRef()}
        (
          settings_id String DEFAULT 'global',
          host String DEFAULT '',
          port UInt16 DEFAULT 587,
          secure UInt8 DEFAULT 0,
          username String DEFAULT '',
          password String DEFAULT '',
          from_email String DEFAULT '',
          from_name String DEFAULT 'GrapesNTA',
          enabled UInt8 DEFAULT 0,
          updated_at DateTime('UTC') DEFAULT now()
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY settings_id
        SETTINGS index_granularity = 8192
      `, {}, { name: 'smtp/ensure-table' });

      await executeCommand(`
        CREATE VIEW IF NOT EXISTS ${settingsViewRef()}
        (
          settings_id String,
          host String,
          port UInt16,
          secure UInt8,
          username String,
          password String,
          from_email String,
          from_name String,
          enabled UInt8,
          updated_at DateTime('UTC')
        )
        AS SELECT
          settings_id,
          host,
          port,
          secure,
          username,
          password,
          from_email,
          from_name,
          enabled,
          updated_at_latest AS updated_at
        FROM
        (
          SELECT
            settings_id,
            argMax(host, updated_at) AS host,
            argMax(port, updated_at) AS port,
            argMax(secure, updated_at) AS secure,
            argMax(username, updated_at) AS username,
            argMax(password, updated_at) AS password,
            argMax(from_email, updated_at) AS from_email,
            argMax(from_name, updated_at) AS from_name,
            argMax(enabled, updated_at) AS enabled,
            max(updated_at) AS updated_at_latest
          FROM ${settingsTableRef()}
          GROUP BY settings_id
        )
      `, {}, { name: 'smtp/ensure-view' });

      await ensureObservationRunsEmailColumns();
    })().catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

async function getCurrentSettingsRaw() {
  await ensureSmtpSettingsTables();
  const { rows } = await query(`
    SELECT
      host, port, secure, username, password, from_email, from_name, enabled, updated_at
    FROM ${settingsViewRef()}
    WHERE settings_id = {id:String}
    LIMIT 1
  `, { id: SETTINGS_ID }, { name: 'smtp/settings-current' });
  return rows[0] || null;
}

async function getSmtpSettings() {
  const current = await getCurrentSettingsRaw();
  return mapSettings(current || DEFAULT_SETTINGS);
}

async function saveSmtpSettings(payload = {}) {
  const existing = await getCurrentSettingsRaw();
  const base = existing || DEFAULT_SETTINGS;
  const replacement = String(payload.password ?? '').trim();
  const password = replacement || String(base.password ?? '');

  const enabled = boolInt(payload.enabled, Number(base.enabled) === 1 ? 1 : 0);
  const host = String(payload.host ?? base.host ?? '').trim();
  const fromEmail = String(payload.fromEmail ?? payload.from_email ?? base.from_email ?? '').trim();

  if (enabled && (!host || !fromEmail)) {
    throw apiError('Укажите host и from_email перед включением SMTP');
  }

  const record = {
    settings_id: SETTINGS_ID,
    host,
    port: boundedInt(payload.port, Number(base.port), 1, 65535, 'Порт'),
    secure: boolInt(payload.secure, Number(base.secure) === 1 ? 1 : 0),
    username: String(payload.username ?? base.username ?? '').trim(),
    password,
    from_email: fromEmail,
    from_name: String(payload.fromName ?? payload.from_name ?? base.from_name ?? DEFAULT_SETTINGS.from_name).trim()
      || DEFAULT_SETTINGS.from_name,
    enabled,
  };

  const { elapsedMs } = await insertRows(SETTINGS_TABLE, [record], { name: 'smtp/settings-save' });
  return { elapsedMs };
}

async function loadMailTransportConfig() {
  const raw = await getCurrentSettingsRaw();
  if (!raw || Number(raw.enabled) !== 1) {
    throw apiError('SMTP отключён или не настроен', 503);
  }
  if (!String(raw.host ?? '').trim()) {
    throw apiError('SMTP host не задан', 503);
  }
  if (!String(raw.from_email ?? '').trim()) {
    throw apiError('SMTP from_email не задан', 503);
  }
  return {
    host: String(raw.host),
    port: Number(raw.port) || DEFAULT_SETTINGS.port,
    secure: Number(raw.secure) === 1,
    auth: String(raw.username ?? '').trim()
      ? { user: String(raw.username), pass: String(raw.password ?? '') }
      : undefined,
    fromEmail: String(raw.from_email),
    fromName: String(raw.from_name || DEFAULT_SETTINGS.from_name),
  };
}

async function sendSmtpMail({ to, subject, html, attachments = [] } = {}) {
  const cfg = await loadMailTransportConfig();
  const recipients = Array.isArray(to) ? to : [to];
  const filtered = recipients.map((item) => String(item || '').trim()).filter(Boolean);
  if (!filtered.length) throw apiError('Не указаны получатели');

  const transporter = nodemailer.createTransport({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    auth: cfg.auth,
  });

  return transporter.sendMail({
    from: cfg.fromName ? `"${cfg.fromName}" <${cfg.fromEmail}>` : cfg.fromEmail,
    to: filtered.join(', '),
    subject: String(subject || ''),
    html: String(html || ''),
    attachments: Array.isArray(attachments) ? attachments : [],
  });
}

async function sendTestMail(to) {
  const recipient = String(to || '').trim();
  if (!recipient) throw apiError('Укажите адрес получателя');
  return sendSmtpMail({
    to: recipient,
    subject: 'GrapesNTA: тест SMTP',
    html: '<p>Тестовое письмо от GrapesNTA. SMTP настроен корректно.</p>',
  });
}

module.exports = {
  SETTINGS_TABLE,
  SETTINGS_VIEW,
  ensureSmtpSettingsTables,
  getSmtpSettings,
  saveSmtpSettings,
  sendSmtpMail,
  sendTestMail,
};
