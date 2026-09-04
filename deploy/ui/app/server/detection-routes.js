'use strict';

const express = require('express');
const { loadLatest, loadHistory } = require('./detection-engine');
const {
  getDetectionTelegramSettings,
  saveDetectionTelegramSettings,
  sendTestTelegramMessage,
  loadDetectionEvents,
  exportDetectionEventsCsv,
} = require('./detection-telegram');
const { listObjectThresholds, saveObjectThreshold } = require('./detection-thresholds');

function sendError(res, err) {
  const status = Number(err.statusCode) || 500;
  res.status(status).json({ error: err.message || String(err) });
}

function requireAdmin(req, res) {
  if (String(req.user?.roleId || '') !== 'Administrator') {
    res.status(403).json({ error: 'Только администратор' });
    return false;
  }
  return true;
}

function createDetectionRouter() {
  const router = express.Router();

  router.get('/latest', async (_req, res) => {
    try {
      res.json({ data: await loadLatest() });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/history', async (req, res) => {
    try {
      res.json({
        data: await loadHistory({
          scope: req.query.scope,
          scopeId: req.query.scopeId || req.query.scope_id,
          proto: req.query.proto,
          metric: req.query.metric,
          hours: req.query.hours,
          from: req.query.from,
          to: req.query.to,
        }),
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/events', async (req, res) => {
    try {
      res.json({
        data: await loadDetectionEvents({
          status: req.query.status,
          limit: req.query.limit,
          from: req.query.from,
          to: req.query.to,
        }),
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/events/export', async (req, res) => {
    try {
      const { csv, count } = await exportDetectionEventsCsv({
        status: req.query.status || 'normalized',
        from: req.query.from,
        to: req.query.to,
        limit: req.query.limit || 10000,
      });
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="detection-history-${stamp}.csv"`);
      res.setHeader('X-Detection-Events-Count', String(count));
      res.send(csv);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/telegram', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return;
      res.json({ data: await getDetectionTelegramSettings() });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.put('/telegram', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return;
      res.json({ ok: true, data: await saveDetectionTelegramSettings(req.body || {}) });
    } catch (err) {
      sendError(res, err);
    }
  });

  // Общий порог отдаём здесь тоже: настройки Telegram видит только админ, а
  // колонку с порогом читают все, и подставлять дефолт вместо реального
  // значения — врать наблюдателю.
  router.get('/thresholds', async (_req, res) => {
    try {
      const [items, settings] = await Promise.all([
        listObjectThresholds(),
        getDetectionTelegramSettings(),
      ]);
      res.json({ data: { global: settings.growthThreshold, items } });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.put('/thresholds', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return;
      res.json({ ok: true, data: await saveObjectThreshold(req.body || {}) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/telegram/test', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return;
      await sendTestTelegramMessage();
      res.json({ ok: true });
    } catch (err) {
      sendError(res, err);
    }
  });

  return router;
}

module.exports = { createDetectionRouter };
