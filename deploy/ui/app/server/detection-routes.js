'use strict';

const express = require('express');
const { loadLatest, loadHistory } = require('./detection-engine');
const {
  getDetectionTelegramSettings,
  saveDetectionTelegramSettings,
  sendTestTelegramMessage,
} = require('./detection-telegram');

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
