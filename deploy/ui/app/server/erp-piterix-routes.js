'use strict';

const express = require('express');
const clickhouse = require('./clickhouse');
const {
  createModuleAdapter,
  runSync,
  getStatus,
  listJournal,
  getSettings,
  saveSettings,
  getReport,
  reportToCsv,
} = require('./erp-piterix-run');

function sendError(res, err) {
  const status = Number(err.statusCode) || 500;
  res.status(status).json({ error: err.message || String(err) });
}

function createErpPiterixRouter() {
  const router = express.Router();
  const db = createModuleAdapter(clickhouse);

  router.get('/status', async (_req, res) => {
    try {
      res.json({ data: await getStatus(db) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/settings', async (_req, res) => {
    try {
      res.json({ data: await getSettings(db) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.put('/settings', async (req, res) => {
    try {
      res.json({ data: await saveSettings(db, req.body || {}) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/journal', async (req, res) => {
    try {
      res.json({ data: await listJournal(db, req.query.limit) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/runs/:runId/report.csv', async (req, res) => {
    try {
      const rows = await getReport(db, req.params.runId);
      if (!rows.length) {
        res.status(404).json({ error: 'Отчёт за этот прогон не найден' });
        return;
      }
      const stamp = String(req.params.runId).slice(0, 8);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="erp-piterix-report-${stamp}.csv"`);
      res.send(`\uFEFF${reportToCsv(rows)}`);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/run', async (req, res) => {
    try {
      const full = !!req.body?.full;
      const limit = Math.min(Math.max(Number(req.body?.limit) || 50, 1), 500);
      const actor = String(req.user?.login || req.user?.id || '');
      const data = await runSync(db, {
        full,
        limit,
        trigger: 'ui',
        actor,
      });
      res.json({ data });
    } catch (err) {
      sendError(res, err);
    }
  });

  return router;
}

module.exports = { createErpPiterixRouter };
