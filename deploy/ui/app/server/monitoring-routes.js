'use strict';

const express = require('express');
const { loadDetectionEvents, loadDetectionEvent, loadMonitoringPeaks } = require('./detection-telegram');
const { loadExcessAsnTop } = require('./detection-investigate');
const { loadFlowspecReport } = require('./detection-flowspec-report');
const {
  getMonitoringProblems,
  loadAttackHistory,
  attackSliceMinute,
  shortPublicError,
} = require('./monitoring');

function sendError(res, err) {
  const status = Number(err.statusCode) || 500;
  const error = status >= 500 ? shortPublicError(err) : (err.message || 'Ошибка');
  res.status(status).json({ error });
}

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function createMonitoringRouter() {
  const router = express.Router();

  router.get('/attacks', async (_req, res) => {
    try {
      const attacks = await loadDetectionEvents({ status: 'active' });
      let peaks = [];
      let peaksError = null;
      try {
        peaks = await loadMonitoringPeaks();
      } catch (err) {
        peaksError = shortPublicError(err);
      }
      res.json({ data: { attacks, peaks, peaksError } });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/attacks/:id/history', async (req, res) => {
    try {
      const event = await loadDetectionEvent(req.params.id);
      res.json({ data: await loadAttackHistory(event) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/attacks/:id/asn', async (req, res) => {
    try {
      const event = await loadDetectionEvent(req.params.id);
      const minute = attackSliceMinute(event);
      if (!minute) throw apiError('Нет минуты среза');
      res.json({
        data: await loadExcessAsnTop({
          scope: event.scope,
          scopeId: event.scopeId,
          minute,
        }),
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/attacks/:id/flowspec', async (req, res) => {
    try {
      const event = await loadDetectionEvent(req.params.id);
      const minute = attackSliceMinute(event);
      if (!minute) throw apiError('Нет горячей минуты');
      res.json({
        data: await loadFlowspecReport({
          scope: event.scope,
          scopeId: event.scopeId,
          minute,
        }),
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/attacks/:id', async (req, res) => {
    try {
      res.json({ data: await loadDetectionEvent(req.params.id) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/problems', async (_req, res) => {
    try {
      res.json({ data: await getMonitoringProblems() });
    } catch (err) {
      sendError(res, err);
    }
  });

  return router;
}

module.exports = {
  createMonitoringRouter,
};
