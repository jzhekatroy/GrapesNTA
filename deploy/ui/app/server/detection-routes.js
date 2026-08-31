'use strict';

const express = require('express');
const { loadLatest } = require('./detection-engine');

function sendError(res, err) {
  const status = Number(err.statusCode) || 500;
  res.status(status).json({ error: err.message || String(err) });
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

  return router;
}

module.exports = { createDetectionRouter };
