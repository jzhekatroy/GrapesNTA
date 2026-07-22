const express = require('express');
const { loadAppPages } = require('./resources');
const { requireResource } = require('./middleware');
const {
  listRoles,
  getRoleWithPermissions,
  createRole,
  updateRole,
  deleteRole,
  getUserPermissionOverrides,
  saveUserPermissionOverrides,
  assignUserRole,
} = require('./permissions');

function sendApiError(res, err, fallbackStatus = 502) {
  const status = err.statusCode || fallbackStatus;
  res.status(status).json({ error: err.message });
}

function createRbacRouter() {
  const router = express.Router();
  const guard = requireResource('users');

  router.get('/resources', guard, (_req, res) => {
    res.json({ data: loadAppPages() });
  });

  router.get('/roles', guard, async (_req, res) => {
    try {
      res.json(await listRoles());
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.post('/roles', guard, async (req, res) => {
    try {
      const data = await createRole(req.body || {});
      res.status(201).json({ ok: true, data });
    } catch (err) {
      sendApiError(res, err, err.statusCode || 502);
    }
  });

  router.get('/roles/:id', guard, async (req, res) => {
    try {
      const data = await getRoleWithPermissions(req.params.id);
      if (!data) {
        res.status(404).json({ error: 'Роль не найдена' });
        return;
      }
      res.json({ data });
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.put('/roles/:id', guard, async (req, res) => {
    try {
      const data = await updateRole(req.params.id, req.body || {});
      res.json({ ok: true, data });
    } catch (err) {
      sendApiError(res, err, err.statusCode || 502);
    }
  });

  router.delete('/roles/:id', guard, async (req, res) => {
    try {
      const result = await deleteRole(req.params.id);
      res.json(result);
    } catch (err) {
      sendApiError(res, err, err.statusCode || 502);
    }
  });

  router.get('/users/:id/permissions', guard, async (req, res) => {
    try {
      const data = await getUserPermissionOverrides(req.params.id);
      res.json({ data });
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.put('/users/:id/permissions', guard, async (req, res) => {
    try {
      const data = await saveUserPermissionOverrides(req.params.id, req.body?.overrides || req.body || {});
      res.json({ ok: true, data });
    } catch (err) {
      sendApiError(res, err, err.statusCode || 502);
    }
  });

  router.put('/users/:id/role', guard, async (req, res) => {
    try {
      const roleId = req.body?.roleId;
      if (!roleId) {
        res.status(400).json({ error: 'Укажите roleId' });
        return;
      }
      const data = await assignUserRole(req.params.id, roleId);
      res.json({ ok: true, data });
    } catch (err) {
      sendApiError(res, err, err.statusCode || 502);
    }
  });

  return router;
}

module.exports = {
  createRbacRouter,
};
