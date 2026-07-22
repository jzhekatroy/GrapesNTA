const { canAccess, canWrite } = require('./permissions');
const { getResourceForPath, isResourceGuardExempt, isMutatingRequest } = require('./api-map');

async function checkResourceAccess(req, res, resource) {
  const mutating = isMutatingRequest(req.path, req.method);
  const allowed = mutating
    ? await canWrite(req.user, resource)
    : await canAccess(req.user, resource);
  if (!allowed) {
    res.status(403).json({
      error: mutating ? 'Недостаточно прав для изменения данных' : 'Недостаточно прав',
    });
    return false;
  }
  return true;
}

function requireResource(resource) {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        res.status(401).json({ error: 'Требуется авторизация' });
        return;
      }
      if (!(await checkResourceAccess(req, res, resource))) return;
      next();
    } catch (err) {
      res.status(502).json({ error: err.message });
    }
  };
}

async function apiResourceGuard(req, res, next) {
  try {
    if (isResourceGuardExempt(req.path)) return next();

    const resource = getResourceForPath(req.path, req.method);
    if (!resource) return next();

    if (!req.user) {
      res.status(401).json({ error: 'Требуется авторизация' });
      return;
    }

    if (!(await checkResourceAccess(req, res, resource))) return;

    next();
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
}

module.exports = {
  requireResource,
  apiResourceGuard,
};
