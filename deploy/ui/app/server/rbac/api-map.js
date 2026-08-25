function normalizeApiPath(path) {
  // Middleware mounted at /api sees req.path without the /api prefix.
  const raw = String(path || '');
  if (!raw) return '';
  if (raw === '/api' || raw.startsWith('/api/')) return raw;
  if (raw.startsWith('/')) return `/api${raw}`;
  return `/api/${raw}`;
}

function isDashboardLayoutPath(path) {
  const p = normalizeApiPath(path);
  return p === '/api/dashboard/layout' || p === '/api/dashboard/layout/reset';
}

function getResourceForPath(path, method) {
  const p = normalizeApiPath(path);

  if (p.startsWith('/api/explorer/')) return 'explorer';
  if (p.startsWith('/api/dns-explorer/')) return 'dns-explorer';
  if (p.startsWith('/api/observations')) return 'observations';
  if (p.startsWith('/api/settings/smtp')) return 'diagnostics';
  if (p.startsWith('/api/dashboard/')) return 'dashboard';
  if (p.startsWith('/api/dns/')) return 'dns';
  if (p.startsWith('/api/refs/l3-prefixes')) return 'cidr';
  if (p.startsWith('/api/refs/dns-resolvers')) return 'dns-resolvers';
  if (p.startsWith('/api/refs/flow-exclusions')) return 'flow-exclusions';
  if (p.startsWith('/api/refs/locations')
    || p.startsWith('/api/refs/collectors')
    || p.startsWith('/api/refs/flow-sources')
    || p.startsWith('/api/refs/snmp-settings')
    || p.startsWith('/api/refs/snmp-agents')) return 'collectors';
  if (p.startsWith('/api/collectors/overview')
    || p.startsWith('/api/collectors/discovered')
    || p.startsWith('/api/collectors/completeness')) return 'collectors';
  if (p.startsWith('/api/collectors/status')) return 'collector-status';
  if (p.startsWith('/api/bmp/')) return 'bmp';
  if (p.startsWith('/api/refs/entities') || p.startsWith('/api/refs/net-entities')) return 'entities';
  if (p.startsWith('/api/refs/vlans') || p.startsWith('/api/vlan/')) return 'vlan';
  if (p.startsWith('/api/refs/port-services')) return 'port-services';
  if (p.startsWith('/api/refs/direction-settings')) return 'traffic-classification';
  if (p.startsWith('/api/refs/interface-role-rules')
    || p.startsWith('/api/refs/interface-roles')) return 'interface-roles';
  if (p.startsWith('/api/diagnostics/direction/')) return 'traffic-classification';
  if (p.startsWith('/api/admin/ttl')) return 'ttl';
  if (p.startsWith('/api/erp-piterix')) return 'diagnostics';
  if (p.startsWith('/api/audit')) {
    if (p === '/api/audit/page' && method === 'POST') return null;
    return 'audit';
  }
  if (p.startsWith('/api/diagnostics')) return 'diagnostics';
  if (p.startsWith('/api/cabinet/')) return null;
  if (p.startsWith('/api/clients')) return 'clients';
  if (p.startsWith('/api/users') || p.startsWith('/api/rbac/')) {
    if (method === 'POST' && /^\/api\/users\/[^/]+\/password$/.test(p)) return null;
    return 'users';
  }
  return null;
}

function isResourceGuardExempt(path) {
  const p = normalizeApiPath(path);
  if (p === '/api/health') return true;
  if (p.startsWith('/api/auth/')) return true;
  if (p.startsWith('/api/cabinet/')) return true;
  return false;
}

function isMutatingRequest(path, method) {
  const m = String(method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return false;

  const p = normalizeApiPath(path);
  if (m === 'POST' && /^\/api\/users\/[^/]+\/password$/.test(p)) return false;

  return true;
}

module.exports = {
  normalizeApiPath,
  getResourceForPath,
  isResourceGuardExempt,
  isMutatingRequest,
  isDashboardLayoutPath,
};
