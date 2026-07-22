function getResourceForPath(path, method) {
  const p = String(path || '');

  if (p.startsWith('/api/explorer/')) return 'explorer';
  if (p.startsWith('/api/observations')) return 'observations';
  if (p.startsWith('/api/dashboard/')) return 'dashboard';
  if (p.startsWith('/api/dns/')) return 'dns';
  if (p.startsWith('/api/monitoring/')) return 'monitoring';
  if (p.startsWith('/api/refs/l3-prefixes')) return 'cidr';
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
  if (p.startsWith('/api/admin/ttl')) return 'ttl';
  if (p.startsWith('/api/diagnostics')) return 'diagnostics';
  if (p.startsWith('/api/users') || p.startsWith('/api/rbac/')) {
    if (method === 'POST' && /^\/api\/users\/[^/]+\/password$/.test(p)) return null;
    return 'users';
  }
  return null;
}

function isResourceGuardExempt(path) {
  const p = String(path || '');
  if (p === '/api/health') return true;
  if (p.startsWith('/api/auth/')) return true;
  return false;
}

function isMutatingRequest(path, method) {
  const m = String(method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return false;

  const p = String(path || '');
  if (m === 'POST' && /^\/api\/users\/[^/]+\/password$/.test(p)) return false;

  return true;
}

module.exports = {
  getResourceForPath,
  isResourceGuardExempt,
  isMutatingRequest,
};
