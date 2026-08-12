const CLIENT_ROLE_ID = 'Client';
const CLIENTS_RESOURCE = 'clients';
const MAX_USERS_PER_CLIENT = 5;
const IMPERSONATION_TTL_MS = 30 * 60 * 1000;

/** Paths a client-mode session may call. Everything else is denied. */
const CLIENT_API_ALLOWLIST = [
  /^\/api\/auth\/me$/,
  /^\/api\/auth\/logout$/,
  /^\/api\/auth\/stop-impersonation$/,
  /^\/api\/cabinet(\/|$)/,
  /^\/api\/users\/[^/]+\/password$/,
];

/** Page resources the Client role may see in the future UI menu. */
const CLIENT_PAGE_RESOURCES = new Set(['dashboard', 'explorer', 'dns']);

module.exports = {
  CLIENT_ROLE_ID,
  CLIENTS_RESOURCE,
  MAX_USERS_PER_CLIENT,
  IMPERSONATION_TTL_MS,
  CLIENT_API_ALLOWLIST,
  CLIENT_PAGE_RESOURCES,
};
