/* Shared i18n helpers for «Моя сеть» (network chunk). */

function networkT(key, params) {
  return GrapesI18n.t(key, params);
}

function networkEmDash() {
  return networkT('network.emDash');
}

function resolveNetworkLoadError(desc) {
  if (desc === ApiClient.LOAD_FAILED) return networkT('dashboard.loadFailed');
  return desc;
}

function formatNetworkApiError(err) {
  const code = err && err.code;
  if (code) {
    const key = `network.err.${code}`;
    if (GrapesI18n.has(key)) {
      return networkT(key, err.params || undefined);
    }
  }
  if (err && err.message) return err.message;
  return networkT('network.err.saveFailed');
}

function networkSourceLabel(source) {
  const s = String(source ?? '').trim();
  if (!s) return networkEmDash();
  const key = `network.source.${s}`;
  if (GrapesI18n.has(key)) return networkT(key);
  return s;
}

function fmtNetworkDateTime(value) {
  if (!value) return networkEmDash();
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(GrapesI18n.intlLocale(), {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function l3RoleLabel(role) {
  const key = `network.cidr.role.${role}`;
  if (GrapesI18n.has(key)) return networkT(key);
  return role || networkEmDash();
}

function entityTypeLabel(type) {
  const key = `network.entities.type.${type}`;
  if (GrapesI18n.has(key)) return networkT(key);
  return type || networkEmDash();
}

Object.assign(window, {
  networkT,
  networkEmDash,
  resolveNetworkLoadError,
  formatNetworkApiError,
  networkSourceLabel,
  fmtNetworkDateTime,
  l3RoleLabel,
  entityTypeLabel,
});
