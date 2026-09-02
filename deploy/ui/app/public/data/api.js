/* HTTP-клиент к API бэкенда (ClickHouse). При недоступности API — пустые данные и ошибка загрузки. */

const ApiClient = (() => {
  const LOAD_FAILED = 'Не удалось загрузить';
  let status = { connected: false, checkedAt: 0 };
  let onSessionInvalid = null;

  function stripCacheBustQuery() {
    try {
      const url = new URL(window.location.href);
      if (!url.searchParams.has('_')) return;
      url.searchParams.delete('_');
      window.history.replaceState(null, '', url.pathname + url.search + url.hash);
    } catch {
      // Ignore malformed URLs; navigation still works with the original address.
    }
  }

  stripCacheBustQuery();

  function isSessionInvalidError(err) {
    if (!err?.status) return false;
    if (err.status === 401) return true;
    if (err.status !== 403) return false;
    if (err.body?.code === 'client_disabled') return true;
    const msg = String(err.message || '').toLowerCase();
    return msg.includes('приостановлен') || msg.includes('учётная запись отключена');
  }

  function sessionInvalidToast(err, { wasCabinetClient = false } = {}) {
    const msg = String(err?.message || '').toLowerCase();
    if (err?.body?.code === 'client_disabled' || msg.includes('приостановлен')) {
      return {
        kind: 'warning',
        title: 'Доступ приостановлен',
        desc: 'Компания отключена оператором. Обратитесь к оператору.',
        duration: 8000,
      };
    }
    if (msg.includes('учётная запись отключена')) {
      return {
        kind: 'warning',
        title: 'Учётная запись отключена',
        desc: 'Обратитесь к оператору для восстановления доступа.',
        duration: 8000,
      };
    }
    if (wasCabinetClient) {
      return {
        kind: 'warning',
        title: 'Доступ приостановлен',
        desc: 'Сессия завершена. Если доступ был отключён оператором, обратитесь к нему.',
        duration: 8000,
      };
    }
    return {
      kind: 'info',
      title: 'Сессия завершена',
      desc: 'Войдите снова.',
      duration: 5000,
    };
  }

  let sessionInvalidNotified = false;

  function maybeInvalidateSession(err) {
    if (!isSessionInvalidError(err) || !onSessionInvalid) return;
    if (sessionInvalidNotified) return;
    sessionInvalidNotified = true;
    onSessionInvalid(err);
    setTimeout(() => { sessionInvalidNotified = false; }, 1500);
  }

  function setSessionInvalidHandler(fn) {
    onSessionInvalid = typeof fn === 'function' ? fn : null;
  }

  function apiCustomPeriodParams(customPeriod) {
    if (!customPeriod?.from || !customPeriod?.to) return null;
    if (typeof displayDatetimeLocalToData === 'function') {
      const displayTz = typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined;
      return {
        from: displayDatetimeLocalToData(customPeriod.from, displayTz),
        to: displayDatetimeLocalToData(customPeriod.to, displayTz),
      };
    }
    return { from: customPeriod.from, to: customPeriod.to };
  }

  function appendCustomPeriodParams(params, timeRange, customPeriod) {
    if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(customPeriod);
      params.set('range', 'custom');
      params.set('from', apiPeriod.from);
      params.set('to', apiPeriod.to);
      return true;
    }
    params.set('range', timeRange || '24h');
    return false;
  }

  async function checkHealth(force = false) {
    const now = Date.now();
    if (!force && now - status.checkedAt < 10000) return status;
    try {
      const res = await fetch('/api/health', { cache: 'no-store', credentials: 'same-origin' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      status = {
        connected: !!body.clickhouse?.connected,
        version: body.clickhouse?.version,
        database: body.clickhouse?.database,
        table: body.clickhouse?.table,
        error: body.clickhouse?.error,
        checkedAt: now,
      };
    } catch (err) {
      status = { connected: false, error: err.message, checkedAt: now };
    }
    return status;
  }

  async function loadDashboardCollectors() {
    try {
      const body = await getJson('/api/dashboard/collectors', { widget: 'dashboard/collectors' });
      const payload = body.data;
      if (Array.isArray(payload)) {
        return { collectors: payload, locations: [] };
      }
      return {
        collectors: Array.isArray(payload?.collectors) ? payload.collectors : [],
        locations: Array.isArray(payload?.locations) ? payload.locations : [],
      };
    } catch (err) {
      console.warn('[ApiClient] collectors failed:', err.message);
      return { collectors: [], locations: [] };
    }
  }

  async function getJson(path, { widget } = {}) {
    const name = widget || path;
    const finish = DashboardLog?.fetchStart?.(name) ?? ((extra) => ({ loadMs: 0, ...extra }));
    try {
      const res = await fetch(path, { cache: 'no-store', credentials: 'same-origin' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const err = new Error(body.error || `HTTP ${res.status}`);
        err.status = res.status;
        err.body = body;
        throw err;
      }
      const body = await res.json();
      const metrics = finish({
        serverMs: body.meta?.elapsedMs,
        rows: body.meta?.rows,
        source: 'clickhouse',
      });
      return {
        ...body,
        loadMs: metrics.loadMs,
        serverMs: body.meta?.elapsedMs ?? null,
      };
    } catch (err) {
      const metrics = finish({ source: 'error', error: err.message });
      err.loadMs = metrics.loadMs;
      maybeInvalidateSession(err);
      throw err;
    }
  }

  async function requestJson(path, { method = 'GET', body } = {}) {
    const res = await fetch(path, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const payload = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(payload.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.occupants = payload.occupants;
      err.quotas = payload.quotas;
      err.body = payload;
      maybeInvalidateSession(err);
      throw err;
    }
    return payload;
  }

  async function login({ username, password }) {
    return requestJson('/api/auth/login', {
      method: 'POST',
      body: { username, password },
    });
  }

  async function logout() {
    return requestJson('/api/auth/logout', { method: 'POST' });
  }

  async function loadCurrentUser() {
    const body = await requestJson('/api/auth/me');
    return body.user;
  }

  async function loadUsers() {
    const body = await requestJson('/api/users');
    return body.data || [];
  }

  async function createUser(payload) {
    const body = await requestJson('/api/users', {
      method: 'POST',
      body: payload,
    });
    return body.data;
  }

  async function updateUser(id, payload) {
    const body = await requestJson(`/api/users/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: payload,
    });
    return body.data;
  }

  async function deleteUser(id) {
    return requestJson(`/api/users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async function changeUserPassword(id, payload) {
    const body = await requestJson(`/api/users/${encodeURIComponent(id)}/password`, {
      method: 'POST',
      body: payload,
    });
    return body.data;
  }

  async function resetUserPassword(id, payload = {}) {
    return requestJson(`/api/users/${encodeURIComponent(id)}/password-reset`, {
      method: 'POST',
      body: payload,
    });
  }

  async function loadCabinetProfile() {
    return requestJson('/api/cabinet/profile');
  }

  async function patchCabinetProfile(payload) {
    const body = await requestJson('/api/cabinet/profile', {
      method: 'PATCH',
      body: payload,
    });
    return body.data;
  }

  async function changeCabinetProfilePassword(payload) {
    const body = await requestJson('/api/cabinet/profile/password', {
      method: 'POST',
      body: payload,
    });
    return body.data;
  }

  async function loadRbacResources() {
    const body = await requestJson('/api/rbac/resources');
    return body.data || [];
  }

  async function loadRoles() {
    const body = await requestJson('/api/rbac/roles');
    return body.data || [];
  }

  async function loadRole(id) {
    const body = await requestJson(`/api/rbac/roles/${encodeURIComponent(id)}`);
    return body.data;
  }

  async function createRole(payload) {
    const body = await requestJson('/api/rbac/roles', { method: 'POST', body: payload });
    return body.data;
  }

  async function updateRole(id, payload) {
    const body = await requestJson(`/api/rbac/roles/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: payload,
    });
    return body.data;
  }

  async function deleteRole(id) {
    return requestJson(`/api/rbac/roles/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async function loadUserPermissions(id) {
    const body = await requestJson(`/api/rbac/users/${encodeURIComponent(id)}/permissions`);
    return body.data || {};
  }

  async function saveUserPermissions(id, overrides) {
    const body = await requestJson(`/api/rbac/users/${encodeURIComponent(id)}/permissions`, {
      method: 'PUT',
      body: { overrides },
    });
    return body.data;
  }

  async function updateUserRole(id, roleId) {
    const body = await requestJson(`/api/rbac/users/${encodeURIComponent(id)}/role`, {
      method: 'PUT',
      body: { roleId },
    });
    return body.data;
  }

  function appendCollectorFilter(params, collectorFilter) {
    const items = Array.isArray(collectorFilter)
      ? collectorFilter.map((v) => String(v).trim()).filter(Boolean)
      : (collectorFilter ? [String(collectorFilter).trim()] : []);
    if (items.length) params.set('collector_id', items.join(','));
  }

  function hasCollectorInFilters(filters) {
    return (filters || []).some((f) => String(f?.field || f?.dim || '').trim() === 'collector');
  }

  function appendCollectorFilterBody(body, collectorFilter) {
    if (hasCollectorInFilters(body.filters)) return;
    const items = Array.isArray(collectorFilter)
      ? collectorFilter.map((v) => String(v).trim()).filter(Boolean)
      : (collectorFilter ? [String(collectorFilter).trim()] : []);
    if (items.length) body.collectorId = items.join(',');
  }

  function trafficStatsQuery({ timeRange = '24h', customPeriod, direction, collectorFilter } = {}) {
    const params = new URLSearchParams();
    appendCustomPeriodParams(params, timeRange, customPeriod);
    if (direction) params.set('direction', direction);
    appendCollectorFilter(params, collectorFilter);
    return params.toString();
  }

  const CHART_DIRECTION_TO_SQL = {
    total: 'total',
    incoming: 'in',
    outgoing: 'out',
    transit: 'transit',
    internal: 'internal',
    unclassified: 'unknown',
  };

  function resolveChartSqlDirections(directions) {
    const flowIds = Object.keys(CHART_DIRECTION_TO_SQL);
    const enabled = flowIds.filter((id) => directions?.[id]);
    if (!enabled.length) return [];
    if (enabled.length === flowIds.length) {
      return ['total', 'in', 'out', 'transit', 'internal', 'unknown'];
    }
    return enabled.map((id) => CHART_DIRECTION_TO_SQL[id]);
  }

  const PROTOCOL_DIRECTION_MAP = {
    incoming: 'in',
    outgoing: 'out',
    transit: 'transit',
    internal: 'internal',
    unclassified: 'unknown',
  };

  function resolveProtocolSqlDirections(directions) {
    const flowIds = Object.keys(PROTOCOL_DIRECTION_MAP);
    const enabled = flowIds.filter((id) => directions?.[id]);
    if (!enabled.length || enabled.length === flowIds.length) {
      return ['in', 'out', 'transit', 'internal', 'unknown'];
    }
    return enabled.map((id) => PROTOCOL_DIRECTION_MAP[id]);
  }

  function protocolQuery({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
    const params = new URLSearchParams();
    appendCustomPeriodParams(params, timeRange, customPeriod);
    params.set('directions', resolveProtocolSqlDirections(directions).join(','));
    appendCollectorFilter(params, collectorFilter);
    return params.toString();
  }

  function chartTrafficQuery({ timeRange = '1h', customPeriod, directions, collectorFilter } = {}) {
    const params = new URLSearchParams();
    appendCustomPeriodParams(params, timeRange, customPeriod);
    params.set('directions', resolveChartSqlDirections(directions).join(','));
    appendCollectorFilter(params, collectorFilter);
    return params.toString();
  }

  async function fetchDashboard(path, widget) {
    try {
      const body = await getJson(path, { widget });
      return {
        ok: true,
        data: body.data,
        meta: body.meta,
        loadMs: body.loadMs,
        serverMs: body.serverMs,
      };
    } catch (err) {
      return {
        ok: false,
        loadMs: err.loadMs ?? null,
        serverMs: null,
        error: err,
      };
    }
  }

  async function dashboardTraffic({ timeRange = '1h', customPeriod, directions, collectorFilter } = {}) {
    const qs = chartTrafficQuery({ timeRange, customPeriod, directions, collectorFilter });
    const body = await getJson(`/api/dashboard/traffic?${qs}`, { widget: 'dashboard/traffic' });
    return body.data;
  }

  async function dashboardTrafficStats({ timeRange = '24h', customPeriod, collectorFilter } = {}) {
    const qs = trafficStatsQuery({ timeRange, customPeriod, collectorFilter });
    const body = await getJson(`/api/dashboard/traffic-stats?${qs}`, { widget: 'dashboard/traffic-stats' });
    return body.data;
  }

  async function dashboardProtocols({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
    const qs = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });
    const body = await getJson(`/api/dashboard/protocols?${qs}`, { widget: 'dashboard/protocols' });
    return body.data;
  }

  async function dashboardServices({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
    const qs = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });
    const body = await getJson(`/api/dashboard/services?${qs}`, { widget: 'dashboard/services' });
    return body.data;
  }

  async function loadProtocolTrend({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
    const qs = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });
    return fetchDashboard(`/api/dashboard/protocols/timeseries?${qs}`, 'dashboard/protocols/timeseries');
  }

  async function loadServiceTrend({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
    const qs = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });
    return fetchDashboard(`/api/dashboard/services/timeseries?${qs}`, 'dashboard/services/timeseries');
  }

  function vlanQuery({ timeRange, customPeriod, directions, collectorFilter, attachmentType, limit } = {}) {
    const qs = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });
    const params = new URLSearchParams(qs);
    if (attachmentType && attachmentType !== 'all') params.set('attachment_type', attachmentType);
    if (limit) params.set('limit', String(limit));
    return params.toString();
  }

  async function dashboardVlans({ timeRange = '24h', customPeriod, directions, collectorFilter, attachmentType } = {}) {
    const qs = vlanQuery({ timeRange, customPeriod, directions, collectorFilter, attachmentType });
    const body = await getJson(`/api/dashboard/vlans?${qs}`, { widget: 'dashboard/vlans' });
    return body.data;
  }

  async function loadVlanTrend({ timeRange = '24h', customPeriod, directions, collectorFilter, attachmentType } = {}) {
    const qs = vlanQuery({ timeRange, customPeriod, directions, collectorFilter, attachmentType });
    return fetchDashboard(`/api/dashboard/vlans/timeseries?${qs}`, 'dashboard/vlans/timeseries');
  }

  async function loadVlanTop({ timeRange = '24h', customPeriod, directions, collectorFilter, attachmentType, limit = 50 } = {}) {
    const qs = vlanQuery({ timeRange, customPeriod, directions, collectorFilter, attachmentType, limit });
    return fetchDashboard(`/api/vlan/top?${qs}`, 'vlan/top');
  }

  async function dashboardOtherPorts({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
    const qs = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });
    const body = await getJson(`/api/dashboard/other-ports?${qs}`, { widget: 'dashboard/other-ports' });
    return body.data;
  }

  async function loadExplorerSchema() {
    const body = await getJson('/api/explorer/schema', { widget: 'explorer/schema' });
    return body.data;
  }

  async function searchExplorerEntities({ type, q = '', limit = 20, switchIp = '' } = {}) {
    const params = new URLSearchParams();
    params.set('type', type);
    if (q) params.set('q', q);
    if (limit) params.set('limit', String(limit));
    if (switchIp) params.set('switch_ip', String(switchIp));
    const body = await getJson(`/api/explorer/entities?${params}`, { widget: 'explorer/entities' });
    return body.data || [];
  }

  async function loadExplorerQuery({
    metric = 'bps',
    groupBy = [],
    filters = [],
    thresholds = [],
    limit = 10,
    offset = 0,
    timeRange = '1h',
    customPeriod,
    granularity = 'auto',
    includeSummary = true,
    includeTimeseries = true,
    includeBreakdowns = true,
    collectorFilter,
  } = {}) {
    const finish = DashboardLog?.widgetStart?.('explorer/query') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const body = {
      metric,
      groupBy,
      filters,
      thresholds: Array.isArray(thresholds) ? thresholds : [],
      limit,
      offset,
      range: timeRange,
      granularity,
      includeSummary,
      includeTimeseries,
      includeBreakdowns,
    };
    appendCollectorFilterBody(body, collectorFilter);
    if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(customPeriod);
      body.range = 'custom';
      body.from = apiPeriod.from;
      body.to = apiPeriod.to;
    }
    try {
      const res = await requestJson('/api/explorer/query', { method: 'POST', body });
      const metrics = finish({
        source: 'clickhouse',
        rows: res.meta?.rows,
        serverMs: res.meta?.elapsedMs,
      });
      return {
        source: 'clickhouse',
        rows: Array.isArray(res.data?.rows) ? res.data.rows : [],
        summary: res.data?.summary || null,
        timeseries: Array.isArray(res.data?.timeseries) ? res.data.timeseries : [],
        resultSeries: res.data?.resultSeries || null,
        breakdowns: res.data?.breakdowns || {},
        meta: res.meta || null,
        snapshotId: res.meta?.snapshotId ?? null,
        snapshotExpiresAt: res.meta?.snapshotExpiresAt ?? null,
        loadMs: metrics.loadMs,
        serverMs: res.meta?.elapsedMs ?? null,
      };
    } catch (err) {
      const metrics = finish({ source: 'error', error: err.message });
      return {
        source: 'error',
        rows: [],
        summary: null,
        timeseries: [],
        resultSeries: null,
        breakdowns: {},
        error: err.message || LOAD_FAILED,
        meta: null,
        loadMs: metrics.loadMs,
        serverMs: null,
      };
    }
  }

  async function loadExplorerFlows({
    metric = 'bps',
    groupBy = [],
    filters = [],
    thresholds = [],
    limit = 10,
    timeRange = '1h',
    customPeriod,
    collectorFilter,
  } = {}) {
    const finish = DashboardLog?.widgetStart?.('explorer/flows') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const body = { metric, groupBy, filters, thresholds: Array.isArray(thresholds) ? thresholds : [], limit, range: timeRange };
    appendCollectorFilterBody(body, collectorFilter);
    if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(customPeriod);
      body.range = 'custom';
      body.from = apiPeriod.from;
      body.to = apiPeriod.to;
    }
    try {
      const res = await requestJson('/api/explorer/flows', { method: 'POST', body });
      const metrics = finish({
        source: 'clickhouse',
        rows: res.meta?.rows,
        serverMs: res.meta?.elapsedMs,
      });
      return {
        source: 'clickhouse',
        rows: Array.isArray(res.data) ? res.data : [],
        meta: res.meta || null,
        loadMs: metrics.loadMs,
        serverMs: res.meta?.elapsedMs ?? null,
      };
    } catch (err) {
      const metrics = finish({ source: 'error', error: err.message });
      return { source: 'error', rows: [], error: err.message || LOAD_FAILED, meta: null, loadMs: metrics.loadMs, serverMs: null };
    }
  }

  async function exportExplorerCsv(queryBody = {}) {
    const body = { ...queryBody };
    appendCollectorFilterBody(body, body.collectorFilter);
    delete body.collectorFilter;
    if (body.from && body.to) {
      body.range = 'custom';
      delete body.timeRange;
      delete body.customPeriod;
    } else if (body.timeRange === 'custom' && body.customPeriod?.from && body.customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(body.customPeriod);
      body.range = 'custom';
      body.from = apiPeriod.from;
      body.to = apiPeriod.to;
    } else if (body.timeRange) {
      body.range = body.timeRange;
    }
    delete body.customPeriod;
    const res = await fetch('/api/explorer/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `HTTP ${res.status}`);
    }
    return res.blob();
  }

  async function loadExplorerSavedFilters() {
    const body = await getJson('/api/explorer/saved-filters', { widget: 'explorer/saved-filters' });
    return body.data || [];
  }

  async function saveExplorerFilter(payload) {
    return requestJson('/api/explorer/saved-filters', { method: 'POST', body: payload });
  }

  async function deleteExplorerFilter(id) {
    return requestJson(`/api/explorer/saved-filters/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async function updateExplorerFilter(id, payload) {
    return requestJson(`/api/explorer/saved-filters/${encodeURIComponent(id)}`, { method: 'PUT', body: payload });
  }

  async function loadObservationsConfig() {
    const body = await getJson('/api/observations/config', { widget: 'observations/config' });
    return body.data;
  }

  async function loadObservations() {
    const body = await getJson('/api/observations', { widget: 'observations/list' });
    return body.data || [];
  }

  async function loadObservationAnalyticsDiagnostics() {
    const body = await getJson('/api/observations/analytics/diagnostics', {
      widget: 'observations/analytics-diagnostics',
    });
    return body.data || body;
  }

  async function loadWorkerDiagnostics() {
    const body = await getJson('/api/diagnostics/worker', {
      widget: 'diagnostics/worker',
    });
    return body.data || body;
  }

  async function scanWorkerGaps(opts = {}) {
    const q = new URLSearchParams();
    if (opts && opts.from && opts.to) {
      q.set('from', opts.from);
      q.set('to', opts.to);
    } else {
      q.set('days', String((opts && opts.days) || 3));
    }
    const body = await getJson(`/api/diagnostics/worker/gaps?${q}`, {
      widget: 'diagnostics/worker-gaps',
    });
    return body.data || body;
  }

  async function loadWorkerBackfillQueue() {
    const body = await getJson('/api/diagnostics/worker/backfill', {
      widget: 'diagnostics/worker-backfill',
    });
    return body.data || body;
  }

  async function enqueueWorkerBackfill(payload) {
    const body = await requestJson('/api/diagnostics/worker/backfill', {
      method: 'POST',
      body: payload,
    });
    return body.data || body;
  }

  async function cancelWorkerBackfill() {
    const body = await requestJson('/api/diagnostics/worker/backfill/cancel', {
      method: 'POST',
      body: {},
    });
    return body.data || body;
  }

  async function loadEnrichmentDiagnostics() {
    const body = await getJson('/api/diagnostics/enrichment', {
      widget: 'diagnostics/enrichment',
    });
    return body.data || body;
  }

  async function loadSnmpDiagnostics() {
    const body = await getJson('/api/diagnostics/snmp', {
      widget: 'diagnostics/snmp',
    });
    return body.data || body;
  }

  async function loadAnalysisSnapshotsDiagnostics() {
    const body = await getJson('/api/diagnostics/analysis-snapshots', {
      widget: 'diagnostics/analysis-snapshots',
    });
    return body.data || body;
  }

  async function loadBuildInfo() {
    const body = await getJson('/api/diagnostics/build-info', {
      widget: 'diagnostics/build-info',
    });
    return body.data || body;
  }

  async function loadFailedRequestsDiagnostics({ limit = 50, offset = 0 } = {}) {
    const q = new URLSearchParams();
    if (limit != null) q.set('limit', String(limit));
    if (offset != null) q.set('offset', String(offset));
    const body = await getJson(`/api/diagnostics/failed-requests?${q.toString()}`, {
      widget: 'diagnostics/failed-requests',
    });
    return body.data || body;
  }

  async function loadLatestBuildInfo() {
    const body = await requestJson('/api/build-info');
    return body.data || body;
  }

  async function hardReload() {
    if (window.caches) {
      try {
        const keys = await window.caches.keys();
        await Promise.all(keys.map((key) => caches.delete(key)));
      } catch {
        // Best-effort cache purge before reload.
      }
    }
    if (navigator.serviceWorker) {
      try {
        const registrations = await navigator.serviceWorker.getRegistrations();
        await Promise.all(registrations.map((reg) => reg.unregister()));
      } catch {
        // Service workers are not used in this app.
      }
    }

    stripCacheBustQuery();
    try {
      await fetch(window.location.pathname, { cache: 'reload', credentials: 'same-origin' });
    } catch {
      // Reload below still runs if the prefetch fails.
    }
    window.location.reload();
  }

  async function loadObservation(id) {
    const body = await getJson(`/api/observations/${encodeURIComponent(id)}`, { widget: 'observations/get' });
    return body.data;
  }

  async function createObservation(payload) {
    return requestJson('/api/observations', { method: 'POST', body: payload });
  }

  async function updateObservation(id, payload) {
    return requestJson(`/api/observations/${encodeURIComponent(id)}`, { method: 'PUT', body: payload });
  }

  async function deleteObservation(id) {
    return requestJson(`/api/observations/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async function materializeObservation(id) {
    return requestJson(`/api/observations/${encodeURIComponent(id)}/materialize`, { method: 'POST', body: {} });
  }

  async function previewObservation(id, payload = {}) {
    return requestJson(`/api/observations/${encodeURIComponent(id)}/preview`, { method: 'POST', body: payload });
  }

  async function runObservationReport(id) {
    return requestJson(`/api/observations/${encodeURIComponent(id)}/run`, { method: 'POST', body: {} });
  }

  async function loadObservationRuns(id) {
    const body = await getJson(`/api/observations/${encodeURIComponent(id)}/runs`, { widget: 'observations/runs' });
    return body.data || [];
  }

  async function duplicateObservation(id) {
    return requestJson(`/api/observations/${encodeURIComponent(id)}/duplicate`, { method: 'POST', body: {} });
  }

  async function cancelObservationMaterialize(id) {
    return requestJson(`/api/observations/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {} });
  }

  function observationRunArtifactUrl(observationId, runId, file = 'report.html') {
    const q = new URLSearchParams({ file: String(file || 'report.html') });
    return `/api/observations/${encodeURIComponent(observationId)}/runs/${encodeURIComponent(runId)}/artifact?${q}`;
  }

  async function loadSmtpSettings() {
    const body = await getJson('/api/settings/smtp', { widget: 'settings/smtp' });
    return body.data;
  }

  async function saveSmtpSettings(payload) {
    return requestJson('/api/settings/smtp', { method: 'PUT', body: payload });
  }

  async function testSmtpSettings(to) {
    return requestJson('/api/settings/smtp/test', { method: 'POST', body: { to } });
  }

  async function loadErpPiterixStatus() {
    const body = await requestJson('/api/erp-piterix/status');
    return body.data;
  }

  async function loadErpPiterixJournal() {
    const body = await requestJson('/api/erp-piterix/journal');
    return body.data || [];
  }

  async function saveErpPiterixSettings(payload) {
    const body = await requestJson('/api/erp-piterix/settings', { method: 'PUT', body: payload });
    return body.data;
  }

  async function runErpPiterixSync(payload) {
    const body = await requestJson('/api/erp-piterix/run', { method: 'POST', body: payload });
    return body.data;
  }

  function erpPiterixReportUrl(runId) {
    return `/api/erp-piterix/runs/${encodeURIComponent(runId)}/report.csv`;
  }

  async function loadDetectionLatest() {
    const body = await requestJson('/api/detection/latest');
    return body.data;
  }

  async function loadDetectionHistory({ scope, scopeId, proto, metric, hours, from, to } = {}) {
    const params = new URLSearchParams();
    params.set('scope', scope);
    params.set('scopeId', scopeId);
    params.set('proto', proto || 'all');
    params.set('metric', metric);
    if (from && to) {
      params.set('from', from);
      params.set('to', to);
    } else if (hours) {
      params.set('hours', String(hours));
    }
    const body = await requestJson(`/api/detection/history?${params}`);
    return body.data;
  }

  async function loadDetectionTelegramSettings() {
    const body = await requestJson('/api/detection/telegram');
    return body.data;
  }

  async function saveDetectionTelegramSettings(payload) {
    const body = await requestJson('/api/detection/telegram', { method: 'PUT', body: payload });
    return body.data;
  }

  async function testDetectionTelegramSettings() {
    return requestJson('/api/detection/telegram/test', { method: 'POST', body: {} });
  }

  async function loadDetectionEvents({ status = 'active', limit = 200, from, to } = {}) {
    const params = new URLSearchParams();
    params.set('status', status);
    params.set('limit', String(limit));
    if (from) params.set('from', from);
    if (to) params.set('to', to);
    const body = await requestJson(`/api/detection/events?${params}`);
    return body.data;
  }

  async function exportDetectionEventsCsv({ status = 'normalized', from, to, limit = 10000 } = {}) {
    const params = new URLSearchParams();
    params.set('status', status);
    params.set('limit', String(limit));
    if (from) params.set('from', from);
    if (to) params.set('to', to);
    const res = await fetch(`/api/detection/events/export?${params}`, {
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `HTTP ${res.status}`);
    }
    const count = Number(res.headers.get('X-Detection-Events-Count') || 0);
    const blob = await res.blob();
    return { blob, count };
  }

  function countryQuery({ timeRange = '24h', customPeriod, directions, basis = 'ip', mapSide = 'remote', sourceIds, collectorFilter } = {}) {
    const params = new URLSearchParams();
    appendCustomPeriodParams(params, timeRange, customPeriod);
    params.set('directions', resolveProtocolSqlDirections(directions).join(','));
    params.set('basis', basis || 'ip');
    params.set('map_side', mapSide || 'remote');
    if (sourceIds?.length) params.set('source_ids', sourceIds.join(','));
    appendCollectorFilter(params, collectorFilter);
    return params.toString();
  }

  async function dashboardCountries({ timeRange = '24h', customPeriod, directions, basis = 'ip', mapSide = 'remote', sourceIds, collectorFilter } = {}) {
    const qs = countryQuery({ timeRange, customPeriod, directions, basis, mapSide, sourceIds, collectorFilter });
    const body = await getJson(`/api/dashboard/countries?${qs}`, { widget: 'dashboard/countries' });
    return body.data;
  }

  async function loadCountries({ timeRange = '24h', customPeriod, directions, basis = 'ip', mapSide = 'remote', sourceIds, collectorFilter } = {}) {
    const finish = DashboardLog?.widgetStart?.('countries') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const health = await checkHealth();
    if (!health.connected) {
      const metrics = finish({ source: 'error', rows: 0 });
      return { source: 'error', rows: [], error: LOAD_FAILED, loadMs: metrics.loadMs, serverMs: null };
    }
    const qs = countryQuery({ timeRange, customPeriod, directions, basis, mapSide, sourceIds, collectorFilter });
    const result = await fetchDashboard(`/api/dashboard/countries?${qs}`, 'dashboard/countries');
    if (!result.ok) {
      console.warn('[ApiClient] countries failed:', result.error?.message);
      const metrics = finish({ source: 'error', error: result.error?.message, rows: 0 });
      return { source: 'error', rows: [], error: LOAD_FAILED, loadMs: metrics.loadMs, serverMs: null };
    }
    const rows = Array.isArray(result.data) ? result.data : [];
    const metrics = finish({ source: 'clickhouse', rows: rows.length });
    return { source: 'clickhouse', rows, loadMs: metrics.loadMs, serverMs: result.serverMs };
  }

  function talkersQuery({ timeRange = '1h', customPeriod, directions, group = 'src', limit = 7, offset = 0, sourceIds, collectorFilter } = {}) {
    const params = new URLSearchParams();
    appendCustomPeriodParams(params, timeRange, customPeriod);
    params.set('directions', resolveProtocolSqlDirections(directions).join(','));
    params.set('group', group || 'src');
    params.set('limit', String(limit));
    if (offset > 0) params.set('offset', String(offset));
    if (sourceIds?.length) params.set('source_ids', sourceIds.join(','));
    appendCollectorFilter(params, collectorFilter);
    return params.toString();
  }

  async function dashboardTopTalkers({ timeRange = '1h', customPeriod, directions, group = 'src', limit = 7, sourceIds, collectorFilter } = {}) {
    const qs = talkersQuery({ timeRange, customPeriod, directions, group, limit, sourceIds, collectorFilter });
    const body = await getJson(`/api/dashboard/top-talkers?${qs}`, { widget: 'dashboard/top-talkers' });
    return body.data;
  }

  function dnsOverviewQuery({
    timeRange = '24h',
    customPeriod,
    sourceIds,
    collectorFilter,
    hideResolvers,
    limit,
  } = {}) {
    const params = new URLSearchParams();
    appendCustomPeriodParams(params, timeRange, customPeriod);
    if (sourceIds?.length) params.set('source_ids', sourceIds.join(','));
    appendCollectorFilter(params, collectorFilter);
    if (hideResolvers !== undefined) params.set('hide_resolvers', hideResolvers ? '1' : '0');
    if (limit != null) params.set('limit', String(limit));
    return params.toString();
  }

  /** @deprecated use dnsOverviewQuery for overview widgets */
  function dnsQuery(opts) {
    return dnsOverviewQuery(opts);
  }

  async function loadDnsExplorerSchema() {
    const body = await getJson('/api/dns-explorer/schema', { widget: 'dns-explorer/schema' });
    return body.data;
  }

  async function runDnsExplorerQuery(payload) {
    try {
      const res = await requestJson('/api/dns-explorer/query', { method: 'POST', body: payload });
      return {
        ok: true,
        source: 'clickhouse',
        data: res.data,
        meta: res.meta,
        snapshotId: res.meta?.snapshotId ?? null,
        snapshotExpiresAt: res.meta?.snapshotExpiresAt ?? null,
        loadMs: res.loadMs ?? null,
        serverMs: res.meta?.elapsedMs ?? null,
      };
    } catch (err) {
      return {
        ok: false,
        source: 'error',
        error: err,
        message: err.message || LOAD_FAILED,
        loadMs: err.loadMs ?? null,
        serverMs: null,
      };
    }
  }

  function explorerSnapshotApiBase(cabinetMode = false) {
    return cabinetMode ? '/api/cabinet/explorer/snapshots' : '/api/explorer/snapshots';
  }

  function mapExplorerSharedSnapshot(data) {
    const q = data?.query || {};
    const timeRange = q.range === 'custom' ? 'custom' : (q.range || '1h');
    const customPeriod = timeRange === 'custom'
      ? { from: q.from, to: q.to }
      : null;
    const payload = data?.payload || {};
    return {
      snapshot: {
        timeRange,
        customPeriod,
        filters: q.filters || [],
        thresholds: q.thresholds || [],
        metric: q.metric || 'bps',
        groupBy: q.groupBy || [],
        limit: q.limit || 25,
      },
      payload: {
        rows: payload.rows || [],
        summary: payload.summary || null,
        timeseries: payload.timeseries || [],
        resultSeries: payload.resultSeries || null,
        meta: payload.meta || null,
        loadMs: payload.loadMs ?? null,
        serverMs: payload.serverMs ?? null,
      },
      shareMeta: data?.meta || null,
    };
  }

  function mapDnsExplorerSharedSnapshot(data) {
    const q = data?.query || {};
    const timeRange = q.range === 'custom' ? 'custom' : (q.range || '24h');
    const customPeriod = timeRange === 'custom'
      ? { from: q.from, to: q.to }
      : null;
    const payload = data?.payload || {};
    const collectorFilter = q.collectorId
      ? String(q.collectorId).split(',').map((v) => v.trim()).filter(Boolean)
      : [];
    return {
      snapshot: {
        metric: q.metric || 'queries_per_sec',
        groupBy: q.groupBy || [],
        filters: q.filters || [],
        timeRange,
        customPeriod,
        collectorFilter,
      },
      payload: {
        rows: payload.rows || [],
        timeseries: payload.timeseries || [],
        resultSeries: payload.resultSeries || null,
        meta: payload.meta || null,
        loadMs: payload.loadMs ?? null,
        serverMs: payload.serverMs ?? null,
      },
      shareMeta: data?.meta || null,
    };
  }

  async function shareExplorerSnapshot(snapshotId, cabinetMode = false) {
    const base = explorerSnapshotApiBase(cabinetMode);
    const body = await requestJson(`${base}/${encodeURIComponent(snapshotId)}/share`, { method: 'POST' });
    return body.data;
  }

  async function loadExplorerSharedSnapshot(token, cabinetMode = false) {
    const base = explorerSnapshotApiBase(cabinetMode);
    try {
      const body = await getJson(`${base}/shared/${encodeURIComponent(token)}`, { widget: 'explorer/snapshot' });
      return { ok: true, ...mapExplorerSharedSnapshot(body.data) };
    } catch (err) {
      return { ok: false, message: err.message, status: err.status || 0 };
    }
  }

  async function revokeExplorerSnapshotShare(snapshotId, cabinetMode = false) {
    const base = explorerSnapshotApiBase(cabinetMode);
    return requestJson(`${base}/${encodeURIComponent(snapshotId)}/share`, { method: 'DELETE' });
  }

  async function shareDnsExplorerSnapshot(snapshotId) {
    const body = await requestJson(`/api/dns-explorer/snapshots/${encodeURIComponent(snapshotId)}/share`, { method: 'POST' });
    return body.data;
  }

  async function loadDnsExplorerSharedSnapshot(token) {
    try {
      const body = await getJson(`/api/dns-explorer/snapshots/shared/${encodeURIComponent(token)}`, { widget: 'dns-explorer/snapshot' });
      return { ok: true, ...mapDnsExplorerSharedSnapshot(body.data) };
    } catch (err) {
      return { ok: false, message: err.message, status: err.status || 0 };
    }
  }

  async function revokeDnsExplorerSnapshotShare(snapshotId) {
    return requestJson(`/api/dns-explorer/snapshots/${encodeURIComponent(snapshotId)}/share`, { method: 'DELETE' });
  }

  async function exportDnsExplorerCsv(queryBody = {}) {
    const body = { ...queryBody };
    if (body.collectorFilter?.length) {
      body.collectorId = body.collectorFilter.join(',');
    }
    delete body.collectorFilter;
    if (body.from && body.to) {
      body.range = 'custom';
      delete body.timeRange;
      delete body.customPeriod;
    } else if (body.timeRange === 'custom' && body.customPeriod?.from && body.customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(body.customPeriod);
      body.range = 'custom';
      body.from = apiPeriod.from;
      body.to = apiPeriod.to;
    } else if (body.timeRange) {
      body.range = body.timeRange;
    }
    delete body.customPeriod;
    delete body.timeRange;
    const res = await fetch('/api/dns-explorer/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `HTTP ${res.status}`);
    }
    return res.blob();
  }

  async function suggestDnsExplorerDomains(ctx, q) {
    const params = new URLSearchParams(dnsOverviewQuery(ctx));
    if (ctx.filters?.length) params.set('filters', encodeURIComponent(JSON.stringify(ctx.filters)));
    if (q) params.set('q', q);
    const body = await getJson(`/api/dns-explorer/suggest/domains?${params}`, { widget: 'dns-explorer/suggest/domains' });
    return body.data || [];
  }

  async function suggestDnsExplorerClientIps(ctx, q) {
    const params = new URLSearchParams(dnsOverviewQuery(ctx));
    if (ctx.filters?.length) params.set('filters', encodeURIComponent(JSON.stringify(ctx.filters)));
    if (q) params.set('q', q);
    const body = await getJson(`/api/dns-explorer/suggest/client-ips?${params}`, { widget: 'dns-explorer/suggest/client-ips' });
    return body.data || [];
  }

  async function suggestDnsExplorerServerIps(ctx, q) {
    const params = new URLSearchParams(dnsOverviewQuery(ctx));
    if (ctx.filters?.length) params.set('filters', encodeURIComponent(JSON.stringify(ctx.filters)));
    if (q) params.set('q', q);
    const body = await getJson(`/api/dns-explorer/suggest/server-ips?${params}`, { widget: 'dns-explorer/suggest/server-ips' });
    return body.data || [];
  }

  async function suggestDnsExplorerQtypes(ctx) {
    const params = new URLSearchParams(dnsOverviewQuery(ctx));
    if (ctx.filters?.length) params.set('filters', encodeURIComponent(JSON.stringify(ctx.filters)));
    const body = await getJson(`/api/dns-explorer/suggest/qtypes?${params}`, { widget: 'dns-explorer/suggest/qtypes' });
    return body.data || [];
  }

  async function suggestDnsExplorerAnswers(ctx, q) {
    const params = new URLSearchParams(dnsOverviewQuery(ctx));
    if (ctx.filters?.length) params.set('filters', encodeURIComponent(JSON.stringify(ctx.filters)));
    if (q) params.set('q', q);
    const body = await getJson(`/api/dns-explorer/suggest/answers?${params}`, { widget: 'dns-explorer/suggest/answers' });
    return body.data || [];
  }

  async function fetchDns(path, widget) {
    try {
      const body = await getJson(path, { widget });
      return {
        ok: true,
        data: body.data,
        meta: body.meta,
        loadMs: body.loadMs,
        serverMs: body.serverMs,
      };
    } catch (err) {
      return {
        ok: false,
        loadMs: err.loadMs ?? null,
        serverMs: null,
        error: err,
      };
    }
  }

  async function loadDnsWidget(path, widget, filters) {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', data: null, rows: [], error: LOAD_FAILED, loadMs: null, serverMs: null };
    }
    const qs = dnsOverviewQuery(filters);
    const result = await fetchDns(`${path}?${qs}`, widget);
    if (!result.ok) {
      return {
        source: 'error',
        data: null,
        rows: [],
        error: LOAD_FAILED,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    const data = result.data;
    const rows = Array.isArray(data) ? data : (data ? [data] : []);
    return {
      source: 'clickhouse',
      data,
      rows,
      meta: result.meta,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadDnsSources() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDns('/api/dns/sources', 'dns/sources');
    if (!result.ok) return { source: 'error', rows: [], error: LOAD_FAILED };
    return { source: 'clickhouse', rows: Array.isArray(result.data) ? result.data : [] };
  }

  async function loadDnsActivity(filters) {
    return loadDnsWidget('/api/dns/activity', 'dns/activity', filters);
  }

  async function loadDnsTopDomains(filters) {
    return loadDnsWidget('/api/dns/top-domains', 'dns/top-domains', filters);
  }

  async function loadDnsTopClients(filters) {
    return loadDnsWidget('/api/dns/top-clients', 'dns/top-clients', filters);
  }

  async function loadDnsTopServers(filters) {
    return loadDnsWidget('/api/dns/top-servers', 'dns/top-servers', filters);
  }

  async function loadDnsRecent(filters) {
    return loadDnsWidget('/api/dns/recent', 'dns/recent', filters);
  }

  async function loadDnsQtypes(filters) {
    return loadDnsWidget('/api/dns/qtypes', 'dns/qtypes', filters);
  }

  async function loadTopTalkers({ timeRange = '1h', customPeriod, directions, group = 'src', limit = 7, offset = 0, sourceIds, collectorFilter } = {}) {
    const finish = DashboardLog?.widgetStart?.('top-talkers') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const health = await checkHealth();
    if (!health.connected) {
      const metrics = finish({ source: 'error', rows: 0 });
      return {
        source: 'error',
        rows: [],
        meta: null,
        hasMore: false,
        error: LOAD_FAILED,
        loadMs: metrics.loadMs,
        serverMs: null,
      };
    }
    const qs = talkersQuery({ timeRange, customPeriod, directions, group, limit, offset, sourceIds, collectorFilter });
    const result = await fetchDashboard(`/api/dashboard/top-talkers?${qs}`, 'dashboard/top-talkers');
    if (!result.ok) {
      console.warn('[ApiClient] top-talkers failed:', result.error?.message);
      const metrics = finish({ source: 'error', error: result.error?.message, rows: 0 });
      return {
        source: 'error',
        rows: [],
        meta: null,
        hasMore: false,
        error: result.error?.message,
        loadMs: metrics.loadMs,
        serverMs: null,
      };
    }
    const rows = Array.isArray(result.data) ? result.data : [];
    const metrics = finish({ source: 'clickhouse', rows: rows.length });
    return {
      source: 'clickhouse',
      rows,
      meta: result.meta || null,
      hasMore: result.meta?.hasMore ?? rows.length >= limit,
      loadMs: metrics.loadMs,
      serverMs: result.serverMs,
    };
  }

  function recentFlowsQuery({ directions, limit = 20, collectorFilter } = {}) {
    const params = new URLSearchParams({ limit: String(limit) });
    params.set('directions', resolveProtocolSqlDirections(directions).join(','));
    appendCollectorFilter(params, collectorFilter);
    return params.toString();
  }

  async function dashboardRecentFlows({ limit = 20, directions } = {}) {
    const qs = recentFlowsQuery({ directions, limit });
    const body = await getJson(`/api/dashboard/recent-flows?${qs}`, { widget: 'dashboard/recent-flows' });
    return body.data;
  }

  async function loadRecentFlows({ directions, limit = 20, collectorFilter } = {}) {
    const finish = DashboardLog?.widgetStart?.('recent-flows') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const health = await checkHealth();
    if (!health.connected) {
      const metrics = finish({ source: 'error' });
      return { source: 'error', rows: [], error: LOAD_FAILED, loadMs: metrics.loadMs, serverMs: null };
    }
    const qs = recentFlowsQuery({ directions, limit, collectorFilter });
    const result = await fetchDashboard(`/api/dashboard/recent-flows?${qs}`, 'dashboard/recent-flows');
    if (!result.ok) {
      const metrics = finish({ source: 'error', error: result.error?.message });
      return { source: 'error', rows: [], error: LOAD_FAILED, loadMs: metrics.loadMs, serverMs: null };
    }
    const metrics = finish({ source: 'clickhouse', rows: (result.data || []).length });
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: metrics.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadL3Prefixes() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/l3-prefixes', 'refs/l3-prefixes');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadNetEntities() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/entities', 'refs/entities');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function saveL3Prefix(payload) {
    const res = await fetch('/api/refs/l3-prefixes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function toggleL3Prefix({ prefix, family, enabled }) {
    const res = await fetch('/api/refs/l3-prefixes/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify({ prefix, family, enabled }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function deleteL3Prefix({ prefix, family }) {
    const res = await fetch('/api/refs/l3-prefixes', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify({ prefix, family }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function loadDnsResolvers() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/dns-resolvers', 'refs/dns-resolvers');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function saveDnsResolver(payload) {
    const res = await fetch('/api/refs/dns-resolvers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function toggleDnsResolver({ resolverId, enabled }) {
    const res = await fetch('/api/refs/dns-resolvers/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify({ resolverId, enabled }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function deleteDnsResolver({ resolverId }) {
    const res = await fetch('/api/refs/dns-resolvers', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify({ resolverId }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function loadFlowExclusions() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], stats: null, error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/flow-exclusions', 'refs/flow-exclusions');
    if (!result.ok) {
      return { source: 'error', rows: [], stats: null, error: LOAD_FAILED };
    }
    const meta = result.meta || {};
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      stats: {
        rulesTotal: meta.rulesTotal ?? 0,
        rulesEnabled: meta.rulesEnabled ?? 0,
        excludedPackets24h: meta.excludedPackets24h ?? 0,
        excludedBytes24h: meta.excludedBytes24h ?? 0,
      },
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function saveFlowExclusion(payload) {
    const res = await fetch('/api/refs/flow-exclusions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function toggleFlowExclusion({ ruleId, enabled }) {
    const res = await fetch('/api/refs/flow-exclusions/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify({ ruleId, enabled }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function deleteFlowExclusion({ ruleId }) {
    const res = await fetch('/api/refs/flow-exclusions', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify({ ruleId }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function loadNetEntitiesAdmin() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/net-entities', 'refs/net-entities');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function saveNetEntity(payload) {
    const res = await fetch('/api/refs/net-entities', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function loadPortServices({ search, transport, category } = {}) {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const params = new URLSearchParams();
    if (search) params.set('search', search);
    if (transport) params.set('transport', transport);
    if (category) params.set('category', category);
    const qs = params.toString();
    const path = `/api/refs/port-services${qs ? `?${qs}` : ''}`;
    const result = await fetchDashboard(path, 'refs/port-services');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function savePortService(payload) {
    const res = await fetch('/api/refs/port-services', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function disablePortService(payload) {
    const res = await fetch('/api/refs/port-services/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function previewPortServiceDefaults() {
    const res = await fetch('/api/refs/port-services/seed-defaults', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function seedPortServiceDefaults() {
    const res = await fetch('/api/refs/port-services/seed-defaults', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: '{}',
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function loadRefVlans() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/vlans', 'refs/vlans');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadRefVlansSeen({ hours = 24, limit = 200 } = {}) {
    const params = new URLSearchParams();
    if (hours) params.set('hours', String(hours));
    if (limit) params.set('limit', String(limit));
    const result = await fetchDashboard(`/api/refs/vlans/seen?${params.toString()}`, 'refs/vlans-seen');
    if (!result.ok) return { source: 'error', rows: [], error: LOAD_FAILED };
    return { source: 'clickhouse', rows: Array.isArray(result.data) ? result.data : [] };
  }

  async function saveRefVlan(payload) {
    const res = await fetch('/api/refs/vlans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function setRefVlanEnabled(payload) {
    const res = await fetch('/api/refs/vlans/enabled', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function deleteRefVlan(payload) {
    const res = await fetch('/api/refs/vlans/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function loadLocations() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/locations', 'refs/locations');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function saveLocation(payload) {
    const res = await fetch('/api/refs/locations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function loadCollectorsAdmin() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/collectors', 'refs/collectors');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function saveCollector(payload) {
    const res = await fetch('/api/refs/collectors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function deleteCollector(payload) {
    return requestJson('/api/refs/collectors/delete', {
      method: 'POST',
      body: payload,
    });
  }

  async function loadFlowSources() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/flow-sources', 'refs/flow-sources');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function bindFlowSource(payload) {
    return requestJson('/api/refs/flow-sources/bind', {
      method: 'POST',
      body: payload,
    });
  }

  async function registerFlowSource(payload) {
    return requestJson('/api/refs/flow-sources', {
      method: 'POST',
      body: payload,
    });
  }

  async function deleteFlowSource(payload) {
    return requestJson('/api/refs/flow-sources/delete', {
      method: 'POST',
      body: payload,
    });
  }

  async function loadSnmpSettings() {
    try {
      const body = await getJson('/api/refs/snmp-settings', { widget: 'refs/snmp-settings' });
      return { source: 'clickhouse', data: body.data || null, meta: body.meta || null };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  async function saveSnmpSettings(payload) {
    return requestJson('/api/refs/snmp-settings', { method: 'POST', body: payload });
  }

  async function loadSnmpAgents() {
    try {
      const body = await getJson('/api/refs/snmp-agents', { widget: 'refs/snmp-agents' });
      return {
        source: 'clickhouse',
        rows: Array.isArray(body.data) ? body.data : [],
        meta: body.meta || null,
      };
    } catch (err) {
      return { source: 'error', rows: [], error: err.message || LOAD_FAILED };
    }
  }

  async function saveSnmpAgent(payload) {
    return requestJson('/api/refs/snmp-agents', { method: 'POST', body: payload });
  }

  async function loadSnmpInterfaces(switchIp) {
    try {
      const body = await getJson(
        `/api/refs/snmp-agents/${encodeURIComponent(switchIp)}/interfaces`,
        { widget: 'refs/snmp-agent-interfaces' },
      );
      return { source: 'clickhouse', rows: Array.isArray(body.data) ? body.data : [] };
    } catch (err) {
      return { source: 'error', rows: [], error: err.message || LOAD_FAILED };
    }
  }

  async function requestSnmpProbe(switchIp) {
    return requestJson(`/api/refs/snmp-agents/${encodeURIComponent(switchIp)}/probe`, {
      method: 'POST',
    });
  }

  async function requestSnmpProbeAll() {
    return requestJson('/api/refs/snmp-agents/probe-all', {
      method: 'POST',
    });
  }

  async function deleteSnmpAgent(switchIp) {
    return requestJson(`/api/refs/snmp-agents/${encodeURIComponent(switchIp)}`, {
      method: 'DELETE',
    });
  }

  async function loadCollectorOptions() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    const result = await fetchDashboard('/api/refs/collectors/options', 'refs/collectors-options');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadDiscoveredSources() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED, meta: null };
    }
    const result = await fetchDashboard('/api/collectors/discovered', 'collectors/discovered');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED, meta: null };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCollectorOverview() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', data: null, error: LOAD_FAILED, meta: null };
    }
    const result = await fetchDashboard('/api/collectors/overview', 'collectors/overview');
    if (!result.ok) {
      return { source: 'error', data: null, error: LOAD_FAILED, meta: null };
    }
    return {
      source: 'clickhouse',
      data: result.data || null,
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadTtl() {
    const body = await requestJson('/api/admin/ttl');
    return { data: body.data || [], disk: body.disk || null };
  }

  async function loadAudit({ from, to, q, ip, kind, result, limit, offset } = {}) {
    const params = new URLSearchParams();
    if (from) params.set('from', from);
    if (to) params.set('to', to);
    if (q) params.set('q', q);
    if (ip) params.set('ip', ip);
    if (kind) params.set('kind', kind);
    if (result) params.set('result', result);
    if (limit != null) params.set('limit', String(limit));
    if (offset != null) params.set('offset', String(offset));
    const qs = params.toString();
    return requestJson(`/api/audit${qs ? `?${qs}` : ''}`);
  }

  function reportAuditPage(pageId) {
    if (!pageId) return Promise.resolve();
    return requestJson('/api/audit/page', {
      method: 'POST',
      body: { pageId },
    }).catch(() => {});
  }

  async function updateTtl(id, days) {
    const body = await requestJson(`/api/admin/ttl/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: { days },
    });
    return body;
  }

  async function loadDirectionSettings() {
    try {
      const body = await requestJson('/api/refs/direction-settings');
      return { source: 'clickhouse', data: body.data || null };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  async function saveDirectionSettings(payload) {
    return requestJson('/api/refs/direction-settings', { method: 'POST', body: payload });
  }

  async function loadInterfaceRoleRules() {
    try {
      const body = await getJson('/api/refs/interface-role-rules', { widget: 'refs/interface-role-rules' });
      return {
        source: 'clickhouse',
        rows: Array.isArray(body.data) ? body.data : [],
        meta: body.meta || null,
      };
    } catch (err) {
      return { source: 'error', rows: [], error: err.message || LOAD_FAILED };
    }
  }

  async function saveInterfaceRoleRule(payload) {
    return requestJson('/api/refs/interface-role-rules', { method: 'POST', body: payload });
  }

  async function deleteInterfaceRoleRule(payload) {
    return requestJson('/api/refs/interface-role-rules/delete', { method: 'POST', body: payload });
  }

  async function previewInterfaceRoleRule(payload) {
    try {
      const body = await requestJson('/api/refs/interface-role-rules/preview', { method: 'POST', body: payload });
      return { source: 'clickhouse', data: body.data || { total: 0, interfaces: [] }, meta: body.meta || null };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  async function loadInterfaceRoleSummary() {
    try {
      const body = await getJson('/api/refs/interface-roles/summary', { widget: 'refs/interface-roles-summary' });
      return { source: 'clickhouse', data: body.data || null, meta: body.meta || null };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  async function loadInterfaceRoleSwitches() {
    try {
      const body = await getJson('/api/refs/interface-roles/switches', { widget: 'refs/interface-roles-switches' });
      return {
        source: 'clickhouse',
        rows: Array.isArray(body.data) ? body.data : [],
        meta: body.meta || null,
      };
    } catch (err) {
      return { source: 'error', rows: [], error: err.message || LOAD_FAILED };
    }
  }

  async function loadInterfaceRolesForSwitch(switchIp) {
    try {
      const body = await getJson(
        `/api/refs/interface-roles/${encodeURIComponent(switchIp)}`,
        { widget: 'refs/interface-roles' },
      );
      return { source: 'clickhouse', rows: Array.isArray(body.data) ? body.data : [], meta: body.meta || null };
    } catch (err) {
      return { source: 'error', rows: [], error: err.message || LOAD_FAILED };
    }
  }

  async function saveInterfaceRole(payload) {
    return requestJson('/api/refs/interface-roles', { method: 'POST', body: payload });
  }

  async function deleteInterfaceRole(payload) {
    return requestJson('/api/refs/interface-roles/delete', { method: 'POST', body: payload });
  }

  async function rebuildInterfaceRoles() {
    return requestJson('/api/refs/interface-roles/rebuild', { method: 'POST' });
  }

  function directionInterfacesQuery(params = {}) {
    const q = new URLSearchParams();
    if (params.hours != null) q.set('hours', String(params.hours));
    if (params.limit != null) q.set('limit', String(params.limit));
    if (params.onlyUnmarked) q.set('only_unmarked', '1');
    if (params.asnThreshold != null) q.set('asn_threshold', String(params.asnThreshold));
    if (params.switchIp) q.set('switch_ip', params.switchIp);
    const s = q.toString();
    return s ? `?${s}` : '';
  }

  async function loadDirectionCoverage(hours = 1) {
    try {
      const body = await getJson(
        `/api/diagnostics/direction/coverage?hours=${encodeURIComponent(hours)}`,
        { widget: 'diagnostics/direction-coverage' },
      );
      return { source: 'clickhouse', data: body.data || null, meta: body.meta || null };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  async function loadDirectionCompare({ hours = 1, oneSided } = {}) {
    try {
      const q = new URLSearchParams({ hours: String(hours) });
      if (oneSided) q.set('one_sided', oneSided);
      const body = await getJson(
        `/api/diagnostics/direction/compare?${q.toString()}`,
        { widget: 'diagnostics/direction-compare' },
      );
      return { source: 'clickhouse', data: body.data || null, meta: body.meta || null };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  async function loadDirectionInterfaces(params = {}) {
    try {
      const body = await getJson(
        `/api/diagnostics/direction/interfaces${directionInterfacesQuery(params)}`,
        { widget: 'diagnostics/direction-interfaces' },
      );
      const payload = body.data;
      const rows = Array.isArray(payload) ? payload : (payload?.rows || []);
      const stats = Array.isArray(payload) ? null : (payload?.stats || null);
      return { source: 'clickhouse', rows, stats, meta: body.meta || null };
    } catch (err) {
      return { source: 'error', rows: [], stats: null, error: err.message || LOAD_FAILED };
    }
  }

  async function loadCollectorStatus() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED, meta: null };
    }
    const result = await fetchDashboard('/api/collectors/status', 'collectors/status');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED, meta: null };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCollectorCompleteness() {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', rows: [], error: LOAD_FAILED, meta: null };
    }
    const result = await fetchDashboard('/api/collectors/completeness', 'collectors/completeness');
    if (!result.ok) {
      return { source: 'error', rows: [], error: LOAD_FAILED, meta: null };
    }
    return {
      source: 'clickhouse',
      rows: Array.isArray(result.data) ? result.data : [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  function pipelineQueryString(sourceId, window) {
    const q = new URLSearchParams();
    if (sourceId) q.set('sourceId', sourceId);
    if (window) q.set('window', window);
    const s = q.toString();
    return s ? `?${s}` : '';
  }

  async function loadCompletenessDetail(sourceId, window = '30m') {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', data: null, error: LOAD_FAILED };
    }
    try {
      const body = await getJson(`/api/collectors/completeness/detail${pipelineQueryString(sourceId, window)}`, {
        widget: 'collectors/completeness/detail',
      });
      return { source: 'clickhouse', data: body };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  async function loadCompletenessHistory(sourceId, window = '24h') {
    const health = await checkHealth();
    if (!health.connected) {
      return { source: 'error', data: null, error: LOAD_FAILED };
    }
    try {
      const body = await getJson(`/api/collectors/completeness/history${pipelineQueryString(sourceId, window)}`, {
        widget: 'collectors/completeness/history',
      });
      return { source: 'clickhouse', data: body };
    } catch (err) {
      return { source: 'error', data: null, error: err.message || LOAD_FAILED };
    }
  }

  function bmpQueryString(params = {}) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v != null && v !== '') q.set(k, String(v));
    }
    const s = q.toString();
    return s ? `?${s}` : '';
  }

  async function loadBmpSummary() {
    return requestJson('/api/bmp/summary');
  }

  async function loadBmpPeers(params = {}) {
    return requestJson(`/api/bmp/peers${bmpQueryString(params)}`);
  }

  async function loadBmpRouters() {
    return requestJson('/api/bmp/routers');
  }

  async function loadBmpRoutes(params = {}) {
    return requestJson(`/api/bmp/routes${bmpQueryString(params)}`);
  }

  async function loadBmpEvents(params = {}) {
    return requestJson(`/api/bmp/events${bmpQueryString(params)}`);
  }

  async function loadBmpCounts(params = {}) {
    return requestJson(`/api/bmp/counts${bmpQueryString(params)}`);
  }

  async function loadBmpChurn(params = {}) {
    return requestJson(`/api/bmp/churn${bmpQueryString(params)}`);
  }

  async function loadBmpFlap(params = {}) {
    return requestJson(`/api/bmp/flap${bmpQueryString(params)}`);
  }

  async function settledValue(result, fallback) {
    return result.status === 'fulfilled' ? result.value : fallback;
  }

  function enrichChartSeries(series) {
    if (!series?.points?.length || !series?.lines?.length) return null;
    const points = series.points.map((pt) => {
      const next = { ...pt };
      for (const ln of series.lines) {
        const f = `${ln.key}_pps`;
        if (next[f] == null && ln.key === 'total' && next.pps != null) {
          next[f] = Number(next.pps) || 0;
        }
      }
      return next;
    });
    const hasPps = points.some((pt) => series.lines.some((ln) => pt[`${ln.key}_pps`] != null));
    return hasPps ? { points, lines: series.lines } : null;
  }

  const emptyDashboardPayload = () => ({
    series: { points: [], lines: [] },
    protocols: [],
    services: [],
  });

  const CABINET_TIME_RANGE_HOURS = {
    '30m': 1,
    '1h': 1,
    '3h': 3,
    '6h': 6,
    '12h': 12,
    '24h': 24,
    '2d': 48,
    '7d': 168,
    '14d': 336,
    '30d': 720,
  };

  function cabinetRangeQuery({ timeRange = '24h', customPeriod } = {}) {
    const params = new URLSearchParams();
    if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(customPeriod);
      params.set('from', apiPeriod.from);
      params.set('to', apiPeriod.to);
    } else {
      params.set('hours', String(CABINET_TIME_RANGE_HOURS[timeRange] || 24));
    }
    return params;
  }

  async function fetchCabinet(path, widget) {
    try {
      const body = await getJson(path, { widget });
      return {
        ok: true,
        data: body.data,
        meta: body.meta,
        loadMs: body.loadMs,
        serverMs: body.serverMs,
      };
    } catch (err) {
      return {
        ok: false,
        loadMs: err.loadMs ?? null,
        serverMs: null,
        error: err,
      };
    }
  }

  async function loadCabinetOverviewSeries({ timeRange = '24h', customPeriod, granularity = 'auto' } = {}) {
    const params = cabinetRangeQuery({ timeRange, customPeriod });
    params.set('granularity', granularity || 'auto');
    const result = await fetchCabinet(`/api/cabinet/overview/series?${params}`, 'cabinet/overview/series');
    if (!result.ok) {
      return {
        source: 'error',
        data: [],
        meta: null,
        error: result.error?.message || LOAD_FAILED,
        status: result.error?.status || 0,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    return {
      source: 'clickhouse',
      data: result.data || [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCabinetOverviewStats({ timeRange = '24h', customPeriod } = {}) {
    const params = cabinetRangeQuery({ timeRange, customPeriod });
    const result = await fetchCabinet(`/api/cabinet/overview/stats?${params}`, 'cabinet/overview/stats');
    if (!result.ok) {
      return {
        source: 'error',
        data: null,
        meta: null,
        error: result.error?.message || LOAD_FAILED,
        status: result.error?.status || 0,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    return {
      source: 'clickhouse',
      data: result.data || null,
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCabinetOverviewCountries({
    timeRange = '24h',
    customPeriod,
    direction,
    limit = 20,
  } = {}) {
    const params = cabinetRangeQuery({ timeRange, customPeriod });
    if (direction) params.set('direction', direction);
    if (limit != null) params.set('limit', String(limit));
    const result = await fetchCabinet(`/api/cabinet/overview/countries?${params}`, 'cabinet/overview/countries');
    if (!result.ok) {
      return {
        source: 'error',
        data: [],
        meta: null,
        error: result.error?.message || LOAD_FAILED,
        status: result.error?.status || 0,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    return {
      source: 'clickhouse',
      data: result.data || [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCabinetOverviewServices({
    timeRange = '24h',
    customPeriod,
    direction,
    limit = 20,
  } = {}) {
    const params = cabinetRangeQuery({ timeRange, customPeriod });
    if (direction) params.set('direction', direction);
    if (limit != null) params.set('limit', String(limit));
    const result = await fetchCabinet(`/api/cabinet/overview/services?${params}`, 'cabinet/overview/services');
    if (!result.ok) {
      return {
        source: 'error',
        data: [],
        meta: null,
        error: result.error?.message || LOAD_FAILED,
        status: result.error?.status || 0,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    return {
      source: 'clickhouse',
      data: result.data || [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCabinetOverviewRecentFlows({ limit = 20 } = {}) {
    const params = new URLSearchParams();
    params.set('limit', String(limit));
    const result = await fetchCabinet(
      `/api/cabinet/overview/recent-flows?${params}`,
      'cabinet/overview/recent-flows',
    );
    if (!result.ok) {
      return {
        source: 'error',
        data: [],
        meta: null,
        error: result.error?.message || LOAD_FAILED,
        status: result.error?.status || 0,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    return {
      source: 'clickhouse',
      data: Array.isArray(result.data) ? result.data : [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCabinetDnsDomains({
    timeRange = '24h',
    customPeriod,
    sourceId,
    limit = 50,
  } = {}) {
    const params = cabinetRangeQuery({ timeRange, customPeriod });
    if (sourceId) params.set('sourceId', sourceId);
    if (limit != null) params.set('limit', String(limit));
    const result = await fetchCabinet(`/api/cabinet/dns/domains?${params}`, 'cabinet/dns/domains');
    if (!result.ok) {
      return {
        source: 'error',
        data: [],
        meta: null,
        error: result.error?.message || LOAD_FAILED,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    return {
      source: 'clickhouse',
      data: result.data || [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadCabinetDnsQueries({
    timeRange = '24h',
    customPeriod,
    domain,
    limit = 100,
  } = {}) {
    const params = cabinetRangeQuery({ timeRange, customPeriod });
    if (domain) params.set('domain', domain);
    if (limit != null) params.set('limit', String(Math.min(Math.max(Number(limit) || 100, 100), 1000)));
    const result = await fetchCabinet(`/api/cabinet/dns/queries?${params}`, 'cabinet/dns/queries');
    if (!result.ok) {
      return {
        source: 'error',
        data: [],
        meta: null,
        error: result.error?.message || LOAD_FAILED,
        loadMs: result.loadMs,
        serverMs: null,
      };
    }
    return {
      source: 'clickhouse',
      data: result.data || [],
      meta: result.meta || null,
      loadMs: result.loadMs,
      serverMs: result.serverMs,
    };
  }

  /** Статистика по направлениям — отдельно от остального dashboard. */
  async function loadTrafficStats({ timeRange = '24h', customPeriod, collectorFilter } = {}) {
    const finish = DashboardLog?.widgetStart?.('traffic-stats') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const health = await checkHealth();
    if (!health.connected) {
      const metrics = finish({ source: 'error' });
      return { source: 'error', trafficStats: null, error: LOAD_FAILED, loadMs: metrics.loadMs, serverMs: null };
    }
    const qs = trafficStatsQuery({ timeRange, customPeriod, collectorFilter });
    const result = await fetchDashboard(`/api/dashboard/traffic-stats?${qs}`, 'dashboard/traffic-stats');
    if (!result.ok) {
      console.warn('[ApiClient] traffic stats failed:', result.error?.message);
      const metrics = finish({ source: 'error', error: result.error?.message });
      return { source: 'error', trafficStats: null, error: LOAD_FAILED, loadMs: metrics.loadMs, serverMs: null };
    }
    const metrics = finish({ source: 'clickhouse' });
    return {
      source: 'clickhouse',
      trafficStats: result.data || null,
      loadMs: metrics.loadMs,
      serverMs: result.serverMs,
    };
  }

  async function loadDashboardLayout() {
    const body = await getJson('/api/dashboard/layout', { widget: 'dashboard/layout' });
    return {
      data: body.data || null,
      updatedAt: body.updatedAt || null,
    };
  }

  async function saveDashboardLayout(layout) {
    return requestJson('/api/dashboard/layout', { method: 'PUT', body: layout });
  }

  async function resetDashboardLayout() {
    return requestJson('/api/dashboard/layout/reset', { method: 'POST', body: {} });
  }

  /** Загрузить данные dashboard из ClickHouse. Ошибка одного блока не сбрасывает остальные. */
  async function loadDashboardData({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
    const finishBatch = DashboardLog?.batchStart?.('main') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const health = await checkHealth();
    if (!health.connected) {
      finishBatch({ source: 'error', widgets: 0 });
      return { source: 'error', error: LOAD_FAILED, ...emptyDashboardPayload(), loadTimings: {} };
    }

    const qsTraffic = chartTrafficQuery({ timeRange, customPeriod, directions, collectorFilter });
    const qsProtocols = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });
    const qsServices = protocolQuery({ timeRange, customPeriod, directions, collectorFilter });

    const [seriesR, protocolsR, servicesR] = await Promise.all([
      fetchDashboard(`/api/dashboard/traffic?${qsTraffic}`, 'dashboard/traffic'),
      fetchDashboard(`/api/dashboard/protocols?${qsProtocols}`, 'dashboard/protocols'),
      fetchDashboard(`/api/dashboard/services?${qsServices}`, 'dashboard/services'),
    ]);

    const loadTimings = {
      series: seriesR.loadMs,
      protocols: protocolsR.loadMs,
      services: servicesR.loadMs,
    };
    const loadServerMs = {
      series: seriesR.serverMs,
      protocols: protocolsR.serverMs,
      services: servicesR.serverMs,
    };

    const okCount = [seriesR, protocolsR, servicesR].filter((r) => r.ok).length;
    const hasAny = okCount > 0;

    if (!hasAny) {
      const err = seriesR.error || protocolsR.error || servicesR.error;
      console.warn('[ApiClient] ClickHouse fetch failed:', err?.message || err);
      finishBatch({ source: 'error', widgets: 0, error: err?.message || String(err) });
      return { source: 'error', error: LOAD_FAILED, ...emptyDashboardPayload(), loadTimings, loadServerMs };
    }

    const chartSeries = seriesR.ok
      ? (enrichChartSeries(seriesR.data) || { points: [], lines: [] })
      : { points: [], lines: [] };
    finishBatch({
      source: hasAny ? 'clickhouse' : 'error',
      widgets: okCount,
    });
    return {
      source: hasAny ? 'clickhouse' : 'error',
      series: chartSeries,
      protocols: protocolsR.ok ? (protocolsR.data || []) : [],
      services: servicesR.ok ? (servicesR.data || []) : [],
      failedWidgets: {
        series: !seriesR.ok,
        protocols: !protocolsR.ok,
        services: !servicesR.ok,
      },
      loadTimings,
      loadServerMs,
    };
  }

  const CABINET_RANGE_HOURS = {
    '30m': 1,
    '1h': 1,
    '3h': 3,
    '6h': 6,
    '12h': 12,
    '24h': 24,
    '2d': 48,
    '7d': 168,
    '14d': 336,
    '30d': 720,
  };

  function cabinetRangeQueryParams(timeRange, customPeriod) {
    if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(customPeriod);
      return { from: apiPeriod.from, to: apiPeriod.to };
    }
    return { hours: CABINET_RANGE_HOURS[timeRange] ?? CABINET_RANGE_HOURS['24h'] };
  }

  function appendCabinetRangeParams(params, timeRange, customPeriod) {
    const rangeParams = cabinetRangeQueryParams(timeRange, customPeriod);
    if (rangeParams.from && rangeParams.to) {
      params.set('from', rangeParams.from);
      params.set('to', rangeParams.to);
    } else {
      params.set('hours', String(rangeParams.hours));
    }
  }

  function appendCabinetRangeBody(body, timeRange, customPeriod) {
    if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(customPeriod);
      body.range = 'custom';
      body.from = apiPeriod.from;
      body.to = apiPeriod.to;
      return;
    }
    body.range = timeRange || '24h';
  }

  async function loadClients() {
    const body = await requestJson('/api/clients');
    return { data: body.data || [], meta: body.meta || null };
  }

  async function createClient(payload) {
    return requestJson('/api/clients', { method: 'POST', body: payload });
  }

  async function updateClient(clientId, payload) {
    return requestJson(`/api/clients/${encodeURIComponent(clientId)}`, {
      method: 'PUT',
      body: payload,
    });
  }

  async function loadClientPrefixes(clientId) {
    const body = await requestJson(`/api/clients/${encodeURIComponent(clientId)}/prefixes`);
    return { data: body.data || [], meta: body.meta || null };
  }

  async function saveClientPrefixes(clientId, { items }) {
    return requestJson(`/api/clients/${encodeURIComponent(clientId)}/prefixes`, {
      method: 'PUT',
      body: { items },
    });
  }

  async function loadClientPorts(clientId) {
    const body = await requestJson(`/api/clients/${encodeURIComponent(clientId)}/ports`);
    return { data: body.data || [], meta: body.meta || null };
  }

  async function saveClientPorts(clientId, { items }) {
    return requestJson(`/api/clients/${encodeURIComponent(clientId)}/ports`, {
      method: 'PUT',
      body: { items },
    });
  }

  async function loadClientPrefixOptions({ q, limit } = {}) {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (limit != null) params.set('limit', String(limit));
    const qs = params.toString();
    const body = await requestJson(`/api/clients/options/prefixes${qs ? `?${qs}` : ''}`);
    return { data: body.data || [], meta: body.meta || null };
  }

  async function loadClientPortOptions({ q, limit } = {}) {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (limit != null) params.set('limit', String(limit));
    const qs = params.toString();
    const body = await requestJson(`/api/clients/options/ports${qs ? `?${qs}` : ''}`);
    return { data: body.data || [], meta: body.meta || null };
  }

  async function impersonateClient(clientId) {
    return requestJson(`/api/clients/${encodeURIComponent(clientId)}/impersonate`, { method: 'POST' });
  }

  async function stopImpersonation() {
    return requestJson('/api/auth/stop-impersonation', { method: 'POST' });
  }

  async function loadImpersonationAudit({ limit } = {}) {
    const params = new URLSearchParams();
    if (limit != null) params.set('limit', String(limit));
    const qs = params.toString();
    return requestJson(`/api/clients/impersonation/audit${qs ? `?${qs}` : ''}`);
  }

  async function loadUsersForClient(clientId) {
    const params = new URLSearchParams({ clientId: String(clientId) });
    const body = await requestJson(`/api/users?${params}`);
    return { data: body.data || [], meta: body.meta || null };
  }

  async function loadCabinetExplorerSchema() {
    const body = await getJson('/api/cabinet/explorer/schema', { widget: 'cabinet/explorer/schema' });
    return body.data;
  }

  async function loadCabinetExplorerQuery({
    metric = 'bps',
    groupBy = [],
    filters = [],
    thresholds = [],
    limit = 10,
    offset = 0,
    timeRange = '1h',
    customPeriod,
    granularity = 'auto',
    includeSummary = true,
    includeTimeseries = true,
    includeBreakdowns = true,
  } = {}) {
    const finish = DashboardLog?.widgetStart?.('cabinet/explorer/query') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const body = {
      metric,
      groupBy,
      filters,
      thresholds: Array.isArray(thresholds) ? thresholds : [],
      limit,
      offset,
      granularity,
      includeSummary,
      includeTimeseries,
      includeBreakdowns,
    };
    appendCabinetRangeBody(body, timeRange, customPeriod);
    try {
      const res = await requestJson('/api/cabinet/explorer/query', { method: 'POST', body });
      const metrics = finish({
        source: 'clickhouse',
        rows: res.meta?.rows,
        serverMs: res.meta?.elapsedMs,
      });
      return {
        source: 'clickhouse',
        rows: Array.isArray(res.data?.rows) ? res.data.rows : [],
        summary: res.data?.summary || null,
        timeseries: Array.isArray(res.data?.timeseries) ? res.data.timeseries : [],
        resultSeries: res.data?.resultSeries || null,
        breakdowns: res.data?.breakdowns || {},
        meta: res.meta || null,
        snapshotId: res.meta?.snapshotId ?? null,
        snapshotExpiresAt: res.meta?.snapshotExpiresAt ?? null,
        loadMs: metrics.loadMs,
        serverMs: res.meta?.elapsedMs ?? null,
      };
    } catch (err) {
      const metrics = finish({ source: 'error', error: err.message });
      return {
        source: 'error',
        rows: [],
        summary: null,
        timeseries: [],
        resultSeries: null,
        breakdowns: {},
        error: err.status === 403 ? 'Недостаточно прав' : (err.message || LOAD_FAILED),
        meta: null,
        loadMs: metrics.loadMs,
        serverMs: null,
      };
    }
  }

  async function loadCabinetExplorerFlows({
    metric = 'bps',
    groupBy = [],
    filters = [],
    thresholds = [],
    limit = 10,
    timeRange = '1h',
    customPeriod,
  } = {}) {
    const finish = DashboardLog?.widgetStart?.('cabinet/explorer/flows') ?? ((extra) => ({ loadMs: 0, ...extra }));
    const body = {
      metric,
      groupBy,
      filters,
      thresholds: Array.isArray(thresholds) ? thresholds : [],
      limit,
    };
    appendCabinetRangeBody(body, timeRange, customPeriod);
    try {
      const res = await requestJson('/api/cabinet/explorer/flows', { method: 'POST', body });
      const metrics = finish({
        source: 'clickhouse',
        rows: res.meta?.rows,
        serverMs: res.meta?.elapsedMs,
      });
      return {
        source: 'clickhouse',
        rows: Array.isArray(res.data) ? res.data : [],
        meta: res.meta || null,
        loadMs: metrics.loadMs,
        serverMs: res.meta?.elapsedMs ?? null,
      };
    } catch (err) {
      const metrics = finish({ source: 'error', error: err.message });
      return {
        source: 'error',
        rows: [],
        error: err.status === 403 ? 'Недостаточно прав' : (err.message || LOAD_FAILED),
        meta: null,
        loadMs: metrics.loadMs,
        serverMs: null,
      };
    }
  }

  async function exportCabinetExplorerCsv(queryBody = {}) {
    const body = { ...queryBody };
    if (body.from && body.to) {
      body.range = 'custom';
      delete body.timeRange;
      delete body.customPeriod;
    } else if (body.timeRange === 'custom' && body.customPeriod?.from && body.customPeriod?.to) {
      const apiPeriod = apiCustomPeriodParams(body.customPeriod);
      body.range = 'custom';
      body.from = apiPeriod.from;
      body.to = apiPeriod.to;
    } else if (body.timeRange) {
      body.range = body.timeRange;
    }
    delete body.customPeriod;
    const res = await fetch('/api/cabinet/explorer/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const err = new Error(errBody.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.body = errBody;
      maybeInvalidateSession(err);
      throw err;
    }
    return res.blob();
  }

  return {
    LOAD_FAILED,
    isSessionInvalidError,
    sessionInvalidToast,
    setSessionInvalidHandler,
    login,
    logout,
    loadCurrentUser,
    loadUsers,
    loadUsersForClient,
    createUser,
    updateUser,
    deleteUser,
    changeUserPassword,
    resetUserPassword,
    loadCabinetProfile,
    patchCabinetProfile,
    changeCabinetProfilePassword,
    loadClients,
    createClient,
    updateClient,
    loadClientPrefixes,
    saveClientPrefixes,
    loadClientPorts,
    saveClientPorts,
    loadClientPrefixOptions,
    loadClientPortOptions,
    impersonateClient,
    stopImpersonation,
    loadImpersonationAudit,
    cabinetRangeQueryParams,
    loadCabinetOverviewSeries,
    loadCabinetOverviewStats,
    loadCabinetOverviewCountries,
    loadCabinetOverviewServices,
    loadCabinetOverviewRecentFlows,
    loadCabinetDnsDomains,
    loadCabinetDnsQueries,
    loadCabinetExplorerSchema,
    loadCabinetExplorerQuery,
    loadCabinetExplorerFlows,
    exportCabinetExplorerCsv,
    loadRbacResources,
    loadRoles,
    loadRole,
    createRole,
    updateRole,
    deleteRole,
    loadUserPermissions,
    saveUserPermissions,
    updateUserRole,
    checkHealth,
    loadDashboardCollectors,
    loadDashboardLayout,
    saveDashboardLayout,
    resetDashboardLayout,
    loadDashboardData,
    loadTrafficStats,
    resolveChartSqlDirections,
    resolveProtocolSqlDirections,
    dashboardTraffic,
    dashboardTrafficStats,
    dashboardProtocols,
    dashboardServices,
    loadProtocolTrend,
    loadServiceTrend,
    dashboardVlans,
    loadVlanTrend,
    loadVlanTop,
    loadExplorerSchema,
    searchExplorerEntities,
    loadExplorerQuery,
    loadExplorerFlows,
    exportExplorerCsv,
    shareExplorerSnapshot,
    loadExplorerSharedSnapshot,
    revokeExplorerSnapshotShare,
    loadExplorerSavedFilters,
    saveExplorerFilter,
    deleteExplorerFilter,
    updateExplorerFilter,
    loadObservationsConfig,
    loadObservations,
    loadObservationAnalyticsDiagnostics,
    loadWorkerDiagnostics,
    scanWorkerGaps,
    loadWorkerBackfillQueue,
    enqueueWorkerBackfill,
    cancelWorkerBackfill,
    loadEnrichmentDiagnostics,
    loadSnmpDiagnostics,
    loadAnalysisSnapshotsDiagnostics,
    loadFailedRequestsDiagnostics,
    loadBuildInfo,
    loadLatestBuildInfo,
    hardReload,
    loadObservation,
    createObservation,
    updateObservation,
    deleteObservation,
    materializeObservation,
    previewObservation,
    runObservationReport,
    loadObservationRuns,
    duplicateObservation,
    cancelObservationMaterialize,
    observationRunArtifactUrl,
    loadSmtpSettings,
    saveSmtpSettings,
    testSmtpSettings,
    loadErpPiterixStatus,
    loadErpPiterixJournal,
    saveErpPiterixSettings,
    runErpPiterixSync,
    erpPiterixReportUrl,
    loadDetectionLatest,
    loadDetectionHistory,
    loadDetectionTelegramSettings,
    saveDetectionTelegramSettings,
    testDetectionTelegramSettings,
    loadDetectionEvents,
    exportDetectionEventsCsv,
    dashboardOtherPorts,
    dashboardCountries,
    loadCountries,
    dashboardTopTalkers,
    loadTopTalkers,
    talkersQuery,
    dashboardRecentFlows,
    recentFlowsQuery,
    loadRecentFlows,
    dnsOverviewQuery,
    dnsQuery,
    loadDnsExplorerSchema,
    runDnsExplorerQuery,
    exportDnsExplorerCsv,
    shareDnsExplorerSnapshot,
    loadDnsExplorerSharedSnapshot,
    revokeDnsExplorerSnapshotShare,
    suggestDnsExplorerDomains,
    suggestDnsExplorerClientIps,
    suggestDnsExplorerServerIps,
    suggestDnsExplorerQtypes,
    suggestDnsExplorerAnswers,
    loadDnsSources,
    loadDnsActivity,
    loadDnsTopDomains,
    loadDnsTopClients,
    loadDnsTopServers,
    loadDnsRecent,
    loadDnsQtypes,
    loadL3Prefixes,
    loadNetEntities,
    loadNetEntitiesAdmin,
    saveL3Prefix,
    toggleL3Prefix,
    deleteL3Prefix,
    loadDnsResolvers,
    saveDnsResolver,
    toggleDnsResolver,
    deleteDnsResolver,
    loadFlowExclusions,
    saveFlowExclusion,
    toggleFlowExclusion,
    deleteFlowExclusion,
    saveNetEntity,
    loadPortServices,
    savePortService,
    disablePortService,
    previewPortServiceDefaults,
    seedPortServiceDefaults,
    loadRefVlans,
    loadRefVlansSeen,
    saveRefVlan,
    setRefVlanEnabled,
    deleteRefVlan,
    loadLocations,
    saveLocation,
    loadCollectorsAdmin,
    saveCollector,
    deleteCollector,
    loadFlowSources,
    bindFlowSource,
    registerFlowSource,
    deleteFlowSource,
    loadSnmpSettings,
    saveSnmpSettings,
    loadSnmpAgents,
    saveSnmpAgent,
    loadSnmpInterfaces,
    requestSnmpProbe,
    requestSnmpProbeAll,
    deleteSnmpAgent,
    loadCollectorOptions,
    loadDiscoveredSources,
    loadCollectorOverview,
    loadCollectorStatus,
    loadCollectorCompleteness,
    loadCompletenessDetail,
    loadCompletenessHistory,
    loadBmpSummary,
    loadBmpPeers,
    loadBmpRouters,
    loadBmpRoutes,
    loadBmpEvents,
    loadBmpCounts,
    loadBmpChurn,
    loadBmpFlap,
    loadTtl,
    loadAudit,
    reportAuditPage,
    updateTtl,
    loadDirectionSettings,
    saveDirectionSettings,
    loadInterfaceRoleRules,
    saveInterfaceRoleRule,
    deleteInterfaceRoleRule,
    previewInterfaceRoleRule,
    loadInterfaceRoleSummary,
    loadInterfaceRoleSwitches,
    loadInterfaceRolesForSwitch,
    saveInterfaceRole,
    deleteInterfaceRole,
    rebuildInterfaceRoles,
    loadDirectionCoverage,
    loadDirectionCompare,
    loadDirectionInterfaces,
    getStatus: () => ({ ...status }),
  };
})();

Object.assign(window, { ApiClient });
