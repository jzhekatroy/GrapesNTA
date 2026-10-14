/* SNMP settings and sFlow switch inventory. */

const { useCallback, useEffect, useMemo, useState } = React;

const SFLOW_STALE_DAYS = 7;
const LAST_OK_STALE_FACTOR = 3;

function snmpT(key, params) {
  return GrapesI18n.t(key, params);
}

function snmpBoundaryLabel(value) {
  const id = String(value || 'unknown');
  const key = `snmpPage.boundary.${id}`;
  return GrapesI18n.has(key) ? snmpT(key) : snmpT('snmpPage.boundary.unknown');
}

function parseCatalogMs(value) {
  if (!value) return null;
  const text = String(value).replace('T', ' ').trim().slice(0, 19);
  if (
    !text
    || text.startsWith('1970-01-01')
    || text.startsWith('0000-00-00')
    || text.startsWith('0001-01-01')
  ) return null;
  const ms = typeof parseChartBucketMs === 'function'
    ? parseChartBucketMs(text)
    : Date.parse(`${text.replace(' ', 'T')}Z`);
  if (ms == null || !Number.isFinite(ms) || ms <= 0) return null;
  return ms;
}

function fmtLastOkAt(value, displayTimezone = getDisplayTimezone()) {
  const formatted = fmtCatalogUpdatedAt(value, displayTimezone);
  if (formatted === '—') return snmpT('snmpPage.status.neverPolled');
  return formatted;
}

function isLastOkStale(lastOkAt, refreshIntervalSec) {
  const ms = parseCatalogMs(lastOkAt);
  const interval = Number(refreshIntervalSec);
  if (ms == null || !Number.isFinite(interval) || interval <= 0) return false;
  return (Date.now() - ms) > LAST_OK_STALE_FACTOR * interval * 1000;
}

function sflowStaleDays(lastSeenAt) {
  const ms = parseCatalogMs(lastSeenAt);
  if (ms == null) return null;
  const days = Math.floor((Date.now() - ms) / (24 * 60 * 60 * 1000));
  if (days < SFLOW_STALE_DAYS) return null;
  return days;
}

function lastPollAttemptTitle(agent, displayTimezone = getDisplayTimezone()) {
  if (!agent.snmpEnabled || !agent.lastPollAt) return undefined;
  const formatted = fmtCatalogUpdatedAt(agent.lastPollAt, displayTimezone);
  if (formatted === '—') return undefined;
  return snmpT('snmpPage.status.lastAttempt', { time: formatted });
}

async function deleteSnmpAgentFromInventory(switchIp) {
  if (typeof ApiClient.deleteSnmpAgent === 'function') {
    return ApiClient.deleteSnmpAgent(switchIp);
  }
  const res = await fetch(`/api/refs/snmp-agents/${encodeURIComponent(switchIp)}`, {
    method: 'DELETE',
    credentials: 'same-origin',
    cache: 'no-store',
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(payload.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return payload;
}

function confirmSnmpAgentRemoval(count) {
  const n = Number(count) || 0;
  if (GrapesI18n.getLocale() === 'en') {
    return window.confirm(snmpT(n === 1 ? 'snmpPage.confirmRemoveOne' : 'snmpPage.confirmRemoveMany', { count: n }));
  }
  const noun = pluralRu(
    n,
    snmpT('snmpPage.noun.switch.one'),
    snmpT('snmpPage.noun.switch.few'),
    snmpT('snmpPage.noun.switch.many'),
  );
  return window.confirm(snmpT('snmpPage.confirmRemove', { count: n, noun }));
}

async function deleteSnmpAgentsFromInventory(switchIps) {
  const results = await Promise.allSettled(
    switchIps.map((switchIp) => deleteSnmpAgentFromInventory(switchIp)),
  );
  const deleted = [];
  const failed = [];
  switchIps.forEach((switchIp, index) => {
    if (results[index].status === 'fulfilled') deleted.push(switchIp);
    else failed.push({ switchIp, error: results[index].reason?.message || snmpT('snmpPage.error.generic') });
  });
  return { deleted, failed };
}

function fmtCatalogUpdatedAt(value, displayTimezone = getDisplayTimezone()) {
  if (!value) return '—';
  const text = String(value).replace('T', ' ').trim().slice(0, 19);
  if (
    !text
    || text.startsWith('1970-01-01')
    || text.startsWith('0000-00-00')
    || text.startsWith('0001-01-01')
  ) return '—';
  // ClickHouse stores these DateTime('UTC') wall-clock values in data TZ.
  const ms = typeof parseChartBucketMs === 'function'
    ? parseChartBucketMs(text)
    : Date.parse(`${text.replace(' ', 'T')}Z`);
  if (ms == null || !Number.isFinite(ms) || ms <= 0) return '—';
  return new Date(ms).toLocaleString(GrapesI18n.intlLocale(), {
    timeZone: displayTimezone || getDisplayTimezone(),
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function PageSnmp({ displayTimezone, canOpenInterfaceRoles }) {
  const canWrite = AuthAccess.canWritePage('snmp') || AuthAccess.canWritePage('collectors');
  const [refreshKey, setRefreshKey] = useState(0);
  const [probingAll, setProbingAll] = useState(false);
  const [watchUntil, setWatchUntil] = useState(0);
  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);
  const tz = displayTimezone || getDisplayTimezone();

  useEffect(() => {
    if (!watchUntil || Date.now() >= watchUntil) return undefined;
    const t = setInterval(() => {
      if (Date.now() >= watchUntil) {
        setWatchUntil(0);
        return;
      }
      reload();
    }, 5000);
    return () => clearInterval(t);
  }, [watchUntil, reload]);

  const probeAll = async () => {
    if (!window.confirm(snmpT('snmpPage.confirmProbeAll'))) return;
    setProbingAll(true);
    try {
      const res = await ApiClient.requestSnmpProbeAll();
      const accepted = res?.meta?.accepted ?? 0;
      pushToast({
        kind: 'success',
        title: snmpT('snmpPage.toast.probeQueued'),
        desc: accepted
          ? snmpT('snmpPage.toast.probeAllDesc', { accepted })
          : snmpT('snmpPage.toast.probeAllEmpty'),
      });
      // Watch poller progress for ~3 minutes (timeouts are slow).
      setWatchUntil(Date.now() + 3 * 60 * 1000);
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: snmpT('snmpPage.toast.probeFailed'), desc: err.message });
    } finally {
      setProbingAll(false);
    }
  };

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{snmpT('snmpPage.title')}</h1>
          <p>
            {snmpT('snmpPage.subtitle')}
            {watchUntil > Date.now() ? snmpT('snmpPage.watchQueue') : ''}
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload}>{snmpT('chrome.refresh')}</Button>
          <Button kind="primary" icon="refresh" onClick={probeAll} disabled={!canWrite || probingAll}>
            {probingAll ? snmpT('snmpPage.queuing') : snmpT('snmpPage.probeAll')}
          </Button>
        </div>
      </div>
      <SnmpSwitchesPage refreshKey={refreshKey} onReload={reload} displayTimezone={tz} canOpenInterfaceRoles={canOpenInterfaceRoles} />
    </div>
  );
}

function SnmpSettingsCard({ settings, canWrite, onSaved }) {
  const [form, setForm] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!settings) return;
    setForm({
      ...settings,
      community: '',
    });
    setError('');
  }, [settings]);

  if (!form) return null;
  const set = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));
  const save = async () => {
    setSaving(true);
    setError('');
    try {
      await ApiClient.saveSnmpSettings(form);
      pushToast({ kind: 'success', title: snmpT('snmpPage.saveSuccessTitle'), desc: snmpT('snmpPage.saveSuccessDesc') });
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card pad="sm" style={{ marginBottom: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{snmpT('snmpPage.settings.title')}</div>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {snmpT('snmpPage.settings.hint')}
          </div>
        </div>
        <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
          <label className="row" style={{ gap: 8 }}>
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => set('enabled', e.target.checked)}
              disabled={!canWrite}
            />
            {snmpT('snmpPage.settings.enabled')}
          </label>
          <label className="row" style={{ gap: 8 }}>
            <input
              type="checkbox"
              checked={!!form.autoEnableNewAgents}
              onChange={(e) => set('autoEnableNewAgents', e.target.checked)}
              disabled={!canWrite}
            />
            {snmpT('snmpPage.settings.autoEnableNew')}
          </label>
        </div>
      </div>
      {error && <div style={{ marginBottom: 10, color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{error}</div>}
      <div className="grid grid--4col-fit grid--gap-xs">
        <div className="field">
          <label>Community</label>
          <input
            className="input"
            type="password"
            autoComplete="new-password"
            placeholder={settings.hasCommunity ? snmpT('snmpPage.placeholder.communitySet') : snmpT('snmpPage.placeholder.communityUnset')}
            value={form.community}
            onChange={(e) => set('community', e.target.value)}
            disabled={!canWrite}
          />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.settings.port')}</label>
          <input className="input" type="number" value={form.port} onChange={(e) => set('port', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.settings.timeoutMs')}</label>
          <input className="input" type="number" value={form.timeoutMs} onChange={(e) => set('timeoutMs', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.settings.retries')}</label>
          <input className="input" type="number" value={form.retries} onChange={(e) => set('retries', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.settings.discoverHours')}</label>
          <input className="input" type="number" value={form.discoverLookbackHours} onChange={(e) => set('discoverLookbackHours', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.settings.pollSec')}</label>
          <input className="input" type="number" value={form.refreshIntervalSec} onChange={(e) => set('refreshIntervalSec', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.settings.fullWalkSec')}</label>
          <input className="input" type="number" value={form.fullWalkIntervalSec} onChange={(e) => set('fullWalkIntervalSec', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="row" style={{ justifyContent: 'flex-end', alignItems: 'flex-end', paddingBottom: 1 }}>
          <Button kind="primary" icon="save" onClick={save} disabled={!canWrite || saving}>
            {saving ? snmpT('snmpPage.saving') : snmpT('snmpPage.save')}
          </Button>
        </div>
      </div>
    </Card>
  );
}

function SnmpAgentStatus({ agent, displayTimezone }) {
  const pollTitle = lastPollAttemptTitle(agent, displayTimezone);
  if (!agent.snmpEnabled) return <StatusIndicator status="idle" label={snmpT('snmpPage.status.disabled')} />;
  const status = agent.lastPollStatus || 'never';
  const hasCache = !!agent.hasCachedInterfaces || Number(agent.interfaceCount) > 0;

  if (status === 'ok') {
    return (
      <div title={pollTitle}>
        <StatusIndicator status="healthy" label={snmpT('snmpPage.status.ok')} />
      </div>
    );
  }
  // Re-poll queued: keep using last catalog; do not look like "never seen".
  if (status === 'queued' || status === 'never') {
    if (hasCache) {
      return (
        <div title={pollTitle}>
          <StatusIndicator status="warning" label={snmpT('snmpPage.status.polling')} />
        </div>
      );
    }
    return (
      <div title={pollTitle}>
        <StatusIndicator status="warning" label={snmpT('snmpPage.status.waiting')} />
      </div>
    );
  }
  // timeout / auth / error — catalog rows stay in CH; Explorer uses last names.
  const err = String(agent.lastPollError || '').trim();
  const shortErr = err ? (err.length > 48 ? `${err.slice(0, 48)}…` : err) : '';
  const title = [pollTitle, err].filter(Boolean).join('\n') || undefined;
  if (hasCache) {
    return (
      <div title={title}>
        <StatusIndicator status="warning" label={snmpT('snmpPage.status.unavailableCache')} />
        {shortErr ? <div className="mono" style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 2 }}>{shortErr}</div> : null}
      </div>
    );
  }
  return (
    <div title={title}>
      <StatusIndicator status="critical" label={status === 'timeout' ? snmpT('snmpPage.status.timeout') : snmpT('snmpPage.status.snmpError')} />
      {shortErr ? <div className="mono" style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 2 }}>{shortErr}</div> : null}
    </div>
  );
}

function SnmpAgentModal({
  open, agent, canWrite, onClose, onSaved, onDeleted, displayTimezone, canOpenInterfaceRoles,
}) {
  const [form, setForm] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [roleByIndex, setRoleByIndex] = useState({});
  const [showUnmarkedOnly, setShowUnmarkedOnly] = useState(false);
  const [interfacesError, setInterfacesError] = useState('');
  const [saving, setSaving] = useState(false);
  const [probing, setProbing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState('');
  const tz = displayTimezone || getDisplayTimezone();

  const showInterfaceRolesLink = !!canOpenInterfaceRoles;

  useEffect(() => {
    if (!open || !agent) return undefined;
    let cancelled = false;
    setForm({
      displayName: agent.displayName || '',
      snmpEnabled: agent.snmpEnabled,
      useGlobalCommunity: !agent.hasCommunityOverride,
      communityOverride: '',
      portOverride: agent.portOverride ?? '',
      timeoutMsOverride: agent.timeoutMsOverride ?? '',
      retriesOverride: agent.retriesOverride ?? '',
    });
    setInterfaces([]);
    setRoleByIndex({});
    setShowUnmarkedOnly(false);
    setInterfacesError('');
    setError('');
    Promise.all([
      ApiClient.loadSnmpInterfaces(agent.switchIp),
      ApiClient.loadInterfaceRolesForSwitch(agent.switchIp),
    ]).then(([ifRes, rolesRes]) => {
      if (cancelled) return;
      if (ifRes.source === 'error') setInterfacesError(ifRes.error || snmpT('snmpPage.loadFailed'));
      else setInterfaces(ifRes.rows || []);
      const map = {};
      if (rolesRes.source !== 'error') {
        for (const row of rolesRes.rows || []) {
          map[row.ifIndex] = row;
        }
      }
      setRoleByIndex(map);
    });
    return () => { cancelled = true; };
  }, [open, agent]);

  const interfaceRows = useMemo(() => {
    const rows = interfaces.map((row) => {
      const role = roleByIndex[row.ifIndex] || {};
      return {
        ...row,
        id: row.ifIndex,
        boundary: role.boundary || 'unknown',
        boundarySource: role.boundarySource || 'default',
      };
    });
    if (!showUnmarkedOnly) return rows;
    return rows.filter((r) => r.boundary === 'unknown');
  }, [interfaces, roleByIndex, showUnmarkedOnly]);

  if (!open || !agent || !form) return null;
  const set = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));
  const save = async () => {
    setSaving(true);
    setError('');
    try {
      await ApiClient.saveSnmpAgent({
        switchIp: agent.switchIp,
        ...form,
        portOverride: form.portOverride === '' ? null : form.portOverride,
        timeoutMsOverride: form.timeoutMsOverride === '' ? null : form.timeoutMsOverride,
        retriesOverride: form.retriesOverride === '' ? null : form.retriesOverride,
        isNew: false,
      });
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };
  const probe = async () => {
    setProbing(true);
    setError('');
    try {
      await ApiClient.requestSnmpProbe(agent.switchIp);
      pushToast({ kind: 'success', title: snmpT('snmpPage.toast.probeQueued'), desc: snmpT('snmpPage.toast.probeOneDesc') });
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setProbing(false);
    }
  };
  const remove = async () => {
    if (!confirmSnmpAgentRemoval(1)) return;
    setDeleting(true);
    setError('');
    try {
      await deleteSnmpAgentFromInventory(agent.switchIp);
      pushToast({ kind: 'success', title: snmpT('snmpPage.toast.removedFromPoll'), desc: agent.switchIp });
      onDeleted(agent.switchIp);
    } catch (err) {
      setError(err.message);
    } finally {
      setDeleting(false);
    }
  };
  const interfaceCols = [
    { key: 'ifIndex', title: 'ifIndex', width: 80, render: (r) => <span className="mono">{r.ifIndex}</span> },
    { key: 'ifName', title: snmpT('snmpPage.col.name'), width: 140, render: (r) => <span className="mono">{r.ifName || '—'}</span> },
    { key: 'ifAlias', title: 'Alias', width: 140, render: (r) => r.ifAlias || '—' },
    { key: 'ifDescr', title: snmpT('snmpPage.col.description'), width: 160, render: (r) => r.ifDescr || '—' },
    { key: 'ifSpeedBps', title: snmpT('snmpPage.col.speed'), width: 100, render: (r) => (r.ifSpeedBps ? fmtBits(r.ifSpeedBps) : '—') },
    {
      key: 'boundary',
      title: snmpT('snmpPage.col.side'),
      width: 110,
      render: (r) => (
        <Badge tone={r.boundary === 'unknown' ? 'neutral' : irBoundaryBadgeTone(r.boundary)}>
          {snmpBoundaryLabel(r.boundary)}
        </Badge>
      ),
    },
  ];

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={agent.displayName || agent.switchIp}
      subtitle={agent.switchIp}
      size="lg"
      footer={(
        <div className="row" style={{ width: '100%', gap: 8, justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <Button
            kind="danger"
            icon="trash"
            onClick={remove}
            disabled={!canWrite || saving || probing || deleting}
          >
            {deleting ? snmpT('snmpPage.deleting') : snmpT('snmpPage.modal.deleteFromPoll')}
          </Button>
          <div className="row" style={{ gap: 8, marginLeft: 'auto' }}>
            <Button kind="ghost" onClick={onClose} disabled={saving || probing || deleting}>{snmpT('modal.close')}</Button>
            <Button kind="ghost" icon="refresh" onClick={probe} disabled={!canWrite || saving || probing || deleting}>
              {probing ? snmpT('snmpPage.queuing') : snmpT('snmpPage.modal.probe')}
            </Button>
            <Button kind="primary" icon="save" onClick={save} disabled={!canWrite || saving || probing || deleting}>
              {saving ? snmpT('snmpPage.saving') : snmpT('snmpPage.save')}
            </Button>
          </div>
        </div>
      )}
    >
      {error && <div style={{ marginBottom: 12, color: 'var(--st-critical)' }}>{error}</div>}
      <div className="grid grid--2col grid--gap-sm" style={{ marginBottom: 18 }}>
        <div className="field">
          <label>{snmpT('snmpPage.modal.sysNameLabel')}</label>
          <input className="input" value={form.displayName} onChange={(e) => set('displayName', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>SNMP</label>
          <label className="row" style={{ gap: 8, minHeight: 36 }}>
            <input type="checkbox" checked={form.snmpEnabled} onChange={(e) => set('snmpEnabled', e.target.checked)} disabled={!canWrite} />
            {snmpT('snmpPage.modal.pollEnabled')}
          </label>
        </div>
        <div className="field">
          <label>Community override</label>
          <label className="row" style={{ gap: 8, marginBottom: 6 }}>
            <input type="checkbox" checked={form.useGlobalCommunity} onChange={(e) => set('useGlobalCommunity', e.target.checked)} disabled={!canWrite} />
            {snmpT('snmpPage.modal.useGlobalCommunity')}
          </label>
          {!form.useGlobalCommunity && (
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              placeholder={agent.hasCommunityOverride ? snmpT('snmpPage.placeholder.communitySet') : snmpT('snmpPage.placeholder.newOverride')}
              value={form.communityOverride}
              onChange={(e) => set('communityOverride', e.target.value)}
              disabled={!canWrite}
            />
          )}
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.modal.portOverride')}</label>
          <input className="input" type="number" placeholder={snmpT('snmpPage.placeholder.global')} value={form.portOverride} onChange={(e) => set('portOverride', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.modal.timeoutOverride')}</label>
          <input className="input" type="number" placeholder={snmpT('snmpPage.placeholder.global')} value={form.timeoutMsOverride} onChange={(e) => set('timeoutMsOverride', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>{snmpT('snmpPage.modal.retriesOverride')}</label>
          <input className="input" type="number" placeholder={snmpT('snmpPage.placeholder.globalPlural')} value={form.retriesOverride} onChange={(e) => set('retriesOverride', e.target.value)} disabled={!canWrite} />
        </div>
      </div>
      <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 8 }}>{snmpT('snmpPage.modal.interfaces')}</div>
      {showInterfaceRolesLink && (
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8, flexWrap: 'wrap', gap: 8 }}>
          <label className="row" style={{ gap: 6, font: 'var(--pv-text-body-3)' }}>
            <input type="checkbox" checked={showUnmarkedOnly} onChange={(e) => setShowUnmarkedOnly(e.target.checked)} />
            {snmpT('snmpPage.modal.showUnmarked')}
          </label>
          <Button
            kind="ghost"
            size="sm"
            onClick={() => {
              onClose();
              location.hash = `interface-roles?switch=${encodeURIComponent(agent.switchIp)}`;
            }}
          >
            {snmpT('snmpPage.modal.markRoles')}
          </Button>
        </div>
      )}
      {agent.snmpEnabled && agent.lastPollAt && (
        <div style={{ marginBottom: 8, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {snmpT('snmpPage.modal.lastPollAttempt', { time: fmtCatalogUpdatedAt(agent.lastPollAt, tz) })}
          {agent.lastPollError ? ` · ${agent.lastPollError}` : ''}
        </div>
      )}
      {agent.hasCachedInterfaces && agent.lastPollStatus && agent.lastPollStatus !== 'ok' && (
        <div style={{ marginBottom: 8, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {snmpT('snmpPage.modal.cachedCatalog')}
          {agent.lastOkAt ? ` · ${fmtLastOkAt(agent.lastOkAt, tz)}` : ''}.
        </div>
      )}
      {interfacesError ? (
        <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{interfacesError}</div>
      ) : (
        <DataTable
          rows={interfaceRows}
          columns={interfaceCols}
          rowKey="id"
          pageSize={10}
          emptyTitle={snmpT('snmpPage.interfaces.emptyTitle')}
          emptyDesc={snmpT('snmpPage.interfaces.emptyDesc')}
        />
      )}
    </Modal>
  );
}

function SnmpSwitchesPage({ refreshKey, onReload, displayTimezone, canOpenInterfaceRoles }) {
  const canWrite = AuthAccess.canWritePage('snmp') || AuthAccess.canWritePage('collectors');
  const [settings, setSettings] = useState(null);
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(() => new Set());
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [editing, setEditing] = useState(null);
  const tz = displayTimezone || getDisplayTimezone();

  useEffect(() => {
    setSelected((prev) => {
      const ids = new Set(rows.map((r) => r.switchIp));
      const next = new Set([...prev].filter((id) => ids.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [rows]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError('');
      const [settingsRes, agentsRes] = await Promise.all([
        ApiClient.loadSnmpSettings(),
        ApiClient.loadSnmpAgents(),
      ]);
      if (cancelled) return;
      if (settingsRes.source === 'error' || agentsRes.source === 'error') {
        setLoadError(settingsRes.error || agentsRes.error || snmpT('snmpPage.loadFailed'));
      } else {
        setSettings(settingsRes.data);
        setRows((agentsRes.rows || []).map((row) => ({ ...row, id: row.switchIp })));
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((row) => (
      (row.switchIp || '').toLowerCase().includes(needle)
      || (row.displayName || '').toLowerCase().includes(needle)
      || (row.sourceIds || []).some((id) => id.toLowerCase().includes(needle))
    ));
  }, [rows, search]);

  const selectStaleSflow = () => {
    const staleIps = rows
      .filter((row) => sflowStaleDays(row.lastSeenAt) != null)
      .map((row) => row.switchIp);
    setSelected(new Set(staleIps));
  };

  const removeSelected = async () => {
    const switchIps = [...selected];
    if (!switchIps.length || !confirmSnmpAgentRemoval(switchIps.length)) return;
    setBulkDeleting(true);
    try {
      const { deleted, failed } = await deleteSnmpAgentsFromInventory(switchIps);
      if (deleted.length) {
        setRows((prev) => prev.filter((r) => !deleted.includes(r.switchIp)));
        setSelected((prev) => {
          const next = new Set(prev);
          deleted.forEach((ip) => next.delete(ip));
          return next;
        });
      }
      if (failed.length) {
        pushToast({
          kind: 'error',
          title: snmpT('snmpPage.toast.partialDelete'),
          desc: snmpT('snmpPage.toast.partialDeleteDesc', {
            deleted: deleted.length,
            failed: failed.length,
            ip: failed[0].switchIp,
            error: failed[0].error,
          }),
        });
      } else {
        pushToast({
          kind: 'success',
          title: snmpT('snmpPage.toast.removedFromPoll'),
          desc: deleted.length === 1 ? deleted[0] : snmpT('snmpPage.toast.removedCount', { count: deleted.length }),
        });
      }
      if (deleted.length) onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: snmpT('snmpPage.toast.deleteFailed'), desc: err.message });
    } finally {
      setBulkDeleting(false);
    }
  };

  const cols = [
    {
      key: 'displayName',
      title: snmpT('snmpPage.col.switch'),
      width: 230,
      render: (r) => {
        const staleDays = sflowStaleDays(r.lastSeenAt);
        return (
          <div>
            <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
              <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || snmpT('snmpPage.noSysName')}</span>
              {r.isNew && <Badge tone="warning">New</Badge>}
              {staleDays != null && <Badge tone="neutral">{snmpT('snmpPage.badge.noSflow', { days: staleDays })}</Badge>}
            </div>
            <div className="mono" style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>{r.switchIp}</div>
          </div>
        );
      },
    },
    { key: 'status', title: 'SNMP', width: 180, render: (r) => <SnmpAgentStatus agent={r} displayTimezone={tz} /> },
    {
      key: 'lastSeenAt',
      title: snmpT('snmpPage.col.lastSflow'),
      width: 160,
      render: (r) => fmtCatalogUpdatedAt(r.lastSeenAt, tz),
    },
    {
      key: 'sourceIds',
      title: 'Source IDs',
      width: 240,
      render: (r) => (
        <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
          {(r.sourceIds || []).length
            ? r.sourceIds.map((id) => <span key={id} className="tag mono">{id}</span>)
            : <span style={{ color: 'var(--fg-secondary)' }}>—</span>}
        </div>
      ),
    },
    {
      key: 'lastOkAt',
      title: snmpT('snmpPage.col.lastOkPoll'),
      width: 180,
      render: (r) => {
        const stale = isLastOkStale(r.lastOkAt, settings?.refreshIntervalSec);
        return (
          <span style={{ color: stale ? 'var(--st-warning)' : undefined }}>
            {fmtLastOkAt(r.lastOkAt, tz)}
          </span>
        );
      },
    },
  ];

  const statusSummary = useMemo(() => {
    const enabled = rows.filter((r) => r.snmpEnabled);
    const count = (status) => enabled.filter((r) => (r.lastPollStatus || 'never') === status).length;
    return {
      total: rows.length,
      enabled: enabled.length,
      ok: count('ok'),
      queued: count('queued') + count('never'),
      timeout: count('timeout'),
      auth: count('auth_error'),
      error: enabled.filter((r) => ['error', 'config_error'].includes(r.lastPollStatus)).length,
    };
  }, [rows]);

  if (loading) return <Card pad="sm"><div style={{ padding: 32, textAlign: 'center' }}>{snmpT('snmpPage.loading')}</div></Card>;
  if (loadError) {
    return <Empty icon="db" title={snmpT('snmpPage.loadFailed')} desc={loadError} action={<Button kind="primary" icon="refresh" onClick={onReload}>{snmpT('snmpPage.retry')}</Button>} />;
  }
  const allFailing = statusSummary.enabled > 0
    && statusSummary.ok === 0
    && (statusSummary.timeout + statusSummary.error + statusSummary.auth) > 0;
  return (
    <>
      <SnmpSettingsCard settings={settings} canWrite={canWrite} onSaved={onReload} />
      <Card pad="sm" style={{ marginBottom: 12 }}>
        <div className="row" style={{ gap: 16, flexWrap: 'wrap', font: 'var(--pv-text-body-3)' }}>
          <span>{snmpT('snmpPage.summary.agents')} <b className="mono">{statusSummary.total}</b></span>
          <span>{snmpT('snmpPage.summary.enabled')} <b className="mono">{statusSummary.enabled}</b></span>
          <span>ok: <b className="mono">{statusSummary.ok}</b></span>
          <span>{snmpT('snmpPage.summary.queue')} <b className="mono">{statusSummary.queued}</b></span>
          <span>timeout: <b className="mono" style={{ color: statusSummary.timeout ? 'var(--st-critical)' : undefined }}>{statusSummary.timeout}</b></span>
          <span>{snmpT('snmpPage.summary.authError')} <b className="mono">{statusSummary.auth + statusSummary.error}</b></span>
        </div>
        {allFailing ? (
          <div style={{ marginTop: 8, color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
            {snmpT('snmpPage.banner.allFailing')}
          </div>
        ) : null}
      </Card>
      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        pageSize={15}
        selectable={canWrite}
        selected={selected}
        onSelectChange={setSelected}
        toolbar={{
          search,
          onSearch: setSearch,
          left: canWrite ? (
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              {selected.size > 0 ? (
                <>
                  <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
                    {snmpT('snmpPage.selected')} <b>{selected.size}</b>
                  </span>
                  <Button
                    size="sm"
                    kind="danger"
                    icon="trash"
                    onClick={removeSelected}
                    disabled={bulkDeleting}
                  >
                    {bulkDeleting ? snmpT('snmpPage.deleting') : snmpT('snmpPage.deleteSelected')}
                  </Button>
                  <Button size="sm" kind="ghost" onClick={() => setSelected(new Set())} disabled={bulkDeleting}>
                    {snmpT('snmpPage.clearSelection')}
                  </Button>
                </>
              ) : (
                <Button size="sm" kind="ghost" onClick={selectStaleSflow} disabled={bulkDeleting}>
                  {snmpT('snmpPage.selectStaleSflow', { days: SFLOW_STALE_DAYS })}
                </Button>
              )}
            </div>
          ) : null,
        }}
        onRowClick={(r) => setEditing(r)}
        emptyTitle={snmpT('snmpPage.empty.switchesTitle')}
        emptyDesc={snmpT('snmpPage.empty.switchesDesc')}
      />
      <SnmpAgentModal
        open={!!editing}
        agent={editing}
        canWrite={canWrite}
        displayTimezone={tz}
        onClose={() => setEditing(null)}
        canOpenInterfaceRoles={canOpenInterfaceRoles}
        onSaved={() => {
          setEditing(null);
          onReload();
        }}
        onDeleted={(switchIp) => {
          setEditing(null);
          setRows((prev) => prev.filter((r) => r.switchIp !== switchIp));
          onReload();
        }}
      />
    </>
  );
}

Object.assign(window, { PageSnmp });
