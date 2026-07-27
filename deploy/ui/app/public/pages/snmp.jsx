/* SNMP settings and sFlow switch inventory. */

const { useCallback, useEffect, useMemo, useState } = React;

const SAVE_SUCCESS_TITLE = 'Настройки сохранены';
const SAVE_SUCCESS_DESC = 'Изменения записаны в ClickHouse.';

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
  return new Date(ms).toLocaleString('ru-RU', {
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
    if (!window.confirm('Включить SNMP и поставить в очередь опрос всех коммутаторов из списка?')) return;
    setProbingAll(true);
    try {
      const res = await ApiClient.requestSnmpProbeAll();
      const accepted = res?.meta?.accepted ?? 0;
      pushToast({
        kind: 'success',
        title: 'Опрос поставлен в очередь',
        desc: accepted
          ? `Агентов: ${accepted}. Поллер grapes-enrichment берёт до 25/мин. Статусы обновятся сами.`
          : 'Список пуст.',
      });
      // Watch poller progress for ~3 minutes (timeouts are slow).
      setWatchUntil(Date.now() + 3 * 60 * 1000);
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось поставить опрос', desc: err.message });
    } finally {
      setProbingAll(false);
    }
  };

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>SNMP</h1>
          <p>
            Глобальные настройки SNMP и коммутаторы sFlow из sampler_address.
            {watchUntil > Date.now() ? ' Следим за очередью опроса…' : ''}
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload}>Обновить</Button>
          <Button kind="primary" icon="refresh" onClick={probeAll} disabled={!canWrite || probingAll}>
            {probingAll ? 'Постановка…' : 'Опросить всех'}
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
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
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
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>Глобальные настройки SNMP</div>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            Существующий community не отображается. Пустое поле оставляет его без изменений.
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
            SNMP включён
          </label>
          <label className="row" style={{ gap: 8 }}>
            <input
              type="checkbox"
              checked={!!form.autoEnableNewAgents}
              onChange={(e) => set('autoEnableNewAgents', e.target.checked)}
              disabled={!canWrite}
            />
            Автоопрос новых
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
            placeholder={settings.hasCommunity ? 'Задан · оставить без изменений' : 'Не задан'}
            value={form.community}
            onChange={(e) => set('community', e.target.value)}
            disabled={!canWrite}
          />
        </div>
        <div className="field">
          <label>Порт</label>
          <input className="input" type="number" value={form.port} onChange={(e) => set('port', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Timeout, мс</label>
          <input className="input" type="number" value={form.timeoutMs} onChange={(e) => set('timeoutMs', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Повторы</label>
          <input className="input" type="number" value={form.retries} onChange={(e) => set('retries', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Обнаружение, ч</label>
          <input className="input" type="number" value={form.discoverLookbackHours} onChange={(e) => set('discoverLookbackHours', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Опрос, сек</label>
          <input className="input" type="number" value={form.refreshIntervalSec} onChange={(e) => set('refreshIntervalSec', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Полный walk, сек</label>
          <input className="input" type="number" value={form.fullWalkIntervalSec} onChange={(e) => set('fullWalkIntervalSec', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="row" style={{ justifyContent: 'flex-end', alignItems: 'flex-end', paddingBottom: 1 }}>
          <Button kind="primary" icon="save" onClick={save} disabled={!canWrite || saving}>
            {saving ? 'Сохранение…' : 'Сохранить'}
          </Button>
        </div>
      </div>
    </Card>
  );
}

function SnmpAgentStatus({ agent }) {
  if (!agent.snmpEnabled) return <StatusIndicator status="idle" label="Отключён" />;
  const status = agent.lastPollStatus || 'never';
  const hasCache = !!agent.hasCachedInterfaces || Number(agent.interfaceCount) > 0;

  if (status === 'ok') {
    return <StatusIndicator status="healthy" label="SNMP работает" />;
  }
  // Re-poll queued: keep using last catalog; do not look like "never seen".
  if (status === 'queued' || status === 'never') {
    if (hasCache) return <StatusIndicator status="warning" label="Идёт опрос" />;
    return <StatusIndicator status="warning" label="Ожидает опроса" />;
  }
  // timeout / auth / error — catalog rows stay in CH; Explorer uses last names.
  const err = String(agent.lastPollError || '').trim();
  const shortErr = err ? (err.length > 48 ? `${err.slice(0, 48)}…` : err) : '';
  if (hasCache) {
    return (
      <div title={err || undefined}>
        <StatusIndicator status="warning" label="Недоступен · есть кэш" />
        {shortErr ? <div className="mono" style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 2 }}>{shortErr}</div> : null}
      </div>
    );
  }
  return (
    <div title={err || undefined}>
      <StatusIndicator status="critical" label={status === 'timeout' ? 'Timeout' : 'Ошибка SNMP'} />
      {shortErr ? <div className="mono" style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 2 }}>{shortErr}</div> : null}
    </div>
  );
}

function SnmpAgentModal({ open, agent, canWrite, onClose, onSaved, canOpenInterfaceRoles }) {
  const [form, setForm] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [roleByIndex, setRoleByIndex] = useState({});
  const [showUnmarkedOnly, setShowUnmarkedOnly] = useState(false);
  const [interfacesError, setInterfacesError] = useState('');
  const [saving, setSaving] = useState(false);
  const [probing, setProbing] = useState(false);
  const [error, setError] = useState('');

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
      if (ifRes.source === 'error') setInterfacesError(ifRes.error || ApiClient.LOAD_FAILED);
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
        connectivity: role.connectivity || '',
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
      pushToast({ kind: 'success', title: 'Опрос поставлен в очередь', desc: 'Poller выполнит SNMP-опрос.' });
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setProbing(false);
    }
  };
  const interfaceCols = [
    { key: 'ifIndex', title: 'ifIndex', width: 80, render: (r) => <span className="mono">{r.ifIndex}</span> },
    { key: 'ifName', title: 'Имя', width: 140, render: (r) => <span className="mono">{r.ifName || '—'}</span> },
    { key: 'ifAlias', title: 'Alias', width: 140, render: (r) => r.ifAlias || '—' },
    { key: 'ifDescr', title: 'Описание', width: 160, render: (r) => r.ifDescr || '—' },
    { key: 'ifSpeedBps', title: 'Скорость', width: 100, render: (r) => (r.ifSpeedBps ? fmtBits(r.ifSpeedBps) : '—') },
    {
      key: 'boundary',
      title: 'Сторона',
      width: 110,
      render: (r) => (
        <Badge tone={r.boundary === 'unknown' ? 'neutral' : irBoundaryBadgeTone(r.boundary)}>
          {irBoundaryLabel(r.boundary)}
        </Badge>
      ),
    },
    {
      key: 'connectivity',
      title: 'Тип стыка',
      width: 110,
      render: (r) => (r.connectivity ? <Badge tone="info">{irConnectivityLabel(r.connectivity)}</Badge> : '—'),
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
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving || probing}>Закрыть</Button>
          <Button kind="ghost" icon="refresh" onClick={probe} disabled={!canWrite || saving || probing}>
            {probing ? 'Постановка…' : 'Опросить'}
          </Button>
          <Button kind="primary" icon="save" onClick={save} disabled={!canWrite || saving || probing}>
            {saving ? 'Сохранение…' : 'Сохранить'}
          </Button>
        </>
      )}
    >
      {error && <div style={{ marginBottom: 12, color: 'var(--st-critical)' }}>{error}</div>}
      <div className="grid grid--2col grid--gap-sm" style={{ marginBottom: 18 }}>
        <div className="field">
          <label>sysName / название</label>
          <input className="input" value={form.displayName} onChange={(e) => set('displayName', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>SNMP</label>
          <label className="row" style={{ gap: 8, minHeight: 36 }}>
            <input type="checkbox" checked={form.snmpEnabled} onChange={(e) => set('snmpEnabled', e.target.checked)} disabled={!canWrite} />
            Опрос устройства включён
          </label>
        </div>
        <div className="field">
          <label>Community override</label>
          <label className="row" style={{ gap: 8, marginBottom: 6 }}>
            <input type="checkbox" checked={form.useGlobalCommunity} onChange={(e) => set('useGlobalCommunity', e.target.checked)} disabled={!canWrite} />
            Использовать глобальный
          </label>
          {!form.useGlobalCommunity && (
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              placeholder={agent.hasCommunityOverride ? 'Задан · оставить без изменений' : 'Новый override'}
              value={form.communityOverride}
              onChange={(e) => set('communityOverride', e.target.value)}
              disabled={!canWrite}
            />
          )}
        </div>
        <div className="field">
          <label>Порт override</label>
          <input className="input" type="number" placeholder="Глобальный" value={form.portOverride} onChange={(e) => set('portOverride', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Timeout override, мс</label>
          <input className="input" type="number" placeholder="Глобальный" value={form.timeoutMsOverride} onChange={(e) => set('timeoutMsOverride', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Повторы override</label>
          <input className="input" type="number" placeholder="Глобальные" value={form.retriesOverride} onChange={(e) => set('retriesOverride', e.target.value)} disabled={!canWrite} />
        </div>
      </div>
      <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 8 }}>Интерфейсы</div>
      {showInterfaceRolesLink && (
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8, flexWrap: 'wrap', gap: 8 }}>
          <label className="row" style={{ gap: 6, font: 'var(--pv-text-body-3)' }}>
            <input type="checkbox" checked={showUnmarkedOnly} onChange={(e) => setShowUnmarkedOnly(e.target.checked)} />
            Показать неразмеченные
          </label>
          <Button
            kind="ghost"
            size="sm"
            onClick={() => {
              onClose();
              location.hash = `interface-roles?switch=${encodeURIComponent(agent.switchIp)}`;
            }}
          >
            Разметить
          </Button>
        </div>
      )}
      {agent.hasCachedInterfaces && agent.lastPollStatus && agent.lastPollStatus !== 'ok' && (
        <div style={{ marginBottom: 8, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          Показан последний успешный каталог
          {agent.interfacesUpdatedAt ? ` · ${fmtCatalogUpdatedAt(agent.interfacesUpdatedAt)}` : ''}.
          {agent.lastPollError ? ` Последняя попытка: ${agent.lastPollError}` : ''}
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
          emptyTitle="Интерфейсы ещё не получены"
          emptyDesc="Выполните опрос; таблицу заполнит SNMP poller. При недоступности свитча остаются прошлые данные."
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
  const [editing, setEditing] = useState(null);
  const tz = displayTimezone || getDisplayTimezone();

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
        setLoadError(settingsRes.error || agentsRes.error || ApiClient.LOAD_FAILED);
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

  const cols = [
    {
      key: 'displayName',
      title: 'Коммутатор',
      width: 230,
      render: (r) => (
        <div>
          <div className="row" style={{ gap: 6 }}>
            <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || 'Без sysName'}</span>
            {r.isNew && <Badge tone="warning">New</Badge>}
          </div>
          <div className="mono" style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>{r.switchIp}</div>
        </div>
      ),
    },
    { key: 'status', title: 'SNMP', width: 180, render: (r) => <SnmpAgentStatus agent={r} /> },
    {
      key: 'lastSeenAt',
      title: 'Последний sFlow',
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
      key: 'lastPollAt',
      title: 'Последний опрос',
      width: 160,
      render: (r) => fmtCatalogUpdatedAt(r.lastPollAt, tz),
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

  if (loading) return <Card pad="sm"><div style={{ padding: 32, textAlign: 'center' }}>Загрузка…</div></Card>;
  if (loadError) {
    return <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={onReload}>Повторить</Button>} />;
  }
  const allFailing = statusSummary.enabled > 0
    && statusSummary.ok === 0
    && (statusSummary.timeout + statusSummary.error + statusSummary.auth) > 0;
  return (
    <>
      <SnmpSettingsCard settings={settings} canWrite={canWrite} onSaved={onReload} />
      <Card pad="sm" style={{ marginBottom: 12 }}>
        <div className="row" style={{ gap: 16, flexWrap: 'wrap', font: 'var(--pv-text-body-3)' }}>
          <span>агентов: <b className="mono">{statusSummary.total}</b></span>
          <span>включено: <b className="mono">{statusSummary.enabled}</b></span>
          <span>ok: <b className="mono">{statusSummary.ok}</b></span>
          <span>очередь: <b className="mono">{statusSummary.queued}</b></span>
          <span>timeout: <b className="mono" style={{ color: statusSummary.timeout ? 'crimson' : undefined }}>{statusSummary.timeout}</b></span>
          <span>auth/error: <b className="mono">{statusSummary.auth + statusSummary.error}</b></span>
        </div>
        {allFailing ? (
          <div style={{ marginTop: 8, color: 'crimson', font: 'var(--pv-text-body-3)' }}>
            Опросы идут, но свитчи не отвечают (timeout). Проверьте маршрут/ACL с хоста UI/поллера до mgmt-сети (UDP/161).
            Детали — Диагностика → SNMP.
          </div>
        ) : null}
      </Card>
      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        pageSize={15}
        toolbar={{ search, onSearch: setSearch }}
        onRowClick={(r) => setEditing(r)}
        emptyTitle="Коммутаторы sFlow не обнаружены"
        emptyDesc="Poller добавит устройства из sampler_address после появления потоков."
      />
      <SnmpAgentModal
        open={!!editing}
        agent={editing}
        canWrite={canWrite}
        onClose={() => setEditing(null)}
        canOpenInterfaceRoles={canOpenInterfaceRoles}
        onSaved={() => {
          setEditing(null);
          onReload();
        }}
      />
    </>
  );
}

Object.assign(window, { PageSnmp });
