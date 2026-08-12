/* Порты оборудования — MVP: ручная разметка стороны порта (наш / внешний). */

const { useCallback, useEffect, useMemo, useState } = React;

function useDebouncedValue(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

function readInterfaceRolesHashParams() {
  const { pageId, params } = parseAppHash();
  if (pageId !== 'interface-roles') return {};
  return { switchIp: params.get('switch') || '' };
}

function buildInterfaceRolesHash({ switchIp } = {}) {
  return switchIp ? `#interface-roles?switch=${encodeURIComponent(switchIp)}` : '#interface-roles';
}

function computeSwitchStatus({ marked, portsWithAlias }) {
  if (!marked) return 'not_started';
  if (marked >= portsWithAlias && portsWithAlias > 0) return 'done';
  return 'partial';
}

function switchStatusLabel(status) {
  return IR_SWITCH_STATUS_LABELS[status] || status;
}

function switchStatusTone(status) {
  if (status === 'done') return 'success';
  if (status === 'partial') return 'warning';
  return 'neutral';
}

function filterSwitchPorts(rows, { aliasQ, nameQ }) {
  const alias = aliasQ.trim().toLowerCase();
  const name = nameQ.trim().toLowerCase();
  return rows.filter((r) => {
    if (alias && !String(r.ifAlias || '').toLowerCase().includes(alias)) return false;
    if (name && !String(r.ifName || '').toLowerCase().includes(name)) return false;
    return true;
  });
}

function SwitchListScreen({ switches, loading, loadError, onOpenSwitch }) {
  const rows = useMemo(() => switches.map((s) => ({
    ...s,
    id: s.switchIp,
    status: computeSwitchStatus(s),
  })), [switches]);

  const columns = [
    {
      key: 'switchIp',
      title: 'Коммутатор',
      width: 220,
      sortAccessor: (r) => r.switchIp,
      render: (r) => (
        <div>
          <div className="mono">{r.switchIp}</div>
          {r.displayName && (
            <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>{r.displayName}</div>
          )}
        </div>
      ),
    },
    { key: 'ports', title: 'Портов', width: 80, num: true, sortAccessor: (r) => r.ports, render: (r) => <span className="mono">{r.ports}</span> },
    { key: 'portsWithAlias', title: 'С алиасом', width: 100, num: true, sortAccessor: (r) => r.portsWithAlias, render: (r) => <span className="mono">{r.portsWithAlias}</span> },
    { key: 'marked', title: 'Размечено', width: 100, num: true, sortAccessor: (r) => r.marked, render: (r) => <span className="mono">{r.marked}</span> },
    { key: 'unmarked', title: 'Не размечено', width: 110, num: true, sortAccessor: (r) => r.unmarked, render: (r) => <span className="mono">{r.unmarked}</span> },
    {
      key: 'status',
      title: 'Статус',
      width: 120,
      sortAccessor: (r) => r.status,
      render: (r) => (
        <Badge tone={switchStatusTone(r.status)} className={`ir-status-badge ir-status-badge--${r.status}`}>
          {switchStatusLabel(r.status)}
        </Badge>
      ),
    },
  ];

  return (
    <Card
      pad="sm"
      title="Коммутаторы"
      subtitle="Нажмите на строку, чтобы открыть порты коммутатора и разметить их вручную или пакетно."
    >
      {loadError && <div className="form-error" style={{ marginBottom: 12 }}>{loadError}</div>}
      {!loading && rows.length > 0 && (
        <p className="ir-list-hint">
          Клик по коммутатору открывает список его портов: там можно задать сторону «наша» или «внешняя»
          для каждого порта или сразу для группы по фильтру.
        </p>
      )}
      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
      ) : (
        <DataTable
          rows={rows}
          columns={columns}
          rowKey="id"
          pageSize={20}
          initialSort={{ key: 'unmarked', dir: 'desc' }}
          emptyTitle="Нет коммутаторов в каталоге SNMP"
          emptyDesc="Сначала опросите устройства на странице SNMP."
          onRowClick={(r) => onOpenSwitch(r.switchIp)}
        />
      )}
    </Card>
  );
}

function SwitchPortsScreen({
  switchIp,
  displayName,
  ports,
  loading,
  loadError,
  canWrite,
  onBack,
  onReload,
}) {
  const [aliasQ, setAliasQ] = useState('');
  const [nameQ, setNameQ] = useState('');
  const [selected, setSelected] = useState(() => new Set());
  const [saving, setSaving] = useState(false);

  const debAlias = useDebouncedValue(aliasQ);
  const debName = useDebouncedValue(nameQ);

  const filteredPorts = useMemo(() => filterSwitchPorts(ports, {
    aliasQ: debAlias,
    nameQ: debName,
  }), [ports, debAlias, debName]);

  const summary = useMemo(() => {
    const marked = ports.filter((p) => p.boundary === 'internal' || p.boundary === 'external').length;
    return { total: ports.length, marked, unmarked: ports.length - marked };
  }, [ports]);

  useEffect(() => {
    setSelected(new Set());
  }, [switchIp, debAlias, debName]);

  const selectAllFiltered = () => {
    setSelected(new Set(filteredPorts.map((r) => r.ifIndex)));
  };

  const saveBoundary = async (ifIndex, boundary) => {
    if (!canWrite) return;
    setSaving(true);
    try {
      if (boundary === 'unknown' || boundary === '') {
        await ApiClient.deleteInterfaceRole({ switchIp, ifIndex });
        pushToast({ kind: 'success', title: 'Разметка снята' });
      } else {
        await ApiClient.saveInterfaceRole({ switchIp, ifIndex, boundary, connectivity: '' });
        pushToast({ kind: 'success', title: 'Разметка сохранена' });
      }
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сохранить', desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const bulkApply = async (boundary) => {
    if (!canWrite || !selected.size) return;
    setSaving(true);
    try {
      const items = [...selected].map((ifIndex) => ({ switchIp, ifIndex, boundary, connectivity: '' }));
      await ApiClient.saveInterfaceRole({ interfaces: items });
      pushToast({ kind: 'success', title: `Размечено портов: ${items.length}` });
      setSelected(new Set());
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сохранить', desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const bulkClear = async () => {
    if (!canWrite || !selected.size) return;
    setSaving(true);
    try {
      const items = [...selected].map((ifIndex) => ({ switchIp, ifIndex }));
      await ApiClient.deleteInterfaceRole({ interfaces: items });
      pushToast({ kind: 'success', title: `Снята разметка: ${items.length}` });
      setSelected(new Set());
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось снять', desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const columns = [
    { key: 'ifIndex', title: 'ifIndex', width: 80, render: (r) => <span className="mono">{r.ifIndex}</span> },
    { key: 'ifName', title: 'Имя', width: 140, render: (r) => <span className="mono">{r.ifName || '—'}</span> },
    { key: 'ifAlias', title: 'Алиас', width: 160, render: (r) => r.ifAlias || '—' },
    { key: 'speedMbps', title: 'Скорость', width: 90, num: true, render: (r) => <span className="mono">{r.speedMbps ? `${r.speedMbps} Мбит/с` : '—'}</span> },
    {
      key: 'boundary',
      title: 'Сторона',
      width: 160,
      render: (r) => {
        if (!canWrite) {
          return (
            <Badge tone={r.boundary === 'unknown' ? 'neutral' : irBoundaryBadgeTone(r.boundary)}>
              {irBoundaryLabel(r.boundary)}
            </Badge>
          );
        }
        return (
          <select
            className="input"
            value={r.boundary === 'internal' || r.boundary === 'external' ? r.boundary : 'unknown'}
            disabled={saving}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => saveBoundary(r.ifIndex, e.target.value)}
            style={{ minWidth: 130 }}
          >
            <option value="unknown">{irBoundaryLabel('unknown')}</option>
            <option value="internal">{irBoundaryLabel('internal')}</option>
            <option value="external">{irBoundaryLabel('external')}</option>
          </select>
        );
      },
    },
  ];

  const bulkPanel = canWrite && (
    selected.size > 0 ? (
      <div className="ir-bulk-panel">
        <div className="ir-bulk-panel__head">
          <span className="ir-bulk-panel__title">Массовое изменение</span>
          <span className="ir-bulk-panel__count">
            Выбрано: <b>{selected.size}</b> {selected.size === 1 ? 'порт' : selected.size < 5 ? 'порта' : 'портов'}
          </span>
        </div>
        <div className="ir-bulk-panel__actions row">
          <Button kind="primary" size="sm" disabled={saving} onClick={() => bulkApply('internal')}>Наша сторона</Button>
          <Button kind="primary" size="sm" disabled={saving} onClick={() => bulkApply('external')}>Внешняя сторона</Button>
          <Button kind="ghost" size="sm" disabled={saving} onClick={bulkClear}>Снять разметку</Button>
          <Button kind="ghost" size="sm" disabled={saving} onClick={() => setSelected(new Set())}>Сбросить выбор</Button>
          {selected.size < filteredPorts.length && (
            <Button kind="ghost" size="sm" disabled={saving || !filteredPorts.length} onClick={selectAllFiltered}>
              Добавить все отфильтрованные ({filteredPorts.length})
            </Button>
          )}
        </div>
      </div>
    ) : (
      <div className="ir-bulk-hint">
        <p>Отметьте порты галочками слева в таблице, чтобы изменить сторону сразу у нескольких.</p>
        <Button kind="ghost" size="sm" disabled={saving || !filteredPorts.length} onClick={selectAllFiltered}>
          Выбрать все отфильтрованные ({filteredPorts.length})
        </Button>
      </div>
    )
  );

  return (
    <div>
      <div className="page-head" style={{ marginBottom: 16 }}>
        <div>
          <Button kind="ghost" size="sm" icon="chevL" onClick={onBack} style={{ marginBottom: 8 }}>К списку</Button>
          <h1 style={{ margin: 0 }}>{displayName || switchIp}</h1>
          <p className="mono" style={{ color: 'var(--fg-secondary)', marginTop: 4 }}>{switchIp}</p>
          <p style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 8 }}>
            Всего {summary.total} · размечено {summary.marked} · не размечено {summary.unmarked}
          </p>
        </div>
        <Button kind="ghost" icon="refresh" onClick={onReload} disabled={loading || saving}>Обновить</Button>
      </div>

      <Card pad="sm" title="Порты">
        {loadError && <div className="form-error" style={{ marginBottom: 12 }}>{loadError}</div>}
        <div className="row ir-port-filters" style={{ gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <div className="field" style={{ margin: 0 }}>
            <label>Алиас содержит</label>
            <input className="input" value={aliasQ} onChange={(e) => setAliasQ(e.target.value)} placeholder="mgmt, yandex…" />
          </div>
          <div className="field" style={{ margin: 0 }}>
            <label>Имя содержит</label>
            <input className="input" value={nameQ} onChange={(e) => setNameQ(e.target.value)} placeholder="Ethernet…" />
          </div>
        </div>

        {bulkPanel}

        {loading ? (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        ) : (
          <DataTable
            rows={filteredPorts.map((r) => ({ ...r, id: r.ifIndex }))}
            columns={columns}
            rowKey="id"
            pageSize={25}
            initialSort={{ key: 'ifIndex', dir: 'asc' }}
            emptyTitle="Нет портов по фильтру"
            selectable={canWrite}
            selected={selected}
            onSelectChange={setSelected}
          />
        )}
      </Card>
    </div>
  );
}

function PageInterfaceRoles({ onNavigate }) {
  const canWrite = AuthAccess.canWritePage('interface-roles');
  const [switchIp, setSwitchIp] = useState(() => readInterfaceRolesHashParams().switchIp || '');
  const [refreshKey, setRefreshKey] = useState(0);
  const [switches, setSwitches] = useState([]);
  const [ports, setPorts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    const syncFromHash = () => {
      const { switchIp: ip } = readInterfaceRolesHashParams();
      setSwitchIp(ip || '');
    };
    addEventListener('hashchange', syncFromHash);
    return () => removeEventListener('hashchange', syncFromHash);
  }, []);

  const openSwitch = useCallback((ip) => {
    location.hash = buildInterfaceRolesHash({ switchIp: ip }).slice(1);
    setSwitchIp(ip);
  }, []);

  const goToList = useCallback(() => {
    location.hash = 'interface-roles';
    setSwitchIp('');
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError('');

      if (switchIp) {
        const [portsR, swR] = await Promise.all([
          ApiClient.loadInterfaceRolesForSwitch(switchIp),
          ApiClient.loadInterfaceRoleSwitches(),
        ]);
        if (cancelled) return;
        if (portsR.source === 'error') {
          setLoadError(portsR.error || ApiClient.LOAD_FAILED);
          setPorts([]);
        } else {
          setPorts(portsR.rows);
        }
        setSwitches(swR.source === 'error' ? [] : swR.rows);
      } else {
        const swR = await ApiClient.loadInterfaceRoleSwitches();
        if (cancelled) return;
        if (swR.source === 'error') {
          setLoadError(swR.error || ApiClient.LOAD_FAILED);
          setSwitches([]);
        } else {
          setSwitches(swR.rows);
        }
        setPorts([]);
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [switchIp, refreshKey]);

  const displayName = useMemo(() => {
    const sw = switches.find((s) => s.switchIp === switchIp);
    return sw?.displayName || '';
  }, [switches, switchIp]);

  return (
    <div className="main__container">
      {!switchIp && (
        <>
          <div className="page-head">
            <div>
              <h1>Порты оборудования</h1>
              <p>
                Ручная разметка стороны порта для определения направления трафика.
                Выберите коммутатор в таблице ниже — откроется детальный список его портов.
                {' '}
                Режим «по портам» настраивается на странице{' '}
                <button type="button" className="link-btn" onClick={() => { location.hash = 'traffic-classification'; }}>
                  Классификация трафика
                </button>
                .
              </p>
            </div>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
          </div>
          <SwitchListScreen
            switches={switches}
            loading={loading}
            loadError={loadError}
            onOpenSwitch={openSwitch}
          />
        </>
      )}

      {switchIp && (
        <SwitchPortsScreen
          switchIp={switchIp}
          displayName={displayName}
          ports={ports}
          loading={loading}
          loadError={loadError}
          canWrite={canWrite}
          onBack={goToList}
          onReload={reload}
        />
      )}
    </div>
  );
}

Object.assign(window, { PageInterfaceRoles });
