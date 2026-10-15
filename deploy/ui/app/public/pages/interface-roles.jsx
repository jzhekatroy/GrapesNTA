/* Порты оборудования — MVP: ручная разметка стороны порта (наш / внешний). */

const { useCallback, useEffect, useMemo, useRef, useState } = React;

function interfaceRolesT(key, params) {
  return GrapesI18n.t(key, params);
}

function interfaceRolesPortNoun(n) {
  const count = Number(n) || 0;
  if (GrapesI18n.getLocale() === 'en') {
    return count === 1
      ? interfaceRolesT('interfaceRolesPage.noun.port.one')
      : interfaceRolesT('interfaceRolesPage.noun.port.many');
  }
  return pluralRu(
    count,
    interfaceRolesT('interfaceRolesPage.noun.port.one'),
    interfaceRolesT('interfaceRolesPage.noun.port.few'),
    interfaceRolesT('interfaceRolesPage.noun.port.many'),
  );
}

function confirmHideSwitch(label) {
  return window.confirm(interfaceRolesT('interfaceRolesPage.confirm.hideSwitch', { label }));
}

function confirmHideSwitches(count) {
  const n = Number(count) || 0;
  if (GrapesI18n.getLocale() === 'en') {
    return window.confirm(interfaceRolesT(
      n === 1 ? 'interfaceRolesPage.confirm.hideSwitchesOne' : 'interfaceRolesPage.confirm.hideSwitchesMany',
      { count: n },
    ));
  }
  const noun = pluralRu(
    n,
    interfaceRolesT('interfaceRolesPage.noun.switch.one'),
    interfaceRolesT('interfaceRolesPage.noun.switch.few'),
    interfaceRolesT('interfaceRolesPage.noun.switch.many'),
  );
  return window.confirm(interfaceRolesT('interfaceRolesPage.confirm.hideSwitches', { count: n, noun }));
}

function confirmClearPortMarking(label) {
  return window.confirm(interfaceRolesT('interfaceRolesPage.confirm.clearPortMarking', { label }));
}

function confirmClearPortsMarking(count) {
  const n = Number(count) || 0;
  if (GrapesI18n.getLocale() === 'en') {
    return window.confirm(interfaceRolesT(
      n === 1 ? 'interfaceRolesPage.confirm.clearPortsMarkingOne' : 'interfaceRolesPage.confirm.clearPortsMarkingMany',
      { count: n },
    ));
  }
  return window.confirm(interfaceRolesT('interfaceRolesPage.confirm.clearPortsMarkingMany', { count: n }));
}

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
  return irSwitchStatusLabel(status);
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

function portMarkingLabel(row) {
  const name = String(row?.ifName || '').trim();
  return name || String(row?.ifIndex ?? '');
}

function switchListLabel(row) {
  const name = String(row?.displayName || '').trim();
  return name || String(row?.switchIp ?? '');
}

function fmtHiddenSwitchAt(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(GrapesI18n.intlLocale());
}

function SwitchListScreen({
  switches,
  hiddenSwitches,
  loading,
  loadError,
  canWrite,
  onOpenSwitch,
  onReload,
}) {
  const [selected, setSelected] = useState(() => new Set());
  const [saving, setSaving] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  const rows = useMemo(() => switches.map((s) => ({
    ...s,
    id: s.switchIp,
    status: computeSwitchStatus(s),
  })), [switches]);

  useEffect(() => {
    setSelected(new Set());
  }, [switches]);

  useEffect(() => {
    if (!menuOpen) return undefined;
    const onDoc = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setMenuOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [menuOpen]);

  const hideSwitch = async (row) => {
    if (!canWrite) return;
    const label = switchListLabel(row);
    if (!confirmHideSwitch(label)) return;
    setSaving(true);
    try {
      await ApiClient.hideInterfaceRoleSwitches({ switchIp: row.switchIp });
      pushToast({ kind: 'success', title: interfaceRolesT('interfaceRolesPage.toast.switchHidden') });
      setMenuOpen(false);
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: interfaceRolesT('interfaceRolesPage.toast.deleteFailed'), desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const bulkHideSelected = async () => {
    if (!canWrite || !selected.size) return;
    const n = selected.size;
    if (!confirmHideSwitches(n)) return;
    setSaving(true);
    try {
      const items = [...selected].map((switchIp) => ({ switchIp }));
      await ApiClient.hideInterfaceRoleSwitches({ switches: items });
      pushToast({
        kind: 'success',
        title: interfaceRolesT('interfaceRolesPage.toast.removedFromList', { count: items.length }),
      });
      setSelected(new Set());
      setMenuOpen(false);
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: interfaceRolesT('interfaceRolesPage.toast.deleteFailed'), desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const restoreSwitch = async (row) => {
    if (!canWrite) return;
    setSaving(true);
    try {
      await ApiClient.restoreInterfaceRoleSwitches({ switchIp: row.switchIp });
      pushToast({ kind: 'success', title: interfaceRolesT('interfaceRolesPage.toast.switchRestored') });
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: interfaceRolesT('interfaceRolesPage.toast.restoreFailed'), desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const columns = [
    {
      key: 'switchIp',
      title: interfaceRolesT('interfaceRolesPage.col.switch'),
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
    {
      key: 'ports',
      title: interfaceRolesT('interfaceRolesPage.col.ports'),
      width: 80,
      num: true,
      sortAccessor: (r) => r.ports,
      render: (r) => <span className="mono">{r.ports}</span>,
    },
    {
      key: 'portsWithAlias',
      title: interfaceRolesT('interfaceRolesPage.col.withAlias'),
      width: 100,
      num: true,
      sortAccessor: (r) => r.portsWithAlias,
      render: (r) => <span className="mono">{r.portsWithAlias}</span>,
    },
    {
      key: 'marked',
      title: interfaceRolesT('interfaceRolesPage.col.marked'),
      width: 100,
      num: true,
      sortAccessor: (r) => r.marked,
      render: (r) => <span className="mono">{r.marked}</span>,
    },
    {
      key: 'unmarked',
      title: interfaceRolesT('interfaceRolesPage.col.unmarked'),
      width: 110,
      num: true,
      sortAccessor: (r) => r.unmarked,
      render: (r) => <span className="mono">{r.unmarked}</span>,
    },
    {
      key: 'status',
      title: interfaceRolesT('interfaceRolesPage.col.status'),
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
      title={interfaceRolesT('interfaceRolesPage.card.switchesTitle')}
      subtitle={interfaceRolesT('interfaceRolesPage.card.switchesSubtitle')}
    >
      {loadError && <div className="form-error" style={{ marginBottom: 12 }}>{loadError}</div>}
      {canWrite && (
        <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12 }}>
          <div className="ir-hidden-switches" ref={menuRef}>
            <Button
              kind="ghost"
              size="sm"
              disabled={loading || saving}
              onClick={() => setMenuOpen((open) => !open)}
            >
              {hiddenSwitches.length
                ? interfaceRolesT('interfaceRolesPage.hiddenSwitchesCount', { count: hiddenSwitches.length })
                : interfaceRolesT('interfaceRolesPage.hiddenSwitches')}
            </Button>
            {menuOpen && (
              <div className="ir-hidden-switches__menu" role="menu">
                {hiddenSwitches.length === 0 ? (
                  <p className="ir-hidden-switches__empty">{interfaceRolesT('interfaceRolesPage.noHidden')}</p>
                ) : (
                  <ul className="ir-hidden-switches__list">
                    {hiddenSwitches.map((row) => (
                      <li key={row.switchIp} className="ir-hidden-switches__item">
                        <div className="ir-hidden-switches__meta">
                          <div className="mono">{row.switchIp}</div>
                          {row.displayName && (
                            <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
                              {row.displayName}
                            </div>
                          )}
                          <div style={{ color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)', marginTop: 4 }}>
                            {interfaceRolesT('interfaceRolesPage.hiddenAt', { time: fmtHiddenSwitchAt(row.hiddenAt) })}
                          </div>
                        </div>
                        <Button
                          size="sm"
                          kind="primary"
                          disabled={saving}
                          onClick={() => restoreSwitch(row)}
                        >
                          {interfaceRolesT('interfaceRolesPage.restore')}
                        </Button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      )}
      {!loading && rows.length > 0 && (
        <p className="ir-list-hint">
          {interfaceRolesT('interfaceRolesPage.listHint')}
        </p>
      )}
      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-secondary)' }}>
          {interfaceRolesT('dashboard.loading')}
        </div>
      ) : (
        <DataTable
          rows={rows}
          columns={columns}
          rowKey="id"
          pageSize={20}
          initialSort={{ key: 'unmarked', dir: 'desc' }}
          emptyTitle={interfaceRolesT('interfaceRolesPage.empty.switchesTitle')}
          emptyDesc={interfaceRolesT('interfaceRolesPage.empty.switchesDesc')}
          onRowClick={(r) => onOpenSwitch(r.switchIp)}
          selectable={canWrite}
          selected={selected}
          onSelectChange={setSelected}
          toolbar={canWrite ? {
            left: selected.size > 0 ? (
              <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <Button
                  kind="danger"
                  size="sm"
                  icon="trash"
                  disabled={saving}
                  onClick={bulkHideSelected}
                >
                  {saving
                    ? interfaceRolesT('interfaceRolesPage.deleting')
                    : interfaceRolesT('interfaceRolesPage.deleteSelected', { count: selected.size })}
                </Button>
                <Button kind="ghost" size="sm" disabled={saving} onClick={() => setSelected(new Set())}>
                  {interfaceRolesT('snmpPage.clearSelection')}
                </Button>
              </div>
            ) : null,
          } : undefined}
          actionsColumnWidth={130}
          rowActions={canWrite ? (r) => (
            <Button
              size="sm"
              kind="ghost"
              disabled={saving}
              onClick={(e) => {
                e.stopPropagation();
                hideSwitch(r);
              }}
            >
              {interfaceRolesT('interfaceRolesPage.delete')}
            </Button>
          ) : null}
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
        pushToast({ kind: 'success', title: interfaceRolesT('interfaceRolesPage.toast.markingCleared') });
      } else {
        await ApiClient.saveInterfaceRole({ switchIp, ifIndex, boundary, connectivity: '' });
        pushToast({ kind: 'success', title: interfaceRolesT('interfaceRolesPage.toast.markingSaved') });
      }
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: interfaceRolesT('interfaceRolesPage.toast.saveFailed'), desc: err.message });
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
      pushToast({
        kind: 'success',
        title: interfaceRolesT('interfaceRolesPage.toast.portsMarked', { count: items.length }),
      });
      setSelected(new Set());
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: interfaceRolesT('interfaceRolesPage.toast.saveFailed'), desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const deletePortMarking = async (ifIndex, row) => {
    if (!canWrite) return;
    const label = portMarkingLabel(row ?? { ifIndex });
    if (!confirmClearPortMarking(label)) return;
    setSaving(true);
    try {
      await ApiClient.deleteInterfaceRole({ switchIp, ifIndex });
      pushToast({ kind: 'success', title: interfaceRolesT('interfaceRolesPage.toast.markingCleared') });
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: interfaceRolesT('interfaceRolesPage.toast.deleteFailed'), desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const bulkDeleteSelected = async () => {
    if (!canWrite || !selected.size) return;
    const n = selected.size;
    if (!confirmClearPortsMarking(n)) return;
    setSaving(true);
    try {
      const items = [...selected].map((ifIndex) => ({ switchIp, ifIndex }));
      await ApiClient.deleteInterfaceRole({ interfaces: items });
      pushToast({
        kind: 'success',
        title: interfaceRolesT('interfaceRolesPage.toast.clearedCount', { count: items.length }),
      });
      setSelected(new Set());
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: interfaceRolesT('interfaceRolesPage.toast.deleteFailed'), desc: err.message });
    } finally {
      setSaving(false);
    }
  };

  const columns = [
    {
      key: 'ifIndex',
      title: interfaceRolesT('interfaceRolesPage.col.ifIndex'),
      width: 80,
      render: (r) => <span className="mono">{r.ifIndex}</span>,
    },
    {
      key: 'ifName',
      title: interfaceRolesT('interfaceRolesPage.col.name'),
      width: 140,
      render: (r) => <span className="mono">{r.ifName || '—'}</span>,
    },
    {
      key: 'ifAlias',
      title: interfaceRolesT('interfaceRolesPage.col.alias'),
      width: 160,
      render: (r) => r.ifAlias || '—',
    },
    {
      key: 'speedMbps',
      title: interfaceRolesT('interfaceRolesPage.col.speed'),
      width: 90,
      num: true,
      render: (r) => (
        <span className="mono">
          {r.speedMbps ? interfaceRolesT('interfaceRolesPage.speedMbps', { speed: r.speedMbps }) : '—'}
        </span>
      ),
    },
    {
      key: 'boundary',
      title: interfaceRolesT('interfaceRolesPage.col.side'),
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
    {
      key: 'boundarySource',
      title: interfaceRolesT('interfaceRolesPage.col.source'),
      width: 140,
      render: (r) => {
        if (r.boundarySource === 'client') {
          return (
            <span title={r.clientId ? interfaceRolesT('interfaceRolesPage.source.clientTitle', { clientId: r.clientId }) : ''}>
              <Badge tone="info">{irSourceLabel('client')}</Badge>
            </span>
          );
        }
        if (r.boundarySource === 'default') return '—';
        return <Badge tone="neutral">{irSourceLabel(r.boundarySource)}</Badge>;
      },
    },
  ];

  const bulkPanel = canWrite && (
    selected.size > 0 ? (
      <div className="ir-bulk-panel">
        <div className="ir-bulk-panel__head">
          <span className="ir-bulk-panel__title">{interfaceRolesT('interfaceRolesPage.bulk.title')}</span>
          <span className="ir-bulk-panel__count">
            {interfaceRolesT('interfaceRolesPage.bulk.selected', { count: selected.size })}{' '}
            {interfaceRolesPortNoun(selected.size)}
          </span>
        </div>
        <div className="ir-bulk-panel__actions row">
          <Button kind="primary" size="sm" disabled={saving} onClick={() => bulkApply('internal')}>
            {interfaceRolesT('interfaceRolesPage.bulk.internal')}
          </Button>
          <Button kind="primary" size="sm" disabled={saving} onClick={() => bulkApply('external')}>
            {interfaceRolesT('interfaceRolesPage.bulk.external')}
          </Button>
          <Button kind="ghost" size="sm" disabled={saving} onClick={() => setSelected(new Set())}>
            {interfaceRolesT('interfaceRolesPage.bulk.resetSelection')}
          </Button>
          {selected.size < filteredPorts.length && (
            <Button kind="ghost" size="sm" disabled={saving || !filteredPorts.length} onClick={selectAllFiltered}>
              {interfaceRolesT('interfaceRolesPage.bulk.addAllFiltered', { count: filteredPorts.length })}
            </Button>
          )}
        </div>
      </div>
    ) : (
      <div className="ir-bulk-hint">
        <p>{interfaceRolesT('interfaceRolesPage.bulk.hint')}</p>
        <Button kind="ghost" size="sm" disabled={saving || !filteredPorts.length} onClick={selectAllFiltered}>
          {interfaceRolesT('interfaceRolesPage.bulk.selectAllFiltered', { count: filteredPorts.length })}
        </Button>
      </div>
    )
  );

  return (
    <div>
      <div className="page-head" style={{ marginBottom: 16 }}>
        <div>
          <Button kind="ghost" size="sm" icon="chevL" onClick={onBack} style={{ marginBottom: 8 }}>
            {interfaceRolesT('interfaceRolesPage.backToList')}
          </Button>
          <h1 style={{ margin: 0 }}>{displayName || switchIp}</h1>
          <p className="mono" style={{ color: 'var(--fg-secondary)', marginTop: 4 }}>{switchIp}</p>
          <p style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 8 }}>
            {interfaceRolesT('interfaceRolesPage.summary', {
              total: summary.total,
              marked: summary.marked,
              unmarked: summary.unmarked,
            })}
          </p>
        </div>
        <Button kind="ghost" icon="refresh" onClick={onReload} disabled={loading || saving}>
          {interfaceRolesT('chrome.refresh')}
        </Button>
      </div>

      <Card pad="sm" title={interfaceRolesT('interfaceRolesPage.card.portsTitle')}>
        {loadError && <div className="form-error" style={{ marginBottom: 12 }}>{loadError}</div>}
        <div className="row ir-port-filters" style={{ gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <div className="field" style={{ margin: 0 }}>
            <label>{interfaceRolesT('interfaceRolesPage.filter.aliasLabel')}</label>
            <input
              className="input"
              value={aliasQ}
              onChange={(e) => setAliasQ(e.target.value)}
              placeholder={interfaceRolesT('interfaceRolesPage.filter.aliasPlaceholder')}
            />
          </div>
          <div className="field" style={{ margin: 0 }}>
            <label>{interfaceRolesT('interfaceRolesPage.filter.nameLabel')}</label>
            <input
              className="input"
              value={nameQ}
              onChange={(e) => setNameQ(e.target.value)}
              placeholder={interfaceRolesT('interfaceRolesPage.filter.namePlaceholder')}
            />
          </div>
        </div>

        {bulkPanel}

        {loading ? (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-secondary)' }}>
            {interfaceRolesT('dashboard.loading')}
          </div>
        ) : (
          <DataTable
            rows={filteredPorts.map((r) => ({ ...r, id: r.ifIndex }))}
            columns={columns}
            rowKey="id"
            pageSize={25}
            initialSort={{ key: 'ifIndex', dir: 'asc' }}
            emptyTitle={interfaceRolesT('interfaceRolesPage.empty.portsFilter')}
            selectable={canWrite}
            selected={selected}
            onSelectChange={setSelected}
            toolbar={canWrite ? {
              left: selected.size > 0 ? (
                <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <Button
                    kind="danger"
                    size="sm"
                    icon="trash"
                    disabled={saving}
                    onClick={bulkDeleteSelected}
                  >
                    {saving
                      ? interfaceRolesT('interfaceRolesPage.deleting')
                      : interfaceRolesT('interfaceRolesPage.deleteSelectedMarking', { count: selected.size })}
                  </Button>
                  <Button kind="ghost" size="sm" disabled={saving} onClick={() => setSelected(new Set())}>
                    {interfaceRolesT('snmpPage.clearSelection')}
                  </Button>
                </div>
              ) : null,
            } : undefined}
            actionsColumnWidth={150}
            rowActions={canWrite ? (r) => (
              <Button
                size="sm"
                kind="ghost"
                disabled={saving}
                onClick={(e) => {
                  e.stopPropagation();
                  deletePortMarking(r.ifIndex, r);
                }}
              >
                {interfaceRolesT('interfaceRolesPage.deleteMarking')}
              </Button>
            ) : null}
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
  const [hiddenSwitches, setHiddenSwitches] = useState([]);
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
          if (/скрыт/i.test(portsR.error || '')) {
            location.hash = 'interface-roles';
            setSwitchIp('');
            setPorts([]);
            setLoadError('');
          } else {
            setLoadError(portsR.error || interfaceRolesT('interfaceRolesPage.loadFailed'));
            setPorts([]);
          }
        } else {
          setPorts(portsR.rows);
        }
        setSwitches(swR.source === 'error' ? [] : swR.rows);
        setHiddenSwitches([]);
      } else {
        const [swR, hidR] = await Promise.all([
          ApiClient.loadInterfaceRoleSwitches(),
          ApiClient.loadHiddenInterfaceRoleSwitches(),
        ]);
        if (cancelled) return;
        if (swR.source === 'error') {
          setLoadError(swR.error || interfaceRolesT('interfaceRolesPage.loadFailed'));
          setSwitches([]);
        } else {
          setSwitches(swR.rows);
        }
        setHiddenSwitches(hidR.source === 'error' ? [] : hidR.rows);
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
              <h1>{interfaceRolesT('interfaceRolesPage.title')}</h1>
              <p>
                {interfaceRolesT('interfaceRolesPage.introLead')}
                {' '}
                {interfaceRolesT('interfaceRolesPage.introPortsMode')}{' '}
                <button type="button" className="link-btn" onClick={() => { location.hash = 'traffic-classification'; }}>
                  {interfaceRolesT('nav.item.traffic-classification')}
                </button>
                .
              </p>
            </div>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>
              {interfaceRolesT('chrome.refresh')}
            </Button>
          </div>
          <SwitchListScreen
            switches={switches}
            hiddenSwitches={hiddenSwitches}
            loading={loading}
            loadError={loadError}
            canWrite={canWrite}
            onOpenSwitch={openSwitch}
            onReload={reload}
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
