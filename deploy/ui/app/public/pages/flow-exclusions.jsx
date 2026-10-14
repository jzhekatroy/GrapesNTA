/* Исключения из статистики — правила net_flow_exclusions (ClickHouse) */

function collectorsT(key, params) {
  return GrapesI18n.t(key, params);
}

const CONDITION_TYPES = [
  { id: 'network', labelKey: 'collectorsPage.exclusion.condition.network' },
  { id: 'protocol', labelKey: 'collectorsPage.exclusion.condition.protocol' },
  { id: 'port', labelKey: 'collectorsPage.exclusion.condition.port' },
  { id: 'vlan', labelKey: 'collectorsPage.exclusion.condition.vlan' },
  { id: 'observation', labelKey: 'collectorsPage.exclusion.condition.observation' },
  { id: 'collector', labelKey: 'collectorsPage.exclusion.condition.collector' },
];

const MATCH_SIDES = [
  { value: 'any', labelKey: 'collectorsPage.exclusion.side.any' },
  { value: 'src', labelKey: 'collectorsPage.exclusion.side.src' },
  { value: 'dst', labelKey: 'collectorsPage.exclusion.side.dst' },
];

const PORT_SIDES = [
  { value: 'any', labelKey: 'collectorsPage.exclusion.side.any' },
  { value: 'src', labelKey: 'collectorsPage.exclusion.side.src' },
  { value: 'dst', labelKey: 'collectorsPage.exclusion.side.dst' },
];

const PROTO_PRESETS = [
  { value: 6, label: 'TCP' },
  { value: 17, label: 'UDP' },
  { value: 1, label: 'ICMP' },
  { value: -1, labelKey: 'collectorsPage.exclusion.protoOther' },
];

const PROTO_LABELS = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };

function warningBanner() {
  return collectorsT('collectorsPage.exclusion.warningBanner');
}

function rulesIndependenceNote() {
  return collectorsT('collectorsPage.exclusion.independenceNote');
}

function fmtRuleUpdatedAt(value) {
  if (!value) return '—';
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

function parseCidrClient(prefix) {
  const trimmed = String(prefix ?? '').trim();
  if (!trimmed) return { ok: false, error: collectorsT('collectorsPage.exclusion.err.cidr') };
  const slash = trimmed.indexOf('/');
  if (slash < 0) return { ok: false, error: collectorsT('collectorsPage.exclusion.err.cidr') };
  const ipPart = trimmed.slice(0, slash);
  const mask = Number(trimmed.slice(slash + 1));
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ipPart);
  const v6 = ipPart.includes(':');
  if (v4 && mask >= 0 && mask <= 32) return { ok: true, prefix: `${ipPart}/${mask}`, family: 4 };
  if (v6 && mask >= 0 && mask <= 128) return { ok: true, prefix: trimmed, family: 6 };
  return { ok: false, error: collectorsT('collectorsPage.exclusion.err.cidr') };
}

function isValidSwitchIp(value) {
  const switchIp = String(value ?? '').trim();
  if (!switchIp) return false;
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(switchIp);
  const v6 = switchIp.includes(':');
  return v4 || v6;
}

function resolveProto(condition) {
  if (!condition || condition.type !== 'protocol') return 0;
  if (condition.protoMode === -1) return Number(condition.protoCustom) || 0;
  return Number(condition.protoMode) || 0;
}

function resolvePortFrom(condition) {
  if (!condition || condition.type !== 'port') return 0;
  const from = condition.portFrom === '' ? 0 : Number(condition.portFrom);
  const to = condition.portTo === '' ? 0 : Number(condition.portTo);
  if (from > 0) return from;
  return to > 0 ? to : 0;
}

function resolvePortTo(condition) {
  if (!condition || condition.type !== 'port') return 0;
  const from = condition.portFrom === '' ? 0 : Number(condition.portFrom);
  const to = condition.portTo === '' ? 0 : Number(condition.portTo);
  if (from > 0 && to > 0) return to;
  if (from > 0) return from;
  return to > 0 ? to : 0;
}

function formatNetworkPhrase(prefix, matchSide) {
  if (!prefix) return null;
  if (matchSide === 'src') return collectorsT('collectorsPage.exclusion.phrase.network.src', { prefix });
  if (matchSide === 'dst') return collectorsT('collectorsPage.exclusion.phrase.network.dst', { prefix });
  return collectorsT('collectorsPage.exclusion.phrase.network.any', { prefix });
}

function formatProtocolPhrase(proto) {
  if (!proto || proto <= 0) return null;
  const label = PROTO_LABELS[proto] || String(proto);
  return collectorsT('collectorsPage.exclusion.phrase.protocol', { label });
}

function formatPortPhrase(portFrom, portTo, portSide) {
  const from = portFrom > 0 ? portFrom : 0;
  const to = portTo > 0 ? portTo : 0;
  if (!from && !to) return null;
  const lo = from || to;
  const hi = to || from;
  const sideKey = portSide === 'src' ? 'collectorsPage.exclusion.phrase.portSide.src'
    : portSide === 'dst' ? 'collectorsPage.exclusion.phrase.portSide.dst'
      : 'collectorsPage.exclusion.phrase.portSide.any';
  const side = collectorsT(sideKey);
  if (lo !== hi) return collectorsT('collectorsPage.exclusion.phrase.port.range', { side, from: lo, to: hi });
  return collectorsT('collectorsPage.exclusion.phrase.port.single', { side, port: lo });
}

function formatVlanPhrase(vlanId) {
  const id = Number(vlanId);
  if (!id || id <= 0) return null;
  return collectorsT('collectorsPage.exclusion.phrase.vlan', { id });
}

function formatObservationPhrase(switchIp, ifIndex) {
  const ip = String(switchIp ?? '').trim();
  if (!ip) return null;
  const idx = Number(ifIndex) || 0;
  if (idx > 0) return collectorsT('collectorsPage.exclusion.phrase.observation.port', { ip, port: idx });
  return collectorsT('collectorsPage.exclusion.phrase.observation.switch', { ip });
}

function formatCollectorPhrase(sourceId, flowSources) {
  const id = String(sourceId ?? '').trim();
  if (!id) return null;
  const src = (flowSources || []).find((s) => s.sourceId === id);
  const label = src?.displayName || src?.sourceName || id;
  return collectorsT('collectorsPage.exclusion.phrase.collector', { label });
}

function phraseFromCondition(condition, { includeCollector = true, flowSources = [] } = {}) {
  if (!condition) return null;
  switch (condition.type) {
    case 'network':
      return formatNetworkPhrase(String(condition.prefix || '').trim(), condition.matchSide || 'any');
    case 'protocol':
      return formatProtocolPhrase(resolveProto(condition));
    case 'port':
      return formatPortPhrase(
        resolvePortFrom(condition),
        resolvePortTo(condition),
        condition.portSide || 'any',
      );
    case 'vlan':
      return formatVlanPhrase(condition.vlanId);
    case 'observation':
      return formatObservationPhrase(condition.switchIp, condition.ifIndex);
    case 'collector':
      return includeCollector ? formatCollectorPhrase(condition.sourceId, flowSources) : null;
    default:
      return null;
  }
}

function phrasesFromConditions(conditions, options = {}) {
  return (conditions || [])
    .map((c) => phraseFromCondition(c, options))
    .filter(Boolean);
}

function joinPhrases(phrases, style) {
  if (!phrases.length) return '';
  if (style === 'preview') {
    if (phrases.length === 1) return phrases[0];
    return collectorsT('collectorsPage.exclusion.previewJoinSingle', {
      first: phrases[0],
      rest: phrases.slice(1).join(', '),
    });
  }
  return phrases.join(collectorsT('collectorsPage.exclusion.previewJoinTable'));
}

function formatRuleCondition(row, flowSources = []) {
  const conditions = rowToConditions(row);
  const phrases = phrasesFromConditions(conditions, { includeCollector: false, flowSources });
  return phrases.length ? joinPhrases(phrases, 'table') : '—';
}

function formatRulePreview(conditions, flowSources = []) {
  const phrases = phrasesFromConditions(conditions, { includeCollector: true, flowSources });
  if (!phrases.length) return collectorsT('collectorsPage.exclusion.previewNeedCondition');
  return collectorsT('collectorsPage.exclusion.previewWillDrop', { phrases: joinPhrases(phrases, 'preview') });
}

function defaultCondition(type) {
  const id = `c-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  switch (type) {
    case 'network':
      return { id, type, prefix: '', matchSide: 'any' };
    case 'protocol':
      return { id, type, protoMode: 17, protoCustom: '' };
    case 'port':
      return { id, type, portFrom: '', portTo: '', portSide: 'any' };
    case 'vlan':
      return { id, type, vlanId: '' };
    case 'observation':
      return { id, type, switchIp: '', ifIndex: '' };
    case 'collector':
      return { id, type, sourceId: '' };
    default:
      return { id, type };
  }
}

function rowToConditions(row) {
  if (!row) return [];
  const conditions = [];
  if (row.prefix) {
    conditions.push({
      ...defaultCondition('network'),
      prefix: row.prefix,
      matchSide: row.matchSide || 'any',
    });
  }
  if (row.proto > 0) {
    const known = [1, 6, 17].includes(row.proto);
    conditions.push({
      ...defaultCondition('protocol'),
      protoMode: known ? row.proto : -1,
      protoCustom: known ? '' : String(row.proto),
    });
  }
  if (row.portFrom > 0 || row.portTo > 0) {
    conditions.push({
      ...defaultCondition('port'),
      portFrom: row.portFrom > 0 ? String(row.portFrom) : '',
      portTo: row.portTo > 0 ? String(row.portTo) : '',
      portSide: row.portSide || 'any',
    });
  }
  if (row.vlanId > 0) {
    conditions.push({
      ...defaultCondition('vlan'),
      vlanId: String(row.vlanId),
    });
  }
  if (row.switchIp) {
    conditions.push({
      ...defaultCondition('observation'),
      switchIp: row.switchIp,
      ifIndex: row.ifIndex > 0 ? String(row.ifIndex) : '',
    });
  }
  if (row.sourceId) {
    conditions.push({
      ...defaultCondition('collector'),
      sourceId: row.sourceId,
    });
  }
  return conditions;
}

function conditionsToPayload(conditions, { displayName, comment, ruleId } = {}) {
  const payload = {
    displayName,
    comment,
    enabled: 1,
    prefix: '',
    family: 0,
    matchSide: 'any',
    proto: 0,
    portFrom: 0,
    portTo: 0,
    portSide: 'any',
    vlanId: 0,
    switchIp: '',
    ifIndex: 0,
    sourceId: '',
  };

  for (const c of conditions) {
    switch (c.type) {
      case 'network': {
        const parsed = parseCidrClient(c.prefix);
        if (parsed.ok) {
          payload.prefix = parsed.prefix;
          payload.family = parsed.family;
          payload.matchSide = c.matchSide || 'any';
        }
        break;
      }
      case 'protocol':
        payload.proto = resolveProto(c);
        break;
      case 'port': {
        const from = resolvePortFrom(c);
        const to = resolvePortTo(c);
        payload.portFrom = from;
        payload.portTo = to;
        payload.portSide = c.portSide || 'any';
        break;
      }
      case 'vlan':
        payload.vlanId = Number(c.vlanId) || 0;
        break;
      case 'observation':
        payload.switchIp = String(c.switchIp || '').trim();
        payload.ifIndex = c.ifIndex === '' ? 0 : Number(c.ifIndex) || 0;
        break;
      case 'collector':
        payload.sourceId = String(c.sourceId || '').trim();
        break;
      default:
        break;
    }
  }

  if (ruleId) payload.ruleId = ruleId;
  return payload;
}

function validateConditions(conditions) {
  if (!conditions.length) {
    return collectorsT('collectorsPage.exclusion.err.needCondition');
  }

  for (const c of conditions) {
    switch (c.type) {
      case 'network': {
        const parsed = parseCidrClient(c.prefix);
        if (!parsed.ok) return parsed.error;
        break;
      }
      case 'protocol': {
        const proto = resolveProto(c);
        if (c.protoMode === -1) {
          if (!Number.isInteger(proto) || proto < 0 || proto > 255) {
            return collectorsT('collectorsPage.exclusion.err.protoRange');
          }
        }
        if (!proto || proto <= 0) return collectorsT('collectorsPage.exclusion.err.protoRequired');
        break;
      }
      case 'port': {
        const fromRaw = c.portFrom === '' ? 0 : Number(c.portFrom);
        const toRaw = c.portTo === '' ? 0 : Number(c.portTo);
        if (!fromRaw && !toRaw) return collectorsT('collectorsPage.exclusion.err.portRequired');
        if (!Number.isInteger(fromRaw) || fromRaw < 0 || fromRaw > 65535
            || !Number.isInteger(toRaw) || toRaw < 0 || toRaw > 65535) {
          return collectorsT('collectorsPage.exclusion.err.portRange');
        }
        const from = fromRaw || toRaw;
        const to = toRaw || fromRaw;
        if (from > 0 && to > 0 && from > to) return collectorsT('collectorsPage.exclusion.err.portOrder');
        break;
      }
      case 'vlan': {
        const vlanId = Number(c.vlanId);
        if (!Number.isInteger(vlanId) || vlanId <= 0 || vlanId > 65535) {
          return collectorsT('collectorsPage.exclusion.err.vlan');
        }
        break;
      }
      case 'observation': {
        const switchIp = String(c.switchIp || '').trim();
        const ifIndex = c.ifIndex === '' ? 0 : Number(c.ifIndex);
        if (!switchIp) return collectorsT('collectorsPage.exclusion.err.switchIp');
        if (!isValidSwitchIp(switchIp)) return collectorsT('collectorsPage.exclusion.err.switchIpInvalid');
        if (ifIndex > 0 && !switchIp) return collectorsT('collectorsPage.exclusion.err.switchIpForPort');
        if (!Number.isInteger(ifIndex) || ifIndex < 0) return collectorsT('collectorsPage.exclusion.err.ifIndex');
        break;
      }
      case 'collector': {
        if (!String(c.sourceId || '').trim()) return collectorsT('collectorsPage.exclusion.err.pickCollector');
        break;
      }
      default:
        break;
    }
  }

  return '';
}

function isCollectorOnlyRule(conditions) {
  if (conditions.length !== 1 || conditions[0].type !== 'collector') return false;
  return !!String(conditions[0].sourceId || '').trim();
}

function PageFlowExclusions({ embedded = false, refreshKey: parentRefreshKey = 0, onReload } = {}) {
  const canWrite = AuthAccess.canWritePage('flow-exclusions');
  const [rows, setRows] = useState([]);
  const [flowSources, setFlowSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [localRefreshKey, setLocalRefreshKey] = useState(0);
  const [togglingId, setTogglingId] = useState(null);

  const refreshKey = onReload ? parentRefreshKey : localRefreshKey;
  const reload = useCallback(() => {
    if (onReload) onReload();
    else setLocalRefreshKey((k) => k + 1);
  }, [onReload]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const [res, fsRes] = await Promise.all([
        ApiClient.loadFlowExclusions(),
        ApiClient.loadFlowSources(),
      ]);
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
      } else {
        setRows((res.rows || []).map((r) => ({ ...r, id: r.ruleId })));
      }
      setFlowSources(fsRes.rows || []);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => {
      const cond = formatRuleCondition(r, flowSources).toLowerCase();
      return (
        (r.displayName || '').toLowerCase().includes(s)
        || (r.comment || '').toLowerCase().includes(s)
        || (r.sourceId || '').toLowerCase().includes(s)
        || cond.includes(s)
      );
    });
  }, [rows, search, flowSources]);

  const handleToggle = async (row) => {
    const next = row.enabled === 1 ? 0 : 1;
    const action = next === 1 ? collectorsT('collectorsPage.exclusion.actionEnable') : collectorsT('collectorsPage.exclusion.actionDisable');
    const name = row.displayName || formatRuleCondition(row, flowSources);
    if (!window.confirm(collectorsT('collectorsPage.exclusion.confirmToggle', { action, name }))) return;
    setTogglingId(row.id);
    try {
      await ApiClient.toggleFlowExclusion({ ruleId: row.ruleId, enabled: next });
      pushToast({ kind: 'success', title: collectorsT('collectorsPage.saveSuccessTitle'), desc: collectorsT('collectorsPage.saveSuccessDesc') });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: collectorsT('collectorsPage.exclusion.toast.statusFailed'), desc: err.message });
    } finally {
      setTogglingId(null);
    }
  };

  const handleDelete = async (row) => {
    const name = row.displayName || formatRuleCondition(row, flowSources);
    if (!window.confirm(collectorsT('collectorsPage.exclusion.confirmDelete', { name }))) return;
    try {
      await ApiClient.deleteFlowExclusion({ ruleId: row.ruleId });
      pushToast({ kind: 'success', title: collectorsT('collectorsPage.exclusion.toast.ruleDeleted'), desc: collectorsT('collectorsPage.exclusion.toast.ruleDeletedDesc') });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: collectorsT('collectorsPage.toast.deleteFailed'), desc: err.message });
    }
  };

  const cols = [
    {
      key: 'displayName',
      title: collectorsT('collectorsPage.col.name'),
      width: 200,
      sortAccessor: (r) => r.displayName || r.ruleId,
      render: (r) => (
        <div style={{ opacity: r.enabled === 1 ? 1 : 0.55 }}>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || '—'}</div>
          {r.comment && (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2 }}>
              {r.comment}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'condition',
      title: collectorsT('collectorsPage.exclusion.col.condition'),
      width: 360,
      sortAccessor: (r) => formatRuleCondition(r, flowSources),
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', opacity: r.enabled === 1 ? 1 : 0.55 }}>
          {formatRuleCondition(r, flowSources)}
        </span>
      ),
    },
    {
      key: 'sourceId',
      title: collectorsT('collectorsPage.exclusion.col.scope'),
      width: 160,
      sortAccessor: (r) => r.sourceId || '',
      render: (r) => (
        <span style={{ opacity: r.enabled === 1 ? 1 : 0.55 }}>
          {r.sourceId ? <span className="mono">{r.sourceId}</span> : collectorsT('collectorsPage.exclusion.scopeAllCollectors')}
        </span>
      ),
    },
    {
      key: 'enabled',
      title: collectorsT('collectorsPage.exclusion.col.status'),
      width: 88,
      sortAccessor: (r) => r.enabled,
      render: (r) => (
        <RuleEnabledToggle
          enabled={r.enabled === 1}
          disabled={!canWrite || togglingId === r.id}
          onChange={() => handleToggle(r)}
        />
      ),
    },
    {
      key: 'updatedAt',
      title: collectorsT('collectorsPage.col.updated'),
      width: 140,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', opacity: r.enabled === 1 ? 1 : 0.55 }}>
          {fmtRuleUpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ];

  const body = (
    <>
      {!embedded && (
        <div className="page-head">
          <div>
            <h1>{collectorsT('collectorsPage.exclusion.title')}</h1>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>{collectorsT('chrome.refresh')}</Button>
            <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>
              {collectorsT('collectorsPage.exclusion.addRule')}
            </Button>
          </div>
        </div>
      )}

      {embedded && (
        <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12 }}>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>
            {collectorsT('collectorsPage.exclusion.addRule')}
          </Button>
        </div>
      )}

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : loadError ? (
        <Empty icon="db" title={collectorsT('collectorsPage.empty.loadFailed')} desc={loadError} action={<Button kind="primary" icon="refresh" onClick={reload}>{collectorsT('collectorsPage.retry')}</Button>} />
      ) : (
        <>
          <p style={{ margin: '0 0 12px', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {rulesIndependenceNote()}
          </p>
          <DataTable
            rows={filtered}
            columns={cols}
            rowKey="id"
            pageSize={15}
            onRowClick={canWrite ? (r) => setEditing({ ...r, isNew: false }) : undefined}
            emptyTitle={collectorsT('collectorsPage.exclusion.emptyTitle')}
            emptyDesc={collectorsT('collectorsPage.exclusion.emptyDesc')}
            toolbar={{
              search,
              onSearch: setSearch,
            }}
            rowActions={canWrite ? (r) => (
              <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                <button className="icon-btn tt" data-tt={collectorsT('collectorsPage.edit')} onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
                  <Icon name="edit" size={15} />
                </button>
                <button className="icon-btn tt" data-tt={collectorsT('collectorsPage.delete')} onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
                  <Icon name="trash" size={15} />
                </button>
              </div>
            ) : null}
          />
        </>
      )}

      <FlowExclusionFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd || (editing && editing.isNew)}
        flowSources={flowSources}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          reload();
          pushToast({ kind: 'success', title: collectorsT('collectorsPage.saveSuccessTitle'), desc: collectorsT('collectorsPage.saveSuccessDesc') });
        }}
      />
    </>
  );

  if (embedded) return body;
  return <div className="main__container">{body}</div>;
}

function RuleEnabledToggle({ enabled, disabled, onChange }) {
  return (
    <button
      type="button"
      className="l3-enabled-toggle"
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onChange(); }}
      title={enabled ? collectorsT('collectorsPage.exclusion.toggleDisable') : collectorsT('collectorsPage.exclusion.toggleEnable')}
      aria-pressed={enabled}
      style={{
        width: 36,
        height: 20,
        borderRadius: 999,
        border: 'none',
        padding: 0,
        cursor: disabled ? 'wait' : 'pointer',
        background: enabled ? 'var(--grad-primary)' : 'var(--surf-4)',
        position: 'relative',
        transition: 'background var(--pv-dur-fast)',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      <span style={{
        position: 'absolute',
        top: 2,
        left: enabled ? 18 : 2,
        width: 16,
        height: 16,
        borderRadius: 999,
        background: 'var(--pv-white-main)',
        transition: 'left var(--pv-dur-fast) var(--pv-ease-out)',
      }} />
    </button>
  );
}

function ConditionAndSeparator() {
  return (
    <div style={{
      textAlign: 'center',
      color: 'var(--fg-secondary)',
      font: 'var(--pv-text-body-2-bold)',
      padding: '2px 0',
    }}
    >{collectorsT('collectorsPage.exclusion.andSeparator')}</div>
  );
}

function ConditionCard({ condition, label, onRemove, children }) {
  return (
    <div className="card card--pad-sm" style={{ position: 'relative' }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{label}</div>
        <button
          type="button"
          className="icon-btn"
          title={collectorsT('collectorsPage.exclusion.removeCondition')}
          onClick={onRemove}
        >
          <Icon name="x" size={16} />
        </button>
      </div>
      {children}
    </div>
  );
}

function ObservationConditionFields({ condition, onChange, switches }) {
  const [ports, setPorts] = useState([]);

  useEffect(() => {
    const switchIp = String(condition.switchIp || '').trim();
    if (!switchIp) {
      setPorts([]);
      return undefined;
    }
    let cancelled = false;
    (async () => {
      const res = await ApiClient.loadInterfaceRolesForSwitch(switchIp);
      if (!cancelled) setPorts(res.rows || []);
    })();
    return () => { cancelled = true; };
  }, [condition.switchIp]);

  return (
    <div className="grid grid--2col">
      <div className="field">
        <label>{collectorsT('collectorsPage.exclusion.label.switchIp')}</label>
        <input
          className="input mono"
          list={`flow-exclusion-switches-${condition.id}`}
          placeholder="192.0.2.7"
          value={condition.switchIp}
          onChange={(e) => onChange({ ...condition, switchIp: e.target.value })}
        />
        <datalist id={`flow-exclusion-switches-${condition.id}`}>
          {switches.map((s) => (
            <option key={s.switchIp} value={s.switchIp}>{s.displayName || s.switchIp}</option>
          ))}
        </datalist>
      </div>
      <div className="field">
        <label>{collectorsT('collectorsPage.exclusion.label.ifIndex')}</label>
        <input
          className="input mono"
          list={`flow-exclusion-ports-${condition.id}`}
          placeholder={collectorsT('collectorsPage.optional')}
          value={condition.ifIndex}
          onChange={(e) => onChange({ ...condition, ifIndex: e.target.value })}
        />
        <datalist id={`flow-exclusion-ports-${condition.id}`}>
          {ports.map((p) => (
            <option key={p.ifIndex} value={p.ifIndex}>{p.ifName || p.ifIndex}</option>
          ))}
        </datalist>
      </div>
    </div>
  );
}

function FlowExclusionFormModal({ open, row, isNew, flowSources, onClose, onSaved }) {
  const [displayName, setDisplayName] = useState('');
  const [comment, setComment] = useState('');
  const [conditions, setConditions] = useState([]);
  const [switches, setSwitches] = useState([]);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const addMenuRef = useRef(null);

  const usedTypes = useMemo(() => new Set(conditions.map((c) => c.type)), [conditions]);
  const availableTypes = useMemo(
    () => CONDITION_TYPES.filter((t) => !usedTypes.has(t.id)),
    [usedTypes],
  );

  const previewText = useMemo(
    () => formatRulePreview(conditions, flowSources),
    [conditions, flowSources],
  );

  const validationError = useMemo(
    () => (conditions.length ? validateConditions(conditions) : ''),
    [conditions],
  );

  const canSave = conditions.length > 0 && !validationError && !saving;

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    (async () => {
      const swRes = await ApiClient.loadInterfaceRoleSwitches();
      if (!cancelled) setSwitches(swRes.rows || []);
    })();
    return () => { cancelled = true; };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    if (isNew) {
      setDisplayName('');
      setComment('');
      setConditions([]);
    } else if (row) {
      setDisplayName(row.displayName || '');
      setComment(row.comment || '');
      setConditions(rowToConditions(row));
    }
    setFormError('');
    setAddMenuOpen(false);
  }, [open, isNew, row]);

  useEffect(() => {
    if (!addMenuOpen) return undefined;
    const onDocClick = (e) => {
      if (addMenuRef.current?.contains(e.target)) return;
      setAddMenuOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, [addMenuOpen]);

  const updateCondition = (id, next) => {
    setConditions((prev) => prev.map((c) => (c.id === id ? next : c)));
  };

  const removeCondition = (id) => {
    setConditions((prev) => prev.filter((c) => c.id !== id));
  };

  const addCondition = (type) => {
    setConditions((prev) => [...prev, defaultCondition(type)]);
    setAddMenuOpen(false);
  };

  const handleSave = async () => {
    const err = validateConditions(conditions);
    if (err) {
      setFormError(err);
      return;
    }

    if (isCollectorOnlyRule(conditions)) {
      const ok = window.confirm(collectorsT('collectorsPage.exclusion.confirmCollectorOnly'));
      if (!ok) return;
    }

    const payload = conditionsToPayload(conditions, {
      displayName,
      comment,
      ruleId: !isNew && row?.ruleId ? row.ruleId : undefined,
    });

    setSaving(true);
    setFormError('');
    try {
      await ApiClient.saveFlowExclusion(payload);
      onSaved();
    } catch (e) {
      setFormError(e.message || collectorsT('collectorsPage.exclusion.saveError'));
    } finally {
      setSaving(false);
    }
  };

  const renderConditionFields = (condition) => {
    switch (condition.type) {
      case 'network':
        return (
          <div className="grid grid--2col">
            <div className="field">
              <label>{collectorsT('collectorsPage.exclusion.label.prefix')}</label>
              <input
                className="input mono"
                placeholder="10.0.0.0/8"
                value={condition.prefix}
                onChange={(e) => updateCondition(condition.id, { ...condition, prefix: e.target.value })}
              />
            </div>
            <div className="field">
              <label>{collectorsT('collectorsPage.exclusion.label.addressSide')}</label>
              <select
                className="input"
                value={condition.matchSide}
                onChange={(e) => updateCondition(condition.id, { ...condition, matchSide: e.target.value })}
              >
                {MATCH_SIDES.map((s) => (
                  <option key={s.value} value={s.value}>{collectorsT(s.labelKey)}</option>
                ))}
              </select>
            </div>
          </div>
        );
      case 'protocol':
        return (
          <div className="grid grid--2col">
            <div className="field">
              <label>{collectorsT('collectorsPage.exclusion.label.protocol')}</label>
              <select
                className="input"
                value={condition.protoMode}
                onChange={(e) => updateCondition(condition.id, { ...condition, protoMode: Number(e.target.value) })}
              >
                {PROTO_PRESETS.map((p) => (
                  <option key={p.value} value={p.value}>{p.labelKey ? collectorsT(p.labelKey) : p.label}</option>
                ))}
              </select>
            </div>
            {condition.protoMode === -1 && (
              <div className="field">
                <label>{collectorsT('collectorsPage.exclusion.label.protocolNumber')}</label>
                <input
                  className="input mono"
                  placeholder="0–255"
                  value={condition.protoCustom}
                  onChange={(e) => updateCondition(condition.id, { ...condition, protoCustom: e.target.value })}
                />
              </div>
            )}
          </div>
        );
      case 'port':
        return (
          <div className="grid grid--2col">
            <div className="field">
              <label>{collectorsT('collectorsPage.exclusion.label.portFrom')}</label>
              <input
                className="input mono"
                placeholder="122"
                value={condition.portFrom}
                onChange={(e) => updateCondition(condition.id, { ...condition, portFrom: e.target.value })}
              />
            </div>
            <div className="field">
              <label>{collectorsT('collectorsPage.exclusion.label.portTo')}</label>
              <input
                className="input mono"
                placeholder={collectorsT('collectorsPage.optional')}
                value={condition.portTo}
                onChange={(e) => updateCondition(condition.id, { ...condition, portTo: e.target.value })}
              />
            </div>
            <div className="field" style={{ gridColumn: '1 / -1' }}>
              <label>{collectorsT('collectorsPage.exclusion.label.portSide')}</label>
              <select
                className="input"
                value={condition.portSide}
                onChange={(e) => updateCondition(condition.id, { ...condition, portSide: e.target.value })}
              >
                {PORT_SIDES.map((s) => (
                  <option key={s.value} value={s.value}>{collectorsT(s.labelKey)}</option>
                ))}
              </select>
            </div>
          </div>
        );
      case 'vlan':
        return (
          <div className="field">
            <label>{collectorsT('collectorsPage.exclusion.label.vlanId')}</label>
            <input
              className="input mono"
              placeholder="100"
              value={condition.vlanId}
              onChange={(e) => updateCondition(condition.id, { ...condition, vlanId: e.target.value })}
            />
          </div>
        );
      case 'observation':
        return (
          <ObservationConditionFields
            condition={condition}
            switches={switches}
            onChange={(next) => updateCondition(condition.id, next)}
          />
        );
      case 'collector':
        return (
          <div className="field">
            <label>{collectorsT('collectorsPage.exclusion.label.collectorSource')}</label>
            <select
              className="input mono"
              value={condition.sourceId}
              onChange={(e) => updateCondition(condition.id, { ...condition, sourceId: e.target.value })}
            >
              <option value="">{collectorsT('collectorsPage.exclusion.selectCollector')}</option>
              {flowSources.map((s) => (
                <option key={s.sourceId} value={s.sourceId}>
                  {s.displayName || s.sourceName || s.sourceId} ({s.sourceId})
                </option>
              ))}
            </select>
          </div>
        );
      default:
        return null;
    }
  };

  if (!open) return null;

  const conditionLabel = (type) => { const t = CONDITION_TYPES.find((x) => x.id === type); return t ? collectorsT(t.labelKey) : type; };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? collectorsT('collectorsPage.exclusion.modal.add') : collectorsT('collectorsPage.exclusion.modal.edit')}
      subtitle={isNew ? collectorsT('collectorsPage.exclusion.modal.subtitleNew') : (row?.displayName || formatRuleCondition(row || {}, flowSources))}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>{collectorsT('collectorsPage.cancel')}</Button>
          <Button kind="primary" icon="save" onClick={handleSave} disabled={!canSave}>
            {saving ? collectorsT('collectorsPage.saving') : collectorsT('collectorsPage.save')}
          </Button>
        </>
      }
    >
      {formError && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
          {formError}
        </div>
      )}

      <div className="grid grid--2col">
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{collectorsT('collectorsPage.col.name')}</label>
          <input className="input" placeholder={collectorsT('collectorsPage.exclusion.placeholder.ruleName')} value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{collectorsT('collectorsPage.col.comment')}</label>
          <input className="input" placeholder={collectorsT('collectorsPage.optional')} value={comment} onChange={(e) => setComment(e.target.value)} />
        </div>
      </div>

      <div style={{ marginTop: 20 }}>
        <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 10 }}>{collectorsT('collectorsPage.exclusion.conditionsTitle')}</div>

        {conditions.length === 0 && (
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginBottom: 12 }}>
            {collectorsT('collectorsPage.exclusion.noConditions')}
          </div>
        )}

        {conditions.map((condition, index) => (
          <React.Fragment key={condition.id}>
            {index > 0 && <ConditionAndSeparator />}
            <ConditionCard
              condition={condition}
              label={conditionLabel(condition.type)}
              onRemove={() => removeCondition(condition.id)}
            >
              {renderConditionFields(condition)}
            </ConditionCard>
          </React.Fragment>
        ))}

        {availableTypes.length > 0 && (
          <div ref={addMenuRef} style={{ position: 'relative', marginTop: 14 }}>
            <Button kind="ghost" icon="plus" onClick={() => setAddMenuOpen((v) => !v)}>
              {collectorsT('collectorsPage.exclusion.addCondition')}
            </Button>
            {addMenuOpen && (
              <div style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                marginTop: 6,
                minWidth: 220,
                background: 'var(--bg-surface)',
                border: '1px solid var(--bd-default)',
                borderRadius: 10,
                boxShadow: 'var(--pv-shadow-popover)',
                padding: 6,
                zIndex: 20,
              }}
              >
                {availableTypes.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    className="btn btn--ghost btn--sm"
                    style={{ width: '100%', justifyContent: 'flex-start' }}
                    onClick={() => addCondition(t.id)}
                  >
                    {collectorsT(t.labelKey)}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div style={{
        marginTop: 16,
        padding: '12px 14px',
        borderRadius: 8,
        background: 'var(--surf-2)',
        color: 'var(--fg-secondary)',
        font: 'var(--pv-text-body-3)',
        lineHeight: 1.5,
      }}
      >
        {previewText}
      </div>

      <div style={{
        marginTop: 12,
        padding: '12px 14px',
        borderRadius: 8,
        background: 'var(--st-warning-bg)',
        color: 'var(--fg-secondary)',
        font: 'var(--pv-text-body-3)',
        lineHeight: 1.5,
      }}
      >
        {warningBanner()}
      </div>
    </Modal>
  );
}

Object.assign(window, { PageFlowExclusions });
