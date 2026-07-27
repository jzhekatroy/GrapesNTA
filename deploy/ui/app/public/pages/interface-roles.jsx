/* Порты оборудования — разметка boundary/connectivity и отчёт «сети vs порты». */

const { useCallback, useEffect, useMemo, useState } = React;

const TRAFFIC_HOUR_OPTIONS = [1, 3, 6, 12, 24];

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
  return {
    switchIp: params.get('switch') || '',
    onlyUnmarked: params.get('only_unmarked') === '1',
  };
}

function buildInterfaceRolesHash({ switchIp, onlyUnmarked } = {}) {
  const q = new URLSearchParams();
  if (switchIp) q.set('switch', switchIp);
  if (onlyUnmarked) q.set('only_unmarked', '1');
  const s = q.toString();
  return s ? `#interface-roles?${s}` : '#interface-roles';
}

function IrSumCard({ label, value, hint, action }) {
  return (
    <Card pad="sm" className="ir-sum-card">
      <div className="ir-sum-card__label">{label}</div>
      <div className="ir-sum-card__value">{value}</div>
      {hint && <div className="ir-sum-card__hint">{hint}</div>}
      {action}
    </Card>
  );
}

function DirectionSettingsCard({ settings, options, canWrite, onSaved }) {
  const [form, setForm] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!settings) return;
    setForm({ ...settings });
    setError('');
  }, [settings]);

  if (!form) return null;
  const set = (k, v) => setForm((s) => ({ ...s, [k]: v }));

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      await ApiClient.saveDirectionSettings({
        directionMode: form.directionMode,
        defaultBoundary: form.defaultBoundary,
        oneSided: form.oneSided,
      });
      pushToast({ kind: 'success', title: 'Настройки сохранены' });
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const boundaries = options?.boundaries || ['unknown', 'internal', 'external'];
  const policies = options?.oneSidedPolicies || ['strict', 'infer'];
  const modes = options?.directionModes || ['prefixes', 'ports'];

  return (
    <Card pad="sm" title="Настройки" style={{ marginBottom: 16 }}>
      {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}
      <div className="grid grid--3col grid--gap-sm">
        <div className="field">
          <label>Определение направления</label>
          <select className="input" value={form.directionMode} disabled={!canWrite} onChange={(e) => set('directionMode', e.target.value)}>
            {modes.map((m) => <option key={m} value={m}>{IR_DIRECTION_MODE_LABELS[m] || m}</option>)}
          </select>
          <div className="field-hint">По портам заработает после обновления коллектора</div>
        </div>
        <div className="field">
          <label>Неразмеченный порт считать</label>
          <select className="input" value={form.defaultBoundary} disabled={!canWrite} onChange={(e) => set('defaultBoundary', e.target.value)}>
            {boundaries.map((b) => <option key={b} value={b}>{irBoundaryLabel(b)}</option>)}
          </select>
          <div className="field-hint">«Не определён» — дыры в разметке будут видны в отчётах</div>
        </div>
        <div className="field">
          <label>Если известна только одна сторона</label>
          <select className="input" value={form.oneSided} disabled={!canWrite} onChange={(e) => set('oneSided', e.target.value)}>
            {policies.map((p) => <option key={p} value={p}>{IR_ONE_SIDED_LABELS[p] || p}</option>)}
          </select>
          <div className="field-hint">Нужно, когда экспортёр не отдаёт выходной интерфейс</div>
        </div>
      </div>
      {canWrite && (
        <div className="row" style={{ justifyContent: 'flex-end', marginTop: 12 }}>
          <Button kind="primary" icon="save" onClick={save} disabled={saving}>{saving ? 'Сохранение…' : 'Сохранить'}</Button>
        </div>
      )}
    </Card>
  );
}

function InterfaceRoleRuleModal({ open, rule, onClose, onSaved, canWrite }) {
  const empty = {
    ruleId: '', priority: 100, matchField: 'descr', pattern: '', caseSensitive: false,
    minSpeedMbps: '', maxSpeedMbps: '', boundary: '', connectivity: '', comment: '', enabled: true,
  };
  const [form, setForm] = useState(empty);
  const [preview, setPreview] = useState(null);
  const [previewError, setPreviewError] = useState('');
  const [previewLoading, setPreviewLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const debouncedForm = useDebouncedValue(form, 300);

  useEffect(() => {
    if (!open) return;
    setForm(rule ? { ...empty, ...rule, minSpeedMbps: rule.minSpeedMbps || '', maxSpeedMbps: rule.maxSpeedMbps || '' } : empty);
    setPreview(null);
    setPreviewError('');
    setError('');
  }, [open, rule]);

  useEffect(() => {
    if (!open) return undefined;
    const hasCondition = debouncedForm.pattern?.trim()
      || Number(debouncedForm.minSpeedMbps) > 0
      || Number(debouncedForm.maxSpeedMbps) > 0;
    if (!hasCondition) {
      setPreview(null);
      setPreviewError('');
      return undefined;
    }
    let cancelled = false;
    setPreviewLoading(true);
    ApiClient.previewInterfaceRoleRule({
      ...debouncedForm,
      minSpeedMbps: Number(debouncedForm.minSpeedMbps) || 0,
      maxSpeedMbps: Number(debouncedForm.maxSpeedMbps) || 0,
      limit: 20,
    }).then((res) => {
      if (cancelled) return;
      if (res.source === 'error') {
        setPreview(null);
        setPreviewError(res.error);
      } else {
        setPreview(res.data);
        setPreviewError('');
      }
      setPreviewLoading(false);
    });
    return () => { cancelled = true; };
  }, [open, debouncedForm]);

  if (!open) return null;
  const set = (k, v) => setForm((s) => ({ ...s, [k]: v }));

  const validate = () => {
    const hasCondition = form.pattern?.trim() || Number(form.minSpeedMbps) > 0 || Number(form.maxSpeedMbps) > 0;
    const hasAssign = (form.boundary && form.boundary !== 'unknown') || form.connectivity;
    if (!hasCondition) return 'Задайте шаблон или диапазон скорости';
    if (!hasAssign) return 'Задайте сторону или тип стыка';
    return '';
  };

  const save = async () => {
    const err = validate();
    if (err) { setError(err); return; }
    setSaving(true);
    setError('');
    try {
      await ApiClient.saveInterfaceRoleRule({
        ...form,
        minSpeedMbps: Number(form.minSpeedMbps) || 0,
        maxSpeedMbps: Number(form.maxSpeedMbps) || 0,
        boundary: form.boundary || '',
        connectivity: form.connectivity || '',
      });
      onSaved();
      onClose();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const previewCols = [
    { key: 'switchIp', title: 'Коммутатор', width: 130, render: (r) => <span className="mono">{r.switchIp}</span> },
    { key: 'ifName', title: 'Порт', width: 140, render: (r) => <span className="mono">{r.ifName || r.ifIndex}</span> },
    { key: 'ifDescr', title: 'Описание', width: 180, render: (r) => r.ifDescr || '—' },
    { key: 'speedMbps', title: 'Мбит/с', width: 80, render: (r) => <span className="mono">{r.speedMbps || '—'}</span> },
  ];

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={rule?.ruleId ? 'Редактировать правило' : 'Новое правило'}
      size="lg"
      footer={(
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          {canWrite && <Button kind="primary" icon="save" onClick={save} disabled={saving}>{saving ? 'Сохранение…' : 'Сохранить'}</Button>}
        </>
      )}
    >
      {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}
      <div className="grid grid--2col grid--gap-sm">
        <div className="field">
          <label>Приоритет</label>
          <input className="input mono" type="number" value={form.priority} onChange={(e) => set('priority', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Поле</label>
          <select className="input" value={form.matchField} onChange={(e) => set('matchField', e.target.value)} disabled={!canWrite}>
            {Object.entries(IR_MATCH_FIELD_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Шаблон (regex)</label>
          <input className="input mono" value={form.pattern} onChange={(e) => set('pattern', e.target.value)} disabled={!canWrite} placeholder="^(?:UPLINK|MAG)" />
          {previewError && <div className="field-error">{previewError}</div>}
        </div>
        <div className="field">
          <label className="row" style={{ gap: 8 }}>
            <input type="checkbox" checked={form.caseSensitive} onChange={(e) => set('caseSensitive', e.target.checked)} disabled={!canWrite} />
            Учитывать регистр
          </label>
        </div>
        <div className="field">
          <label>Скорость от, Мбит/с</label>
          <input className="input mono" type="number" value={form.minSpeedMbps} onChange={(e) => set('minSpeedMbps', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Скорость до, Мбит/с</label>
          <input className="input mono" type="number" value={form.maxSpeedMbps} onChange={(e) => set('maxSpeedMbps', e.target.value)} disabled={!canWrite} />
        </div>
        <div className="field">
          <label>Сторона</label>
          <select className="input" value={form.boundary} onChange={(e) => set('boundary', e.target.value)} disabled={!canWrite}>
            <option value="">Не менять</option>
            <option value="internal">Наша сторона</option>
            <option value="external">Внешняя</option>
          </select>
        </div>
        <div className="field">
          <label>Тип стыка</label>
          <select className="input" value={form.connectivity} onChange={(e) => set('connectivity', e.target.value)} disabled={!canWrite}>
            <option value="">Не менять</option>
            {Object.entries(IR_CONNECTIVITY_LABELS).filter(([k]) => k).map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
        </div>
      </div>
      <div style={{ marginTop: 16 }}>
        <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 8 }}>
          Предпросмотр {previewLoading ? '…' : preview ? `— найдено ${preview.total} портов` : ''}
        </div>
        {preview?.interfaces?.length ? (
          <DataTable rows={preview.interfaces.map((r, i) => ({ ...r, id: i }))} columns={previewCols} rowKey="id" pageSize={10} />
        ) : (
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Измените условия — покажем совпадения</div>
        )}
      </div>
    </Modal>
  );
}

function DirectionCompareMatrix({ cells, totalBytes }) {
  const directions = ['in', 'out', 'internal', 'transit', 'unknown'];
  const matrix = useMemo(() => {
    const map = new Map();
    for (const c of cells || []) {
      map.set(`${c.portDirection}|${c.chDirection}`, c);
    }
    return map;
  }, [cells]);

  const pct = (bytes) => (totalBytes ? `${((bytes * 100) / totalBytes).toFixed(1)}%` : '0%');

  return (
    <div className="ir-compare-matrix-wrap">
      <table className="table ir-compare-matrix">
        <thead>
          <tr>
            <th>Порты ↓ / Сети →</th>
            {directions.map((d) => <th key={d}>{irDirectionLabel(d)}</th>)}
          </tr>
        </thead>
        <tbody>
          {directions.map((rowDir) => (
            <tr key={rowDir}>
              <th>{irDirectionLabel(rowDir)}</th>
              {directions.map((colDir) => {
                const cell = matrix.get(`${rowDir}|${colDir}`) || { bytes: 0 };
                const match = rowDir === colDir;
                const unknown = rowDir === 'unknown' || colDir === 'unknown';
                const cls = match ? 'ir-matrix-cell--match' : unknown ? 'ir-matrix-cell--unknown' : 'ir-matrix-cell--mismatch';
                return (
                  <td key={colDir} className={cls} title={`${fmtBytes(cell.bytes)} · ${pct(cell.bytes)}`}>
                    <div className="mono">{fmtBytes(cell.bytes)}</div>
                    <div className="ir-matrix-cell__pct">{pct(cell.bytes)}</div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function compareNarrative(cells, totalBytes) {
  if (!cells?.length || !totalBytes) return '';
  const mismatches = cells.filter((c) => c.portDirection !== c.chDirection && c.portDirection !== 'unknown');
  if (!mismatches.length) return 'Модели совпадают по всем направлениям с ненулевым трафиком.';
  const top = [...mismatches].sort((a, b) => b.bytes - a.bytes)[0];
  const share = ((top.bytes * 100) / totalBytes).toFixed(1);
  return `${share}% трафика портовая модель считает «${irDirectionLabel(top.portDirection)}», а текущая — «${irDirectionLabel(top.chDirection)}». Обычно это клиентские сети, которых нет в справочнике «Собственные сети (CIDR)».`;
}

function PageInterfaceRoles({ onNavigate }) {
  const canWrite = AuthAccess.canWritePage('interface-roles');
  const hashInit = useMemo(() => readInterfaceRolesHashParams(), []);
  const [refreshKey, setRefreshKey] = useState(0);
  const [settings, setSettings] = useState(null);
  const [options, setOptions] = useState(null);
  const [summary, setSummary] = useState(null);
  const [rules, setRules] = useState([]);
  const [trafficRows, setTrafficRows] = useState([]);
  const [trafficStats, setTrafficStats] = useState(null);
  const [coverage, setCoverage] = useState(null);
  const [compare, setCompare] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [hours, setHours] = useState(1);
  const [onlyUnmarked, setOnlyUnmarked] = useState(!!hashInit.onlyUnmarked);
  const [switchIp, setSwitchIp] = useState(hashInit.switchIp || '');
  const [asnThreshold, setAsnThreshold] = useState(50);
  const [compareOneSided, setCompareOneSided] = useState('strict');
  const [editingRule, setEditingRule] = useState(null);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [switchPanelIp, setSwitchPanelIp] = useState(hashInit.switchIp || '');
  const [switchPorts, setSwitchPorts] = useState([]);
  const [switchPortsLoading, setSwitchPortsLoading] = useState(false);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError('');
      const [settingsR, summaryR, rulesR, trafficR, coverageR, compareR] = await Promise.all([
        ApiClient.loadDirectionSettings(),
        ApiClient.loadInterfaceRoleSummary(),
        ApiClient.loadInterfaceRoleRules(),
        ApiClient.loadDirectionInterfaces({
          hours, limit: 100, onlyUnmarked, asnThreshold, switchIp: switchIp || undefined,
        }),
        ApiClient.loadDirectionCoverage(hours),
        ApiClient.loadDirectionCompare({ hours, oneSided: compareOneSided }),
      ]);
      if (cancelled) return;
      if (settingsR.source === 'error') {
        setLoadError(settingsR.error || ApiClient.LOAD_FAILED);
      } else {
        setSettings(settingsR.data);
        setOptions(settingsR.data?.options || null);
        setCompareOneSided(settingsR.data?.oneSided || 'strict');
      }
      setSummary(summaryR.source === 'error' ? null : summaryR.data);
      setRules(rulesR.source === 'error' ? [] : rulesR.rows);
      setTrafficRows(trafficR.source === 'error' ? [] : trafficR.rows);
      setTrafficStats(trafficR.stats || null);
      setCoverage(coverageR.source === 'error' ? null : coverageR.data);
      setCompare(compareR.source === 'error' ? null : compareR.data);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [hours, onlyUnmarked, switchIp, asnThreshold, compareOneSided, refreshKey]);

  useEffect(() => {
    if (!switchPanelIp) { setSwitchPorts([]); return undefined; }
    let cancelled = false;
    setSwitchPortsLoading(true);
    ApiClient.loadInterfaceRolesForSwitch(switchPanelIp).then((res) => {
      if (cancelled) return;
      setSwitchPorts(res.source === 'error' ? [] : res.rows);
      setSwitchPortsLoading(false);
    });
    return () => { cancelled = true; };
  }, [switchPanelIp, refreshKey]);

  const afterMutation = async () => {
    reload();
  };

  const applySuggestion = async (row) => {
    if (!canWrite) return;
    try {
      await ApiClient.saveInterfaceRole({
        switchIp: row.switchIp,
        ifIndex: row.ifIndex,
        boundary: row.suggestedBoundary,
        connectivity: '',
      });
      pushToast({ kind: 'success', title: 'Разметка применена' });
      afterMutation();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось применить', desc: err.message });
    }
  };

  const resetManual = async (row) => {
    if (!canWrite) return;
    try {
      await ApiClient.deleteInterfaceRole({ switchIp: row.switchIp, ifIndex: row.ifIndex });
      pushToast({ kind: 'success', title: 'Ручная разметка сброшена' });
      afterMutation();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сбросить', desc: err.message });
    }
  };

  const saveSwitchPortRole = async (row, patch) => {
    if (!canWrite) return;
    try {
      await ApiClient.saveInterfaceRole({
        switchIp: switchPanelIp,
        ifIndex: row.ifIndex,
        boundary: patch.boundary ?? row.boundary,
        connectivity: patch.connectivity ?? row.connectivity ?? '',
      });
      pushToast({ kind: 'success', title: 'Разметка сохранена' });
      afterMutation();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сохранить', desc: err.message });
    }
  };

  const resetSwitchPortManual = async (row) => {
    if (!canWrite) return;
    try {
      await ApiClient.deleteInterfaceRole({ switchIp: switchPanelIp, ifIndex: row.ifIndex });
      pushToast({ kind: 'success', title: 'Ручная разметка сброшена' });
      afterMutation();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сбросить', desc: err.message });
    }
  };

  const boundaryOptions = options?.boundaries || ['unknown', 'internal', 'external'];
  const connectivityOptions = options?.connectivity || ['', 'customer', 'transit', 'pni', 'ppni', 'ix', 'core', 'cgnat', 'mgmt'];

  const toggleRuleEnabled = async (rule) => {
    if (!canWrite) return;
    try {
      await ApiClient.saveInterfaceRoleRule({ ...rule, enabled: !rule.enabled });
      afterMutation();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сохранить', desc: err.message });
    }
  };

  const deleteRule = async (rule) => {
    if (!canWrite || !window.confirm('Удалить правило?')) return;
    try {
      await ApiClient.deleteInterfaceRoleRule({ ruleId: rule.ruleId });
      afterMutation();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const coverageProblems = useMemo(() => {
    const problems = [];
    if (coverage && coverage.flowsWithAnyPercent < 80) {
      problems.push({
        level: 'warning',
        text: `Только ${coverage.flowsWithAnyPercent}% flow имеют in_if/out_if — портовая модель на таких данных работать не будет.`,
      });
    }
    if (coverage && coverage.flowsInIfOtherFormat > coverage.flowsWithInIf * 0.1) {
      problems.push({
        level: 'warning',
        text: 'Входной интерфейс приходит почти всегда, выходной часто в другом формате — попробуйте одностороннюю классификацию.',
      });
    }
    return problems;
  }, [coverage]);

  const ruleCols = [
    { key: 'priority', title: 'Приоритет', width: 90, sortAccessor: (r) => r.priority, render: (r) => <span className="mono">{r.priority}</span> },
    {
      key: 'condition',
      title: 'Условие',
      width: 220,
      render: (r) => (
        <div className="mono" style={{ fontSize: 12 }}>
          {IR_MATCH_FIELD_LABELS[r.matchField]} {r.pattern ? `/ ${r.pattern}/` : ''}
          {(r.minSpeedMbps || r.maxSpeedMbps) ? ` · ${r.minSpeedMbps || 0}–${r.maxSpeedMbps || '∞'} Мбит/с` : ''}
        </div>
      ),
    },
    { key: 'boundary', title: 'Сторона', width: 110, render: (r) => r.boundary ? irBoundaryLabel(r.boundary) : '—' },
    { key: 'connectivity', title: 'Тип стыка', width: 110, render: (r) => r.connectivity ? irConnectivityLabel(r.connectivity) : '—' },
    {
      key: 'enabled',
      title: 'Вкл.',
      width: 70,
      render: (r) => (
        <Checkbox checked={r.enabled} disabled={!canWrite} onChange={() => toggleRuleEnabled(r)} />
      ),
    },
    {
      key: 'actions',
      title: '',
      width: 90,
      render: (r) => canWrite && (
        <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
          <button className="icon-btn" title="Редактировать" onClick={() => { setEditingRule(r); setShowRuleModal(true); }}><Icon name="edit" size={14} /></button>
          <button className="icon-btn" title="Удалить" onClick={() => deleteRule(r)}><Icon name="trash" size={14} /></button>
        </div>
      ),
    },
  ];

  const trafficCols = [
    {
      key: 'switchIp',
      title: 'Коммутатор',
      width: 130,
      render: (r) => <span className="mono">{r.switchIp}</span>,
    },
    {
      key: 'port',
      title: 'Порт',
      width: 200,
      render: (r) => (
        <div>
          <div className="mono">{r.ifName || r.ifIndex}</div>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {[r.ifDescr, r.speedMbps ? `${r.speedMbps} Мбит/с` : ''].filter(Boolean).join(' · ') || '—'}
          </div>
        </div>
      ),
    },
    {
      key: 'boundary',
      title: 'Сторона',
      width: 120,
      render: (r) => (
        <Badge tone={r.boundary === 'unknown' ? 'neutral' : irBoundaryBadgeTone(r.boundary)}>
          {irBoundaryLabel(r.boundary)}
        </Badge>
      ),
    },
    {
      key: 'source',
      title: 'Источник',
      width: 100,
      render: (r) => <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>{irSourceLabel(r.boundarySource)}</span>,
    },
    {
      key: 'connectivity',
      title: 'Тип стыка',
      width: 110,
      render: (r) => r.connectivity ? <Badge tone="info">{irConnectivityLabel(r.connectivity)}</Badge> : '—',
    },
    {
      key: 'bytes',
      title: 'Трафик',
      width: 110,
      sortAccessor: (r) => r.bytes,
      render: (r) => (
        <span className="mono tt" data-tt={`вход ${fmtBytes(r.ingressBytes)} · выход ${fmtBytes(r.egressBytes)}`}>{fmtBytes(r.bytes)}</span>
      ),
    },
    { key: 'asn', title: 'ASN', width: 70, render: (r) => <span className="mono">{r.ingressAsnCount}</span> },
    {
      key: 'hint',
      title: 'Подсказка',
      width: 200,
      render: (r) => (
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{irSuggestedBoundaryLabel(r.suggestedBoundary)}</span>
          {canWrite && r.suggestedBoundary && r.boundary === 'unknown' && (
            <Button kind="ghost" size="xs" onClick={() => applySuggestion(r)}>Применить</Button>
          )}
          {canWrite && r.boundarySource === 'manual' && (
            <button className="icon-btn" title="Сбросить ручную разметку" onClick={() => resetManual(r)}><Icon name="x" size={12} /></button>
          )}
        </div>
      ),
    },
    {
      key: 'catalog',
      title: 'В каталоге',
      width: 100,
      render: (r) => (!r.inCatalog ? <Badge tone="warning">Нет в SNMP</Badge> : <span style={{ color: 'var(--fg-secondary)' }}>Да</span>),
    },
  ];

  const classifiedPct = summary?.classifiedPercent ?? 0;
  const trafficClassifiedPct = trafficStats?.classifiedPercent ?? 0;

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Порты оборудования</h1>
          <p>Разметка физических интерфейсов коммутаторов и сравнение портовой модели направления с текущей.</p>
        </div>
        <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
      </div>

      {loadError && (
        <Card pad="sm" style={{ marginBottom: 16 }}>
          <div className="form-error">{loadError}</div>
        </Card>
      )}

      <DirectionSettingsCard settings={settings} options={options} canWrite={canWrite} onSaved={afterMutation} />

      <div className="grid grid--3col grid--gap-sm grid--mb">
        <IrSumCard
          label="Размечено портов"
          value={summary ? `${summary.classified} / ${summary.total}` : '—'}
          hint={summary ? `${classifiedPct}% каталога SNMP` : undefined}
        />
        <IrSumCard
          label="Трафик через размеченные порты"
          value={trafficStats ? `${trafficClassifiedPct}%` : '—'}
          hint={trafficStats ? `за ${hours} ч · ${fmtBytes(trafficStats.classifiedBytes)} из ${fmtBytes(trafficStats.totalBytes)}` : undefined}
        />
        <IrSumCard
          label="Порты без разметки с трафиком"
          value={trafficStats ? String(trafficStats.unmarkedPortsWithTraffic) : '—'}
          action={(
            <Button kind="ghost" size="xs" onClick={() => { setOnlyUnmarked(true); setSwitchIp(''); location.hash = buildInterfaceRolesHash({ onlyUnmarked: true }).slice(1); }}>
              Показать
            </Button>
          )}
        />
      </div>

      <Card pad="sm" title="Правила" style={{ marginBottom: 16 }}
        tools={canWrite && (
          <Button kind="primary" size="sm" icon="plus" onClick={() => { setEditingRule(null); setShowRuleModal(true); }}>Добавить</Button>
        )}
      >
        <DataTable
          rows={rules.map((r) => ({ ...r, id: r.ruleId }))}
          columns={ruleCols}
          rowKey="id"
          pageSize={10}
          initialSort={{ key: 'priority', dir: 'asc' }}
          emptyTitle="Правил пока нет"
          emptyDesc="Добавьте правило по описанию или скорости порта."
        />
      </Card>

      <Card pad="sm" title="Порты по трафику" style={{ marginBottom: 16 }}>
        <div className="row ir-traffic-toolbar" style={{ gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <div className="seg">
            {TRAFFIC_HOUR_OPTIONS.map((h) => (
              <button key={h} type="button" className={hours === h ? 'is-active' : ''} onClick={() => setHours(h)}>{h} ч</button>
            ))}
          </div>
          <label className="row" style={{ gap: 6, font: 'var(--pv-text-body-3)' }}>
            <input type="checkbox" checked={onlyUnmarked} onChange={(e) => setOnlyUnmarked(e.target.checked)} />
            Только без разметки
          </label>
          <div className="field" style={{ margin: 0 }}>
            <input
              className="input mono"
              placeholder="IP коммутатора"
              value={switchIp}
              onChange={(e) => setSwitchIp(e.target.value)}
              style={{ width: 160 }}
            />
          </div>
          <div className="field" style={{ margin: 0 }}>
            <label style={{ font: 'var(--pv-text-body-3)', marginRight: 6 }}>Порог ASN</label>
            <input className="input mono" type="number" value={asnThreshold} onChange={(e) => setAsnThreshold(Number(e.target.value) || 50)} style={{ width: 72 }} />
          </div>
        </div>
        <p style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginBottom: 12 }}>
          За клиентским или участковым портом видны единицы ASN, за аплинком и магистралью — сотни. Подсказка не размечает порт автоматически.
        </p>
        {loading ? (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        ) : (
          <DataTable
            rows={trafficRows.map((r, i) => ({ ...r, id: `${r.switchIp}-${r.ifIndex}-${i}` }))}
            columns={trafficCols}
            rowKey="id"
            pageSize={20}
            initialSort={{ key: 'bytes', dir: 'desc' }}
            emptyTitle="Нет портов с трафиком"
            onRowClick={(r) => setSwitchPanelIp(r.switchIp)}
          />
        )}
      </Card>

      {switchPanelIp && (
        <Card pad="sm" title={`Порты ${switchPanelIp}`} style={{ marginBottom: 16 }}
          tools={<Button kind="ghost" size="sm" onClick={() => setSwitchPanelIp('')}>Закрыть</Button>}
        >
          {switchPortsLoading ? (
            <div style={{ padding: 16, color: 'var(--fg-secondary)' }}>Загрузка каталога…</div>
          ) : (
            <DataTable
              rows={switchPorts.map((r) => ({ ...r, id: r.ifIndex }))}
              columns={[
                { key: 'ifIndex', title: 'ifIndex', width: 70, render: (r) => <span className="mono">{r.ifIndex}</span> },
                { key: 'ifName', title: 'Порт', width: 140, render: (r) => <span className="mono">{r.ifName || '—'}</span> },
                {
                  key: 'boundary',
                  title: 'Сторона',
                  width: 160,
                  render: (r) => {
                    const fromRule = r.boundarySource === 'rule' || r.boundarySource === 'default';
                    if (!canWrite) {
                      return (
                        <span style={{ color: fromRule ? 'var(--fg-secondary)' : undefined }} title={r.boundaryRuleId ? `правило ${r.boundaryRuleId}` : irSourceLabel(r.boundarySource)}>
                          {irBoundaryLabel(r.boundary)}
                        </span>
                      );
                    }
                    return (
                      <select
                        className="input"
                        value={r.boundary || 'unknown'}
                        style={{ color: fromRule && !r.manualBoundary ? 'var(--fg-secondary)' : undefined, minWidth: 130 }}
                        title={r.boundaryRuleId ? `правило ${r.boundaryRuleId}` : irSourceLabel(r.boundarySource)}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => saveSwitchPortRole(r, { boundary: e.target.value })}
                      >
                        {boundaryOptions.map((b) => <option key={b} value={b}>{irBoundaryLabel(b)}</option>)}
                      </select>
                    );
                  },
                },
                {
                  key: 'connectivity',
                  title: 'Тип стыка',
                  width: 150,
                  render: (r) => {
                    const fromRule = r.connectivitySource === 'rule' || r.connectivitySource === 'default';
                    if (!canWrite) {
                      return (
                        <span style={{ color: fromRule ? 'var(--fg-secondary)' : undefined }}>
                          {r.connectivity ? irConnectivityLabel(r.connectivity) : '—'}
                        </span>
                      );
                    }
                    return (
                      <select
                        className="input"
                        value={r.connectivity || ''}
                        style={{ color: fromRule && !r.manualConnectivity ? 'var(--fg-secondary)' : undefined, minWidth: 120 }}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => saveSwitchPortRole(r, { connectivity: e.target.value })}
                      >
                        {connectivityOptions.map((c) => <option key={c || '_empty'} value={c}>{irConnectivityLabel(c)}</option>)}
                      </select>
                    );
                  },
                },
                {
                  key: 'actions',
                  title: '',
                  width: 48,
                  render: (r) => canWrite && (r.boundarySource === 'manual' || r.connectivitySource === 'manual') && (
                    <button className="icon-btn" title="Сбросить ручную разметку" onClick={(e) => { e.stopPropagation(); resetSwitchPortManual(r); }}>
                      <Icon name="x" size={12} />
                    </button>
                  ),
                },
              ]}
              rowKey="id"
              pageSize={15}
            />
          )}
        </Card>
      )}

      <Card pad="sm" title="Сети vs порты">
        {coverageProblems.length > 0 && (
          <div className="col" style={{ gap: 8, marginBottom: 12 }}>
            {coverageProblems.map((p, i) => (
              <div key={i} className="ir-coverage-warn">{p.text}</div>
            ))}
          </div>
        )}
        <div className="row" style={{ gap: 16, flexWrap: 'wrap', marginBottom: 12, alignItems: 'center' }}>
          <span>Совпадение: <b>{compare ? `${compare.agreePercent}%` : '—'}</b></span>
          <span>Не определено портами: <b>{compare ? `${compare.undecidedPercent}%` : '—'}</b></span>
          <span>Объём: <b>{compare ? fmtBytes(compare.totalBytes) : '—'}</b></span>
          <div className="seg">
            <button type="button" className={compareOneSided === 'strict' ? 'is-active' : ''} onClick={() => setCompareOneSided('strict')}>Строго</button>
            <button type="button" className={compareOneSided === 'infer' ? 'is-active' : ''} onClick={() => setCompareOneSided('infer')}>Односторонне</button>
          </div>
        </div>
        {compare?.cells?.length ? (
          <>
            <DirectionCompareMatrix cells={compare.cells} totalBytes={compare.totalBytes} />
            <p style={{ marginTop: 12, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
              {compareNarrative(compare.cells, compare.totalBytes)}
            </p>
          </>
        ) : (
          <div style={{ color: 'var(--fg-secondary)', padding: 16 }}>Нет данных для сравнения за выбранное окно.</div>
        )}
      </Card>

      <InterfaceRoleRuleModal
        open={showRuleModal}
        rule={editingRule}
        onClose={() => { setShowRuleModal(false); setEditingRule(null); }}
        onSaved={afterMutation}
        canWrite={canWrite}
      />
    </div>
  );
}

Object.assign(window, { PageInterfaceRoles });
