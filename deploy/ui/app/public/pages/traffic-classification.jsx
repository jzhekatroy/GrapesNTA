/* Классификация трафика — настройки определения направления. */

const { useCallback, useEffect, useState } = React;

const DIRECTION_MODE_OPTIONS = [
  {
    value: 'prefixes',
    label: 'По сетям',
    hint: 'Направление выводится из справочника L3-префиксов (собственные сети).',
  },
  {
    value: 'ports',
    label: 'По портам',
    hint: 'Направление — по стороне входного и выходного интерфейса. Требует разметки на «Порты оборудования» и поддержки коллектора.',
  },
];

const UNKNOWN_NETWORK_HINTS = {
  foreign: 'Удобно, пока справочник неполон. Но если своя сеть не внесена в справочник, её трафик попадёт в транзит, и это ничем не будет заметно.',
  unclassified: 'Транзитом считается только трафик между сетями, явно описанными в справочнике. Пробелы в разметке видны сразу.',
};

function openUnclassifiedTrafficExplorer() {
  const url = buildExplorerShareUrl({
    metric: 'bps',
    groupBy: ['dst_asn'],
    filters: [{ field: 'direction', op: '=', value: 'unknown' }],
    limit: 25,
    vis: 'data',
    timeRange: '1h',
  });
  location.hash = url.slice(url.indexOf('#') + 1);
}

function ChoiceGroup({ name, value, options, disabled, onChange }) {
  return (
    <div className="tc-choice-list" role="radiogroup" aria-label={name}>
      {options.map((opt) => {
        const id = `${name}-${opt.value}`;
        const checked = value === opt.value;
        return (
          <label
            key={opt.value}
            htmlFor={id}
            className={`tc-choice-item${checked ? ' is-selected' : ''}${disabled ? ' is-disabled' : ''}`}
          >
            <input
              id={id}
              type="radio"
              name={name}
              value={opt.value}
              checked={checked}
              disabled={disabled}
              onChange={() => onChange(opt.value)}
            />
            <span className="tc-choice-item__body">
              <span className="tc-choice-item__label">{opt.label}</span>
              {opt.hint && <span className="field-hint">{opt.hint}</span>}
            </span>
          </label>
        );
      })}
    </div>
  );
}

function PageTrafficClassification() {
  const canWrite = AuthAccess.canWritePage('traffic-classification');
  const [settings, setSettings] = useState(null);
  const [form, setForm] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError('');
      const res = await ApiClient.loadDirectionSettings();
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(res.error || ApiClient.LOAD_FAILED);
        setSettings(null);
        setForm(null);
      } else {
        setSettings(res.data);
        setForm({
          directionMode: res.data.directionMode || 'prefixes',
          unknownNetworks: res.data.unknownNetworks || 'foreign',
        });
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const unknownOptions = (settings?.options?.unknownNetworks || ['foreign', 'unclassified']).map((value) => ({
    value,
    label: settings?.options?.unknownNetworkLabels?.[value] || value,
    hint: UNKNOWN_NETWORK_HINTS[value] || '',
  }));

  const directionOptions = DIRECTION_MODE_OPTIONS.map((opt) => ({
    ...opt,
    label: IR_DIRECTION_MODE_LABELS[opt.value] || opt.label,
  }));

  const save = async () => {
    if (!form) return;
    setSaving(true);
    setSaveError('');
    try {
      await ApiClient.saveDirectionSettings({
        directionMode: form.directionMode,
        unknownNetworks: form.unknownNetworks,
      });
      pushToast({ kind: 'success', title: 'Настройки сохранены' });
      reload();
    } catch (err) {
      setSaveError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Классификация трафика</h1>
          <p>
            Как система определяет направление потоков: входящий, исходящий, транзит, внутренний или неразмеченный.
          </p>
        </div>
        <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading || saving}>
          Обновить
        </Button>
      </div>

      {loadError && <div className="form-error" style={{ marginBottom: 16 }}>{loadError}</div>}
      {saveError && <div className="form-error" style={{ marginBottom: 16 }}>{saveError}</div>}

      {loading && !form ? (
        <Card pad="sm">
          <div style={{ padding: 28, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : form && (
        <div className="col" style={{ gap: 16 }}>
          <Card pad="sm" title="Определение направления">
            <ChoiceGroup
              name="directionMode"
              value={form.directionMode}
              options={directionOptions}
              disabled={!canWrite}
              onChange={(directionMode) => setForm((prev) => ({ ...prev, directionMode }))}
            />
            {form.directionMode === 'ports' && (
              <p className="field-hint" style={{ marginTop: 12 }}>
                Разметка портов — на странице{' '}
                <button type="button" className="link-btn" onClick={() => { location.hash = 'interface-roles'; }}>
                  Порты оборудования
                </button>
                .
              </p>
            )}
          </Card>

          {form.directionMode === 'prefixes' && (
            <Card pad="sm" title="Трафик между неизвестными сетями">
              <ChoiceGroup
                name="unknownNetworks"
                value={form.unknownNetworks}
                options={unknownOptions}
                disabled={!canWrite}
                onChange={(unknownNetworks) => setForm((prev) => ({ ...prev, unknownNetworks }))}
              />
              <div className="tc-impact">
                <button type="button" className="link-btn" onClick={openUnclassifiedTrafficExplorer}>
                  Посмотреть неразмеченный трафик по автономным системам
                </button>
              </div>
              <p className="field-hint" style={{ marginTop: 8 }}>
                Правило применяется к новому трафику в течение ~60 секунд. Уже сохранённые данные не пересчитываются.
              </p>
            </Card>
          )}

          {canWrite && (
            <div>
              <Button kind="primary" icon="save" onClick={save} disabled={saving || loading}>
                {saving ? 'Сохранение…' : 'Сохранить'}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

Object.assign(window, { PageTrafficClassification });
