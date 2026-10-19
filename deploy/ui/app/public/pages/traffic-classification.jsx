/* Классификация трафика — настройки определения направления. */

const { useCallback, useEffect, useState } = React;

const DIRECTION_MODE_VALUES = ['prefixes', 'ports'];
const UNKNOWN_NETWORK_VALUES = ['foreign', 'unclassified'];

function trafficClassificationT(key, params) {
  return GrapesI18n.t(key, params);
}

function directionModeOptions() {
  return DIRECTION_MODE_VALUES.map((value) => ({
    value,
    label: trafficClassificationT(`trafficClassification.directionMode.${value}.label`),
    hint: trafficClassificationT(`trafficClassification.directionMode.${value}.hint`),
  }));
}

function unknownNetworkOptions(allowedValues) {
  const values = Array.isArray(allowedValues) && allowedValues.length
    ? allowedValues
    : UNKNOWN_NETWORK_VALUES;
  return values.map((value) => ({
    value,
    label: GrapesI18n.has(`trafficClassification.unknown.${value}.label`)
      ? trafficClassificationT(`trafficClassification.unknown.${value}.label`)
      : value,
    hint: GrapesI18n.has(`trafficClassification.unknown.${value}.hint`)
      ? trafficClassificationT(`trafficClassification.unknown.${value}.hint`)
      : '',
  }));
}

function mapTrafficClassificationError(message) {
  const msg = String(message || '').trim();
  if (!msg || msg === ApiClient.LOAD_FAILED || msg === 'Не удалось загрузить') {
    return trafficClassificationT('trafficClassification.loadFailed');
  }
  if (msg === 'Неизвестный режим определения направления') {
    return trafficClassificationT('trafficClassification.err.unknownDirectionMode');
  }
  if (msg === 'Недопустимое значение unknownNetworks') {
    return trafficClassificationT('trafficClassification.err.invalidUnknownNetworks');
  }
  return msg;
}

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

function PortsMarkupHint() {
  const pageLabel = trafficClassificationT('nav.item.interface-roles');
  const template = trafficClassificationT('trafficClassification.portsMarkupHint', { page: '{page}' });
  const parts = template.split('{page}');
  return (
    <p className="field-hint" style={{ marginTop: 12 }}>
      {parts[0]}
      <button type="button" className="link-btn" onClick={() => { location.hash = 'interface-roles'; }}>
        {pageLabel}
      </button>
      {parts[1] ?? ''}
    </p>
  );
}

function ChoiceGroup({ name, ariaLabel, value, options, disabled, onChange }) {
  return (
    <div className="tc-choice-list" role="radiogroup" aria-label={ariaLabel || name}>
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
        setLoadError(mapTrafficClassificationError(res.error));
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

  const unknownOptions = unknownNetworkOptions(settings?.options?.unknownNetworks);
  const directionOptions = directionModeOptions();

  const save = async () => {
    if (!form) return;
    setSaving(true);
    setSaveError('');
    try {
      await ApiClient.saveDirectionSettings({
        directionMode: form.directionMode,
        unknownNetworks: form.unknownNetworks,
      });
      pushToast({ kind: 'success', title: trafficClassificationT('trafficClassification.saveSuccessTitle') });
      reload();
    } catch (err) {
      setSaveError(mapTrafficClassificationError(err.message));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{trafficClassificationT('nav.item.traffic-classification')}</h1>
          <p>{trafficClassificationT('trafficClassification.subtitle')}</p>
        </div>
        <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading || saving}>
          {trafficClassificationT('chrome.refresh')}
        </Button>
      </div>

      {loadError && <div className="form-error" style={{ marginBottom: 16 }}>{loadError}</div>}
      {saveError && <div className="form-error" style={{ marginBottom: 16 }}>{saveError}</div>}

      {loading && !form ? (
        <Card pad="sm">
          <div style={{ padding: 28, textAlign: 'center', color: 'var(--fg-secondary)' }}>
            {trafficClassificationT('trafficClassification.loading')}
          </div>
        </Card>
      ) : form && (
        <div className="col" style={{ gap: 16 }}>
          <Card pad="sm" title={trafficClassificationT('trafficClassification.card.direction')}>
            <ChoiceGroup
              name="directionMode"
              ariaLabel={trafficClassificationT('trafficClassification.card.direction')}
              value={form.directionMode}
              options={directionOptions}
              disabled={!canWrite}
              onChange={(directionMode) => setForm((prev) => ({ ...prev, directionMode }))}
            />
            {form.directionMode === 'ports' && <PortsMarkupHint />}
          </Card>

          {form.directionMode === 'prefixes' && (
            <Card pad="sm" title={trafficClassificationT('trafficClassification.card.unknownNetworks')}>
              <ChoiceGroup
                name="unknownNetworks"
                ariaLabel={trafficClassificationT('trafficClassification.card.unknownNetworks')}
                value={form.unknownNetworks}
                options={unknownOptions}
                disabled={!canWrite}
                onChange={(unknownNetworks) => setForm((prev) => ({ ...prev, unknownNetworks }))}
              />
              <div className="tc-impact">
                <button type="button" className="link-btn" onClick={openUnclassifiedTrafficExplorer}>
                  {trafficClassificationT('trafficClassification.viewUnclassifiedExplorer')}
                </button>
              </div>
              <p className="field-hint" style={{ marginTop: 8 }}>
                {trafficClassificationT('trafficClassification.applyRuleHint')}
              </p>
            </Card>
          )}

          {canWrite && (
            <div>
              <Button kind="primary" icon="save" onClick={save} disabled={saving || loading}>
                {saving
                  ? trafficClassificationT('trafficClassification.saving')
                  : trafficClassificationT('trafficClassification.save')}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

Object.assign(window, { PageTrafficClassification });
