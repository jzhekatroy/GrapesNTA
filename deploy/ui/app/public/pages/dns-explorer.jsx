/* Разбор DNS — исследование dns_log по образцу Explorer */

const DNS_EXPLORER_DEFAULT_METRIC = 'queries_per_sec';
const DNS_EXPLORER_DEFAULT_LIMIT = 50;
const DNS_EXPLORER_DEFAULT_VISUAL_LIMIT = 5;
const DNS_EXPLORER_CHART_HEIGHT = 196;

const DNS_RCODE_OPTIONS = [
  { value: '0', label: 'Успешно' },
  { value: '2', label: 'Ошибка DNS-сервера' },
  { value: '3', label: 'Домен не найден' },
  { value: 'other', label: 'Другой код' },
];

const DNS_EXPLORER_FILTER_LOGIC_OPTIONS = [
  { id: 'and', label: 'И', altLabel: 'AND' },
  { id: 'or', label: 'ИЛИ', altLabel: 'OR' },
  { id: 'and_not', label: 'И НЕ', altLabel: 'AND NOT' },
  { id: 'or_not', label: 'ИЛИ НЕ', altLabel: 'OR NOT' },
];

const DNS_EXPLORER_TEXT_TIME_RANGES = ['30m', '1h', '3h', '6h', '12h', '24h', '7d'];

const DNS_EXPLORER_SUGGEST_FIELDS = new Set(['query_name', 'client_ip', 'server_ip', 'qtype', 'answer']);

const DNS_ANSWER_GROUP_IDS = new Set(['answer', 'answer_type']);
const DNS_QUERY_METRICS = new Set(['queries_per_sec', 'queries_total']);

const DNS_FIELD_OPS = {
  client_ip: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in_cidr', label: 'входит в CIDR' },
  ],
  query_name: [
    { id: 'eq', label: 'равно' },
    { id: 'contains', label: 'содержит' },
    { id: 'not_contains', label: 'не содержит' },
  ],
  server_ip: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in_cidr', label: 'входит в CIDR' },
  ],
  qtype: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in', label: 'один из' },
  ],
  rcode: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in', label: 'один из' },
  ],
  answer: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in_cidr', label: 'входит в CIDR' },
    { id: 'contains', label: 'содержит' },
  ],
  source_id: [{ id: 'in', label: 'один из' }],
};

function normalizeDnsExplorerFilterLogic(logic) {
  const key = String(logic || 'and').trim().toLowerCase();
  return DNS_EXPLORER_FILTER_LOGIC_OPTIONS.some((o) => o.id === key) ? key : 'and';
}

function normalizeDnsExplorerFilter(filter) {
  const next = {
    ...filter,
    logic: normalizeDnsExplorerFilterLogic(filter?.logic),
    values: filter?.values ? [...filter.values] : undefined,
  };
  return next;
}

function cloneDnsExplorerFilters(filters) {
  return ensureDnsFilterIds(filters || []);
}

const DNS_EXPLORER_MAX_RANGE_DAYS = 7;

const DNS_OP_TOKENS = [
  { token: 'eq', op: 'eq' },
  { token: 'равно', op: 'eq' },
  { token: 'ne', op: 'ne' },
  { token: 'не равно', op: 'ne' },
  { token: 'contains', op: 'contains' },
  { token: 'содержит', op: 'contains' },
  { token: 'not_contains', op: 'not_contains' },
  { token: 'не содержит', op: 'not_contains' },
  { token: 'in_cidr', op: 'in_cidr' },
  { token: 'входит в cidr', op: 'in_cidr' },
  { token: 'in', op: 'in' },
  { token: 'один из', op: 'in' },
];

function ensureDnsFilterIds(filters) {
  return (filters || []).map((f, i) => ({
    ...normalizeDnsExplorerFilter(f),
    id: f?.id ?? `dns-f-${Date.now()}-${i}-${Math.random().toString(36).slice(2, 6)}`,
  }));
}

function dnsExplorerOpLabel(op) {
  for (const fieldOps of Object.values(DNS_FIELD_OPS)) {
    const hit = fieldOps.find((item) => item.id === op);
    if (hit) return hit.label;
  }
  return op;
}

function hasDnsAnswerGrouping(groupBy) {
  return (groupBy || []).some((id) => DNS_ANSWER_GROUP_IDS.has(id));
}

function isDnsQueryMetricDisabled(metricId, groupBy) {
  return hasDnsAnswerGrouping(groupBy) && DNS_QUERY_METRICS.has(metricId);
}

function coerceDnsMetricForGrouping(metric, groupBy) {
  if (isDnsQueryMetricDisabled(metric, groupBy)) return 'responses_per_sec';
  return metric;
}

function dnsDimensionMatchesQuery(dim, queryText) {
  const q = String(queryText || '').trim().toLowerCase();
  if (!q) return true;
  if (String(dim.label || '').toLowerCase().includes(q)) return true;
  if (dim.id === 'answer' && (q.includes('ответ') || q.includes('адрес'))) return true;
  if (dim.id === 'answer_type' && q.includes('ответ')) return true;
  return false;
}

function resolveDnsOpToken(raw) {
  const key = String(raw || '').trim().toLowerCase();
  const hit = DNS_OP_TOKENS.find((item) => item.token.toLowerCase() === key);
  return hit?.op || key;
}

function resolveDnsFieldId(field, schema) {
  const id = String(field || '').trim();
  if (schema?.fields?.some((f) => f.id === id)) return id;
  throw new Error(`неизвестное поле «${field}»`);
}

function validateDnsExplorerCustomPeriod(period, timeRange = '24h') {
  if (timeRange !== 'custom') return null;
  const err = validateCustomPeriod(period);
  if (err) return err;
  const span = new Date(period.to).getTime() - new Date(period.from).getTime();
  if (!Number.isFinite(span) || span <= 0) return 'Некорректный пользовательский период';
  if (span > DNS_EXPLORER_MAX_RANGE_DAYS * 86400000) {
    return `Период не может превышать ${DNS_EXPLORER_MAX_RANGE_DAYS} дней`;
  }
  return null;
}

function parseDnsLogicOnlyLine(line) {
  const trimmed = String(line || '').trim();
  if (/^(И\s+НЕ|AND\s+NOT)$/i.test(trimmed)) return 'and_not';
  if (/^(ИЛИ\s+НЕ|OR\s+NOT)$/i.test(trimmed)) return 'or_not';
  if (/^(ИЛИ|OR)$/i.test(trimmed)) return 'or';
  if (/^(И|AND)$/i.test(trimmed)) return 'and';
  return null;
}

function parseDnsLogicPrefix(line) {
  const trimmed = line.trim();
  if (/^(И\s+НЕ|AND\s+NOT)\s+/i.test(trimmed)) {
    return { logic: 'and_not', rest: trimmed.replace(/^(И\s+НЕ|AND\s+NOT)\s+/i, '') };
  }
  if (/^(ИЛИ\s+НЕ|OR\s+NOT)\s+/i.test(trimmed)) {
    return { logic: 'or_not', rest: trimmed.replace(/^(ИЛИ\s+НЕ|OR\s+NOT)\s+/i, '') };
  }
  if (/^(ИЛИ|OR)\s+/i.test(trimmed)) {
    return { logic: 'or', rest: trimmed.replace(/^(ИЛИ|OR)\s+/i, '') };
  }
  if (/^(И|AND)\s+/i.test(trimmed)) {
    return { logic: 'and', rest: trimmed.replace(/^(И|AND)\s+/i, '') };
  }
  return { logic: 'and', rest: trimmed };
}

function serializeDnsExplorerFilterDsl({ timeRange, customPeriod, filters }) {
  const lines = [];
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    lines.push(`time between "${customPeriod.from}" and "${customPeriod.to}"`);
  } else {
    lines.push(`time range ${timeRange}`);
  }
  (filters || []).forEach((f, i) => {
    const logicOpt = DNS_EXPLORER_FILTER_LOGIC_OPTIONS.find((o) => o.id === normalizeDnsExplorerFilterLogic(f.logic));
    const logicLabel = i === 0 ? '' : `${logicOpt?.label || 'И'} `;
    const quoteVal = (v) => (String(v).includes(' ') ? `"${v}"` : v);
    if (f.op === 'in') {
      const vals = (f.values || []).map(quoteVal).join(', ');
      lines.push(`${logicLabel}${f.field} in (${vals})`);
      return;
    }
    lines.push(`${logicLabel}${f.field} ${f.op} ${quoteVal(f.value ?? '')}`.trim());
  });
  return lines.join('\n');
}

function parseDnsExplorerFilterDsl(text, schema = null) {
  const rawLines = String(text || '').split('\n');
  const lines = [];
  const lineNumbers = [];
  rawLines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed) {
      lines.push(trimmed);
      lineNumbers.push(index + 1);
    }
  });
  if (!lines.length) throw new Error('Фильтр пуст');

  let timeRange = '24h';
  let customPeriod = defaultCustomPeriod();
  const filters = [];
  let conditionIndex = 0;
  let pendingLogic = null;

  const pushFilter = (partial) => {
    filters.push({
      id: `dns-f-${Date.now()}-${conditionIndex++}`,
      logic: normalizeDnsExplorerFilterLogic(partial.logic),
      field: resolveDnsFieldId(partial.field, schema),
      op: resolveDnsOpToken(partial.op),
      value: partial.value,
      values: partial.values,
    });
  };

  const parseError = (lineNum, message) => {
    throw new Error(`Строка ${lineNum}: ${message}`);
  };

  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index];
    const lineNum = lineNumbers[index];
    try {
      const logicOnly = parseDnsLogicOnlyLine(rawLine);
      if (logicOnly) {
        pendingLogic = logicOnly;
        continue;
      }

      const lineLower = rawLine.toLowerCase();
      if (lineLower.startsWith('time ')) {
        const betweenMatch = rawLine.match(/^time\s+between\s+"([^"]+)"\s+and\s+"([^"]+)"/i);
        if (betweenMatch) {
          timeRange = 'custom';
          customPeriod = { from: betweenMatch[1], to: betweenMatch[2] };
          const err = validateDnsExplorerCustomPeriod(customPeriod, 'custom');
          if (err) parseError(lineNum, err);
          continue;
        }
        const rangeMatch = rawLine.match(/^time\s+range\s+(\S+)/i);
        if (rangeMatch) {
          timeRange = rangeMatch[1];
          continue;
        }
        parseError(lineNum, `неверный формат времени: ${rawLine}`);
      }

      const { logic: inlineLogic, rest } = parseDnsLogicPrefix(rawLine);
      const logic = pendingLogic ?? (filters.length > 0 ? inlineLogic : 'and');
      pendingLogic = null;

      const inMatch = rest.match(/^([\w_]+)\s+(in|один из)\s*\(([^)]+)\)/i);
      if (inMatch) {
        pushFilter({
          field: inMatch[1],
          op: 'in',
          values: inMatch[3].split(',').map((s) => s.trim().replace(/^"|"$/g, '')).filter(Boolean),
          logic,
        });
        continue;
      }

      let simpleHandled = false;
      const fieldLead = rest.match(/^([\w_]+)\s+(.+)$/);
      if (fieldLead) {
        const remainder = fieldLead[2].trim();
        for (const { token, op } of DNS_OP_TOKENS) {
          const opRe = new RegExp(`^${token.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}\\s+(.+)$`, 'i');
          const opMatch = remainder.match(opRe);
          if (opMatch) {
            pushFilter({
              field: fieldLead[1],
              op,
              value: opMatch[1].trim().replace(/^"|"$/g, ''),
              logic,
            });
            simpleHandled = true;
            break;
          }
        }
      }
      if (simpleHandled) continue;

      parseError(lineNum, `не удалось разобрать строку: ${rawLine}`);
    } catch (err) {
      if (/^Строка \d+:/.test(String(err.message || ''))) throw err;
      parseError(lineNum, err.message || 'ошибка разбора');
    }
  }

  if (pendingLogic) {
    throw new Error('После связки условия (И, ИЛИ, И НЕ, ИЛИ НЕ) ожидается фильтр');
  }

  const periodErr = validateDnsExplorerCustomPeriod(
    timeRange === 'custom' ? customPeriod : {},
    timeRange,
  );
  if (periodErr) throw new Error(periodErr);

  return { timeRange, customPeriod, filters: ensureDnsFilterIds(filters) };
}

function BuilderControl({ label, children }) {
  return (
    <div className="col" style={{ gap: 4, minWidth: 0 }}>
      <div style={{ font: 'var(--pv-text-body-3-bold)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-secondary)', fontSize: 10 }}>{label}</div>
      <div className="row" style={{ gap: 4 }}>{children}</div>
    </div>
  );
}

function DnsDimensionPicker({ anchorRef, dimensions, selected, onPick, onClose }) {
  const [q, setQ] = useState('');
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);
  const items = useMemo(
    () => dimensions.filter((d) => dnsDimensionMatchesQuery(d, q)),
    [dimensions, q],
  );

  React.useLayoutEffect(() => {
    const anchor = anchorRef?.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({ position: 'fixed', top: rect.bottom + 6, left: Math.max(8, rect.left), width: 280, maxHeight: 320, zIndex: 1200, overflowY: 'auto' });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => { window.removeEventListener('resize', updatePosition); window.removeEventListener('scroll', updatePosition, true); };
  }, [anchorRef]);

  useEffect(() => {
    const onPointerDown = (e) => {
      if (panelRef.current?.contains(e.target) || anchorRef?.current?.contains(e.target)) return;
      onClose();
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [onClose, anchorRef]);

  if (!menuStyle) return null;
  return ReactDOM.createPortal(
    <div ref={panelRef} style={{ ...menuStyle, background: 'var(--bg-surface)', border: '1px solid var(--bd-default)', borderRadius: 12, boxShadow: 'var(--pv-shadow-popover)', padding: 8 }}>
      <input className="input" placeholder="Поиск измерения..." value={q} onChange={(e) => setQ(e.target.value)} autoFocus />
      {items.map((d) => {
        const dis = selected.includes(d.id);
        return (
          <div key={d.id} onClick={() => !dis && onPick(d.id)} style={{ padding: '8px 10px', borderRadius: 8, cursor: dis ? 'default' : 'pointer', color: dis ? 'var(--fg-muted)' : 'var(--fg-primary)' }}>
            {d.label}
          </div>
        );
      })}
    </div>,
    document.body,
  );
}

function DnsExplorerFilterModeToggle({ filterMode, onFilterModeChange }) {
  return (
    <div className="seg explorer-filter-mode-toggle" role="group" aria-label="Режим фильтра">
      <button
        type="button"
        className={filterMode === 'graphic' ? 'is-active' : ''}
        title="Графический режим"
        aria-label="Графический режим"
        aria-pressed={filterMode === 'graphic'}
        onClick={() => onFilterModeChange('graphic')}
      >
        <Icon name="sliders" size={14} />
      </button>
      <button
        type="button"
        className={filterMode === 'text' ? 'is-active' : ''}
        title="Текстовый режим"
        aria-label="Текстовый режим"
        aria-pressed={filterMode === 'text'}
        onClick={() => onFilterModeChange('text')}
      >
        <Icon name="code" size={14} />
      </button>
    </div>
  );
}

function DnsExplorerSystemFilterRow({ title, mandatory, children }) {
  return (
    <div className="col" style={{ padding: '8px 10px', background: 'var(--surf-1)', border: '1px solid var(--bd-soft)', borderRadius: 10, gap: 6 }}>
      <div className="row" style={{ gap: 6, alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-secondary)' }}>
          {title}
          {mandatory && <span style={{ color: 'var(--st-critical)', marginLeft: 4 }}>*</span>}
        </div>
      </div>
      {children}
    </div>
  );
}

function DnsExplorerAddFilterMenu({ schema, onPickField }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const anchorRef = React.useRef(null);
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);
  const items = useMemo(
    () => (schema?.fields || []).filter((f) => !q || f.label.toLowerCase().includes(q.toLowerCase()) || f.id.includes(q.toLowerCase())),
    [schema, q],
  );

  React.useLayoutEffect(() => {
    if (!open) return undefined;
    const anchor = anchorRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({ position: 'fixed', top: rect.bottom + 4, left: Math.max(8, rect.left), width: Math.max(rect.width, 260), maxHeight: 280, zIndex: 1300, overflowY: 'auto' });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => { window.removeEventListener('resize', updatePosition); window.removeEventListener('scroll', updatePosition, true); };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (panelRef.current?.contains(e.target) || anchorRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  return (
    <>
      <div ref={anchorRef}>
        <Button kind="ghost" size="sm" icon="plus" onClick={() => setOpen((v) => !v)}>Условие</Button>
      </div>
      {open && menuStyle && ReactDOM.createPortal(
        <div ref={panelRef} style={{ ...menuStyle, background: 'var(--bg-surface)', border: '1px solid var(--bd-default)', borderRadius: 10, boxShadow: 'var(--pv-shadow-popover)', padding: 8 }}>
          <input className="input" placeholder="Поиск поля..." value={q} onChange={(e) => setQ(e.target.value)} autoFocus style={{ marginBottom: 6 }} />
          {items.length === 0 ? (
            <div style={{ padding: '8px 4px', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Ничего не найдено</div>
          ) : items.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => { onPickField(item.id); setOpen(false); setQ(''); }}
              style={{ all: 'unset', display: 'block', width: '100%', boxSizing: 'border-box', padding: '8px 10px', borderRadius: 8, cursor: 'pointer' }}
            >
              {item.label}
            </button>
          ))}
        </div>,
        document.body,
      )}
    </>
  );
}

function dnsTextLineBounds(value, cursor) {
  const safeCursor = Math.max(0, Math.min(Number(cursor) || 0, String(value || '').length));
  const before = String(value || '').lastIndexOf('\n', safeCursor - 1);
  const after = String(value || '').indexOf('\n', safeCursor);
  return {
    start: before < 0 ? 0 : before + 1,
    end: after < 0 ? String(value || '').length : after,
  };
}

function dnsTextValueFragment(line) {
  const inMatch = line.match(/\(([^)]*)$/);
  if (inMatch) return inMatch[1].split(',').pop().trim().replace(/^"|"$/g, '');
  const parts = line.trim().split(/\s+/);
  return (parts[parts.length - 1] || '').replace(/^"|"$/g, '');
}

function getDnsTextareaCaretCoordinates(textarea, pos) {
  const style = window.getComputedStyle(textarea);
  const rect = textarea.getBoundingClientRect();
  const mirror = document.createElement('div');
  const props = [
    'boxSizing', 'width', 'borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth',
    'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft',
    'fontStyle', 'fontVariant', 'fontWeight', 'fontStretch', 'fontSize', 'lineHeight', 'fontFamily',
    'textAlign', 'textTransform', 'textIndent', 'textDecoration', 'letterSpacing', 'wordSpacing', 'tabSize',
  ];
  mirror.style.position = 'fixed';
  mirror.style.visibility = 'hidden';
  mirror.style.top = `${rect.top}px`;
  mirror.style.left = `${rect.left}px`;
  mirror.style.whiteSpace = 'pre-wrap';
  mirror.style.wordWrap = 'break-word';
  mirror.style.overflow = 'hidden';
  props.forEach((prop) => {
    mirror.style[prop] = style[prop];
  });
  mirror.style.width = `${rect.width}px`;

  const safePos = Math.max(0, Math.min(pos, textarea.value.length));
  const before = textarea.value.slice(0, safePos);
  mirror.textContent = before;
  const marker = document.createElement('span');
  marker.textContent = '\u200b';
  mirror.appendChild(marker);
  document.body.appendChild(mirror);
  const markerRect = marker.getBoundingClientRect();
  document.body.removeChild(mirror);

  const lineHeight = Number.parseFloat(style.lineHeight);
  return {
    top: markerRect.top - textarea.scrollTop,
    left: markerRect.left - textarea.scrollLeft,
    height: Number.isFinite(lineHeight) ? lineHeight : markerRect.height,
  };
}

function dnsLogicAutocompleteEntries() {
  return DNS_EXPLORER_FILTER_LOGIC_OPTIONS.flatMap((o) => ([
    { token: o.label, hint: `${o.altLabel} · связка` },
    { token: o.altLabel, hint: `${o.label} · logic` },
  ]));
}

function resolveDnsFieldToken(token, schema) {
  const id = String(token || '').trim();
  if (schema?.fields?.some((f) => f.id === id)) return id;
  const byLabel = schema?.fields?.find((f) => String(f.label || '').toLowerCase() === id.toLowerCase());
  return byLabel?.id || id;
}

function dnsFieldMeta(schema, fieldId) {
  const resolved = resolveDnsFieldToken(fieldId, schema);
  return schema?.fields?.find((f) => f.id === resolved);
}

function buildDnsExplorerTextSuggestions({
  value,
  cursor,
  schema,
  suggestItems = [],
  dnsSources = [],
}) {
  const { start, end } = dnsTextLineBounds(value, cursor);
  const rawLine = String(value || '').slice(start, end);
  const leading = rawLine.match(/^\s*/)?.[0] || '';
  const trimmed = rawLine.trim();
  const { rest } = parseDnsLogicPrefix(trimmed);
  const logicPrefix = trimmed === rest ? '' : trimmed.slice(0, trimmed.length - rest.length);
  const fields = schema?.fields || [];
  const lowerRest = rest.toLowerCase();

  const lineSuggestion = (label, insert, hint) => ({ label, hint, insert: `${leading}${insert}`, mode: 'line' });
  const suggestions = [];

  if (!trimmed) return [];

  const needle = trimmed.toLowerCase();
  const matchesNeedle = (label, hint) => (
    String(label || '').toLowerCase().includes(needle)
    || String(hint || '').toLowerCase().includes(needle)
  );

  [
    lineSuggestion('time range', 'time range 1h', 'Период'),
    lineSuggestion('time between', 'time between "YYYY-MM-DDTHH:mm" and "YYYY-MM-DDTHH:mm"', 'Ручной диапазон'),
    ...dnsLogicAutocompleteEntries().map(({ token, hint }) => lineSuggestion(token, `${token} `, hint)),
  ]
    .filter((item) => matchesNeedle(item.label, item.hint))
    .forEach((item) => suggestions.push(item));

  if (!rest.includes(' ') && !lowerRest.startsWith('time')) {
    const fieldNeedle = rest.toLowerCase();
    fields
      .filter((f) => fieldNeedle && (
        f.id.toLowerCase().includes(fieldNeedle)
        || String(f.label).toLowerCase().includes(fieldNeedle)
      ))
      .slice(0, 12)
      .forEach((f) => {
        const defaultOp = DNS_FIELD_OPS[f.id]?.[0]?.id || 'eq';
        const display = f.label && f.label !== f.id ? f.label : null;
        suggestions.push(lineSuggestion(
          f.id,
          `${logicPrefix}${f.id} ${defaultOp} `,
          display || defaultOp,
        ));
      });
  }

  if (lowerRest.startsWith('time')) {
    DNS_EXPLORER_TEXT_TIME_RANGES.forEach((range) => {
      suggestions.push(lineSuggestion(`time range ${range}`, `time range ${range}`, 'Готовый период'));
    });
    suggestions.push(lineSuggestion('time between ...', 'time between "YYYY-MM-DDTHH:mm" and "YYYY-MM-DDTHH:mm"', 'Ручной диапазон'));
  }

  const fieldMatch = rest.match(/^([\w_]+)(?:\s+(\S+))?/);
  const fieldToken = fieldMatch?.[1];
  const field = fieldToken ? resolveDnsFieldToken(fieldToken, schema) : fieldToken;
  const op = fieldMatch?.[2]?.toLowerCase();
  const meta = dnsFieldMeta(schema, field);
  if (meta && (!op || rest.trim().split(/\s+/).length <= 2)) {
    (DNS_FIELD_OPS[field] || [{ id: 'eq' }]).forEach((candidate) => {
      suggestions.push(lineSuggestion(
        `${field} ${candidate.id}`,
        `${logicPrefix}${field} ${candidate.id} `,
        `${meta.label || field} · ${dnsExplorerOpLabel(candidate.id)}`,
      ));
    });
  }

  if (meta && op) {
    const fragment = dnsTextValueFragment(rest).toLowerCase();
    const resolvedOp = resolveDnsOpToken(op);

    if (field === 'rcode') {
      DNS_RCODE_OPTIONS
        .filter((item) => String(item.value).toLowerCase().includes(fragment)
          || String(item.label).toLowerCase().includes(fragment))
        .slice(0, 8)
        .forEach((item) => {
          const insert = resolvedOp === 'in'
            ? `${logicPrefix}${field} in (${item.value})`
            : `${logicPrefix}${field} ${resolvedOp} ${item.value}`;
          suggestions.push(lineSuggestion(item.value, insert, item.label));
        });
    }

    if (field === 'source_id') {
      (dnsSources || [])
        .filter((item) => String(item.sourceId).toLowerCase().includes(fragment)
          || String(item.displayName || '').toLowerCase().includes(fragment))
        .slice(0, 8)
        .forEach((item) => {
          suggestions.push(lineSuggestion(
            item.sourceId,
            `${logicPrefix}${field} in (${item.sourceId})`,
            item.displayName || item.sourceId,
          ));
        });
    }

    suggestItems
      .filter((item) => {
        const v = String(item.value ?? item.id ?? item).toLowerCase();
        const label = String(item.label ?? v).toLowerCase();
        return !fragment || v.includes(fragment) || label.includes(fragment);
      })
      .slice(0, 8)
      .forEach((item) => {
        const v = item.value ?? item.id ?? item;
        const hint = item.resolverLabel || (item.label && item.label !== v ? item.label : null);
        const insert = resolvedOp === 'in'
          ? `${logicPrefix}${field} in (${v})`
          : `${logicPrefix}${field} ${resolvedOp} ${v}`;
        suggestions.push(lineSuggestion(String(v), insert, hint || 'Значение'));
      });
  }

  const seen = new Set();
  return suggestions.filter((item) => {
    const key = `${item.label}|${item.insert}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 12);
}

function DnsExplorerFilterTextEditor({
  value,
  onChange,
  error,
  schema,
  suggestCtx,
  dnsSources = [],
}) {
  const textareaRef = React.useRef(null);
  const itemRefs = React.useRef([]);
  const [cursor, setCursor] = useState(0);
  const [activeIndex, setActiveIndex] = useState(0);
  const [suggestItems, setSuggestItems] = useState([]);
  const [suggestLoading, setSuggestLoading] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);
  const [autocompleteOpen, setAutocompleteOpen] = useState(false);

  const currentLine = useMemo(() => {
    const { start, end } = dnsTextLineBounds(value, cursor);
    return String(value || '').slice(start, end);
  }, [value, cursor]);

  const currentField = useMemo(() => {
    const { rest } = parseDnsLogicPrefix(currentLine.trim());
    return resolveDnsFieldToken(rest.match(/^([\w_]+)/)?.[1], schema);
  }, [schema, currentLine]);

  const suggestSearchReady = useMemo(() => {
    if (!DNS_EXPLORER_SUGGEST_FIELDS.has(currentField)) return false;
    const { rest } = parseDnsLogicPrefix(currentLine.trim());
    return /^[\w_]+\s+\S+/.test(rest);
  }, [currentField, currentLine]);

  useEffect(() => {
    if (!suggestSearchReady) {
      setSuggestItems([]);
      setSuggestLoading(false);
      return undefined;
    }
    const q = dnsTextValueFragment(currentLine);
    let cancelled = false;
    setSuggestLoading(true);
    const timer = setTimeout(() => {
      const loader = currentField === 'query_name'
        ? ApiClient.suggestDnsExplorerDomains
        : currentField === 'client_ip'
          ? ApiClient.suggestDnsExplorerClientIps
          : currentField === 'server_ip'
            ? ApiClient.suggestDnsExplorerServerIps
            : currentField === 'qtype'
              ? ApiClient.suggestDnsExplorerQtypes
              : currentField === 'answer'
                ? ApiClient.suggestDnsExplorerAnswers
                : null;
      if (!loader) {
        if (!cancelled) setSuggestLoading(false);
        return;
      }
      const promise = currentField === 'qtype'
        ? loader(suggestCtx)
        : loader(suggestCtx, q);
      promise.then((rows) => {
        if (!cancelled) {
          setSuggestItems(rows || []);
          setSuggestLoading(false);
        }
      }).catch(() => {
        if (!cancelled) {
          setSuggestItems([]);
          setSuggestLoading(false);
        }
      });
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [currentField, currentLine, suggestSearchReady, suggestCtx]);

  const suggestions = useMemo(
    () => buildDnsExplorerTextSuggestions({
      value,
      cursor,
      schema,
      suggestItems,
      dnsSources,
    }),
    [value, cursor, schema, suggestItems, dnsSources],
  );
  const visibleSuggestions = autocompleteOpen ? suggestions : [];
  const showAutocompleteMenu = autocompleteOpen && (
    visibleSuggestions.length > 0 || (suggestLoading && suggestSearchReady)
  );

  const safeActiveIndex = visibleSuggestions.length
    ? Math.min(activeIndex, visibleSuggestions.length - 1)
    : 0;

  useEffect(() => {
    setActiveIndex(0);
    if (suggestions.length === 0 && !suggestLoading) {
      setAutocompleteOpen(false);
    }
  }, [suggestions.length, currentLine, suggestLoading]);

  useEffect(() => {
    itemRefs.current[safeActiveIndex]?.scrollIntoView({ block: 'nearest' });
  }, [safeActiveIndex, menuStyle]);

  const updateCursor = () => {
    const el = textareaRef.current;
    if (el) setCursor(el.selectionStart || 0);
  };

  const applySuggestion = (suggestion) => {
    const bounds = dnsTextLineBounds(value, cursor);
    const next = `${String(value || '').slice(0, bounds.start)}${suggestion.insert}${String(value || '').slice(bounds.end)}`;
    onChange(next);
    const nextCursor = bounds.start + suggestion.insert.length;
    requestAnimationFrame(() => {
      textareaRef.current?.focus();
      textareaRef.current?.setSelectionRange(nextCursor, nextCursor);
      setCursor(nextCursor);
      setAutocompleteOpen(false);
    });
  };

  React.useLayoutEffect(() => {
    if (!showAutocompleteMenu || !textareaRef.current) {
      setMenuStyle(null);
      return undefined;
    }
    const updatePosition = () => {
      const el = textareaRef.current;
      if (!el) return;
      const coords = getDnsTextareaCaretCoordinates(el, cursor);
      const panelWidth = visibleSuggestions.length
        ? Math.min(
          Math.max(220, ...visibleSuggestions.map((item) => (
            String(item.label || '').length * 7 + String(item.hint || '').length * 5 + 44
          ))),
          420,
        )
        : 220;
      const panelHeight = visibleSuggestions.length
        ? Math.min(visibleSuggestions.length * 28 + 8, 224)
        : 36;
      let top = coords.top + coords.height + 4;
      if (top + panelHeight > window.innerHeight - 8) {
        top = Math.max(8, coords.top - panelHeight - 4);
      }
      const maxLeft = Math.max(8, window.innerWidth - panelWidth - 8);
      setMenuStyle({
        position: 'fixed',
        top,
        left: Math.min(Math.max(8, coords.left), maxLeft),
        width: panelWidth,
        maxHeight: 224,
        zIndex: 1300,
        overflowY: 'auto',
      });
    };
    updatePosition();
    const el = textareaRef.current;
    el.addEventListener('scroll', updatePosition);
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      el.removeEventListener('scroll', updatePosition);
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [cursor, showAutocompleteMenu, visibleSuggestions, value]);

  const handleKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') return;

    if (!visibleSuggestions.length) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((idx) => (idx + 1) % visibleSuggestions.length);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((idx) => (idx - 1 + visibleSuggestions.length) % visibleSuggestions.length);
      return;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      setActiveIndex(0);
      setAutocompleteOpen(false);
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      applySuggestion(visibleSuggestions[safeActiveIndex]);
    }
  };

  return (
    <div className="col" style={{ gap: 6, position: 'relative' }}>
      <textarea
        ref={textareaRef}
        className="input mono"
        rows={12}
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setCursor(e.target.selectionStart || 0);
          setAutocompleteOpen(true);
        }}
        onClick={() => {
          updateCursor();
          setAutocompleteOpen(false);
        }}
        onKeyUp={updateCursor}
        onKeyDown={handleKeyDown}
        onFocus={updateCursor}
        placeholder={'time range 24h\nquery_name contains example.com\nИ client_ip eq 10.0.0.1'}
        spellCheck={false}
        style={{ minHeight: 180, resize: 'vertical', fontSize: 12, lineHeight: 1.45 }}
      />
      {error && (
        <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }} role="alert">{error}</div>
      )}
      {showAutocompleteMenu && menuStyle && ReactDOM.createPortal(
        <div
          role="listbox"
          aria-label="Подсказки фильтра"
          style={{
            ...menuStyle,
            background: 'var(--bg-surface)',
            border: '1px solid var(--bd-default)',
            borderRadius: 10,
            boxShadow: 'var(--pv-shadow-popover)',
            padding: 4,
          }}
        >
          {suggestLoading && visibleSuggestions.length === 0 ? (
            <div style={{ padding: '8px 10px', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Поиск…</div>
          ) : visibleSuggestions.map((item, index) => {
            const active = index === safeActiveIndex;
            return (
              <button
                key={`${item.label}-${item.insert}`}
                ref={(el) => { itemRefs.current[index] = el; }}
                type="button"
                role="option"
                aria-selected={active}
                title={item.hint || undefined}
                onMouseDown={(ev) => {
                  ev.preventDefault();
                  applySuggestion(item);
                }}
                onMouseEnter={() => setActiveIndex(index)}
                style={{
                  all: 'unset',
                  display: 'flex',
                  alignItems: 'center',
                  width: '100%',
                  boxSizing: 'border-box',
                  minHeight: 26,
                  padding: '4px 8px',
                  borderRadius: 6,
                  cursor: 'pointer',
                  background: active ? 'var(--surf-3)' : 'transparent',
                }}
              >
                <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }}>
                  {item.label}
                </div>
                {item.hint && (
                  <div style={{
                    font: 'var(--pv-text-body-3)',
                    color: 'var(--fg-muted)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    marginLeft: 10,
                  }}>
                    {item.hint}
                  </div>
                )}
              </button>
            );
          })}
        </div>,
        document.body,
      )}
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        ↑↓ выбор · Tab вставка · Enter новая строка · Ctrl+Enter применить
      </div>
    </div>
  );
}

function DnsExplorerFilters({
  schema,
  filters,
  setFilters,
  timeRange,
  onTimeRangeChange,
  customPeriod,
  onCustomPeriodChange,
  displayTimezone,
  filterMode,
  onFilterModeChange,
  filterText,
  onFilterTextChange,
  filterTextError,
  onClearFilters,
  onCollapse,
  onRun,
  suggestCtx,
  dnsSources,
  isLoading = false,
}) {
  const panelRef = React.useRef(null);

  useEffect(() => {
    const onKeyDown = (e) => {
      if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter') return;
      if (!panelRef.current?.contains(document.activeElement)) return;
      e.preventDefault();
      onRun?.();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onRun]);

  const updateFilter = (id, patch) => {
    setFilters(filters.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  };
  const removeFilter = (id) => setFilters(filters.filter((f) => f.id !== id));
  const addFilter = (fieldId) => {
    const field = fieldId || 'query_name';
    setFilters([
      ...filters,
      {
        id: `dns-f-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        field,
        op: DNS_FIELD_OPS[field]?.[0]?.id || 'eq',
        value: '',
        logic: 'and',
      },
    ]);
  };

  return (
    <div ref={panelRef}>
      <Card pad="sm" className="explorer-filters-panel">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
          <div className="row" style={{ gap: 8, alignItems: 'center' }}>
            <div style={{ font: 'var(--pv-text-h4)' }}>Фильтры</div>
            <DnsExplorerFilterModeToggle filterMode={filterMode} onFilterModeChange={onFilterModeChange} />
          </div>
          <button type="button" className="icon-btn" onClick={onCollapse} title="Свернуть панель"><Icon name="chevL" size={14} /></button>
        </div>

        {filterMode === 'graphic' ? (
          <div className="col explorer-filters-panel__body" style={{ marginBottom: 12 }}>
            <DnsExplorerSystemFilterRow title="Период" mandatory>
              <TimeFilter
                variant="explorer"
                timeRange={timeRange}
                onTimeRangeChange={onTimeRangeChange}
                customPeriod={customPeriod}
                onCustomPeriodChange={onCustomPeriodChange}
              />
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
                Макс. {DNS_EXPLORER_MAX_RANGE_DAYS} дней
              </div>
            </DnsExplorerSystemFilterRow>

            <div className="explorer-panel-section">
              <div className="explorer-panel-section__head">Условия</div>
              {!filters.length && (
                <div className="explorer-panel-section__empty">
                  <span>Добавьте при необходимости кнопкой «Условие»</span>
                </div>
              )}
              {filters.map((row, i) => (
                <DnsExplorerFilterRow
                  key={row.id}
                  row={row}
                  index={i}
                  schema={schema}
                  suggestCtx={suggestCtx}
                  onChange={(patch) => updateFilter(row.id, patch)}
                  onRemove={() => removeFilter(row.id)}
                  dnsSources={dnsSources}
                />
              ))}
              <div className="explorer-panel-section__add">
                <DnsExplorerAddFilterMenu
                  schema={schema}
                  onPickField={(fieldId) => addFilter(fieldId)}
                />
              </div>
            </div>

            <div className="explorer-filters-actions">
              <Button kind="ghost" size="sm" icon="x" onClick={onClearFilters}>Очистить фильтры</Button>
              <Button kind="ghost" size="sm" icon="play" onClick={onRun} disabled={isLoading}>Применить</Button>
              <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>Ctrl+Enter — применить</span>
            </div>
          </div>
        ) : (
          <div className="col explorer-filters-panel__body" style={{ marginBottom: 12 }}>
            <DnsExplorerFilterTextEditor
              value={filterText}
              onChange={onFilterTextChange}
              error={filterTextError}
              schema={schema}
              suggestCtx={suggestCtx}
              dnsSources={dnsSources}
            />
            <div className="explorer-filters-actions">
              <Button kind="ghost" size="sm" icon="x" onClick={onClearFilters}>Очистить фильтры</Button>
              <Button kind="ghost" size="sm" icon="play" onClick={onRun} disabled={isLoading}>Применить</Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function dnsExplorerFilterLabel(fieldId, schema) {
  return schema?.fields?.find((f) => f.id === fieldId)?.label || fieldId;
}

function dnsExplorerMetricLabel(metricId, schema) {
  return schema?.metrics?.find((m) => m.id === metricId)?.label || metricId;
}

function dnsExplorerGroupLabel(groupId, schema) {
  return schema?.groupBy?.find((g) => g.id === groupId)?.label || groupId;
}

function buildDnsExplorerPayload({
  metric,
  groupBy,
  filters,
  timeRange,
  customPeriod,
  collectorFilter,
  limit,
}) {
  const body = {
    metric,
    groupBy,
    filters,
    limit,
    range: timeRange,
  };
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    body.from = customPeriod.from;
    body.to = customPeriod.to;
  }
  if (collectorFilter?.length) {
    body.collectorId = collectorFilter.join(',');
  }
  return body;
}

function defaultDnsChartSeriesIds(rows, limit = DNS_EXPLORER_DEFAULT_VISUAL_LIMIT) {
  return new Set(sliceDnsVisualRows(rows, limit).map((r) => r.id));
}

function resolveDnsVisualCount(visualLimit, total) {
  if (visualLimit === 'all') return total;
  const n = Number(visualLimit);
  if (!Number.isFinite(n) || n <= 0) return Math.min(DNS_EXPLORER_DEFAULT_VISUAL_LIMIT, total);
  return Math.min(n, total);
}

function sliceDnsVisualRows(rows, visualLimit) {
  return (rows || []).slice(0, resolveDnsVisualCount(visualLimit, rows?.length || 0));
}

function isDnsDisplayLimitActive(buttonLimit, visualLimit, fetchLimit) {
  if (visualLimit === 'all') return buttonLimit === fetchLimit;
  return Number(visualLimit) === buttonLimit;
}

function DnsExplorerVisualLimitControl({ total, fetchLimit, value, onChange }) {
  const shown = resolveDnsVisualCount(value, total);
  const instantOptions = [5, 10, 25, 50].filter((n) => n <= fetchLimit);
  if (total <= DNS_EXPLORER_DEFAULT_VISUAL_LIMIT && fetchLimit <= DNS_EXPLORER_DEFAULT_VISUAL_LIMIT) return null;

  return (
    <div className="explorer-visual-limit">
      <div className="explorer-visual-limit__main row">
        <span className="explorer-visual-limit__summary">
          Загружено {total} · показано {shown}
        </span>
        <div className="seg explorer-visual-limit__seg">
          {instantOptions.map((opt) => (
            <button
              key={String(opt)}
              type="button"
              className={isDnsDisplayLimitActive(opt, value, fetchLimit) ? 'is-active' : ''}
              onClick={() => onChange(opt)}
            >
              {opt}
            </button>
          ))}
          {fetchLimit > DNS_EXPLORER_DEFAULT_VISUAL_LIMIT && (
            <button
              type="button"
              className={value === 'all' ? 'is-active' : ''}
              onClick={() => onChange('all')}
            >
              Все
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function dnsExplorerDimDisplayValue(value, fieldId, context = {}) {
  if (fieldId === 'rcode') {
    const n = Number(value);
    if (n === 0) return 'Успешно';
    if (n === 2) return 'Ошибка DNS-сервера';
    if (n === 3) return 'Домен не найден';
    if (Number.isFinite(n)) return 'Другой код';
  }
  if (fieldId === 'answer_type') {
    if (value === 'none' || value === '') return 'без записей';
    return value ?? '—';
  }
  if (fieldId === 'answer') {
    if (value === '' || value == null) return 'без записей в ответе';
    const answerType = context.answerType;
    if (answerType === 'CNAME') return `${value} (CNAME)`;
    return value;
  }
  return value ?? '—';
}

function renderDnsExplorerDimValue(value, fieldId, row, groupBy) {
  const answerTypeIdx = groupBy.indexOf('answer_type');
  const answerType = answerTypeIdx >= 0 ? row?.values?.[answerTypeIdx] : null;
  const display = dnsExplorerDimDisplayValue(value, fieldId, { answerType });
  const muted = fieldId === 'answer' && (value === '' || value == null);
  const mono = fieldId === 'answer' || fieldId === 'client_ip' || fieldId === 'server_ip';
  return (
    <span className={mono ? 'mono' : undefined} style={muted ? { color: 'var(--fg-muted)' } : undefined}>
      {display}
    </span>
  );
}

function dnsExplorerRowLabel(row, groupBy) {
  return (row?.values || []).map((val, idx) => {
    const answerTypeIdx = groupBy.indexOf('answer_type');
    const answerType = answerTypeIdx >= 0 ? row?.values?.[answerTypeIdx] : null;
    return dnsExplorerDimDisplayValue(val, groupBy[idx], { answerType });
  }).join(' · ');
}

function dnsExplorerMetricKind(metricId, schema) {
  return schema?.metrics?.find((m) => m.id === metricId)?.kind
    || (String(metricId || '').endsWith('_per_sec') ? 'rate' : 'total');
}

function formatDnsMetric(value, metric, schema) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  if (dnsExplorerMetricKind(metric, schema) === 'rate') {
    if (n >= 1e6) return `${(n / 1e6).toFixed(n >= 10e6 ? 0 : 1)} млн/с`;
    if (n >= 1e3) return `${(n / 1e3).toFixed(n >= 10e3 ? 0 : 1)} тыс/с`;
    if (n > 0 && n < 10 && !Number.isInteger(n)) return `${n.toFixed(1)}/с`;
    return `${fmtNum(n)}/с`;
  }
  return fmtNum(n);
}

function formatDnsMetricAxis(value, metric, schema) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '0';
  if (dnsExplorerMetricKind(metric, schema) === 'rate') {
    if (n >= 1e6) return `${(n / 1e6).toFixed(n >= 10e6 ? 0 : 1)}M`;
    if (n >= 1e3) return `${(n / 1e3).toFixed(n >= 10e3 ? 0 : 1)}k`;
    return n < 10 && !Number.isInteger(n) ? n.toFixed(1) : String(Math.round(n));
  }
  return fmtCompact(n);
}

function dnsMetricAxisUnit(metric, schema) {
  return dnsExplorerMetricLabel(metric, schema) || '';
}

function dnsExplorerTableMetricTitle(metricId, schema) {
  const label = dnsExplorerMetricLabel(metricId, schema);
  if (dnsExplorerMetricKind(metricId, schema) === 'rate') {
    return `${label} (ср.)`;
  }
  return label;
}

function DnsExplorerChartToggleButton({ onChart, onClick }) {
  return (
    <button
      type="button"
      className={`badge explorer-row-actions__btn${onChart ? ' badge--info' : ''}`}
      title={onChart ? 'Скрыть серию с графика динамики' : 'Показать серию на графике динамики'}
      onClick={onClick}
    >
      <span className="explorer-row-actions__label explorer-row-actions__label--full">{onChart ? 'Скрыть с графика' : 'Показать'}</span>
      <span className="explorer-row-actions__label explorer-row-actions__label--short">{onChart ? 'Скрыть' : 'Показать'}</span>
    </button>
  );
}

function DnsExplorerTotalChart({
  points,
  metric,
  metricLabel,
  schema,
  displayTimezone,
  chartLongRange,
  bucketSeconds,
}) {
  const normalizedPoints = (Array.isArray(points) ? points : [])
    .map((point) => {
      const next = {
        ...point,
        bucket: normalizeBucketString(point.bucket),
        value: Number(point.value) || 0,
      };
      next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
      return next;
    })
    .sort((a, b) => (resolvePointEpochMs(a) || 0) - (resolvePointEpochMs(b) || 0));
  const chartPoints = normalizedPoints.length === 1
    ? [normalizedPoints[0], { ...normalizedPoints[0] }]
    : normalizedPoints;

  if (chartPoints.length < 2) {
    return (
      <div className="explorer-lines__empty">
        Недостаточно временных точек для динамики. Расширьте период или выберите другую метрику.
      </div>
    );
  }

  return (
    <div className="explorer-lines col" style={{ gap: 8 }}>
      <div className="explorer-time-chart explorer-dynamics-chart">
        <DualChart
          points={chartPoints}
          lines={[{ key: 'value', label: metricLabel || metric, color: '#7381f4' }]}
          height={DNS_EXPLORER_CHART_HEIGHT}
          mode="bw"
          gapAsZero
          bucketSeconds={bucketSeconds}
          displayTimezone={displayTimezone}
          valueFormatter={(value) => formatDnsMetric(value, metric, schema)}
          axisFormatter={(value) => formatDnsMetricAxis(value, metric, schema)}
          yAxisUnit={dnsMetricAxisUnit(metric, schema)}
        />
      </div>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        Ось Y — {metricLabel || metric} по всем DNS-событиям, соответствующим условиям, в каждом временном интервале.
      </div>
    </div>
  );
}

function DnsExplorerDynamicsChart({
  results,
  resultSeries,
  metric,
  metricLabel,
  schema,
  displayTimezone,
  chartLongRange,
  selectedSeriesIds,
  groupBy,
  bucketSeconds,
}) {
  const [chartKey, setChartKey] = useState(0);
  const selectedSeriesKey = [...selectedSeriesIds].sort().join('|');
  useEffect(() => {
    setChartKey((k) => k + 1);
  }, [selectedSeriesKey]);

  const seriesByRow = resultSeries?.seriesByRow || {};
  const resultIdSet = new Set(results.map((r) => r.id));
  const selectedIds = [...selectedSeriesIds].filter((id) => resultIdSet.has(id));
  const lines = results
    .filter((r) => selectedIds.includes(r.id))
    .map((row) => ({
      key: row.id,
      label: dnsExplorerRowLabel(row, groupBy),
      color: row.color,
    }));

  const pointsByBucket = new Map();
  for (const rowId of selectedIds) {
    for (const pt of seriesByRow[rowId] || []) {
      const bucket = normalizeBucketString(pt.bucket);
      if (!pointsByBucket.has(bucket)) {
        pointsByBucket.set(bucket, { ...pt, bucket });
      }
      const current = Number(pointsByBucket.get(bucket)[rowId]) || 0;
      pointsByBucket.get(bucket)[rowId] = current + (Number(pt.value) || 0);
    }
  }

  const points = [...pointsByBucket.values()]
    .sort((a, b) => (resolvePointEpochMs(a) || 0) - (resolvePointEpochMs(b) || 0))
    .map((pt) => {
      const next = { ...pt };
      for (const rowId of selectedIds) {
        if (next[rowId] == null) next[rowId] = 0;
      }
      next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
      if (next.bucketMs != null) next.bucketMs = Number(next.bucketMs);
      return next;
    });
  const chartPoints = points.length === 1 ? [points[0], { ...points[0] }] : points;

  return (
    <div className="explorer-lines col" style={{ gap: 12 }}>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        {selectedIds.length
          ? `На графике ${selectedIds.length} серий. Управляйте сериями кнопками «Показать» / «Скрыть с графика» в таблице.`
          : 'Нет серий на графике. Включите строки кнопкой «Показать» в таблице «Результаты».'}
      </div>
      {chartPoints.length > 1 && lines.length ? (
        <>
          <div className="explorer-time-chart explorer-dynamics-chart">
            <DualChart
              key={chartKey}
              points={chartPoints}
              lines={lines}
              height={DNS_EXPLORER_CHART_HEIGHT}
              mode="bw"
              gapAsZero
              bucketSeconds={bucketSeconds}
              displayTimezone={displayTimezone}
              valueFormatter={(v) => formatDnsMetric(v, metric, schema)}
              axisFormatter={(v) => formatDnsMetricAxis(v, metric, schema)}
              yAxisUnit={dnsMetricAxisUnit(metric, schema)}
            />
          </div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: -4 }}>
            Ось Y — {metricLabel || metric} в каждом временном интервале. В таблице — среднее за период.
          </div>
        </>
      ) : (
        <div className="explorer-lines__empty">
          {selectedIds.length
            ? 'Недостаточно временных точек для динамики. Расширьте период или выберите другую метрику.'
            : 'Включите серии в таблице «Результаты», чтобы добавить их на график.'}
        </div>
      )}
    </div>
  );
}

function DnsExplorerFilterRow({
  row,
  index,
  schema,
  suggestCtx,
  onChange,
  onRemove,
  dnsSources,
}) {
  const ops = DNS_FIELD_OPS[row.field] || [{ id: 'eq', label: 'равно' }];
  const [suggestions, setSuggestions] = useState([]);
  const [qtypes, setQtypes] = useState([]);

  useEffect(() => {
    if (row.field === 'qtype') {
      ApiClient.suggestDnsExplorerQtypes(suggestCtx).then(setQtypes).catch(() => setQtypes([]));
    }
  }, [row.field, suggestCtx]);

  useEffect(() => {
    if (!row.value || row.field === 'rcode' || row.field === 'source_id' || row.field === 'qtype') {
      setSuggestions([]);
      return undefined;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      const loader = row.field === 'query_name'
        ? ApiClient.suggestDnsExplorerDomains
        : row.field === 'client_ip'
          ? ApiClient.suggestDnsExplorerClientIps
          : row.field === 'server_ip'
            ? ApiClient.suggestDnsExplorerServerIps
            : row.field === 'answer'
              ? ApiClient.suggestDnsExplorerAnswers
              : null;
      if (!loader) return;
      loader(suggestCtx, row.value).then((items) => {
        if (!cancelled) setSuggestions(items);
      }).catch(() => { if (!cancelled) setSuggestions([]); });
    }, 300);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [row.field, row.value, suggestCtx]);

  const renderValueInput = () => {
    if (row.field === 'rcode') {
      if (row.op === 'in') {
        return (
          <select
            className="input"
            multiple
            value={row.values || []}
            onChange={(e) => onChange({
              values: [...e.target.selectedOptions].map((o) => o.value),
            })}
          >
            {DNS_RCODE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        );
      }
      return (
        <select className="input" value={row.value || ''} onChange={(e) => onChange({ value: e.target.value })}>
          <option value="">Выберите…</option>
          {DNS_RCODE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      );
    }
    if (row.field === 'source_id') {
      return (
        <select
          className="input"
          multiple
          value={row.values || []}
          onChange={(e) => onChange({
            values: [...e.target.selectedOptions].map((o) => o.value),
          })}
        >
          {(dnsSources || []).map((s) => (
            <option key={s.sourceId} value={s.sourceId}>{s.displayName || s.sourceId}</option>
          ))}
        </select>
      );
    }
    if (row.field === 'qtype' && row.op === 'in') {
      return (
        <select
          className="input"
          multiple
          value={row.values || []}
          onChange={(e) => onChange({
            values: [...e.target.selectedOptions].map((o) => o.value),
          })}
        >
          {qtypes.map((o) => (
            <option key={o.value} value={o.value}>{o.value} ({fmtNum(o.count)})</option>
          ))}
        </select>
      );
    }
    return (
      <div className="dns-explorer-suggest explorer-filter-value-wrap">
        <input
          className="input"
          value={row.value || ''}
          onChange={(e) => onChange({ value: e.target.value })}
          placeholder="Значение"
          list={`dns-explorer-suggest-${row.id}`}
        />
        {suggestions.length > 0 && (
          <datalist id={`dns-explorer-suggest-${row.id}`}>
            {suggestions.map((s) => (
              <option key={s.value} value={s.value}>{s.resolverLabel ? `${s.value} · ${s.resolverLabel}` : s.value}</option>
            ))}
          </datalist>
        )}
      </div>
    );
  };

  return (
    <div className={`explorer-filter-row${index === 0 ? ' explorer-filter-row--first' : ''}`}>
      <div className="explorer-filter-row__main">
        {index > 0 ? (
          <select
            className="input explorer-filter-row__logic"
            value={normalizeDnsExplorerFilterLogic(row.logic)}
            onChange={(e) => onChange({ logic: e.target.value })}
            title="Связь с предыдущим условием"
          >
            {DNS_EXPLORER_FILTER_LOGIC_OPTIONS.map((opt) => (
              <option key={opt.id} value={opt.id}>{opt.label}</option>
            ))}
          </select>
        ) : (
          <span className="explorer-filter-row__logic-placeholder" aria-hidden="true" />
        )}
        <div className="explorer-filter-row__field">
          <select
            className="input"
            value={row.field}
            onChange={(e) => onChange({
              field: e.target.value,
              op: DNS_FIELD_OPS[e.target.value]?.[0]?.id || 'eq',
              value: '',
              values: undefined,
              logic: row.logic || 'and',
            })}
          >
            {(schema?.fields || []).map((f) => (
              <option key={f.id} value={f.id}>{f.label}</option>
            ))}
          </select>
        </div>
        <select className="input explorer-filter-row__op" value={row.op} onChange={(e) => onChange({ op: e.target.value })}>
          {ops.map((o) => (
            <option key={o.id} value={o.id}>{o.label}</option>
          ))}
        </select>
        <div className="explorer-filter-row__value">
          {renderValueInput()}
        </div>
        <button type="button" className="icon-btn explorer-filter-row__remove" title="Удалить условие" onClick={onRemove}>
          <Icon name="x" size={10} stroke={2.5} />
        </button>
      </div>
    </div>
  );
}

function hydrateDnsFromSharedSnapshot({ snapshot, payload, shareMeta }, handlers) {
  if (snapshot.timeRange) handlers.setTimeRange(snapshot.timeRange);
  if (snapshot.timeRange === 'custom' && snapshot.customPeriod) {
    handlers.setCustomPeriod(snapshot.customPeriod);
  }
  if (snapshot.collectorFilter) handlers.setCollectorFilter([...(snapshot.collectorFilter || [])]);
  handlers.setMetric(snapshot.metric || DNS_EXPLORER_DEFAULT_METRIC);
  handlers.setGroupBy([...(snapshot.groupBy || [])]);
  handlers.setFilters(ensureDnsFilterIds(snapshot.filters || []));
  handlers.setAppliedSnapshot({
    metric: snapshot.metric || DNS_EXPLORER_DEFAULT_METRIC,
    groupBy: [...(snapshot.groupBy || [])],
    filters: cloneDnsExplorerFilters(snapshot.filters || []),
    timeRange: snapshot.timeRange,
    customPeriod: snapshot.customPeriod ? { ...snapshot.customPeriod } : handlers.customPeriod,
    collectorFilter: [...(snapshot.collectorFilter || [])],
  });
  handlers.setHasAppliedQuery(true);
  handlers.setRows(Array.isArray(payload.rows) ? payload.rows : []);
  handlers.setTimeseries(Array.isArray(payload.timeseries) ? payload.timeseries : []);
  handlers.setResultSeries(payload.resultSeries || null);
  handlers.setMeta(payload.meta || null);
  handlers.setLoadMs(payload.loadMs ?? null);
  handlers.setServerMs(payload.serverMs ?? null);
  handlers.setSource('snapshot');
  handlers.setError(null);
  handlers.setShareMeta(shareMeta || null);
  handlers.setSnapshotId(shareMeta?.id || null);
  handlers.setChartSeriesIds((snapshot.groupBy || []).length
    ? defaultDnsChartSeriesIds(payload.rows || [], handlers.visualLimit)
    : new Set());
}

function formatDnsSnapshotTimestamp(value, displayTimezone) {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString('ru-RU', displayTimezone ? { timeZone: displayTimezone } : undefined);
  } catch {
    return String(value);
  }
}

function PageDnsExplorer({ onNavigate, displayTimezone }) {
  const urlGlobals = useMemo(() => applyDnsExplorerUrlGlobals(parseAppHash().params), []);
  const urlState = useMemo(() => readDnsExplorerPageParamsFromHash?.() || null, []);
  const urlSnapshotToken = urlState?.snapshot || null;
  const mountRestoreDoneRef = useRef(false);

  const [schema, setSchema] = useState(null);
  const [dnsSources, setDnsSources] = useState([]);
  const [timeRange, setTimeRange] = useState(urlGlobals.timeRange || '24h');
  const [customPeriod, setCustomPeriod] = useState(urlGlobals.customPeriod || defaultCustomPeriod());
  const [collectorFilter, setCollectorFilter] = useState(urlGlobals.collectorFilter || []);
  const [metric, setMetric] = useState(() => coerceDnsMetricForGrouping(
    urlState?.metric || DNS_EXPLORER_DEFAULT_METRIC,
    urlState?.groupBy || [],
  ));
  const [groupBy, setGroupBy] = useState(urlState?.groupBy || []);
  const [filters, setFilters] = useState(() => ensureDnsFilterIds(urlState?.filters?.length ? urlState.filters : []));
  const initialDraftRef = useRef({
    metric: urlState?.metric || DNS_EXPLORER_DEFAULT_METRIC,
    groupBy: urlState?.groupBy || [],
    filters: ensureDnsFilterIds(urlState?.filters?.length ? urlState.filters : []),
    timeRange: urlGlobals.timeRange || '24h',
    customPeriod: urlGlobals.customPeriod || defaultCustomPeriod(),
    collectorFilter: urlGlobals.collectorFilter || [],
  });
  const [filterPanel, setFilterPanel] = useState(true);
  const [filterMode, setFilterMode] = useState('graphic');
  const [filterText, setFilterText] = useState('');
  const [filterTextError, setFilterTextError] = useState(null);
  const [addingDim, setAddingDim] = useState(false);
  const dimAnchorRef = useRef(null);
  const [appliedSnapshot, setAppliedSnapshot] = useState(null);
  const [hasAppliedQuery, setHasAppliedQuery] = useState(false);
  const [source, setSource] = useState('idle');
  const [error, setError] = useState(null);
  const [meta, setMeta] = useState(null);
  const [timeseries, setTimeseries] = useState([]);
  const [resultSeries, setResultSeries] = useState(null);
  const [rows, setRows] = useState([]);
  const [visualLimit, setVisualLimit] = useState(DNS_EXPLORER_DEFAULT_VISUAL_LIMIT);
  const [chartSeriesIds, setChartSeriesIds] = useState(() => new Set());
  const prevVisualLimitRef = useRef(null);
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);
  const [exporting, setExporting] = useState(false);
  const [snapshotId, setSnapshotId] = useState(null);
  const [shareMeta, setShareMeta] = useState(null);
  const [sharing, setSharing] = useState(false);

  useEffect(() => {
    if (mountRestoreDoneRef.current) return;
    mountRestoreDoneRef.current = true;
    if (!urlSnapshotToken) return undefined;

    let cancelled = false;
    setSource('loading');
    ApiClient.loadDnsExplorerSharedSnapshot(urlSnapshotToken).then((result) => {
      if (cancelled) return;
      if (!result.ok) {
        setSource('error');
        setError(result.message || ApiClient.LOAD_FAILED);
        return;
      }
      hydrateDnsFromSharedSnapshot(result, {
        setTimeRange,
        setCustomPeriod,
        setCollectorFilter,
        setMetric,
        setGroupBy,
        setFilters,
        setAppliedSnapshot,
        setHasAppliedQuery,
        setRows,
        setTimeseries,
        setResultSeries,
        setMeta,
        setLoadMs,
        setServerMs,
        setSource,
        setError,
        setShareMeta,
        setSnapshotId,
        setChartSeriesIds,
        visualLimit,
        customPeriod,
      });
    }).catch((err) => {
      if (cancelled) return;
      setSource('error');
      setError(err.message || ApiClient.LOAD_FAILED);
    });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    ApiClient.loadDnsExplorerSchema().then(setSchema).catch(() => setSchema(null));
    ApiClient.loadDnsSources().then((r) => setDnsSources(r.rows || [])).catch(() => setDnsSources([]));
  }, []);

  useEffect(() => {
    setMetric((current) => coerceDnsMetricForGrouping(current, groupBy));
  }, [groupBy]);

  useEffect(() => {
    if (filterMode !== 'text') return;
    setFilterText(serializeDnsExplorerFilterDsl({ timeRange, customPeriod, filters }));
    setFilterTextError(null);
  }, [filterMode]);

  const groupDimensions = useMemo(
    () => (schema?.groupBy || []).map((g) => ({ id: g.id, label: g.label })),
    [schema],
  );

  const applyParsedTextToDraft = (text) => {
    const parsed = parseDnsExplorerFilterDsl(text, schema);
    setTimeRange(parsed.timeRange);
    if (parsed.timeRange === 'custom') setCustomPeriod(parsed.customPeriod);
    setFilters(parsed.filters);
    setFilterTextError(null);
    return parsed;
  };

  const changeFilterMode = (nextMode) => {
    if (nextMode === filterMode) return;
    if (filterMode === 'text' && nextMode === 'graphic') {
      if (String(filterText || '').trim()) {
        try {
          applyParsedTextToDraft(filterText);
        } catch (err) {
          setFilterTextError(err.message);
          pushToast?.({ kind: 'error', title: 'Ошибка фильтра', desc: err.message });
          return;
        }
      } else {
        setFilters([]);
        setFilterTextError(null);
      }
    }
    if (nextMode === 'text') {
      setFilterText(serializeDnsExplorerFilterDsl({ timeRange, customPeriod, filters }));
      setFilterTextError(null);
    }
    setFilterMode(nextMode);
  };

  const clearDnsExplorerFilters = () => {
    setFilters([]);
    setFilterText(serializeDnsExplorerFilterDsl({
      timeRange,
      customPeriod,
      filters: [],
    }));
    setFilterTextError(null);
  };

  const openFilterPanel = () => setFilterPanel(true);

  const suggestCtx = useMemo(() => ({
    timeRange,
    customPeriod,
    collectorFilter,
    filters,
  }), [timeRange, customPeriod?.from, customPeriod?.to, collectorFilter, filters]);

  const runQuery = async (overrides = {}) => {
    let nextFilters = overrides.filters ?? filters;
    let nextTimeRange = overrides.timeRange ?? timeRange;
    let nextCustomPeriod = overrides.customPeriod ?? customPeriod;
    let nextMetric = overrides.metric ?? metric;
    let nextGroupBy = overrides.groupBy ?? groupBy;

    if (filterMode === 'text' && !overrides.skipTextParse) {
      try {
        const parsed = applyParsedTextToDraft(filterText);
        nextFilters = parsed.filters;
        nextTimeRange = parsed.timeRange;
        nextCustomPeriod = parsed.customPeriod;
      } catch (err) {
        setFilterTextError(err.message);
        pushToast?.({ kind: 'error', title: 'Ошибка фильтра', desc: err.message });
        return;
      }
    }

    nextMetric = coerceDnsMetricForGrouping(nextMetric, nextGroupBy);
    if (overrides.metric != null || overrides.groupBy != null) {
      setMetric(nextMetric);
      setGroupBy([...nextGroupBy]);
      if (overrides.filters != null) setFilters(cloneDnsExplorerFilters(nextFilters));
    }

    setSource('loading');
    setError(null);
    const snapshot = {
      metric: nextMetric,
      groupBy: [...nextGroupBy],
      filters: cloneDnsExplorerFilters(nextFilters),
      timeRange: nextTimeRange,
      customPeriod: { ...nextCustomPeriod },
      collectorFilter: [...(collectorFilter || [])],
    };
    const payload = buildDnsExplorerPayload({ ...snapshot, limit: DNS_EXPLORER_DEFAULT_LIMIT });
    const result = await ApiClient.runDnsExplorerQuery(payload);
    if (!result.ok) {
      setSource('error');
      setError(result.message || ApiClient.LOAD_FAILED);
      setRows([]);
      setTimeseries([]);
      setResultSeries(null);
      setChartSeriesIds(new Set());
      setMeta(null);
      return;
    }
    const apiRows = result.data?.rows || [];
    setAppliedSnapshot(snapshot);
    setHasAppliedQuery(true);
    setSource('clickhouse');
    setMeta(result.meta);
    setLoadMs(result.loadMs);
    setServerMs(result.serverMs);
    setSnapshotId(result.snapshotId || null);
    setRows(apiRows);
    setTimeseries(result.data?.timeseries || []);
    setResultSeries(result.data?.resultSeries || null);
    setChartSeriesIds(snapshot.groupBy?.length
      ? defaultDnsChartSeriesIds(apiRows, visualLimit)
      : new Set());
  };

  useEffect(() => {
    if (prevVisualLimitRef.current === null) {
      prevVisualLimitRef.current = visualLimit;
      return;
    }
    if (prevVisualLimitRef.current === visualLimit) return;
    prevVisualLimitRef.current = visualLimit;
    if (!hasAppliedQuery || !(appliedSnapshot?.groupBy || []).length || !rows.length) return;
    setChartSeriesIds(defaultDnsChartSeriesIds(rows, visualLimit));
  }, [visualLimit, hasAppliedQuery, appliedSnapshot?.groupBy, rows]);

  const toggleChartSeries = (rowId) => {
    setChartSeriesIds((prev) => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId);
      else next.add(rowId);
      return next;
    });
  };

  const showAnswersForDomain = (domainValue) => {
    const normalizedDomain = String(domainValue || '').replace(/\.$/, '');
    const nextFilters = cloneDnsExplorerFilters(filters).filter((f) => f.field !== 'query_name');
    nextFilters.push({
      id: `dns-f-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      field: 'query_name',
      op: 'eq',
      value: normalizedDomain,
      logic: 'and',
    });
    runQuery({
      filters: nextFilters,
      groupBy: ['answer'],
      metric: 'responses_per_sec',
      skipTextParse: filterMode === 'text',
    });
  };

  const tableColumns = useMemo(() => {
    const appliedGroup = appliedSnapshot?.groupBy || [];
    if (!appliedGroup.length) return [];
    const domainIdx = appliedGroup.indexOf('query_name');
    const cols = appliedGroup.map((id, idx) => ({
      key: `dim_${idx}`,
      title: dnsExplorerGroupLabel(id, schema),
      headerClassName: 'explorer-col-dim',
      cellClassName: 'explorer-col-dim',
      render: (row) => (
        idx === 0 ? (
          <div className="explorer-dim-cell">
            <span className="explorer-dim-cell__swatch" style={{ background: row.color }} aria-hidden="true" />
            {renderDnsExplorerDimValue(row.values?.[idx], id, row, appliedGroup)}
          </div>
        ) : (
          renderDnsExplorerDimValue(row.values?.[idx], id, row, appliedGroup)
        )
      ),
    }));
    cols.push({
      key: 'value',
      title: dnsExplorerTableMetricTitle(appliedSnapshot?.metric, schema),
      align: 'right',
      num: true,
      headerClassName: 'explorer-col-metric',
      cellClassName: 'explorer-col-metric',
      render: (r) => formatDnsMetric(r.value, appliedSnapshot?.metric, schema),
    });
    cols.push({
      key: 'actions',
      title: '',
      sortable: false,
      headerClassName: 'explorer-col-actions',
      cellClassName: 'explorer-col-actions',
      render: (row) => (
        <div className="explorer-row-actions">
          {domainIdx >= 0 && (
            <button
              type="button"
              className="badge explorer-row-actions__btn"
              title="Показать ответы для этого домена"
              onClick={() => showAnswersForDomain(row.values?.[domainIdx])}
            >
              <span className="explorer-row-actions__label explorer-row-actions__label--full">Показать ответы</span>
              <span className="explorer-row-actions__label explorer-row-actions__label--short">Ответы</span>
            </button>
          )}
          <DnsExplorerChartToggleButton
            onChart={chartSeriesIds.has(row.id)}
            onClick={() => toggleChartSeries(row.id)}
          />
        </div>
      ),
    });
    return cols;
  }, [appliedSnapshot, schema, chartSeriesIds, filters, filterMode, metric, groupBy, timeRange, customPeriod, collectorFilter]);

  const appliedGroupBy = appliedSnapshot?.groupBy || [];
  const hasAppliedAnswerGrouping = hasDnsAnswerGrouping(appliedGroupBy);
  const chartLongRange = isLongChartRange(appliedSnapshot?.timeRange || timeRange, appliedSnapshot?.customPeriod || customPeriod);
  const chartBucketSeconds = dnsBucketSecondsFromMode(meta?.bucketMode);
  const appliedMetricLabel = dnsExplorerMetricLabel(appliedSnapshot?.metric, schema);
  const visibleResults = useMemo(
    () => sliceDnsVisualRows(rows, visualLimit),
    [rows, visualLimit],
  );
  const visiblePageSize = Math.max(resolveDnsVisualCount(visualLimit, visibleResults.length), 1);

  const copyFilterShareUrl = async () => {
    const url = buildDnsExplorerShareUrl({
      metric,
      groupBy,
      filters: cloneDnsExplorerFilters(filters).map(normalizeDnsExplorerFilter),
      timeRange,
      customPeriod,
    });
    try {
      await copyTextToClipboard(url);
      pushToast?.({ kind: 'success', title: 'Ссылка скопирована', desc: 'URL содержит параметры фильтра.' });
    } catch (err) {
      pushToast?.({ kind: 'error', title: 'Не удалось скопировать', desc: err.message });
    }
  };

  const copyResultsShareUrl = async () => {
    if (!snapshotId) {
      pushToast?.({ kind: 'error', title: 'Нет данных для шаринга', desc: 'Сначала выполните запрос.' });
      return;
    }
    setSharing(true);
    try {
      const data = await ApiClient.shareDnsExplorerSnapshot(snapshotId);
      const url = buildDnsExplorerSnapshotShareUrl(data.token);
      await copyTextToClipboard(url);
      setShareMeta((prev) => ({
        ...(prev || {}),
        expiresAt: data.expiresAt,
        sharedAt: data.sharedAt,
      }));
      pushToast?.({
        kind: 'success',
        title: 'Ссылка скопирована',
        desc: `Сохранённые результаты доступны до ${formatDnsSnapshotTimestamp(data.expiresAt, displayTimezone)}.`,
      });
    } catch (err) {
      pushToast?.({ kind: 'error', title: 'Не удалось создать ссылку', desc: err.message });
    } finally {
      setSharing(false);
    }
  };

  const exportCsv = async () => {
    if (!hasAppliedQuery || !appliedSnapshot) return;
    setExporting(true);
    try {
      const exportPayload = buildDnsExplorerPayload({
        ...appliedSnapshot,
        filters: (appliedSnapshot.filters || []).map(normalizeDnsExplorerFilter),
        limit: DNS_EXPLORER_DEFAULT_LIMIT,
      });
      if (meta?.from && meta?.to) {
        exportPayload.from = meta.from;
        exportPayload.to = meta.to;
        exportPayload.range = 'custom';
      }
      const blob = await ApiClient.exportDnsExplorerCsv(exportPayload);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dns-explorer-${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      pushToast?.({
        kind: 'success',
        title: 'CSV экспортирован',
        desc: 'Файл сохранён на ваш компьютер.',
      });
    } catch (err) {
      pushToast?.({
        kind: 'error',
        title: 'Не удалось экспортировать CSV',
        desc: err.message || ApiClient.LOAD_FAILED,
      });
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="main__container dns-explorer-page">
      <div className="page-head">
        <div>
          <h1>Разбор DNS</h1>
          <p>Исследование DNS-запросов по условиям · {timeRangeLabel(timeRange, customPeriod)}</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" size="sm" onClick={() => onNavigate?.('dns')}>Вернуться в обзор DNS</Button>
          <Button kind="ghost" size="sm" icon="link" onClick={copyFilterShareUrl}>Поделиться фильтрами</Button>
          {hasAppliedQuery && (
            <>
              <Button kind="ghost" size="sm" icon="export" onClick={exportCsv} disabled={exporting}>
                {exporting ? 'Экспорт…' : 'CSV'}
              </Button>
              <Button
                kind="ghost"
                size="sm"
                icon="copy"
                onClick={copyResultsShareUrl}
                disabled={!snapshotId || sharing}
              >
                {sharing ? 'Ссылка…' : 'Поделиться результатами'}
              </Button>
            </>
          )}
        </div>
      </div>

      {(source === 'snapshot') && hasAppliedQuery && (
        <div
          className="row"
          style={{
            gap: 12,
            flexWrap: 'wrap',
            alignItems: 'center',
            padding: '10px 14px',
            marginBottom: 8,
            borderRadius: 10,
            border: '1px solid var(--bd-soft)',
            background: 'rgba(126, 146, 248, 0.08)',
          }}
        >
          <div style={{ flex: 1, minWidth: 220, font: 'var(--pv-text-body-3)' }}>
            Просмотр сохранённого снимка результатов
            {shareMeta?.createdAt ? ` · создан ${formatDnsSnapshotTimestamp(shareMeta.createdAt, displayTimezone)}` : ''}
            {shareMeta?.expiresAt ? ` · доступен до ${formatDnsSnapshotTimestamp(shareMeta.expiresAt, displayTimezone)}` : ''}
          </div>
        </div>
      )}

      <div className="col" style={{ gap: 16, minWidth: 0 }}>
        <Card pad="sm">
          <div className="row" style={{ gap: 14, flexWrap: 'wrap' }}>
            {!filterPanel && (
              <Button kind="ghost" size="sm" icon="filter" onClick={openFilterPanel}>
                Фильтры
                {filters.length > 0 && <span className="nav-item__badge" style={{ marginLeft: 4 }}>{filters.length}</span>}
              </Button>
            )}
            <BuilderControl label="Метрика">
              <select
                className="input"
                style={{ width: 'auto', minWidth: 140 }}
                value={metric}
                onChange={(e) => setMetric(e.target.value)}
                title={hasDnsAnswerGrouping(groupBy) ? 'Метрики по запросам недоступны при группировке по ответу' : undefined}
              >
                {(schema?.metrics || []).map((m) => (
                  <option
                    key={m.id}
                    value={m.id}
                    disabled={isDnsQueryMetricDisabled(m.id, groupBy)}
                    title={isDnsQueryMetricDisabled(m.id, groupBy) ? 'Метрика считает запросы, а у запроса нет ответа' : undefined}
                  >
                    {m.label}
                  </option>
                ))}
              </select>
            </BuilderControl>
            <BuilderControl label="Группировка">
              <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                {groupBy.map((id) => (
                  <span key={id} className="badge badge--info" style={{ padding: '4px 10px 4px 8px', gap: 6, fontSize: 12 }}>
                    {dnsExplorerGroupLabel(id, schema)}
                    <button type="button" onClick={() => setGroupBy((g) => g.filter((x) => x !== id))} style={{ all: 'unset', cursor: 'pointer', opacity: 0.8, marginLeft: 2 }}>
                      <Icon name="x" size={10} stroke={2.5} />
                    </button>
                  </span>
                ))}
                <div ref={dimAnchorRef}>
                  <Button kind="ghost" size="xs" icon="plus" onClick={() => setAddingDim((v) => !v)}>Измерение</Button>
                  {addingDim && (
                    <DnsDimensionPicker
                      anchorRef={dimAnchorRef}
                      dimensions={groupDimensions}
                      selected={groupBy}
                      onPick={(id) => {
                        if (!groupBy.includes(id)) {
                          const nextGroupBy = [...groupBy, id];
                          setGroupBy(nextGroupBy);
                          setMetric((current) => coerceDnsMetricForGrouping(current, nextGroupBy));
                        }
                        setAddingDim(false);
                      }}
                      onClose={() => setAddingDim(false)}
                    />
                  )}
                </div>
              </div>
            </BuilderControl>
          </div>
          {hasDnsAnswerGrouping(groupBy) && (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: 10 }}>
              В ответах учитываются только записи A, AAAA и CNAME. MX, TXT, NS и другие типы коллектор не сохраняет.
            </div>
          )}
        </Card>

        {filterPanel && (
          <DnsExplorerFilters
            schema={schema}
            filters={filters}
            setFilters={setFilters}
            timeRange={timeRange}
            onTimeRangeChange={setTimeRange}
            customPeriod={customPeriod}
            onCustomPeriodChange={setCustomPeriod}
            displayTimezone={displayTimezone}
            filterMode={filterMode}
            onFilterModeChange={changeFilterMode}
            filterText={filterText}
            onFilterTextChange={setFilterText}
            filterTextError={filterTextError}
            onClearFilters={clearDnsExplorerFilters}
            onCollapse={() => setFilterPanel(false)}
            onRun={runQuery}
            suggestCtx={suggestCtx}
            dnsSources={dnsSources}
            isLoading={source === 'loading'}
          />
        )}

      {source === 'loading' ? (
        <Card pad="sm">
          <div className="explorer-refreshing-data">Получение данных</div>
        </Card>
      ) : !hasAppliedQuery ? (
        <Card pad="sm">
          <div className="other-ports-table__state">Задайте условия и нажмите «Применить».</div>
        </Card>
      ) : source === 'error' ? (
        <Card pad="sm"><div className="other-ports-table__state" style={{ color: 'var(--st-critical)' }}>{error}</div></Card>
      ) : (
        appliedGroupBy.length === 0 ? (
          <Card
            title={`Динамика · ${appliedMetricLabel}`}
            subtitle={`${timeRangeLabel(appliedSnapshot?.timeRange, appliedSnapshot?.customPeriod)} · ${meta?.dataTable || 'dns_log'}`}
            loadMs={loadMs}
            serverMs={serverMs}
          >
            <DnsExplorerTotalChart
              points={timeseries}
              metric={appliedSnapshot?.metric}
              metricLabel={appliedMetricLabel}
              schema={schema}
              displayTimezone={displayTimezone}
              chartLongRange={chartLongRange}
              bucketSeconds={chartBucketSeconds}
            />
          </Card>
        ) : (
          <Card
            className="card--explorer-results dns-explorer-results"
            title="Результаты"
            subtitle="График динамики и таблица: серии по селектору «Показать», отдельные строки — «Показать» / «Скрыть с графика»"
            loadMs={loadMs}
            serverMs={serverMs}
            pad="0"
            tools={(
              <div className="explorer-results-tools">
                <div className="explorer-results-tools__cluster">
                  <div className="explorer-results-tools__limit-block">
                    <DnsExplorerVisualLimitControl
                      total={rows.length}
                      fetchLimit={DNS_EXPLORER_DEFAULT_LIMIT}
                      value={visualLimit}
                      onChange={setVisualLimit}
                    />
                  </div>
                  <Button kind="ghost" size="sm" icon="download" onClick={exportCsv} disabled={!rows.length || exporting}>
                    CSV
                  </Button>
                </div>
              </div>
            )}
          >
            <div className="explorer-results-layout">
              <div className="explorer-results-chart">
                <DnsExplorerDynamicsChart
                  results={rows}
                  resultSeries={resultSeries}
                  metric={appliedSnapshot?.metric}
                  metricLabel={appliedMetricLabel}
                  schema={schema}
                  displayTimezone={displayTimezone}
                  chartLongRange={chartLongRange}
                  selectedSeriesIds={chartSeriesIds}
                  groupBy={appliedGroupBy}
                  bucketSeconds={chartBucketSeconds}
                />
              </div>
              <DataTable
                rows={visibleResults}
                rowKey="id"
                dense
                resizableColumns={false}
                pageSize={visiblePageSize}
                getRowClassName={(row) => (chartSeriesIds.has(row.id) ? 'is-dynamics-active' : '')}
                columns={tableColumns}
                footerNote={(
                  <span>
                    Показано {visibleResults.length} из {rows.length} загруженных · {meta?.dataTable || 'dns_log'}
                    {hasAppliedAnswerGrouping && (
                      <> · Один ответ может содержать несколько записей, поэтому сумма по строкам больше общего числа ответов</>
                    )}
                  </span>
                )}
              />
            </div>
          </Card>
        )
      )}
      </div>
    </div>
  );
}

Object.assign(window, { PageDnsExplorer });
