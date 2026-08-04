/* Shared UI primitives: Card, Button, Badge, Status, Checkbox, Mini bar,
   Modal, SidePanel, Toast stack, Empty state, DataTable. */

const { useState, useEffect, useMemo, useRef, useCallback } = React;

/* =================== Card =================== */
function WidgetLoadBadge({ loadMs, serverMs }) {
  if (loadMs == null || !DashboardLog?.isVerbose?.()) return null;
  const title = serverMs != null
    ? `загрузка ${loadMs} ms · SQL ${serverMs} ms`
    : `${loadMs} ms`;
  return (
    <span className="widget-load-badge" title={title}>
      {loadMs} ms
    </span>
  );
}

function Card({ title, subtitle, tools, children, className = '', pad = '', style, loadMs, serverMs }) {
  return (
    <div className={`card ${pad === 'sm' ? 'card--pad-sm' : pad === '0' ? 'card--pad-0' : ''} ${className}`} style={style}>
      <WidgetLoadBadge loadMs={loadMs} serverMs={serverMs} />
      {(title || tools) && (
        <div className="card__head">
          {title && (
            <div>
              <div className="card__title">{title}</div>
              {subtitle && <div className="card__sub" style={{marginTop: 2}}>{subtitle}</div>}
            </div>
          )}
          {tools && <div className="card__tools">{tools}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

/* =================== Button =================== */
function Button({ kind = 'default', size = 'md', icon, iconRight, children, onClick, disabled, type = 'button', className = '', title, style }) {
  const cls = [
    'btn',
    kind === 'primary' && 'btn--primary',
    kind === 'ghost' && 'btn--ghost',
    kind === 'danger' && 'btn--danger',
    size === 'sm' && 'btn--sm',
    size === 'xs' && 'btn--xs',
    !children && (icon || iconRight) && 'btn--icon-only',
    className,
  ].filter(Boolean).join(' ');
  return (
    <button type={type} className={cls} disabled={disabled} onClick={onClick} title={title} style={style}>
      {icon && <Icon name={icon} size={size === 'xs' ? 12 : size === 'sm' ? 14 : 16} />}
      {children}
      {iconRight && <Icon name={iconRight} size={size === 'xs' ? 12 : size === 'sm' ? 14 : 16} />}
    </button>
  );
}

/* =================== Badge / Tag =================== */
function Badge({ tone = 'neutral', dot, children, style }) {
  return (
    <span className={`badge badge--${tone}`} style={style}>
      {dot && <span className="badge__dot" />}
      {children}
    </span>
  );
}
function Tag({ children, onRemove, color }) {
  return (
    <span className="tag" style={color ? {color, background: 'transparent', border: `1px solid ${color}40`} : null}>
      {children}
      {onRemove && (
        <button onClick={onRemove} style={{all: 'unset', cursor: 'pointer', marginLeft: 4, opacity: 0.7}}>
          <Icon name="x" size={10} />
        </button>
      )}
    </span>
  );
}

/* =================== Status indicator =================== */
function StatusIndicator({ status, label }) {
  const tones = { healthy: 'ok', warning: 'warn', critical: 'err', error: 'err', idle: 'idle', offline: 'idle' };
  const cls = tones[status] || 'idle';
  const text = label || ({ healthy: 'Здоров', warning: 'Внимание', critical: 'Критично', error: 'Ошибка', idle: 'Отключён', offline: 'Не в сети' }[status] || status);
  return (
    <span className={`status status--${cls}`}>
      <span className="status__dot" />
      <span>{text}</span>
    </span>
  );
}

/* =================== Checkbox =================== */
function Checkbox({ checked, indeterminate, disabled, onChange }) {
  return (
    <span
      role="checkbox"
      aria-checked={checked}
      aria-disabled={disabled || undefined}
      className={`checkbox ${checked ? 'is-checked' : ''} ${indeterminate ? 'is-indet' : ''} ${disabled ? 'is-disabled' : ''}`}
      onClick={(e) => { e.stopPropagation(); if (!disabled && onChange) onChange(!checked); }}
    >
      {checked && !indeterminate && <Icon name="check" size={12} stroke={3} />}
      {indeterminate && <Icon name="menu" size={10} stroke={3} />}
    </span>
  );
}

/* =================== Mini bar =================== */
function MiniBar({ value, max = 100, label, warn, crit }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  const cls = crit && pct >= crit ? 'crit' : warn && pct >= warn ? 'warn' : '';
  return (
    <div style={{display: 'flex', alignItems: 'center', gap: 8, minWidth: 110}}>
      <div className={`minibar ${cls}`}><span style={{width: `${pct}%`}} /></div>
      <span className="mono" style={{font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-secondary)', minWidth: 36, textAlign: 'right'}}>
        {label || `${Math.round(pct)}%`}
      </span>
    </div>
  );
}

function useOverlayLock(open) {
  useEffect(() => {
    if (!open) return undefined;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    document.documentElement.classList.add('modal-open');
    return () => {
      document.body.style.overflow = prev;
      document.documentElement.classList.remove('modal-open');
    };
  }, [open]);
}

/* =================== Modal =================== */
function Modal({ open, onClose, title, subtitle, children, footer, size = 'md' }) {
  useOverlayLock(open);

  if (!open) return null;

  const modal = (
    <div className="modal-mask" onClick={onClose}>
      <div className={`modal ${size === 'lg' ? 'modal--lg' : ''} ${size === 'xl' ? 'modal--xl' : ''} ${size === 'map' ? 'modal--map' : ''}`} onClick={(e) => e.stopPropagation()}>
        <div className="modal__head">
          <div style={{flex: 1}}>
            <div className="modal__title">{title}</div>
            {subtitle && <div className="modal__sub">{subtitle}</div>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Закрыть"><Icon name="x" size={18} /></button>
        </div>
        <div className="modal__body">{children}</div>
        {footer && <div className="modal__foot">{footer}</div>}
      </div>
    </div>
  );

  return ReactDOM.createPortal(modal, document.body);
}

/* =================== Side panel =================== */
function SidePanel({ open, onClose, title, subtitle, children, footer }) {
  useOverlayLock(open);

  if (!open) return null;

  const panel = (
    <div className="side-panel-root">
      <div className="side-panel-mask" onClick={onClose} />
      <aside className="side-panel" onClick={(e) => e.stopPropagation()}>
        <div className="side-panel__head">
          <div style={{flex: 1}}>
            <div className="modal__title">{title}</div>
            {subtitle && <div className="modal__sub">{subtitle}</div>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Закрыть"><Icon name="x" size={18} /></button>
        </div>
        <div className="side-panel__body">{children}</div>
        {footer && <div className="side-panel__foot">{footer}</div>}
      </aside>
    </div>
  );

  return ReactDOM.createPortal(panel, document.body);
}

/* =================== Toasts =================== */
const toastListeners = new Set();
let toastSeq = 0;
function pushToast(t) {
  const id = ++toastSeq;
  const item = { id, ...t };
  toastListeners.forEach((fn) => fn({ type: 'add', item }));
  setTimeout(() => {
    toastListeners.forEach((fn) => fn({ type: 'remove', id }));
  }, t.duration || 4000);
}
function ToastStack() {
  const [items, setItems] = useState([]);
  useEffect(() => {
    const fn = (ev) => {
      if (ev.type === 'add') setItems((s) => [...s, ev.item]);
      else if (ev.type === 'remove') setItems((s) => s.filter((i) => i.id !== ev.id));
    };
    toastListeners.add(fn);
    return () => toastListeners.delete(fn);
  }, []);
  const iconFor = (k) => ({ success: 'check', error: 'alert', info: 'info' }[k] || 'info');
  return (
    <div className="toast-stack">
      {items.map((t) => (
        <div key={t.id} className={`toast toast--${t.kind || 'info'}`}>
          <div className="toast__icon"><Icon name={iconFor(t.kind)} size={16} stroke={2.4} /></div>
          <div className="toast__body">
            <div className="toast__title">{t.title}</div>
            {t.desc && <div className="toast__desc">{t.desc}</div>}
          </div>
          <button className="icon-btn" style={{width: 28, height: 28}} onClick={() => setItems((s) => s.filter((i) => i.id !== t.id))}>
            <Icon name="x" size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

/* =================== Empty state =================== */
function Empty({ icon = 'info', title, desc, action }) {
  return (
    <div className="empty">
      <div className="empty__icon"><Icon name={icon} size={24} /></div>
      <div style={{font: 'var(--pv-text-h4)', color: 'var(--fg-primary)'}}>{title}</div>
      {desc && <div style={{maxWidth: 360}}>{desc}</div>}
      {action && <div style={{marginTop: 8}}>{action}</div>}
    </div>
  );
}

/* =================== OverflowText =================== */
function splitTextMiddle(text) {
  const s = String(text ?? '');
  if (s.length <= 12) return { start: s, end: '' };
  const mid = Math.ceil(s.length / 2);
  return { start: s.slice(0, mid), end: s.slice(mid) };
}

const OverflowText = React.forwardRef(function OverflowText({
  value,
  mode = 'end',
  className = '',
  title,
  expanded = false,
}, ref) {
  const text = value == null || value === '' ? '—' : String(value);
  const localRef = useRef(null);
  const setRef = useCallback((node) => {
    localRef.current = node;
    if (typeof ref === 'function') ref(node);
    else if (ref) ref.current = node;
  }, [ref]);
  const [overflows, setOverflows] = useState(false);

  const measureOverflow = useCallback(() => {
    const el = localRef.current;
    if (!el) return;
    if (mode === 'expand-open') {
      setOverflows(true);
      return;
    }
    const target = el.querySelector?.('.overflow-text__value') || el;
    setOverflows(target.scrollWidth > target.clientWidth + 1);
  }, [mode]);

  useEffect(() => {
    measureOverflow();
    const el = localRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return undefined;
    const ro = new ResizeObserver(measureOverflow);
    ro.observe(el);
    return () => ro.disconnect();
  }, [measureOverflow, text, mode, expanded]);

  const tooltip = title ?? (overflows && mode !== 'expand-open' ? text : undefined);
  const rootClass = [
    'overflow-text',
    `overflow-text--${mode}`,
    expanded && mode === 'expand-open' ? 'is-expanded' : '',
    className,
  ].filter(Boolean).join(' ');

  if (mode === 'middle') {
    const { start, end } = splitTextMiddle(text);
    return (
      <span ref={setRef} className={rootClass} title={tooltip}>
        <span className="overflow-text__start">{start}</span>
        {end ? <span className="overflow-text__end">{end}</span> : null}
      </span>
    );
  }

  if (mode === 'expand-open') {
    return (
      <span ref={setRef} className={rootClass} title={tooltip}>
        <span className="overflow-text__value overflow-text__value--wrap">{text}</span>
      </span>
    );
  }

  return (
    <span ref={setRef} className={rootClass} title={tooltip}>
      <span className="overflow-text__value overflow-text__value--clip">{text}</span>
    </span>
  );
});

/* =================== DataTable =================== */
function DataTable({
  rows,
  columns,           // [{ key, title, render?, sortable?, align?, width?, num? }]
  resizableColumns = true,
  selectable,
  selected,
  onSelectChange,
  rowKey = 'id',
  emptyTitle = 'Нет данных',
  emptyDesc,
  initialSort,
  toolbar,           // { left, right, search, onSearch }
  rowActions,        // fn(row) => element rendered in actions column
  onRowClick,
  getRowClassName,
  pageSize = 10,
  dense,
  footerNote,
  fitColumnWidths,
  pinnedRows,        // rows rendered after the page, outside sorting and paging
}) {
  const [sort, setSort] = useState(initialSort || null);
  const [page, setPage] = useState(1);
  const [colVis, setColVis] = useState(() => Object.fromEntries(columns.map(c => [c.key, true])));
  const [colMenu, setColMenu] = useState(false);
  const [colWidths, setColWidths] = useState(() => Object.fromEntries(
    columns.map((c) => [c.key, Number(c.width) || 160]),
  ));
  const resizeRef = useRef(null);
  const colKeysSig = columns.map((c) => c.key).join('\0');
  const rowFitSig = useMemo(() => {
    const all = [...(rows || []), ...(pinnedRows || [])];
    if (!all.length) return '0';
    return `${all.length}\0${all.map((r) => r[rowKey]).join('\0')}`;
  }, [rows, pinnedRows, rowKey]);

  useEffect(() => {
    setColVis((prev) => Object.fromEntries(
      columns.map((c) => [c.key, prev[c.key] !== undefined ? prev[c.key] : true]),
    ));
    setColWidths((prev) => Object.fromEntries(
      columns.map((c) => [c.key, prev[c.key] ?? (Number(c.width) || 160)]),
    ));
  }, [colKeysSig]);

  useEffect(() => {
    if (typeof fitColumnWidths !== 'function') return undefined;
    const fitted = fitColumnWidths(columns, rows, pinnedRows);
    if (!fitted) return undefined;
    setColWidths((prev) => {
      const next = { ...prev };
      columns.forEach((c) => {
        if (fitted[c.key] != null) next[c.key] = fitted[c.key];
      });
      return next;
    });
    return undefined;
  }, [colKeysSig, rowFitSig, fitColumnWidths, columns, rows, pinnedRows]);

  useEffect(() => () => {
    const drag = resizeRef.current;
    if (!drag) return;
    window.removeEventListener('mousemove', drag.onMove);
    window.removeEventListener('mouseup', drag.onUp);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }, []);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const dir = sort.dir === 'asc' ? 1 : -1;
    const col = columns.find((c) => c.key === sort.key);
    const accessor = col?.sortAccessor || ((r) => r[sort.key]);
    return [...rows].sort((a, b) => {
      const va = accessor(a), vb = accessor(b);
      if (va == null) return 1; if (vb == null) return -1;
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
      return String(va).localeCompare(String(vb), 'ru') * dir;
    });
  }, [rows, sort, columns]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const pageRows = useMemo(() => sorted.slice((page - 1) * pageSize, page * pageSize), [sorted, page, pageSize]);

  useEffect(() => { if (page > totalPages) setPage(totalPages); }, [totalPages]);

  const toggleSort = (key) => {
    setSort((s) => !s || s.key !== key ? { key, dir: 'asc' } : s.dir === 'asc' ? { key, dir: 'desc' } : null);
  };

  const allSelected = selectable && selected && pageRows.length > 0 && pageRows.every((r) => selected.has(r[rowKey]));
  const someSelected = selectable && selected && pageRows.some((r) => selected.has(r[rowKey]));
  const toggleAll = () => {
    if (!onSelectChange) return;
    const next = new Set(selected || []);
    if (allSelected) pageRows.forEach((r) => next.delete(r[rowKey]));
    else pageRows.forEach((r) => next.add(r[rowKey]));
    onSelectChange(next);
  };

  const visibleCols = columns.filter((c) => colVis[c.key]);
  const columnWidth = (c) => colWidths[c.key] ?? (Number(c.width) || 160);
  const resetColumnWidth = (e, c) => {
    e.preventDefault();
    e.stopPropagation();
    setColWidths((prev) => ({ ...prev, [c.key]: Number(c.width) || 160 }));
  };
  const startColumnResize = (e, c) => {
    if (!resizableColumns || c.resizable === false || e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startWidth = columnWidth(c);
    const minWidth = Number(c.minWidth) || 72;
    const maxWidth = Number(c.maxWidth) || 800;
    const onMove = (ev) => {
      const next = Math.max(minWidth, Math.min(maxWidth, startWidth + ev.clientX - startX));
      setColWidths((prev) => ({ ...prev, [c.key]: Math.round(next) }));
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      resizeRef.current = null;
    };
    resizeRef.current = { onMove, onUp };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };
  const resizableTableWidth = resizableColumns
    ? visibleCols.reduce((sum, c) => sum + columnWidth(c), selectable ? 36 : 0)
      + (rowActions ? 120 : 0)
    : null;

  return (
    <div>
      {toolbar && (
        <div className="table-toolbar">
          {toolbar.left}
          {toolbar.search !== undefined && (
            <div className="input-wrap" style={{maxWidth: 280, flex: 1}}>
              <Icon name="search" size={14} />
              <input className="input input--with-icon" placeholder="Поиск..." value={toolbar.search} onChange={(e) => toolbar.onSearch && toolbar.onSearch(e.target.value)} />
            </div>
          )}
          <div style={{marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, position: 'relative'}}>
            {toolbar.right}
            <button className="icon-btn" title="Столбцы" onClick={() => setColMenu((v) => !v)}>
              <Icon name="sliders" size={16} />
            </button>
            {colMenu && (
              <div style={{
                position: 'absolute', top: '110%', right: 0, zIndex: 30,
                background: 'var(--bg-surface-2)', border: '1px solid var(--bd-default)', borderRadius: 10,
                padding: 6, minWidth: 200, boxShadow: 'var(--pv-shadow-popover)',
              }} onMouseLeave={() => setColMenu(false)}>
                <div style={{font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '8px 10px'}}>Столбцы</div>
                {columns.map((c) => (
                  <label key={c.key} style={{display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', cursor: 'pointer'}}>
                    <Checkbox checked={!!colVis[c.key]} onChange={(v) => setColVis((s) => ({...s, [c.key]: v}))} />
                    <span style={{font: 'var(--pv-text-body-2)'}}>{c.title}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
      <div className="table-wrap">
        <table
          className={`table${resizableColumns ? ' table--resizable' : ''}`}
          style={resizableColumns ? { width: `${resizableTableWidth}px`, minWidth: '100%' } : undefined}
        >
          {resizableColumns && (
            <colgroup>
              {selectable && <col style={{ width: 36 }} />}
              {visibleCols.map((c) => <col key={c.key} style={{ width: columnWidth(c) }} />)}
              {rowActions && <col style={{ width: 120 }} />}
            </colgroup>
          )}
          <thead>
            <tr>
              {selectable && (
                <th style={{width: 36}}><Checkbox checked={allSelected} indeterminate={!allSelected && someSelected} onChange={toggleAll} /></th>
              )}
              {visibleCols.map((c) => {
                const isSorted = sort?.key === c.key;
                return (
                  <th
                    key={c.key}
                    style={{width: resizableColumns ? columnWidth(c) : c.width, textAlign: c.align || 'left'}}
                    className={[isSorted ? 'is-sorted' : '', c.headerClassName].filter(Boolean).join(' ') || undefined}
                    onClick={c.sortable !== false ? () => toggleSort(c.key) : null}
                    data-sort={c.sortable === false ? 'none' : 'yes'}
                    data-col-key={c.key}
                  >
                    <span style={{display: 'inline-flex', alignItems: 'center', gap: 4, cursor: c.sortable === false ? 'default' : 'pointer'}}>
                      {c.title}
                      {c.sortable !== false && (
                        <span className="sort">
                          {isSorted
                            ? <Icon name={sort.dir === 'asc' ? 'sortAsc' : 'sortDesc'} size={11} fill="currentColor" stroke={0} />
                            : <Icon name="caret" size={10} />}
                        </span>
                      )}
                    </span>
                    {resizableColumns && c.resizable !== false && (
                      <span
                        className="col-resize"
                        role="separator"
                        aria-orientation="vertical"
                        aria-label={`Изменить ширину столбца «${c.title}»`}
                        title="Перетащите для изменения ширины · двойной клик — сброс"
                        onMouseDown={(e) => startColumnResize(e, c)}
                        onClick={(e) => e.stopPropagation()}
                        onDoubleClick={(e) => resetColumnWidth(e, c)}
                      />
                    )}
                  </th>
                );
              })}
              {rowActions && <th className="actions" style={{textAlign: 'right'}}>Действия</th>}
            </tr>
          </thead>
          <tbody>
            {pageRows.length === 0 ? (
              <tr><td colSpan={visibleCols.length + (selectable ? 1 : 0) + (rowActions ? 1 : 0)}>
                <Empty title={emptyTitle} desc={emptyDesc} />
              </td></tr>
            ) : pageRows.map((row) => {
              const isSel = selectable && selected?.has(row[rowKey]);
              return (
                <tr
                  key={row[rowKey]}
                  className={[isSel ? 'is-selected' : '', getRowClassName?.(row)].filter(Boolean).join(' ')}
                  onClick={onRowClick ? () => onRowClick(row) : null}
                  style={onRowClick ? {cursor: 'pointer'} : null}
                >
                  {selectable && (
                    <td onClick={(e) => e.stopPropagation()}>
                      <Checkbox checked={isSel} onChange={() => {
                        const next = new Set(selected || []);
                        if (isSel) next.delete(row[rowKey]); else next.add(row[rowKey]);
                        onSelectChange && onSelectChange(next);
                      }} />
                    </td>
                  )}
                  {visibleCols.map((c) => (
                    <td
                      key={c.key}
                      className={[c.num ? 'num' : '', c.cellClassName].filter(Boolean).join(' ') || undefined}
                      style={{textAlign: c.align || 'left'}}
                    >
                      {c.render ? c.render(row) : row[c.key]}
                    </td>
                  ))}
                  {rowActions && <td className="actions" onClick={(e) => e.stopPropagation()}>{rowActions(row)}</td>}
                </tr>
              );
            })}
            {(pinnedRows || []).map((row) => (
              <tr key={`pinned-${row[rowKey]}`} className={['is-pinned', getRowClassName?.(row)].filter(Boolean).join(' ')}>
                {selectable && <td />}
                {visibleCols.map((c) => (
                  <td
                    key={c.key}
                    className={[c.num ? 'num' : '', c.cellClassName].filter(Boolean).join(' ') || undefined}
                    style={{ textAlign: c.align || 'left' }}
                  >
                    {c.render ? c.render(row) : row[c.key]}
                  </td>
                ))}
                {rowActions && <td className="actions" />}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="table-foot">
        <div className="table-foot__row">
          <div>
            {selectable && selected?.size > 0
              ? <span>Выбрано: <b style={{color: 'var(--fg-primary)'}}>{selected.size}</b> из {sorted.length}</span>
              : <span>{sorted.length} {pluralRu(sorted.length, 'запись', 'записи', 'записей')}</span>
            }
          </div>
          <Pagination page={page} totalPages={totalPages} onChange={setPage} />
        </div>
        {footerNote && <div className="table-foot__row table-foot__meta">{footerNote}</div>}
      </div>
    </div>
  );
}

function pluralRu(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
  return many;
}

function Pagination({ page, totalPages, onChange }) {
  const pages = [];
  for (let i = 1; i <= totalPages; i++) pages.push(i);
  const window = pages.filter((p) => p === 1 || p === totalPages || Math.abs(p - page) <= 1);
  return (
    <div style={{display: 'flex', alignItems: 'center', gap: 6}}>
      <Button kind="ghost" size="sm" icon="chevL" disabled={page === 1} onClick={() => onChange(page - 1)} />
      {window.map((p, i) => {
        const prev = window[i - 1];
        const gap = prev && p - prev > 1;
        return (
          <React.Fragment key={p}>
            {gap && <span style={{color: 'var(--fg-muted)', padding: '0 2px'}}>…</span>}
            <button
              className="btn btn--sm"
              onClick={() => onChange(p)}
              style={p === page
                ? {background: 'var(--grad-primary)', borderColor: 'transparent', color: '#fff', minWidth: 30}
                : {minWidth: 30}}>{p}</button>
          </React.Fragment>
        );
      })}
      <Button kind="ghost" size="sm" icon="chevR" disabled={page === totalPages} onClick={() => onChange(page + 1)} />
    </div>
  );
}

async function copyTextToClipboard(text) {
  const value = String(text ?? '');
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const ta = document.createElement('textarea');
  ta.value = value;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  try {
    const ok = document.execCommand('copy');
    if (!ok) throw new Error('Копирование не поддерживается в этом браузере');
  } finally {
    document.body.removeChild(ta);
  }
}

Object.assign(window, {
  Card, Button, Badge, Tag, StatusIndicator, Checkbox, MiniBar, Modal, SidePanel,
  ToastStack, pushToast, Empty, OverflowText, splitTextMiddle, DataTable, Pagination, pluralRu, WidgetLoadBadge,
  copyTextToClipboard,
});
