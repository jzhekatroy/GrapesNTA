/* Application shell: Sidebar (collapsible, accordion) + Header. */

const { useState, useEffect, useLayoutEffect, useRef, useMemo } = React;

const NAV = [
  {
    id: 'overview',
    section: 'Главное',
    items: [
      { id: 'dashboard', label: 'Обзор', icon: 'dashboard' },
      { id: 'observations', label: 'Наблюдения', icon: 'query' },
      { id: 'dns', label: 'DNS', icon: 'globe' },
    ],
  },
  {
    id: 'traffic',
    section: 'Анализ трафика',
    items: [
      { id: 'explorer', label: 'Разбор трафика', icon: 'explorer' },
      { id: 'dns-explorer', label: 'Разбор DNS', icon: 'search' },
      { id: 'top', label: 'Топ ASN', icon: 'top' },
    ],
  },
  {
    id: 'settings',
    section: 'Настройка',
    icon: 'sliders',
    groups: [
      {
        id: 'data',
        section: 'Сбор данных',
        icon: 'collectors',
        items: [
          { id: 'collectors', label: 'Коллекторы', icon: 'collectors' },
          { id: 'snmp', label: 'SNMP', icon: 'network' },
          { id: 'bmp', label: 'BMP / BGP', icon: 'router' },
        ],
      },
      {
        id: 'netmodel',
        section: 'Модель сети',
        icon: 'refs',
        items: [
          { id: 'traffic-classification', label: 'Классификация трафика', icon: 'filter' },
          { id: 'cidr', label: 'Моя сеть', icon: 'cidr' },
          { id: 'dns-resolvers', label: 'DNS-резолверы', icon: 'db' },
          { id: 'interface-roles', label: 'Порты оборудования', icon: 'link' },
          { id: 'port-services', label: 'Сервисы и порты приложений', icon: 'flow' },
        ],
      },
      {
        id: 'admin',
        section: 'Администрирование',
        items: [
          { id: 'users', label: 'Пользователи и права', icon: 'shield' },
          { id: 'audit', label: 'Журнал аудита', icon: 'clock' },
          { id: 'clients', label: 'Клиенты', icon: 'users' },
          { id: 'smtp', label: 'Почта (SMTP)', icon: 'export' },
          { id: 'ttl', label: 'Сроки хранения', icon: 'clock' },
        ],
      },
    ],
  },
];

const CABINET_NAV = [
  {
    id: 'cabinet',
    section: 'Кабинет',
    items: [
      { id: 'dashboard', label: 'Обзор', icon: 'dashboard' },
      { id: 'explorer', label: 'Разбор трафика', icon: 'explorer' },
      { id: 'dns', label: 'DNS', icon: 'globe' },
    ],
  },
];

const CABINET_PAGE_IDS = new Set(['dashboard', 'explorer', 'dns']);

function isCabinetMode(user) {
  const mode = user?.cabinet?.mode;
  return mode === 'client' || mode === 'impersonation';
}

function isImpersonating(user) {
  return user?.cabinet?.mode === 'impersonation';
}

const PAGES_WITHOUT_HEADER_FILTERS = new Set([
  'explorer',
  'dns-explorer',
  'observations',
  'diagnostics',
  'users',
  'audit',
  'clients',
  'collectors',
  'snmp',
  'bmp',
  'entities',
  'cidr',
  'dns-resolvers',
  'interface-roles',
  'traffic-classification',
  'port-services',
  'flow-exclusions',
  'vlan',
  'smtp',
  'ttl',
]);

function hasNavPermission(effectivePermissions, pageId) {
  if (!effectivePermissions) return true;
  if (pageId === 'snmp') return !!(effectivePermissions.snmp || effectivePermissions.collectors);
  // SMTP API и доступ завязаны на diagnostics (только администратор).
  if (pageId === 'smtp') return !!effectivePermissions.diagnostics;
  // «Моя сеть» — общая оболочка для cidr / entities / vlan.
  if (pageId === 'cidr') {
    return !!(effectivePermissions.cidr || effectivePermissions.entities || effectivePermissions.vlan);
  }
  return !!effectivePermissions[pageId];
}

const DEFAULT_OPEN_SECTIONS = new Set(['overview', 'traffic']);

function getSectionItems(sec) {
  if (sec.items) return sec.items;
  if (sec.groups) return sec.groups.flatMap((g) => g.items || []);
  return [];
}

function filterNav(nav, effectivePermissions) {
  if (!effectivePermissions) return nav;
  return nav.map((sec) => {
    if (sec.groups) {
      const groups = sec.groups.map((grp) => {
        const items = grp.items.filter((it) => hasNavPermission(effectivePermissions, it.id));
        if (!items.length) return null;
        return { ...grp, items };
      }).filter(Boolean);
      if (!groups.length) return null;
      return { ...sec, groups };
    }
    const items = sec.items.filter((it) => hasNavPermission(effectivePermissions, it.id));
    if (!items.length) return null;
    return { ...sec, items };
  }).filter(Boolean);
}

/* =============== Sidebar =============== */
function Sidebar({ current, onNavigate, collapsed, effectivePermissions, cabinetMode, clientDisplayName }) {
  const visibleNav = useMemo(
    () => (cabinetMode ? CABINET_NAV : filterNav(NAV, effectivePermissions)),
    [cabinetMode, effectivePermissions],
  );
  const [openSections, setOpenSections] = useState(() => {
    const o = {};
    visibleNav.forEach((sec) => {
      // В кабинете одна секция — держим открытой. В админке по умолчанию
      // только «Главное» и «Анализ трафика».
      o[sec.id] = cabinetMode || DEFAULT_OPEN_SECTIONS.has(sec.id);
    });
    return o;
  });
  useEffect(() => {
    visibleNav.forEach((sec) => {
      if (sec.groups) {
        sec.groups.forEach((grp) => {
          if (grp.items.some((it) => it.id === current)) {
            setOpenSections((s) => ({ ...s, [sec.id]: true, [grp.id]: true }));
          }
        });
      } else if (sec.items.some((it) => it.id === current)) {
        setOpenSections((s) => ({ ...s, [sec.id]: true }));
      }
    });
  }, [current, visibleNav]);

  const toggleSection = (sid) => setOpenSections((s) => ({ ...s, [sid]: !s[sid] }));

  return (
    <aside className="sidebar">
      <div className="sidebar__brand" onClick={() => onNavigate('dashboard')} style={{cursor: 'pointer'}} title={cabinetMode ? clientDisplayName : undefined}>
        <div className="sidebar__logo">
          <GrapesGlyph size={18} />
        </div>
        <div className="sidebar__wordmark">
          <span className="sidebar__wordmark-name">{cabinetMode ? (clientDisplayName || 'кабинет') : 'grapes'}</span>
          {!cabinetMode && <span className="sidebar__wordmark-dot">.</span>}
          <small>{cabinetMode ? 'кабинет' : 'NTA'}</small>
        </div>
      </div>
      <nav className="sidebar__nav">
        {visibleNav.map((sec) => (
          <NavSection
            key={sec.id}
            sec={sec}
            open={openSections[sec.id] ?? false}
            onToggle={() => toggleSection(sec.id)}
            openSections={openSections}
            onToggleSection={toggleSection}
            current={current}
            onNavigate={onNavigate}
            collapsed={collapsed}
          />
        ))}
      </nav>
      <button
        type="button"
        className={`sidebar__footer${collapsed ? ' sidebar__footer--collapsed' : ''}`}
        onClick={() => onNavigate('__toggle')}
        aria-label={collapsed ? 'Развернуть меню' : 'Свернуть меню'}
      >
        <Icon name="chevL" size={16} />
        <span className="sidebar__footer-label">
          {collapsed ? 'Развернуть меню' : 'Свернуть меню'}
        </span>
      </button>
    </aside>
  );
}

function NavItem({ item, active, onNavigate, collapsed }) {
  const content = (
    <>
      <Icon name={item.icon} size={18} className="nav-item__icon" />
      <span className="nav-item__label">{item.label}</span>
      {item.badge && <span className="nav-item__badge">{item.badge}</span>}
      {item.soon && <span className="tag" style={{ fontSize: 10, padding: '1px 6px' }}>скоро</span>}
    </>
  );

  if (item.soon) {
    return (
      <div className="nav-item" title={collapsed ? item.label : undefined}>
        {content}
      </div>
    );
  }

  // <a href="#…"> даёт «Открыть в новой вкладке» и клик колёсиком.
  // Обычный левый клик без модификаторов оставляем на SPA-navigate.
  const handleClick = (e) => {
    if (e.defaultPrevented) return;
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    onNavigate(item.id);
  };

  return (
    <a
      href={`#${item.id}`}
      className={`nav-item ${active ? 'nav-item--active' : ''}`}
      onClick={handleClick}
      onMouseEnter={() => PageChunks?.preload?.(item.id)}
      title={collapsed ? item.label : undefined}
      aria-current={active ? 'page' : undefined}
    >
      {content}
    </a>
  );
}

function NavSection({
  sec,
  open,
  onToggle,
  openSections,
  onToggleSection,
  current,
  onNavigate,
  collapsed,
  nested = false,
}) {
  const items = getSectionItems(sec);
  const hasActive = items.some((it) => it.id === current);

  if (collapsed) {
    return (
      <>
        {items.map((it) => (
          <NavItem
            key={it.id}
            item={it}
            active={current === it.id}
            onNavigate={onNavigate}
            collapsed={collapsed}
          />
        ))}
      </>
    );
  }

  if (sec.groups) {
    return (
      <div className={`nav-section nav-section--parent ${open ? 'nav-section--open' : ''}`}>
        <div
          className={`nav-section__head ${hasActive && !open ? 'nav-section__head--active' : ''}`}
          onClick={onToggle}
        >
          {sec.icon && <Icon name={sec.icon} size={16} className="nav-section__icon" />}
          <span className="nav-section__label">{sec.section}</span>
          <Icon name="chevR" size={14} className="nav-section__chev" />
        </div>
        <div className="nav-section__body">
          <div className="nav-section__body-inner">
            {sec.groups.map((grp) => (
              <NavSection
                key={grp.id}
                sec={grp}
                open={openSections[grp.id] ?? false}
                onToggle={() => onToggleSection(grp.id)}
                openSections={openSections}
                onToggleSection={onToggleSection}
                current={current}
                onNavigate={onNavigate}
                collapsed={false}
                nested
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`nav-section${nested ? ' nav-section--nested' : ''} ${open ? 'nav-section--open' : ''}`}>
      <div
        className={`nav-section__head ${hasActive && !open ? 'nav-section__head--active' : ''}`}
        onClick={onToggle}
      >
        {sec.icon && <Icon name={sec.icon} size={16} className="nav-section__icon" />}
        <span className="nav-section__label">{sec.section}</span>
        <Icon name="chevR" size={14} className="nav-section__chev" />
      </div>
      <div className="nav-section__body">
        <div className="nav-section__body-inner">
          {sec.items.map((it) => (
            <NavItem
              key={it.id}
              item={it}
              active={current === it.id}
              onNavigate={onNavigate}
              collapsed={collapsed}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

/* =============== Header =============== */
function formatUserDateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
}

function UserAccountMenu({ currentUser, pageTitles, hiddenPageIds }) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);
  const rootRef = useRef(null);
  const menuRef = useRef(null);
  const titles = pageTitles || PAGE_TITLES || {};
  const displayName = currentUser?.fullName || currentUser?.username || 'Пользователь';
  const displayRole = currentUser?.role?.displayName || currentUser?.roleId || 'Пользователь';
  const initials = displayName.trim().slice(0, 1).toUpperCase() || 'U';

  const allowedPages = useMemo(() => {
    const perms = currentUser?.effectivePermissions;
    const hidden = hiddenPageIds || new Set();
    if (!perms) return [];
    return Object.entries(perms)
      .filter(([id, allowed]) => allowed && !hidden.has(id))
      .map(([id]) => ({
        id,
        title: titles[id]?.title || id,
        section: titles[id]?.section || '',
      }))
      .sort((a, b) => (
        a.section.localeCompare(b.section, 'ru')
        || a.title.localeCompare(b.title, 'ru')
      ));
  }, [currentUser, pageTitles, hiddenPageIds]);

  useLayoutEffect(() => {
    if (!open) {
      setMenuStyle(null);
      return undefined;
    }
    const anchor = rootRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const width = Math.min(320, window.innerWidth - 16);
      setMenuStyle({
        ...computeFixedDropdownStyle(anchor, { minWidth: width, align: 'right' }),
        width,
        minWidth: width,
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (rootRef.current?.contains(e.target) || menuRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const dropdownBody = (
    <>
      <div className="user-menu__header">
        <span className="user-menu__name">{displayName}</span>
        <span className="user-menu__username">{currentUser?.username}</span>
      </div>
      <div className="time-filter__divider" />
      <div className="time-filter__heading">Разрешённые разделы</div>
      <div className="user-menu__pages">
        {allowedPages.length ? allowedPages.map((page) => (
          <div key={page.id} className="user-menu__page">
            <span className="user-menu__page-title">{page.title}</span>
            <span className="user-menu__page-section">{page.section}</span>
          </div>
        )) : (
          <div className="user-menu__empty">Нет доступных разделов</div>
        )}
      </div>
      <div className="time-filter__divider" />
      <div className="user-menu__meta-row">
        <span className="user-menu__meta-label">Последняя смена пароля</span>
        <span className="user-menu__meta-value">{formatUserDateTime(currentUser?.updatedAt)}</span>
      </div>
    </>
  );

  return (
    <div className="user-menu" ref={rootRef}>
      <button
        type="button"
        className="user-chip"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        title={currentUser?.username || 'Профиль'}
      >
        <span className="user-chip__avatar user-chip__avatar--text">{initials}</span>
        <div className="user-chip__meta">
          <span className="user-chip__name">{displayName}</span>
          <span className="user-chip__role">{displayRole}</span>
        </div>
        <Icon name="chevD" size={14} className="user-chip__chev" />
      </button>
      {open && menuStyle && ReactDOM.createPortal(
        <div
          ref={menuRef}
          className="user-menu__dropdown user-menu__dropdown--portal"
          style={menuStyle}
          role="dialog"
          aria-label="Профиль пользователя"
        >
          {dropdownBody}
        </div>,
        document.body,
      )}
    </div>
  );
}

function Header({ current, onNavigate, onToggleSidebar, currentUser, onLogout, onRefresh, theme, onToggleTheme, timeRange, onTimeRangeChange, customPeriod, onCustomPeriodChange, chartZoomDepth, onChartZoomReset, directions, onDirectionsChange, collectorFilter, onCollectorFilterChange, pageTitles, hiddenPageIds, displayTimezone, timezonePref, onTimezonePrefChange, cabinetMode, clientDisplayName, onStopImpersonation }) {
  const titles = pageTitles || PAGE_TITLES || {};
  const meta = titles[current] || titles.dashboard || { title: current, section: '' };
  const hidePageFilters = cabinetMode
    ? current === 'explorer'
    : PAGES_WITHOUT_HEADER_FILTERS.has(current);
  const hideDirectionFilter = current === 'dns' || cabinetMode;
  const hideCollectorFilter = cabinetMode;
  const sectionLabel = cabinetMode ? (clientDisplayName || 'Кабинет клиента') : meta.section;
  return (
    <header className="header">
      <button className="icon-btn" onClick={onToggleSidebar} title="Меню">
        <Icon name="menu" size={20} />
      </button>
      <div className="header__breadcrumb">
        <span className="crumb-section" title={sectionLabel}>{sectionLabel}</span>
        <span className="crumb-sep">/</span>
        <span className="crumb-cur">{meta.title}</span>
      </div>
      <div className="header__actions">
        <div className="header-filters">
          {!hidePageFilters && (
            <>
              {!hideDirectionFilter && (
                <DirectionFilter
                  directions={directions}
                  onDirectionsChange={onDirectionsChange}
                />
              )}
              {!hideCollectorFilter && (
                <CollectorFilter
                  collectorFilter={collectorFilter}
                  onCollectorFilterChange={onCollectorFilterChange}
                />
              )}
              <TimeFilter
                timeRange={timeRange}
                onTimeRangeChange={onTimeRangeChange}
                customPeriod={customPeriod}
                onCustomPeriodChange={onCustomPeriodChange}
                maxRangeDays={cabinetMode && current === 'dashboard' ? 730 : null}
              />
            </>
          )}
          {chartZoomDepth > 0 && (
            <button
              type="button"
              className="time-pill time-pill--reset"
              title="Вернуть предыдущий период"
              onClick={onChartZoomReset}
            >
              <Icon name="zoom" size={14} />
              <span>Сброс zoom</span>
            </button>
          )}
        </div>
        <span className="hr-v" />
        <TimezoneSelector
          displayTimezone={displayTimezone}
          timezonePref={timezonePref}
          onTimezonePrefChange={onTimezonePrefChange}
        />
        <PortalTooltip label="Обновить">
          <button className="icon-btn" title="Обновить" onClick={onRefresh}>
            <Icon name="refresh" size={18} />
          </button>
        </PortalTooltip>
        <PortalTooltip label={theme === 'dark' ? 'Светлая тема' : 'Тёмная тема'}>
          <button
            className="icon-btn"
            title={theme === 'dark' ? 'Светлая тема' : 'Тёмная тема'}
            onClick={onToggleTheme}
          >
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={18} />
          </button>
        </PortalTooltip>
        <span className="hr-v" />
        <UserAccountMenu currentUser={currentUser} pageTitles={pageTitles} hiddenPageIds={hiddenPageIds} />
        {isImpersonating(currentUser) && onStopImpersonation && (
          <Button kind="ghost" size="sm" onClick={onStopImpersonation}>Выйти из кабинета</Button>
        )}
        <PortalTooltip label="Выйти">
          <button className="icon-btn" title="Выйти" onClick={onLogout}>
            <Icon name="logOut" size={18} />
          </button>
        </PortalTooltip>
      </div>
    </header>
  );
}

const TIME_RANGE_OPTIONS = [
  { id: '30m', label: '30 минут' },
  { id: '1h', label: '1 час' },
  { id: '3h', label: '3 часа' },
  { id: '6h', label: '6 часов' },
  { id: '12h', label: '12 часов' },
  { id: '24h', label: '24 часа' },
  { id: '2d', label: '2 дня' },
  { id: '7d', label: '7 дней' },
  { id: '14d', label: '14 дней' },
  { id: '30d', label: '30 дней' },
  { id: 'custom', label: 'Свой период' },
];

const TRAFFIC_DIRECTIONS = [
  { id: 'total', label: 'Всего', color: '#7E92F8' },
  { id: 'incoming', label: 'Входящий', color: '#51D16D' },
  { id: 'outgoing', label: 'Исходящий', color: '#6972F0' },
  { id: 'transit', label: 'Транзит', color: '#F0B400' },
  { id: 'internal', label: 'Внутренний', color: '#A4ADFF' },
  { id: 'unclassified', label: 'Неразмеченный', color: '#7F7F9D' },
];

function defaultDirectionsEnabled() {
  return Object.fromEntries(TRAFFIC_DIRECTIONS.map((d) => [d.id, true]));
}

function toDatetimeLocalValue(date) {
  const ms = date instanceof Date ? date.getTime() : new Date(date).getTime();
  return msToDatetimeLocalValue(ms, getDisplayTimezone());
}

function defaultCustomPeriod() {
  const toMs = Date.now();
  const fromMs = toMs - 60 * 60 * 1000;
  return {
    from: msToDatetimeLocalValue(fromMs, getDisplayTimezone()),
    to: msToDatetimeLocalValue(toMs, getDisplayTimezone()),
  };
}

function formatCustomPeriodLabel({ from, to }) {
  const fromParts = String(from || '').match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  const toParts = String(to || '').match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (!fromParts || !toParts) return 'Свой период';
  const [, fy, fmo, fd, fh, fmi] = fromParts;
  const [, , , td, th, tmi] = toParts;
  if (`${fy}-${fmo}-${fd}` === `${toParts[1]}-${toParts[2]}-${td}`) {
    return `${fd}.${fmo} ${fh}:${fmi}–${th}:${tmi}`;
  }
  return `${fd}.${fmo} ${fh}:${fmi} — ${td}.${toParts[2]} ${th}:${tmi}`;
}

function validateCustomPeriod({ from, to }) {
  if (!from || !to) return 'Укажите начало и конец периода';
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(to)) {
    return 'Некорректная дата';
  }
  if (from >= to) return 'Начало должно быть раньше конца';
  return null;
}

const EXPLORER_MAX_RANGE_DAYS = 365;

function explorerRangeLimitDays(maxRangeDays) {
  const days = Number(maxRangeDays);
  return Number.isFinite(days) && days > 0 ? days : EXPLORER_MAX_RANGE_DAYS;
}

function timeRangePresetMs(rangeId) {
  const match = /^(\d+)([mhd])$/.exec(String(rangeId || ''));
  if (!match) return null;
  const unitMs = match[2] === 'm' ? 60000 : match[2] === 'h' ? 3600000 : 86400000;
  return Number(match[1]) * unitMs;
}

function validateExplorerCustomPeriod({ from, to }, timeRange = '1h', maxRangeDays = EXPLORER_MAX_RANGE_DAYS, periodOptions = {}) {
  if (timeRange !== 'custom') return null;
  const err = validateCustomPeriod({ from, to });
  if (err) return err;
  const fromMs = new Date(from).getTime();
  const toMs = new Date(to).getTime();
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs)) return 'Некорректная дата';
  const limitDays = explorerRangeLimitDays(maxRangeDays);
  const limitMs = Number(periodOptions.maxRangeMs) > 0
    ? Number(periodOptions.maxRangeMs)
    : limitDays * 86400000;
  const overMsg = periodOptions.rangeErrorMessage || `Период не может превышать ${limitDays} дней`;
  if (toMs - fromMs > limitMs) {
    return overMsg;
  }
  return null;
}

function dnsBucketSecondsFromMode(bucketMode) {
  return bucketMode === '1m' ? 60 : 300;
}

function explorerGranularityBucketSeconds(granularity) {
  const map = { '1m': 60, '5m': 300, '1h': 3600, '1d': 86400 };
  return map[granularity] || 300;
}

function timeRangeLabel(timeRange, customPeriod) {
  if (timeRange === 'custom') return formatCustomPeriodLabel(customPeriod);
  return TIME_RANGE_OPTIONS.find((o) => o.id === timeRange)?.label || '1 час';
}

const TIMEZONE_PRESETS = [
  { id: 'auto', label: 'Авто — пояс браузера' },
  { id: 'Europe/Moscow', label: 'Москва' },
  { id: 'Europe/Kaliningrad', label: 'Калининград' },
  { id: 'Europe/Samara', label: 'Самара' },
  { id: 'Asia/Yekaterinburg', label: 'Екатеринбург' },
  { id: 'Asia/Omsk', label: 'Омск' },
  { id: 'Asia/Krasnoyarsk', label: 'Красноярск' },
  { id: 'Asia/Irkutsk', label: 'Иркутск' },
  { id: 'Asia/Yakutsk', label: 'Якутск' },
  { id: 'Asia/Vladivostok', label: 'Владивосток' },
  { id: 'UTC', label: 'UTC' },
];

function directionSummaryLabel(directions) {
  const enabled = TRAFFIC_DIRECTIONS.filter((d) => directions[d.id]);
  if (enabled.length === TRAFFIC_DIRECTIONS.length) return 'Все направления';
  if (enabled.length === 0) return 'Нет направлений';
  if (enabled.length === 1) return enabled[0].label;
  return `${enabled.length} из ${TRAFFIC_DIRECTIONS.length}`;
}

const NO_LOCATION_KEY = '__none__';
const NO_LOCATION_LABEL = 'Без локации';

function normalizeLocationId(value) {
  const v = String(value ?? '').trim();
  return v || null;
}

function locationScopeId(locationId) {
  if (!locationId || locationId === NO_LOCATION_KEY) return `loc:${NO_LOCATION_KEY}`;
  return `loc:${locationId}`;
}

function isLocationScope(value) {
  return String(value || '').startsWith('loc:');
}

function locationScopeLabel(locations, collectors, locationId) {
  if (locationId === NO_LOCATION_KEY || !locationId) return NO_LOCATION_LABEL;
  const loc = (locations || []).find((l) => normalizeLocationId(l.locationId) === normalizeLocationId(locationId));
  if (loc?.displayName) return loc.displayName;
  const item = (collectors || []).find((c) => normalizeLocationId(c.locationId) === normalizeLocationId(locationId));
  return item?.locationName || locationId;
}

function collectorsInLocation(collectors, locationId) {
  if (locationId === NO_LOCATION_KEY || !locationId) {
    return (collectors || []).filter((c) => !normalizeLocationId(c.locationId));
  }
  const id = normalizeLocationId(locationId);
  return (collectors || []).filter((c) => normalizeLocationId(c.locationId) === id);
}

function sortByName(items, key) {
  return [...items].sort((a, b) => String(a[key] || '').localeCompare(String(b[key] || ''), 'ru'));
}

function buildCollectorFilterGroups(collectors, locations) {
  if (locations?.length) {
    const catalogIds = new Set(
      locations.map((loc) => normalizeLocationId(loc.locationId)).filter(Boolean),
    );
    const groups = sortByName(
      locations.map((loc) => ({
        locationId: normalizeLocationId(loc.locationId),
        locationName: loc.displayName || loc.locationId,
        collectors: sortByName(
          collectors.filter((c) => normalizeLocationId(c.locationId) === normalizeLocationId(loc.locationId)),
          'collectorName',
        ),
      })),
      'locationName',
    );

    const unassigned = sortByName(
      collectors.filter((c) => {
        const id = normalizeLocationId(c.locationId);
        return !id || !catalogIds.has(id);
      }),
      'collectorName',
    );
    if (unassigned.length) {
      groups.push({
        locationId: NO_LOCATION_KEY,
        locationName: NO_LOCATION_LABEL,
        collectors: unassigned,
      });
    }
    return groups;
  }

  const map = new Map();
  for (const item of collectors) {
    const locId = normalizeLocationId(item.locationId);
    const key = locId || NO_LOCATION_KEY;
    if (!map.has(key)) {
      map.set(key, {
        locationId: locId || NO_LOCATION_KEY,
        locationName: locId ? (item.locationName || locId) : NO_LOCATION_LABEL,
        collectors: [],
      });
    }
    map.get(key).collectors.push(item);
  }

  return sortByName([...map.values()], 'locationName').map((group) => ({
    ...group,
    collectors: sortByName(group.collectors, 'collectorName'),
  }));
}

function scopeTokenLabel(token, collectors, locations) {
  if (isLocationScope(token)) {
    const locationId = token.slice(4);
    const inLocation = collectorsInLocation(collectors, locationId);
    const name = locationScopeLabel(locations, collectors, locationId);
    return `${name} · все (${inLocation.length})`;
  }
  const item = (collectors || []).find((c) => c.collectorId === token);
  if (!item) return token;
  const locationName = locationScopeLabel(locations, collectors, item.locationId) || NO_LOCATION_LABEL;
  return `${locationName} · ${item.collectorName}`;
}

function isLocationSelected(selectedSet, group) {
  return selectedSet.has(locationScopeId(group.locationId));
}

function isCollectorSelected(selectedSet, group, item) {
  return isLocationSelected(selectedSet, group) || selectedSet.has(item.collectorId);
}

function toggleLocationSelection(selected, group) {
  const next = new Set(selected);
  const locScope = locationScopeId(group.locationId);
  const collectorIds = group.collectors.map((c) => c.collectorId);
  if (isLocationSelected(next, group)) {
    next.delete(locScope);
    collectorIds.forEach((id) => next.delete(id));
  } else {
    next.add(locScope);
    collectorIds.forEach((id) => next.delete(id));
  }
  return [...next];
}

function toggleCollectorSelection(selected, group, item) {
  const next = new Set(selected);
  const locScope = locationScopeId(group.locationId);
  const collectorIds = group.collectors.map((c) => c.collectorId);
  if (isCollectorSelected(next, group, item)) {
    if (next.has(locScope)) {
      next.delete(locScope);
      collectorIds.forEach((id) => {
        if (id !== item.collectorId) next.add(id);
      });
    } else {
      next.delete(item.collectorId);
    }
  } else {
    next.add(item.collectorId);
    if (collectorIds.every((id) => next.has(id))) {
      collectorIds.forEach((id) => next.delete(id));
      next.add(locScope);
    }
  }
  return [...next];
}

function collectorFilterLabel(collectorFilter, collectors, locations) {
  const items = collectorFilter || [];
  if (!items.length) return 'Все коллекторы';
  if (items.length === 1) return scopeTokenLabel(items[0], collectors, locations);
  return `${items.length} выбрано`;
}

function useCloseOnOutsideClick(open, setOpen, rootRef) {
  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);
}

function computeFixedDropdownStyle(anchorEl, { minWidth = 248, maxHeight = 360, align = 'left' } = {}) {
  const rect = anchorEl.getBoundingClientRect();
  const gap = 6;
  const pad = 8;
  const width = Math.max(rect.width, minWidth);
  const left = align === 'right'
    ? Math.max(pad, rect.right - width)
    : Math.max(pad, Math.min(rect.left, window.innerWidth - width - pad));
  return {
    position: 'fixed',
    top: rect.bottom + gap,
    left,
    width,
    minWidth: width,
    maxHeight,
    zIndex: 1300,
    overflowY: 'auto',
  };
}

function PortalTooltip({ label, children }) {
  const [visible, setVisible] = useState(false);
  const [style, setStyle] = useState(null);
  const anchorRef = useRef(null);

  useLayoutEffect(() => {
    if (!visible) {
      setStyle(null);
      return undefined;
    }
    const anchor = anchorRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setStyle({
        position: 'fixed',
        top: rect.bottom + 6,
        left: rect.left + rect.width / 2,
        transform: 'translateX(-50%)',
        zIndex: 1300,
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [visible]);

  return (
    <>
      <span
        ref={anchorRef}
        className="portal-tooltip-anchor"
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
        onFocus={() => setVisible(true)}
        onBlur={() => setVisible(false)}
      >
        {children}
      </span>
      {visible && label && style && ReactDOM.createPortal(
        <div className="portal-tooltip" style={style} role="tooltip">
          {label}
        </div>,
        document.body,
      )}
    </>
  );
}

function TimezoneSelector({ displayTimezone, timezonePref, onTimezonePrefChange }) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);
  const rootRef = useRef(null);
  const menuRef = useRef(null);
  const browserTimezone = detectBrowserTimezone();
  const shortLabel = formatTimezoneShortLabel(displayTimezone);
  const mode = timezonePref?.mode === 'manual' ? 'manual' : 'auto';
  const activeManual = mode === 'manual' ? timezonePref.timezone : null;

  useLayoutEffect(() => {
    if (!open) {
      setMenuStyle(null);
      return undefined;
    }
    const anchor = rootRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      setMenuStyle(computeFixedDropdownStyle(anchor, { minWidth: 280, align: 'right' }));
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (rootRef.current?.contains(e.target) || menuRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const selectPreset = (presetId) => {
    if (presetId === 'auto') {
      onTimezonePrefChange({ mode: 'auto', timezone: browserTimezone });
    } else {
      onTimezonePrefChange({ mode: 'manual', timezone: presetId });
    }
    setOpen(false);
  };

  return (
    <div className="timezone-filter" ref={rootRef}>
      <button
        type="button"
        className="time-pill time-pill--tz"
        title={formatTimezoneLongLabel(displayTimezone)}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <Icon name="globe" size={14} />
        <span className="time-pill__range">{shortLabel}</span>
        <Icon name="chevD" size={14} />
      </button>
      {open && menuStyle && ReactDOM.createPortal(
        <div
          ref={menuRef}
          className="time-filter__menu timezone-filter__menu timezone-filter__menu--portal"
          style={menuStyle}
          role="menu"
        >
          <div className="time-filter__section timezone-filter__section">
            <div className="timezone-filter__hint">
              Данные ClickHouse: {formatTimezoneShortLabel(getDataTimezone())} · отображение ниже
            </div>
            {TIMEZONE_PRESETS.map((preset) => {
              const isAuto = preset.id === 'auto';
              const selected = isAuto ? mode === 'auto' : mode === 'manual' && activeManual === preset.id;
              const subtitle = isAuto ? formatTimezoneLongLabel(browserTimezone) : formatTimezoneShortLabel(preset.id);
              return (
                <button
                  key={preset.id}
                  type="button"
                  role="menuitemradio"
                  aria-checked={selected}
                  className={`time-filter__option timezone-filter__option ${selected ? 'is-active' : ''}`}
                  onClick={() => selectPreset(preset.id)}
                >
                  <span className="timezone-filter__option-label">{preset.label}</span>
                  <span className="timezone-filter__option-sub">{subtitle}</span>
                </button>
              );
            })}
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
}

function computeTimeFilterMenuStyle(anchorEl, { customOpen = false } = {}) {
  const rect = anchorEl.getBoundingClientRect();
  const gap = 6;
  const pad = 8;
  const minWidth = customOpen ? 280 : 248;
  const width = Math.max(rect.width, minWidth);
  const left = Math.min(Math.max(pad, rect.left), window.innerWidth - width - pad);
  const below = window.innerHeight - rect.bottom - gap - pad;
  const above = rect.top - gap - pad;
  const preferBelow = below >= above;
  const availableHeight = Math.max(160, preferBelow ? below : above);
  const top = preferBelow
    ? rect.bottom + gap
    : Math.max(pad, rect.top - gap - availableHeight);
  return {
    position: 'fixed',
    top,
    left,
    width,
    minWidth,
    availableHeight,
    zIndex: 1300,
  };
}

function measureTimeFilterMenuNaturalHeight(menuEl, optionsEl) {
  if (optionsEl) return optionsEl.scrollHeight + 12;
  return menuEl.scrollHeight;
}

function timeFilterMenuPositionChanged(prev, next) {
  if (!prev || !next) return true;
  return prev.top !== next.top
    || prev.left !== next.left
    || prev.width !== next.width
    || prev.availableHeight !== next.availableHeight;
}

function TimeFilter({ timeRange, onTimeRangeChange, customPeriod, onCustomPeriodChange, variant = 'header', maxRangeDays = null }) {
  const isExplorer = variant === 'explorer';
  const [open, setOpen] = useState(false);
  const [menuView, setMenuView] = useState('presets');
  const [draftPeriod, setDraftPeriod] = useState(customPeriod);
  const [periodError, setPeriodError] = useState(null);
  const [menuPosition, setMenuPosition] = useState(null);
  const [needsScroll, setNeedsScroll] = useState(false);
  const rootRef = useRef(null);
  const menuRef = useRef(null);
  const optionsRef = useRef(null);
  const availableHeightRef = useRef(0);
  const customFromId = isExplorer ? 'time-filter-from-explorer' : 'time-filter-from';
  const customToId = isExplorer ? 'time-filter-to-explorer' : 'time-filter-to';

  const rangeLabel = timeRangeLabel(timeRange, customPeriod);
  const customViewOpen = menuView === 'custom';
  const presetOptions = useMemo(() => {
    const limitMs = Number(maxRangeDays) > 0 ? Number(maxRangeDays) * 86400000 : null;
    if (!limitMs) return TIME_RANGE_OPTIONS;
    return TIME_RANGE_OPTIONS.filter((o) => {
      const presetMs = timeRangePresetMs(o.id);
      return presetMs == null || presetMs <= limitMs;
    });
  }, [maxRangeDays]);

  useEffect(() => {
    if (!open) return;
    setDraftPeriod(customPeriod);
    setMenuView(timeRange === 'custom' ? 'custom' : 'presets');
  }, [open, customPeriod, timeRange]);

  useLayoutEffect(() => {
    if (!open) {
      setMenuPosition(null);
      setNeedsScroll(false);
      return undefined;
    }
    const anchor = rootRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const next = computeTimeFilterMenuStyle(anchor, { customOpen: customViewOpen });
      availableHeightRef.current = next.availableHeight;
      setMenuPosition((prev) => (timeFilterMenuPositionChanged(prev, next) ? next : prev));
    };
    updatePosition();
    const onScroll = (e) => {
      if (menuRef.current?.contains(e.target)) return;
      updatePosition();
    };
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [open, customViewOpen]);

  useLayoutEffect(() => {
    if (!open || !menuPosition) {
      setNeedsScroll(false);
      return undefined;
    }
    const updateScrollNeed = () => {
      const menu = menuRef.current;
      if (!menu) return;
      const naturalHeight = measureTimeFilterMenuNaturalHeight(menu, optionsRef.current);
      const next = naturalHeight > availableHeightRef.current;
      setNeedsScroll((prev) => (prev === next ? prev : next));
    };
    updateScrollNeed();
    window.addEventListener('resize', updateScrollNeed);
    return () => window.removeEventListener('resize', updateScrollNeed);
  }, [open, menuPosition, customViewOpen]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (rootRef.current?.contains(e.target) || menuRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const applyCustomPeriod = () => {
    const err = (isExplorer || Number(maxRangeDays) > 0)
      ? validateExplorerCustomPeriod(draftPeriod, 'custom', maxRangeDays)
      : validateCustomPeriod(draftPeriod);
    if (err) {
      setPeriodError(err);
      return;
    }
    setPeriodError(null);
    onTimeRangeChange('custom');
    onCustomPeriodChange(draftPeriod);
    setOpen(false);
  };

  const pickPreset = (optionId) => {
    if (optionId === 'custom') {
      onTimeRangeChange(optionId);
      setDraftPeriod(customPeriod);
      setPeriodError(null);
      setMenuView('custom');
      return;
    }
    if (timeRange === optionId) return;
    onTimeRangeChange(optionId);
    setOpen(false);
  };

  const isPresetCurrent = (optionId) => timeRange === optionId;

  const resetCustomDraft = () => {
    setDraftPeriod(defaultCustomPeriod());
    setPeriodError(null);
  };

  const menuStyle = menuPosition ? {
    position: menuPosition.position,
    top: menuPosition.top,
    left: menuPosition.left,
    width: menuPosition.width,
    minWidth: menuPosition.minWidth,
    zIndex: menuPosition.zIndex,
    ...(needsScroll ? { maxHeight: menuPosition.availableHeight } : {}),
  } : null;

  const menu = open && menuStyle ? (
    <div
      ref={menuRef}
      className={`time-filter__menu time-filter__menu--fixed${needsScroll ? ' time-filter__menu--scrollable' : ''}${isExplorer ? ' time-filter__menu--explorer' : ''}`}
      role="menu"
      style={menuStyle}
    >
      {!customViewOpen ? (
      <div ref={optionsRef} className="time-filter__section time-filter__section--options">
        {presetOptions.map((o) => {
          const current = isPresetCurrent(o.id);
          if (isExplorer) {
            return (
              <div
                key={o.id}
                className={`direction-picker-item${current ? ' is-disabled' : ''}`}
                role="menuitem"
                aria-disabled={current}
                onClick={() => !current && pickPreset(o.id)}
              >
                {o.label}
              </div>
            );
          }
          return (
            <button
              key={o.id}
              type="button"
              role="menuitemradio"
              aria-checked={current}
              className={`time-filter__option ${current ? 'is-active' : ''}`}
              onClick={() => pickPreset(o.id)}
            >
              {o.label}
            </button>
          );
        })}
      </div>
      ) : (
        <>
          <button
            type="button"
            className="time-filter__back"
            onClick={() => setMenuView('presets')}
          >
            <Icon name="chevL" size={14} />
            <span>Предустановленные</span>
          </button>
          <div className="time-filter__custom">
            <div className="field">
              <label htmlFor={customFromId}>Начало</label>
              <input
                id={customFromId}
                type="datetime-local"
                className="input"
                value={draftPeriod.from}
                max={draftPeriod.to || undefined}
                onChange={(e) => {
                  setDraftPeriod((p) => ({ ...p, from: e.target.value }));
                  setPeriodError(null);
                }}
              />
            </div>
            <div className="field">
              <label htmlFor={customToId}>Конец</label>
              <input
                id={customToId}
                type="datetime-local"
                className="input"
                value={draftPeriod.to}
                min={draftPeriod.from || undefined}
                onChange={(e) => {
                  setDraftPeriod((p) => ({ ...p, to: e.target.value }));
                  setPeriodError(null);
                }}
              />
            </div>
            {periodError && <div className="time-filter__custom-error" role="alert">{periodError}</div>}
            <div className="time-filter__custom-actions">
              <Button kind="ghost" size="sm" type="button" onClick={resetCustomDraft}>
                Сбросить
              </Button>
              <Button kind="primary" size="sm" type="button" onClick={applyCustomPeriod}>
                Применить
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  ) : null;

  return (
    <div className={`time-filter${isExplorer ? ' time-filter--explorer' : ''}`} ref={rootRef}>
      {isExplorer ? (
        <button type="button" className="period-select" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          <span className="period-select__label" title={timeRange === 'custom' ? rangeLabel : undefined}>{rangeLabel}</span>
          <Icon name="chevD" size={14} />
        </button>
      ) : (
        <button type="button" className="time-pill" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          <span className="live-dot" />
          <Icon name="clock" size={14} />
          <span className="time-pill__label" title={timeRange === 'custom' ? rangeLabel : undefined}>{rangeLabel}</span>
          <Icon name="chevD" size={14} />
        </button>
      )}
      {menu && ReactDOM.createPortal(menu, document.body)}
    </div>
  );
}

function DirectionFilter({ directions, onDirectionsChange, embedded = false, formatSummary }) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);
  const rootRef = useRef(null);
  const addRef = useRef(null);
  const menuRef = useRef(null);

  const enabledDirections = TRAFFIC_DIRECTIONS.filter((d) => directions[d.id]);
  const enabledCount = enabledDirections.length;
  const allEnabled = enabledCount === TRAFFIC_DIRECTIONS.length;
  const summary = (formatSummary || directionSummaryLabel)(directions);

  const toggleDirection = (id) => {
    onDirectionsChange({ ...directions, [id]: !directions[id] });
  };

  const setAllDirections = (on) => {
    onDirectionsChange(Object.fromEntries(TRAFFIC_DIRECTIONS.map((d) => [d.id, on])));
  };

  const removeDirection = (id) => {
    onDirectionsChange({ ...directions, [id]: false });
  };

  const pickDirection = (id) => {
    onDirectionsChange({ ...directions, [id]: true });
    setOpen(false);
  };

  const pickAllDirections = () => {
    setAllDirections(true);
    setOpen(false);
  };

  useLayoutEffect(() => {
    if (!open) {
      setMenuStyle(null);
      return undefined;
    }
    const anchor = embedded ? addRef.current : rootRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      const width = embedded ? 248 : Math.max(rect.width, 248);
      setMenuStyle({
        position: 'fixed',
        top: rect.bottom + 6,
        left: Math.max(8, rect.left),
        width,
        maxHeight: 360,
        zIndex: 1300,
        overflowY: 'auto',
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [embedded, open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (rootRef.current?.contains(e.target) || menuRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const headerMenu = open && menuStyle && !embedded ? ReactDOM.createPortal(
    <div
      ref={menuRef}
      className="direction-filter__menu direction-filter__menu--portal"
      style={menuStyle}
      role="menu"
    >
      <div className="time-filter__heading">
        <span>Направления</span>
        <button
          type="button"
          className="time-filter__link"
          onClick={() => setAllDirections(!allEnabled)}
        >
          {allEnabled ? 'Снять все' : 'Выбрать все'}
        </button>
      </div>
      <div className="time-filter__section time-filter__section--directions">
        {TRAFFIC_DIRECTIONS.map((d) => {
          const on = !!directions[d.id];
          return (
            <label key={d.id} className={`direction-option ${on ? 'is-on' : ''}`}>
              <input
                type="checkbox"
                checked={on}
                onChange={() => toggleDirection(d.id)}
              />
              <span className="direction-option__swatch" style={{ background: d.color }} />
              <span className="direction-option__label">{d.label}</span>
            </label>
          );
        })}
      </div>
    </div>,
    document.body,
  ) : null;

  const embeddedMenu = open && menuStyle ? ReactDOM.createPortal(
    <div
      ref={menuRef}
      className="direction-filter__menu direction-filter__menu--portal"
      style={menuStyle}
      role="menu"
    >
      <div
        className={`direction-picker-item${allEnabled ? ' is-disabled' : ''}`}
        role="menuitem"
        aria-disabled={allEnabled}
        onClick={() => !allEnabled && pickAllDirections()}
      >
        Все
      </div>
      {TRAFFIC_DIRECTIONS.map((d) => {
        const selected = !!directions[d.id];
        return (
          <div
            key={d.id}
            className={`direction-picker-item${selected ? ' is-disabled' : ''}`}
            role="menuitem"
            aria-disabled={selected}
            onClick={() => !selected && pickDirection(d.id)}
          >
            {d.label}
          </div>
        );
      })}
    </div>,
    document.body,
  ) : null;

  if (embedded) {
    return (
      <div className="direction-filter direction-filter--embedded direction-filter--chips" ref={rootRef}>
        <div className="direction-filter__chips">
          {allEnabled ? (
            <span className="badge badge--info direction-chip">
              <span className="direction-chip__label">Все</span>
              <button
                type="button"
                className="direction-chip__remove"
                title="Снять все направления"
                onClick={() => setAllDirections(false)}
              >
                <Icon name="x" size={10} stroke={2.5} />
              </button>
            </span>
          ) : (
            enabledDirections.map((d) => (
              <span key={d.id} className="badge badge--info direction-chip">
                <span className="direction-chip__label">{d.label}</span>
                <button
                  type="button"
                  className="direction-chip__remove"
                  title={`Убрать ${d.label}`}
                  onClick={() => removeDirection(d.id)}
                >
                  <Icon name="x" size={10} stroke={2.5} />
                </button>
              </span>
            ))
          )}
          {enabledCount === 0 && (
            <span className="direction-filter__empty-hint">Нет направлений</span>
          )}
          <div className="direction-filter__add" ref={addRef}>
            <Button
              kind="ghost"
              size="xs"
              icon="plus"
              type="button"
              aria-expanded={open}
              onClick={() => setOpen((v) => !v)}
            >
              Направление
            </Button>
          </div>
        </div>
        {embeddedMenu}
      </div>
    );
  }

  return (
    <div className="direction-filter" ref={rootRef}>
      <button
        type="button"
        className="direction-pill"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        title="Фильтр по направлениям трафика"
      >
        <span className="direction-pill__chips" aria-hidden="true">
          {TRAFFIC_DIRECTIONS.map((d) => (
            <span
              key={d.id}
              className={`direction-pill__chip ${directions[d.id] ? 'is-on' : ''}`}
              style={{ background: d.color }}
            />
          ))}
        </span>
        <span className="direction-pill__label">{summary}</span>
        <Icon name="chevD" size={14} />
      </button>
      {headerMenu}
    </div>
  );
}

function CollectorFilter({ collectorFilter, onCollectorFilterChange, embedded = false }) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);
  const [collectors, setCollectors] = useState([]);
  const [locations, setLocations] = useState([]);
  const rootRef = useRef(null);
  const menuRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    ApiClient.loadDashboardCollectors().then(({ collectors: collectorRows, locations: locationRows }) => {
      if (cancelled) return;
      setCollectors(collectorRows);
      setLocations(locationRows);
    });
    return () => { cancelled = true; };
  }, []);

  useLayoutEffect(() => {
    if (embedded || !open) {
      setMenuStyle(null);
      return undefined;
    }
    const anchor = rootRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({
        position: 'fixed',
        top: rect.bottom + 6,
        left: Math.max(8, rect.right - Math.max(rect.width, 248)),
        width: Math.max(rect.width, 248),
        maxHeight: 360,
        zIndex: 1300,
        overflowY: 'auto',
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [embedded, open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (rootRef.current?.contains(e.target) || menuRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const selected = useMemo(() => new Set(collectorFilter || []), [collectorFilter]);
  const grouped = useMemo(
    () => buildCollectorFilterGroups(collectors, locations),
    [collectors, locations],
  );
  const label = collectorFilterLabel(collectorFilter, collectors, locations);

  const applySelection = (nextItems) => {
    onCollectorFilterChange(nextItems);
  };

  const menuBody = (
    <>
      <button
        type="button"
        role="menuitemcheckbox"
        aria-checked={!collectorFilter?.length}
        className={`time-filter__option ${!collectorFilter?.length ? 'is-active' : ''}`}
        onClick={() => applySelection([])}
      >
        <input type="checkbox" checked={!collectorFilter?.length} readOnly tabIndex={-1} />
        Все коллекторы
      </button>
      {grouped.map((group) => {
        const locationSelected = isLocationSelected(selected, group);
        return (
          <div key={group.locationId} className="collector-filter__group">
            <button
              type="button"
              role="menuitemcheckbox"
              aria-checked={locationSelected}
              className={`collector-filter__location ${locationSelected ? 'is-active' : ''}`}
              onClick={() => applySelection(toggleLocationSelection(selected, group))}
            >
              <input type="checkbox" checked={locationSelected} readOnly tabIndex={-1} />
              <span>{group.locationName}</span>
            </button>
            {group.collectors.map((item) => {
              const collectorChecked = isCollectorSelected(selected, group, item);
              return (
                <button
                  key={item.collectorId}
                  type="button"
                  role="menuitemcheckbox"
                  aria-checked={collectorChecked}
                  className={`time-filter__option time-filter__option--nested time-filter__option--collector ${collectorChecked ? 'is-active' : ''}`}
                  onClick={() => applySelection(toggleCollectorSelection(selected, group, item))}
                >
                  <input type="checkbox" checked={collectorChecked} readOnly tabIndex={-1} />
                  {item.collectorName}
                </button>
              );
            })}
          </div>
        );
      })}
    </>
  );

  return (
    <div className={`collector-filter${embedded ? ' collector-filter--embedded' : ''}`} ref={rootRef}>
      <button
        type="button"
        className={embedded ? 'input' : 'collector-pill'}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        title="Фильтр по коллектору"
        style={embedded ? {
          minWidth: 0,
          flex: 1,
          textAlign: 'left',
          justifyContent: 'space-between',
          gap: 6,
        } : undefined}
      >
        {!embedded && <Icon name="collectors" size={14} />}
        <span
          className={embedded ? undefined : 'collector-pill__label'}
          style={embedded ? { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 } : undefined}
        >
          {label}
        </span>
        <Icon name="chevD" size={embedded ? 12 : 14} />
      </button>
      {embedded && open && (
        <div className="collector-filter__menu" role="menu">
          {menuBody}
        </div>
      )}
      {!embedded && open && menuStyle && ReactDOM.createPortal(
        <div
          ref={menuRef}
          className="collector-filter__menu collector-filter__menu--portal"
          style={menuStyle}
          role="menu"
        >
          {menuBody}
        </div>,
        document.body,
      )}
    </div>
  );
}

/* Brand glyph: stylised grape cluster */
function GrapesGlyph({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="9"  cy="9"  r="2.6" fill="currentColor" />
      <circle cx="15" cy="9"  r="2.6" fill="currentColor" fillOpacity="0.7" />
      <circle cx="12" cy="13" r="2.6" fill="currentColor" />
      <circle cx="9"  cy="17" r="2.4" fill="currentColor" fillOpacity="0.85" />
      <circle cx="15" cy="17" r="2.4" fill="currentColor" fillOpacity="0.6" />
      <path d="M12 7 L11 4 L13 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

function parseAppHash() {
  const raw = (location.hash || '#dashboard').slice(1);
  const qIdx = raw.indexOf('?');
  const pageId = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
  const params = qIdx >= 0 ? new URLSearchParams(raw.slice(qIdx + 1)) : new URLSearchParams();
  return { pageId, params };
}

function parseJsonSearchParam(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    try {
      return JSON.parse(decodeURIComponent(raw));
    } catch {
      return null;
    }
  }
}

function parseDirectionsParam(value) {
  if (!value) return null;
  const ids = new Set(value.split(',').map((s) => s.trim()).filter(Boolean));
  if (!ids.size) return null;
  return Object.fromEntries(TRAFFIC_DIRECTIONS.map((d) => [d.id, ids.has(d.id)]));
}

function applyTopTalkersUrlGlobals(params) {
  const next = {};
  const range = params.get('range');
  if (range) next.timeRange = range;
  const from = params.get('from');
  const to = params.get('to');
  if (range === 'custom' && from && to && !validateCustomPeriod({ from, to })) {
    next.customPeriod = { from, to };
  }
  const dirs = parseDirectionsParam(params.get('dirs'));
  if (dirs) next.directions = dirs;
  if (params.has('collectors')) {
    next.collectorFilter = params.get('collectors')
      ? params.get('collectors').split(',').map((s) => s.trim()).filter(Boolean)
      : [];
  }
  return next;
}

const TOP_TALKERS_PAGE_METRICS = ['bps', 'volume', 'pps', 'fps'];
const TOP_TALKERS_PAGE_GROUPS = ['src', 'dst', 'pair'];

// Shared metric catalogue used by top-talkers.jsx (referenced as
// the global METRICS). It used to live in explorer.jsx and was dropped when the
// Explorer page was rewritten; restore it here so those pages keep resolving labels.
const METRICS = [
  { id: 'bps', label: 'Средняя скорость / Average bitrate', unit: 'бит/с', icon: 'flow' },
  { id: 'volume', label: 'Объём / Volume', unit: 'байт', icon: 'layers' },
  { id: 'pps', label: 'Пакеты/с / Packets per second', unit: 'п/с', icon: 'top' },
  { id: 'fps', label: 'Потоки/с / Flows per second', unit: 'ф/с', icon: 'explorer' },
  { id: 'flows', label: 'Всего потоков / Total flows', unit: '', icon: 'layers' },
  { id: 'uniq_src', label: 'Уникальных IP источника / Unique source IPs', unit: '', icon: 'network' },
];

function parseTopTalkersPageParams(params) {
  const group = params.get('group');
  const metric = params.get('metric');
  return {
    direction: TOP_TALKERS_PAGE_GROUPS.includes(group) ? group : 'src',
    metric: TOP_TALKERS_PAGE_METRICS.includes(metric) ? metric : 'bps',
    search: params.get('q') || '',
  };
}

function readTopTalkersPageParamsFromHash() {
  const { pageId, params } = parseAppHash();
  if (pageId !== 'top' || !params.toString()) return null;
  return parseTopTalkersPageParams(params);
}

function buildTopTalkersShareUrl({
  direction,
  metric,
  search,
  timeRange,
  customPeriod,
  directions,
  collectorFilter,
}) {
  const params = new URLSearchParams();
  params.set('group', direction);
  params.set('metric', metric);
  if (search) params.set('q', search);
  params.set('range', timeRange);
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    params.set('from', customPeriod.from);
    params.set('to', customPeriod.to);
  }
  const enabledDirs = TRAFFIC_DIRECTIONS.filter((d) => directions?.[d.id]).map((d) => d.id);
  if (enabledDirs.length && enabledDirs.length < TRAFFIC_DIRECTIONS.length) {
    params.set('dirs', enabledDirs.join(','));
  }
  if (collectorFilter?.length) params.set('collectors', collectorFilter.join(','));
  return `${window.location.origin}${window.location.pathname}#top?${params.toString()}`;
}

function parseExplorerPageParams(params) {
  const snapshot = String(params.get('snapshot') || '').trim();
  if (snapshot) {
    return { snapshot };
  }
  const metric = params.get('metric');
  const groupBy = (params.get('groupBy') || '').split(',').map((s) => s.trim()).filter(Boolean);
  const limit = Number(params.get('limit'));
  const vis = params.get('vis');
  const filtersParsed = parseJsonSearchParam(params.get('filters'));
  const filters = Array.isArray(filtersParsed) ? filtersParsed : [];
  const thresholdsParsed = parseJsonSearchParam(params.get('thresholds'));
  const thresholds = Array.isArray(thresholdsParsed) ? thresholdsParsed : [];
  const EXPLORER_VIS_IDS = new Set([
    'contribution', 'dynamics', 'data',
    'lines', 'donut', 'sankey', 'table', 'bars', 'relations',
  ]);
  const EXPLORER_VIS_LEGACY_MAP = {
    lines: 'data',
    dynamics: 'data',
    donut: 'contribution',
    bars: 'contribution',
    sankey: 'contribution',
    relations: 'contribution',
    table: 'data',
  };
  const normalizedVis = EXPLORER_VIS_IDS.has(vis)
    ? (EXPLORER_VIS_LEGACY_MAP[vis] || vis)
    : 'data';
  return {
    metric: metric || 'bps',
    groupBy: groupBy.length ? groupBy : ['src_ip', 'dst_ip'],
    filters: Array.isArray(filters) ? filters : [],
    thresholds: Array.isArray(thresholds) ? thresholds : [],
    limit: Number.isFinite(limit) && limit > 0 ? limit : 25,
    vis: normalizedVis,
  };
}

function readExplorerPageParamsFromHash() {
  const { pageId, params } = parseAppHash();
  if (pageId !== 'explorer' || !params.toString()) return null;
  return parseExplorerPageParams(params);
}

function applyExplorerUrlGlobals(params) {
  const next = applyTopTalkersUrlGlobals(params);
  return next;
}

function buildExplorerShareUrl({
  metric,
  groupBy,
  filters,
  thresholds,
  limit,
  vis,
  timeRange,
  customPeriod,
}) {
  const params = new URLSearchParams();
  params.set('metric', metric || 'bps');
  if (groupBy?.length) params.set('groupBy', groupBy.join(','));
  if (limit) params.set('limit', String(limit));
  if (vis) params.set('vis', vis);
  if (filters?.length) params.set('filters', JSON.stringify(filters));
  if (thresholds?.length) params.set('thresholds', JSON.stringify(thresholds));
  params.set('range', timeRange || '1h');
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    params.set('from', customPeriod.from);
    params.set('to', customPeriod.to);
  }
  return `${window.location.origin}${window.location.pathname}#explorer?${params.toString()}`;
}

function buildExplorerSnapshotShareUrl(token) {
  const params = new URLSearchParams();
  params.set('snapshot', token);
  return `${window.location.origin}${window.location.pathname}#explorer?${params.toString()}`;
}

function parseDnsExplorerPageParams(params) {
  const snapshot = String(params.get('snapshot') || '').trim();
  if (snapshot) {
    return { snapshot };
  }
  const metric = params.get('metric');
  const groupBy = (params.get('groupBy') || '').split(',').map((s) => s.trim()).filter(Boolean);
  const filtersParsed = parseJsonSearchParam(params.get('filters'));
  const filters = Array.isArray(filtersParsed) ? filtersParsed : [];
  return {
    metric: metric || 'queries_per_sec',
    groupBy,
    filters,
  };
}

function readDnsExplorerPageParamsFromHash() {
  const { pageId, params } = parseAppHash();
  if (pageId !== 'dns-explorer' || !params.toString()) return null;
  return parseDnsExplorerPageParams(params);
}

function applyDnsExplorerUrlGlobals(params) {
  return applyTopTalkersUrlGlobals(params);
}

function buildDnsExplorerDraftUrl({
  metric,
  groupBy,
  filters,
  timeRange,
  customPeriod,
}) {
  const params = new URLSearchParams();
  if (metric) params.set('metric', metric);
  if (groupBy?.length) params.set('groupBy', groupBy.join(','));
  if (filters?.length) params.set('filters', JSON.stringify(filters));
  params.set('range', timeRange || '24h');
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    params.set('from', customPeriod.from);
    params.set('to', customPeriod.to);
  }
  return `#dns-explorer?${params.toString()}`;
}

function buildDnsExplorerShareUrl({
  metric,
  groupBy,
  filters,
  timeRange,
  customPeriod,
}) {
  const params = new URLSearchParams();
  params.set('metric', metric || 'queries_per_sec');
  if (groupBy?.length) params.set('groupBy', groupBy.join(','));
  if (filters?.length) params.set('filters', JSON.stringify(filters));
  params.set('range', timeRange || '24h');
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    params.set('from', customPeriod.from);
    params.set('to', customPeriod.to);
  }
  return `${window.location.origin}${window.location.pathname}#dns-explorer?${params.toString()}`;
}

function buildDnsExplorerSnapshotShareUrl(token) {
  const params = new URLSearchParams();
  params.set('snapshot', token);
  return `${window.location.origin}${window.location.pathname}#dns-explorer?${params.toString()}`;
}

let PAGE_TITLES = {};

function ImpersonationBanner({ cabinet, onStop, onRefreshUser }) {
  const [now, setNow] = useState(Date.now());
  const expiresAt = Number(cabinet?.impersonation?.expiresAt) || 0;
  const startedAt = cabinet?.impersonation?.startedAt;
  const clientName = cabinet?.clientDisplayName || cabinet?.clientId || 'клиент';

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!expiresAt) return undefined;
    if (expiresAt <= now) {
      onRefreshUser?.();
      return undefined;
    }
    const delay = Math.max(expiresAt - now, 0);
    const timer = setTimeout(() => onRefreshUser?.(), delay);
    return () => clearTimeout(timer);
  }, [expiresAt, now, onRefreshUser]);

  const remainingMs = Math.max(expiresAt - now, 0);
  const mins = Math.floor(remainingMs / 60000);
  const secs = Math.floor((remainingMs % 60000) / 1000);
  const timerLabel = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  const bannerText = `Просмотр кабинета «${clientName}» · только чтение · осталось ${timerLabel}`;

  return (
    <div className="impersonation-banner" role="status">
      <div className="impersonation-banner__content">
        <Icon name="users" size={16} />
        <span className="impersonation-banner__text" title={bannerText}>
          {bannerText}
        </span>
        {startedAt && (
          <span className="impersonation-banner__meta">
            с {formatUserDateTime(startedAt)}
          </span>
        )}
      </div>
      <Button kind="primary" size="sm" onClick={onStop}>Выйти из кабинета</Button>
    </div>
  );
}

function setPageTitles(map) {
  PAGE_TITLES = map || {};
  window.PAGE_TITLES = PAGE_TITLES;
}

Object.assign(window, {
  Sidebar, Header, NAV, CABINET_NAV, CABINET_PAGE_IDS, PAGE_TITLES, setPageTitles, GrapesGlyph,
  isCabinetMode, isImpersonating, ImpersonationBanner,
  TIME_RANGE_OPTIONS, TIMEZONE_PRESETS, TRAFFIC_DIRECTIONS, defaultDirectionsEnabled,
  defaultCustomPeriod, formatCustomPeriodLabel, validateCustomPeriod, validateExplorerCustomPeriod, explorerRangeLimitDays, timeRangePresetMs, EXPLORER_MAX_RANGE_DAYS, timeRangeLabel,
  toDatetimeLocalValue, dnsBucketSecondsFromMode, explorerGranularityBucketSeconds,
  collectorFilterLabel, directionSummaryLabel, TimezoneSelector,
  parseAppHash, parseJsonSearchParam, parseDirectionsParam, applyTopTalkersUrlGlobals,
  parseTopTalkersPageParams, readTopTalkersPageParamsFromHash, buildTopTalkersShareUrl,
  METRICS,
  parseExplorerPageParams, readExplorerPageParamsFromHash, applyExplorerUrlGlobals, buildExplorerShareUrl, buildExplorerSnapshotShareUrl,
  parseDnsExplorerPageParams, readDnsExplorerPageParamsFromHash, applyDnsExplorerUrlGlobals,
  buildDnsExplorerDraftUrl, buildDnsExplorerShareUrl, buildDnsExplorerSnapshotShareUrl,
});
