/* Global modal when a new attack starts (any page). */

const { useState, useEffect, useRef, useCallback } = React;

const POLL_MS = 5000;
const DISMISS_KEY = 'grapes-attack-alert-dismissed';
const OPEN_EVENT = 'grapes-attack-open';

function alertT(key, params) {
  return GrapesI18n.t(key, params);
}

function kindLabel(kind) {
  const key = `monitoring.kind.${kind}`;
  if (GrapesI18n.has(key)) return alertT(key);
  return window.DetectionKindLabel?.[kind] || kind || '—';
}

function parseStartMs(value) {
  if (!value) return null;
  const text = String(value).trim();
  const isoLike = text.includes('T') ? text : text.replace(' ', 'T');
  const ms = Date.parse(isoLike.endsWith('Z') ? isoLike : `${isoLike}Z`);
  return Number.isNaN(ms) ? null : ms;
}

function formatBps(value) {
  if (window.DetectionFormatBps) return window.DetectionFormatBps(value);
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return '—';
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} Gbit/s`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} Mbit/s`;
  return `${Math.round(n)} bit/s`;
}

function attackDetailLines(row) {
  const lines = [];
  const bps = row?.alertByProto?.all?.bps;
  if (Number.isFinite(Number(bps)) && Number(bps) > 0) {
    lines.push(alertT('attackAlert.volume', { bps: formatBps(bps) }));
  }
  const victim = window.DetectionFormatVictimCell?.(row.investigate);
  if (victim && victim !== '—') {
    lines.push(alertT('attackAlert.victim', { target: victim }));
  }
  const sw = window.DetectionFormatSwitchCell?.(row.investigate);
  if (sw && sw !== '—') {
    lines.push(alertT('attackAlert.switchIn', { port: sw }));
  }
  if (row.test && row.testTriggeredBy) {
    lines.push(alertT('attackAlert.triggeredBy', { user: row.testTriggeredBy }));
  }
  if (row.testNote) {
    lines.push(row.testNote);
  }
  return lines;
}

function formatStartTime(value) {
  const ms = parseStartMs(value);
  if (ms == null) return '—';
  const tz = typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined;
  const intlLoc = GrapesI18n.intlLocale?.() || 'ru-RU';
  return new Date(ms).toLocaleString(intlLoc, {
    dateStyle: 'short',
    timeStyle: 'short',
    ...(tz ? { timeZone: tz } : {}),
  });
}

function loadDismissed() {
  try {
    const raw = sessionStorage.getItem(DISMISS_KEY);
    const list = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(list) ? list : []);
  } catch {
    return new Set();
  }
}

function saveDismissed(set) {
  try {
    sessionStorage.setItem(DISMISS_KEY, JSON.stringify([...set]));
  } catch (_) { /* ignore */ }
}

function AttackAlertModal({ open, attacks, onClose, onOpenMonitoring, showMonitoringLink }) {
  if (!open || !attacks?.length) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      variant="attack-alert"
      title={attacks.length > 1 ? alertT('attackAlert.titleMany', { n: attacks.length }) : alertT('attackAlert.title')}
      subtitle={alertT('attackAlert.subtitle')}
      size="lg"
      footer={(
        <>
          <span style={{ flex: 1 }} />
          {showMonitoringLink && (
            <Button
              kind="ghost"
              onClick={() => {
                onClose();
                onOpenMonitoring(attacks[0]?.id);
              }}
            >
              {alertT('attackAlert.openMonitoring')}
            </Button>
          )}
          <Button kind="primary" onClick={onClose}>{alertT('attackAlert.dismiss')}</Button>
        </>
      )}
    >
      <ul className="attack-alert-list">
        {attacks.map((row) => (
          <li key={row.id} className="attack-alert-list__item">
            <div className="attack-alert-list__head">
              {row.test && (
                <Badge tone="warning">{alertT('attackAlert.testBadge')}</Badge>
              )}
              <Badge tone="critical">{kindLabel(row.verdict?.kind)}</Badge>
            </div>
            <div className="attack-alert-list__target">{row.name || row.scopeId}</div>
            <div className="attack-alert-list__meta">
              {alertT('attackAlert.startedAt', { time: formatStartTime(row.startMinute || row.alertMinute) })}
            </div>
            {attackDetailLines(row).map((line, idx) => (
              <div key={idx} className="attack-alert-list__detail">{line}</div>
            ))}
          </li>
        ))}
      </ul>
    </Modal>
  );
}

function AttackAlertHost({ user, onNavigate, cabinetMode }) {
  const enabled = !!user?.role?.attackAlert;
  const showMonitoringLink = !cabinetMode && !!user?.effectivePermissions?.monitoring;
  const [open, setOpen] = useState(false);
  const [attacks, setAttacks] = useState([]);
  const knownIdsRef = useRef(null);
  const dismissedRef = useRef(loadDismissed());

  const openWithAttacks = useCallback((list) => {
    const fresh = (list || []).filter((a) => a?.id && !dismissedRef.current.has(a.id));
    if (!fresh.length) return;
    setAttacks(fresh);
    setOpen(true);
  }, []);

  const close = useCallback(() => {
    setOpen(false);
    for (const row of attacks) {
      if (row?.id) dismissedRef.current.add(row.id);
    }
    saveDismissed(dismissedRef.current);
    for (const row of attacks) {
      if (row?.id) knownIdsRef.current?.add(row.id);
    }
  }, [attacks]);

  useEffect(() => {
    if (!enabled) {
      knownIdsRef.current = null;
      setOpen(false);
      setAttacks([]);
      return undefined;
    }

    let cancelled = false;

    const poll = async () => {
      try {
        const body = await ApiClient.loadAttackAlerts();
        if (cancelled || !body?.enabled) return;
        const list = body.attacks || [];
        const ids = new Set(list.map((a) => a.id).filter(Boolean));
        if (knownIdsRef.current === null) {
          knownIdsRef.current = ids;
          return;
        }
        const newcomers = list.filter((a) => a.id && !knownIdsRef.current.has(a.id));
        knownIdsRef.current = ids;
        if (newcomers.length) openWithAttacks(newcomers);
      } catch (_) { /* polling is best-effort */ }
    };

    poll();
    const timer = setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [enabled, user?.id, openWithAttacks]);

  useEffect(() => {
    if (!enabled) return undefined;
    const onForceOpen = (event) => {
      const list = event?.detail?.attacks;
      if (!Array.isArray(list) || !list.length) return;
      for (const row of list) {
        if (!row?.id) continue;
        if (knownIdsRef.current === null) knownIdsRef.current = new Set();
        knownIdsRef.current.add(row.id);
      }
      openWithAttacks(list);
    };
    window.addEventListener(OPEN_EVENT, onForceOpen);
    return () => window.removeEventListener(OPEN_EVENT, onForceOpen);
  }, [enabled, openWithAttacks]);

  if (!enabled) return null;

  return (
    <AttackAlertModal
      open={open}
      attacks={attacks}
      onClose={close}
      showMonitoringLink={showMonitoringLink}
      onOpenMonitoring={(attackId) => {
        if (typeof onNavigate === 'function') onNavigate('monitoring');
        window.location.hash = attackId
          ? `monitoring?attack=${encodeURIComponent(attackId)}`
          : 'monitoring';
      }}
    />
  );
}

window.AttackAlertHost = AttackAlertHost;
