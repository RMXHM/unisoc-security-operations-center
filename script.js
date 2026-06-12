const API = {
  session: '/api/session',
  login: '/api/login',
  logout: '/api/logout',
  logs: '/api/logs',
  summary: '/api/dashboard-summary',
  blockIp: '/api/block-ip',
  unblockIp: '/api/unblock-ip',
  banUser: '/api/ban-user',
  markSuspicious: '/api/mark-suspicious',
  deleteLog: (id) => `/api/log/${id}`,
};

const POLL_INTERVAL_MS = 5000;
const FETCH_TIMEOUT_MS = 7000;
const TABLE_PAGE_SIZE = 12;
const RECENT_LOG_LIMIT = 8;
const EXPORT_PAGE_SIZE = 250;
const VALID_RISKS = ['low', 'medium', 'high', 'critical'];
const VALID_STATUSES = ['success', 'failed', 'blocked', 'suspicious'];
const THEME_KEY = 'soc-theme-preference';
const SESSION_KEY = 'soc-session-state';
const CSRF_KEY = 'soc-csrf-token';

const THREAT_PATTERNS = [
  { name: 'SQL Injection', severity: 'CRITICAL', regex: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|TABLE|WHERE|VALUES)\b|'[\s\S]*--|;[\s\S]*--|\/\*[\s\S]*\*\/|1=1|1='1|OR\s+1|AND\s+1)/i },
  { name: 'XSS Reflected', severity: 'CRITICAL', regex: /<scrip[\s\S]*?>|<\/script>|javascript\s*:|on\w+\s*=|eval\s*\(|document\.cookie|window\.location/i },
  { name: 'Command Injection', severity: 'CRITICAL', regex: /[|;&`]|\$\(|`[\s\S]*`|\b(ls|cat|wget|curl|nc|bash|sh|python|perl|ruby|php)\b/i },
  { name: 'Path Traversal', severity: 'HIGH', regex: /\.\.[/\\]|%2e%2e[%2f%5c]|%252e|\.\.%2f/i },
  { name: 'Template Injection', severity: 'HIGH', regex: /\{\{[\s\S]*\}\}|\$\{[\s\S]*\}|<%[\s\S]*%>/ },
  { name: 'NoSQL Injection', severity: 'HIGH', regex: /\$ne|\$gt|\$lt|\$regex|"\s*\$where\s*"/i },
  { name: 'SSRF Probe', severity: 'MEDIUM', regex: /(127\.0\.0\.1|169\.254\.169\.254|localhost|metadata\.)/i },
  { name: 'Fuzzing Pattern', severity: 'MEDIUM', regex: /[^\x00-\x7F]{3,}|(.)\1{20,}|%[0-9a-f]{2}(%[0-9a-f]{2}){3,}/i },
];

const IP_DB = {
  '203.45.67.89': { country: 'China', isp: 'Alibaba Cloud', type: 'Credential attack node', score: 94, verdict: 'MALICIOUS' },
  '91.108.4.55': { country: 'Russia', isp: 'Telegram Network', type: 'Reconnaissance node', score: 45, verdict: 'SUSPICIOUS' },
  '45.33.12.99': { country: 'United States (VPS)', isp: 'Linode', type: 'Honeypot scanner', score: 78, verdict: 'MALICIOUS' },
  '5.188.206.4': { country: 'Russia', isp: 'Hosting Provider', type: 'Command injection bot', score: 99, verdict: 'MALICIOUS' },
  '185.220.101.1': { country: 'Germany (Tor)', isp: 'Tor Exit Node', type: 'Anonymous exit traffic', score: 60, verdict: 'SUSPICIOUS' },
  '192.168.10.14': { country: 'Campus Network', isp: 'University LAN', type: 'Authorized admin workstation', score: 4, verdict: 'CLEAN' },
};

const viewTitles = {
  overview: 'Security Overview',
  logs: 'Activity Logs',
  alerts: 'Security Alerts',
  scanner: 'Input Scanner',
  intel: 'Threat Intelligence',
  anomaly: 'Anomaly Detection',
  honeypot: 'Honeypot Monitor',
  export: 'Log Export',
};

const rateLimits = {};
const state = {
  currentView: 'overview',
  session: null,
  csrfToken: sessionStorage.getItem(CSRF_KEY) || '',
  theme: localStorage.getItem(THEME_KEY) || 'dark',
  filters: {
    search: '',
    ip: '',
    user: '',
    event: '',
    risk: '',
    status: '',
  },
  tablePage: 1,
  tableMeta: { page: 1, per_page: TABLE_PAGE_SIZE, total: 0 },
  tableLogs: [],
  recentLogs: [],
  summary: {
    metrics: {
      security_score: 0,
      total_attacks: 0,
      active_threats: 0,
      failed_logins: 0,
      requests_per_minute: 0,
      blocked_ips: 0,
      banned_users: 0,
    },
    alerts: [],
    timeline: { labels: [], sql: [], xss: [], brute: [], recon: [] },
    top_attackers: [],
    anomalies: [],
    honeypot_hits: [],
    recent_actions: [],
  },
  previousRecentIds: new Set(),
  freshIds: new Set(),
  dismissedAlerts: new Set(),
  pollingHandle: null,
  fetchToken: 0,
  fetchInFlight: false,
  chart: null,
};

function $(id) {
  return document.getElementById(id);
}

function sanitize(value) {
  const element = document.createElement('div');
  element.textContent = String(value ?? '');
  return element.innerHTML;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function guardLength(value, max = 120) {
  return typeof value === 'string' && value.length <= max;
}

function safeText(value, max = 120) {
  return String(value ?? '').trim().slice(0, max);
}

function parseDate(value) {
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }

    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

function isValidIPv6(ip) {
  return /^(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:)|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:))$/.test(ip);
}

function isValidIP(ip) {
  return typeof ip === 'string' && (isValidIPv4(ip) || isValidIPv6(ip));
}

function isPrivateNetwork(ip) {
  return ip.startsWith('10.')
    || ip.startsWith('192.168.')
    || /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip);
}

function rateLimit(key, max, windowMs) {
  const now = Date.now();
  rateLimits[key] = (rateLimits[key] || []).filter((timestamp) => now - timestamp < windowMs);
  if (rateLimits[key].length >= max) {
    return false;
  }

  rateLimits[key].push(now);
  return true;
}

function isBot() {
  return $('hp-username')?.value.length > 0;
}

function detectThreats(input) {
  return THREAT_PATTERNS.filter((pattern) => pattern.regex.test(input));
}

function formatClockDate(date) {
  return date.toLocaleString('en-US', {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatTableTime(date) {
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatShortTime(date) {
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatRelativeTime(date) {
  const diff = Date.now() - date.getTime();
  const minutes = Math.max(1, Math.round(diff / 60000));
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.round(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  return `${Math.round(hours / 24)}d ago`;
}

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) {
    element.className = className;
  }
  if (typeof text === 'string') {
    element.textContent = text;
  }
  return element;
}

function clearElement(element) {
  if (element) {
    element.replaceChildren();
  }
}

function showToast(message, type = 'ok', duration = 3600) {
  const area = $('toast-area');
  if (!area) {
    return;
  }

  const toast = createElement('div', `toast toast-${type}`);
  const icon = createElement('span', 'toast-icon', type === 'crit' ? '!' : type === 'warn' ? '!' : '+');
  const body = createElement('span', 'toast-msg', safeText(message, 220));
  const close = createElement('button', 'toast-close', 'x');
  close.type = 'button';
  close.addEventListener('click', () => toast.remove());

  toast.append(icon, body, close);
  area.appendChild(toast);
  window.setTimeout(() => toast.remove(), duration);
}

function applyTheme(theme) {
  state.theme = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', state.theme);
  localStorage.setItem(THEME_KEY, state.theme);
  const button = $('theme-toggle');
  if (button) {
    button.textContent = state.theme === 'dark' ? 'Light Mode' : 'Dark Mode';
  }
}

function updateClock() {
  $('topbar-clock').textContent = formatClockDate(new Date());
}

function updateDataStatus(mode, message = '') {
  const pill = $('data-status-pill');
  const label = $('data-status-label');
  const banner = $('data-source-banner');
  const activityBadge = $('activity-live-badge');

  if (!pill || !label || !banner) {
    return;
  }

  pill.classList.remove('is-syncing', 'is-degraded');
  banner.classList.remove('show', 'is-degraded');

  if (mode === 'syncing') {
    pill.classList.add('is-syncing');
    label.textContent = 'SYNCING API';
    banner.textContent = message || 'Refreshing authenticated telemetry from the Laravel backend.';
    banner.classList.add('show');
    if (activityBadge) {
      activityBadge.textContent = 'SYNCING';
    }
    return;
  }

  if (mode === 'degraded') {
    pill.classList.add('is-degraded');
    label.textContent = 'DEGRADED';
    banner.textContent = message || 'The SOC API is temporarily unavailable. Existing data remains visible until the next successful refresh.';
    banner.classList.add('show', 'is-degraded');
    if (activityBadge) {
      activityBadge.textContent = 'DEGRADED';
    }
    return;
  }

  label.textContent = 'LIVE API';
  if (activityBadge) {
    activityBadge.textContent = 'LIVE API';
  }
}

function buildStatusTag(status) {
  const normalized = safeText(status, 16).toLowerCase();
  const map = {
    success: ['tag-ok', 'SUCCESS'],
    failed: ['tag-fail', 'FAILED'],
    blocked: ['tag-block', 'BLOCKED'],
    suspicious: ['tag-warn', 'SUSPICIOUS'],
  };
  const [cls, text] = map[normalized] || ['tag-warn', normalized.toUpperCase()];
  return createElement('span', `status-tag ${cls}`, text);
}

function buildRiskTag(risk) {
  const normalized = safeText(risk, 16).toLowerCase();
  const map = {
    low: ['tag-ok', 'LOW'],
    medium: ['tag-warn', 'MEDIUM'],
    high: ['tag-fail', 'HIGH'],
    critical: ['tag-block', 'CRITICAL'],
  };
  const [cls, text] = map[normalized] || ['tag-warn', normalized.toUpperCase()];
  return createElement('span', `status-tag ${cls}`, text);
}

function normalizeLogRecord(record) {
  if (!record || typeof record !== 'object') {
    return null;
  }

  const user = safeText(record.user, 120);
  const event = safeText(record.event, 120);
  const ip = safeText(record.ip, 45);
  const risk = safeText(record.risk, 16).toLowerCase();
  const status = safeText(record.status, 16).toLowerCase();
  const timestamp = parseDate(record.timestamp);
  const id = Number(record.id);

  if (!user || !event || !ip || !VALID_RISKS.includes(risk) || !VALID_STATUSES.includes(status) || !timestamp || !Number.isFinite(id) || !isValidIP(ip)) {
    return null;
  }

  return {
    id,
    user,
    event,
    ip,
    risk,
    status,
    timestamp,
    ip_blocked: Boolean(record.ip_blocked),
    user_banned: Boolean(record.user_banned),
  };
}

function normalizeLogs(payload) {
  const records = Array.isArray(payload) ? payload : [];
  return records
    .map(normalizeLogRecord)
    .filter(Boolean)
    .sort((left, right) => right.timestamp - left.timestamp || right.id - left.id);
}

function getStoredSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function persistSession(payload) {
  state.session = payload;
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(payload));
  if (payload?.csrfToken) {
    state.csrfToken = payload.csrfToken;
    sessionStorage.setItem(CSRF_KEY, payload.csrfToken);
  }
}

async function fetchJson(url, options = {}, includeCsrf = false) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');

  if (includeCsrf && state.csrfToken) {
    headers.set('X-CSRF-TOKEN', state.csrfToken);
  }

  try {
    const response = await fetch(url, {
      ...options,
      credentials: 'same-origin',
      cache: 'no-store',
      headers,
      signal: controller.signal,
    });

    const isJson = response.headers.get('content-type')?.includes('application/json');
    const payload = isJson ? await response.json() : null;

    if (response.status === 401) {
      redirectToLogin();
      throw new Error('Unauthenticated session');
    }

    if (!response.ok) {
      const message = payload?.message || `Request failed with ${response.status}`;
      const error = new Error(message);
      error.payload = payload;
      throw error;
    }

    return payload;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

function redirectToLogin() {
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(CSRF_KEY);
  window.location.assign('/login');
}

async function bootstrapSession() {
  const payload = await fetchJson(API.session);
  if (!payload?.authenticated) {
    redirectToLogin();
    return false;
  }

  persistSession(payload);
  updateOperatorIdentity(payload.user);
  return true;
}

function updateOperatorIdentity(user) {
  const email = user?.email || getStoredSession()?.user?.email || 'admin@university.edu';
  const name = user?.name || getStoredSession()?.user?.name || 'SOC Administrator';
  $('operator-chip').textContent = email;
  $('role-name').textContent = name;
  $('role-tag').textContent = 'ADMIN SOC ACCESS';
  $('role-avatar').textContent = 'AD';
  $('operator-note').textContent = `Authenticated admin workspace for ${email}. All containment actions are written to the audit trail.`;
}

function setView(view) {
  state.currentView = view;
  document.querySelectorAll('.view-section').forEach((section) => {
    section.classList.toggle('hidden-view', section.id !== `view-${view}`);
  });
  document.querySelectorAll('.nav-item[data-view]').forEach((button) => {
    button.classList.toggle('active', button.dataset.view === view);
  });
  $('view-title').textContent = viewTitles[view] || 'SOC Workspace';
}

function setGlobalSearch(value) {
  if (!guardLength(value, 120)) {
    return;
  }

  state.filters.search = safeText(value, 120);
  $('log-search').value = state.filters.search;
  state.tablePage = 1;
  setView('logs');
  void refreshDashboardData();
}

function updateKpis() {
  const metrics = state.summary.metrics;
  $('kpi-score').textContent = String(metrics.security_score);
  $('kpi-attacks').textContent = String(metrics.total_attacks);
  $('kpi-threats').textContent = String(metrics.active_threats);
  $('kpi-failed').textContent = String(metrics.failed_logins);
  $('kpi-blocked').textContent = String(metrics.blocked_ips);
  $('kpi-score-sub').textContent = `${metrics.requests_per_minute} requests/min across the last hour`;
  $('kpi-attacks-sub').textContent = 'Last 24 hours';
  $('kpi-threats-sub').textContent = 'Last 60 minutes';
  $('kpi-failed-sub').textContent = 'Failed or blocked authentications';
  $('kpi-blocked-sub').textContent = `${metrics.banned_users} banned identities`;
}

function setFactor(fillId, valueId, value, color) {
  const fill = $(fillId);
  const label = $(valueId);
  const bounded = clamp(Math.round(value), 0, 100);
  fill.style.width = `${bounded}%`;
  fill.style.background = color;
  label.textContent = String(bounded);
}

function updateScore() {
  const score = clamp(Number(state.summary.metrics.security_score || 0), 0, 100);
  const circumference = 2 * Math.PI * 52;
  const offset = circumference - ((score / 100) * circumference);
  const ring = $('score-ring');
  const scoreDisplay = $('score-display');
  ring.style.strokeDashoffset = String(offset);
  ring.style.stroke = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--amber)' : 'var(--red)';
  scoreDisplay.textContent = String(score);
  scoreDisplay.className = `score-big ${score >= 80 ? 'text-green' : score >= 60 ? 'text-amber' : 'text-red'}`;

  const metrics = state.summary.metrics;
  setFactor('f1', 'f1v', 92, 'var(--green)');
  setFactor('f2', 'f2v', clamp(100 - (state.summary.alerts.length * 8), 40, 96), metrics.active_threats > 4 ? 'var(--amber)' : 'var(--green)');
  setFactor('f3', 'f3v', clamp((metrics.blocked_ips * 12) + (metrics.banned_users * 10), 30, 98), metrics.blocked_ips > 0 ? 'var(--green)' : 'var(--amber)');
  setFactor('f4', 'f4v', clamp(65 + Math.min(30, metrics.requests_per_minute), 0, 100), 'var(--blue)');
  setFactor('f5', 'f5v', 95, 'var(--green)');
}

function updateChart() {
  if (!state.chart) {
    return;
  }

  const timeline = state.summary.timeline || { labels: [], sql: [], xss: [], brute: [], recon: [] };
  state.chart.data.labels = timeline.labels;
  state.chart.data.datasets[0].data = timeline.sql;
  state.chart.data.datasets[1].data = timeline.xss;
  state.chart.data.datasets[2].data = timeline.brute;
  state.chart.data.datasets[3].data = timeline.recon;
  state.chart.update();

  const totalSeries = [...timeline.sql, ...timeline.xss, ...timeline.brute, ...timeline.recon];
  const totalAttacks = totalSeries.reduce((sum, value) => sum + Number(value || 0), 0);
  $('attack-count-badge').textContent = totalAttacks > 0 ? `${totalAttacks} EVENTS` : 'QUIET';
}

function buildEmptyState(message) {
  return createElement('div', 'empty-state', message);
}

function renderAlerts(containerId) {
  const container = $(containerId);
  clearElement(container);
  const alerts = state.summary.alerts.filter((alert) => !state.dismissedAlerts.has(String(alert.id)));

  if (!alerts.length) {
    container.appendChild(buildEmptyState('No active alerts in the current telemetry window.'));
    return;
  }

  alerts.forEach((alert) => {
    const severityClass = alert.severity === 'critical' ? 'alert-crit' : alert.severity === 'warning' ? 'alert-warn' : 'alert-info';
    const item = createElement('div', `alert-item ${severityClass}`);
    const icon = createElement('span', 'banner-icon', alert.severity === 'critical' ? '!' : alert.severity === 'warning' ? '!' : '+');
    const body = createElement('div', 'flex1');
    body.append(
      createElement('div', 'alert-msg', safeText(alert.message, 220)),
      createElement('div', 'alert-time', formatRelativeTime(parseDate(alert.created_at) || new Date()))
    );

    const dismiss = createElement('button', 'alert-dismiss', 'x');
    dismiss.type = 'button';
    dismiss.addEventListener('click', () => {
      state.dismissedAlerts.add(String(alert.id));
      renderAlerts('alerts-container');
      renderAlerts('alerts-view-body');
      updateAlertCounters();
    });

    item.append(icon, body, dismiss);
    container.appendChild(item);
  });
}

function updateAlertCounters() {
  const visibleCount = state.summary.alerts.filter((alert) => !state.dismissedAlerts.has(String(alert.id))).length;
  $('alert-badge').textContent = String(visibleCount);
  $('alert-count-badge').textContent = `${visibleCount} ACTIVE`;
  $('alerts-view-count').textContent = `${visibleCount} active`;
  $('intel-badge').textContent = String(state.summary.top_attackers.length);
}

function createCell(text, className = '') {
  const cell = document.createElement('td');
  if (className) {
    cell.className = className;
  }
  cell.textContent = text;
  return cell;
}

function buildWrappedCell(child) {
  const cell = document.createElement('td');
  cell.appendChild(child);
  return cell;
}

function isThreatLog(log) {
  return ['blocked', 'suspicious'].includes(log.status) || ['high', 'critical'].includes(log.risk);
}

function renderOverviewLogs() {
  const body = $('overview-log-body');
  clearElement(body);

  if (!state.recentLogs.length) {
    const row = document.createElement('tr');
    const cell = createElement('td', 'empty-state', 'No authenticated log data available.');
    cell.colSpan = 5;
    row.appendChild(cell);
    body.appendChild(row);
  } else {
    state.recentLogs.forEach((log) => {
      const row = document.createElement('tr');
      if (state.freshIds.has(log.id)) {
        row.classList.add('log-row-fresh');
      }
      if (isThreatLog(log)) {
        row.classList.add('threat-row');
      }

      row.append(
        createCell(log.user, 'mono'),
        createCell(log.event),
        createCell(log.ip, 'mono'),
        buildWrappedCell(buildRiskTag(log.risk)),
        createCell(formatTableTime(log.timestamp), 'mono')
      );
      body.appendChild(row);
    });
  }

  $('log-badge').textContent = String(state.tableMeta.total || state.recentLogs.length);
}

function buildActionButton(action, label, logId, disabled = false, critical = false) {
  const button = createElement('button', `log-action-btn${critical ? ' critical' : ''}`, label);
  button.type = 'button';
  button.dataset.action = action;
  button.dataset.logId = String(logId);
  button.disabled = disabled;
  return button;
}

function buildActionCell(log) {
  const cell = document.createElement('td');
  const row = createElement('div', 'log-action-row');
  row.append(
    buildActionButton(log.ip_blocked ? 'unblock-ip' : 'block-ip', log.ip_blocked ? 'Unblock IP' : 'Block IP', log.id),
    buildActionButton('ban-user', 'Ban User', log.id, log.user_banned),
    buildActionButton('mark-suspicious', 'Mark Suspicious', log.id, log.status === 'suspicious'),
    buildActionButton('delete-log', 'Delete', log.id, false, true)
  );
  cell.appendChild(row);
  return cell;
}

function renderLogTable() {
  const body = $('full-log-body');
  clearElement(body);
  $('full-log-count').textContent = `${state.tableMeta.total} entries`;

  if (!state.tableLogs.length) {
    const row = document.createElement('tr');
    const cell = createElement('td', 'empty-state', 'No logs matched the active filters.');
    cell.colSpan = 8;
    row.appendChild(cell);
    body.appendChild(row);
  } else {
    state.tableLogs.forEach((log) => {
      const row = document.createElement('tr');
      row.dataset.logId = String(log.id);
      if (state.freshIds.has(log.id)) {
        row.classList.add('log-row-fresh');
      }
      if (isThreatLog(log)) {
        row.classList.add('threat-row');
      }

      row.append(
        createCell(String(log.id), 'mono'),
        createCell(log.user, 'mono'),
        createCell(log.event),
        createCell(log.ip, 'mono'),
        buildWrappedCell(buildRiskTag(log.risk)),
        buildWrappedCell(buildStatusTag(log.status)),
        createCell(formatTableTime(log.timestamp), 'mono'),
        buildActionCell(log)
      );
      body.appendChild(row);
    });
  }

  const totalPages = Math.max(1, Math.ceil((state.tableMeta.total || 0) / state.tableMeta.per_page));
  $('page-info').textContent = `Page ${state.tableMeta.page} of ${totalPages}`;
  $('log-prev').disabled = state.tableMeta.page <= 1;
  $('log-next').disabled = state.tableMeta.page >= totalPages;
}

function lookupThreatIntel(ip) {
  if (IP_DB[ip]) {
    return IP_DB[ip];
  }

  if (isPrivateNetwork(ip)) {
    return {
      country: 'Campus Network',
      isp: 'University LAN',
      type: 'Internal address',
      score: 5,
      verdict: 'CLEAN',
    };
  }

  return {
    country: 'Unknown',
    isp: 'Unknown ISP',
    type: 'Unclassified source',
    score: 24,
    verdict: 'CLEAN',
  };
}

function renderThreatIntel() {
  const topAttackers = $('top-attackers-body');
  const intelSummary = $('intel-summary-body');
  const recentActions = $('recent-actions-body');
  clearElement(topAttackers);
  clearElement(intelSummary);
  clearElement(recentActions);

  if (!state.summary.top_attackers.length) {
    topAttackers.appendChild(buildEmptyState('No active attacking sources detected.'));
  } else {
    const maxCount = state.summary.top_attackers[0]?.count || 1;
    state.summary.top_attackers.forEach((attacker) => {
      const intel = lookupThreatIntel(attacker.ip);
      const item = createElement('div', 'intel-item');
      item.append(
        createElement('div', 'intel-country', `${intel.country} | ${attacker.ip}`),
        createElement('div', 'intel-count', String(attacker.count)),
        createElement('div', 'intel-type', `${intel.type} | ${attacker.latest_event} | ${attacker.blocked ? 'Blocked' : 'Active'}`)
      );
      const bar = createElement('div', 'intel-bar');
      const fill = createElement('div', 'intel-bar-fill');
      fill.style.width = `${Math.round((attacker.count / maxCount) * 100)}%`;
      bar.appendChild(fill);
      item.appendChild(bar);
      topAttackers.appendChild(item);
    });
  }

  const summaryItems = [
    `Active threats: ${state.summary.metrics.active_threats}`,
    `Blocked IPs: ${state.summary.metrics.blocked_ips}`,
    `Failed logins: ${state.summary.metrics.failed_logins}`,
    `Requests/min: ${state.summary.metrics.requests_per_minute}`,
  ];
  const summaryList = createElement('div', 'intel-summary-list');
  summaryItems.forEach((text) => {
    summaryList.appendChild(createElement('div', 'intel-summary-item', text));
  });
  intelSummary.appendChild(summaryList);

  if (!state.summary.recent_actions.length) {
    recentActions.appendChild(buildEmptyState('No audited SOC actions have been recorded yet.'));
  } else {
    const list = createElement('div', 'recent-actions-list');
    state.summary.recent_actions.forEach((audit) => {
      const item = createElement('div', 'action-audit-item');
      item.append(
        createElement('div', 'action-audit-title', `${audit.action} | ${audit.target_type}: ${audit.target_value}`),
        createElement('div', 'action-audit-meta', `${audit.actor_email} | ${formatRelativeTime(parseDate(audit.created_at) || new Date())}`)
      );
      list.appendChild(item);
    });
    recentActions.appendChild(list);
  }
}

function renderAnomalies() {
  const body = $('anomaly-table');
  clearElement(body);

  state.summary.anomalies.forEach((anomaly) => {
    const row = document.createElement('tr');
    const user = createCell(anomaly.user, 'mono');
    const statusCell = buildWrappedCell(buildStatusTag(anomaly.label === 'BLOCKED' ? 'blocked' : anomaly.label === 'NORMAL' ? 'success' : 'suspicious'));
    const trigger = createCell(anomaly.trigger);
    trigger.style.color = 'var(--text1)';
    const score = createCell(String(anomaly.score), `mono ${anomaly.score >= 85 ? 'text-red' : anomaly.score >= 60 ? 'text-amber' : 'text-green'}`);
    const action = createCell(anomaly.action, 'mono');
    row.append(user, statusCell, trigger, score, action);
    body.appendChild(row);
  });
}

function renderHoneypot() {
  const container = $('hp-log');
  clearElement(container);

  if (!state.summary.honeypot_hits.length) {
    container.appendChild(buildEmptyState('No honeypot traffic in the active telemetry window.'));
    return;
  }

  state.summary.honeypot_hits.forEach((hit) => {
    const wrapper = createElement('div', 'hp-entry');
    wrapper.append(
      createElement('span', 'hp-time', formatShortTime(parseDate(hit.timestamp) || new Date())),
      createElement('span', 'hp-ip', hit.ip),
      createElement('span', 'hp-action', `${hit.event} | ${hit.status}`)
    );
    container.appendChild(wrapper);
  });
}

function updateBruteBanner() {
  const banner = $('brute-banner');
  const bruteAlert = state.summary.alerts.find((alert) => String(alert.id).startsWith('brute-'));
  if (!bruteAlert) {
    banner.classList.remove('show');
    $('brute-msg').textContent = 'Monitoring active attack patterns.';
    return;
  }

  banner.classList.add('show');
  $('brute-msg').textContent = bruteAlert.message;
}

function initChart() {
  if (typeof Chart === 'undefined') {
    return;
  }

  const canvas = $('attackChart');
  if (!canvas) {
    return;
  }

  state.chart = new Chart(canvas, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'SQL Injection', data: [], borderColor: '#ff647f', backgroundColor: 'rgba(255, 100, 127, 0.1)', tension: 0.34, pointRadius: 0, borderWidth: 1.6 },
        { label: 'XSS', data: [], borderColor: '#ffb347', backgroundColor: 'rgba(255, 179, 71, 0.1)', tension: 0.34, pointRadius: 0, borderWidth: 1.6 },
        { label: 'Brute Force', data: [], borderColor: '#b296ff', backgroundColor: 'rgba(178, 150, 255, 0.1)', tension: 0.34, pointRadius: 0, borderWidth: 1.6 },
        { label: 'Recon / Scan', data: [], borderColor: '#58b5ff', backgroundColor: 'rgba(88, 181, 255, 0.1)', tension: 0.34, pointRadius: 0, borderWidth: 1.6 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          labels: {
            color: '#92a8c4',
            font: { family: 'Cascadia Mono, Consolas, monospace', size: 11 },
          },
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(140, 170, 205, 0.08)' },
          ticks: { color: '#92a8c4', font: { family: 'Cascadia Mono, Consolas, monospace', size: 10 } },
        },
        y: {
          grid: { color: 'rgba(140, 170, 205, 0.08)' },
          ticks: { color: '#92a8c4', font: { family: 'Cascadia Mono, Consolas, monospace', size: 10 }, precision: 0 },
          beginAtZero: true,
        },
      },
    },
  });
}

function buildLogQuery(page, perPage, filters) {
  const params = new URLSearchParams();
  params.set('page', String(page));
  params.set('per_page', String(perPage));
  Object.entries(filters).forEach(([key, value]) => {
    if (value) {
      params.set(key, value);
    }
  });
  return `${API.logs}?${params.toString()}`;
}

async function fetchLogsData(page, perPage, filters = {}) {
  const payload = await fetchJson(buildLogQuery(page, perPage, filters));
  return {
    logs: normalizeLogs(payload?.data || []),
    meta: {
      page: Number(payload?.meta?.page || page),
      per_page: Number(payload?.meta?.per_page || perPage),
      total: Number(payload?.meta?.total || 0),
    },
  };
}

function updateFreshLogIds(newRecentLogs) {
  const nextIds = new Set(newRecentLogs.map((log) => log.id));
  const freshIds = new Set();
  newRecentLogs.forEach((log) => {
    if (!state.previousRecentIds.has(log.id)) {
      freshIds.add(log.id);
    }
  });
  state.previousRecentIds = nextIds;
  state.freshIds = freshIds;
}

async function refreshDashboardData({ silent = false } = {}) {
  if (state.fetchInFlight) {
    return;
  }

  state.fetchInFlight = true;
  const token = ++state.fetchToken;
  if (!silent) {
    updateDataStatus('syncing');
  }

  try {
    const [summaryPayload, recentPayload, tablePayload] = await Promise.all([
      fetchJson(API.summary),
      fetchLogsData(1, RECENT_LOG_LIMIT, {}),
      fetchLogsData(state.tablePage, TABLE_PAGE_SIZE, state.filters),
    ]);

    if (token !== state.fetchToken) {
      return;
    }

    state.summary = summaryPayload || state.summary;
    updateFreshLogIds(recentPayload.logs);
    state.recentLogs = recentPayload.logs;
    state.tableLogs = tablePayload.logs;
    state.tableMeta = tablePayload.meta;

    renderEverything();
    updateDataStatus('live');
  } catch (error) {
    updateDataStatus('degraded', safeText(error.message || 'Unable to refresh the live SOC API.', 180));
    if (!silent) {
      showToast(error.message || 'Unable to refresh authenticated telemetry.', 'warn');
    }
  } finally {
    state.fetchInFlight = false;
  }
}

function renderEverything() {
  updateKpis();
  updateScore();
  updateChart();
  renderOverviewLogs();
  renderLogTable();
  renderAlerts('alerts-container');
  renderAlerts('alerts-view-body');
  renderThreatIntel();
  renderAnomalies();
  renderHoneypot();
  updateBruteBanner();
  updateAlertCounters();
}

function attachNavHandlers() {
  document.querySelectorAll('.nav-item[data-view]').forEach((button) => {
    button.addEventListener('click', () => setView(button.dataset.view));
  });
}

function debounce(fn, delay = 260) {
  let handle = 0;
  return (...args) => {
    window.clearTimeout(handle);
    handle = window.setTimeout(() => fn(...args), delay);
  };
}

function syncFiltersFromInputs() {
  const nextFilters = {
    search: safeText($('log-search').value, 120),
    ip: safeText($('log-ip-filter').value, 45),
    user: safeText($('log-user-filter').value, 120),
    event: safeText($('log-event-filter').value, 120),
    risk: safeText($('log-risk-filter').value, 16).toLowerCase(),
    status: safeText($('log-status-filter').value, 16).toLowerCase(),
  };

  if (nextFilters.ip && !isValidIP(nextFilters.ip)) {
    showToast('Invalid IP filter value.', 'warn', 2200);
    return;
  }

  state.filters = {
    search: nextFilters.search,
    ip: nextFilters.ip,
    user: nextFilters.user,
    event: nextFilters.event,
    risk: VALID_RISKS.includes(nextFilters.risk) ? nextFilters.risk : '',
    status: VALID_STATUSES.includes(nextFilters.status) ? nextFilters.status : '',
  };
  state.tablePage = 1;
  void refreshDashboardData({ silent: true });
}

function attachFilterHandlers() {
  const debouncedFilter = debounce(syncFiltersFromInputs, 250);
  ['log-search', 'log-ip-filter', 'log-user-filter', 'log-event-filter'].forEach((id) => {
    $(id).addEventListener('input', debouncedFilter);
  });
  ['log-risk-filter', 'log-status-filter'].forEach((id) => {
    $(id).addEventListener('change', debouncedFilter);
  });

  $('global-search').addEventListener('input', debounce((event) => {
    const value = safeText(event.target.value, 120);
    if (value) {
      setGlobalSearch(value);
    }
  }, 240));
}

function attachPaginationHandlers() {
  $('log-prev').addEventListener('click', () => {
    if (state.tablePage > 1) {
      state.tablePage -= 1;
      void refreshDashboardData({ silent: true });
    }
  });

  $('log-next').addEventListener('click', () => {
    const totalPages = Math.max(1, Math.ceil((state.tableMeta.total || 0) / state.tableMeta.per_page));
    if (state.tablePage < totalPages) {
      state.tablePage += 1;
      void refreshDashboardData({ silent: true });
    }
  });
}

function getLogById(logId) {
  return state.tableLogs.find((log) => log.id === logId) || state.recentLogs.find((log) => log.id === logId) || null;
}

function updateLocalLog(logId, updater) {
  state.tableLogs = state.tableLogs.map((log) => (log.id === logId ? updater({ ...log }) : log));
  state.recentLogs = state.recentLogs.map((log) => (log.id === logId ? updater({ ...log }) : log));
}

function updateLocalByIp(ip, updater) {
  state.tableLogs = state.tableLogs.map((log) => (log.ip === ip ? updater({ ...log }) : log));
  state.recentLogs = state.recentLogs.map((log) => (log.ip === ip ? updater({ ...log }) : log));
}

function updateLocalByUser(user, updater) {
  state.tableLogs = state.tableLogs.map((log) => (log.user === user ? updater({ ...log }) : log));
  state.recentLogs = state.recentLogs.map((log) => (log.user === user ? updater({ ...log }) : log));
}

function removeLocalLog(logId) {
  state.tableLogs = state.tableLogs.filter((log) => log.id !== logId);
  state.recentLogs = state.recentLogs.filter((log) => log.id !== logId);
}

function snapshotLogs() {
  const clone = (log) => ({ ...log, timestamp: new Date(log.timestamp) });
  return {
    tableLogs: state.tableLogs.map(clone),
    recentLogs: state.recentLogs.map(clone),
  };
}

function restoreLogs(snapshot) {
  state.tableLogs = snapshot.tableLogs;
  state.recentLogs = snapshot.recentLogs;
}

async function handleLogAction(action, logId, button) {
  const log = getLogById(logId);
  if (!log) {
    return;
  }

  const snapshot = snapshotLogs();
  button.disabled = true;

  try {
    let payload;

    if (action === 'block-ip') {
      updateLocalByIp(log.ip, (entry) => ({ ...entry, ip_blocked: true, status: 'blocked' }));
      renderEverything();
      payload = await fetchJson(API.blockIp, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: log.ip, log_id: log.id, reason: 'Blocked from SOC dashboard' }),
      }, true);
    } else if (action === 'unblock-ip') {
      updateLocalByIp(log.ip, (entry) => ({ ...entry, ip_blocked: false }));
      renderEverything();
      payload = await fetchJson(API.unblockIp, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: log.ip, reason: 'Released from SOC dashboard' }),
      }, true);
    } else if (action === 'ban-user') {
      updateLocalByUser(log.user, (entry) => ({ ...entry, user_banned: true, status: 'blocked' }));
      renderEverything();
      payload = await fetchJson(API.banUser, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: log.user, log_id: log.id, reason: 'Banned from SOC dashboard' }),
      }, true);
    } else if (action === 'mark-suspicious') {
      updateLocalLog(log.id, (entry) => ({ ...entry, status: 'suspicious', risk: entry.risk === 'low' ? 'medium' : entry.risk }));
      renderEverything();
      payload = await fetchJson(API.markSuspicious, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_id: log.id, reason: 'Flagged by SOC operator' }),
      }, true);
    } else if (action === 'delete-log') {
      removeLocalLog(log.id);
      renderEverything();
      payload = await fetchJson(API.deleteLog(log.id), { method: 'DELETE' }, true);
    } else {
      return;
    }

    if (payload?.summary) {
      state.summary = payload.summary;
    }
    if (payload?.log) {
      const normalized = normalizeLogRecord(payload.log);
      if (normalized) {
        updateLocalLog(normalized.id, () => normalized);
      }
    }

    renderEverything();
    showToast(payload?.message || 'SOC action completed.', 'ok');
    void refreshDashboardData({ silent: true });
  } catch (error) {
    restoreLogs(snapshot);
    renderEverything();
    showToast(error.message || 'SOC action failed.', 'crit');
  } finally {
    button.disabled = false;
  }
}

function attachActionHandlers() {
  $('full-log-body').addEventListener('click', (event) => {
    const button = event.target.closest('.log-action-btn');
    if (!button) {
      return;
    }

    const action = button.dataset.action;
    const logId = Number(button.dataset.logId);
    if (!Number.isFinite(logId) || !action) {
      return;
    }

    void handleLogAction(action, logId, button);
  });
}

function attachScannerHandlers() {
  $('scan-btn').addEventListener('click', runScan);
  $('scan-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      runScan();
    }
  });

  document.querySelectorAll('.payload-btn').forEach((button) => {
    button.addEventListener('click', () => {
      $('scan-input').value = button.dataset.payload || '';
      $('scan-input').focus();
    });
  });

  $('ip-check-btn').addEventListener('click', checkIp);
}

function runScan() {
  if (isBot()) {
    showToast('Bot detected and request blocked.', 'crit');
    return;
  }

  if (!rateLimit('scan', 30, 60000)) {
    $('scan-rate-banner').classList.add('show');
    showToast('Too many scan requests. Slow down.', 'warn');
    return;
  }

  $('scan-rate-banner').classList.remove('show');
  const rawInput = $('scan-input').value;
  if (!guardLength(rawInput, 5000)) {
    showToast('Input too long for safe analysis.', 'warn');
    return;
  }

  const payload = rawInput.trim();
  if (!payload) {
    return;
  }

  const button = $('scan-btn');
  button.disabled = true;
  button.textContent = 'Scanning...';

  window.setTimeout(() => {
    const threats = detectThreats(payload);
    const result = $('scan-result');
    const title = $('scan-result-title');
    const detail = $('scan-result-detail');
    const threatBox = $('scan-threats');
    clearElement(threatBox);

    if (threats.length) {
      result.className = 'scan-result show threat';
      title.textContent = `${threats.length} threat pattern${threats.length > 1 ? 's' : ''} detected`;
      detail.textContent = 'Payload matches known malicious patterns. Production workflow should reject and log this request.';
      threats.forEach((threat) => {
        threatBox.appendChild(createElement('span', 'threat-tag', `${threat.name} | ${threat.severity}`));
      });
      showToast(`Scanner flagged ${threats.map((threat) => threat.name).join(', ')}`, 'warn');
    } else {
      result.className = 'scan-result show safe';
      title.textContent = 'Input appears safe';
      detail.textContent = 'No known malicious patterns were matched. Server-side validation is still required.';
    }

    button.disabled = false;
    button.textContent = 'Scan';
  }, 480);
}

function checkIp() {
  if (!rateLimit('ip-check', 20, 60000)) {
    showToast('Too many IP reputation checks. Wait a moment.', 'warn');
    return;
  }

  const input = safeText($('ip-input').value, 45);
  $('ip-input').value = input;
  if (!input) {
    return;
  }

  if (!isValidIP(input)) {
    showToast('Invalid IP address format.', 'warn');
    return;
  }

  const intel = lookupThreatIntel(input);
  $('ip-r-addr').textContent = input;
  $('ip-r-country').textContent = intel.country;
  $('ip-r-isp').textContent = intel.isp;
  $('ip-r-type').textContent = intel.type;
  $('ip-r-score').textContent = `${intel.score}/100`;
  $('ip-r-verdict').textContent = intel.verdict;
  $('ip-r-verdict').className = `ip-val ${intel.verdict === 'MALICIOUS' ? 'threat' : intel.verdict === 'CLEAN' ? 'clean' : ''}`.trim();
  $('ip-rep-fill').style.width = `${intel.score}%`;
  $('ip-rep-fill').style.background = intel.score > 70 ? 'var(--red)' : intel.score > 40 ? 'var(--amber)' : 'var(--green)';
  $('ip-result').classList.add('show');
}

async function fetchExportLogs() {
  let page = 1;
  let totalPages = 1;
  const collected = [];

  while (page <= totalPages) {
    const payload = await fetchLogsData(page, EXPORT_PAGE_SIZE, state.filters);
    collected.push(...payload.logs);
    totalPages = Math.max(1, Math.ceil((payload.meta.total || 0) / payload.meta.per_page));
    page += 1;
  }

  return collected;
}

function downloadFile(filename, content, mimeType) {
  const link = document.createElement('a');
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 500);
}

async function exportLogs(format) {
  try {
    const logs = await fetchExportLogs();
    if (!logs.length) {
      showToast('No logs available for export.', 'warn');
      return;
    }

    const datePart = new Date().toISOString().slice(0, 10);
    if (format === 'json') {
      const json = JSON.stringify(logs.map((log) => ({
        id: log.id,
        user: log.user,
        event: log.event,
        ip: log.ip,
        risk: log.risk,
        status: log.status,
        timestamp: log.timestamp.toISOString(),
        ip_blocked: log.ip_blocked,
        user_banned: log.user_banned,
      })), null, 2);
      downloadFile(`soc-logs-${datePart}.json`, json, 'application/json');
    } else {
      const header = 'ID,User,Event,IP,Risk,Status,Timestamp,IP Blocked,User Banned\n';
      const rows = logs.map((log) => [
        log.id,
        log.user,
        log.event,
        log.ip,
        log.risk,
        log.status,
        log.timestamp.toISOString(),
        log.ip_blocked ? 'true' : 'false',
        log.user_banned ? 'true' : 'false',
      ].map((value) => `"${String(value).replace(/"/g, '""')}"`).join(',')).join('\n');
      downloadFile(`soc-logs-${datePart}.csv`, `${header}${rows}`, 'text/csv');
    }

    showToast(`${format.toUpperCase()} export ready.`, 'ok');
  } catch (error) {
    showToast(error.message || 'Export failed.', 'crit');
  }
}

function attachExportHandlers() {
  document.querySelectorAll('[data-export]').forEach((button) => {
    button.addEventListener('click', () => exportLogs(button.dataset.export));
  });

  $('export-json-btn').addEventListener('click', () => exportLogs('json'));
  $('export-csv-btn').addEventListener('click', () => exportLogs('csv'));
}

function attachTopbarHandlers() {
  $('theme-toggle').addEventListener('click', () => {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark');
  });

  $('logout-btn').addEventListener('click', async () => {
    try {
      const payload = await fetchJson(API.logout, { method: 'POST' }, true);
      persistSession(payload);
      redirectToLogin();
    } catch (error) {
      showToast(error.message || 'Logout failed.', 'crit');
    }
  });

  $('view-all-logs-btn').addEventListener('click', () => setView('logs'));
}

function attachMiscHandlers() {
  window.addEventListener('storage', (event) => {
    if (event.key === THEME_KEY && event.newValue) {
      applyTheme(event.newValue);
    }
  });
}

async function initializeDashboard() {
  applyTheme(state.theme);
  updateClock();
  window.setInterval(updateClock, 1000);
  initChart();
  attachNavHandlers();
  attachFilterHandlers();
  attachPaginationHandlers();
  attachActionHandlers();
  attachScannerHandlers();
  attachExportHandlers();
  attachTopbarHandlers();
  attachMiscHandlers();
  setView('overview');
  updateDataStatus('syncing');

  const sessionOk = await bootstrapSession();
  if (!sessionOk) {
    return;
  }

  const storedSession = getStoredSession();
  if (storedSession?.user) {
    updateOperatorIdentity(storedSession.user);
  }

  await refreshDashboardData();
  state.pollingHandle = window.setInterval(() => {
    void refreshDashboardData({ silent: true });
  }, POLL_INTERVAL_MS);
}

window.addEventListener('DOMContentLoaded', () => {
  void initializeDashboard();
});
