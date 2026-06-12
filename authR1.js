const SESSION_URL_R1 = '/api/session';
const LOGIN_URL_R1 = '/api/login';
const THEME_KEY_R1 = 'soc-theme-preference';
const SESSION_KEY_R1 = 'soc-session-state';
const CSRF_KEY_R1 = 'soc-csrf-token';

function authEl(id) {
  return document.getElementById(id);
}

function authSafeText(value, max = 180) {
  return String(value ?? '').trim().slice(0, max);
}

function applyAuthTheme(theme) {
  const normalized = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', normalized);
  localStorage.setItem(THEME_KEY_R1, normalized);
  const button = authEl('theme-toggle');
  if (button) {
    button.textContent = normalized === 'dark' ? 'Light Mode' : 'Dark Mode';
  }
}

function authToast(message, type = 'ok', duration = 3200) {
  const area = authEl('toast-area');
  if (!area) {
    return;
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  const icon = document.createElement('span');
  icon.className = 'toast-icon';
  icon.textContent = type === 'crit' ? '!' : type === 'warn' ? '!' : '+';
  const body = document.createElement('span');
  body.className = 'toast-msg';
  body.textContent = authSafeText(message, 220);
  const close = document.createElement('button');
  close.className = 'toast-close';
  close.type = 'button';
  close.textContent = 'x';
  close.addEventListener('click', () => toast.remove());

  toast.append(icon, body, close);
  area.appendChild(toast);
  window.setTimeout(() => toast.remove(), duration);
}

async function authFetch(url, options = {}, includeCsrf = false) {
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (includeCsrf) {
    const token = sessionStorage.getItem(CSRF_KEY_R1);
    if (token) {
      headers.set('X-CSRF-TOKEN', token);
    }
  }

  const response = await fetch(url, {
    ...options,
    credentials: 'same-origin',
    cache: 'no-store',
    headers,
  });

  const isJson = response.headers.get('content-type')?.includes('application/json');
  const payload = isJson ? await response.json() : null;

  if (!response.ok) {
    const error = new Error(payload?.message || `Request failed with ${response.status}`);
    error.payload = payload;
    throw error;
  }

  return payload;
}

function persistAuthSession(payload) {
  if (payload?.csrfToken) {
    sessionStorage.setItem(CSRF_KEY_R1, payload.csrfToken);
  }
  sessionStorage.setItem(SESSION_KEY_R1, JSON.stringify(payload));
}

function setAuthError(message = '') {
  const panel = authEl('auth-error');
  if (!panel) {
    return;
  }

  if (!message) {
    panel.textContent = '';
    panel.classList.remove('show');
    return;
  }

  panel.textContent = authSafeText(message, 220);
  panel.classList.add('show');
}

async function bootstrapAuthPage() {
    const theme = localStorage.getItem(THEME_KEY_R1) || 'dark';
    applyAuthTheme(theme);

    try {
        const payload = await authFetch(SESSION_URL_R1);
        persistAuthSession(payload);

        if (payload?.authenticated) {
            window.location.assign('/');
        }
    } catch (error) {
        setAuthError(error.message || 'Unable to contact the SOC backend.');
        authToast(error.message || 'Unable to contact the SOC backend.', 'crit');
    }
}

async function submitLogin(event) {
  event.preventDefault();
  setAuthError('');

  const email = authSafeText(authEl('login-email').value, 120).toLowerCase();
  const password = authSafeText(authEl('login-password').value, 120);

  if (!email || !password) {
    setAuthError('Email and password are required.');
    return;
  }

  if (password.length < 10) {
    setAuthError('Password must be at least 10 characters.');
    return;
  }

  const submit = authEl('login-submit');
  submit.disabled = true;
  submit.textContent = 'Signing In...';

  try {
    const payload = await authFetch(LOGIN_URL_R1, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    }, true);

    persistAuthSession(payload);
    authToast('Authenticated successfully.', 'ok');
    window.location.assign('/');
  } catch (error) {
    setAuthError(error.message || 'Login failed.');
    authToast(error.message || 'Login failed.', 'crit');
  } finally {
    submit.disabled = false;
    submit.textContent = 'Sign In';
  }
}

window.addEventListener('DOMContentLoaded', () => {
  void bootstrapAuthPage();
  authEl('login-form').addEventListener('submit', submitLogin);
  authEl('theme-toggle').addEventListener('click', () => {
    const nextTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyAuthTheme(nextTheme);
  });
});
