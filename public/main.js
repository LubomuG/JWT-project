const authView = document.getElementById('auth-view');
const userView = document.getElementById('user-view');
const authForm = document.getElementById('auth-form');
const passwordForm = document.getElementById('password-form');
const message = document.getElementById('message');
const passwordMessage = document.getElementById('password-message');
const submitButton = document.getElementById('submit-btn');
const loginTab = document.getElementById('login-tab');
const registerTab = document.getElementById('register-tab');
let mode = 'login';

async function rawRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  const data = await response.json().catch(() => ({}));
  return { response, data };
}

async function api(url, options = {}, canRefresh = true) {
  let { response, data } = await rawRequest(url, options);
  if (response.status === 401 && canRefresh && !['/api/login', '/api/register', '/api/refresh'].includes(url)) {
    const refresh = await rawRequest('/api/refresh', { method: 'POST' });
    if (refresh.response.ok) ({ response, data } = await rawRequest(url, options));
    else data = refresh.data;
  }
  if (!response.ok) throw new Error(data.error || 'Сталася помилка. Спробуйте ще раз.');
  return data;
}

function setMode(nextMode) {
  mode = nextMode;
  const login = mode === 'login';
  loginTab.classList.toggle('active', login);
  registerTab.classList.toggle('active', !login);
  loginTab.setAttribute('aria-pressed', String(login));
  registerTab.setAttribute('aria-pressed', String(!login));
  submitButton.textContent = login ? 'Увійти' : 'Зареєструватися';
  authForm.elements.password.autocomplete = login ? 'current-password' : 'new-password';
  message.textContent = '';
}

function formatExpiry(seconds) {
  return new Intl.DateTimeFormat('uk-UA', { timeStyle: 'short' })
    .format(new Date(seconds * 1000));
}

async function showUser() {
  const user = await api('/api/me');
  document.getElementById('username').textContent = user.username;
  document.getElementById('role-label').textContent = user.role === 'admin' ? 'Адміністратор' : 'Користувач';
  document.getElementById('session-expiry').textContent = `Сесія діє до ${formatExpiry(user.exp)}`;
  authView.hidden = true;
  userView.hidden = false;
  const adminPanel = document.getElementById('admin-panel');
  adminPanel.hidden = user.role !== 'admin';
  if (user.role === 'admin') {
    const adminData = await api('/api/admin');
    document.getElementById('admin-message').textContent = adminData.message;
  }
}

loginTab.addEventListener('click', () => setMode('login'));
registerTab.addEventListener('click', () => setMode('register'));

authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.textContent = '';
  submitButton.disabled = true;
  const data = new FormData(authForm);
  try {
    await api(`/api/${mode}`, {
      method: 'POST',
      body: JSON.stringify({ username: data.get('username').trim(), password: data.get('password') }),
    }, false);
    authForm.reset();
    await showUser();
  } catch (error) {
    message.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
});

passwordForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  passwordMessage.textContent = '';
  const data = new FormData(passwordForm);
  try {
    const result = await api('/api/change-password', {
      method: 'POST',
      body: JSON.stringify({ oldPassword: data.get('oldPassword'), newPassword: data.get('newPassword') }),
    });
    passwordMessage.textContent = result.message;
    passwordForm.reset();
    await api('/api/logout', { method: 'POST' }, false);
    userView.hidden = true;
    authView.hidden = false;
    setMode('login');
  } catch (error) {
    passwordMessage.textContent = error.message;
  }
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' }, false);
  } finally {
    userView.hidden = true;
    authView.hidden = false;
    setMode('login');
  }
});

showUser().catch(() => {
  userView.hidden = true;
  authView.hidden = false;
});
