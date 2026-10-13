require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true, minlength: 3, maxlength: 40 },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user', required: true },
  refreshTokenHash: { type: String, default: null },
  adminPasswordReset: { type: Boolean, default: false },
}, { timestamps: true }));
const LoginAttempt = mongoose.model('LoginAttempt', new mongoose.Schema({
  usernameKey: { type: String, required: true, unique: true },
  failedCount: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
}, { timestamps: true }));

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
const ACCESS_COOKIE = 'accessToken';
const REFRESH_COOKIE = 'refreshToken';
const ACCESS_TTL_MS = 15 * 60 * 1000;
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const cookieOptions = { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' };

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function signAccessToken(user) {
  return jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, {
    subject: user.id,
    expiresIn: '15m',
  });
}

function signRefreshToken(user) {
  return jwt.sign({ type: 'refresh', jti: crypto.randomUUID() }, JWT_SECRET, {
    subject: user.id,
    expiresIn: '7d',
  });
}

async function issueSession(user, res) {
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  user.refreshTokenHash = hashToken(refreshToken);
  await user.save();
  res.cookie(ACCESS_COOKIE, accessToken, { ...cookieOptions, maxAge: ACCESS_TTL_MS });
  res.cookie(REFRESH_COOKIE, refreshToken, { ...cookieOptions, maxAge: REFRESH_TTL_MS });
  return jwt.decode(accessToken).exp;
}

function requireAuth(req, res, next) {
  const token = req.cookies[ACCESS_COOKIE];
  if (!token) return res.status(401).json({ error: 'Потрібно увійти' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Сесія потребує оновлення' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ лише для адміністратора' });
  next();
}

function clearSessionCookies(res) {
  res.clearCookie(ACCESS_COOKIE, cookieOptions);
  res.clearCookie(REFRESH_COOKIE, cookieOptions);
}

app.post('/api/register', async (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (username.length < 3 || username.length > 40 || password.length < 6) {
    return res.status(400).json({ error: 'Логін має містити 3–40 символів, пароль — щонайменше 6' });
  }
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const role = ADMIN_USERNAME && username.toLowerCase() === ADMIN_USERNAME ? 'admin' : 'user';
    const user = await User.create({ username, passwordHash, role });
    const exp = await issueSession(user, res);
    res.status(201).json({ username: user.username, role: user.role, exp });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'Такий логін уже є' });
    console.error('Registration failed:', error.message);
    res.status(500).json({ error: 'Не вдалося створити акаунт' });
  }
});

app.post('/api/login', async (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!username || !password) return res.status(400).json({ error: 'Введіть логін і пароль' });
  const key = username.toLowerCase();
  try {
    const attempt = await LoginAttempt.findOne({ usernameKey: key });
    if (attempt?.lockUntil && attempt.lockUntil > new Date()) {
      const seconds = Math.ceil((attempt.lockUntil.getTime() - Date.now()) / 1000);
      return res.status(429).json({ error: `Забагато спроб. Спробуйте через ${seconds} с.` });
    }

    const user = await User.findOne({ username: new RegExp(`^${username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') });
    const valid = user && await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      const nextCount = (attempt?.failedCount || 0) + 1;
      await LoginAttempt.findOneAndUpdate(
        { usernameKey: key },
        { $set: nextCount >= 5 ? { failedCount: 0, lockUntil: new Date(Date.now() + 60_000) } : { failedCount: nextCount, lockUntil: null } },
        { upsert: true, new: true },
      );
      return res.status(401).json({ error: 'Неправильний логін або пароль' });
    }

    await LoginAttempt.deleteOne({ usernameKey: key });
    const exp = await issueSession(user, res);
    res.json({ username: user.username, role: user.role, exp });
  } catch (error) {
    console.error('Login failed:', error.message);
    res.status(500).json({ error: 'Не вдалося виконати вхід' });
  }
});

app.post('/api/refresh', async (req, res) => {
  const token = req.cookies[REFRESH_COOKIE];
  if (!token) return res.status(401).json({ error: 'Сесія завершилася. Увійдіть знову.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'refresh') throw new Error('Invalid token type');
    const user = await User.findById(payload.sub);
    if (!user || user.refreshTokenHash !== hashToken(token)) throw new Error('Refresh token revoked');
    const exp = await issueSession(user, res);
    res.json({ username: user.username, role: user.role, exp });
  } catch {
    clearSessionCookies(res);
    res.status(401).json({ error: 'Сесія завершилася. Увійдіть знову.' });
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub).select('username role');
    if (!user) return res.status(401).json({ error: 'Користувача не знайдено' });
    res.json({ username: user.username, role: user.role, exp: req.user.exp });
  } catch (error) {
    console.error('Session lookup failed:', error.message);
    res.status(500).json({ error: 'Не вдалося отримати дані сесії' });
  }
});

app.get('/api/admin', requireAuth, requireAdmin, async (req, res) => {
  res.json({ message: 'Вітаємо в панелі адміністратора', username: req.user.username });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const oldPassword = typeof req.body.oldPassword === 'string' ? req.body.oldPassword : '';
  const newPassword = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
  if (newPassword.length < 6) return res.status(400).json({ error: 'Новий пароль має містити щонайменше 6 символів' });
  try {
    const user = await User.findById(req.user.sub);
    if (!user || !(await bcrypt.compare(oldPassword, user.passwordHash))) {
      return res.status(400).json({ error: 'Старий пароль неправильний' });
    }
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    user.refreshTokenHash = null;
    await user.save();
    clearSessionCookies(res);
    res.json({ ok: true, message: 'Пароль змінено. Увійдіть з новим паролем.' });
  } catch (error) {
    console.error('Password change failed:', error.message);
    res.status(500).json({ error: 'Не вдалося змінити пароль' });
  }
});

app.post('/api/logout', async (req, res) => {
  const token = req.cookies[REFRESH_COOKIE];
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(payload.sub);
      if (user && user.refreshTokenHash === hashToken(token)) {
        user.refreshTokenHash = null;
        await user.save();
      }
    } catch {}
  }
  clearSessionCookies(res);
  res.json({ ok: true });
});

async function start() {
  if (!JWT_SECRET || !MONGODB_URI) throw new Error('Set JWT_SECRET and MONGODB_URI in .env');
  await mongoose.connect(MONGODB_URI);
  if (ADMIN_USERNAME) {
    const admin = await User.findOne({ username: ADMIN_USERNAME });
    if (!admin) {
      await User.create({ username: ADMIN_USERNAME, passwordHash: await bcrypt.hash('11111111', 10), role: 'admin', adminPasswordReset: true });
      console.log(`Створено адміністратора ${ADMIN_USERNAME} з новим паролем.`);
    } else if (!admin.adminPasswordReset) {
      admin.passwordHash = await bcrypt.hash('11111111', 10);
      admin.role = 'admin';
      admin.refreshTokenHash = null;
      admin.adminPasswordReset = true;
      await admin.save();
      console.log(`Пароль адміністратора ${ADMIN_USERNAME} оновлено.`);
    }
  }
  app.listen(PORT, () => console.log(`Сервер запущено: http://localhost:${PORT}`));
}

start().catch((error) => {
  console.error(`Не вдалося запустити сервер: ${error.message}`);
  process.exit(1);
});
