const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const webpush = require('web-push');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tracl-dev-secret-change-in-production';
const DB_PATH = process.env.DATA_PATH || path.join(__dirname, 'tracl.db.json');
const KILL_SWITCH_PASSWORD = process.env.KILL_SWITCH_PASSWORD || '';

const MAX_NAME = 64;
const MAX_NOTE = 500;
const MAX_TAG_LEN = 32;
const MAX_TAGS = 10;

// ── DATABASE ──
function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {}
  return { users: [], sessions: [], subscriptions: [], connections: [] };
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db), 'utf8');
}
const q = {
  userByEmail: (db, email) => db.users.find(u => u.email === email),
  userById: (db, id) => db.users.find(u => u.id === id),
  sessionsByUser: (db, userId) => db.sessions.filter(s => s.userId === userId),
  openSession: (db, userId) => db.sessions.find(s => s.userId === userId && !s.endedAt),
  sessionById: (db, id, userId) => db.sessions.find(s => s.id === id && s.userId === userId),
};

// ── SSE ──
const clients = new Map();
function getClients(userId) {
  if (!clients.has(userId)) clients.set(userId, new Set());
  return clients.get(userId);
}
function pushToUser(userId, event, data) {
  const conns = clients.get(userId);
  if (!conns) return;
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of conns) {
    try { res.write(msg); } catch {}
  }
}

// ── RATE LIMITING ──
const rlMap = new Map();
function rateLimit(windowMs, max) {
  return (req, res, next) => {
    const key = (req.ip || '') + '|' + req.path;
    const now = Date.now();
    const entry = rlMap.get(key);
    if (!entry || now > entry.resetAt) {
      rlMap.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    entry.count++;
    if (entry.count > max) return res.status(429).json({ error: 'Too many requests, try again later.' });
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rlMap) if (now > v.resetAt) rlMap.delete(k);
}, 5 * 60 * 1000);

// ── MIDDLEWARE ──
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Password');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ── HELPERS ──
function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + JWT_SECRET).digest('hex');
}
function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '90d' });
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'not authenticated' });
  try {
    const { userId } = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = userId;
    next();
  } catch {
    res.status(401).json({ error: 'token expired or invalid' });
  }
}
function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}
function dayKey(ts) {
  return new Date(ts).toISOString().slice(0, 10);
}
function sanitizeTags(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map(t => String(t).trim().toLowerCase().slice(0, MAX_TAG_LEN))
    .filter(t => t.length > 0)
    .slice(0, MAX_TAGS);
}
function fmtSession(s) {
  return { id: s.id, startedAt: s.startedAt, endedAt: s.endedAt, durationSecs: s.durationSecs, method: s.method, note: s.note, tags: s.tags || [], type: s.type || 'study' };
}
function checkAdminPassword(req, res) {
  if (!KILL_SWITCH_PASSWORD) { res.status(503).json({ error: 'Admin not configured (set KILL_SWITCH_PASSWORD).' }); return false; }
  const pw = req.headers['x-admin-password'] || req.body?.password || req.query.password;
  if (!pw) { res.status(401).json({ error: 'Password required.' }); return false; }
  const provided = Buffer.from(String(pw));
  const expected = Buffer.from(KILL_SWITCH_PASSWORD);
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    res.status(403).json({ error: 'Incorrect password.' });
    return false;
  }
  return true;
}

// ── SSE ENDPOINT ──
app.get('/events', (req, res) => {
  const token = req.headers.authorization?.slice(7) || req.query.token;
  if (!token) return res.status(401).end();
  try {
    const { userId } = jwt.verify(token, JWT_SECRET);
    req.userId = userId;
  } catch { return res.status(401).end(); }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const heartbeat = setInterval(() => {
    try { res.write(': ping\n\n'); } catch {}
  }, 25000);

  const userClients = getClients(req.userId);
  userClients.add(res);
  req.on('close', () => {
    clearInterval(heartbeat);
    userClients.delete(res);
  });
});

// ── AUTH ──
const authLimiter = rateLimit(15 * 60 * 1000, 10);

app.post('/auth/signup', authLimiter, (req, res) => {
  const { name, email, password, goalSecs } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email and password required' });
  if (typeof name !== 'string' || name.trim().length === 0) return res.status(400).json({ error: 'invalid name' });
  if (name.trim().length > MAX_NAME) return res.status(400).json({ error: `name must be ${MAX_NAME} characters or fewer` });
  if (password.length < 6) return res.status(400).json({ error: 'password must be at least 6 characters' });
  if (password.length > 128) return res.status(400).json({ error: 'password too long' });
  if (!email.includes('@')) return res.status(400).json({ error: 'invalid email' });

  const db = loadDB();
  if (q.userByEmail(db, email.toLowerCase())) return res.status(409).json({ error: 'email already in use' });

  const user = {
    id: uid(),
    name: name.trim().slice(0, MAX_NAME),
    email: email.toLowerCase().trim().slice(0, 254),
    passHash: hashPass(password),
    goalSecs: typeof goalSecs === 'number' && goalSecs > 0 ? goalSecs : 18000,
    createdAt: Date.now()
  };
  db.users.push(user);
  saveDB(db);
  res.json({ token: makeToken(user.id), user: { id: user.id, name: user.name, email: user.email, goalSecs: user.goalSecs } });
});

app.post('/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const db = loadDB();
  const user = q.userByEmail(db, email.toLowerCase().trim());
  if (!user || user.passHash !== hashPass(password)) return res.status(401).json({ error: 'incorrect email or password' });
  res.json({ token: makeToken(user.id), user: { id: user.id, name: user.name, email: user.email, goalSecs: user.goalSecs } });
});

app.get('/auth/me', requireAuth, (req, res) => {
  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  res.json({ id: user.id, name: user.name, email: user.email, goalSecs: user.goalSecs });
});

app.patch('/auth/me', requireAuth, (req, res) => {
  const { name, goalSecs } = req.body;
  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });

  if (name !== undefined) {
    if (typeof name !== 'string' || name.trim().length === 0) return res.status(400).json({ error: 'invalid name' });
    if (name.trim().length > MAX_NAME) return res.status(400).json({ error: `name must be ${MAX_NAME} characters or fewer` });
    user.name = name.trim();
  }
  if (goalSecs !== undefined) {
    if (typeof goalSecs !== 'number' || goalSecs <= 0) return res.status(400).json({ error: 'goalSecs must be a positive number' });
    user.goalSecs = goalSecs;
  }
  saveDB(db);
  res.json({ id: user.id, name: user.name, email: user.email, goalSecs: user.goalSecs });
});

app.post('/auth/password', requireAuth, rateLimit(60 * 60 * 1000, 5), (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword and newPassword required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'new password must be at least 6 characters' });
  if (newPassword.length > 128) return res.status(400).json({ error: 'new password too long' });

  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  if (user.passHash !== hashPass(currentPassword)) return res.status(403).json({ error: 'current password is incorrect' });

  user.passHash = hashPass(newPassword);
  saveDB(db);
  res.json({ ok: true });
});

app.delete('/auth/me', requireAuth, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required to delete account' });

  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  if (user.passHash !== hashPass(password)) return res.status(403).json({ error: 'incorrect password' });

  db.users = db.users.filter(u => u.id !== req.userId);
  db.sessions = db.sessions.filter(s => s.userId !== req.userId);
  db.connections = (db.connections || []).filter(c => c.sharerId !== req.userId && c.viewerId !== req.userId);
  saveDB(db);
  clients.delete(req.userId);
  res.json({ ok: true });
});

// ── SESSIONS ──
app.post('/sessions/start', requireAuth, (req, res) => {
  const db = loadDB();
  const open = q.openSession(db, req.userId);
  if (open) return res.status(409).json({ error: 'session already active', sessionId: open.id });

  const type = ['study', 'work'].includes(req.body.type) ? req.body.type : 'study';
  const session = {
    id: uid(),
    userId: req.userId,
    startedAt: Date.now(),
    endedAt: null,
    durationSecs: null,
    method: req.body.method || 'manual',
    type,
    note: null,
    tags: sanitizeTags(req.body.tags),
    createdAt: Date.now()
  };
  db.sessions.push(session);
  saveDB(db);
  pushToUser(req.userId, 'session:start', { sessionId: session.id, startedAt: session.startedAt, method: session.method, type: session.type });
  res.json({ sessionId: session.id, startedAt: session.startedAt });
});

app.post('/sessions/end', requireAuth, (req, res) => {
  const { sessionId, note, tags } = req.body;
  const db = loadDB();
  const session = q.sessionById(db, sessionId, req.userId);
  if (!session) return res.status(404).json({ error: 'session not found' });
  if (session.endedAt) return res.status(409).json({ error: 'session already ended' });

  const now = Date.now();
  const durationSecs = Math.floor((now - session.startedAt) / 1000);

  if (durationSecs < 30) {
    db.sessions = db.sessions.filter(s => s.id !== sessionId);
    saveDB(db);
    pushToUser(req.userId, 'session:discard', { sessionId });
    return res.json({ discarded: true, reason: 'session too short' });
  }

  session.endedAt = now;
  session.durationSecs = durationSecs;
  session.note = note ? String(note).slice(0, MAX_NOTE) : null;
  if (tags !== undefined) session.tags = sanitizeTags(tags);
  saveDB(db);
  pushToUser(req.userId, 'session:end', { sessionId, startedAt: session.startedAt, endedAt: now, durationSecs });
  res.json({ sessionId, startedAt: session.startedAt, endedAt: now, durationSecs });
});

app.post('/sessions/log', requireAuth, (req, res) => {
  const { startedAt, endedAt, note, tags, method } = req.body;
  if (!startedAt || !endedAt) return res.status(400).json({ error: 'startedAt and endedAt required' });
  if (typeof startedAt !== 'number' || typeof endedAt !== 'number') return res.status(400).json({ error: 'startedAt and endedAt must be ms timestamps' });
  if (endedAt <= startedAt) return res.status(400).json({ error: 'endedAt must be after startedAt' });

  const durationSecs = Math.floor((endedAt - startedAt) / 1000);
  if (durationSecs < 30) return res.status(400).json({ error: 'session must be at least 30 seconds' });
  if (durationSecs > 86400) return res.status(400).json({ error: 'session cannot exceed 24 hours' });

  const type = ['study', 'work'].includes(req.body.type) ? req.body.type : 'study';
  const db = loadDB();
  const session = {
    id: uid(),
    userId: req.userId,
    startedAt,
    endedAt,
    durationSecs,
    method: method || 'manual',
    type,
    note: note ? String(note).slice(0, MAX_NOTE) : null,
    tags: sanitizeTags(tags),
    createdAt: Date.now()
  };
  db.sessions.push(session);
  saveDB(db);
  res.status(201).json(fmtSession(session));
});

app.patch('/sessions/:id', requireAuth, (req, res) => {
  const { note, tags } = req.body;
  const db = loadDB();
  const session = q.sessionById(db, req.params.id, req.userId);
  if (!session) return res.status(404).json({ error: 'session not found' });
  if (!session.endedAt) return res.status(409).json({ error: 'cannot edit an active session' });

  if (note !== undefined) session.note = note ? String(note).slice(0, MAX_NOTE) : null;
  if (tags !== undefined) session.tags = sanitizeTags(tags);
  saveDB(db);
  res.json(fmtSession(session));
});

app.get('/sessions/today', requireAuth, (req, res) => {
  const db = loadDB();
  const user = q.userById(db, req.userId);
  const today = dayKey(Date.now());
  const all = q.sessionsByUser(db, req.userId);
  const sessions = all
    .filter(s => s.endedAt && dayKey(s.startedAt) === today)
    .sort((a, b) => b.startedAt - a.startedAt)
    .map(fmtSession);
  const totalSecs = sessions.reduce((acc, s) => acc + s.durationSecs, 0);
  const goalSecs = user?.goalSecs || 18000;
  const open = q.openSession(db, req.userId);
  res.json({
    sessions,
    activeSession: open ? { id: open.id, started_at: open.startedAt, method: open.method, type: open.type || 'study' } : null,
    progress: { totalSecs, goalSecs, percent: Math.min(100, Math.round((totalSecs / goalSecs) * 100)) }
  });
});

app.get('/sessions/week', requireAuth, (req, res) => {
  const db = loadDB();
  const user = q.userById(db, req.userId);
  const sevenAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const typeFilter = ['study', 'work'].includes(req.query.type) ? req.query.type : null;
  let weekSessions = q.sessionsByUser(db, req.userId).filter(s => s.endedAt && s.startedAt >= sevenAgo);
  if (typeFilter) weekSessions = weekSessions.filter(s => (s.type || 'study') === typeFilter);
  const sessions = weekSessions.sort((a, b) => b.startedAt - a.startedAt).map(fmtSession);
  const totalSecs = sessions.reduce((acc, s) => acc + s.durationSecs, 0);
  const goalSecs = user?.goalSecs || 18000;
  res.json({
    sessions,
    progress: { totalSecs, goalSecs: goalSecs * 7, percent: Math.min(100, Math.round((totalSecs / (goalSecs * 7)) * 100)) }
  });
});

app.get('/sessions/history', requireAuth, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const tag = req.query.tag ? String(req.query.tag).toLowerCase() : null;

  const db = loadDB();
  let all = q.sessionsByUser(db, req.userId)
    .filter(s => s.endedAt)
    .sort((a, b) => b.startedAt - a.startedAt);

  const typeFilter = ['study', 'work'].includes(req.query.type) ? req.query.type : null;
  if (typeFilter) all = all.filter(s => (s.type || 'study') === typeFilter);
  if (tag) all = all.filter(s => (s.tags || []).includes(tag));

  const total = all.length;
  const sessions = all.slice((page - 1) * limit, page * limit).map(fmtSession);
  res.json({ sessions, total, page, limit, pages: Math.ceil(total / limit) });
});

app.get('/sessions/stats', requireAuth, (req, res) => {
  const db = loadDB();
  const typeFilter = ['study', 'work'].includes(req.query.type) ? req.query.type : null;
  let all = q.sessionsByUser(db, req.userId).filter(s => s.endedAt);
  if (typeFilter) all = all.filter(s => (s.type || 'study') === typeFilter);

  let streak = 0;
  const seen = new Set(all.map(s => dayKey(s.startedAt)));
  for (let i = 0; i < 365; i++) {
    const d = new Date(); d.setDate(d.getDate() - i);
    if (seen.has(d.toISOString().slice(0, 10))) streak++;
    else if (i > 0) break;
  }

  const sevenAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const weekTotal = all.filter(s => s.startedAt >= sevenAgo).reduce((a, s) => a + s.durationSecs, 0);
  const avg = all.length > 0 ? Math.round(all.reduce((a, s) => a + s.durationSecs, 0) / all.length) : 0;

  const tagCounts = {};
  for (const s of all) for (const t of (s.tags || [])) tagCounts[t] = (tagCounts[t] || 0) + 1;
  const topTags = Object.entries(tagCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([tag, count]) => ({ tag, count }));

  res.json({ streak, weekTotal, avgSession: avg, totalSessions: all.length, topTags });
});

app.get('/sessions/export.csv', requireAuth, (req, res) => {
  const db = loadDB();
  const sessions = q.sessionsByUser(db, req.userId)
    .filter(s => s.endedAt)
    .sort((a, b) => a.startedAt - b.startedAt);

  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [['id', 'type', 'startedAt', 'endedAt', 'durationSecs', 'method', 'note', 'tags'].join(',')];
  for (const s of sessions) {
    rows.push([
      esc(s.id),
      esc(s.type || 'study'),
      esc(new Date(s.startedAt).toISOString()),
      esc(new Date(s.endedAt).toISOString()),
      s.durationSecs,
      esc(s.method),
      esc(s.note || ''),
      esc((s.tags || []).join(';'))
    ].join(','));
  }

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tracl-sessions.csv"');
  res.send(rows.join('\n'));
});

// ── PUSH NOTIFICATIONS ──
function fmtDuration(secs) {
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60);
  return h ? (m ? `${h}h ${m}m` : `${h}h`) : `${m}m`;
}

// VAPID keys: generate once, persist in DB on the Railway volume
function initVapid() {
  const db = loadDB();
  if (!db.vapidKeys) {
    db.vapidKeys = webpush.generateVAPIDKeys();
    saveDB(db);
    console.log('[vapid] generated new VAPID keys');
  }
  webpush.setVapidDetails(
    'mailto:tracl@localhost',
    db.vapidKeys.publicKey,
    db.vapidKeys.privateKey
  );
  return db.vapidKeys.publicKey;
}
const VAPID_PUBLIC_KEY = initVapid();

// Convert UTC ms + tzOffset (from getTimezoneOffset) to local YYYY-MM-DD
function localDay(utcMs, tzOffset) {
  return new Date(utcMs - tzOffset * 60000).toISOString().slice(0, 10);
}

// Notify scheduler — runs every minute
setInterval(async () => {
  const db = loadDB();
  if (!db.subscriptions?.length) return;
  const now = new Date();
  const utcMin = now.getUTCHours() * 60 + now.getUTCMinutes();

  for (const user of db.users) {
    const ns = user.notifSettings;
    if (!ns?.enabled || !ns.times?.length) continue;
    const subs = (db.subscriptions || []).filter(s => s.userId === user.id);
    if (!subs.length) continue;

    for (const sub of subs) {
      const tz = sub.tzOffset ?? 0;
      const localMin = ((utcMin - tz) % 1440 + 1440) % 1440;
      const localHH = String(Math.floor(localMin / 60)).padStart(2, '0');
      const localMM = String(localMin % 60).padStart(2, '0');
      if (!ns.times.includes(`${localHH}:${localMM}`)) continue;

      const today = localDay(Date.now(), tz);
      const todaySessions = db.sessions.filter(s =>
        s.userId === user.id && s.endedAt && localDay(s.startedAt, tz) === today
      );
      const done = todaySessions.reduce((a, s) => a + s.durationSecs, 0);
      if (ns.onlyIfBehind && done >= (user.goalSecs || 18000)) continue;

      const remaining = (user.goalSecs || 18000) - done;
      const body = done === 0
        ? `Time to study! Your goal is ${fmtDuration(user.goalSecs || 18000)} today.`
        : `${fmtDuration(Math.max(0, remaining))} left to reach your ${fmtDuration(user.goalSecs || 18000)} goal.`;

      try {
        await webpush.sendNotification(sub.subscription, JSON.stringify({ title: 'tracl', body, tag: 'tracl-daily' }));
      } catch (err) {
        if (err.statusCode === 410 || err.statusCode === 404) {
          db.subscriptions = db.subscriptions.filter(s => s !== sub);
          saveDB(db);
        }
      }
    }
  }
}, 60 * 1000);

app.get('/notifications/vapid-key', (_req, res) => {
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

app.post('/notifications/subscribe', requireAuth, (req, res) => {
  const { subscription, tzOffset } = req.body;
  if (!subscription?.endpoint) return res.status(400).json({ error: 'subscription required' });
  const db = loadDB();
  if (!db.subscriptions) db.subscriptions = [];
  // Replace existing subscription for this endpoint (device)
  db.subscriptions = db.subscriptions.filter(s => s.subscription.endpoint !== subscription.endpoint);
  db.subscriptions.push({ userId: req.userId, tzOffset: tzOffset ?? 0, subscription });
  saveDB(db);
  res.json({ ok: true });
});

app.delete('/notifications/subscribe', requireAuth, (req, res) => {
  const db = loadDB();
  db.subscriptions = (db.subscriptions || []).filter(s => s.userId !== req.userId);
  saveDB(db);
  res.json({ ok: true });
});

app.get('/notifications/settings', requireAuth, (req, res) => {
  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  const subscribed = (db.subscriptions || []).some(s => s.userId === req.userId);
  res.json({ ...(user.notifSettings || { enabled: false, times: ['09:00'], onlyIfBehind: true }), subscribed });
});

app.patch('/notifications/settings', requireAuth, (req, res) => {
  const { enabled, times, onlyIfBehind } = req.body;
  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  if (!user.notifSettings) user.notifSettings = { enabled: false, times: ['09:00'], onlyIfBehind: true };
  if (enabled !== undefined) user.notifSettings.enabled = !!enabled;
  if (Array.isArray(times)) user.notifSettings.times = times.filter(t => /^\d{2}:\d{2}$/.test(t)).slice(0, 3);
  if (onlyIfBehind !== undefined) user.notifSettings.onlyIfBehind = !!onlyIfBehind;
  saveDB(db);
  res.json({ ...user.notifSettings });
});

app.post('/notifications/test', requireAuth, async (req, res) => {
  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  const subs = (db.subscriptions || []).filter(s => s.userId === req.userId);
  if (!subs.length) return res.status(400).json({ error: 'no subscription found — enable notifications first' });
  let sent = 0;
  for (const sub of subs) {
    try {
      await webpush.sendNotification(sub.subscription, JSON.stringify({ title: 'tracl', body: 'Notifications are working!', tag: 'tracl-test' }));
      sent++;
    } catch {}
  }
  res.json({ ok: true, sent });
});

// ── SOCIAL ──
const socialLimiter = rateLimit(60 * 60 * 1000, 40);

// canView: returns true if viewerId has an accepted connection to see sharerId's data
function canView(db, viewerId, sharerId) {
  return (db.connections || []).some(c => c.sharerId === sharerId && c.viewerId === viewerId && c.status === 'accepted');
}

function fmtConnection(db, c, perspectiveUserId) {
  const otherId = c.sharerId === perspectiveUserId ? c.viewerId : c.sharerId;
  const other = q.userById(db, otherId);
  // nickname is always from the perspective of perspectiveUserId about the OTHER person
  const nickname = c.viewerId === perspectiveUserId ? (c.viewerNickname || null) : (c.sharerNickname || null);
  return { id: c.id, status: c.status, createdAt: c.createdAt, nickname, user: other ? { id: other.id, name: other.name, email: other.email } : null };
}

// Share MY data with someone → they must accept to see me
app.post('/social/invite', requireAuth, socialLimiter, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  const db = loadDB();
  const target = q.userByEmail(db, email.toLowerCase().trim());
  if (!target) return res.status(404).json({ error: 'no user found with that email' });
  if (target.id === req.userId) return res.status(400).json({ error: 'cannot share with yourself' });

  if (!db.connections) db.connections = [];
  const dup = db.connections.find(c => c.sharerId === req.userId && c.viewerId === target.id);
  if (dup) return res.status(409).json({ error: dup.status === 'pending' ? 'invite already sent' : 'already sharing with this person' });

  const conn = { id: uid(), sharerId: req.userId, viewerId: target.id, status: 'pending', createdAt: Date.now() };
  db.connections.push(conn);
  saveDB(db);
  res.status(201).json({ ok: true, connectionId: conn.id, targetName: target.name });
});

// Get all my connections: shared (I'm sharerId) + received (I'm viewerId)
app.get('/social/connections', requireAuth, (req, res) => {
  const db = loadDB();
  const conns = db.connections || [];
  const shared = conns.filter(c => c.sharerId === req.userId).map(c => fmtConnection(db, c, req.userId));
  const received = conns.filter(c => c.viewerId === req.userId).map(c => fmtConnection(db, c, req.userId));
  res.json({ shared, received });
});

// Accept / decline a pending invite, or set a nickname for the other person
app.patch('/social/connections/:id', requireAuth, (req, res) => {
  const { action, nickname } = req.body;
  const db = loadDB();
  const conn = (db.connections || []).find(c => c.id === req.params.id);
  if (!conn) return res.status(404).json({ error: 'connection not found' });

  // Nickname update — either side can set their own label for the other person
  if (nickname !== undefined) {
    if (conn.sharerId !== req.userId && conn.viewerId !== req.userId) return res.status(403).json({ error: 'not your connection' });
    const nick = nickname ? String(nickname).trim().slice(0, 50) || null : null;
    if (conn.viewerId === req.userId) conn.viewerNickname = nick;
    else conn.sharerNickname = nick;
    saveDB(db);
    return res.json({ ok: true });
  }

  // Accept / decline
  if (!['accept', 'decline'].includes(action)) return res.status(400).json({ error: 'action must be accept or decline' });
  if (conn.viewerId !== req.userId) return res.status(403).json({ error: 'only the recipient can respond' });
  if (conn.status !== 'pending') return res.status(409).json({ error: 'not pending' });

  if (action === 'accept') {
    conn.status = 'accepted'; conn.acceptedAt = Date.now(); saveDB(db);
    res.json({ ok: true, status: 'accepted' });
  } else {
    db.connections = db.connections.filter(c => c.id !== req.params.id); saveDB(db);
    res.json({ ok: true, status: 'declined' });
  }
});

// Remove a connection (either side: sharerId revokes, viewerId unfollows)
app.delete('/social/connections/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const conn = (db.connections || []).find(c => c.id === req.params.id);
  if (!conn) return res.status(404).json({ error: 'connection not found' });
  if (conn.sharerId !== req.userId && conn.viewerId !== req.userId) return res.status(403).json({ error: 'not your connection' });
  db.connections = db.connections.filter(c => c.id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

// View another user's profile — requires accepted connection (sharerId=them, viewerId=me)
app.get('/social/users/:userId/profile', requireAuth, (req, res) => {
  const { userId } = req.params;
  const db = loadDB();
  if (!canView(db, req.userId, userId)) return res.status(403).json({ error: 'access not granted' });
  const user = q.userById(db, userId);
  if (!user) return res.status(404).json({ error: 'user not found' });

  const today = dayKey(Date.now());
  const sevenAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const all = q.sessionsByUser(db, userId).filter(s => s.endedAt);

  const todaySess = all.filter(s => dayKey(s.startedAt) === today);
  const todayStudy = todaySess.filter(s => (s.type || 'study') === 'study').reduce((a, s) => a + s.durationSecs, 0);
  const todayWork = todaySess.filter(s => s.type === 'work').reduce((a, s) => a + s.durationSecs, 0);

  let streak = 0;
  const seen = new Set(all.map(s => dayKey(s.startedAt)));
  for (let i = 0; i < 365; i++) {
    const d = new Date(); d.setDate(d.getDate() - i);
    if (seen.has(d.toISOString().slice(0, 10))) streak++;
    else if (i > 0) break;
  }

  const open = q.openSession(db, userId);
  const weekSessions = all.filter(s => s.startedAt >= sevenAgo)
    .map(s => ({ startedAt: s.startedAt, durationSecs: s.durationSecs, type: s.type || 'study' }));
  const recent = all.sort((a, b) => b.startedAt - a.startedAt).slice(0, 15)
    .map(s => ({ id: s.id, startedAt: s.startedAt, endedAt: s.endedAt, durationSecs: s.durationSecs, note: s.note || null, tags: s.tags || [], type: s.type || 'study' }));

  const viewConn = (db.connections || []).find(c => c.sharerId === userId && c.viewerId === req.userId && c.status === 'accepted');
  res.json({
    user: { id: user.id, name: user.name, goalSecs: user.goalSecs },
    nickname: viewConn?.viewerNickname || null,
    today: { study: todayStudy, work: todayWork },
    streak,
    activeSession: open ? { type: open.type || 'study', startedAt: open.startedAt } : null,
    weekSessions,
    recent
  });
});

// ── KILL SWITCH ──
app.get('/admin/reset', (_req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Database</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: #0f0f0f; font-family: system-ui, sans-serif; color: #e0e0e0; }
    .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px; padding: 2rem; width: 100%; max-width: 380px; }
    h1 { font-size: 1.1rem; margin-bottom: 0.4rem; color: #fff; }
    p { font-size: 0.85rem; color: #888; margin-bottom: 1.5rem; }
    input { width: 100%; padding: 0.65rem 0.9rem; background: #0f0f0f; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 0.95rem; margin-bottom: 1rem; outline: none; }
    input:focus { border-color: #e55; }
    button { width: 100%; padding: 0.7rem; background: #c0392b; border: none; border-radius: 8px; color: #fff; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #e74c3c; }
    .msg { margin-top: 1rem; font-size: 0.85rem; text-align: center; }
    .err { color: #e55; } .ok { color: #5c5; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Reset Database</h1>
    <p>This will permanently erase all users and sessions.</p>
    <form id="f">
      <input type="password" id="pw" placeholder="Kill switch password" required autocomplete="off">
      <button type="submit">Erase All Data</button>
    </form>
    <div class="msg" id="msg"></div>
  </div>
  <script>
    document.getElementById('f').addEventListener('submit', async e => {
      e.preventDefault();
      const msg = document.getElementById('msg');
      msg.textContent = '';
      try {
        const r = await fetch('/admin/reset', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: document.getElementById('pw').value })
        });
        const d = await r.json();
        if (r.ok) { msg.className = 'msg ok'; msg.textContent = d.message; document.getElementById('pw').value = ''; }
        else { msg.className = 'msg err'; msg.textContent = d.error; }
      } catch { msg.className = 'msg err'; msg.textContent = 'Request failed.'; }
    });
  </script>
</body>
</html>`);
});

app.post('/admin/reset', (req, res) => {
  if (!checkAdminPassword(req, res)) return;
  const db = loadDB();
  saveDB({ users: [], sessions: [], subscriptions: [], connections: [], vapidKeys: db.vapidKeys });
  clients.clear();
  console.log(`[kill-switch] database wiped at ${new Date().toISOString()}`);
  res.json({ message: 'All data erased.' });
});

// ── ADMIN STATS ──
app.get('/admin/stats', (req, res) => {
  if (!checkAdminPassword(req, res)) return;
  const db = loadDB();
  const completed = db.sessions.filter(s => s.endedAt);
  const totalSecs = completed.reduce((a, s) => a + s.durationSecs, 0);
  res.json({
    users: db.users.length,
    sessions: completed.length,
    activeSessions: db.sessions.filter(s => !s.endedAt).length,
    totalHours: Math.round(totalSecs / 3600 * 10) / 10,
    connectedClients: [...clients.values()].reduce((a, s) => a + s.size, 0)
  });
});

// ── ADMIN USERS ──
app.get('/admin/users', (req, res) => {
  if (!checkAdminPassword(req, res)) return;
  const db = loadDB();
  const search = (req.query.q || '').toLowerCase().trim();
  let users = db.users.map(u => {
    const sessions = db.sessions.filter(s => s.userId === u.id);
    const completed = sessions.filter(s => s.endedAt);
    const totalSecs = completed.reduce((a, s) => a + (s.durationSecs || 0), 0);
    const lastSession = completed.sort((a, b) => b.endedAt - a.endedAt)[0];
    const open = sessions.find(s => !s.endedAt);
    return {
      id: u.id,
      name: u.name,
      email: u.email,
      createdAt: u.createdAt || null,
      sessions: completed.length,
      totalHours: Math.round(totalSecs / 3600 * 10) / 10,
      lastActive: lastSession?.endedAt || null,
      isLive: !!open,
      liveType: open?.type || null,
    };
  });
  if (search) users = users.filter(u =>
    u.name.toLowerCase().includes(search) || u.email.toLowerCase().includes(search)
  );
  users.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json({ users, total: db.users.length });
});

app.delete('/admin/users/:id', (req, res) => {
  if (!checkAdminPassword(req, res)) return;
  const db = loadDB();
  const user = q.userById(db, req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  db.users = db.users.filter(u => u.id !== req.params.id);
  db.sessions = db.sessions.filter(s => s.userId !== req.params.id);
  db.subscriptions = (db.subscriptions || []).filter(s => s.userId !== req.params.id);
  db.connections = (db.connections || []).filter(c => c.sharerId !== req.params.id && c.viewerId !== req.params.id);
  saveDB(db);
  pushToUser(req.params.id, 'logout', {});
  console.log(`[admin] deleted user ${req.params.id} (${user.email})`);
  res.json({ message: 'User deleted.' });
});

// ── ADMIN SETTINGS ──
app.get('/admin/settings', (req, res) => {
  if (!checkAdminPassword(req, res)) return;
  const db = loadDB();
  res.json({ settings: db.settings || {} });
});

app.patch('/admin/settings', (req, res) => {
  if (!checkAdminPassword(req, res)) return;
  const db = loadDB();
  if (!db.settings) db.settings = {};
  const { appName } = req.body;
  if (appName !== undefined) {
    if (typeof appName !== 'string' || !appName.trim()) return res.status(400).json({ error: 'App name cannot be empty.' });
    if (appName.trim().length > 32) return res.status(400).json({ error: 'App name too long (max 32 chars).' });
    db.settings.appName = appName.trim();
  }
  saveDB(db);
  res.json({ settings: db.settings });
});

// ── PUBLIC CONFIG ──
app.get('/config', (_req, res) => {
  const db = loadDB();
  res.json({ appName: db.settings?.appName || 'tracl' });
});

// Live status of people whose data I can view
app.get('/social/live', requireAuth, (req, res) => {
  const db = loadDB();
  const live = (db.connections || [])
    .filter(c => c.viewerId === req.userId && c.status === 'accepted')
    .map(c => {
      const open = q.openSession(db, c.sharerId);
      if (!open) return null;
      const user = q.userById(db, c.sharerId);
      return { userId: c.sharerId, name: user?.name || 'Unknown', nickname: c.viewerNickname || null, type: open.type || 'study', startedAt: open.startedAt };
    })
    .filter(Boolean);
  res.json({ live });
});

app.get('/health', (_req, res) => res.json({ ok: true, time: Date.now() }));

// One-time migration: tag existing sessions with 'study' or 'work' based on their type field
(function migrateSessionTags() {
  const db = loadDB();
  let changed = false;
  (db.sessions || []).forEach(s => {
    if (!s.endedAt) return;
    const tag = s.type === 'work' ? 'work' : 'study';
    if (!s.tags) s.tags = [];
    if (!s.tags.includes(tag)) { s.tags.push(tag); changed = true; }
  });
  if (changed) saveDB(db);
})();

app.listen(PORT, '0.0.0.0', () => console.log(`tracl running on port ${PORT}`));
